package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type backupRunner struct {
	commands []string
	fail     string
	success  map[string]bool
}

func (r *backupRunner) Run(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if r.fail != "" && strings.Contains(command, r.fail) {
		return nil, errors.New("injected")
	}
	if r.success[command] {
		return nil, nil
	}
	switch command {
	case "systemctl is-enabled --quiet nftfw-early.service":
		return nil, nil
	case "systemctl is-active --quiet nftfw-web.service":
		return nil, nil
	default:
		if strings.HasPrefix(command, "systemctl is-") {
			return nil, errors.New("inactive")
		}
		if strings.HasPrefix(command, "sysctl -n ") {
			return []byte("1\n"), nil
		}
		return nil, nil
	}
}

func TestCreateAndRestoreBackupRoundTrip(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "etc/nftfw/nftfw.toml")
	missing := filepath.Join(root, "etc/nftfw/intent.toml")
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &backupRunner{}
	directory := filepath.Join(root, "backup")
	manifest, err := createBackup(
		context.Background(), runner, directory,
		[]string{source, missing},
		[]string{"nftfw-early.service", "nftfw-web.service"},
		[]string{"net.ipv6.conf.eth0.disable_ipv6"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 2 || !manifest.Files[0].Exists || manifest.Files[1].Exists {
		t.Fatalf("unexpected backup manifest: %#v", manifest)
	}
	if err := os.WriteFile(source, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(missing, []byte("created\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreBackup(context.Background(), runner, directory); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(source); string(data) != "old\n" {
		t.Fatalf("source was not restored: %q", data)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new file was not removed: %v", err)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "systemctl enable nftfw-early.service") ||
		!strings.Contains(joined, "systemctl start nftfw-web.service") {
		t.Fatalf("unit state was not restored:\n%s", joined)
	}
}

func TestRestoreBackupDefersKernelUnavailableIPv6UntilExplicitFinalize(t *testing.T) {
	runner := &backupRunner{}
	directory := filepath.Join(t.TempDir(), "backup")
	if _, err := createBackup(context.Background(), runner, directory, nil,
		[]string{"nftfw-early.service"},
		[]string{"net.ipv4.ip_forward", "net.ipv6.conf.eth0.disable_ipv6"}); err != nil {
		t.Fatal(err)
	}
	runner.commands = nil
	if err := restoreBackupDeferring(
		context.Background(), runner, directory, bootIPv6Sysctl,
	); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "sysctl -w net.ipv4.ip_forward=1") ||
		strings.Contains(joined, "sysctl -w net.ipv6.") ||
		!strings.Contains(joined, "systemctl enable nftfw-early.service") {
		t.Fatalf("deferred restore did not complete every available state class:\n%s", joined)
	}
	runner.commands = nil
	if err := restoreDeferredSysctls(
		context.Background(), runner, directory, bootIPv6Sysctl,
	); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(runner.commands, "\n")
	if joined != "sysctl -w net.ipv6.conf.eth0.disable_ipv6=1" {
		t.Fatalf("explicit post-reboot restore touched the wrong state: %q", joined)
	}
	runner.commands = nil
	if err := restoreDeferredSysctls(
		context.Background(), runner, directory, anyBackupSysctl,
	); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(runner.commands, "\n")
	if joined != "sysctl -w net.ipv4.ip_forward=1\n"+
		"sysctl -w net.ipv6.conf.eth0.disable_ipv6=1" {
		t.Fatalf("post-reboot restore omitted a volatile sysctl: %q", joined)
	}
	if err := restoreDeferredSysctls(
		context.Background(), runner, directory, func(string) bool { return false },
	); err == nil {
		t.Fatal("empty deferred sysctl class was accepted")
	}
}

func TestBackupRejectsUnsafeInputs(t *testing.T) {
	runner := &backupRunner{}
	if _, err := createBackup(context.Background(), runner, "relative", nil, nil, nil); err == nil {
		t.Fatal("relative backup path accepted")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := createBackup(
		context.Background(), runner, filepath.Join(root, "backup"),
		[]string{link}, nil, nil,
	); err == nil {
		t.Fatal("symlink backup source accepted")
	}
	runner.fail = "sysctl -n"
	if _, err := createBackup(
		context.Background(), runner, filepath.Join(root, "backup-2"),
		nil, nil, []string{"net.ipv6.conf.eth0.disable_ipv6"},
	); err == nil {
		t.Fatal("failed sysctl capture accepted")
	}
}

func TestCopyRegularAndAtomicWriteBoundaries(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, make([]byte, (4<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyRegular(source, filepath.Join(root, "copy"), 0o600); err == nil ||
		err.Error() != "SETUP_BACKUP_FILE_TOO_LARGE" {
		t.Fatalf("oversized backup source accepted: %v", err)
	}
	if err := writeAtomic("relative", []byte("data"), 0o600); err == nil {
		t.Fatal("relative atomic target accepted")
	}
	path := filepath.Join(root, "nested", "file")
	if err := WriteAtomicFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomicFile(path, []byte("second"), 0o640); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "second" {
		t.Fatalf("atomic replacement failed: %q", data)
	}
	link := filepath.Join(root, "unsafe")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(link, []byte("bad"), 0o600); err == nil {
		t.Fatal("symlink atomic target accepted")
	}
}

func TestBackupManifestAndJournalValidation(t *testing.T) {
	root := t.TempDir()
	if _, err := readBackup(root); err == nil {
		t.Fatal("missing backup manifest accepted")
	}
	manifestPath := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{"schema":"wrong"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBackup(root); err == nil {
		t.Fatal("invalid backup manifest accepted")
	}
	if err := os.Chmod(manifestPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBackup(root); err == nil {
		t.Fatal("world-readable backup manifest accepted")
	}
	if err := os.Chmod(manifestPath, 0o600); err != nil {
		t.Fatal(err)
	}
	store := FileJournal{Path: filepath.Join(root, "setup", "journal.json")}
	if err := (FileJournal{Path: "relative"}).Write(Journal{}); err == nil {
		t.Fatal("relative journal path accepted")
	}
	if err := store.Write(Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "test",
		StartedAt: testTime(), UpdatedAt: testTime(), Deadline: testTime().Add(1),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.Path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(); err == nil {
		t.Fatal("world-readable journal accepted")
	}
}

func TestBootBackupManifestIdentityFailsClosed(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "backup")
	manifest, err := createBackup(context.Background(), &backupRunner{}, directory, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest.PreparedSHA256 = "short"
	if err := writeBackupManifest(manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := readBackup(directory); err == nil {
		t.Fatal("malformed prepared-plan identity was accepted")
	}
	manifest.PreparedSHA256 = strings.Repeat("a", 64)
	manifest.Boot = &bootBackup{
		Schema: bootBackupSchema, PreBootID: testBootID1,
		MountSHA256: strings.Repeat("b", 64), KernelSHA256: strings.Repeat("c", 64),
		InitialGeneratedSHA256:  strings.Repeat("d", 64),
		PreparedGeneratedSHA256: strings.Repeat("e", 64),
	}
	if err := writeBackupManifest(manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := readBackup(directory); err == nil {
		t.Fatal("partial prepared boot identity was accepted")
	}
}

func TestRestoreBackupCommandFailures(t *testing.T) {
	for _, fail := range []string{
		"sysctl -w", "systemctl daemon-reload",
		"systemctl enable nftfw-early.service", "systemctl start nftfw-web.service",
	} {
		t.Run(fail, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "source")
			if err := os.WriteFile(source, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			runner := &backupRunner{}
			directory := filepath.Join(root, "backup")
			if _, err := createBackup(
				context.Background(), runner, directory, []string{source},
				[]string{"nftfw-early.service", "nftfw-web.service"},
				[]string{"net.ipv6.conf.eth0.disable_ipv6"},
			); err != nil {
				t.Fatal(err)
			}
			runner.fail = fail
			if err := restoreBackup(context.Background(), runner, directory); err == nil {
				t.Fatal("restore command failure was ignored")
			}
		})
	}
}

func TestRestoreRejectsMissingBackupPayloadAndUnsafeNewTarget(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	newTarget := filepath.Join(root, "new-target")
	if err := os.WriteFile(source, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &backupRunner{}
	directory := filepath.Join(root, "backup")
	manifest, err := createBackup(
		context.Background(), runner, directory, []string{source, newTarget}, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, manifest.Files[0].Backup)); err != nil {
		t.Fatal(err)
	}
	if err := restoreBackup(context.Background(), runner, directory); err == nil ||
		err.Error() != "SETUP_BACKUP_RESTORE_READ_FAILED" {
		t.Fatalf("missing backup payload accepted: %v", err)
	}

	directory = filepath.Join(root, "backup-2")
	if _, err := createBackup(
		context.Background(), runner, directory, []string{source, newTarget}, nil, nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(newTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := restoreBackup(context.Background(), runner, directory); err == nil ||
		err.Error() != "SETUP_BACKUP_RESTORE_TARGET_UNSAFE" {
		t.Fatalf("unsafe new target accepted: %v", err)
	}
}

func TestRestoreRejectsTamperedChecksummedPayload(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &backupRunner{}
	directory := filepath.Join(root, "backup")
	manifest, err := createBackup(
		context.Background(), runner, directory, []string{source}, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Files[0].SHA256 == "" {
		t.Fatal("new setup backup omitted payload checksum")
	}
	if err := os.WriteFile(
		filepath.Join(directory, manifest.Files[0].Backup), []byte("new"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := restoreBackup(context.Background(), runner, directory); err == nil ||
		err.Error() != "SETUP_BACKUP_RESTORE_CHECKSUM_FAILED" {
		t.Fatalf("tampered backup payload accepted: %v", err)
	}
}

func TestRestoreSelectedBootFilesIsExactAndFailClosed(t *testing.T) {
	type fixture struct {
		directory string
		source    string
		missing   string
		manifest  backupManifest
	}
	newFixture := func(t *testing.T) fixture {
		t.Helper()
		root := t.TempDir()
		source := filepath.Join(root, "boot/grub/grub.cfg")
		missing := filepath.Join(root, "etc/default/grub.d/90-nftfw-ipv6-disabled.cfg")
		if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source, []byte("initial\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		directory := filepath.Join(root, "backup")
		manifest, err := createBackup(context.Background(), &backupRunner{}, directory,
			[]string{source, missing}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return fixture{directory: directory, source: source, missing: missing, manifest: manifest}
	}

	valid := newFixture(t)
	if err := os.WriteFile(valid.source, []byte("prepared\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, valid.missing, []byte(grubFragmentData), 0o600)
	if err := restoreBackupFiles(valid.directory, []string{valid.source, valid.missing}); err != nil {
		t.Fatalf("exact selected restore failed: %v", err)
	}
	if got := mustRead(t, valid.source); string(got) != "initial\n" {
		t.Fatalf("selected existing file was not restored: %q", got)
	}
	if _, err := os.Lstat(valid.missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("selected originally absent file was not removed: %v", err)
	}

	for _, required := range [][]string{{"relative"}, {valid.source, valid.source}, {filepath.Join(t.TempDir(), "unknown")}} {
		if err := restoreBackupFiles(valid.directory, required); err == nil {
			t.Fatalf("invalid selected restore was accepted: %v", required)
		}
	}

	tampered := newFixture(t)
	if err := os.WriteFile(filepath.Join(tampered.directory, tampered.manifest.Files[0].Backup), []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreBackupFiles(tampered.directory, []string{tampered.source}); err == nil ||
		err.Error() != "SETUP_BACKUP_RESTORE_CHECKSUM_FAILED" {
		t.Fatalf("tampered selected payload was accepted: %v", err)
	}

	unsafeTarget := newFixture(t)
	if err := os.MkdirAll(unsafeTarget.missing, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := restoreBackupFiles(unsafeTarget.directory, []string{unsafeTarget.missing}); err == nil ||
		err.Error() != "SETUP_BACKUP_RESTORE_TARGET_UNSAFE" {
		t.Fatalf("unsafe selected removal target was accepted: %v", err)
	}
}

func TestVerifyRestoredBackupFailsClosedOnEveryEvidenceClass(t *testing.T) {
	type fixture struct {
		root, source, directory string
		runner                  *systemRunner
	}
	newFixture := func(t *testing.T) fixture {
		t.Helper()
		root := t.TempDir()
		source := filepath.Join(root, "etc/nftfw.toml")
		if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source, []byte("operator baseline\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runner := &systemRunner{outputs: map[string][]byte{}}
		directory := filepath.Join(root, "backup")
		if _, err := createBackup(context.Background(), runner, directory,
			[]string{source}, []string{"nftfw-early.service"},
			[]string{"net.ipv6.conf.eth0.disable_ipv6"}); err != nil {
			t.Fatal(err)
		}
		return fixture{root: root, source: source, directory: directory, runner: runner}
	}
	valid := newFixture(t)
	if _, err := verifyRestoredBackup(context.Background(), valid.runner, valid.directory); err != nil {
		t.Fatalf("exact restored backup rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, value fixture)
	}{
		{"restored-target", func(t *testing.T, value fixture) {
			if err := os.WriteFile(value.source, []byte("changed\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"payload", func(t *testing.T, value fixture) {
			if err := os.WriteFile(filepath.Join(value.directory, "file-000"), []byte("changed\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"unexpected-entry", func(t *testing.T, value fixture) {
			if err := os.WriteFile(filepath.Join(value.directory, "extra"), []byte("extra\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"unsafe-directory-mode", func(t *testing.T, value fixture) {
			if err := os.Chmod(value.directory, 0o750); err != nil {
				t.Fatal(err)
			}
		}},
		{"unit-state", func(_ *testing.T, value fixture) {
			value.runner.outputs["systemctl show --property=LoadState,ActiveState nftfw-early.service"] =
				[]byte("LoadState=loaded\nActiveState=active\n")
		}},
		{"sysctl-state", func(_ *testing.T, value fixture) {
			value.runner.outputs["sysctl -n net.ipv6.conf.eth0.disable_ipv6"] = []byte("1\n")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := newFixture(t)
			test.mutate(t, value)
			if _, err := verifyRestoredBackup(context.Background(), value.runner, value.directory); err == nil {
				t.Fatal("ambiguous restored backup accepted")
			}
		})
	}
}

func TestMoreAtomicAndCopyFailures(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(destination, []byte("exists"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyRegular(source, destination, 0o600); err == nil ||
		err.Error() != "SETUP_BACKUP_CREATE_FAILED" {
		t.Fatalf("existing copy destination accepted: %v", err)
	}
	if err := copyRegular(filepath.Join(root, "missing"), filepath.Join(root, "missing-copy"), 0o600); err == nil ||
		err.Error() != "SETUP_BACKUP_READ_FAILED" {
		t.Fatalf("missing copy source accepted: %v", err)
	}
	if err := writeAtomic(filepath.Join(root, "oversized"), make([]byte, (4<<20)+1), 0o600); err == nil {
		t.Fatal("oversized atomic data accepted")
	}
	parentFile := filepath.Join(root, "parent-file")
	if err := os.WriteFile(parentFile, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(parentFile, "child"), []byte("data"), 0o600); err == nil ||
		err.Error() != "SETUP_FILE_DIRECTORY_FAILED" {
		t.Fatalf("file parent accepted as directory: %v", err)
	}
	targetDirectory := filepath.Join(root, "target-directory")
	if err := os.Mkdir(targetDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(targetDirectory, []byte("data"), 0o600); err == nil ||
		err.Error() != "SETUP_FILE_TARGET_UNSAFE" {
		t.Fatalf("directory accepted as atomic target: %v", err)
	}
	largeSource := filepath.Join(root, "large-source")
	if err := os.WriteFile(largeSource, make([]byte, (4<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := digestRegular(largeSource); err == nil || err.Error() != "SETUP_BACKUP_DIGEST_FAILED" {
		t.Fatalf("oversized digest source accepted: %v", err)
	}
	largeDestination := filepath.Join(root, "large-copy")
	if err := copyRegular(largeSource, largeDestination, 0o600); err == nil ||
		err.Error() != "SETUP_BACKUP_FILE_TOO_LARGE" {
		t.Fatalf("oversized copy source accepted: %v", err)
	}
	if _, err := os.Stat(largeDestination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed oversized copy was not removed: %v", err)
	}
}

func TestRestoreUnitOrderPlacesUnknownUnitsLast(t *testing.T) {
	ordered := restoreUnitOrder([]string{"z.service", "docker.socket", "nftfw-vpn.service", "a.service", "nftfw-early.service", "docker.service"})
	if strings.Join(ordered, ",") != "docker.service,docker.socket,nftfw-early.service,nftfw-vpn.service,a.service,z.service" {
		t.Fatalf("unexpected restore order: %v", ordered)
	}
}

func TestDockerRestoreClearsOnlyBackedUpActiveUnits(t *testing.T) {
	tests := []struct {
		name        string
		units       []string
		active      []string
		wantReset   string
		wantActions []string
		forbidReset bool
	}{
		{
			name: "socket-present", units: []string{"docker.service", "docker.socket", "nftfw-web.service"},
			active:      []string{"docker.service"},
			wantReset:   "systemctl reset-failed docker.service docker.socket",
			wantActions: []string{"systemctl restart docker.service", "systemctl stop docker.socket"},
		},
		{
			name: "socket-absent", units: []string{"docker.service", "nftfw-web.service"},
			active:      []string{"docker.service"},
			wantReset:   "systemctl reset-failed docker.service",
			wantActions: []string{"systemctl restart docker.service"},
		},
		{
			name: "originally-inactive", units: []string{"docker.service", "docker.socket", "nftfw-web.service"},
			forbidReset: true,
			wantActions: []string{"systemctl stop docker.service", "systemctl stop docker.socket"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "daemon.json")
			if err := os.WriteFile(source, []byte("before\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runner := &backupRunner{success: map[string]bool{}}
			for _, unit := range test.active {
				runner.success["systemctl is-active --quiet "+unit] = true
			}
			directory := filepath.Join(root, "backup")
			if _, err := createBackup(context.Background(), runner, directory,
				[]string{source}, test.units, nil); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(source, []byte("changed\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runner.commands = nil
			if err := restoreBackup(context.Background(), runner, directory); err != nil {
				t.Fatal(err)
			}
			if data, _ := os.ReadFile(source); string(data) != "before\n" {
				t.Fatalf("Docker file was not restored first: %q", data)
			}
			joined := strings.Join(runner.commands, "\n")
			if test.forbidReset && strings.Contains(joined, "reset-failed") {
				t.Fatalf("inactive Docker state was reset:\n%s", joined)
			}
			if test.wantReset != "" && !strings.Contains(joined, test.wantReset) {
				t.Fatalf("missing narrow reset %q:\n%s", test.wantReset, joined)
			}
			if strings.Contains(joined, "reset-failed nftfw-web.service") {
				t.Fatalf("unrelated unit was reset:\n%s", joined)
			}
			for _, action := range test.wantActions {
				if !strings.Contains(joined, action) {
					t.Fatalf("missing restore action %q:\n%s", action, joined)
				}
			}
		})
	}
}

func TestDockerRestoreReportsResetAndRestartFailures(t *testing.T) {
	for _, test := range []struct {
		fail string
		want string
	}{
		{"reset-failed docker.service", "SETUP_BACKUP_RESTORE_DOCKER_RESET_FAILED"},
		{"restart docker.service", "SETUP_BACKUP_RESTORE_DOCKER_RESTART_FAILED"},
	} {
		t.Run(test.fail, func(t *testing.T) {
			root := t.TempDir()
			runner := &backupRunner{success: map[string]bool{
				"systemctl is-active --quiet docker.service": true,
			}}
			directory := filepath.Join(root, "backup")
			if _, err := createBackup(context.Background(), runner, directory,
				nil, []string{"docker.service"}, nil); err != nil {
				t.Fatal(err)
			}
			runner.fail = test.fail
			err := restoreBackup(context.Background(), runner, directory)
			if err == nil || err.Error() != test.want {
				t.Fatalf("restore error=%v want=%s", err, test.want)
			}
		})
	}
}

func testTime() time.Time {
	return time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
}
