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
}

func (r *backupRunner) Run(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if r.fail != "" && strings.Contains(command, r.fail) {
		return nil, errors.New("injected")
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
	store := FileJournal{Path: filepath.Join(root, "journal.json")}
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
	ordered := restoreUnitOrder([]string{"z.service", "nftfw-vpn.service", "a.service", "nftfw-early.service"})
	if strings.Join(ordered, ",") != "nftfw-early.service,nftfw-vpn.service,a.service,z.service" {
		t.Fatalf("unexpected restore order: %v", ordered)
	}
}

func testTime() time.Time {
	return time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
}
