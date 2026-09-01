package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func validBootBackupFixture() *bootBackup {
	return &bootBackup{
		Schema: bootBackupSchema, PreBootID: "11111111-1111-4111-8111-111111111111",
		MountSHA256: strings.Repeat("a", 64), KernelSHA256: strings.Repeat("b", 64),
		InitialGeneratedSHA256:  strings.Repeat("c", 64),
		PreparedGeneratedSHA256: strings.Repeat("d", 64), FragmentSHA256: strings.Repeat("e", 64),
		ResumeGuardSHA256: strings.Repeat("f", 64), ResumeEndpointIPv4: []string{"198.51.100.8"},
		ResumeDockerClean: true,
	}
}

func TestBackupEvidenceHelpersFailClosed(t *testing.T) {
	t.Run("manifest-identity", func(t *testing.T) {
		for _, manifest := range []backupManifest{
			{Schema: "nftfw.setup-backup.v1", Path: "relative"},
			{Schema: "wrong", Path: filepath.Join(t.TempDir(), "backup")},
		} {
			if err := writeBackupManifest(manifest); err == nil ||
				err.Error() != "SETUP_BACKUP_MANIFEST_FAILED" {
				t.Fatalf("invalid manifest identity was accepted: %v", err)
			}
		}
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		manifest := backupManifest{Schema: "nftfw.setup-backup.v1", Path: filepath.Join(blocker, "backup")}
		if err := writeBackupManifest(manifest); err == nil ||
			err.Error() != "SETUP_FILE_DIRECTORY_FAILED" {
			t.Fatalf("manifest beneath a non-directory parent was accepted: %v", err)
		}
	})

	t.Run("directory-identity", func(t *testing.T) {
		if err := validateBackupDirectory("relative"); err == nil || err.Error() != "SETUP_BACKUP_PATH_INVALID" {
			t.Fatalf("relative backup directory was accepted: %v", err)
		}
		root := t.TempDir()
		unsafe := filepath.Join(root, "unsafe")
		if err := os.Mkdir(unsafe, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := validateBackupDirectory(unsafe); err == nil || err.Error() != "SETUP_BACKUP_DIRECTORY_UNSAFE" {
			t.Fatalf("group-accessible backup directory was accepted: %v", err)
		}
		real := filepath.Join(root, "real")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(root, "alias")
		if err := os.Symlink(real, alias); err != nil {
			t.Fatal(err)
		}
		if err := validateBackupDirectory(alias); err == nil || err.Error() != "SETUP_BACKUP_DIRECTORY_UNSAFE" {
			t.Fatalf("aliased backup directory was accepted: %v", err)
		}
	})

	t.Run("payload-and-target", func(t *testing.T) {
		root := t.TempDir()
		payload := filepath.Join(root, "payload")
		if err := os.WriteFile(payload, []byte("baseline\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		digest, err := digestRegular(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateBackupPayload(payload, digest); err != nil {
			t.Fatal(err)
		}
		if err := validateBackupPayload(payload, strings.Repeat("0", 64)); err == nil ||
			err.Error() != "SETUP_BACKUP_RESTORE_CHECKSUM_FAILED" {
			t.Fatalf("changed backup payload was accepted: %v", err)
		}
		if err := os.Chmod(payload, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := validateBackupPayload(payload, digest); err == nil || err.Error() != "SETUP_BACKUP_PAYLOAD_UNSAFE" {
			t.Fatalf("group-readable payload was accepted: %v", err)
		}

		target := filepath.Join(root, "target")
		if err := os.WriteFile(target, []byte("restored\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		targetDigest, err := digestRegular(target)
		if err != nil {
			t.Fatal(err)
		}
		item := backupFile{
			Path: target, Exists: true, Mode: 0o600, SHA256: targetDigest,
			UID: int(stat.Uid), GID: int(stat.Gid),
		}
		if err := validateRestoredTarget(item); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := validateRestoredTarget(item); err == nil ||
			err.Error() != "SETUP_BACKUP_RESTORE_MISMATCH" {
			t.Fatalf("changed restored-target mode was accepted: %v", err)
		}
		if err := os.Chmod(target, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("changed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validateRestoredTarget(item); err == nil ||
			err.Error() != "SETUP_BACKUP_RESTORE_MISMATCH" {
			t.Fatalf("changed restored-target content was accepted: %v", err)
		}
	})

	t.Run("unit-state", func(t *testing.T) {
		command := "systemctl show --property=LoadState,ActiveState nftfw-test.service"
		for _, test := range []struct {
			name     string
			output   string
			expected unitState
		}{
			{name: "unknown-field", output: "LoadState=loaded\nOther=inactive\n"},
			{name: "duplicate", output: "LoadState=loaded\nLoadState=loaded\n"},
			{name: "missing", output: "LoadState=loaded\n"},
			{name: "bad-load", output: "LoadState=masked\nActiveState=inactive\n"},
			{name: "bad-active", output: "LoadState=loaded\nActiveState=failed\n"},
			{name: "active-mismatch", output: "LoadState=loaded\nActiveState=active\n"},
			{name: "enabled-mismatch", output: "LoadState=loaded\nActiveState=inactive\n", expected: unitState{Enabled: true}},
		} {
			t.Run(test.name, func(t *testing.T) {
				runner := &systemRunner{outputs: map[string][]byte{command: []byte(test.output)}}
				if err := verifyRestoredUnit(context.Background(), runner, "nftfw-test.service", test.expected); err == nil ||
					err.Error() != "SETUP_BACKUP_UNIT_MISMATCH" {
					t.Fatalf("ambiguous unit evidence was accepted: %v", err)
				}
			})
		}
	})
}

func TestSelectedBackupRestoreRefusalBoundaries(t *testing.T) {
	newBackup := func(t *testing.T) (string, string, string) {
		t.Helper()
		root := t.TempDir()
		existing := filepath.Join(root, "existing")
		absent := filepath.Join(root, "absent")
		if err := os.WriteFile(existing, []byte("baseline\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		directory := filepath.Join(root, "backup")
		if _, err := createBackup(context.Background(), &systemRunner{}, directory,
			[]string{existing, absent}, nil, nil); err != nil {
			t.Fatal(err)
		}
		return directory, existing, absent
	}
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string, string, string) []string
	}{
		{name: "relative-selection", mutate: func(_ *testing.T, _, _, _ string) []string { return []string{"relative"} }},
		{name: "duplicate-selection", mutate: func(_ *testing.T, _, existing, _ string) []string {
			return []string{existing, existing}
		}},
		{name: "unknown-selection", mutate: func(t *testing.T, directory, _, _ string) []string {
			return []string{filepath.Join(filepath.Dir(directory), "unknown")}
		}},
		{name: "missing-payload", mutate: func(t *testing.T, directory, existing, _ string) []string {
			if err := os.Remove(filepath.Join(directory, "file-000")); err != nil {
				t.Fatal(err)
			}
			return []string{existing}
		}},
		{name: "changed-payload", mutate: func(t *testing.T, directory, existing, _ string) []string {
			if err := os.WriteFile(filepath.Join(directory, "file-000"), []byte("changed\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return []string{existing}
		}},
		{name: "unsafe-absent-target", mutate: func(t *testing.T, _, _, absent string) []string {
			if err := os.Mkdir(absent, 0o700); err != nil {
				t.Fatal(err)
			}
			return []string{absent}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory, existing, absent := newBackup(t)
			required := test.mutate(t, directory, existing, absent)
			if err := restoreBackupFiles(directory, required); err == nil {
				t.Fatal("unsafe selected restore was accepted")
			}
		})
	}
}

func TestVerifiedBackupManifestTopologyRefusals(t *testing.T) {
	type backupFixture struct {
		directory string
		existing  string
		absent    string
		manifest  backupManifest
	}
	newFixture := func(t *testing.T) backupFixture {
		t.Helper()
		root := t.TempDir()
		existing := filepath.Join(root, "existing")
		absent := filepath.Join(root, "absent")
		if err := os.WriteFile(existing, []byte("baseline\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		directory := filepath.Join(root, "backup")
		manifest, err := createBackup(context.Background(), &systemRunner{}, directory,
			[]string{existing, absent}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return backupFixture{directory: directory, existing: existing, absent: absent, manifest: manifest}
	}
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *backupFixture)
	}{
		{name: "missing-manifest", mutate: func(t *testing.T, value *backupFixture) {
			if err := os.Remove(filepath.Join(value.directory, "manifest.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "relative-target", mutate: func(t *testing.T, value *backupFixture) {
			value.manifest.Files[0].Path = "relative"
			if err := writeBackupManifest(value.manifest); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wrong-payload-name", mutate: func(t *testing.T, value *backupFixture) {
			value.manifest.Files[0].Backup = "file-999"
			if err := writeBackupManifest(value.manifest); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "absent-has-metadata", mutate: func(t *testing.T, value *backupFixture) {
			value.manifest.Files[1].Backup = "foreign"
			if err := writeBackupManifest(value.manifest); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "absent-now-exists", mutate: func(t *testing.T, value *backupFixture) {
			if err := os.WriteFile(value.absent, []byte("foreign\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "missing-resume-guard", mutate: func(t *testing.T, value *backupFixture) {
			value.manifest.Boot = validBootBackupFixture()
			value.manifest.Boot.ResumeGuardSHA256 = strings.Repeat("a", 64)
			if err := writeBackupManifest(value.manifest); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := newFixture(t)
			test.mutate(t, &value)
			if _, err := verifyRestoredBackup(context.Background(), &systemRunner{}, value.directory); err == nil {
				t.Fatal("ambiguous backup topology was accepted")
			}
		})
	}
}

func TestReadBackupRejectsCanonicalButInvalidIdentityFields(t *testing.T) {
	newManifest := func(t *testing.T) backupManifest {
		t.Helper()
		directory := filepath.Join(t.TempDir(), "backup")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		return backupManifest{
			Schema: "nftfw.setup-backup.v1", Path: directory,
			Units: map[string]unitState{}, Sysctls: map[string]string{},
		}
	}
	for _, test := range []struct {
		name   string
		mutate func(*backupManifest)
	}{
		{name: "prepared-digest", mutate: func(value *backupManifest) { value.PreparedSHA256 = strings.Repeat("A", 64) }},
		{name: "boot-identity", mutate: func(value *backupManifest) {
			value.Boot = validBootBackupFixture()
			value.Boot.PreBootID = "invalid"
		}},
		{name: "file-digest", mutate: func(value *backupManifest) {
			value.Files = []backupFile{{Path: filepath.Join(value.Path, "target"), Exists: true, SHA256: "invalid"}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := newManifest(t)
			test.mutate(&manifest)
			if err := writeBackupManifest(manifest); err != nil {
				t.Fatal(err)
			}
			if _, err := readBackup(manifest.Path); err == nil || err.Error() != "SETUP_BACKUP_MANIFEST_INVALID" {
				t.Fatalf("invalid canonical manifest was accepted: %v", err)
			}
		})
	}
	t.Run("noncanonical", func(t *testing.T) {
		manifest := newManifest(t)
		if err := writeBackupManifest(manifest); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(manifest.Path, "manifest.json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append([]byte(" "), data...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readBackup(manifest.Path); err == nil || err.Error() != "SETUP_BACKUP_MANIFEST_INVALID" {
			t.Fatalf("noncanonical manifest was accepted: %v", err)
		}
	})
}

func TestCreateBackupRefusesUnsafeSourcesAndRuntimeEvidence(t *testing.T) {
	if _, err := createBackup(context.Background(), &systemRunner{}, "relative", nil, nil, nil); err == nil ||
		err.Error() != "SETUP_BACKUP_PATH_INVALID" {
		t.Fatalf("relative backup destination was accepted: %v", err)
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := createBackup(context.Background(), &systemRunner{}, filepath.Join(root, "unsafe-source"),
		[]string{link}, nil, nil); err == nil || err.Error() != "SETUP_BACKUP_SOURCE_UNSAFE" {
		t.Fatalf("symlinked backup source was accepted: %v", err)
	}
	runner := &systemRunner{fail: "sysctl -n net.ipv4.ip_forward"}
	if _, err := createBackup(context.Background(), runner, filepath.Join(root, "sysctl-failure"),
		nil, nil, []string{"net.ipv4.ip_forward"}); err == nil ||
		err.Error() != "SETUP_BACKUP_SYSCTL_FAILED" {
		t.Fatalf("missing sysctl evidence was accepted: %v", err)
	}
}

func TestJournalHistoryHelpersFailClosed(t *testing.T) {
	if err := syncSetupDirectory(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing directory sync was accepted")
	}
	if err := syncRegularSetupFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file sync was accepted")
	}
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secureHistoryDirectory(filepath.Join(blocker, "history")); err == nil ||
		err.Error() != "SETUP_JOURNAL_HISTORY_CREATE_FAILED" {
		t.Fatalf("history beneath a non-directory parent was accepted: %v", err)
	}
	unsafe := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafe, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := secureHistoryDirectory(unsafe); err == nil || err.Error() != "SETUP_JOURNAL_HISTORY_UNSAFE" {
		t.Fatalf("group-readable history was accepted: %v", err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	if err := secureHistoryDirectory(alias); err == nil || err.Error() != "SETUP_JOURNAL_HISTORY_UNSAFE" {
		t.Fatalf("aliased history was accepted: %v", err)
	}
}

func TestManagedDockerUnitEvidenceRefusalMatrix(t *testing.T) {
	command := "systemctl show --property=LoadState,ActiveState docker.service"
	for _, test := range []struct {
		name   string
		output string
		fail   bool
	}{
		{name: "runner-failure", fail: true},
		{name: "empty"},
		{name: "oversized", output: strings.Repeat("x", 513)},
		{name: "malformed", output: "LoadState\nActiveState=active\n"},
		{name: "unknown-key", output: "LoadState=loaded\nOther=active\n"},
		{name: "empty-value", output: "LoadState=\nActiveState=active\n"},
		{name: "duplicate", output: "LoadState=loaded\nLoadState=loaded\n"},
		{name: "missing", output: "LoadState=loaded\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &systemRunner{outputs: map[string][]byte{command: []byte(test.output)}}
			if test.fail {
				runner.fail = command
			}
			system, _ := testSystem(t, runner)
			if _, err := system.dockerBackupUnitState(context.Background(), "docker.service"); err == nil {
				t.Fatal("ambiguous Docker unit evidence was accepted")
			}
		})
	}
}

func TestResumeEndpointAndNFTTableEvidenceBoundaries(t *testing.T) {
	if _, err := preparedResumeEndpoints(nil); err == nil || err.Error() != "SETUP_PREPARED_IDENTITY_FAILED" {
		t.Fatalf("nil prepared state was accepted: %v", err)
	}
	for _, values := range [][]string{{"invalid"}, {"192.0.2.1/24"}, {"192.0.2.1/32", "192.0.2.1/32"}} {
		private := &prepared{}
		private.Intent.BootstrapIPv4 = values
		if _, err := preparedResumeEndpoints(private); err == nil || err.Error() != "SETUP_PREPARED_IDENTITY_FAILED" {
			t.Fatalf("invalid prepared endpoint set was accepted: %v", err)
		}
	}

	for _, test := range []struct {
		name   string
		output []byte
		names  []string
	}{
		{name: "empty", names: []string{"inet/a"}},
		{name: "malformed", output: []byte("not-json"), names: []string{"inet/a"}},
		{name: "duplicate-request", output: []byte(`{"nftables":[]}`), names: []string{"inet/a", "inet/a"}},
		{name: "unexpected-table", output: []byte(`{"nftables":[{"table":{"family":"inet","name":"b"}}]}`), names: []string{"inet/a"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &systemRunner{outputs: map[string][]byte{"nft --json list ruleset": test.output}}
			system, _ := testSystem(t, runner)
			if err := system.requireExactNFTTables(context.Background(), test.names...); err == nil ||
				err.Error() != "SETUP_RESUME_GUARD_VERIFY_FAILED" {
				t.Fatalf("ambiguous nftables evidence was accepted: %v", err)
			}
		})
	}
}

func TestBootOwnershipHelperRefusalBranches(t *testing.T) {
	t.Run("efi-manager-missing", func(t *testing.T) {
		fixture := newBootFixture(t)
		if err := os.Remove(fixture.paths.EFIBootManager); err != nil {
			t.Fatal(err)
		}
		if err := verifyEFIBootIdentity(context.Background(), fixture, fixture.paths, "x86_64"); err == nil ||
			err.Error() != "SETUP_EFI_BOOT_IDENTITY_UNSUPPORTED" {
			t.Fatalf("missing EFI manager was accepted: %v", err)
		}
	})
	t.Run("efi-package-unverifiable", func(t *testing.T) {
		fixture := newBootFixture(t)
		fixture.fail = "dpkg-query"
		if err := verifyEFIBootIdentity(context.Background(), fixture, fixture.paths, "x86_64"); err == nil ||
			err.Error() != "SETUP_EFI_BOOT_IDENTITY_UNSUPPORTED" {
			t.Fatalf("unverifiable EFI package owner was accepted: %v", err)
		}
	})
	t.Run("boot-hold-publication", func(t *testing.T) {
		missingParent := filepath.Join(t.TempDir(), "missing", "marker")
		if err := publishBootHoldMarker(missingParent); err == nil ||
			err.Error() != "SETUP_BOOT_HOLD_CREATE_FAILED" {
			t.Fatalf("marker beneath a missing protected parent was accepted: %v", err)
		}
		path := filepath.Join(t.TempDir(), "marker")
		if err := publishBootHoldMarker(path); err != nil {
			t.Fatal(err)
		}
		if err := publishBootHoldMarker(path); err == nil || err.Error() != "SETUP_BOOT_HOLD_FOREIGN" {
			t.Fatalf("existing boot-hold marker was overwritten: %v", err)
		}
	})
	t.Run("boot-path-helpers", func(t *testing.T) {
		if fourHexDigits("123") || fourHexDigits("12x4") || !fourHexDigits("aB09") {
			t.Fatal("EFI hexadecimal identity parser accepted an ambiguous value")
		}
		root := t.TempDir()
		real := filepath.Join(root, "real")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(root, "alias")
		if err := os.Symlink(real, alias); err != nil {
			t.Fatal(err)
		}
		if err := requireBootDirectory(alias); err == nil || err.Error() != "SETUP_BOOT_DIRECTORY_UNSAFE" {
			t.Fatalf("aliased boot directory was accepted: %v", err)
		}
		if _, err := digestBootRegular(filepath.Join(root, "missing"), 1024); err == nil {
			t.Fatal("missing boot payload was digested")
		}
	})
}

func TestBootAndDockerHoldRecoveryRefusalBranches(t *testing.T) {
	t.Run("boot-wait-canceled", func(t *testing.T) {
		fixture := newBootFixture(t)
		system, journalPath := managedBootSystem(t, fixture)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := system.WaitBootHold(ctx, FileJournal{Path: journalPath}); err == nil ||
			err.Error() != "SETUP_BOOT_HOLD_CANCELED" {
			t.Fatalf("canceled boot hold was not preserved: %v", err)
		}
	})
	t.Run("boot-ready-without-journal", func(t *testing.T) {
		fixture := newBootFixture(t)
		system, journalPath := managedBootSystem(t, fixture)
		writeFixture(t, system.Paths.BootHoldReady, []byte(bootHoldReadyData), 0o600)
		if err := system.WaitBootHold(context.Background(), FileJournal{Path: journalPath}); err == nil ||
			err.Error() != "SETUP_BOOT_HOLD_STATE_INVALID" {
			t.Fatalf("ready marker without a protected journal was accepted: %v", err)
		}
	})
	t.Run("docker-ready-publication", func(t *testing.T) {
		fixture := newBootFixture(t)
		system, _ := managedBootSystem(t, fixture)
		if err := publishBootHoldMarker(system.Paths.BootHoldMarker); err != nil {
			t.Fatal(err)
		}
		writeFixture(t, system.Paths.DockerHoldService, []byte(dockerServiceHoldDropInData), 0o644)
		writeFixture(t, system.Paths.DockerHoldSocket, []byte(dockerSocketHoldDropInData), 0o644)
		if err := system.WaitDockerHold(context.Background()); err == nil ||
			err.Error() != "SETUP_BOOT_HOLD_RELEASE_FAILED" {
			t.Fatalf("Docker readiness beneath a missing runtime parent was accepted: %v", err)
		}
	})
	for _, operation := range []struct {
		name string
		call func(*System) error
	}{
		{name: "release", call: func(s *System) error { return s.releaseDockerHold() }},
		{name: "cleanup", call: func(s *System) error { return s.cleanupDockerHold(context.Background()) }},
	} {
		t.Run("partial-generator-"+operation.name, func(t *testing.T) {
			fixture := newBootFixture(t)
			system, _ := managedBootSystem(t, fixture)
			writeFixture(t, system.Paths.DockerHoldService, []byte(dockerServiceHoldDropInData), 0o644)
			if err := operation.call(system); err == nil || err.Error() != "SETUP_DOCKER_HOLD_STATE_INVALID" {
				t.Fatalf("partial generator state was accepted: %v", err)
			}
		})
	}
}

func TestManagedFinalizationSecurityFailureBranches(t *testing.T) {
	t.Run("missing-managed-plan", func(t *testing.T) {
		system, _ := testSystem(t, &systemRunner{})
		plan := Plan{Summary: Summary{BootPolicy: ManagedBootPolicy}}
		if err := system.PublishFinalDependencies(context.Background(), plan); err == nil ||
			err.Error() != "SETUP_BOOT_HOLD_STATE_INVALID" {
			t.Fatalf("managed handoff without private identity was accepted: %v", err)
		}
	})
	t.Run("missing-backup", func(t *testing.T) {
		system, _ := testSystem(t, &systemRunner{})
		plan := Plan{
			Summary:     Summary{BootPolicy: ManagedBootPolicy},
			PrivateData: &prepared{BackupDir: filepath.Join(system.Paths.StateDir, "setup", "backups", "missing")},
		}
		if err := system.PublishFinalDependencies(context.Background(), plan); err == nil ||
			err.Error() != "SETUP_BOOT_HOLD_RESTORE_FAILED" {
			t.Fatalf("managed handoff without exact backup was accepted: %v", err)
		}
	})
	t.Run("service-activation", func(t *testing.T) {
		runner := &systemRunner{fail: "systemctl start nftfw-vpn.service"}
		system, _ := testSystem(t, runner)
		if err := system.EnableBoot(context.Background(), Plan{}); err == nil ||
			err.Error() != "SETUP_BOOT_ACTIVATION_FAILED" {
			t.Fatalf("failed final service activation was accepted: %v", err)
		}
	})
	t.Run("resume-guard-removal", func(t *testing.T) {
		runner := systemRunnerFunc(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
			command := name + " " + strings.Join(args, " ")
			switch command {
			case "nft list table inet " + resumeGuardTable:
				return []byte("present\n"), nil
			case "nft delete table inet " + resumeGuardTable:
				return nil, errors.New("injected")
			default:
				return nil, nil
			}
		})
		system := &System{Runner: runner, Paths: Paths{RuntimeDir: t.TempDir()}}
		if err := system.removeResumeGuard(context.Background()); err == nil ||
			err.Error() != "SETUP_RESUME_GUARD_REMOVE_FAILED" {
			t.Fatalf("failed resume-guard removal was accepted: %v", err)
		}
	})
}
