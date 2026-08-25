package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/health"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/version"
)

type doctorChecksRunner struct {
	sequence *[]string
}

func (r doctorChecksRunner) Run(_ context.Context, args ...string) (string, string, error) {
	if len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "ruleset" {
		*r.sequence = append(*r.sequence, "foreign-audit")
		return `{"nftables":[{"metainfo":{"json_schema_version":1}}]}`, "", nil
	}
	if len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		return `{"nftables":[]}`, "", nil
	}
	if len(args) >= 2 && args[0] == "--check" && args[1] == "--file" {
		*r.sequence = append(*r.sequence, "candidate-check")
		return "", "", nil
	}
	return "", "", nil
}

func TestDoctorPreflightsBeforeGlobalLockAndRevalidatesUnderIt(t *testing.T) {
	lockDir := t.TempDir()
	if err := os.Chmod(lockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var sequence []string
	preflight := func(preflightCtx context.Context) error {
		sequence = append(sequence, "preflight")
		release, err := state.AcquireMutationLock(preflightCtx, lockDir)
		if err != nil {
			return err
		}
		release()
		return nil
	}
	revalidate := func(lockedCtx context.Context) error {
		sequence = append(sequence, "locked-revalidation")
		if !state.MutationLockHeld(lockedCtx) {
			return errors.New("doctor revalidation lacks held-lock marker")
		}
		waitCtx, waitCancel := context.WithTimeout(lockedCtx, 30*time.Millisecond)
		defer waitCancel()
		if release, err := state.AcquireMutationLock(waitCtx, lockDir); err == nil {
			release()
			return errors.New("doctor revalidation ran without the actual global lock")
		}
		return nil
	}
	backend := nft.New(doctorChecksRunner{sequence: &sequence})
	if _, err := doctorProtectedChecks(ctx, lockDir, backend, "table inet nftfw_filter { }\n", preflight, revalidate); err != nil {
		t.Fatal(err)
	}
	want := []string{"preflight", "foreign-audit", "candidate-check", "locked-revalidation"}
	if strings.Join(sequence, ",") != strings.Join(want, ",") {
		t.Fatalf("doctor check order=%v want=%v", sequence, want)
	}
	release, err := state.AcquireMutationLock(ctx, lockDir)
	if err != nil {
		t.Fatalf("doctor did not release global lock: %v", err)
	}
	release()
}

func TestStateBackupAndVerify(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(dir, "state.db")
	backup := filepath.Join(dir, "backup", "state.db")
	store, err := state.Open(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NFTFW_RUNTIME_DIR", runtimeDir)
	if err := stateCommand([]string{"verify", "--database", database}); err != nil {
		t.Fatal(err)
	}
	if err := stateCommand([]string{"backup", backup, "--database", database}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(backup); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup missing or unsafe: info=%v err=%v", info, err)
	}
	if err := stateCommand([]string{"backup", "relative.db", "--database", database}); err == nil {
		t.Fatal("relative backup destination accepted")
	}
}

func TestStateOfflineMigrationCommand(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "legacy.db")
	backup := filepath.Join(root, "backups", "legacy.db")
	destination := filepath.Join(root, "generation-state", "state.db")
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE generations (
 id INTEGER PRIMARY KEY, checksum TEXT NOT NULL, script_path TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','applied','committed','rolled_back')),
 created_at TEXT NOT NULL, rollback_deadline TEXT,
 previous_id INTEGER REFERENCES generations(id)
);
CREATE INDEX generations_status_idx ON generations(status);
CREATE TABLE claims (
 id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL,
 family TEXT NOT NULL CHECK(family IN ('ipv4','ipv6')), source TEXT NOT NULL,
 reason TEXT NOT NULL, actor TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT
);
CREATE INDEX claims_address_idx ON claims(address, family);
CREATE TABLE audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
 actor TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL
);
INSERT INTO schema_migrations VALUES(1, '2026-01-01T00:00:00Z');
`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source, 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NFTFW_RUNTIME_DIR", runtimeDir)
	if err := stateCommand([]string{
		"migrate", destination,
		"--database", source,
		"--backup", backup,
	}); err != nil {
		t.Fatal(err)
	}
	if err := stateCommand([]string{"verify", "--database", destination}); err != nil {
		t.Fatal(err)
	}
	sourceBytes, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	backupBytes, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if string(sourceBytes) != string(backupBytes) {
		t.Fatal("state migrate backup is not byte-identical")
	}
	if err := stateCommand([]string{"migrate", filepath.Join(root, "other.db"), "--database", source}); err == nil {
		t.Fatal("state migrate accepted a missing --backup")
	}
}

func TestHealthContractFailsClosed(t *testing.T) {
	const policyHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	healthy := health.Snapshot{
		Schema: health.StatusSchema, Status: "HEALTHY", Active: true,
		PolicyMatch: true, KillSwitchEnforced: true, PolicyHash: policyHash, PolicyChecksum: policyHash,
	}
	if !statusHealthy(healthy) {
		t.Fatal("complete healthy status contract was rejected")
	}
	mutations := []func(*health.Snapshot){
		func(s *health.Snapshot) { s.Schema = "" },
		func(s *health.Snapshot) { s.Status = "DEGRADED" },
		func(s *health.Snapshot) { s.Active = false },
		func(s *health.Snapshot) { s.PolicyMatch = false },
		func(s *health.Snapshot) { s.KillSwitchEnforced = false },
		func(s *health.Snapshot) { s.PolicyHash = "" },
		func(s *health.Snapshot) { s.PolicyHash = strings.ToUpper(policyHash) },
		func(s *health.Snapshot) { s.PolicyChecksum = "" },
		func(s *health.Snapshot) { s.PolicyChecksum = strings.Repeat("f", 64) },
	}
	for index, mutate := range mutations {
		candidate := healthy
		mutate(&candidate)
		if statusHealthy(candidate) {
			t.Fatalf("incomplete status contract %d was accepted: %#v", index, candidate)
		}
	}
}

func TestStateCommandRejectsUnknownArguments(t *testing.T) {
	if err := stateCommand([]string{"restore", "/tmp/state.db"}); err == nil {
		t.Fatal("unsupported destructive restore command accepted")
	}
	if err := stateCommand([]string{"verify", "extra"}); err == nil {
		t.Fatal("unexpected state argument accepted")
	}
}

func TestStateDatabaseFlagOverridesEnvironment(t *testing.T) {
	t.Setenv("NFTFW_STATE_DB", filepath.Join(t.TempDir(), "environment.db"))
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(directory, "flag.db")
	store, err := state.Open(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stateCommand([]string{"verify", "--database", database}); err != nil {
		t.Fatal(err)
	}
}

func TestStateVerifyNeverCreatesOrMigratesMissingState(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(directory, "missing.db")
	if err := stateCommand([]string{"verify", "--database", database}); err == nil {
		t.Fatal("missing database was accepted")
	}
	if _, err := os.Lstat(database); !os.IsNotExist(err) {
		t.Fatalf("verify created missing state: %v", err)
	}
}

func TestSecuritySensitiveCommandsRejectTrailingArguments(t *testing.T) {
	for _, args := range [][]string{
		{"version", "extra"},
		{"apply", "--safe", "--safe"},
		{"commit", "1", "extra"},
		{"rollback", "0"},
		{"reconcile", "extra"},
		{"blocks", "list", "extra"},
		{"block", "remove", "1", "extra"},
		{"wg", "status", "extra"},
	} {
		if err := run(args); err == nil {
			t.Fatalf("ambiguous command accepted: %#v", args)
		}
	}
}

func TestStageRCandidateOnlyAllowsVersionAndNothingElse(t *testing.T) {
	previous := version.BuildDisposition
	previousVersion := version.Version
	version.BuildDisposition = version.StageRCandidateOnly
	t.Cleanup(func() {
		version.BuildDisposition = previous
		version.Version = previousVersion
	})

	for _, args := range [][]string{{"version"}, {"version", "--json"}} {
		if err := run(args); err != nil {
			t.Fatalf("candidate version command %v was rejected: %v", args, err)
		}
	}
	for _, args := range [][]string{
		{"config", "validate", "/does/not/exist"},
		{"plan"},
		{"status"},
		{"state", "verify"},
	} {
		err := run(args)
		if err == nil || !strings.Contains(err.Error(), "candidate-only build is quarantined") {
			t.Fatalf("candidate command %v did not fail at the quarantine gate: %v", args, err)
		}
	}
	version.BuildDisposition = "release"
	version.Version = "2.0.2~stage.r.aaaaaaaaaaaa"
	if err := run([]string{"status"}); err == nil || !strings.Contains(err.Error(), "candidate-only build is quarantined") {
		t.Fatalf("candidate version escaped CLI quarantine under forged disposition: %v", err)
	}
}
