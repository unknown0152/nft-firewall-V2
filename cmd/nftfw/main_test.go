package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/health"
)

func TestStateBackupAndVerify(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(dir, "state.db")
	backup := filepath.Join(dir, "backup", "state.db")
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
	if err := stateCommand([]string{"verify", "--database", filepath.Join(directory, "flag.db")}); err != nil {
		t.Fatal(err)
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
