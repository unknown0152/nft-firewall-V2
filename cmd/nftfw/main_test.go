package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateBackupAndVerify(t *testing.T) {
	dir := t.TempDir()
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
	if err := stateCommand([]string{"verify", "--database", filepath.Join(t.TempDir(), "flag.db")}); err != nil {
		t.Fatal(err)
	}
}
