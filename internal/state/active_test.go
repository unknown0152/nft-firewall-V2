package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActiveSnapshotLifecycle(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(context.Background(), filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	script := "table inet nftfw_filter { }\n"
	sum := sha256.Sum256([]byte(script))
	checksum := hex.EncodeToString(sum[:])
	if err := store.PublishActive(script, checksum); err != nil {
		t.Fatal(err)
	}
	got, enabled, err := LoadActiveSnapshot(dir)
	if err != nil || !enabled || got != script {
		t.Fatalf("load snapshot: enabled=%t script=%q err=%v", enabled, got, err)
	}
	for _, name := range []string{activeSnapshotName, activeMarkerName} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("unsafe %s mode: %v %v", name, info, err)
		}
	}
	if err := store.ClearActive(); err != nil {
		t.Fatal(err)
	}
	if _, enabled, err := LoadActiveSnapshot(dir); err != nil || enabled {
		t.Fatalf("cleared snapshot remains enabled: %t %v", enabled, err)
	}
}

func TestActiveSnapshotFailsClosedOnDamage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, activeMarkerName), []byte("enabled\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, enabled, err := LoadActiveSnapshot(dir); err == nil || !enabled {
		t.Fatalf("missing snapshot did not fail closed: enabled=%t err=%v", enabled, err)
	}
	bad := `{"checksum":"` + strings.Repeat("0", 64) + `","script":"table inet nftfw_filter {}"}`
	if err := os.WriteFile(filepath.Join(dir, activeSnapshotName), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, enabled, err := LoadActiveSnapshot(dir); err == nil || !enabled {
		t.Fatalf("bad checksum did not fail closed: enabled=%t err=%v", enabled, err)
	}
}

func TestActiveSnapshotRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "marker")
	if err := os.WriteFile(target, []byte("enabled\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, activeMarkerName)); err != nil {
		t.Fatal(err)
	}
	if _, enabled, err := LoadActiveSnapshot(dir); err == nil || !enabled {
		t.Fatalf("symlink marker accepted: enabled=%t err=%v", enabled, err)
	}
}

func TestEnforcementMarkerPreventsEmptyDatabaseRecreation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, activeMarkerName), []byte("enabled\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	if store, err := Open(context.Background(), path); err == nil {
		store.Close()
		t.Fatal("missing enforced database was silently recreated")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("state database was created despite enforcement marker: %v", err)
	}
}
