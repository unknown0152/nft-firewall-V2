package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
)

func TestActiveSnapshotLifecycle(t *testing.T) {
	dir := secureTestDir(t)
	store, err := Open(context.Background(), filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	script := "table inet nftfw_filter { }\n"
	sum := sha256.Sum256([]byte(script))
	checksum := hex.EncodeToString(sum[:])
	metadata := testGenerationMetadata(t)
	ledger, err := provenance.Open(context.Background(), filepath.Join(dir, "provenance-ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve(context.Background(), metadata.Provenance); err != nil {
		ledger.Close()
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveGenerationWithMetadata(context.Background(), 1, checksum, script, nil, nil, metadata); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	got, enabled, err := LoadActiveSnapshot(dir)
	if err != nil || !enabled || got != script {
		t.Fatalf("load snapshot: enabled=%t script=%q err=%v", enabled, got, err)
	}
	for _, path := range []string{filepath.Join(dir, activeMarkerName), generationSnapshotPath(dir, 1)} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("unsafe %s mode: %v %v", path, info, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, activeSnapshotName)); !os.IsNotExist(err) {
		t.Fatalf("legacy mutable snapshot was published: %v", err)
	}
	pointer, exists, err := ReadEnforcementPointer(dir)
	if err != nil || !exists {
		t.Fatalf("published pointer unavailable: %#v %t %v", pointer, exists, err)
	}
	durable, err := EnsurePublishedGenerationDurable(dir, *pointer)
	if err != nil || durable.Generation != 1 || durable.Script != script {
		t.Fatalf("published generation durability failed: %#v %v", durable, err)
	}
	wrong := *pointer
	wrong.Generation = 2
	if _, err := EnsurePublishedGenerationDurable(dir, wrong); err == nil {
		t.Fatal("changed expected pointer was accepted")
	}
	prepared, err := PrepareEnforcementPointer(dir, *pointer)
	if err != nil {
		t.Fatal(err)
	}
	if err := CancelPreparedPointer(prepared); err != nil {
		t.Fatal(err)
	}
	if err := CancelPreparedPointer(prepared); err != nil {
		t.Fatal(err)
	}
	if err := PublishPreparedPointer(nil); err == nil {
		t.Fatal("nil prepared pointer accepted")
	}
	if err := store.ClearActive(); err != nil {
		t.Fatal(err)
	}
	if _, enabled, err := LoadActiveSnapshot(dir); err != nil || enabled {
		t.Fatalf("cleared snapshot remains enabled: %t %v", enabled, err)
	}
}

func TestActiveSnapshotFailsClosedOnDamage(t *testing.T) {
	dir := secureTestDir(t)
	if err := os.WriteFile(filepath.Join(dir, activeMarkerName), []byte("enabled\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, enabled, err := LoadActiveSnapshot(dir); err == nil || !enabled {
		t.Fatalf("missing snapshot did not fail closed: enabled=%t err=%v", enabled, err)
	}
	script := "table inet nftfw_filter { }\n"
	sum := sha256.Sum256([]byte(script))
	pointer := fmt.Sprintf(`{"schema":"%s","generation":9,"checksum":"%s"}`+"\n", pointerSchema, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(filepath.Join(dir, activeMarkerName), []byte(pointer), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, enabled, err := LoadActiveSnapshot(dir); err == nil || !enabled {
		t.Fatalf("missing immutable snapshot did not fail closed: enabled=%t err=%v", enabled, err)
	}
}

func TestActiveSnapshotRejectsSymlink(t *testing.T) {
	dir := secureTestDir(t)
	target := filepath.Join(secureTestDir(t), "marker")
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
	dir := secureTestDir(t)
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
