package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

type fallbackRunner struct {
	tables  string
	scripts []string
}

func (r *fallbackRunner) Run(_ context.Context, args ...string) (string, string, error) {
	if len(args) >= 3 && args[0] == "-j" {
		return r.tables, "", nil
	}
	if len(args) >= 2 && (args[0] == "--check" || args[0] == "--file") {
		content, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return "", "", err
		}
		r.scripts = append(r.scripts, string(content))
	}
	return "", "", nil
}

func TestRollbackFallbackRestoresSnapshotOrRemovesFirstGeneration(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := state.Open(ctx, filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	script := nft.EmergencyDenyScript
	sum := sha256.Sum256([]byte(script))
	if err := store.PublishActive(script, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	store.Close()
	runner := &fallbackRunner{tables: `{"nftables":[]}`}
	if err := restoreRollbackFallback(ctx, dir, nft.New(runner)); err != nil {
		t.Fatal(err)
	}
	if len(runner.scripts) != 2 || !strings.Contains(runner.scripts[1], "nftfw:output-default-deny") {
		t.Fatalf("committed fallback was not checked and applied: %#v", runner.scripts)
	}

	firstDir := t.TempDir()
	runner = &fallbackRunner{tables: `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`}
	if err := restoreRollbackFallback(ctx, firstDir, nft.New(runner)); err != nil {
		t.Fatal(err)
	}
	if len(runner.scripts) != 1 || !strings.Contains(runner.scripts[0], "destroy table inet nftfw_filter") {
		t.Fatalf("first-generation fallback did not remove only owned state: %#v", runner.scripts)
	}
}
