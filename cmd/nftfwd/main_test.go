package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

type fallbackRunner struct {
	tables  string
	scripts []string
}

func (r *fallbackRunner) Run(_ context.Context, args ...string) (string, string, error) {
	if len(args) >= 5 && args[0] == "-j" && args[1] == "list" && args[2] == "table" {
		return fmt.Sprintf(`{"nftables":[{"table":{"family":%q,"name":%q}}]}`, args[3], args[4]), "", nil
	}
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

func TestRollbackExpiredWithoutRuntimeRequiresDurableExpiredPendingState(t *testing.T) {
	ctx := context.Background()
	noPendingPath := filepath.Join(secureTestDir(t), "state.db")
	store, err := state.Open(ctx, noPendingPath)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	runner := &fallbackRunner{tables: `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`}
	rolledBack, err := rollbackExpiredWithoutRuntime(ctx, noPendingPath, nft.New(runner))
	if err != nil || rolledBack || len(runner.scripts) != 0 {
		t.Fatalf("no-pending fallback mutated nftables: rolled_back=%t scripts=%#v err=%v", rolledBack, runner.scripts, err)
	}

	futurePath := filepath.Join(secureTestDir(t), "state.db")
	store, err = state.Open(ctx, futurePath)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(time.Hour)
	script := nft.EmergencyDenyScript
	sum := sha256.Sum256([]byte(script))
	if err := store.SaveGeneration(ctx, 1, hex.EncodeToString(sum[:]), script, nil, &future); err != nil {
		t.Fatal(err)
	}
	store.Close()
	runner = &fallbackRunner{tables: `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`}
	rolledBack, err = rollbackExpiredWithoutRuntime(ctx, futurePath, nft.New(runner))
	if err != nil || rolledBack || len(runner.scripts) != 0 {
		t.Fatalf("unexpired fallback mutated nftables: rolled_back=%t scripts=%#v err=%v", rolledBack, runner.scripts, err)
	}

	expiredPath := filepath.Join(secureTestDir(t), "state.db")
	store, err = state.Open(ctx, expiredPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveGeneration(ctx, 1, hex.EncodeToString(sum[:]), script, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, 1); err != nil {
		t.Fatal(err)
	}
	previous := uint64(1)
	past := time.Now().UTC().Add(-time.Minute)
	if err := store.SaveGeneration(ctx, 2, hex.EncodeToString(sum[:]), script, &previous, &past); err != nil {
		t.Fatal(err)
	}
	store.Close()
	runner = &fallbackRunner{tables: `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}},{"table":{"family":"ip","name":"nftfw_nat"}},{"table":{"family":"ip6","name":"nftfw_filter6"}}]}`}
	rolledBack, err = rollbackExpiredWithoutRuntime(ctx, expiredPath, nft.New(runner))
	if err != nil || !rolledBack || len(runner.scripts) != 2 {
		t.Fatalf("expired fallback was not checked and applied exactly once: rolled_back=%t scripts=%#v err=%v", rolledBack, runner.scripts, err)
	}
	store, err = state.Open(ctx, expiredPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Pending(ctx); err == nil {
		t.Fatal("expired generation remained pending after fallback rollback")
	}
	publication, err := store.ClaimPublicationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if publication.DesiredRevision == publication.AppliedRevision {
		t.Fatalf("fallback rollback falsely marked mutable claims published: %+v", publication)
	}
}

func TestRollbackExpiredWithoutRuntimeRecoversCorruptDatabaseConservatively(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t)
	databasePath := filepath.Join(dir, "state.db")
	store, err := state.Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	script := nft.EmergencyDenyScript
	sum := sha256.Sum256([]byte(script))
	if err := store.PublishActive(script, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(databasePath, []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fallbackRunner{tables: `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}},{"table":{"family":"ip","name":"nftfw_nat"}},{"table":{"family":"ip6","name":"nftfw_filter6"}}]}`}
	recovered, err := rollbackExpiredWithoutRuntime(ctx, databasePath, nft.New(runner))
	if err != nil || !recovered || len(runner.scripts) != 2 || runner.scripts[0] != runner.scripts[1] {
		t.Fatalf("corrupt database did not restore the verified committed snapshot: recovered=%t scripts=%#v err=%v", recovered, runner.scripts, err)
	}

	unmarkedDir := secureTestDir(t)
	unmarkedDB := filepath.Join(unmarkedDir, "state.db")
	if err := os.WriteFile(unmarkedDB, []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner = &fallbackRunner{tables: `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`}
	if recovered, err := rollbackExpiredWithoutRuntime(ctx, unmarkedDB, nft.New(runner)); err == nil || recovered || !strings.Contains(err.Error(), "refusing automatic deletion") {
		t.Fatalf("corrupt unmarked state adopted product-named tables: recovered=%t err=%v", recovered, err)
	}
	if len(runner.scripts) != 0 {
		t.Fatalf("corrupt unmarked state mutated nftables: %#v", runner.scripts)
	}
}

func TestRollbackFallbackWaitsForClaimPublicationLockBeforeMutation(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t)
	databasePath := filepath.Join(dir, "state.db")
	store, err := state.Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	script := nft.EmergencyDenyScript
	sum := sha256.Sum256([]byte(script))
	if err := store.SaveGeneration(ctx, 1, hex.EncodeToString(sum[:]), script, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, 1); err != nil {
		t.Fatal(err)
	}
	previous := uint64(1)
	past := time.Now().UTC().Add(-time.Minute)
	if err := store.SaveGeneration(ctx, 2, hex.EncodeToString(sum[:]), script, &previous, &past); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	release, err := state.AcquireClaimPublicationLock(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	runner := &fallbackRunner{tables: `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`}
	waitCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	rolledBack, err := rollbackExpiredWithoutRuntime(waitCtx, databasePath, nft.New(runner))
	if rolledBack || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended fallback did not honor its deadline: rolled_back=%t err=%v", rolledBack, err)
	}
	if len(runner.scripts) != 0 {
		t.Fatalf("contended fallback mutated nftables before acquiring the claim lock: %#v", runner.scripts)
	}
}

func TestRollbackFallbackRestoresSnapshotOrPreservesUnverifiedTables(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t)
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

	firstDir := secureTestDir(t)
	runner = &fallbackRunner{tables: `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`}
	if err := restoreRollbackFallback(ctx, firstDir, nft.New(runner)); err == nil || !strings.Contains(err.Error(), "refusing automatic deletion") {
		t.Fatalf("unverified product-named table was not preserved: %v", err)
	}
	if len(runner.scripts) != 0 {
		t.Fatalf("unverified product-named table reached nft mutation: %#v", runner.scripts)
	}
	runner = &fallbackRunner{tables: `{"nftables":[]}`}
	if err := restoreRollbackFallback(ctx, secureTestDir(t), nft.New(runner)); err != nil {
		t.Fatalf("empty unmarked state did not remain a no-op: %v", err)
	}
	if len(runner.scripts) != 0 {
		t.Fatalf("empty unmarked state reached nft mutation: %#v", runner.scripts)
	}
}
