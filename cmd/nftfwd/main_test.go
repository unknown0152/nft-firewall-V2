package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/version"
)

func TestStageRCandidateOnlyRefusesDaemonStartup(t *testing.T) {
	previous := version.BuildDisposition
	previousVersion := version.Version
	version.BuildDisposition = version.StageRCandidateOnly
	t.Cleanup(func() {
		version.BuildDisposition = previous
		version.Version = previousVersion
	})

	if err := candidateStartupGuard(); err == nil {
		t.Fatal("candidate-only nftfwd startup was accepted")
	}
	version.BuildDisposition = "development"
	version.Version = "2.0.2~stage.r.aaaaaaaaaaaa"
	if err := candidateStartupGuard(); err == nil {
		t.Fatal("candidate-version nftfwd startup was accepted under a forged disposition")
	}
	version.Version = previousVersion
	if err := candidateStartupGuard(); err != nil {
		t.Fatalf("development nftfwd startup guard failed: %v", err)
	}
}

func staticGenerationMetadata(t *testing.T, bootID string) state.GenerationMetadata {
	t.Helper()
	if bootID == "" {
		var err error
		bootID, err = state.CurrentBootID()
		if err != nil {
			t.Fatal(err)
		}
	}
	return state.GenerationMetadata{BootID: bootID, Provenance: []provenance.Assignment{{Name: "eth0", ID: 1}}}
}

type staticRunner struct {
	owned          bool
	foreignMarkUse bool
	rulesetCalls   int
	applyFileCalls int
	scripts        []string
}

func (r *staticRunner) Run(_ context.Context, args ...string) (string, string, error) {
	if len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "ruleset" {
		r.rulesetCalls++
		if r.foreignMarkUse {
			return `{"nftables":[{"metainfo":{"json_schema_version":1}},{"rule":{"family":"inet","table":"foreign","chain":"input","handle":9,"expr":[{"match":{"op":"==","left":{"ct":{"key":"mark"}},"right":0}}]}}]}`, "", nil
		}
		return `{"nftables":[{"metainfo":{"json_schema_version":1}}]}`, "", nil
	}
	if len(args) >= 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		if !r.owned {
			return `{"nftables":[]}`, "", nil
		}
		return `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}},{"table":{"family":"ip","name":"nftfw_nat"}},{"table":{"family":"ip6","name":"nftfw_filter6"}}]}`, "", nil
	}
	if len(args) == 5 && args[0] == "-j" && args[1] == "list" && args[2] == "table" {
		return staticOwnedTableJSON(args[3], args[4]), "", nil
	}
	if len(args) > 0 && (args[0] == "--check" || args[0] == "--file") {
		data, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return "", "", err
		}
		script := string(data)
		r.scripts = append(r.scripts, script)
		if args[0] == "--file" {
			r.applyFileCalls++
			hasCreate := false
			for _, line := range strings.Split(script, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "table ") {
					hasCreate = true
				}
			}
			if hasCreate {
				r.owned = true
			} else if strings.Contains(script, "destroy table") {
				r.owned = false
			}
		}
	}
	return "", "", nil
}

func staticOwnedTableJSON(family, name string) string {
	var objects []string
	addChain := func(chain, typ, hook, policy string) {
		objects = append(objects, fmt.Sprintf(`{"chain":{"family":%q,"table":%q,"name":%q,"type":%q,"hook":%q,"policy":%q}}`, family, name, chain, typ, hook, policy))
	}
	addRule := func(chain, comment string) {
		objects = append(objects, fmt.Sprintf(`{"rule":{"family":%q,"table":%q,"chain":%q,"comment":%q}}`, family, name, chain, comment))
	}
	switch family + "/" + name {
	case "inet/nftfw_filter":
		for _, chain := range []string{"input", "output", "forward"} {
			addChain(chain, "filter", chain, "drop")
		}
		for _, item := range [][2]string{{"input", "nftfw:input-default-deny"}, {"input", "nftfw:input-reply-only"}, {"output", "nftfw:output-default-deny"}, {"forward", "nftfw:forward-default-deny"}, {"forward", "nftfw:forward-physical-deny"}, {"output", "nftfw:vpn-only-egress"}} {
			addRule(item[0], item[1])
		}
		for _, marker := range [][2]string{{"input", "nftfw:provenance-tag-input:"}, {"output", "nftfw:provenance-tag-output:"}, {"forward", "nftfw:provenance-tag-forward:"}, {"output", "nftfw:provenance-reply-output:"}, {"forward", "nftfw:provenance-reply-forward:"}} {
			addRule(marker[0], marker[1]+"eth0")
		}
	case "ip/nftfw_nat":
		addChain("prerouting", "nat", "prerouting", "accept")
		addRule("prerouting", "nftfw:dnat-chain")
		addChain("postrouting", "nat", "postrouting", "accept")
	case "ip6/nftfw_filter6":
		for _, chain := range []string{"input", "output", "forward"} {
			addChain(chain, "filter", chain, "drop")
		}
		addRule("input", "nftfw:ipv6-mode-disabled")
	}
	return `{"nftables":[` + strings.Join(objects, ",") + `]}`
}

func TestCanonicalStateDatabaseRejectsAmbiguousRoots(t *testing.T) {
	root := secureTestDir(t)
	for _, invalid := range []string{
		"relative",
		"/",
		root + "/../" + filepath.Base(root),
		root + "/",
		root + "?query",
		root + "#fragment",
		root + "%66",
	} {
		if _, err := canonicalStateDatabase(invalid); err == nil {
			t.Fatalf("ambiguous state root %q accepted", invalid)
		}
	}
	got, err := canonicalStateDatabase(root)
	if err != nil || got != filepath.Join(root, "generation-state", "state.db") {
		t.Fatalf("canonical database mismatch: %q %v", got, err)
	}
}

func TestStaticRollbackUsesLockedCurrentSchemaState(t *testing.T) {
	ctx := context.Background()
	root, databasePath := newStateLayout(t)
	store, err := state.Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	script := nft.EmergencyDenyScript
	checksum := checksumOf(script)
	runner := &staticRunner{owned: true}
	backend := nft.New(runner)
	observed, err := backend.Fingerprint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveGenerationWithMetadata(ctx, 1, checksum, script, nil, nil, staticGenerationMetadata(t, "")); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.SetObservedHash(ctx, 1, observed); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, 1); err != nil {
		t.Fatal(err)
	}
	previous := uint64(1)
	past := time.Now().UTC().Add(-time.Minute)
	if err := store.SaveGenerationWithMetadata(ctx, 2, checksum, script, &previous, &past, staticGenerationMetadata(t, "")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	lockDir := secureTestDir(t)
	rolledBack, err := rollbackExpiredStatic(ctx, root, lockDir, backend)
	if err != nil || !rolledBack {
		t.Fatalf("static rollback failed: rolled_back=%t err=%v", rolledBack, err)
	}
	store, err = state.OpenRecovery(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if pending, err := store.Pending(ctx); !errors.Is(err, sql.ErrNoRows) || pending != nil {
		t.Fatalf("pending generation survived: %#v %v", pending, err)
	}
	publication, err := store.ClaimPublicationState(ctx)
	if err != nil || publication.DesiredRevision == publication.AppliedRevision {
		t.Fatalf("runtime claims were not marked unpublished: %+v %v", publication, err)
	}
}

func TestStaticRecoveryManagersRejectForeignMarkCollisionBeforeApply(t *testing.T) {
	ctx := context.Background()
	prepare := func(t *testing.T, pending bool) (string, *staticRunner) {
		t.Helper()
		root, databasePath := newStateLayout(t)
		store, err := state.Open(ctx, databasePath)
		if err != nil {
			t.Fatal(err)
		}
		script := nft.EmergencyDenyScript
		runner := &staticRunner{owned: true}
		observed, err := nft.New(runner).Fingerprint(ctx)
		if err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err := store.SaveGenerationWithMetadata(ctx, 1, checksumOf(script), script, nil, nil, staticGenerationMetadata(t, "")); err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err := store.MarkApplied(ctx, 1); err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err := store.SetObservedHash(ctx, 1, observed); err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err := store.Commit(ctx, 1); err != nil {
			store.Close()
			t.Fatal(err)
		}
		if pending {
			previous := uint64(1)
			past := time.Now().UTC().Add(-time.Minute)
			if err := store.SaveGenerationWithMetadata(ctx, 2, checksumOf(script), script, &previous, &past, staticGenerationMetadata(t, "")); err != nil {
				store.Close()
				t.Fatal(err)
			}
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		runner.owned = false
		runner.foreignMarkUse = true
		return root, runner
	}

	t.Run("early boot", func(t *testing.T) {
		root, runner := prepare(t, false)
		if _, err := recoverAtBoot(ctx, root, secureTestDir(t), nft.New(runner)); err == nil || !strings.Contains(err.Error(), "foreign conntrack-mark ownership") {
			t.Fatalf("early recovery accepted a foreign mark collision: %v", err)
		}
		if runner.applyFileCalls != 0 || runner.rulesetCalls != 1 {
			t.Fatalf("early guard did not stop immediately before apply: apply=%d audits=%d", runner.applyFileCalls, runner.rulesetCalls)
		}
	})

	t.Run("static rollback", func(t *testing.T) {
		root, runner := prepare(t, true)
		if rolledBack, err := rollbackExpiredStatic(ctx, root, secureTestDir(t), nft.New(runner)); err == nil || rolledBack || !strings.Contains(err.Error(), "foreign conntrack-mark ownership") {
			t.Fatalf("static rollback accepted a foreign mark collision: rolled_back=%t err=%v", rolledBack, err)
		}
		if runner.applyFileCalls != 0 || runner.rulesetCalls != 1 {
			t.Fatalf("rollback guard did not stop immediately before apply: apply=%d audits=%d", runner.applyFileCalls, runner.rulesetCalls)
		}
	})
}

func TestStaticRollbackForeignFirstGenerationBlocksReadiness(t *testing.T) {
	ctx := context.Background()
	root, databasePath := newStateLayout(t)
	store, err := state.Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	script := nft.EmergencyDenyScript
	if err := store.SaveGenerationWithMetadata(ctx, 1, checksumOf(script), script, nil, nil, staticGenerationMetadata(t, "foreign-boot")); err != nil {
		t.Fatal(err)
	}
	store.Close()
	runner := &staticRunner{}
	rolledBack, err := rollbackExpiredStatic(ctx, root, secureTestDir(t), nft.New(runner))
	if !rolledBack || err == nil || !strings.Contains(err.Error(), "readiness remains blocked") {
		t.Fatalf("first foreign pending result: rolled_back=%t err=%v", rolledBack, err)
	}
	if len(runner.scripts) != 0 {
		t.Fatalf("empty first pending state mutated nftables: %#v", runner.scripts)
	}
}

func TestStaticRollbackFailsClosedOnCorruptDatabaseAndLockContention(t *testing.T) {
	ctx := context.Background()
	root, databasePath := newStateLayout(t)
	if err := os.WriteFile(databasePath, []byte("not sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &staticRunner{owned: true}
	if rolledBack, err := rollbackExpiredStatic(ctx, root, secureTestDir(t), nft.New(runner)); err == nil || rolledBack {
		t.Fatalf("corrupt database authorized recovery: rolled_back=%t err=%v", rolledBack, err)
	}
	if len(runner.scripts) != 0 {
		t.Fatalf("corrupt database reached nft mutation: %#v", runner.scripts)
	}

	root, databasePath = newStateLayout(t)
	store, err := state.Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	script := nft.EmergencyDenyScript
	if err := store.SaveGenerationWithMetadata(ctx, 1, checksumOf(script), script, nil, nil, staticGenerationMetadata(t, "")); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(databasePath, []byte("not sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner = &staticRunner{}
	rolledBack, err := rollbackExpiredStatic(ctx, root, secureTestDir(t), nft.New(runner))
	if rolledBack || err == nil || !strings.Contains(err.Error(), "no database recovery transition") {
		t.Fatalf("database-failure pointer restore result: rolled_back=%t err=%v", rolledBack, err)
	}
	if len(runner.scripts) != 2 || !runner.owned {
		t.Fatalf("verified pointer snapshot was not checked and restored: %#v", runner.scripts)
	}

	root, _ = newStateLayout(t)
	lockDir := secureTestDir(t)
	release, err := state.AcquireMutationLock(ctx, lockDir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	waitCtx, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancel()
	if rolledBack, err := rollbackExpiredStatic(waitCtx, root, lockDir, nft.New(&staticRunner{})); !errors.Is(err, context.DeadlineExceeded) || rolledBack {
		t.Fatalf("contended rollback ignored lock: rolled_back=%t err=%v", rolledBack, err)
	}
}

func TestVerifierIsReadOnlyAndRejectsPendingState(t *testing.T) {
	ctx := context.Background()
	root, databasePath := newStateLayout(t)
	store, err := state.Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	script := nft.EmergencyDenyScript
	runner := &staticRunner{owned: true}
	backend := nft.New(runner)
	observed, err := backend.Fingerprint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveGenerationWithMetadata(ctx, 1, checksumOf(script), script, nil, nil, staticGenerationMetadata(t, "")); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.SetObservedHash(ctx, 1, observed); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before := stateTreeDigest(t, root)
	if err := verifyEnforcementState(ctx, root, secureTestDir(t), backend); err != nil {
		t.Fatal(err)
	}
	after := stateTreeDigest(t, root)
	if before != after {
		t.Fatalf("verifier changed durable state: before=%s after=%s", before, after)
	}
	if len(runner.scripts) != 0 {
		t.Fatalf("verifier invoked nft mutation: %#v", runner.scripts)
	}

	store, err = state.OpenRecovery(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(time.Hour)
	previous := uint64(1)
	if err := store.SaveGenerationWithMetadata(ctx, 2, checksumOf(script), script, &previous, &future, staticGenerationMetadata(t, "")); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if err := verifyEnforcementState(ctx, root, secureTestDir(t), backend); err == nil || !strings.Contains(err.Error(), "remains pending") {
		t.Fatalf("verifier accepted pending state: %v", err)
	}
}

func newStateLayout(t *testing.T) (string, string) {
	t.Helper()
	root := secureTestDir(t)
	directory := filepath.Join(root, "generation-state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := provenance.Open(context.Background(), filepath.Join(root, "provenance-ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve(context.Background(), []provenance.Assignment{{Name: "eth0", ID: 1}}); err != nil {
		ledger.Close()
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(directory, "state.db")
}

func checksumOf(script string) string {
	sum := sha256.Sum256([]byte(script))
	return hex.EncodeToString(sum[:])
}

func stateTreeDigest(t *testing.T, root string) string {
	t.Helper()
	hash := sha256.New()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		_, _ = hash.Write([]byte(relative + "\x00" + entry.Type().String() + "\x00"))
		if !entry.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, _ = hash.Write(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
