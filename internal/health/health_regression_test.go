package health

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

func newHealthyProvider(t *testing.T) (*state.Store, Provider, string) {
	t.Helper()
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(ctx, filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close state store: %v", err)
		}
	})
	backend := nft.New(healthyRulesetRunner{})
	fingerprint, err := backend.Fingerprint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	script := "add table inet nftfw_filter\n"
	sum := sha256.Sum256([]byte(script))
	checksum := hex.EncodeToString(sum[:])
	saveHealthGeneration(t, store, 1, checksum, script)
	if err := store.SetObservedHash(ctx, 1, fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, 1); err != nil {
		t.Fatal(err)
	}
	publication, err := store.ClaimPublicationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkClaimsPublished(ctx, publication.DesiredRevision, 0); err != nil {
		t.Fatal(err)
	}
	return store, Provider{Store: store, Backend: backend, IPv6Mode: "disabled"}, checksum
}

func TestSnapshotRejectsRevisionMismatchDespitePriorHealthyPublication(t *testing.T) {
	ctx := context.Background()
	store, provider, _ := newHealthyProvider(t)
	before, err := provider.Snapshot(ctx)
	if err != nil || before.Status != "HEALTHY" {
		t.Fatalf("healthy baseline unavailable: status=%s err=%v", before.Status, err)
	}
	if _, err := store.DB.ExecContext(ctx, `UPDATE runtime_claim_publication SET desired_revision=desired_revision+1 WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	integration, err := store.IntegrationState(ctx, "runtime/claims")
	if err != nil || integration.Status != "healthy" || integration.LastSuccess == nil {
		t.Fatalf("test did not preserve the prior healthy row: %#v err=%v", integration, err)
	}

	after, err := provider.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != "DEGRADED" || after.ClaimsDesiredRev == after.ClaimsAppliedRev || !strings.Contains(after.Reason, "not synchronized") {
		t.Fatalf("revision mismatch inherited stale healthy state: %#v", after)
	}
}

func TestSnapshotDetectsUnpublishedSameCountClaimSwap(t *testing.T) {
	ctx := context.Background()
	store, provider, _ := newHealthyProvider(t)
	firstID, err := store.AddClaim(ctx, state.Claim{Address: "192.0.2.1/32", Family: "ipv4", Source: "manual", Reason: "first", Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	publication, err := store.ClaimPublicationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkClaimsPublished(ctx, publication.DesiredRevision, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveClaim(ctx, firstID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddClaim(ctx, state.Claim{Address: "192.0.2.2/32", Family: "ipv4", Source: "manual", Reason: "replacement", Actor: "test"}); err != nil {
		t.Fatal(err)
	}

	snapshot, err := provider.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.BlockClaims != 1 || snapshot.BlockedAddresses != 1 {
		t.Fatalf("test did not retain the same effective count: %#v", snapshot)
	}
	if snapshot.Status != "DEGRADED" || snapshot.ClaimsDesiredRev == snapshot.ClaimsAppliedRev || !strings.Contains(snapshot.Reason, "not synchronized") {
		t.Fatalf("same-count claim swap was treated as published: %#v", snapshot)
	}
}

func TestSnapshotDegradesWhenConfiguredIntegrationHasNoState(t *testing.T) {
	ctx := context.Background()
	_, provider, _ := newHealthyProvider(t)
	provider.ActiveIntegrations = map[string]bool{"runtime/claims": true, "docker": true}

	snapshot, err := provider.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != "DEGRADED" || !strings.Contains(snapshot.Reason, "integration docker has not completed its first health check") {
		t.Fatalf("missing configured integration inherited healthy state: %#v", snapshot)
	}
}

func TestSnapshotRejectsWellFormedWrongGenerationChecksum(t *testing.T) {
	ctx := context.Background()
	store, provider, checksum := newHealthyProvider(t)
	wrong := strings.Repeat("f", sha256.Size*2)
	if wrong == checksum {
		wrong = strings.Repeat("0", sha256.Size*2)
	}
	if _, err := store.DB.ExecContext(ctx, `UPDATE generations SET checksum=? WHERE id=1`, wrong); err != nil {
		t.Fatal(err)
	}

	snapshot, err := provider.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != "DEGRADED" || snapshot.Active || snapshot.PolicyMatch || snapshot.KillSwitchEnforced || !snapshot.Drift {
		t.Fatalf("wrong generation checksum remained active: %#v", snapshot)
	}
	if snapshot.PolicyHash != "" || snapshot.PolicyChecksum != "" || !strings.Contains(snapshot.Reason, "generation script checksum mismatch") {
		t.Fatalf("wrong checksum identity was exposed as valid: %#v", snapshot)
	}
}
