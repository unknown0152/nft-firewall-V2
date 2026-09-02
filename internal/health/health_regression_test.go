package health

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/wireguard"
)

type healthRulesetDocumentRunner struct{ document string }

func (r healthRulesetDocumentRunner) Run(context.Context, ...string) (string, string, error) {
	return r.document, "", nil
}

type failedWGHealthRunner struct{}

func (failedWGHealthRunner) Run(context.Context, ...string) (string, error) {
	return "", errors.New("synthetic WireGuard loss")
}

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
	inspection, err := backend.InspectStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := inspection.Fingerprint
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

func TestSnapshotDegradesWhenManagedDockerForwardingIsDisabled(t *testing.T) {
	_, provider, _ := newHealthyProvider(t)
	provider.Managed = &ManagedProjection{
		Tunnel: true, DockerEnabled: true, DockerNetworks: 2, IPv4Forwarding: false,
	}
	snapshot, err := provider.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != "DEGRADED" || snapshot.IPv4Forwarding ||
		snapshot.DockerNetworkCount != 2 ||
		!strings.Contains(snapshot.Reason, "managed Docker forwarding is not ready") {
		t.Fatalf("disabled managed forwarding was not degraded: %#v", snapshot)
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

func TestAdjacentSnapshotDegradesAfterEveryMutableProtectionInput(t *testing.T) {
	t.Run("nftables", func(t *testing.T) {
		_, provider, _ := newHealthyProvider(t)
		before, err := provider.Snapshot(context.Background())
		if err != nil || before.Status != "HEALTHY" || !before.PolicyMatch {
			t.Fatalf("healthy baseline unavailable: %#v %v", before, err)
		}
		provider.Backend.Runner = healthRulesetDocumentRunner{document: strings.Replace(
			healthyFullRuleset(), `"comment":"nftfw:vpn-only-egress",`, `"comment":"removed-vpn-egress",`, 1,
		)}
		after, err := provider.Snapshot(context.Background())
		if err != nil || after.Status != "DEGRADED" || after.PolicyMatch || after.KillSwitchEnforced {
			t.Fatalf("fresh nftables drift inherited protection: %#v %v", after, err)
		}
	})

	t.Run("IPv4 forwarding", func(t *testing.T) {
		_, provider, _ := newHealthyProvider(t)
		provider.Managed = &ManagedProjection{
			Tunnel: true, DockerEnabled: true, DockerNetworks: 1, IPv4Forwarding: true,
		}
		before, err := provider.Snapshot(context.Background())
		if err != nil || before.Status != "HEALTHY" {
			t.Fatalf("healthy baseline unavailable: %#v %v", before, err)
		}
		provider.Managed.IPv4Forwarding = false
		after, err := provider.Snapshot(context.Background())
		if err != nil || after.Status != "DEGRADED" || after.IPv4Forwarding ||
			!strings.Contains(after.Reason, "forwarding") {
			t.Fatalf("disabled forwarding inherited protection: %#v %v", after, err)
		}
	})

	t.Run("WireGuard", func(t *testing.T) {
		_, provider, _ := newHealthyProvider(t)
		key := base64.StdEncoding.EncodeToString(make([]byte, 32))
		provider.WG = &wireguard.Controller{Runner: healthyWGRunner{key: key, timestamp: time.Now().Unix()}}
		provider.WGName = "wg0"
		provider.WGHealthyWithin = time.Minute
		before, err := provider.Snapshot(context.Background())
		if err != nil || before.Status != "HEALTHY" || !before.WireGuard.Healthy {
			t.Fatalf("healthy baseline unavailable: %#v %v", before, err)
		}
		provider.WG.Runner = failedWGHealthRunner{}
		after, err := provider.Snapshot(context.Background())
		if err != nil || after.Status != "DEGRADED" || after.WireGuard.Healthy {
			t.Fatalf("WireGuard loss inherited protection: %#v %v", after, err)
		}
	})

	t.Run("database", func(t *testing.T) {
		store, provider, _ := newHealthyProvider(t)
		before, err := provider.Snapshot(context.Background())
		if err != nil || before.Status != "HEALTHY" {
			t.Fatalf("healthy baseline unavailable: %#v %v", before, err)
		}
		if err := store.DB.Close(); err != nil {
			t.Fatal(err)
		}
		failed, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "absent.db")+"?mode=ro")
		if err != nil {
			t.Fatal(err)
		}
		store.DB = failed
		after, err := provider.Snapshot(context.Background())
		if err != nil || after.Status != "DEGRADED" || after.Database != "degraded" {
			t.Fatalf("database loss inherited protection: %#v %v", after, err)
		}
	})

	t.Run("provenance ledger", func(t *testing.T) {
		store, provider, _ := newHealthyProvider(t)
		ledger, err := provenance.Open(context.Background(), filepath.Join(store.Dir, "provenance-ledger.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ledger.Close() })
		provider.Ledger = ledger
		provider.RequireProvenance = true
		before, err := provider.Snapshot(context.Background())
		if err != nil || before.Status != "HEALTHY" || before.ProvenanceLedger != "ok" {
			t.Fatalf("healthy baseline unavailable: %#v %v", before, err)
		}
		if err := ledger.DB.Close(); err != nil {
			t.Fatal(err)
		}
		failed, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "absent-ledger.db")+"?mode=ro")
		if err != nil {
			t.Fatal(err)
		}
		ledger.DB = failed
		after, err := provider.Snapshot(context.Background())
		if err != nil || after.Status != "DEGRADED" || after.ProvenanceLedger != "degraded" {
			t.Fatalf("provenance loss inherited protection: %#v %v", after, err)
		}
	})
}
