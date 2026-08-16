package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

func TestIntegrationRefreshScheduleUsesDurableState(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runtime := &Runtime{Store: store}
	if !runtime.integrationDue(ctx, "threatfeed/test", 60) {
		t.Fatal("new integration was not due")
	}
	if err := store.SetIntegrationState(ctx, "threatfeed/test", "healthy", 4, true); err != nil {
		t.Fatal(err)
	}
	if runtime.integrationDue(ctx, "threatfeed/test", 60) {
		t.Fatal("fresh integration was refreshed before its interval")
	}
	old := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := store.DB.ExecContext(ctx, "UPDATE integration_state SET updated_at=? WHERE name=?", old, "threatfeed/test"); err != nil {
		t.Fatal(err)
	}
	if !runtime.integrationDue(ctx, "threatfeed/test", 60) {
		t.Fatal("stale integration was not due")
	}
}

func TestClaimSetsEnforceConfiguredMemberLimit(t *testing.T) {
	runtime := &Runtime{Config: config.Config{Runtime: config.RuntimeConfig{MaxSetMembers: 1}}}
	claims := []state.Claim{
		{Address: "192.0.2.1/32", Family: "ipv4", Source: "manual"},
		{Address: "192.0.2.2/32", Family: "ipv4", Source: "manual"},
	}
	if _, err := runtime.claimSets(claims, time.Now().UTC()); err == nil {
		t.Fatal("oversized effective runtime set was accepted")
	}
}

func TestEffectiveTrustedUsesKernelExpiryAndPermanentDominates(t *testing.T) {
	now := time.Now().UTC()
	expires := now.Add(90*time.Second + time.Nanosecond)
	claims := []state.Claim{
		{Address: "192.0.2.1/32", Family: "ipv4", Source: "allow", ExpiresAt: &expires},
		{Address: "192.0.2.2/32", Family: "ipv4", Source: "allow", ExpiresAt: &expires},
		{Address: "192.0.2.2/32", Family: "ipv4", Source: "allow/operator"},
	}
	elements := effectiveTrusted(claims, "ipv4", now)
	if len(elements) != 2 || elements[0].TimeoutSeconds != 91 || elements[1].TimeoutSeconds != 0 {
		t.Fatalf("unexpected trusted lease encoding: %#v", elements)
	}
}

func TestClaimExpiryBounds(t *testing.T) {
	if expires, err := claimExpiry(0); err != nil || expires != nil {
		t.Fatalf("permanent expiry rejected: %v %v", expires, err)
	}
	if expires, err := claimExpiry(60); err != nil || expires == nil || time.Until(*expires) <= 0 {
		t.Fatalf("temporary expiry rejected: %v %v", expires, err)
	}
	if _, err := claimExpiry(365*24*60*60 + 1); err == nil {
		t.Fatal("unbounded claim expiry accepted")
	}
}

func TestAllowLeaseRequiresExplicitTrustedServices(t *testing.T) {
	runtime := &Runtime{}
	if _, err := runtime.Control(context.Background(), api.Request{Op: "allow-add", Address: "203.0.113.8/32"}); err == nil {
		t.Fatal("temporary access accepted without runtime.trusted_services")
	}
}
