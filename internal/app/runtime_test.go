package app

import (
	"context"
	"os"
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

func TestEffectiveTrustedUsesKernelExpiryAndRejectsPermanentAccess(t *testing.T) {
	now := time.Now().UTC()
	expires := now.Add(90*time.Second + time.Nanosecond)
	later := now.Add(120 * time.Second)
	claims := []state.Claim{
		{Address: "192.0.2.1/32", Family: "ipv4", Source: "allow", ExpiresAt: &expires},
		{Address: "192.0.2.2/32", Family: "ipv4", Source: "allow", ExpiresAt: &expires},
		{Address: "192.0.2.2/32", Family: "ipv4", Source: "allow/operator", ExpiresAt: &later},
	}
	elements, err := effectiveTrusted(claims, "ipv4", now)
	if err != nil || len(elements) != 2 || elements[0].TimeoutSeconds != 91 || elements[1].TimeoutSeconds != 120 {
		t.Fatalf("unexpected trusted lease encoding: %#v", elements)
	}
	claims = append(claims, state.Claim{ID: 9, Address: "192.0.2.3/32", Family: "ipv4", Source: "allow"})
	if _, err := effectiveTrusted(claims, "ipv4", now); err == nil {
		t.Fatal("permanent trusted lease reached nftables encoding")
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

func TestOpenQuietDoesNotWriteConfigurationAudit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nftfw.toml")
	databasePath := filepath.Join(dir, "state.db")
	text := `[system]
ipv6_mode = "disabled"
strict_vpn = true
[[interfaces]]
name = "eth0"
role = "uplink"
[[interfaces]]
name = "wg0"
role = "vpn"
[wireguard]
interface = "wg0"
endpoint_port = 51820
fwmark = "0xca6c"
tcp_mss = 1360
handshake_timeout_seconds = 180
[runtime]
max_block_claims = 100
max_set_members = 100
safe_apply_timeout_seconds = 90
[state]
directory = "` + dir + `"
database = "` + databasePath + `"
[integrations]
docker_enabled = false
threat_feed = false
geoip = false
notifications = false
`
	if err := os.WriteFile(configPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenQuiet(ctx, configPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	events, err := runtime.Store.RecentAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("quiet rollback open wrote audit events: %#v", events)
	}
}
