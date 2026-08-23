package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/threatintel"
	"github.com/unknown0152/nft-firewall-v2/internal/wireguard"
)

type failFirstClaimApplyRunner struct {
	applyCalls       int
	failedScript     string
	successfulScript string
}

type staticEndpointLookup struct{ addresses []net.IP }

func (r staticEndpointLookup) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return r.addresses, nil
}

type countingOwnedRunner struct{ calls int }

func (r *countingOwnedRunner) Run(context.Context, ...string) (string, string, error) {
	r.calls++
	return `{"nftables":[]}`, "", nil
}

type collidingOwnedRunner struct{}

func (collidingOwnedRunner) Run(context.Context, ...string) (string, string, error) {
	return `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`, "", nil
}

func secureRuntimeTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func (r *failFirstClaimApplyRunner) Run(_ context.Context, args ...string) (string, string, error) {
	if len(args) >= 3 && args[0] == "-j" {
		return `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`, "", nil
	}
	if len(args) == 0 || args[0] != "--file" {
		return "", "", nil
	}
	script, err := os.ReadFile(args[len(args)-1])
	if err != nil {
		return "", "", err
	}
	r.applyCalls++
	if r.applyCalls == 1 {
		r.failedScript = string(script)
		return "", "synthetic kernel refresh failure", errors.New("synthetic kernel refresh failure")
	}
	r.successfulScript = string(script)
	return "", "", nil
}

func TestIntegrationRefreshScheduleUsesDurableState(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(ctx, filepath.Join(secureRuntimeTestDir(t), "state.db"))
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

func TestThreatFeedRemainsDisabledUnlessExplicitlyEnabled(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(ctx, filepath.Join(secureRuntimeTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	calls := 0
	runtime := &Runtime{
		Config: config.Config{
			Runtime:     config.RuntimeConfig{MaxBlockClaims: 100, MaxSetMembers: 100},
			ThreatFeeds: []config.ThreatFeedConfig{{Name: "disabled", URL: "https://feed.example.test/list"}},
		},
		Store: store,
		threatFeedFetcher: func(context.Context, threatintel.Feed) ([]string, error) {
			calls++
			return []string{"1.1.1.1/32"}, nil
		},
	}
	if err := runtime.RefreshIntegrations(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("disabled threat integration fetched %d times", calls)
	}
}

func TestThreatFeedProtectsConfiguredTopologyAndBootstrapPrefixes(t *testing.T) {
	dir := secureRuntimeTestDir(t)
	runtime := &Runtime{Config: config.Config{
		Interfaces: []config.Interface{{Name: "eth0", CIDRs: []string{"9.9.9.9/32"}}},
		Zones:      []config.Zone{{Name: "management", Networks: []string{"8.8.8.0/24"}}},
		WireGuard: config.WireGuardConfig{
			BootstrapIPs:   []string{"1.1.1.1/32"},
			BootstrapIPsV6: []string{"2606:4700:4700::1111/128"},
			EndpointHost:   "vpn.example.test",
		},
	}, EndpointResolver: &wireguard.Resolver{
		Resolver:  staticEndpointLookup{addresses: []net.IP{net.ParseIP("208.67.222.222")}},
		CachePath: filepath.Join(dir, "wg-endpoints.json"),
		Max:       64,
	}}
	protected, err := runtime.threatFeedProtectedPrefixes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{
		"8.8.8.8/32",
		"9.9.9.0/24",
		"1.1.1.0/24",
		"2606:4700:4700::/48",
		"208.67.222.0/24",
	} {
		if err := threatintel.Validate([]string{candidate}, protected); err == nil {
			t.Fatalf("configured protected destination could be blocked: %s", candidate)
		}
	}
}

func TestIntegrationKernelRefreshFailureRestoresPriorClaimsAndLiveSets(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(ctx, filepath.Join(secureRuntimeTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const source = "threatfeed/test"
	if _, err := store.ReplaceSourceClaims(ctx, source, "threat intelligence", "integration", []string{"8.8.8.8/32"}); err != nil {
		t.Fatal(err)
	}
	runner := &failFirstClaimApplyRunner{}
	runtime := &Runtime{
		Config: config.Config{
			Runtime:      config.RuntimeConfig{MaxBlockClaims: 100, MaxSetMembers: 100},
			Integrations: config.IntegrationsConfig{ThreatFeed: true},
			ThreatFeeds:  []config.ThreatFeedConfig{{Name: "test", URL: "https://feed.example.test/list"}},
		},
		Store:   store,
		Backend: nft.New(runner),
		threatFeedFetcher: func(context.Context, threatintel.Feed) ([]string, error) {
			return []string{"1.1.1.1/32"}, nil
		},
	}
	if err := runtime.RefreshIntegrations(ctx); err == nil {
		t.Fatal("synthetic kernel refresh failure was not reported")
	}
	addresses, err := runtime.sourceClaimAddresses(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 1 || addresses[0] != "8.8.8.8/32" {
		t.Fatalf("failed kernel update left candidate claims queued: %v", addresses)
	}
	if !strings.Contains(runner.failedScript, "1.1.1.1/32") {
		t.Fatalf("candidate set was not attempted: %s", runner.failedScript)
	}
	if !strings.Contains(runner.successfulScript, "8.8.8.8/32") || strings.Contains(runner.successfulScript, "1.1.1.1/32") {
		t.Fatalf("prior live set was not restored: %s", runner.successfulScript)
	}
	status, err := store.IntegrationState(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "degraded" || status.EntryCount != 1 {
		t.Fatalf("unexpected rolled-back integration status: %#v", status)
	}
}

func TestClaimSetPublicationStateFailsClosedAndRecovers(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(ctx, filepath.Join(secureRuntimeTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.AddClaim(ctx, state.Claim{
		Address: "203.0.113.8/32", Family: "ipv4", Source: "manual", Actor: "test",
	}); err != nil {
		t.Fatal(err)
	}
	runner := &failFirstClaimApplyRunner{}
	runtime := &Runtime{
		Config: config.Config{Runtime: config.RuntimeConfig{MaxSetMembers: 100}},
		Store:  store, Backend: nft.New(runner),
	}
	if _, err := runtime.RefreshClaimSets(ctx); err == nil {
		t.Fatal("synthetic runtime claim-set failure was not reported")
	}
	failed, err := store.IntegrationState(ctx, "runtime/claims")
	if err != nil {
		t.Fatal(err)
	}
	if failed.Status != "degraded" || failed.EntryCount != 1 {
		t.Fatalf("failed publication was not persisted as degraded: %#v", failed)
	}
	if _, err := runtime.RefreshClaimSets(ctx); err != nil {
		t.Fatalf("claim-set retry did not recover: %v", err)
	}
	recovered, err := store.IntegrationState(ctx, "runtime/claims")
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Status != "healthy" || recovered.EntryCount != 1 || recovered.LastSuccess == nil {
		t.Fatalf("successful retry did not clear degraded state: %#v", recovered)
	}
}

func TestClaimSetNoTableDoesNotClearDegradedPublicationState(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(ctx, filepath.Join(secureRuntimeTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SetIntegrationState(ctx, "runtime/claims", "healthy", 1, true); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntegrationState(ctx, "runtime/claims", "degraded", 1, false); err != nil {
		t.Fatal(err)
	}
	before, err := store.IntegrationState(ctx, "runtime/claims")
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		Config:  config.Config{Runtime: config.RuntimeConfig{MaxSetMembers: 100}},
		Store:   store,
		Backend: nft.New(&countingOwnedRunner{}),
	}
	refreshed, err := runtime.RefreshClaimSets(ctx)
	if err != nil || refreshed {
		t.Fatalf("no-table refresh should be a non-mutating no-op: refreshed=%t err=%v", refreshed, err)
	}
	after, err := store.IntegrationState(ctx, "runtime/claims")
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != "degraded" || after.LastSuccess == nil || before.LastSuccess == nil || !after.LastSuccess.Equal(*before.LastSuccess) {
		t.Fatalf("no-table no-op cleared or advanced degraded state: before=%#v after=%#v", before, after)
	}
}

func TestMultipleIndividuallyValidThreatFeedsExceedGlobalCoverage(t *testing.T) {
	var claims []state.Claim
	var first, second []string
	for i := 0; i <= 4096; i++ {
		address := fmt.Sprintf("8.%d.%d.0/24", i>>8, i&0xff)
		source := "threatfeed/first"
		if i >= 2048 {
			source = "threatfeed/second"
			second = append(second, address)
		} else {
			first = append(first, address)
		}
		claims = append(claims, state.Claim{Address: address, Family: "ipv4", Source: source})
	}
	if err := threatintel.Validate(first, nil); err != nil {
		t.Fatalf("first individually bounded feed rejected: %v", err)
	}
	if err := threatintel.Validate(second, nil); err != nil {
		t.Fatalf("second individually bounded feed rejected: %v", err)
	}
	runtime := &Runtime{Config: config.Config{Runtime: config.RuntimeConfig{MaxSetMembers: 5000}}}
	if _, err := runtime.claimSets(claims, time.Now().UTC(), nil); err == nil {
		t.Fatal("aggregate coverage across active threat-feed sources was accepted")
	}
}

func TestRefreshClaimSetsRejectsUnsafePersistedThreatClaimsBeforeKernelAccess(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(ctx, filepath.Join(secureRuntimeTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ReplaceSourceClaims(ctx, "threatfeed/legacy", "legacy", "upgrade", []string{"192.168.1.1/32"}); err != nil {
		t.Fatal(err)
	}
	runner := &countingOwnedRunner{}
	runtime := &Runtime{
		Config:  config.Config{Runtime: config.RuntimeConfig{MaxSetMembers: 100}},
		Store:   store,
		Backend: nft.New(runner),
	}
	if _, err := runtime.RefreshClaimSets(ctx); err == nil {
		t.Fatal("preexisting private threat-feed claim reached the restore path")
	}
	if runner.calls != 0 {
		t.Fatalf("unsafe stored claim reached nft backend: calls=%d", runner.calls)
	}
}

func TestClaimSetsEnforceConfiguredMemberLimit(t *testing.T) {
	runtime := &Runtime{Config: config.Config{Runtime: config.RuntimeConfig{MaxSetMembers: 1}}}
	claims := []state.Claim{
		{Address: "192.0.2.1/32", Family: "ipv4", Source: "manual"},
		{Address: "192.0.2.2/32", Family: "ipv4", Source: "manual"},
	}
	if _, err := runtime.claimSets(claims, time.Now().UTC(), nil); err == nil {
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
	dir := secureRuntimeTestDir(t)
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
	runner := &countingOwnedRunner{}
	runtime, err := OpenQuiet(ctx, configPath, runner)
	if err != nil {
		t.Fatal(err)
	}
	events, err := runtime.Store.RecentAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("quiet rollback open wrote audit events: %#v", events)
	}
	if runner.calls == 0 {
		t.Fatal("pristine state did not perform the first-use ownership check")
	}
	releaseClaims, err := state.AcquireClaimPublicationLock(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	preflightCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	preflight, preflightErr := OpenQuiet(preflightCtx, configPath, &countingOwnedRunner{})
	cancel()
	if preflightErr != nil {
		releaseClaims()
		t.Fatalf("quiet rollback preflight waited on the outer safe-apply lock: %v", preflightErr)
	}
	rolledBack, rollbackErr := preflight.RollbackExpired(ctx)
	if closeErr := preflight.Close(); closeErr != nil {
		t.Error(closeErr)
	}
	releaseClaims()
	if rollbackErr != nil || rolledBack {
		t.Fatalf("no-pending rollback preflight was not a lock-free no-op: rolled_back=%t err=%v", rolledBack, rollbackErr)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if unexpected, err := OpenQuiet(ctx, configPath, collidingOwnedRunner{}); err == nil {
		unexpected.Close()
		t.Fatal("pristine state accepted a pre-existing product-named table")
	} else if !strings.Contains(err.Error(), "first-use nft table collision") {
		t.Fatalf("unexpected first-use collision error: %v", err)
	}
}
