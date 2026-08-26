package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/health"
	"github.com/unknown0152/nft-firewall-v2/internal/intent"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/reconcile"
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

type staticWGCommandRunner struct{ key string }

func (r staticWGCommandRunner) Run(_ context.Context, args ...string) (string, error) {
	switch {
	case len(args) == 3 && args[0] == "show" && args[2] == "peers":
		return r.key + "\n", nil
	case len(args) == 3 && args[0] == "show" && args[2] == "endpoints":
		return r.key + "\t198.51.100.8:51820\n", nil
	case len(args) == 3 && args[0] == "show" && args[2] == "latest-handshakes":
		return fmt.Sprintf("%s\t%d\n", r.key, time.Now().Unix()), nil
	case len(args) == 7 && args[0] == "set":
		return "", nil
	default:
		return "", errors.New("unexpected WireGuard command")
	}
}

type countingOwnedRunner struct{ calls int }

func (r *countingOwnedRunner) Run(_ context.Context, args ...string) (string, string, error) {
	r.calls++
	if len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "ruleset" {
		return `{"nftables":[{"metainfo":{"json_schema_version":1}}]}`, "", nil
	}
	return `{"nftables":[]}`, "", nil
}

type statefulOwnedRunner struct {
	mu      sync.Mutex
	applied bool
}

func (r *statefulOwnedRunner) Run(_ context.Context, args ...string) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	joined := strings.Join(args, " ")
	if joined == "-j list ruleset" {
		return `{"nftables":[{"metainfo":{"json_schema_version":1}}]}`, "", nil
	}
	if len(args) >= 2 && args[0] == "--check" && args[1] == "--file" {
		return "", "", nil
	}
	if len(args) >= 2 && args[0] == "--file" {
		script, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return "", "", err
		}
		r.applied = !strings.Contains(string(script), "delete table") ||
			strings.Contains(string(script), "add table")
		return "", "", nil
	}
	if joined == "-j list tables" {
		if !r.applied {
			return `{"nftables":[]}`, "", nil
		}
		return `{"nftables":[
{"table":{"family":"inet","name":"nftfw_filter"}},
{"table":{"family":"ip","name":"nftfw_nat"}},
{"table":{"family":"ip6","name":"nftfw_filter6"}}
]}`, "", nil
	}
	if len(args) == 5 && strings.Join(args[:3], " ") == "-j list table" {
		return fmt.Sprintf(
			`{"nftables":[{"table":{"family":%q,"name":%q}}]}`,
			args[3], args[4],
		), "", nil
	}
	return "", "", nil
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
	databasePath := filepath.Join(dir, "generation-state", "state.db")
	ledgerPath := filepath.Join(dir, "provenance-ledger.db")
	text := `[system]
ipv6_mode = "disabled"
strict_vpn = true
[[interfaces]]
name = "eth0"
role = "uplink"
provenance_id = 1
[[interfaces]]
name = "wg0"
role = "vpn"
provenance_id = 2
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
provenance_ledger = "` + ledgerPath + `"
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
	releaseClaims, err := state.AcquireClaimPublicationLock(ctx, filepath.Join(dir, "test-runtime"))
	if err != nil {
		t.Fatal(err)
	}
	preflightCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	preflight, preflightErr := OpenQuiet(preflightCtx, configPath, &countingOwnedRunner{})
	cancel()
	releaseClaims()
	if preflight != nil || preflightErr == nil || !strings.Contains(preflightErr.Error(), "context deadline exceeded") {
		if preflight != nil {
			_ = preflight.Close()
		}
		t.Fatalf("state initialization bypassed the held global lock: runtime=%#v err=%v", preflight, preflightErr)
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

func TestRuntimeReloadsProtectedManagedConfiguration(t *testing.T) {
	root := secureRuntimeTestDir(t)
	configPath := filepath.Join(root, "nftfw.toml")
	intentPath := filepath.Join(root, "intent.toml")
	value := intent.Intent{
		Schema: intent.Schema, Managed: true, Uplink: "eth0",
		VPNInterface: intent.VPNInterface,
		LANNetworks:  []string{"192.168.1.0/24"}, ManagementTCP: []int{22},
		VPNAddresses: []string{"10.8.0.2/32"}, EndpointHost: "vpn.example.test",
		EndpointPort: 51820, BootstrapIPv4: []string{"198.51.100.8/32"},
		PublicTCP: []int{443}, MTU: 1420, ResolverMode: "none", DisableIPv6: true,
	}
	intentData, err := value.Render()
	if err != nil {
		t.Fatal(err)
	}
	generated, err := value.Config()
	if err != nil {
		t.Fatal(err)
	}
	configData, err := intent.RenderConfig(generated)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(intentPath, intentData, 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{ConfigPath: configPath, Config: config.Defaults()}
	current, err := runtime.currentConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	if current == runtime || current.ManagedIntent == nil ||
		len(current.ManagedIntent.PublicTCP) != 1 || current.ManagedIntent.PublicTCP[0] != 443 ||
		len(current.Config.Policies) != 3 {
		t.Fatalf("protected managed configuration was not reloaded: %#v", current)
	}
	if len(runtime.Config.Policies) != 0 || runtime.ManagedIntent != nil {
		t.Fatal("configuration reload mutated the shared runtime")
	}
	if err := os.WriteFile(configPath, []byte("[invalid]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.currentConfiguration(); err == nil ||
		!strings.Contains(err.Error(), "reload protected configuration") {
		t.Fatalf("invalid replacement configuration was accepted: %v", err)
	}
}

func TestRuntimeArtifactStatusAndReadControlUseReloadedPolicy(t *testing.T) {
	ctx := context.Background()
	root := secureRuntimeTestDir(t)
	configPath := filepath.Join(root, "nftfw.toml")
	intentPath := filepath.Join(root, "intent.toml")
	databasePath := filepath.Join(root, "generation-state", "state.db")
	ledgerPath := filepath.Join(root, "provenance-ledger.db")
	value := intent.Intent{
		Schema: intent.Schema, Managed: true, Uplink: "eth0",
		VPNInterface: intent.VPNInterface,
		LANNetworks:  []string{"192.168.1.0/24"}, ManagementTCP: []int{22},
		VPNAddresses: []string{"10.8.0.2/32"}, EndpointHost: "vpn.example.test",
		EndpointPort: 51820, BootstrapIPv4: []string{"198.51.100.8/32"},
		MTU: 1420, ResolverMode: "none", DisableIPv6: true,
	}
	writeManaged := func() {
		t.Helper()
		intentData, err := value.Render()
		if err != nil {
			t.Fatal(err)
		}
		generated, err := value.Config()
		if err != nil {
			t.Fatal(err)
		}
		generated.State.Directory = root
		generated.State.Database = databasePath
		generated.State.ProvenanceLedger = ledgerPath
		configData, err := intent.RenderConfig(generated)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, configData, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(intentPath, intentData, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeManaged()
	runner := &statefulOwnedRunner{}
	runtime, err := Open(ctx, configPath, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	runtime.EndpointResolver = &wireguard.Resolver{
		Resolver:  staticEndpointLookup{addresses: []net.IP{net.ParseIP("198.51.100.8")}},
		CachePath: filepath.Join(root, "wg-endpoints.json"),
		Max:       64,
	}
	keyBytes := make([]byte, 32)
	for index := range keyBytes {
		keyBytes[index] = 9
	}
	runtime.WGController = &wireguard.Controller{Runner: staticWGCommandRunner{
		key: base64.StdEncoding.EncodeToString(keyBytes),
	}}
	first, err := runtime.Artifact(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := value.AddExposure("tcp", 443); err != nil {
		t.Fatal(err)
	}
	writeManaged()
	second, err := runtime.Artifact(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.Checksum == second.Checksum {
		t.Fatalf("artifact did not use reloaded policy: first=%s second=%s", first.Checksum, second.Checksum)
	}
	statusValue, err := runtime.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, ok := statusValue.(health.Snapshot)
	if !ok || !snapshot.Managed || len(snapshot.PublicTCP) != 1 ||
		snapshot.PublicTCP[0] != 443 {
		t.Fatalf("status did not use reloaded managed intent: %#v", statusValue)
	}
	runtime.SecurityEvent(ctx, "test_event", "test detail")
	for _, request := range []api.Request{
		{Op: "claims", Limit: 10},
		{Op: "audit"},
		{Op: "plan"},
	} {
		if _, err := runtime.Control(ctx, request); err != nil {
			t.Fatalf("%s failed: %v", request.Op, err)
		}
	}
	if _, err := runtime.Control(ctx, api.Request{Op: "generation", Generation: 999}); err == nil {
		t.Fatal("missing generation was returned")
	}
	if _, err := runtime.Control(ctx, api.Request{Op: "unknown"}); err == nil {
		t.Fatal("unknown control operation accepted")
	}

	runtime.Manager.SafeGuard = func(context.Context) error { return nil }
	runtime.Manager.SafeGuardLocked = func(context.Context) error { return nil }
	runtime.Manager.HealthCheck = nil
	appliedValue, err := runtime.Control(ctx, api.Request{Op: "apply", Safe: true})
	if err != nil {
		t.Fatal(err)
	}
	applied, ok := appliedValue.(reconcile.Result)
	if !ok || applied.Generation == 0 || applied.Deadline == nil {
		t.Fatalf("unexpected safe apply result: %#v", appliedValue)
	}
	generationValue, err := runtime.Control(ctx, api.Request{
		Op: "generation", Generation: applied.Generation,
	})
	if err != nil {
		t.Fatal(err)
	}
	generation, ok := generationValue.(*state.Generation)
	if !ok || generation.Status != "applied" {
		t.Fatalf("applied generation query failed: %#v", generationValue)
	}
	if _, err := runtime.Control(ctx, api.Request{
		Op: "commit", Generation: applied.Generation,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Control(ctx, api.Request{Op: "reconcile"}); err != nil {
		t.Fatal(err)
	}

	pendingValue, err := runtime.Control(ctx, api.Request{Op: "apply", Safe: true})
	if err != nil {
		t.Fatal(err)
	}
	pending := pendingValue.(reconcile.Result)
	if _, err := runtime.Control(ctx, api.Request{
		Op: "rollback", Generation: pending.Generation,
	}); err != nil {
		t.Fatal(err)
	}
	rolled, err := runtime.Store.Generation(ctx, pending.Generation)
	if err != nil || rolled.Status != "rolled_back" {
		t.Fatalf("pending generation was not rolled back: %#v %v", rolled, err)
	}
	if rolledBack, err := runtime.RollbackExpired(ctx); err != nil || rolledBack {
		t.Fatalf("no-pending expiry check changed state: %t %v", rolledBack, err)
	}
}

func TestContainerNetworkProjection(t *testing.T) {
	runtime := &Runtime{Config: config.Config{
		Interfaces: []config.Interface{
			{Name: "br-media", Role: "container", CIDRs: []string{"172.19.0.0/16", "fd00:19::/64"}},
			{Name: "eth0", Role: "uplink"},
		},
		Runtime: config.RuntimeConfig{MaxSetMembers: 4},
	}}
	v4, v6, err := runtime.containerNets(context.Background())
	if err != nil || len(v4) != 1 || v4[0] != "172.19.0.0/16" ||
		len(v6) != 1 || v6[0] != "fd00:19::/64" {
		t.Fatalf("unexpected container networks: %v %v %v", v4, v6, err)
	}
	runtime.Config.Interfaces[0].CIDRs = []string{"0.0.0.0/0"}
	if _, _, err := runtime.containerNets(context.Background()); err == nil {
		t.Fatal("container /0 accepted")
	}
	runtime.containerNetFetcher = func(context.Context) ([]string, []string, error) {
		return []string{"172.20.0.0/16"}, nil, nil
	}
	v4, v6, err = runtime.containerNets(context.Background())
	if err != nil || len(v4) != 1 || v4[0] != "172.20.0.0/16" || len(v6) != 0 {
		t.Fatalf("injected container projection failed: %v %v %v", v4, v6, err)
	}
}

func TestOpenStoreOnlyWrapper(t *testing.T) {
	store, err := OpenStoreOnly(
		context.Background(),
		filepath.Join(secureRuntimeTestDir(t), "state.db"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.QuickCheck(context.Background()); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}
