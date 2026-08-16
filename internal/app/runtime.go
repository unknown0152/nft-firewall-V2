package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/blocks"
	"github.com/unknown0152/nft-firewall-v2/internal/compiler"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/containers"
	"github.com/unknown0152/nft-firewall-v2/internal/geo"
	"github.com/unknown0152/nft-firewall-v2/internal/health"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/policy"
	"github.com/unknown0152/nft-firewall-v2/internal/reconcile"
	"github.com/unknown0152/nft-firewall-v2/internal/recovery"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/threatintel"
	"github.com/unknown0152/nft-firewall-v2/internal/wireguard"
)

type Runtime struct {
	Config           config.Config
	Effective        policy.Effective
	Store            *state.Store
	Backend          *nft.Backend
	Manager          *reconcile.Manager
	EndpointResolver *wireguard.Resolver
	WGController     *wireguard.Controller
}

func Open(ctx context.Context, configPath string, runner nft.Runner) (*Runtime, error) {
	c, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	e, err := policy.Compile(c)
	if err != nil {
		return nil, err
	}
	databasePath := c.State.Database
	if override := os.Getenv("NFTFW_STATE_DB"); override != "" {
		databasePath = override
	}
	st, err := state.Open(ctx, databasePath)
	if err != nil {
		return nil, err
	}
	be := nft.New(runner)
	m := &reconcile.Manager{Backend: be, Store: st, SafeTTL: 90 * time.Second}
	m.SafeGuard = recovery.SystemdGuard{}.Verify
	m.HealthCheck = func(checkCtx context.Context) error {
		ok, detail, checkErr := be.Integrity(checkCtx)
		if checkErr != nil {
			return checkErr
		}
		if !ok {
			return fmt.Errorf("owned-table integrity: %s", detail)
		}
		return nil
	}
	resolver := &wireguard.Resolver{CachePath: filepath.Join(st.Dir, "wg-endpoints.json"), KeepRecent: c.WireGuard.KeepRecent, Max: 64, MaxStale: 24 * time.Hour}
	controller := &wireguard.Controller{}
	return &Runtime{Config: c, Effective: e, Store: st, Backend: be, Manager: m, EndpointResolver: resolver, WGController: controller}, nil
}
func (r *Runtime) Close() error {
	if r == nil || r.Store == nil {
		return nil
	}
	return r.Store.Close()
}

func (r *Runtime) SecurityEvent(ctx context.Context, event, detail string) {
	_ = r.Store.Audit(ctx, "peer", event, detail)
}

func (r *Runtime) Artifact(ctx context.Context) (compiler.Artifact, error) {
	id, err := r.Store.NextGeneration(ctx)
	if err != nil {
		return compiler.Artifact{}, err
	}
	claims, err := r.Store.Claims(ctx, time.Now().UTC())
	if err != nil {
		return compiler.Artifact{}, err
	}
	v4, v6, _, err := r.bootstrapEndpoints(ctx)
	if err != nil {
		return compiler.Artifact{}, err
	}
	dockerV4, dockerV6, err := r.containerNets(ctx)
	if err != nil {
		return compiler.Artifact{}, err
	}
	return compiler.Compile(compiler.Input{Policy: r.Effective, BlockedV4: state.EffectiveAddresses(claims, "ipv4"), BlockedV6: state.EffectiveAddresses(claims, "ipv6"), TrustedV4: state.EffectiveAddressesFrom(claims, "ipv4", "allow"), TrustedV6: state.EffectiveAddressesFrom(claims, "ipv6", "allow"), BootstrapV4: v4, BootstrapV6: v6, DockerNets: dockerV4, DockerNets6: dockerV6}, id)
}

func (r *Runtime) bootstrapEndpoints(ctx context.Context) ([]string, []string, string, error) {
	v4 := append([]string(nil), r.Config.WireGuard.BootstrapIPs...)
	v6 := append([]string(nil), r.Config.WireGuard.BootstrapIPsV6...)
	hosts := append([]string(nil), r.Config.WireGuard.BootstrapHosts...)
	if r.Config.WireGuard.EndpointHost != "" {
		hosts = append(hosts, r.Config.WireGuard.EndpointHost)
	}
	hosts = unique(hosts)
	if len(hosts) == 0 {
		return v4, v6, "", nil
	}
	var lastErr error
	preferred := ""
	for _, host := range hosts {
		addrs, resolveErr := r.EndpointResolver.Resolve(ctx, host)
		if resolveErr != nil {
			lastErr = resolveErr
		}
		if host == r.Config.WireGuard.EndpointHost && len(addrs) > 0 {
			preferred = addrs[0]
		}
		for _, raw := range addrs {
			if ip, parseErr := netip.ParseAddr(raw); parseErr == nil {
				if ip.Is4() {
					v4 = append(v4, ip.String()+"/32")
				} else {
					v6 = append(v6, ip.String()+"/128")
				}
			}
		}
	}
	v4, v6 = unique(v4), unique(v6)
	if len(v4)+len(v6) == 0 {
		return nil, nil, "", fmt.Errorf("WireGuard endpoints could not be resolved and no fresh cached/static address exists: %w", lastErr)
	}
	if len(v4)+len(v6) > 64 {
		return nil, nil, "", fmt.Errorf("WireGuard endpoint set exceeds 64 addresses")
	}
	return v4, v6, preferred, nil
}

func unique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
func (r *Runtime) containerNets(ctx context.Context) (v4, v6 []string, err error) {
	var values []string
	for _, in := range r.Config.Interfaces {
		if in.Role == "container" {
			values = append(values, in.CIDRs...)
		}
	}
	if r.Config.Integrations.DockerEnabled {
		observer := containers.Observer{}
		ok, detail, policyErr := observer.FirewallPolicy()
		if policyErr != nil {
			return nil, nil, fmt.Errorf("Docker integration refused: %s: %w", detail, policyErr)
		}
		if !ok {
			return nil, nil, fmt.Errorf("Docker integration refused: %s", detail)
		}
		networks, observeErr := observer.Networks(ctx)
		if observeErr != nil {
			return nil, nil, fmt.Errorf("observe Docker networks: %w", observeErr)
		}
		for _, network := range networks {
			values = append(values, network.CIDR)
		}
	}
	for _, raw := range unique(values) {
		p, parseErr := netip.ParsePrefix(raw)
		if parseErr != nil || p.Bits() == 0 {
			return nil, nil, fmt.Errorf("invalid container network %q", raw)
		}
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	if len(v4)+len(v6) > r.Config.Runtime.MaxSetMembers {
		return nil, nil, fmt.Errorf("container network count exceeds runtime.max_set_members")
	}
	return v4, v6, nil
}

func (r *Runtime) Status(ctx context.Context) (any, error) {
	return health.Provider{
		Store: r.Store, Backend: r.Backend, WG: r.WGController,
		WGName:          r.Config.WireGuard.Interface,
		WGHealthyWithin: time.Duration(r.Config.WireGuard.HandshakeSecond) * time.Second,
		IPv6Mode:        r.Config.System.IPv6Mode, ZoneCount: len(r.Config.Zones), PolicyCount: len(r.Config.Policies),
	}.Snapshot(ctx)
}
func (r *Runtime) Control(ctx context.Context, req api.Request) (any, error) {
	switch req.Op {
	case "status":
		return r.Status(ctx)
	case "claims":
		return r.Store.Claims(ctx, time.Now().UTC())
	case "audit":
		return r.Store.RecentAudit(ctx, 100)
	case "plan":
		a, err := r.Artifact(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]any{"generation": a.Generation, "checksum": a.Checksum, "script": a.Script}, nil
	case "apply":
		a, err := r.Artifact(ctx)
		if err != nil {
			return nil, err
		}
		return r.Manager.Apply(ctx, a, req.Safe)
	case "commit":
		return nil, r.Manager.Commit(ctx, req.Generation)
	case "rollback":
		return nil, r.Manager.Rollback(ctx, req.Generation)
	case "reconcile":
		return r.Manager.Reconcile(ctx, true)
	case "wg-refresh":
		refreshed, err := r.RefreshEndpoints(ctx)
		return map[string]any{"refreshed": refreshed}, err
	case "block-add":
		id, err := blocks.Service{Store: r.Store, Max: r.Config.Runtime.MaxBlockClaims}.Add(ctx, req.Address, req.Source, req.Reason, "uid:0", nil)
		if err == nil {
			_, err = r.RefreshClaimSets(ctx)
		}
		return map[string]any{"claim_id": id}, err
	case "allow-add":
		id, err := blocks.Service{Store: r.Store, Max: r.Config.Runtime.MaxBlockClaims}.AddAllow(ctx, req.Address, req.Reason, "uid:0", nil)
		if err == nil {
			_, err = r.RefreshClaimSets(ctx)
		}
		return map[string]any{"claim_id": id}, err
	case "block-remove":
		service := blocks.Service{Store: r.Store}
		if err := service.Remove(ctx, req.ClaimID, "uid:0"); err != nil {
			return nil, err
		}
		_, err := r.RefreshClaimSets(ctx)
		return nil, err
	default:
		return nil, fmt.Errorf("unknown control operation %q", req.Op)
	}
}

func (r *Runtime) RollbackExpired(ctx context.Context) (bool, error) {
	return r.Manager.RollbackExpired(ctx)
}

func (r *Runtime) RefreshEndpoints(ctx context.Context) (bool, error) {
	v4, v6, preferred, err := r.bootstrapEndpoints(ctx)
	if err != nil {
		return false, err
	}
	existing, err := r.Backend.ExistingOwned(ctx)
	if err != nil {
		return false, err
	}
	if !existing["inet/"+nft.FilterTable] {
		return false, nil
	}
	if err := r.Backend.ReplaceSets(ctx, map[string][]string{"wg_bootstrap_v4": v4, "wg_bootstrap_v6": v6}); err != nil {
		return false, err
	}
	changed := false
	if preferred != "" && r.WGController != nil {
		changed, err = r.WGController.SetEndpoint(ctx, r.Config.WireGuard.Interface, preferred, r.Config.WireGuard.EndpointPort)
		if err != nil {
			_ = r.Store.Audit(ctx, "system", "wireguard_endpoint_update_failed", "live peer update rejected")
			return false, err
		}
	}
	_ = r.Store.Audit(ctx, "system", "wireguard_endpoint_set_refreshed", fmt.Sprintf("ipv4=%d ipv6=%d", len(v4), len(v6)))
	if changed {
		_ = r.Store.Audit(ctx, "system", "wireguard_endpoint_changed", "live peer endpoint updated")
	}
	return true, nil
}

func (r *Runtime) RefreshClaimSets(ctx context.Context) (bool, error) {
	if _, err := r.Store.PurgeExpiredClaims(ctx, time.Now().UTC()); err != nil {
		return false, err
	}
	claims, err := r.Store.Claims(ctx, time.Now().UTC())
	if err != nil {
		return false, err
	}
	existing, err := r.Backend.ExistingOwned(ctx)
	if err != nil {
		return false, err
	}
	if !existing["inet/"+nft.FilterTable] {
		return false, nil
	}
	sets := map[string][]string{
		"blocked_v4": state.EffectiveAddresses(claims, "ipv4"),
		"blocked_v6": state.EffectiveAddresses(claims, "ipv6"),
		"trusted_v4": state.EffectiveAddressesFrom(claims, "ipv4", "allow"),
		"trusted_v6": state.EffectiveAddressesFrom(claims, "ipv6", "allow"),
	}
	if err := r.Backend.ReplaceSets(ctx, sets); err != nil {
		return false, err
	}
	return true, nil
}

func (r *Runtime) RefreshContainerSets(ctx context.Context) (bool, error) {
	v4, v6, err := r.containerNets(ctx)
	if err != nil {
		if r.Config.Integrations.DockerEnabled {
			_ = r.Store.SetIntegrationState(ctx, "docker", "degraded", 0, false)
		}
		return false, err
	}
	existing, err := r.Backend.ExistingOwned(ctx)
	if err != nil {
		return false, err
	}
	if !existing["inet/"+nft.FilterTable] || !existing["ip/"+nft.NATTable] {
		return false, nil
	}
	if err := r.Backend.ReplaceContainerNetworks(ctx, v4, v6); err != nil {
		return false, err
	}
	if r.Config.Integrations.DockerEnabled {
		_ = r.Store.SetIntegrationState(ctx, "docker", "healthy", len(v4)+len(v6), true)
	}
	return true, nil
}

func (r *Runtime) RefreshIntegrations(ctx context.Context) error {
	var failures []error
	updated := false
	for _, feedConfig := range r.Config.ThreatFeeds {
		name := "threatfeed/" + feedConfig.Name
		if !r.integrationDue(ctx, name, feedConfig.RefreshSeconds) {
			continue
		}
		max := feedConfig.MaxEntries
		if max == 0 {
			max = 10000
		}
		maxBytes := feedConfig.MaxBytes
		if maxBytes == 0 {
			maxBytes = 8 << 20
		}
		min := feedConfig.MinEntries
		if min == 0 {
			min = 1
		}
		addresses, err := (threatintel.Feed{URL: feedConfig.URL, MaxEntries: max, MaxBytes: maxBytes}).Fetch(ctx)
		if err == nil && len(addresses) < min {
			err = fmt.Errorf("entry sanity threshold not met: got %d, require %d", len(addresses), min)
		}
		if err == nil {
			other, countErr := r.Store.ClaimCountExcludingSource(ctx, name)
			if countErr != nil {
				err = countErr
			} else if other+len(addresses) > r.Config.Runtime.MaxBlockClaims {
				err = fmt.Errorf("claim limit would be exceeded")
			}
		}
		if err != nil {
			oldCount, _ := r.Store.SourceClaimCount(ctx, name)
			_ = r.Store.SetIntegrationState(ctx, name, "degraded", oldCount, false)
			_ = r.Store.Audit(ctx, "integration", "threat_feed_failed", fmt.Sprintf("name=%s", feedConfig.Name))
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
			continue
		}
		count, err := r.Store.ReplaceSourceClaims(ctx, name, "threat intelligence", "integration", addresses)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
			continue
		}
		_ = r.Store.SetIntegrationState(ctx, name, "healthy", count, true)
		updated = true
	}
	for _, geoConfig := range r.Config.GeoSets {
		name := "geo/" + geoConfig.Name
		if !r.integrationDue(ctx, name, geoConfig.RefreshSeconds) {
			continue
		}
		max := geoConfig.MaxEntries
		if max == 0 {
			max = 100000
		}
		min := geoConfig.MinEntries
		if min == 0 {
			min = 1
		}
		addresses, err := geo.LoadCIDRs(geoConfig.CIDRFile, max)
		if err == nil && len(addresses) < min {
			err = fmt.Errorf("entry sanity threshold not met: got %d, require %d", len(addresses), min)
		}
		if err != nil {
			oldCount, _ := r.Store.SourceClaimCount(ctx, name)
			_ = r.Store.SetIntegrationState(ctx, name, "degraded", oldCount, false)
			_ = r.Store.Audit(ctx, "integration", "geoip_refresh_failed", fmt.Sprintf("name=%s", geoConfig.Name))
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
			continue
		}
		count, err := r.Store.ReplaceSourceClaims(ctx, name, "GeoIP "+geoConfig.Country, "integration", addresses)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
			continue
		}
		_ = r.Store.SetIntegrationState(ctx, name, "healthy", count, true)
		updated = true
	}
	if updated {
		if _, err := r.RefreshClaimSets(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (r *Runtime) integrationDue(ctx context.Context, name string, refreshSeconds int) bool {
	if refreshSeconds == 0 {
		refreshSeconds = 3600
	}
	current, err := r.Store.IntegrationState(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return true
	}
	if err != nil {
		return true
	}
	return time.Now().UTC().Sub(current.UpdatedAt) >= time.Duration(refreshSeconds)*time.Second
}
func OpenStoreOnly(ctx context.Context, path string) (*state.Store, error) {
	return state.Open(ctx, path)
}
