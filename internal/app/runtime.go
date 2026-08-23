package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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
	Config              config.Config
	Effective           policy.Effective
	Store               *state.Store
	Backend             *nft.Backend
	Manager             *reconcile.Manager
	EndpointResolver    *wireguard.Resolver
	WGController        *wireguard.Controller
	threatFeedFetcher   func(context.Context, threatintel.Feed) ([]string, error)
	containerNetFetcher func(context.Context) ([]string, []string, error)
	claimMu             sync.Mutex
}

type refreshedIntegration struct {
	name   string
	reason string
	count  int
	prior  []string
}

type integrationRefreshCandidate struct {
	name           string
	displayName    string
	kind           string
	reason         string
	addresses      []string
	protected      []string
	refreshSeconds int
	err            error
}

type claimPublicationLockContextKey struct{}

const postMutationRecoveryTimeout = 20 * time.Second

func postMutationRecoveryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), postMutationRecoveryTimeout)
}

func Open(ctx context.Context, configPath string, runner nft.Runner) (*Runtime, error) {
	return open(ctx, configPath, runner, true)
}

// OpenQuiet is used by the frequent independent rollback check. It avoids a
// configuration-loaded audit row for every no-op timer invocation.
func OpenQuiet(ctx context.Context, configPath string, runner nft.Runner) (*Runtime, error) {
	return open(ctx, configPath, runner, false)
}

func open(ctx context.Context, configPath string, runner nft.Runner, auditConfiguration bool) (*Runtime, error) {
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
	knownGood, knownGoodErr := st.LastKnownGood(ctx)
	pending, pendingErr := st.Pending(ctx)
	if knownGoodErr != nil && !errors.Is(knownGoodErr, sql.ErrNoRows) {
		_ = st.Close()
		return nil, fmt.Errorf("inspect committed generation state: %w", knownGoodErr)
	}
	if pendingErr != nil && !errors.Is(pendingErr, sql.ErrNoRows) {
		_ = st.Close()
		return nil, fmt.Errorf("inspect pending generation state: %w", pendingErr)
	}
	if knownGood == nil && pending == nil {
		if err := be.ProtectFirstUse(ctx); err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("first-use ownership check: %w", err)
		}
	}
	m := &reconcile.Manager{Backend: be, Store: st, SafeTTL: time.Duration(c.Runtime.SafeApplySeconds) * time.Second}
	m.SafeGuard = recovery.SystemdGuard{StateDB: st.Path}.Verify
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
	runtime := &Runtime{Config: c, Effective: e, Store: st, Backend: be, Manager: m, EndpointResolver: resolver, WGController: controller}
	// OpenQuiet is the independent safe-apply timer path. It must be able to
	// prove that no pending generation exists while an outer safe apply holds
	// the claim lock during rollback-guard preflight, so it performs no startup
	// retirement writes. The normal daemon open owns lifecycle retirement.
	if auditConfiguration {
		releaseClaims, err := runtime.acquireClaimPublicationLock(ctx)
		if err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("lock integration retirement: %w", err)
		}
		_, retirementErr := st.RetireInactiveIntegrations(ctx, runtime.activeIntegrationNames())
		releaseClaims()
		if retirementErr != nil {
			_ = st.Close()
			return nil, fmt.Errorf("retire inactive integrations: %w", retirementErr)
		}
	}
	m.PostRestore = runtime.RestoreRuntimeState
	if auditConfiguration {
		_ = st.Audit(ctx, "system", "configuration_loaded", fmt.Sprintf("ipv6=%s zones=%d policies=%d", c.System.IPv6Mode, len(c.Zones), len(c.Policies)))
	}
	return runtime, nil
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
	release, err := r.acquireClaimPublicationLock(ctx)
	if err != nil {
		return compiler.Artifact{}, err
	}
	defer release()
	return r.artifactLocked(ctx)
}

func (r *Runtime) artifactLocked(ctx context.Context) (compiler.Artifact, error) {
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
	protected := append(append([]string(nil), v4...), v6...)
	claimSets, err := r.claimSets(claims, time.Now().UTC(), protected)
	if err != nil {
		return compiler.Artifact{}, err
	}
	return compiler.Compile(compiler.Input{Policy: r.Effective, BlockedV4: claimSets.blockedV4, BlockedV6: claimSets.blockedV6, BootstrapV4: v4, BootstrapV6: v6, DockerNets: dockerV4, DockerNets6: dockerV6}, id)
}

type runtimeClaimSets struct {
	blockedV4, blockedV6 []string
	trustedV4, trustedV6 []nft.TimedElement
}

func (r *Runtime) claimSets(claims []state.Claim, now time.Time, bootstrapProtected []string) (runtimeClaimSets, error) {
	threatAddresses := threatFeedClaimAddresses(claims)
	if len(threatAddresses) > 0 {
		protected := append(r.configuredThreatFeedProtectedPrefixes(), bootstrapProtected...)
		if err := threatintel.Validate(threatAddresses, unique(protected)); err != nil {
			return runtimeClaimSets{}, fmt.Errorf("stored threat-feed claims failed safety validation: %w", err)
		}
	}
	trustedV4, err := effectiveTrusted(claims, "ipv4", now)
	if err != nil {
		return runtimeClaimSets{}, err
	}
	trustedV6, err := effectiveTrusted(claims, "ipv6", now)
	if err != nil {
		return runtimeClaimSets{}, err
	}
	sets := runtimeClaimSets{
		blockedV4: state.EffectiveAddresses(claims, "ipv4"),
		blockedV6: state.EffectiveAddresses(claims, "ipv6"),
		trustedV4: trustedV4,
		trustedV6: trustedV6,
	}
	counts := map[string]int{
		"blocked_v4": len(sets.blockedV4), "blocked_v6": len(sets.blockedV6),
		"trusted_v4": len(sets.trustedV4), "trusted_v6": len(sets.trustedV6),
	}
	for name, count := range counts {
		if count > r.Config.Runtime.MaxSetMembers {
			return runtimeClaimSets{}, fmt.Errorf("runtime set %s exceeds runtime.max_set_members (%d)", name, r.Config.Runtime.MaxSetMembers)
		}
	}
	return sets, nil
}

func threatFeedClaimAddresses(claims []state.Claim) []string {
	var addresses []string
	for _, claim := range claims {
		if strings.HasPrefix(claim.Source, "threatfeed/") {
			addresses = append(addresses, claim.Address)
		}
	}
	return unique(addresses)
}

func effectiveTrusted(claims []state.Claim, family string, now time.Time) ([]nft.TimedElement, error) {
	type lease struct {
		expires time.Time
	}
	byAddress := map[string]lease{}
	for _, claim := range claims {
		if claim.Family != family || claim.Source != "allow" && !strings.HasPrefix(claim.Source, "allow/") {
			continue
		}
		if claim.ExpiresAt == nil {
			return nil, fmt.Errorf("temporary access claim %d has no expiry", claim.ID)
		}
		current := byAddress[claim.Address]
		if claim.ExpiresAt.After(current.expires) {
			current.expires = claim.ExpiresAt.UTC()
		}
		byAddress[claim.Address] = current
	}
	result := make([]nft.TimedElement, 0, len(byAddress))
	for address, lease := range byAddress {
		element := nft.TimedElement{Prefix: address}
		remaining := lease.expires.Sub(now)
		if remaining <= 0 {
			continue
		}
		element.TimeoutSeconds = int64((remaining + time.Second - 1) / time.Second)
		result = append(result, element)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Prefix < result[j].Prefix })
	return result, nil
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
	if r.EndpointResolver == nil {
		return nil, nil, "", errors.New("WireGuard endpoint resolver is unavailable")
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
	if r.containerNetFetcher != nil {
		return r.containerNetFetcher(ctx)
	}
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
			return nil, nil, fmt.Errorf("docker integration refused: %s: %w", detail, policyErr)
		}
		if !ok {
			return nil, nil, fmt.Errorf("docker integration refused: %s", detail)
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
		ActiveIntegrations: r.activeIntegrationNames(),
	}.Snapshot(ctx)
}

func (r *Runtime) activeIntegrationNames() map[string]bool {
	names := map[string]bool{
		"runtime/claims": true,
		"wireguard/" + r.Config.WireGuard.Interface: true,
	}
	if r.Config.Integrations.DockerEnabled {
		names["docker"] = true
	}
	if r.Config.Integrations.ThreatFeed {
		for _, feed := range r.Config.ThreatFeeds {
			names["threatfeed/"+feed.Name] = true
		}
	}
	if r.Config.Integrations.GeoIP {
		for _, geoSet := range r.Config.GeoSets {
			names["geo/"+geoSet.Name] = true
		}
	}
	return names
}
func (r *Runtime) Control(ctx context.Context, req api.Request) (any, error) {
	switch req.Op {
	case "status":
		return r.Status(ctx)
	case "claims":
		limit := req.Limit
		if limit == 0 {
			limit = 1000
		}
		now := time.Now().UTC()
		claims, err := r.Store.ClaimsPage(ctx, now, limit, req.Offset)
		if err != nil {
			return nil, err
		}
		total, err := r.Store.ActiveClaimCount(ctx, now)
		return map[string]any{"claims": claims, "total": total, "limit": limit, "offset": req.Offset}, err
	case "audit":
		return r.Store.RecentAudit(ctx, 100)
	case "plan":
		a, err := r.Artifact(ctx)
		if err != nil {
			return nil, err
		}
		_ = r.Store.Audit(ctx, "uid:0", "firewall_plan_generated", fmt.Sprintf("generation=%d checksum=%s", a.Generation, a.Checksum))
		return map[string]any{"generation": a.Generation, "checksum": a.Checksum, "script": a.Script}, nil
	case "apply":
		release, err := r.acquireClaimPublicationLock(ctx)
		if err != nil {
			return nil, err
		}
		defer release()
		a, err := r.artifactLocked(ctx)
		if err != nil {
			return nil, err
		}
		if _, err := r.Store.PrepareClaimPublication(ctx); err != nil {
			return nil, fmt.Errorf("mark runtime claims pending before policy apply: %w", err)
		}
		lockedCtx := context.WithValue(ctx, claimPublicationLockContextKey{}, true)
		result, err := r.Manager.Apply(lockedCtx, a, req.Safe)
		if err != nil {
			return nil, err
		}
		recoveryCtx, cancel := postMutationRecoveryContext(ctx)
		defer cancel()
		recoveryLockedCtx := context.WithValue(recoveryCtx, claimPublicationLockContextKey{}, true)
		if _, err := r.refreshClaimSetsLocked(recoveryCtx); err != nil {
			rollbackErr := r.Manager.Rollback(recoveryLockedCtx, a.Generation)
			if rollbackErr != nil {
				return nil, fmt.Errorf("apply runtime lease reconciliation failed: %w; rollback also failed: %v", err, rollbackErr)
			}
			return nil, fmt.Errorf("apply runtime lease reconciliation failed and generation was rolled back: %w", err)
		}
		return result, nil
	case "commit":
		return nil, r.Commit(ctx, req.Generation)
	case "rollback":
		return nil, r.Rollback(ctx, req.Generation)
	case "reconcile":
		return r.Reconcile(ctx, true)
	case "wg-refresh":
		refreshed, err := r.RefreshEndpoints(ctx)
		return map[string]any{"refreshed": refreshed}, err
	case "block-add":
		expires, err := claimExpiry(req.ExpiresSec)
		if err != nil {
			return nil, err
		}
		release, err := r.acquireClaimPublicationLock(ctx)
		if err != nil {
			return nil, err
		}
		defer release()
		return r.addClaimAndPublishLocked(ctx, "block", func() (int64, error) {
			return (blocks.Service{Store: r.Store, Max: r.Config.Runtime.MaxBlockClaims}).Add(ctx, req.Address, req.Source, req.Reason, "uid:0", expires)
		})
	case "allow-add":
		if len(r.Config.Runtime.TrustedServices) == 0 {
			return nil, errors.New("temporary access is disabled because runtime.trusted_services is empty")
		}
		if req.ExpiresSec <= 0 {
			return nil, errors.New("temporary access requires a positive expiry")
		}
		expires, err := claimExpiry(req.ExpiresSec)
		if err != nil {
			return nil, err
		}
		release, err := r.acquireClaimPublicationLock(ctx)
		if err != nil {
			return nil, err
		}
		defer release()
		return r.addClaimAndPublishLocked(ctx, "allow", func() (int64, error) {
			return (blocks.Service{Store: r.Store, Max: r.Config.Runtime.MaxBlockClaims}).AddAllow(ctx, req.Address, req.Reason, "uid:0", expires)
		})
	case "block-remove":
		release, err := r.acquireClaimPublicationLock(ctx)
		if err != nil {
			return nil, err
		}
		defer release()
		return nil, r.removeClaimAndPublishLocked(ctx, req.ClaimID, "block")
	case "allow-remove":
		release, err := r.acquireClaimPublicationLock(ctx)
		if err != nil {
			return nil, err
		}
		defer release()
		return nil, r.removeClaimAndPublishLocked(ctx, req.ClaimID, "allow")
	default:
		return nil, fmt.Errorf("unknown control operation %q", req.Op)
	}
}

func (r *Runtime) addClaimAndPublishLocked(ctx context.Context, kind string, add func() (int64, error)) (any, error) {
	id, err := add()
	if err != nil {
		return nil, err
	}
	if _, publishErr := r.refreshClaimSetsLocked(ctx); publishErr != nil {
		recoveryCtx, cancel := postMutationRecoveryContext(ctx)
		defer cancel()
		service := blocks.Service{Store: r.Store}
		var compensateErr error
		if kind == "allow" {
			compensateErr = service.RemoveAllow(recoveryCtx, id, "uid:0-compensation")
		} else {
			compensateErr = service.RemoveBlock(recoveryCtx, id, "uid:0-compensation")
		}
		if compensateErr != nil {
			return nil, errors.Join(fmt.Errorf("claim %d publication failed and the durable add could not be reverted: %w", id, publishErr), compensateErr)
		}
		_, restoreErr := r.refreshClaimSetsLocked(recoveryCtx)
		if restoreErr != nil {
			return nil, errors.Join(fmt.Errorf("claim %d publication failed; durable add was reverted", id), publishErr, fmt.Errorf("restore prior runtime sets: %w", restoreErr))
		}
		return nil, fmt.Errorf("claim %d publication failed and was reverted: %w", id, publishErr)
	}
	return map[string]any{"claim_id": id}, nil
}

func (r *Runtime) acquireClaimPublicationLock(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("wait for claim publication lock: %w", err)
	}
	for !r.claimMu.TryLock() {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for claim publication lock: %w", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := ctx.Err(); err != nil {
		r.claimMu.Unlock()
		return nil, fmt.Errorf("wait for claim publication lock: %w", err)
	}
	releaseProcess, err := state.AcquireClaimPublicationLock(ctx, r.Store.Dir)
	if err != nil {
		r.claimMu.Unlock()
		return nil, err
	}
	return func() {
		releaseProcess()
		r.claimMu.Unlock()
	}, nil
}

func (r *Runtime) removeClaimAndPublishLocked(ctx context.Context, id int64, kind string) error {
	claim, err := r.operatorClaimLocked(ctx, id, kind)
	if err != nil {
		return err
	}
	service := blocks.Service{Store: r.Store}
	if kind == "allow" {
		err = service.RemoveAllow(ctx, id, "uid:0")
	} else {
		err = service.RemoveBlock(ctx, id, "uid:0")
	}
	if err != nil {
		return err
	}
	if _, publishErr := r.refreshClaimSetsLocked(ctx); publishErr != nil {
		recoveryCtx, cancel := postMutationRecoveryContext(ctx)
		defer cancel()
		if restoreErr := r.Store.RestoreClaim(recoveryCtx, claim, "uid:0-compensation"); restoreErr != nil {
			return errors.Join(fmt.Errorf("claim %d removal publication failed and the durable claim could not be restored: %w", id, publishErr), restoreErr)
		}
		_, restoreErr := r.refreshClaimSetsLocked(recoveryCtx)
		if restoreErr != nil {
			return errors.Join(fmt.Errorf("claim %d removal publication failed; durable claim was restored", id), publishErr, fmt.Errorf("restore prior runtime sets: %w", restoreErr))
		}
		return fmt.Errorf("claim %d removal publication failed and was reverted: %w", id, publishErr)
	}
	return nil
}

func (r *Runtime) operatorClaimLocked(ctx context.Context, id int64, kind string) (state.Claim, error) {
	claims, err := r.Store.Claims(ctx, time.Now().UTC())
	if err != nil {
		return state.Claim{}, err
	}
	for _, claim := range claims {
		if claim.ID != id {
			continue
		}
		isAllow := claim.Source == "allow" || strings.HasPrefix(claim.Source, "allow/")
		if kind == "allow" && !isAllow || kind == "block" && claim.Source != "manual" {
			return state.Claim{}, fmt.Errorf("claim %d cannot be removed as %s", id, kind)
		}
		return claim, nil
	}
	return state.Claim{}, sql.ErrNoRows
}

func claimExpiry(seconds int64) (*time.Time, error) {
	if seconds < 0 || seconds > 365*24*60*60 {
		return nil, errors.New("claim expiry must be between zero and one year")
	}
	if seconds == 0 {
		return nil, nil
	}
	expires := time.Now().UTC().Add(time.Duration(seconds) * time.Second)
	return &expires, nil
}

func (r *Runtime) RollbackExpired(ctx context.Context) (bool, error) {
	// The systemd guard synchronously starts the timer service while the outer
	// safe apply holds the claim lock. A no-pending (or unexpired) check must
	// therefore complete without that lock; any actionable result is rechecked
	// after acquisition below.
	pending, err := r.Store.Pending(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if pending.RollbackDeadline == nil || time.Now().UTC().Before(*pending.RollbackDeadline) {
		return false, nil
	}
	release, err := r.acquireClaimPublicationLock(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	pending, err = r.Store.Pending(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if pending.RollbackDeadline == nil || time.Now().UTC().Before(*pending.RollbackDeadline) {
		return false, nil
	}
	if _, err := r.Store.PrepareClaimPublication(ctx); err != nil {
		return false, fmt.Errorf("mark runtime claims pending before expired rollback: %w", err)
	}
	lockedCtx := context.WithValue(ctx, claimPublicationLockContextKey{}, true)
	rolledBack, rollbackErr := r.Manager.RollbackExpired(lockedCtx)
	if rollbackErr != nil || !rolledBack {
		return rolledBack, rollbackErr
	}
	recoveryCtx, cancel := postMutationRecoveryContext(ctx)
	defer cancel()
	_, refreshErr := r.refreshClaimSetsLocked(recoveryCtx)
	return true, refreshErr
}

func (r *Runtime) Rollback(ctx context.Context, generation uint64) error {
	release, err := r.acquireClaimPublicationLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	if _, err := r.Store.PrepareClaimPublication(ctx); err != nil {
		return fmt.Errorf("mark runtime claims pending before rollback: %w", err)
	}
	lockedCtx := context.WithValue(ctx, claimPublicationLockContextKey{}, true)
	rollbackErr := r.Manager.Rollback(lockedCtx, generation)
	if rollbackErr != nil {
		return rollbackErr
	}
	recoveryCtx, cancel := postMutationRecoveryContext(ctx)
	defer cancel()
	_, refreshErr := r.refreshClaimSetsLocked(recoveryCtx)
	return refreshErr
}

func (r *Runtime) Commit(ctx context.Context, generation uint64) error {
	release, err := r.acquireClaimPublicationLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	if _, err := r.Store.PrepareClaimPublication(ctx); err != nil {
		return fmt.Errorf("mark runtime claims pending before commit: %w", err)
	}
	lockedCtx := context.WithValue(ctx, claimPublicationLockContextKey{}, true)
	if err := r.Manager.Commit(lockedCtx, generation); err != nil {
		return err
	}
	recoveryCtx, cancel := postMutationRecoveryContext(ctx)
	defer cancel()
	_, err = r.refreshClaimSetsLocked(recoveryCtx)
	return err
}

func (r *Runtime) Reconcile(ctx context.Context, repair bool) (reconcile.Drift, error) {
	if !repair {
		return r.Manager.Reconcile(ctx, false)
	}
	release, err := r.acquireClaimPublicationLock(ctx)
	if err != nil {
		return reconcile.Drift{}, err
	}
	defer release()
	if _, err := r.Store.PrepareClaimPublication(ctx); err != nil {
		return reconcile.Drift{}, fmt.Errorf("mark runtime claims pending before reconciliation: %w", err)
	}
	lockedCtx := context.WithValue(ctx, claimPublicationLockContextKey{}, true)
	drift, reconcileErr := r.Manager.Reconcile(lockedCtx, true)
	if reconcileErr != nil {
		return drift, reconcileErr
	}
	recoveryCtx, cancel := postMutationRecoveryContext(ctx)
	defer cancel()
	_, refreshErr := r.refreshClaimSetsLocked(recoveryCtx)
	return drift, refreshErr
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
		observation := r.WGController.Observe(ctx, r.Config.WireGuard.Interface, time.Duration(r.Config.WireGuard.HandshakeSecond)*time.Second)
		if !observation.Healthy {
			_ = r.Store.Audit(ctx, "system", "wireguard_recovery_attempted", "bounded endpoint refresh")
		}
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

func (r *Runtime) RefreshWireGuardHealth(ctx context.Context) error {
	if r.WGController == nil {
		return nil
	}
	name := "wireguard/" + r.Config.WireGuard.Interface
	observation := r.WGController.Observe(ctx, r.Config.WireGuard.Interface, time.Duration(r.Config.WireGuard.HandshakeSecond)*time.Second)
	previous, previousErr := r.Store.IntegrationState(ctx, name)
	if observation.Healthy {
		if err := r.Store.SetIntegrationState(ctx, name, "healthy", observation.PeerCount, true); err != nil {
			return err
		}
		if previousErr == nil && previous.Status == "degraded" {
			_ = r.Store.Audit(ctx, "system", "vpn_recovered", "WireGuard handshake healthy")
		}
		return nil
	}
	if err := r.Store.SetIntegrationState(ctx, name, "degraded", observation.PeerCount, false); err != nil {
		return err
	}
	if errors.Is(previousErr, sql.ErrNoRows) || previousErr == nil && previous.Status != "degraded" {
		_ = r.Store.Audit(ctx, "system", "vpn_failure_detected", observation.Reason)
	}
	return nil
}

func (r *Runtime) RefreshClaimSets(ctx context.Context) (bool, error) {
	release, err := r.acquireClaimPublicationLock(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	return r.refreshClaimSetsLocked(ctx)
}

func (r *Runtime) refreshClaimSetsLocked(ctx context.Context) (bool, error) {
	if _, err := r.Store.PurgeExpiredClaims(ctx, time.Now().UTC()); err != nil {
		return false, err
	}
	revision, err := r.Store.PrepareClaimPublication(ctx)
	if err != nil {
		return false, fmt.Errorf("prepare runtime claim publication: %w", err)
	}
	claims, publication, err := r.Store.ClaimsWithPublication(ctx, time.Now().UTC())
	if err != nil {
		return false, err
	}
	if publication.DesiredRevision != revision {
		return false, errors.New("runtime claims changed before publication")
	}
	var protected []string
	if len(threatFeedClaimAddresses(claims)) > 0 {
		protected, err = r.threatFeedProtectedPrefixes(ctx)
		if err != nil {
			return false, fmt.Errorf("resolve threat-feed protected prefixes: %w", err)
		}
	}
	sets, err := r.claimSets(claims, time.Now().UTC(), protected)
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
	if err := r.Backend.ReplaceClaimSets(ctx, sets.blockedV4, sets.blockedV6, sets.trustedV4, sets.trustedV6); err != nil {
		return false, err
	}
	stateCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := r.Store.MarkClaimsPublished(stateCtx, revision, len(claims)); err != nil {
		return false, fmt.Errorf("record runtime claim publication: %w", err)
	}
	return true, nil
}

func (r *Runtime) RefreshContainerSets(ctx context.Context) (bool, error) {
	v4, v6, err := r.containerNets(ctx)
	if err != nil {
		return r.failContainerRefresh(ctx, 0, err)
	}
	existing, err := r.Backend.ExistingOwned(ctx)
	if err != nil {
		return r.failContainerRefresh(ctx, len(v4)+len(v6), err)
	}
	if !existing["inet/"+nft.FilterTable] || !existing["ip/"+nft.NATTable] {
		return false, nil
	}
	if err := r.Backend.ReplaceContainerNetworks(ctx, v4, v6); err != nil {
		return r.failContainerRefresh(ctx, len(v4)+len(v6), err)
	}
	if r.Config.Integrations.DockerEnabled {
		if err := r.setDockerIntegrationState(ctx, "healthy", len(v4)+len(v6), true); err != nil {
			return false, fmt.Errorf("record Docker integration health: %w", err)
		}
	}
	return true, nil
}

func (r *Runtime) failContainerRefresh(ctx context.Context, count int, cause error) (bool, error) {
	if r.Config.Integrations.DockerEnabled {
		if stateErr := r.setDockerIntegrationState(ctx, "degraded", count, false); stateErr != nil {
			return false, errors.Join(cause, fmt.Errorf("record Docker integration degradation: %w", stateErr))
		}
	}
	return false, cause
}

func (r *Runtime) setDockerIntegrationState(ctx context.Context, status string, count int, success bool) error {
	return r.setIntegrationStateDurable(ctx, "docker", status, count, success)
}

func (r *Runtime) setIntegrationStateDurable(ctx context.Context, name, status string, count int, success bool) error {
	stateCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return r.Store.SetIntegrationState(stateCtx, name, status, count, success)
}

// RestoreRuntimeState repopulates every mutable set after a generation
// restore. Callers install emergency deny if any component cannot be restored.
func (r *Runtime) RestoreRuntimeState(ctx context.Context) error {
	var failures []error
	var claimErr error
	if locked, _ := ctx.Value(claimPublicationLockContextKey{}).(bool); locked {
		_, claimErr = r.refreshClaimSetsLocked(ctx)
	} else {
		_, claimErr = r.RefreshClaimSets(ctx)
	}
	if claimErr != nil {
		failures = append(failures, fmt.Errorf("claims: %w", claimErr))
	}
	if _, err := r.RefreshEndpoints(ctx); err != nil {
		failures = append(failures, fmt.Errorf("WireGuard endpoints: %w", err))
	}
	if _, err := r.RefreshContainerSets(ctx); err != nil {
		failures = append(failures, fmt.Errorf("container networks: %w", err))
	}
	return errors.Join(failures...)
}

func (r *Runtime) RefreshIntegrations(ctx context.Context) error {
	candidates := r.prepareIntegrationRefreshes(ctx)
	release, err := r.acquireClaimPublicationLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	return r.refreshIntegrationsLocked(ctx, candidates)
}

func (r *Runtime) prepareIntegrationRefreshes(ctx context.Context) []integrationRefreshCandidate {
	var candidates []integrationRefreshCandidate
	var protected []string
	var protectedErr error
	protectedLoaded := false
	if r.Config.Integrations.ThreatFeed {
		for _, feedConfig := range r.Config.ThreatFeeds {
			name := "threatfeed/" + feedConfig.Name
			if !r.integrationDue(ctx, name, feedConfig.RefreshSeconds) {
				continue
			}
			candidate := integrationRefreshCandidate{
				name: name, displayName: feedConfig.Name, kind: "threatfeed",
				reason: "threat intelligence", refreshSeconds: feedConfig.RefreshSeconds,
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
			if !protectedLoaded {
				protected, protectedErr = r.threatFeedProtectedPrefixes(ctx)
				protectedLoaded = true
			}
			candidate.protected = append([]string(nil), protected...)
			if protectedErr != nil {
				candidate.err = fmt.Errorf("resolve protected prefixes: %w", protectedErr)
			} else {
				feed := threatintel.Feed{URL: feedConfig.URL, MaxEntries: max, MaxBytes: maxBytes}
				candidate.addresses, candidate.err = r.fetchThreatFeed(ctx, feed)
				if candidate.err == nil && len(candidate.addresses) < min {
					candidate.err = fmt.Errorf("entry sanity threshold not met: got %d, require %d", len(candidate.addresses), min)
				}
			}
			candidates = append(candidates, candidate)
		}
	}
	if r.Config.Integrations.GeoIP {
		for _, geoConfig := range r.Config.GeoSets {
			name := "geo/" + geoConfig.Name
			if !r.integrationDue(ctx, name, geoConfig.RefreshSeconds) {
				continue
			}
			candidate := integrationRefreshCandidate{
				name: name, displayName: geoConfig.Name, kind: "geo",
				reason: "GeoIP " + geoConfig.Country, refreshSeconds: geoConfig.RefreshSeconds,
			}
			max := geoConfig.MaxEntries
			if max == 0 {
				max = 100000
			}
			min := geoConfig.MinEntries
			if min == 0 {
				min = 1
			}
			candidate.addresses, candidate.err = geo.LoadCIDRs(geoConfig.CIDRFile, max)
			if candidate.err == nil && len(candidate.addresses) < min {
				candidate.err = fmt.Errorf("entry sanity threshold not met: got %d, require %d", len(candidate.addresses), min)
			}
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func (r *Runtime) refreshIntegrationsLocked(ctx context.Context, candidates []integrationRefreshCandidate) error {
	var failures []error
	var refreshed []refreshedIntegration
	for _, candidate := range candidates {
		if !r.integrationDue(ctx, candidate.name, candidate.refreshSeconds) {
			continue
		}
		candidateErr := candidate.err
		if candidateErr == nil && candidate.kind == "threatfeed" {
			candidateErr = r.validateThreatFeedReplacement(ctx, candidate.name, candidate.addresses, candidate.protected)
		}
		if candidateErr != nil {
			oldCount, _ := r.Store.SourceClaimCount(ctx, candidate.name)
			event := "geoip_refresh_failed"
			if candidate.kind == "threatfeed" {
				event = "threat_feed_failed"
			}
			_ = r.Store.Audit(ctx, "integration", event, fmt.Sprintf("name=%s", candidate.displayName))
			failures = append(failures, fmt.Errorf("%s: %w", candidate.name, candidateErr))
			if stateErr := r.setIntegrationStateDurable(ctx, candidate.name, "degraded", oldCount, false); stateErr != nil {
				failures = append(failures, fmt.Errorf("%s: record degraded integration state: %w", candidate.name, stateErr))
			}
			continue
		}
		prior, err := r.sourceClaimAddresses(ctx, candidate.name)
		if err != nil {
			oldCount, _ := r.Store.SourceClaimCount(ctx, candidate.name)
			failures = append(failures, fmt.Errorf("%s: snapshot prior claims: %w", candidate.name, err))
			if stateErr := r.setIntegrationStateDurable(ctx, candidate.name, "degraded", oldCount, false); stateErr != nil {
				failures = append(failures, fmt.Errorf("%s: record degraded integration state: %w", candidate.name, stateErr))
			}
			continue
		}
		count, err := r.Store.ReplaceSourceClaimsBounded(ctx, candidate.name, candidate.reason, "integration", candidate.addresses, r.Config.Runtime.MaxBlockClaims)
		if err != nil {
			oldCount, _ := r.Store.SourceClaimCount(ctx, candidate.name)
			failures = append(failures, fmt.Errorf("%s: %w", candidate.name, err))
			if stateErr := r.setIntegrationStateDurable(ctx, candidate.name, "degraded", oldCount, false); stateErr != nil {
				failures = append(failures, fmt.Errorf("%s: record degraded integration state: %w", candidate.name, stateErr))
			}
			continue
		}
		refreshed = append(refreshed, refreshedIntegration{name: candidate.name, reason: candidate.reason, count: count, prior: prior})
	}
	if len(refreshed) > 0 {
		if _, err := r.refreshClaimSetsLocked(ctx); err != nil {
			failures = append(failures, fmt.Errorf("publish refreshed integration claims: %w", err))
			recoveryCtx, cancel := postMutationRecoveryContext(ctx)
			defer cancel()
			rollbackErr := r.restoreIntegrationClaims(recoveryCtx, refreshed)
			if _, liveErr := r.refreshClaimSetsLocked(recoveryCtx); liveErr != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore current durable claim sets: %w", liveErr))
			}
			for _, integration := range refreshed {
				count := len(integration.prior)
				if rollbackErr != nil {
					count, _ = r.Store.SourceClaimCount(recoveryCtx, integration.name)
				}
				if stateErr := r.setIntegrationStateDurable(recoveryCtx, integration.name, "degraded", count, false); stateErr != nil {
					failures = append(failures, fmt.Errorf("%s: record degraded integration state: %w", integration.name, stateErr))
				}
			}
			if rollbackErr != nil {
				failures = append(failures, fmt.Errorf("roll back integration claims: %w", rollbackErr))
			} else {
				_ = r.Store.Audit(ctx, "integration", "integration_refresh_rolled_back", fmt.Sprintf("sources=%d", len(refreshed)))
			}
		} else {
			for _, integration := range refreshed {
				if stateErr := r.setIntegrationStateDurable(ctx, integration.name, "healthy", integration.count, true); stateErr != nil {
					failures = append(failures, fmt.Errorf("%s: record healthy integration state: %w", integration.name, stateErr))
				}
			}
		}
	}
	return errors.Join(failures...)
}

func (r *Runtime) fetchThreatFeed(ctx context.Context, feed threatintel.Feed) ([]string, error) {
	if r.threatFeedFetcher != nil {
		return r.threatFeedFetcher(ctx, feed)
	}
	return feed.Fetch(ctx)
}

func (r *Runtime) configuredThreatFeedProtectedPrefixes() []string {
	var protected []string
	for _, zone := range r.Config.Zones {
		protected = append(protected, zone.Networks...)
	}
	for _, configured := range r.Config.Interfaces {
		protected = append(protected, configured.CIDRs...)
	}
	protected = append(protected, r.Config.WireGuard.BootstrapIPs...)
	protected = append(protected, r.Config.WireGuard.BootstrapIPsV6...)
	for _, raw := range append(append([]string(nil), r.Config.WireGuard.BootstrapHosts...), r.Config.WireGuard.EndpointHost) {
		if address, err := netip.ParseAddr(raw); err == nil {
			protected = append(protected, netip.PrefixFrom(address, address.BitLen()).String())
		}
	}
	return unique(protected)
}

func (r *Runtime) threatFeedProtectedPrefixes(ctx context.Context) ([]string, error) {
	protected := r.configuredThreatFeedProtectedPrefixes()
	v4, v6, _, err := r.bootstrapEndpoints(ctx)
	if err != nil {
		return nil, err
	}
	protected = append(protected, v4...)
	protected = append(protected, v6...)
	return unique(protected), nil
}

func (r *Runtime) sourceClaimAddresses(ctx context.Context, source string) ([]string, error) {
	claims, err := r.Store.Claims(ctx, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	var addresses []string
	for _, claim := range claims {
		if claim.Source == source {
			addresses = append(addresses, claim.Address)
		}
	}
	return unique(addresses), nil
}

func (r *Runtime) validateThreatFeedReplacement(ctx context.Context, source string, candidate, protected []string) error {
	claims, err := r.Store.Claims(ctx, time.Now().UTC())
	if err != nil {
		return err
	}
	combined := append([]string(nil), candidate...)
	for _, claim := range claims {
		if claim.Source != source && strings.HasPrefix(claim.Source, "threatfeed/") {
			combined = append(combined, claim.Address)
		}
	}
	return threatintel.Validate(unique(combined), protected)
}

func (r *Runtime) restoreIntegrationClaims(ctx context.Context, refreshed []refreshedIntegration) error {
	// Shrinking sources first prevents a transient total above the configured
	// claim limit while returning several integrations to their prior sizes.
	ordered := append([]refreshedIntegration(nil), refreshed...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return len(ordered[i].prior)-ordered[i].count < len(ordered[j].prior)-ordered[j].count
	})
	var failures []error
	for _, integration := range ordered {
		if _, err := r.Store.ReplaceSourceClaimsBounded(ctx, integration.name, integration.reason, "integration-rollback", integration.prior, r.Config.Runtime.MaxBlockClaims); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", integration.name, err))
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
