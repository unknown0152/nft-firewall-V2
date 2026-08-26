package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/discovery"
	"github.com/unknown0152/nft-firewall-v2/internal/health"
	"github.com/unknown0152/nft-firewall-v2/internal/intent"
	"github.com/unknown0152/nft-firewall-v2/internal/reconcile"
	"github.com/unknown0152/nft-firewall-v2/internal/routing"
	"github.com/unknown0152/nft-firewall-v2/internal/wgconfig"
)

type Paths struct {
	Config        string
	Intent        string
	VPN           string
	Sysctl        string
	StateDir      string
	RuntimeDir    string
	SystemdDir    string
	ControlSocket string
	StatusSocket  string
}

func DefaultPaths() Paths {
	return Paths{
		Config: "/etc/nftfw/nftfw.toml", Intent: "/etc/nftfw/intent.toml",
		VPN: intent.VPNConfig, Sysctl: "/etc/sysctl.d/90-nftfw-managed.conf",
		StateDir: "/var/lib/nftfw", RuntimeDir: "/run/nftfw",
		SystemdDir:    "/etc/systemd/system",
		ControlSocket: "/run/nftfw/control.sock", StatusSocket: "/run/nftfw/status.sock",
	}
}

type System struct {
	Paths             Paths
	Runner            routing.Runner
	Discover          func(context.Context) (discovery.Snapshot, error)
	ReadProfile       func(string) (wgconfig.Profile, wgconfig.Summary, error)
	Resolve           func(context.Context, string) ([]netip.Addr, error)
	Resolver          func(context.Context, routing.Runner, bool) (routing.ResolverMode, error)
	Control           func(context.Context, api.Request) (any, error)
	Status            func(context.Context) (health.Snapshot, error)
	ValidateHook      func(context.Context, prepared, uint64) error
	Connectivity      func(context.Context) error
	DNSLookup         func(context.Context, string) ([]string, error)
	ValidationTimeout time.Duration
	ValidationPoll    time.Duration
	Now               func() time.Time
}

type prepared struct {
	Profile    wgconfig.Profile
	Intent     intent.Intent
	Config     config.Config
	IntentData []byte
	ConfigData []byte
	VPNData    []byte
	GuardData  []byte
	SysctlData []byte
	Route      routing.Config
	BackupDir  string
}

func (s *System) Prepare(ctx context.Context, vpnPath string) (Plan, error) {
	s.defaults()
	readProfile := s.ReadProfile
	if readProfile == nil {
		readProfile = wgconfig.Read
	}
	profile, profileSummary, err := readProfile(vpnPath)
	if err != nil {
		return Plan{}, errors.New(wgconfig.RedactedError(err))
	}
	discover := s.Discover
	if discover == nil {
		inspector := discovery.Inspector{Runner: discoveryAdapter{s.Runner}}
		discover = inspector.Discover
	}
	snapshot, err := discover(ctx)
	if err != nil {
		return Plan{}, err
	}
	resolve := s.Resolve
	if resolve == nil {
		resolve = resolveIPv4
	}
	endpoints, err := resolve(ctx, profile.Peer.EndpointHost)
	if err != nil {
		return Plan{}, errors.New("SETUP_ENDPOINT_RESOLUTION_FAILED")
	}
	managedIntent, err := intent.New(snapshot, profile, endpoints)
	if err != nil {
		return Plan{}, err
	}
	managedConfig, err := managedIntent.Config()
	if err != nil {
		return Plan{}, errors.New("SETUP_CONFIG_GENERATION_FAILED")
	}
	configData, err := intent.RenderConfig(managedConfig)
	if err != nil {
		return Plan{}, err
	}
	vpnData, err := profile.NormalizedWGQuick(intent.VPNInterface)
	if err != nil {
		return Plan{}, err
	}
	resolverDetector := s.Resolver
	if resolverDetector == nil {
		resolverDetector = routing.DetectResolver
	}
	resolverMode, err := resolverDetector(ctx, s.Runner, len(profile.DNS) > 0)
	if err != nil {
		return Plan{}, err
	}
	managedIntent.ResolverMode = string(resolverMode)
	intentData, err := managedIntent.Render()
	if err != nil {
		return Plan{}, err
	}
	guardData, err := renderGuard(
		snapshot.Uplink, intent.VPNInterface, intent.VPNFwmark,
		int(profile.Peer.EndpointPort), managedIntent.BootstrapIPv4,
		managedIntent.LANNetworks, managedIntent.ManagementTCP,
	)
	if err != nil {
		return Plan{}, err
	}
	routeConfig := routing.Config{
		Interface: intent.VPNInterface, Uplink: snapshot.Uplink,
		Fwmark: intent.VPNFwmark, Table: routing.DefaultTable,
		Addresses: profile.Addresses, EndpointAddress: endpoints[0],
		DNS: profile.DNS, MTU: profile.MTU, Profile: profile,
		Resolver: resolverMode, RuntimeDir: filepath.Join(s.Paths.RuntimeDir, "setup"),
	}
	if err := routeConfig.Validate(); err != nil {
		return Plan{}, err
	}
	if err := (routing.Manager{Runner: s.Runner}).PreflightClean(ctx, routeConfig); err != nil {
		return Plan{}, err
	}
	ipv6Interfaces := append([]string(nil), snapshot.NonLoopbackInterfaces...)
	if len(ipv6Interfaces) == 0 {
		ipv6Interfaces = []string{snapshot.Uplink}
	}
	sort.Strings(ipv6Interfaces)
	private := &prepared{
		Profile: profile, Intent: managedIntent, Config: managedConfig,
		IntentData: intentData, ConfigData: configData, VPNData: vpnData,
		GuardData: guardData, SysctlData: renderSysctl(ipv6Interfaces),
		Route: routeConfig,
	}
	dockerMode := "disabled"
	if snapshot.DockerPresent && snapshot.DockerClean {
		dockerMode = "clean-detected-not-adopted"
	}
	return Plan{
		VPNSource: vpnPath,
		Summary: Summary{
			Schema: "nftfw.setup-plan.v1", Uplink: snapshot.Uplink,
			VPNInterface: intent.VPNInterface, IPv6Interfaces: ipv6Interfaces,
			LANNetworks:   managedIntent.LANNetworks,
			ManagementTCP: managedIntent.ManagementTCP,
			PublicTCP:     managedIntent.PublicTCP, PublicUDP: managedIntent.PublicUDP,
			IPv6Mode: "disabled", DockerMode: dockerMode,
			ResolverMode: string(resolverMode), SourceModeWarning: profileSummary.SourceWorldReadable,
		},
		PrivateData: private,
	}, nil
}

func (s *System) Backup(ctx context.Context, plan Plan) (string, error) {
	s.defaults()
	private, err := privatePlan(plan)
	if err != nil {
		return "", err
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	directory := filepath.Join(s.Paths.StateDir, "setup", "backups", now().UTC().Format("20060102T150405.000000000Z"))
	manifest, err := createBackup(
		ctx, s.Runner, directory, s.touchedFiles(), managedUnits(),
		managedSysctls(plan.Summary.IPv6Interfaces),
	)
	if err != nil {
		return "", err
	}
	if manifest.Path == "" {
		return "", errors.New("SETUP_BACKUP_INVALID")
	}
	private.BackupDir = directory
	return directory, nil
}

func (s *System) StartGuard(ctx context.Context, plan Plan) error {
	s.defaults()
	private, err := privatePlan(plan)
	if err != nil {
		return err
	}
	if _, err := s.Runner.Run(ctx, nil, "nft", "list", "table", "inet", "nftfw_setup_guard"); err == nil {
		return errors.New("SETUP_GUARD_ALREADY_EXISTS")
	}
	path := filepath.Join(s.Paths.RuntimeDir, "setup-guard.nft")
	if err := writeAtomic(path, private.GuardData, 0o600); err != nil {
		return err
	}
	if _, err := s.Runner.Run(ctx, nil, "nft", "--check", "--file", path); err != nil {
		return errors.New("SETUP_GUARD_CHECK_FAILED")
	}
	if _, err := s.Runner.Run(ctx, nil, "nft", "--file", path); err != nil {
		return errors.New("SETUP_GUARD_APPLY_FAILED")
	}
	if _, err := s.Runner.Run(ctx, nil, "systemctl", "enable", "--now", "nftfw-setup-rollback.timer"); err != nil {
		return errors.New("SETUP_WATCHDOG_START_FAILED")
	}
	return nil
}

func (s *System) Install(ctx context.Context, plan Plan) error {
	s.defaults()
	private, err := privatePlan(plan)
	if err != nil {
		return err
	}
	files := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{s.Paths.VPN, private.VPNData, 0o600},
		{s.Paths.Intent, private.IntentData, 0o640},
		{s.Paths.Config, private.ConfigData, 0o640},
		{s.Paths.Sysctl, private.SysctlData, 0o644},
		{filepath.Join(s.Paths.SystemdDir, "nftfwd.service.d", "50-nftfw-final-early.conf"), []byte(finalEarlyDropIn), 0o644},
		{filepath.Join(s.Paths.SystemdDir, "nftfw-rollback.service.d", "50-nftfw-final-early.conf"), []byte(finalEarlyDropIn), 0o644},
	}
	for _, file := range files {
		if err := writeAtomic(file.path, file.data, file.mode); err != nil {
			return err
		}
	}
	settings := map[string]string{
		"net.ipv6.conf.default.disable_ipv6": "1",
		"net.ipv6.conf.all.forwarding":       "0",
	}
	for _, name := range plan.Summary.IPv6Interfaces {
		settings["net.ipv6.conf."+name+".disable_ipv6"] = "1"
	}
	for key, value := range settings {
		if _, err := s.Runner.Run(ctx, nil, "sysctl", "-w", key+"="+value); err != nil {
			return errors.New("SETUP_SYSCTL_APPLY_FAILED")
		}
	}
	if _, err := s.Runner.Run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return errors.New("SETUP_SYSTEMD_RELOAD_FAILED")
	}
	if _, err := s.Runner.Run(ctx, nil, "systemd-analyze", "verify",
		"nftfw-early.service", "nftfw-enforcement-ready.service",
		"nftfwd.service", "nftfw-rollback.service", "nftfw-rollback.timer",
		"nftfw-setup-rollback.service", "nftfw-setup-rollback.timer",
		"nftfw-vpn.service", "nftfw-web.service"); err != nil {
		return errors.New("SETUP_SYSTEMD_VERIFY_FAILED")
	}
	return nil
}

func (s *System) StartRuntime(ctx context.Context, _ Plan) error {
	s.defaults()
	if _, err := s.Runner.Run(ctx, nil, "systemctl", "enable", "--now", "nftfw-rollback.timer"); err != nil {
		return errors.New("SETUP_ROLLBACK_TIMER_FAILED")
	}
	if _, err := s.Runner.Run(ctx, nil, "systemctl", "start", "nftfwd.service"); err != nil {
		return errors.New("SETUP_DAEMON_START_FAILED")
	}
	return nil
}

func (s *System) ApplySafe(ctx context.Context, _ Plan) (uint64, error) {
	s.defaults()
	data, err := s.control(ctx, api.Request{Op: "apply", Safe: true})
	if err != nil {
		return 0, errors.New("SETUP_SAFE_APPLY_FAILED")
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return 0, errors.New("SETUP_APPLY_RESPONSE_INVALID")
	}
	var result reconcile.Result
	if json.Unmarshal(encoded, &result) != nil || result.Generation == 0 || result.Committed {
		return 0, errors.New("SETUP_APPLY_RESPONSE_INVALID")
	}
	return result.Generation, nil
}

func (s *System) StartTunnel(ctx context.Context, plan Plan) error {
	s.defaults()
	private, err := privatePlan(plan)
	if err != nil {
		return err
	}
	return routing.Manager{Runner: s.Runner}.Up(ctx, private.Route)
}

func (s *System) Validate(ctx context.Context, plan Plan, generation uint64) error {
	s.defaults()
	private, err := privatePlan(plan)
	if err != nil || generation == 0 {
		return errors.New("SETUP_VALIDATION_INPUT_INVALID")
	}
	if s.ValidateHook != nil {
		return s.ValidateHook(ctx, *private, generation)
	}
	manager := routing.Manager{Runner: s.Runner}
	timeout := s.ValidationTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	poll := s.ValidationPoll
	if poll <= 0 {
		poll = time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		status, statusErr := manager.Status(ctx, private.Route)
		if statusErr == nil && status["healthy"] == true {
			break
		}
		if !time.Now().Before(deadline) {
			return errors.New("SETUP_WIREGUARD_HANDSHAKE_FAILED")
		}
		select {
		case <-ctx.Done():
			return errors.New("SETUP_VALIDATION_CANCELED")
		case <-time.After(poll):
		}
	}
	route, err := s.Runner.Run(ctx, nil, "ip", "-j", "-4", "route", "get", "1.1.1.1")
	if err != nil || routeDevice(route) != plan.Summary.VPNInterface {
		return errors.New("SETUP_VPN_ROUTE_VALIDATION_FAILED")
	}
	connectivity := s.Connectivity
	if connectivity == nil {
		connectivity = func(ctx context.Context) error {
			dialer := net.Dialer{Timeout: 8 * time.Second}
			connection, err := dialer.DialContext(ctx, "tcp4", "1.1.1.1:443")
			if err == nil {
				_ = connection.Close()
			}
			return err
		}
	}
	if err := connectivity(ctx); err != nil {
		return errors.New("SETUP_VPN_CONNECTIVITY_FAILED")
	}
	if len(private.Profile.DNS) > 0 {
		dnsCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		lookup := s.DNSLookup
		if lookup == nil {
			lookup = net.DefaultResolver.LookupHost
		}
		if _, err := lookup(dnsCtx, "example.com"); err != nil {
			return errors.New("SETUP_VPN_DNS_FAILED")
		}
	}
	return nil
}

func (s *System) Commit(ctx context.Context, _ Plan, generation uint64) error {
	if generation == 0 {
		return errors.New("SETUP_GENERATION_INVALID")
	}
	if _, err := s.control(ctx, api.Request{Op: "commit", Generation: generation}); err != nil {
		return errors.New("SETUP_COMMIT_FAILED")
	}
	return nil
}

func (s *System) GenerationCommitted(ctx context.Context, generation uint64) (bool, error) {
	if generation == 0 {
		return false, errors.New("SETUP_GENERATION_INVALID")
	}
	snapshot, err := s.status(ctx)
	if err != nil {
		return false, errors.New("SETUP_COMMIT_STATE_UNKNOWN")
	}
	return snapshot.ActiveGeneration == generation && snapshot.PendingGeneration == 0 &&
		snapshot.Active && snapshot.PolicyMatch && snapshot.KillSwitchEnforced, nil
}

func (s *System) EnableBoot(ctx context.Context, _ Plan) error {
	s.defaults()
	units := []string{
		"nftfw-early.service", "nftfw-enforcement-ready.service", "nftfwd.service",
		"nftfw-rollback.timer", "nftfw-web.service", "nftfw-vpn.service",
	}
	args := append([]string{"enable"}, units...)
	if _, err := s.Runner.Run(ctx, nil, "systemctl", args...); err != nil {
		return errors.New("SETUP_BOOT_ENABLE_FAILED")
	}
	for _, unit := range []string{"nftfw-early.service", "nftfw-enforcement-ready.service", "nftfw-vpn.service", "nftfw-web.service"} {
		if _, err := s.Runner.Run(ctx, nil, "systemctl", "start", unit); err != nil {
			return errors.New("SETUP_BOOT_ACTIVATION_FAILED")
		}
	}
	if _, err := s.Runner.Run(ctx, nil, "systemctl", "restart", "nftfwd.service"); err != nil {
		return errors.New("SETUP_DAEMON_FINAL_RESTART_FAILED")
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		snapshot, err := s.status(ctx)
		if err == nil && snapshot.Status == "HEALTHY" && snapshot.Active &&
			snapshot.PolicyMatch && snapshot.KillSwitchEnforced {
			return nil
		}
		if !time.Now().Before(deadline) {
			return errors.New("SETUP_FINAL_HEALTH_FAILED")
		}
		select {
		case <-ctx.Done():
			return errors.New("SETUP_FINAL_HEALTH_CANCELED")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (s *System) Finalize(ctx context.Context, _ Plan) error {
	s.defaults()
	if _, err := s.Runner.Run(ctx, nil, "nft", "delete", "table", "inet", "nftfw_setup_guard"); err != nil {
		if _, existsErr := s.Runner.Run(ctx, nil, "nft", "list", "table", "inet", "nftfw_setup_guard"); existsErr == nil {
			return errors.New("SETUP_GUARD_REMOVE_FAILED")
		}
	}
	_ = os.Remove(filepath.Join(s.Paths.RuntimeDir, "setup-guard.nft"))
	if _, err := s.Runner.Run(ctx, nil, "systemctl", "disable", "--now", "nftfw-setup-rollback.timer"); err != nil {
		return errors.New("SETUP_WATCHDOG_STOP_FAILED")
	}
	report := []byte("NFT Firewall V2 managed setup: COMPLETE\n")
	if err := writeAtomic(filepath.Join(s.Paths.StateDir, "setup", "LAST_SUCCESS"), report, 0o600); err != nil {
		return err
	}
	return nil
}

func (s *System) Rollback(ctx context.Context, plan Plan, journal Journal) error {
	s.defaults()
	summary := plan.Summary
	if summary.Schema == "" {
		summary = journal.Summary
	}
	route := routing.Config{
		Interface: summary.VPNInterface, Table: routing.DefaultTable,
		Resolver: routing.ResolverMode(summary.ResolverMode),
	}
	var failures []string
	if summary.VPNInterface != "" && phaseMayHaveTunnel(journal.Phase) {
		if err := (routing.Manager{Runner: s.Runner}).Down(ctx, route); err != nil {
			failures = append(failures, "tunnel")
		}
	}
	if journal.Generation != 0 && !journal.Committed {
		if _, err := s.control(ctx, api.Request{Op: "rollback", Generation: journal.Generation}); err != nil {
			failures = append(failures, "generation")
		}
	}
	for _, unit := range []string{
		"nftfw-vpn.service", "nftfw-web.service", "nftfwd.service",
		"nftfw-enforcement-ready.service", "nftfw-early.service",
		"nftfw-rollback.timer", "nftfw-setup-rollback.timer",
	} {
		_, _ = s.Runner.Run(ctx, nil, "systemctl", "stop", unit)
	}
	backupDir := journal.BackupDir
	if backupDir == "" {
		if private, err := privatePlan(plan); err == nil {
			backupDir = private.BackupDir
		}
	}
	if backupDir == "" {
		failures = append(failures, "backup")
	} else if err := restoreBackup(ctx, s.Runner, backupDir); err != nil {
		failures = append(failures, "restore")
	}
	_, _ = s.Runner.Run(ctx, nil, "systemctl", "daemon-reload")
	if _, err := s.Runner.Run(ctx, nil, "nft", "delete", "table", "inet", "nftfw_setup_guard"); err != nil {
		if _, existsErr := s.Runner.Run(ctx, nil, "nft", "list", "table", "inet", "nftfw_setup_guard"); existsErr == nil {
			failures = append(failures, "guard")
		}
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		return fmt.Errorf("SETUP_ROLLBACK_INCOMPLETE_%s", strings.ToUpper(strings.Join(failures, "_")))
	}
	return nil
}

func phaseMayHaveTunnel(phase Phase) bool {
	switch phase {
	case PhaseTunnel, PhaseValidate, PhaseCommit, PhaseBoot, PhaseFinalize, PhaseComplete:
		return true
	default:
		return false
	}
}

func (s *System) RecoverCommitted(ctx context.Context, plan Plan, _ Journal) error {
	if err := s.EnableBoot(ctx, plan); err != nil {
		return err
	}
	return s.Finalize(ctx, plan)
}

func (s *System) defaults() {
	defaults := DefaultPaths()
	if s.Paths.Config == "" {
		s.Paths.Config = defaults.Config
	}
	if s.Paths.Intent == "" {
		s.Paths.Intent = defaults.Intent
	}
	if s.Paths.VPN == "" {
		s.Paths.VPN = defaults.VPN
	}
	if s.Paths.Sysctl == "" {
		s.Paths.Sysctl = defaults.Sysctl
	}
	if s.Paths.StateDir == "" {
		s.Paths.StateDir = defaults.StateDir
	}
	if s.Paths.RuntimeDir == "" {
		s.Paths.RuntimeDir = defaults.RuntimeDir
	}
	if s.Paths.SystemdDir == "" {
		s.Paths.SystemdDir = defaults.SystemdDir
	}
	if s.Paths.ControlSocket == "" {
		s.Paths.ControlSocket = defaults.ControlSocket
	}
	if s.Paths.StatusSocket == "" {
		s.Paths.StatusSocket = defaults.StatusSocket
	}
	if s.Runner == nil {
		s.Runner = routing.ExecRunner{}
	}
}

func (s *System) control(ctx context.Context, request api.Request) (any, error) {
	if s.Control != nil {
		return s.Control(ctx, request)
	}
	response, err := api.Call(ctx, s.Paths.ControlSocket, request)
	if err != nil {
		return nil, err
	}
	return response.Data, nil
}

func (s *System) status(ctx context.Context) (health.Snapshot, error) {
	if s.Status != nil {
		return s.Status(ctx)
	}
	response, err := api.Call(ctx, s.Paths.StatusSocket, api.Request{Op: "status"})
	if err != nil {
		return health.Snapshot{}, err
	}
	encoded, err := json.Marshal(response.Data)
	if err != nil {
		return health.Snapshot{}, err
	}
	var snapshot health.Snapshot
	if json.Unmarshal(encoded, &snapshot) != nil {
		return health.Snapshot{}, errors.New("status decode failed")
	}
	return snapshot, nil
}

func (s *System) touchedFiles() []string {
	return []string{
		s.Paths.VPN, s.Paths.Intent, s.Paths.Config, s.Paths.Sysctl,
		filepath.Join(s.Paths.SystemdDir, "nftfwd.service.d", "50-nftfw-final-early.conf"),
		filepath.Join(s.Paths.SystemdDir, "nftfw-rollback.service.d", "50-nftfw-final-early.conf"),
	}
}

func privatePlan(plan Plan) (*prepared, error) {
	private, ok := plan.PrivateData.(*prepared)
	if !ok || private == nil {
		return nil, errors.New("SETUP_PRIVATE_PLAN_MISSING")
	}
	return private, nil
}

func resolveIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Is4() {
			return []netip.Addr{address}, nil
		}
		return nil, errors.New("IPv6 endpoint unsupported")
	}
	values, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var result []netip.Addr
	for _, address := range values {
		if address.Is4() && !address.IsUnspecified() && !address.IsLoopback() &&
			!address.IsMulticast() && !address.IsLinkLocalUnicast() && !seen[address.String()] {
			seen[address.String()] = true
			result = append(result, address)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	if len(result) == 0 || len(result) > 16 {
		return nil, errors.New("endpoint set invalid")
	}
	return result, nil
}

func routeDevice(data []byte) string {
	var routes []struct {
		Device string `json:"dev"`
	}
	if len(data) > 1<<20 || json.Unmarshal(data, &routes) != nil || len(routes) != 1 {
		return ""
	}
	return routes[0].Device
}

func renderSysctl(interfaces []string) []byte {
	var builder strings.Builder
	builder.WriteString("# Managed by NFT Firewall V2.\n")
	builder.WriteString("net.ipv6.conf.default.disable_ipv6 = 1\n")
	for _, name := range interfaces {
		builder.WriteString("net.ipv6.conf." + name + ".disable_ipv6 = 1\n")
	}
	builder.WriteString("net.ipv6.conf.all.forwarding = 0\n")
	return []byte(builder.String())
}

func managedUnits() []string {
	return []string{
		"nftfw-early.service", "nftfw-enforcement-ready.service", "nftfwd.service",
		"nftfw-rollback.timer", "nftfw-web.service", "nftfw-vpn.service",
		"nftfw-setup-rollback.timer", "nftfw-managed-rollback.timer",
	}
}

func managedSysctls(interfaces []string) []string {
	result := []string{
		"net.ipv6.conf.default.disable_ipv6",
		"net.ipv6.conf.all.forwarding",
	}
	for _, name := range interfaces {
		result = append(result, "net.ipv6.conf."+name+".disable_ipv6")
	}
	return result
}

type discoveryAdapter struct {
	runner routing.Runner
}

func (d discoveryAdapter) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return d.runner.Run(ctx, nil, name, args...)
}

const finalEarlyDropIn = `[Unit]
Requisite=nftfw-early.service
After=nftfw-early.service
`
