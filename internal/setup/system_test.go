package setup

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/discovery"
	"github.com/unknown0152/nft-firewall-v2/internal/health"
	"github.com/unknown0152/nft-firewall-v2/internal/reconcile"
	"github.com/unknown0152/nft-firewall-v2/internal/routing"
	"github.com/unknown0152/nft-firewall-v2/internal/wgconfig"
)

type systemRunner struct {
	commands    []string
	fail        string
	routeDevice string
}

type systemRunnerFunc func(context.Context, []byte, string, ...string) ([]byte, error)

func (f systemRunnerFunc) Run(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	return f(ctx, input, name, args...)
}

func (r *systemRunner) Run(_ context.Context, input []byte, name string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	if len(input) > 0 {
		command += " <stdin>"
	}
	r.commands = append(r.commands, command)
	if r.fail != "" && strings.Contains(command, r.fail) {
		return nil, errors.New("injected")
	}
	switch {
	case command == "nft list table inet nftfw_setup_guard":
		return nil, errors.New("absent")
	case command == "ip link show dev nftfw0":
		return nil, errors.New("absent")
	case command == "ip -j -4 rule show":
		return []byte("[]"), nil
	case command == "ip -j -4 route show table 51820":
		return []byte("[]"), nil
	case command == "ip -j -d link show":
		return []byte("[]"), nil
	case strings.HasPrefix(command, "systemctl is-enabled"):
		return nil, errors.New("disabled")
	case strings.HasPrefix(command, "systemctl is-active"):
		return nil, errors.New("inactive")
	case strings.HasPrefix(command, "sysctl -n"):
		return []byte("0\n"), nil
	case strings.Contains(command, "latest-handshakes"):
		return []byte("peer " + strconv.FormatInt(time.Now().Unix(), 10) + "\n"), nil
	case command == "ip -j -4 route get 1.1.1.1":
		device := r.routeDevice
		if device == "" {
			device = "nftfw0"
		}
		return []byte(`[{"dev":"` + device + `"}]`), nil
	default:
		return nil, nil
	}
}

func setupKey(fill byte) string {
	value := make([]byte, 32)
	for i := range value {
		value[i] = fill
	}
	return base64.StdEncoding.EncodeToString(value)
}

func setupProfile(t testing.TB) wgconfig.Profile {
	t.Helper()
	profile, _, err := wgconfig.Parse([]byte(`[Interface]
PrivateKey = ` + setupKey(1) + `
Address = 10.8.0.2/32
DNS = 1.1.1.1
[Peer]
PublicKey = ` + setupKey(2) + `
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.test:51820
PersistentKeepalive = 25
`))
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func testSystem(t testing.TB, runner *systemRunner) (*System, Paths) {
	t.Helper()
	root := t.TempDir()
	paths := Paths{
		Config:        filepath.Join(root, "etc/nftfw/nftfw.toml"),
		Intent:        filepath.Join(root, "etc/nftfw/intent.toml"),
		VPN:           filepath.Join(root, "etc/wireguard/nftfw0.conf"),
		Sysctl:        filepath.Join(root, "etc/sysctl.d/90-nftfw-managed.conf"),
		StateDir:      filepath.Join(root, "var/lib/nftfw"),
		RuntimeDir:    filepath.Join(root, "run/nftfw"),
		SystemdDir:    filepath.Join(root, "etc/systemd/system"),
		ControlSocket: filepath.Join(root, "run/nftfw/control.sock"),
		StatusSocket:  filepath.Join(root, "run/nftfw/status.sock"),
	}
	profile := setupProfile(t)
	system := &System{
		Paths: paths, Runner: runner,
		Discover: func(context.Context) (discovery.Snapshot, error) {
			return discovery.Snapshot{
				OSID: "debian", OSVersion: "13", Architecture: "amd64",
				Uplink: "eth0", UplinkGateway: netip.MustParseAddr("192.168.1.1"),
				LANNetworks:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
				ManagementTCP: []int{22}, DockerClean: true,
			}, nil
		},
		ReadProfile: func(string) (wgconfig.Profile, wgconfig.Summary, error) {
			return profile, wgconfig.Summary{AddressCount: 1, DNSCount: 1, IPv4DefaultRoute: true}, nil
		},
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("198.51.100.8")}, nil
		},
		Resolver: func(context.Context, routing.Runner, bool) (routing.ResolverMode, error) {
			return routing.ResolverResolvconf, nil
		},
		Control: func(_ context.Context, request api.Request) (any, error) {
			switch request.Op {
			case "apply":
				return reconcile.Result{Generation: 7, Checksum: strings.Repeat("a", 64)}, nil
			case "commit", "rollback":
				return nil, nil
			default:
				return nil, errors.New("unexpected control request")
			}
		},
		Status: func(context.Context) (health.Snapshot, error) {
			return health.Snapshot{
				Schema: health.StatusSchema, Status: "HEALTHY", Active: true,
				PolicyMatch: true, KillSwitchEnforced: true,
			}, nil
		},
		ValidateHook: func(context.Context, prepared, uint64) error { return nil },
	}
	return system, paths
}

func TestSystemExecutorCompletesSimulatedCleanHost(t *testing.T) {
	runner := &systemRunner{}
	system, paths := testSystem(t, runner)
	journalPath := filepath.Join(paths.StateDir, "setup", "journal.json")
	engine := Engine{
		Executor: system, Journal: FileJournal{Path: journalPath},
		NewID: func() string { return "system-test" },
		Now:   func() time.Time { return time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC) },
	}
	plan, err := engine.Run(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.PublicTCP != nil || plan.Summary.VPNInterface != "nftfw0" {
		t.Fatalf("unexpected plan: %#v", plan.Summary)
	}
	for _, path := range []string{paths.Config, paths.Intent, paths.VPN, paths.Sysctl} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("managed file missing %s: %v", path, err)
		}
	}
	vpn, err := os.ReadFile(paths.VPN)
	if err != nil || !strings.Contains(string(vpn), "Table = off") {
		t.Fatalf("managed VPN profile missing Table=off: %v", err)
	}
	if strings.Contains(string(mustRead(t, paths.Intent)), setupKey(1)) {
		t.Fatal("intent leaked private key")
	}
	joined := strings.Join(runner.commands, "\n")
	for _, want := range []string{
		"nft --check --file", "systemctl enable --now nftfw-rollback.timer",
		"ip -4 route replace default dev nftfw0 table 51820",
		"systemctl start nftfw-early.service",
		"nft delete table inet nftfw_setup_guard",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("simulated setup missing %q:\n%s", want, joined)
		}
	}
}

func TestSystemFailureRestoresPreexistingFiles(t *testing.T) {
	runner := &systemRunner{fail: "route replace"}
	system, paths := testSystem(t, runner)
	if err := os.MkdirAll(filepath.Dir(paths.Config), 0o755); err != nil {
		t.Fatal(err)
	}
	oldConfig := []byte("old-config\n")
	if err := os.WriteFile(paths.Config, oldConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	engine := Engine{
		Executor: system,
		Journal:  FileJournal{Path: filepath.Join(paths.StateDir, "setup", "journal.json")},
		NewID:    func() string { return "rollback-test" },
	}
	if _, err := engine.Run(context.Background(), "/provider.conf"); err == nil {
		t.Fatal("injected tunnel failure did not fail setup")
	}
	if string(mustRead(t, paths.Config)) != string(oldConfig) {
		t.Fatal("rollback did not restore preexisting configuration")
	}
	if _, err := os.Stat(paths.VPN); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback did not remove newly created VPN profile: %v", err)
	}
}

func TestDefaultsFillMissingPathsIndependently(t *testing.T) {
	system := &System{Paths: Paths{Config: "/custom/nftfw.toml"}}
	system.defaults()
	defaults := DefaultPaths()
	if system.Paths.Config != "/custom/nftfw.toml" {
		t.Fatalf("custom config path was overwritten: %s", system.Paths.Config)
	}
	if system.Paths.Intent != defaults.Intent || system.Paths.VPN != defaults.VPN ||
		system.Paths.StateDir != defaults.StateDir || system.Paths.StatusSocket != defaults.StatusSocket {
		t.Fatalf("missing defaults were not filled: %#v", system.Paths)
	}
}

func TestEnableBootPollsUntilHealthIsReady(t *testing.T) {
	runner := &systemRunner{}
	system, _ := testSystem(t, runner)
	calls := 0
	system.Status = func(context.Context) (health.Snapshot, error) {
		calls++
		if calls == 1 {
			return health.Snapshot{Schema: health.StatusSchema, Status: "DEGRADED"}, nil
		}
		return health.Snapshot{
			Schema: health.StatusSchema, Status: "HEALTHY", Active: true,
			PolicyMatch: true, KillSwitchEnforced: true,
		}, nil
	}
	if err := system.EnableBoot(context.Background(), Plan{}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("health calls=%d want=2", calls)
	}
}

func TestRealValidationChecksHandshakeRouteAndConnectivity(t *testing.T) {
	runner := &systemRunner{}
	system, _ := testSystem(t, runner)
	system.ValidateHook = nil
	system.Connectivity = func(context.Context) error { return nil }
	system.DNSLookup = func(context.Context, string) ([]string, error) {
		return []string{"198.51.100.1"}, nil
	}
	plan, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	if err := system.Validate(context.Background(), plan, 7); err != nil {
		t.Fatal(err)
	}
	if err := system.Validate(context.Background(), plan, 0); err == nil {
		t.Fatal("zero generation accepted")
	}
	system.Connectivity = func(context.Context) error { return errors.New("offline") }
	if err := system.Validate(context.Background(), plan, 7); err == nil ||
		err.Error() != "SETUP_VPN_CONNECTIVITY_FAILED" {
		t.Fatalf("connectivity failure not detected: %v", err)
	}
	system.Connectivity = func(context.Context) error { return nil }
	system.DNSLookup = func(context.Context, string) ([]string, error) {
		return nil, errors.New("dns failed")
	}
	if err := system.Validate(context.Background(), plan, 7); err == nil ||
		err.Error() != "SETUP_VPN_DNS_FAILED" {
		t.Fatalf("DNS failure not detected: %v", err)
	}
}

func TestRealValidationHonorsCancellationWhileHandshakeMissing(t *testing.T) {
	runner := &systemRunner{fail: "latest-handshakes"}
	system, _ := testSystem(t, runner)
	system.ValidateHook = nil
	plan, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := system.Validate(ctx, plan, 7); err == nil ||
		err.Error() != "SETUP_VALIDATION_CANCELED" {
		t.Fatalf("canceled validation did not stop: %v", err)
	}
}

func TestRealValidationHandshakeDeadline(t *testing.T) {
	runner := &systemRunner{fail: "latest-handshakes"}
	system, _ := testSystem(t, runner)
	system.ValidateHook = nil
	system.ValidationTimeout = time.Nanosecond
	system.ValidationPoll = time.Nanosecond
	plan, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	if err := system.Validate(context.Background(), plan, 7); err == nil ||
		err.Error() != "SETUP_WIREGUARD_HANDSHAKE_FAILED" {
		t.Fatalf("handshake deadline did not fail: %v", err)
	}
}

func TestSystemPhaseCommandFailuresAreBounded(t *testing.T) {
	tests := []struct {
		name      string
		fail      string
		call      func(*System, Plan) error
		errorCode string
	}{
		{
			name: "guard-check", fail: "nft --check --file",
			call:      func(system *System, plan Plan) error { return system.StartGuard(context.Background(), plan) },
			errorCode: "SETUP_GUARD_CHECK_FAILED",
		},
		{
			name: "sysctl", fail: "sysctl -w",
			call:      func(system *System, plan Plan) error { return system.Install(context.Background(), plan) },
			errorCode: "SETUP_SYSCTL_APPLY_FAILED",
		},
		{
			name: "daemon-reload", fail: "systemctl daemon-reload",
			call:      func(system *System, plan Plan) error { return system.Install(context.Background(), plan) },
			errorCode: "SETUP_SYSTEMD_RELOAD_FAILED",
		},
		{
			name: "runtime-timer", fail: "enable --now nftfw-rollback.timer",
			call:      func(system *System, plan Plan) error { return system.StartRuntime(context.Background(), plan) },
			errorCode: "SETUP_ROLLBACK_TIMER_FAILED",
		},
		{
			name: "boot-enable", fail: "systemctl enable nftfw-early.service",
			call:      func(system *System, plan Plan) error { return system.EnableBoot(context.Background(), plan) },
			errorCode: "SETUP_BOOT_ENABLE_FAILED",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &systemRunner{}
			system, _ := testSystem(t, runner)
			plan, err := system.Prepare(context.Background(), "/provider.conf")
			if err != nil {
				t.Fatal(err)
			}
			runner.fail = test.fail
			err = test.call(system, plan)
			if err == nil || err.Error() != test.errorCode {
				t.Fatalf("error=%v want=%s", err, test.errorCode)
			}
		})
	}
}

func TestApplyCommitAndCommitInspectionFailures(t *testing.T) {
	runner := &systemRunner{}
	system, _ := testSystem(t, runner)
	plan, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	system.Control = func(context.Context, api.Request) (any, error) {
		return nil, errors.New("unavailable")
	}
	if _, err := system.ApplySafe(context.Background(), plan); err == nil ||
		err.Error() != "SETUP_SAFE_APPLY_FAILED" {
		t.Fatalf("apply failure not bounded: %v", err)
	}
	if err := system.Commit(context.Background(), plan, 0); err == nil {
		t.Fatal("zero commit generation accepted")
	}
	if err := system.Commit(context.Background(), plan, 7); err == nil ||
		err.Error() != "SETUP_COMMIT_FAILED" {
		t.Fatalf("commit failure not bounded: %v", err)
	}
	system.Status = func(context.Context) (health.Snapshot, error) {
		return health.Snapshot{}, errors.New("unavailable")
	}
	if _, err := system.GenerationCommitted(context.Background(), 7); err == nil {
		t.Fatal("unknown committed state accepted")
	}
	if _, err := system.GenerationCommitted(context.Background(), 0); err == nil {
		t.Fatal("zero generation commit inspection accepted")
	}
	system.Status = func(context.Context) (health.Snapshot, error) {
		return health.Snapshot{
			ActiveGeneration: 7, Active: true, PolicyMatch: true, KillSwitchEnforced: true,
		}, nil
	}
	if committed, err := system.GenerationCommitted(context.Background(), 7); err != nil || !committed {
		t.Fatalf("committed generation not recognized: committed=%t err=%v", committed, err)
	}
	if committed, err := system.GenerationCommitted(context.Background(), 8); err != nil || committed {
		t.Fatalf("wrong generation recognized as committed: committed=%t err=%v", committed, err)
	}
}

func TestResolveAndRouteHelpers(t *testing.T) {
	addresses, err := resolveIPv4(context.Background(), "198.51.100.8")
	if err != nil || len(addresses) != 1 || addresses[0].String() != "198.51.100.8" {
		t.Fatalf("literal endpoint resolution failed: %v %v", addresses, err)
	}
	if _, err := resolveIPv4(context.Background(), "::1"); err == nil {
		t.Fatal("IPv6 endpoint accepted")
	}
	if _, err := resolveIPv4(context.Background(), "localhost"); err == nil {
		t.Fatal("loopback hostname endpoint accepted")
	}
	if got := routeDevice([]byte(`[{"dev":"nftfw0"}]`)); got != "nftfw0" {
		t.Fatalf("route device=%q", got)
	}
	if got := routeDevice([]byte(`[]`)); got != "" {
		t.Fatalf("empty route unexpectedly resolved: %q", got)
	}
}

func TestRecoverCommittedRunsBootThenFinalize(t *testing.T) {
	runner := &systemRunner{}
	system, _ := testSystem(t, runner)
	plan, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	if err := system.RecoverCommitted(context.Background(), plan, Journal{}); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverCommittedStopsWhenBootRecoveryFails(t *testing.T) {
	runner := &systemRunner{fail: "systemctl enable"}
	system, _ := testSystem(t, runner)
	if err := system.RecoverCommitted(context.Background(), Plan{}, Journal{}); err == nil {
		t.Fatal("boot recovery failure was ignored")
	}
}

func TestPrepareFailsBeforeMutationForInvalidInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*System, *systemRunner)
	}{
		{
			name: "profile",
			mutate: func(system *System, _ *systemRunner) {
				system.ReadProfile = func(string) (wgconfig.Profile, wgconfig.Summary, error) {
					return wgconfig.Profile{}, wgconfig.Summary{}, errors.New("VPN_PROFILE_INVALID")
				}
			},
		},
		{
			name: "discovery",
			mutate: func(system *System, _ *systemRunner) {
				system.Discover = func(context.Context) (discovery.Snapshot, error) {
					return discovery.Snapshot{}, errors.New("DISCOVERY_FAILED")
				}
			},
		},
		{
			name: "resolution",
			mutate: func(system *System, _ *systemRunner) {
				system.Resolve = func(context.Context, string) ([]netip.Addr, error) {
					return nil, errors.New("offline")
				}
			},
		},
		{
			name: "invalid-clean-host",
			mutate: func(system *System, _ *systemRunner) {
				system.Discover = func(context.Context) (discovery.Snapshot, error) {
					return discovery.Snapshot{
						OSID: "debian", OSVersion: "13", Architecture: "amd64",
						Uplink: "eth0", UplinkGateway: netip.MustParseAddr("192.168.1.1"),
						DockerClean: true,
					}, nil
				}
			},
		},
		{
			name: "resolver",
			mutate: func(system *System, _ *systemRunner) {
				system.Resolver = func(context.Context, routing.Runner, bool) (routing.ResolverMode, error) {
					return routing.ResolverNone, errors.New("unsupported")
				}
			},
		},
		{
			name: "routing-conflict",
			mutate: func(_ *System, runner *systemRunner) {
				runner.fail = "ip -j -4 rule show"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &systemRunner{}
			system, _ := testSystem(t, runner)
			test.mutate(system, runner)
			if _, err := system.Prepare(context.Background(), "/provider.conf"); err == nil {
				t.Fatal("invalid setup input accepted")
			}
			for _, command := range runner.commands {
				if strings.Contains(command, "nft --file") || strings.Contains(command, "systemctl enable") {
					t.Fatalf("mutation occurred during failed prepare: %s", command)
				}
			}
		})
	}
}

func TestAdditionalSystemFailureBranches(t *testing.T) {
	tests := []struct {
		name      string
		fail      string
		call      func(*System, Plan) error
		errorCode string
	}{
		{
			name: "guard-apply", fail: "nft --file",
			call:      func(system *System, plan Plan) error { return system.StartGuard(context.Background(), plan) },
			errorCode: "SETUP_GUARD_APPLY_FAILED",
		},
		{
			name: "guard-watchdog", fail: "nftfw-setup-rollback.timer",
			call:      func(system *System, plan Plan) error { return system.StartGuard(context.Background(), plan) },
			errorCode: "SETUP_WATCHDOG_START_FAILED",
		},
		{
			name: "systemd-verify", fail: "systemd-analyze verify",
			call:      func(system *System, plan Plan) error { return system.Install(context.Background(), plan) },
			errorCode: "SETUP_SYSTEMD_VERIFY_FAILED",
		},
		{
			name: "runtime-daemon", fail: "systemctl start nftfwd.service",
			call:      func(system *System, plan Plan) error { return system.StartRuntime(context.Background(), plan) },
			errorCode: "SETUP_DAEMON_START_FAILED",
		},
		{
			name: "boot-start", fail: "systemctl start nftfw-early.service",
			call:      func(system *System, plan Plan) error { return system.EnableBoot(context.Background(), plan) },
			errorCode: "SETUP_BOOT_ACTIVATION_FAILED",
		},
		{
			name: "boot-restart", fail: "systemctl restart nftfwd.service",
			call:      func(system *System, plan Plan) error { return system.EnableBoot(context.Background(), plan) },
			errorCode: "SETUP_DAEMON_FINAL_RESTART_FAILED",
		},
		{
			name: "finalize-watchdog", fail: "disable --now nftfw-setup-rollback.timer",
			call:      func(system *System, plan Plan) error { return system.Finalize(context.Background(), plan) },
			errorCode: "SETUP_WATCHDOG_STOP_FAILED",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &systemRunner{}
			system, _ := testSystem(t, runner)
			plan, err := system.Prepare(context.Background(), "/provider.conf")
			if err != nil {
				t.Fatal(err)
			}
			runner.fail = test.fail
			err = test.call(system, plan)
			if err == nil || err.Error() != test.errorCode {
				t.Fatalf("error=%v want=%s", err, test.errorCode)
			}
		})
	}
}

func TestGuardRefusesPreexistingTable(t *testing.T) {
	runner := systemRunnerFunc(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		if name+" "+strings.Join(args, " ") == "nft list table inet nftfw_setup_guard" {
			return nil, nil
		}
		return []byte("[]"), nil
	})
	system := &System{Runner: runner}
	if err := system.StartGuard(context.Background(), Plan{PrivateData: &prepared{}}); err == nil ||
		err.Error() != "SETUP_GUARD_ALREADY_EXISTS" {
		t.Fatalf("preexisting setup guard accepted: %v", err)
	}
}

func TestApplyRejectsMalformedResponse(t *testing.T) {
	runner := &systemRunner{}
	system, _ := testSystem(t, runner)
	plan, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, response := range []any{
		map[string]any{"generation": 0},
		reconcile.Result{Generation: 7, Committed: true},
		func() any { return make(chan int) }(),
	} {
		system.Control = func(context.Context, api.Request) (any, error) { return response, nil }
		if _, err := system.ApplySafe(context.Background(), plan); err == nil {
			t.Fatalf("malformed apply response accepted: %#v", response)
		}
	}
}

func TestValidateDetectsWrongRoute(t *testing.T) {
	runner := &systemRunner{routeDevice: "eth0"}
	system, _ := testSystem(t, runner)
	system.ValidateHook = nil
	plan, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	if err := system.Validate(context.Background(), plan, 7); err == nil ||
		err.Error() != "SETUP_VPN_ROUTE_VALIDATION_FAILED" {
		t.Fatalf("wrong VPN route was accepted: %v", err)
	}
}

func TestEnableBootCancellationFailsClosed(t *testing.T) {
	runner := &systemRunner{}
	system, _ := testSystem(t, runner)
	system.Status = func(context.Context) (health.Snapshot, error) {
		return health.Snapshot{Status: "DEGRADED"}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := system.EnableBoot(ctx, Plan{}); err == nil ||
		err.Error() != "SETUP_FINAL_HEALTH_CANCELED" {
		t.Fatalf("canceled final health did not fail closed: %v", err)
	}
}

func TestControlStatusAndAdapterFallbacks(t *testing.T) {
	system := &System{Paths: Paths{
		ControlSocket: filepath.Join(t.TempDir(), "missing-control.sock"),
		StatusSocket:  filepath.Join(t.TempDir(), "missing-status.sock"),
	}}
	if _, err := system.control(context.Background(), api.Request{Op: "status"}); err == nil {
		t.Fatal("missing control socket accepted")
	}
	if _, err := system.status(context.Background()); err == nil {
		t.Fatal("missing status socket accepted")
	}
	runner := &systemRunner{}
	adapter := discoveryAdapter{runner: runner}
	if _, err := adapter.Run(context.Background(), "ip", "-j", "-4", "rule", "show"); err != nil {
		t.Fatal(err)
	}
}

type setupAPIHandler struct {
	status any
}

func (h setupAPIHandler) Status(context.Context) (any, error) {
	return h.status, nil
}

func (h setupAPIHandler) Control(context.Context, api.Request) (any, error) {
	return nil, errors.New("not used")
}

func TestStatusSocketDecode(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(root, "status.sock")
	controlPath := filepath.Join(root, "control.sock")
	ctx, cancel := context.WithCancel(context.Background())
	server := &api.Server{
		Handler: setupAPIHandler{status: health.Snapshot{
			Schema: health.StatusSchema, Status: "HEALTHY", Active: true,
		}},
		StatusPath: statusPath, ControlPath: controlPath,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	for deadline := time.Now().Add(time.Second); ; {
		select {
		case err := <-done:
			cancel()
			t.Fatalf("status server failed: %v", err)
		default:
		}
		if _, err := os.Stat(statusPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("status socket did not start")
		}
		time.Sleep(time.Millisecond)
	}
	system := &System{Paths: Paths{StatusSocket: statusPath}}
	snapshot, err := system.status(context.Background())
	if err != nil || snapshot.Schema != health.StatusSchema {
		cancel()
		t.Fatalf("status decode failed: %#v %v", snapshot, err)
	}
	cancel()
	<-done
}

func TestPhaseTunnelClassification(t *testing.T) {
	for _, phase := range []Phase{PhaseTunnel, PhaseValidate, PhaseCommit, PhaseBoot, PhaseFinalize, PhaseComplete} {
		if !phaseMayHaveTunnel(phase) {
			t.Fatalf("phase %s should permit tunnel cleanup", phase)
		}
	}
	for _, phase := range []Phase{PhaseInspect, PhaseBackup, PhaseGuard, PhaseInstall, PhaseRuntime, PhaseApply} {
		if phaseMayHaveTunnel(phase) {
			t.Fatalf("phase %s unexpectedly permits tunnel cleanup", phase)
		}
	}
}

func TestRollbackReportsEachIncompleteRecoveryClass(t *testing.T) {
	t.Run("missing-backup", func(t *testing.T) {
		system, _ := testSystem(t, &systemRunner{})
		err := system.Rollback(context.Background(), Plan{}, Journal{Phase: PhaseGuard})
		if err == nil || !strings.Contains(err.Error(), "BACKUP") {
			t.Fatalf("missing rollback backup not reported: %v", err)
		}
	})

	t.Run("generation", func(t *testing.T) {
		runner := &systemRunner{}
		system, _ := testSystem(t, runner)
		plan, err := system.Prepare(context.Background(), "/provider.conf")
		if err != nil {
			t.Fatal(err)
		}
		backup, err := system.Backup(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		system.Control = func(context.Context, api.Request) (any, error) {
			return nil, errors.New("rollback unavailable")
		}
		err = system.Rollback(context.Background(), plan, Journal{
			Phase: PhaseApply, Generation: 7, BackupDir: backup,
		})
		if err == nil || !strings.Contains(err.Error(), "GENERATION") {
			t.Fatalf("generation rollback failure not reported: %v", err)
		}
	})

	t.Run("tunnel", func(t *testing.T) {
		runner := &systemRunner{}
		system, _ := testSystem(t, runner)
		plan, err := system.Prepare(context.Background(), "/provider.conf")
		if err != nil {
			t.Fatal(err)
		}
		backup, err := system.Backup(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		runner.fail = "resolvconf -d"
		err = system.Rollback(context.Background(), plan, Journal{
			Phase: PhaseTunnel, BackupDir: backup,
		})
		if err == nil || !strings.Contains(err.Error(), "TUNNEL") {
			t.Fatalf("tunnel rollback failure not reported: %v", err)
		}
	})

	t.Run("restore", func(t *testing.T) {
		system, _ := testSystem(t, &systemRunner{})
		err := system.Rollback(context.Background(), Plan{}, Journal{
			Phase: PhaseInstall, BackupDir: filepath.Join(t.TempDir(), "missing"),
		})
		if err == nil || !strings.Contains(err.Error(), "RESTORE") {
			t.Fatalf("backup restore failure not reported: %v", err)
		}
	})
}

func TestFinalizeDetectsGuardThatStillExists(t *testing.T) {
	runner := systemRunnerFunc(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		switch command {
		case "nft delete table inet nftfw_setup_guard":
			return nil, errors.New("delete failed")
		case "nft list table inet nftfw_setup_guard":
			return nil, nil
		default:
			return nil, nil
		}
	})
	system := &System{
		Paths:  Paths{RuntimeDir: t.TempDir(), StateDir: t.TempDir()},
		Runner: runner,
	}
	if err := system.Finalize(context.Background(), Plan{}); err == nil ||
		err.Error() != "SETUP_GUARD_REMOVE_FAILED" {
		t.Fatalf("remaining guard was not detected: %v", err)
	}
}

func TestPrivatePlanRequired(t *testing.T) {
	system := &System{Runner: &systemRunner{}}
	if _, err := system.Backup(context.Background(), Plan{}); err == nil {
		t.Fatal("backup without private plan accepted")
	}
	if err := system.StartTunnel(context.Background(), Plan{}); err == nil {
		t.Fatal("tunnel start without private plan accepted")
	}
}

func mustRead(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
