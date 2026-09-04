package setup

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/containers"
	"github.com/unknown0152/nft-firewall-v2/internal/discovery"
	"github.com/unknown0152/nft-firewall-v2/internal/health"
	"github.com/unknown0152/nft-firewall-v2/internal/intent"
	"github.com/unknown0152/nft-firewall-v2/internal/netgate"
	"github.com/unknown0152/nft-firewall-v2/internal/reconcile"
	"github.com/unknown0152/nft-firewall-v2/internal/routing"
	"github.com/unknown0152/nft-firewall-v2/internal/wgconfig"
)

type systemRunner struct {
	commands    []string
	fail        string
	routeDevice string
	outputs     map[string][]byte
}

type systemRunnerFunc func(context.Context, []byte, string, ...string) ([]byte, error)

func testNetworkProducers() []string {
	return []string{"ifup@.service", "networking.service"}
}

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
	if value, ok := r.outputs[command]; ok {
		return append([]byte(nil), value...), nil
	}
	switch {
	case command == "nft list table inet nftfw_setup_guard":
		return nil, errors.New("absent")
	case command == "nft list table inet nftfw_setup_resume_guard":
		return nil, errors.New("absent")
	case command == "ip link show dev nftfw0":
		return nil, errors.New("absent")
	case command == "ip -j -4 rule show":
		return []byte("[]"), nil
	case command == "ip -j -N -4 route show table all":
		return []byte("[]"), nil
	case command == "ip -j -d link show":
		return []byte("[]"), nil
	case strings.HasPrefix(command, "systemctl is-enabled"):
		return nil, errors.New("disabled")
	case strings.HasPrefix(command, "systemctl is-active"):
		return nil, errors.New("inactive")
	case command == "systemctl show --property=LoadState,ActiveState docker.service":
		return []byte("LoadState=loaded\nActiveState=active\n"), nil
	case command == "systemctl show --property=LoadState,ActiveState docker.socket":
		return []byte("LoadState=not-found\nActiveState=inactive\n"), nil
	case command == "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,FragmentPath networking.service":
		return []byte("Id=networking.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\nFragmentPath=/usr/lib/systemd/system/networking.service\n"), nil
	case command == "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,FragmentPath ifup@nftfw-probe.service":
		return []byte("Id=ifup@nftfw-probe.service\nLoadState=loaded\nActiveState=inactive\nUnitFileState=static\nFragmentPath=/usr/lib/systemd/system/ifup@.service\n"), nil
	case strings.HasPrefix(command, "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,FragmentPath "):
		unit := strings.TrimPrefix(command, "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,FragmentPath ")
		return []byte("Id=" + unit + "\nLoadState=not-found\nActiveState=inactive\nUnitFileState=\nFragmentPath=\n"), nil
	case strings.HasPrefix(command, "systemctl show --property=Requires,BindsTo,After "):
		return []byte("Requires=nftfw-enforcement-ready.service\nBindsTo=nftfw-enforcement-ready.service\nAfter=network-pre.target nftfw-enforcement-ready.service\n"), nil
	case strings.HasPrefix(command, "systemctl show --property=LoadState,ActiveState nftfw-") ||
		command == "systemctl show --property=LoadState,ActiveState nftfwd.service":
		return []byte("LoadState=loaded\nActiveState=inactive\n"), nil
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
	case strings.HasPrefix(command, "ip -j -4 route get 1.1.1.1 from "):
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
		Config:            filepath.Join(root, "etc/nftfw/nftfw.toml"),
		Intent:            filepath.Join(root, "etc/nftfw/intent.toml"),
		VPN:               filepath.Join(root, "etc/wireguard/nftfw0.conf"),
		Sysctl:            filepath.Join(root, "etc/sysctl.d/90-nftfw-managed.conf"),
		StateDir:          filepath.Join(root, "var/lib/nftfw"),
		RuntimeDir:        filepath.Join(root, "run/nftfw"),
		SystemdDir:        filepath.Join(root, "etc/systemd/system"),
		DockerDaemon:      filepath.Join(root, "etc/docker/daemon.json"),
		DockerDropIn:      filepath.Join(root, "etc/systemd/system/nftfwd.service.d/docker-access.conf"),
		InitramfsMarker:   filepath.Join(root, "etc/nftfw/initramfs-managed-disabled-v1"),
		InitramfsOwner:    filepath.Join(root, "etc/nftfw/initramfs-source-owner-v1"),
		InitramfsLoader:   filepath.Join(root, "etc/initramfs-tools/scripts/init-top/nftfw-ipv6-early"),
		InitramfsGate:     filepath.Join(root, "etc/initramfs-tools/scripts/init-top/udev"),
		InitramfsManager:  filepath.Join(root, "usr/lib/nftfw/initramfs/nftfw-initramfs-manage"),
		BootHoldMarker:    filepath.Join(root, "etc/nftfw/setup-boot-hold-v1"),
		NetworkBootMarker: filepath.Join(root, "etc/nftfw/setup-network-producers-v1"),
		GeneratorDir:      filepath.Join(root, "run/systemd/generator"),
		BootHoldReady:     filepath.Join(root, "run/nftfw/setup-boot-hold-ready"),
		BootHoldRelease:   filepath.Join(root, "run/nftfw/setup-boot-release"),
		DockerHoldReady:   filepath.Join(root, "run/nftfw/setup-docker-hold-ready"),
		DockerHoldRelease: filepath.Join(root, "run/nftfw/setup-docker-release"),
		DockerHoldService: filepath.Join(root, "run/systemd/generator/docker.service.d/50-nftfw-setup-hold.conf"),
		DockerHoldSocket:  filepath.Join(root, "run/systemd/generator/docker.socket.d/50-nftfw-setup-hold.conf"),
		ControlSocket:     filepath.Join(root, "run/nftfw/control.sock"),
		StatusSocket:      filepath.Join(root, "run/nftfw/status.sock"),
	}
	if err := os.MkdirAll(paths.SystemdDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(paths.NetworkBootMarker), 0o750); err != nil {
		t.Fatal(err)
	}
	profile := setupProfile(t)
	system := &System{
		Paths: paths, Runner: runner,
		InspectBoot: func(context.Context) (*bootObservation, error) { return nil, nil },
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
				Schema: health.StatusSchema, Version: "2.1.0", Status: "HEALTHY", Active: true,
				PolicyMatch: true, KillSwitchEnforced: true,
			}, nil
		},
		RuntimeReady: func(context.Context) error { return nil },
		ValidateHook: func(context.Context, prepared, uint64) error { return nil },
	}
	return system, paths
}

func configuredDockerPlan(
	t *testing.T, runner *systemRunner, changed bool,
) (*System, Plan, Paths) {
	t.Helper()
	system, paths := testSystem(t, runner)
	if runner.outputs == nil {
		runner.outputs = map[string][]byte{}
	}
	id := strings.Repeat("e", 64)
	network := config.DockerNetwork{
		Name: "media", Driver: "bridge", BridgeInterface: "br-" + id[:12],
		DynamicBridge: true, Subnets: []string{"172.20.0.0/16"},
		Gateways: []string{"172.20.0.1"},
	}
	runner.outputs["sysctl -n net.ipv4.ip_forward"] = []byte("1\n")
	runner.outputs["docker --host unix:///var/run/docker.sock network ls --no-trunc --format {{.ID}}\t{{.Name}}\t{{.Driver}}"] =
		[]byte(id + "\tmedia\tbridge\n")
	runner.outputs["docker --host unix:///var/run/docker.sock network inspect -- "+id] =
		[]byte(`[{"Id":"` + id + `","Name":"media","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{},"IPAM":{"Config":[{"Subnet":"172.20.0.0/16","Gateway":"172.20.0.1"}]}}]`)
	if err := os.MkdirAll(filepath.Dir(paths.DockerDaemon), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.DockerDaemon, []byte(
		`{"iptables":false,"ip6tables":false,"ip-forward":false,"ip-masq":false,"userland-proxy":false}`+"\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(paths.DockerDropIn), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		paths.DockerDropIn, []byte(containers.ManagedSocketDropIn), 0o644,
	); err != nil {
		t.Fatal(err)
	}
	return system, Plan{
		Summary: Summary{
			Schema: "nftfw.setup-plan.v1", VPNInterface: "nftfw0",
			DockerMode: "enabled", DockerNetworks: []string{"media"},
			DockerRestart: changed, ResolverMode: "none", NetworkProducers: testNetworkProducers(),
		},
		PrivateData: &prepared{
			Intent: intent.Intent{
				Schema: intent.Schema, Managed: true, DockerEnabled: true,
				DockerNetworks: []config.DockerNetwork{network},
			},
			DockerChanged: changed,
			Route: routing.Config{
				Interface: "nftfw0", Uplink: "eth0", Fwmark: "0xca6c",
				Table:           routing.DefaultTable,
				Addresses:       []netip.Prefix{netip.MustParsePrefix("10.8.0.2/32")},
				EndpointAddress: netip.MustParseAddr("198.51.100.8"),
				Resolver:        routing.ResolverNone,
				RuntimeDir:      filepath.Join(paths.RuntimeDir, "setup"),
			},
		},
	}, paths
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
		"nft --check --file " + filepath.Join(paths.RuntimeDir, "setup-candidate.nft"),
		"systemctl enable --now nftfw-rollback.timer",
		"ip -4 route replace default dev nftfw0 table 51820",
		"systemctl start nftfw-early.service",
		"nft delete table inet nftfw_setup_guard",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("simulated setup missing %q:\n%s", want, joined)
		}
	}
	runtimeStart := strings.Index(joined, "systemctl start nftfwd.service")
	earlyStart := strings.Index(joined, "systemctl start nftfw-early.service")
	initramfsBuild := strings.Index(joined, paths.InitramfsManager+" rebuild-enabled")
	bootEnable := strings.Index(joined, "systemctl enable nftfw-early.service")
	if runtimeStart < 0 || earlyStart <= runtimeStart || initramfsBuild <= earlyStart || bootEnable <= initramfsBuild {
		t.Fatalf("first-setup handoff ordering is unsafe:\n%s", joined)
	}
	for _, path := range []string{
		filepath.Join(paths.SystemdDir, "nftfwd.service.d", "50-nftfw-final-early.conf"),
		filepath.Join(paths.SystemdDir, "nftfw-rollback.service.d", "50-nftfw-final-early.conf"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("final dependency artifact missing %s: %v", path, err)
		}
	}
}

func TestInstallDefersFinalDependenciesUntilCommittedHandoff(t *testing.T) {
	runner := &systemRunner{}
	system, paths := testSystem(t, runner)
	plan, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	if err := system.Install(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(paths.SystemdDir, "nftfwd.service.d", "50-nftfw-final-early.conf"),
		filepath.Join(paths.SystemdDir, "nftfw-rollback.service.d", "50-nftfw-final-early.conf"),
		filepath.Join(paths.SystemdDir, "ifup@.service.d", netgate.DropInName),
		filepath.Join(paths.SystemdDir, "networking.service.d", netgate.DropInName),
		paths.InitramfsMarker, paths.InitramfsOwner, paths.InitramfsLoader, paths.InitramfsGate,
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("install phase published final artifact %s: %v", path, err)
		}
	}
	if err := system.StartRuntime(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := system.PublishFinalDependencies(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	for _, unit := range plan.Summary.NetworkProducers {
		path, err := netgate.DropInPath(paths.SystemdDir, unit)
		if err != nil || netgate.ValidateDropIn(path) != nil {
			t.Fatalf("final producer gate missing for %s: %v", unit, err)
		}
	}
	joined := strings.Join(runner.commands, "\n")
	if strings.Index(joined, "systemctl start nftfwd.service") >= strings.Index(joined, "systemctl start nftfw-early.service") {
		t.Fatalf("runtime did not precede final requisite publication:\n%s", joined)
	}
}

func TestNetworkProducerInventoryIsRevalidatedBeforeMutationAndHandoff(t *testing.T) {
	for _, phase := range []string{"backup", "handoff"} {
		t.Run(phase, func(t *testing.T) {
			runner := &systemRunner{}
			system, _ := testSystem(t, runner)
			plan, err := system.Prepare(context.Background(), "/provider.conf")
			if err != nil {
				t.Fatal(err)
			}
			if runner.outputs == nil {
				runner.outputs = map[string][]byte{}
			}
			runner.outputs["systemctl show --property=Id,LoadState,ActiveState,UnitFileState,FragmentPath ifup@nftfw-probe.service"] =
				[]byte("Id=ifup@nftfw-probe.service\nLoadState=not-found\nActiveState=inactive\nUnitFileState=\nFragmentPath=\n")
			var runErr error
			if phase == "backup" {
				_, runErr = system.Backup(context.Background(), plan)
			} else {
				runErr = system.PublishFinalDependencies(context.Background(), plan)
			}
			if runErr == nil || runErr.Error() != "SETUP_NETWORK_PRODUCER_STATE_CHANGED" {
				t.Fatalf("changed producer inventory accepted: %v", runErr)
			}
		})
	}
}

func TestNetworkProducerRevalidationRefusesInvalidAndUnreadableState(t *testing.T) {
	for _, test := range []struct {
		name     string
		expected []string
		mutate   func(*systemRunner)
	}{
		{name: "invalid-expected", expected: []string{"foreign.service"}},
		{
			name: "unreadable-observation", expected: testNetworkProducers(),
			mutate: func(runner *systemRunner) {
				runner.outputs = map[string][]byte{
					"systemctl show --property=Id,LoadState,ActiveState,UnitFileState,FragmentPath networking.service": []byte("truncated\n"),
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &systemRunner{}
			if test.mutate != nil {
				test.mutate(runner)
			}
			system, _ := testSystem(t, runner)
			if err := system.revalidateNetworkProducers(context.Background(), test.expected); err == nil {
				t.Fatal("unsafe producer state was accepted")
			}
		})
	}
}

func TestNetworkProducerGateRollbackRestoresExactPriorFiles(t *testing.T) {
	runner := &systemRunner{}
	system, paths := testSystem(t, runner)
	prior := []byte("[Unit]\nAfter=local-fs.target\n")
	priorPath := filepath.Join(paths.SystemdDir, "ifup@.service.d", netgate.DropInName)
	if err := os.MkdirAll(filepath.Dir(priorPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(priorPath, prior, 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	backup, err := system.Backup(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.PrivateData.(*prepared).BackupDir = backup
	if err := system.PublishFinalDependencies(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := system.Rollback(context.Background(), plan, Journal{
		Phase: PhaseHandoff, BackupDir: backup, Summary: plan.Summary,
	}); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, priorPath); !bytes.Equal(got, prior) {
		t.Fatalf("prior producer drop-in not restored exactly: %q", got)
	}
	absentPath := filepath.Join(paths.SystemdDir, "networking.service.d", netgate.DropInName)
	if _, err := os.Lstat(absentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new producer drop-in survived rollback: %v", err)
	}
}

func TestStartRuntimeWaitsForDaemonReadiness(t *testing.T) {
	runner := &systemRunner{}
	system, _ := testSystem(t, runner)
	system.RuntimeReadyPoll = time.Millisecond
	system.RuntimeReadyTimeout = time.Second
	calls := 0
	system.RuntimeReady = func(context.Context) error {
		calls++
		if calls < 4 {
			return errRuntimeStarting
		}
		return nil
	}
	if err := system.StartRuntime(context.Background(), Plan{}); err != nil {
		t.Fatal(err)
	}
	if calls != 4 {
		t.Fatalf("readiness probes=%d want=4", calls)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "systemctl start nftfwd.service") {
		t.Fatalf("daemon was not started before readiness:\n%s", joined)
	}
}

func TestStartRuntimeReadinessFailuresAreBounded(t *testing.T) {
	tests := []struct {
		name    string
		ctx     func() (context.Context, context.CancelFunc)
		probe   func(context.Context) error
		timeout time.Duration
		want    string
	}{
		{
			name: "daemon-exit", ctx: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			probe:   func(context.Context) error { return errors.New("SETUP_DAEMON_NOT_RUNNING") },
			timeout: time.Second, want: "SETUP_DAEMON_NOT_RUNNING",
		},
		{
			name: "degraded", ctx: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			probe:   func(context.Context) error { return errors.New("SETUP_DAEMON_DEGRADED") },
			timeout: time.Second, want: "SETUP_DAEMON_DEGRADED",
		},
		{
			name: "timeout", ctx: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			probe:   func(context.Context) error { return errRuntimeStarting },
			timeout: 2 * time.Millisecond, want: "SETUP_DAEMON_READINESS_TIMEOUT",
		},
		{
			name: "canceled", ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			probe:   func(context.Context) error { return errRuntimeStarting },
			timeout: time.Second, want: "SETUP_DAEMON_READINESS_CANCELED",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			system, _ := testSystem(t, &systemRunner{})
			system.RuntimeReady = test.probe
			system.RuntimeReadyPoll = time.Millisecond
			system.RuntimeReadyTimeout = test.timeout
			ctx, cancel := test.ctx()
			defer cancel()
			err := system.StartRuntime(ctx, Plan{})
			if err == nil || err.Error() != test.want {
				t.Fatalf("readiness error=%v want=%s", err, test.want)
			}
		})
	}
}

func TestRuntimeProcessPropertiesAreStrict(t *testing.T) {
	valid, err := parseRuntimeProperties([]byte("MainPID=42\nActiveState=active\nSubState=running\n"))
	if err != nil || valid["MainPID"] != "42" {
		t.Fatalf("valid process properties rejected: %#v %v", valid, err)
	}
	for _, data := range [][]byte{
		[]byte("MainPID=42\nActiveState=active\n"),
		[]byte("MainPID=42\nMainPID=43\nActiveState=active\nSubState=running\n"),
		[]byte("MainPID=42\nActiveState=active\nSubState=running\nUnknown=x\n"),
		[]byte("MainPID=\nActiveState=active\nSubState=running\n"),
	} {
		if _, err := parseRuntimeProperties(data); err == nil {
			t.Fatalf("unsafe process properties accepted: %q", data)
		}
	}
}

func TestRuntimeExecutableAllowsOnlySystemdExecTransition(t *testing.T) {
	if err := validateRuntimeExecutable("/usr/lib/nftfw/nftfwd"); err != nil {
		t.Fatalf("expected daemon executable rejected: %v", err)
	}
	if err := validateRuntimeExecutable("/usr/lib/systemd/systemd-executor"); !errors.Is(err, errRuntimeStarting) {
		t.Fatalf("ordinary systemd exec transition rejected: %v", err)
	}
	for _, path := range []string{
		"/tmp/nftfwd", "/usr/local/bin/nftfwd", "/usr/lib/nftfw/nftfwd (deleted)",
	} {
		if err := validateRuntimeExecutable(path); err == nil ||
			err.Error() != "SETUP_DAEMON_PROCESS_UNSAFE" {
			t.Fatalf("unexpected daemon executable accepted %q: %v", path, err)
		}
	}
}

func TestRuntimeProcessReadinessIsFailClosed(t *testing.T) {
	processRoot := t.TempDir()
	uid := uint32(os.Geteuid())
	response := func(value string) systemRunnerFunc {
		return func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
			if name != "systemctl" || strings.Join(args, " ") !=
				"show --property=MainPID,ActiveState,SubState nftfwd.service" {
				t.Fatalf("unexpected command: %s %s", name, strings.Join(args, " "))
			}
			return []byte(value), nil
		}
	}
	systemFor := func(runner routing.Runner) *System {
		return &System{Runner: runner, runtimeProcessRoot: processRoot, runtimeProcessUID: &uid}
	}
	for _, test := range []struct {
		name string
		data string
		want string
	}{
		{"empty", "", "SETUP_DAEMON_STATE_FAILED"},
		{"activating", "MainPID=2\nActiveState=activating\nSubState=start\n", errRuntimeStarting.Error()},
		{"active-start", "MainPID=2\nActiveState=active\nSubState=start\n", errRuntimeStarting.Error()},
		{"inactive", "MainPID=2\nActiveState=inactive\nSubState=dead\n", "SETUP_DAEMON_NOT_RUNNING"},
		{"invalid-pid", "MainPID=text\nActiveState=active\nSubState=running\n", errRuntimeStarting.Error()},
		{"unsafe-pid", "MainPID=1\nActiveState=active\nSubState=running\n", errRuntimeStarting.Error()},
		{"missing-process", "MainPID=42\nActiveState=active\nSubState=running\n", errRuntimeStarting.Error()},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := systemFor(response(test.data)).runtimeProcessReady(context.Background())
			if err == nil || err.Error() != test.want {
				t.Fatalf("error=%v want=%s", err, test.want)
			}
		})
	}
	errRunner := systemRunnerFunc(func(context.Context, []byte, string, ...string) ([]byte, error) {
		return nil, errors.New("injected")
	})
	if err := systemFor(errRunner).runtimeProcessReady(context.Background()); err == nil ||
		err.Error() != "SETUP_DAEMON_STATE_FAILED" {
		t.Fatalf("command failure was accepted: %v", err)
	}
	oversized := strings.Repeat("x", 4097)
	if err := systemFor(response(oversized)).runtimeProcessReady(context.Background()); err == nil ||
		err.Error() != "SETUP_DAEMON_STATE_FAILED" {
		t.Fatalf("oversized state was accepted: %v", err)
	}

	process := filepath.Join(processRoot, "43")
	if err := os.WriteFile(process, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	running := response("MainPID=43\nActiveState=active\nSubState=running\n")
	if err := systemFor(running).runtimeProcessReady(context.Background()); err == nil ||
		err.Error() != "SETUP_DAEMON_PROCESS_UNSAFE" {
		t.Fatalf("non-directory process identity was accepted: %v", err)
	}
	if err := os.Remove(process); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(process, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := systemFor(running).runtimeProcessReady(context.Background()); !errors.Is(err, errRuntimeStarting) {
		t.Fatalf("missing executable was not treated as startup: %v", err)
	}
	if err := os.Symlink("/usr/lib/systemd/systemd-executor", filepath.Join(process, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := systemFor(running).runtimeProcessReady(context.Background()); !errors.Is(err, errRuntimeStarting) {
		t.Fatalf("systemd exec transition was rejected incorrectly: %v", err)
	}
	if err := os.Remove(filepath.Join(process, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/lib/nftfw/nftfwd", filepath.Join(process, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := systemFor(running).runtimeProcessReady(context.Background()); err != nil {
		t.Fatalf("exact daemon process was rejected: %v", err)
	}
	wrongUID := uid + 1
	wrongOwner := systemFor(running)
	wrongOwner.runtimeProcessUID = &wrongUID
	if err := wrongOwner.runtimeProcessReady(context.Background()); err == nil ||
		err.Error() != "SETUP_DAEMON_PROCESS_UNSAFE" {
		t.Fatalf("wrong process owner was accepted: %v", err)
	}
}

func TestRuntimeReadinessRequiresBothAPIsAndExactProcess(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(root, "status.sock")
	controlPath := filepath.Join(root, "control.sock")
	statusSocket, err := net.Listen("unix", statusPath)
	if err != nil {
		t.Fatal(err)
	}
	defer statusSocket.Close()
	controlSocket, err := net.Listen("unix", controlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer controlSocket.Close()
	if err := os.Chmod(statusPath, 0o660); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(controlPath, 0o600); err != nil {
		t.Fatal(err)
	}
	processRoot := filepath.Join(root, "proc")
	process := filepath.Join(processRoot, "44")
	if err := os.MkdirAll(process, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/lib/nftfw/nftfwd", filepath.Join(process, "exe")); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	healthy := health.Snapshot{
		Schema: health.StatusSchema, Version: "2.1.0", Status: "HEALTHY",
		Active: true, PolicyMatch: true, KillSwitchEnforced: true,
	}
	system := &System{
		Paths: Paths{StatusSocket: statusPath, ControlSocket: controlPath},
		Runner: systemRunnerFunc(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
			if name != "systemctl" || len(args) == 0 {
				return nil, errors.New("unexpected")
			}
			return []byte("MainPID=44\nActiveState=active\nSubState=running\n"), nil
		}),
		Status:             func(context.Context) (health.Snapshot, error) { return healthy, nil },
		Control:            func(context.Context, api.Request) (any, error) { return healthy, nil },
		runtimeProcessRoot: processRoot,
		runtimeProcessUID:  &uid,
	}
	if err := system.runtimeReady(context.Background()); err != nil {
		t.Fatalf("complete readiness proof failed: %v", err)
	}
}

func TestRuntimeReadinessStopsBeforeUnsafeDependencies(t *testing.T) {
	if uid := (&System{}).expectedRuntimeUID(); uid != 0 {
		t.Fatalf("production runtime UID=%d want=0", uid)
	}
	processFailure := &System{Runner: systemRunnerFunc(func(context.Context, []byte, string, ...string) ([]byte, error) {
		return nil, errors.New("injected")
	})}
	if err := processFailure.runtimeReady(context.Background()); err == nil ||
		err.Error() != "SETUP_DAEMON_STATE_FAILED" {
		t.Fatalf("process inspection failure was accepted: %v", err)
	}
	root := t.TempDir()
	process := filepath.Join(root, "45")
	if err := os.Mkdir(process, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/lib/nftfw/nftfwd", filepath.Join(process, "exe")); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	socketFailure := &System{
		Paths: Paths{
			StatusSocket:  filepath.Join(root, "missing-runtime", "status.sock"),
			ControlSocket: filepath.Join(root, "missing-runtime", "control.sock"),
		},
		Runner: systemRunnerFunc(func(context.Context, []byte, string, ...string) ([]byte, error) {
			return []byte("MainPID=45\nActiveState=active\nSubState=running\n"), nil
		}),
		runtimeProcessRoot: root,
		runtimeProcessUID:  &uid,
	}
	if err := socketFailure.runtimeReady(context.Background()); !errors.Is(err, errRuntimeStarting) {
		t.Fatalf("missing socket contract was not fail-closed: %v", err)
	}
}

func TestRuntimeAPIReadinessFailureMatrix(t *testing.T) {
	healthy := health.Snapshot{
		Schema: health.StatusSchema, Version: "2.1.0", Status: "HEALTHY",
		Active: true, PolicyMatch: true, KillSwitchEnforced: true,
	}
	degraded := healthy
	degraded.Status = "DEGRADED"
	for _, test := range []struct {
		name    string
		status  func(context.Context) (health.Snapshot, error)
		control func(context.Context, api.Request) (any, error)
		want    string
	}{
		{"status-error", func(context.Context) (health.Snapshot, error) { return health.Snapshot{}, errors.New("injected") }, nil, errRuntimeStarting.Error()},
		{"status-degraded", func(context.Context) (health.Snapshot, error) { return degraded, nil }, nil, "SETUP_DAEMON_DEGRADED"},
		{"control-error", func(context.Context) (health.Snapshot, error) { return healthy, nil }, func(context.Context, api.Request) (any, error) { return nil, errors.New("injected") }, errRuntimeStarting.Error()},
		{"control-invalid", func(context.Context) (health.Snapshot, error) { return healthy, nil }, func(context.Context, api.Request) (any, error) { return "invalid", nil }, "SETUP_DAEMON_STATUS_INVALID"},
		{"control-degraded", func(context.Context) (health.Snapshot, error) { return healthy, nil }, func(context.Context, api.Request) (any, error) { return degraded, nil }, "SETUP_DAEMON_DEGRADED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			system := &System{Status: test.status, Control: test.control}
			err := system.runtimeAPIReady(context.Background())
			if err == nil || err.Error() != test.want {
				t.Fatalf("error=%v want=%s", err, test.want)
			}
		})
	}
	if _, err := decodeRuntimeSnapshot(make(chan int)); err == nil || err.Error() != "SETUP_DAEMON_STATUS_INVALID" {
		t.Fatalf("unencodable runtime status was accepted: %v", err)
	}
}

func TestRuntimeSocketContracts(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(root, "status.sock")
	controlPath := filepath.Join(root, "control.sock")
	system := &System{Paths: Paths{StatusSocket: statusPath, ControlSocket: controlPath}}
	if err := system.runtimeSocketContracts(uint32(os.Geteuid())); !errors.Is(err, errRuntimeStarting) {
		t.Fatalf("missing sockets were not treated as startup: %v", err)
	}
	status, err := net.Listen("unix", statusPath)
	if err != nil {
		t.Fatal(err)
	}
	defer status.Close()
	if err := os.Chmod(statusPath, 0o660); err != nil {
		t.Fatal(err)
	}
	if err := system.runtimeSocketContracts(uint32(os.Geteuid())); !errors.Is(err, errRuntimeStarting) {
		t.Fatalf("missing control socket was not treated as startup: %v", err)
	}
	control, err := net.Listen("unix", controlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if err := os.Chmod(controlPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := system.runtimeSocketContracts(uint32(os.Geteuid())); err != nil {
		t.Fatalf("valid runtime sockets rejected: %v", err)
	}
	if err := os.Chmod(statusPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := system.runtimeSocketContracts(uint32(os.Geteuid())); err == nil ||
		err.Error() != "SETUP_DAEMON_SOCKET_UNSAFE" {
		t.Fatalf("unsafe socket mode accepted: %v", err)
	}
	if err := os.Chmod(statusPath, 0o660); err != nil {
		t.Fatal(err)
	}
	if err := system.runtimeSocketContracts(uint32(os.Geteuid() + 1)); err == nil ||
		err.Error() != "SETUP_DAEMON_SOCKET_UNSAFE" {
		t.Fatalf("wrong socket ownership accepted: %v", err)
	}
	status.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := status.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(statusPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statusPath, []byte("not-a-socket"), 0o660); err != nil {
		t.Fatal(err)
	}
	if err := system.runtimeSocketContracts(uint32(os.Geteuid())); err == nil ||
		err.Error() != "SETUP_DAEMON_SOCKET_UNSAFE" {
		t.Fatalf("wrong socket type accepted: %v", err)
	}
}

func TestRuntimeSnapshotRejectsEstablishedDegradation(t *testing.T) {
	bootstrap := health.Snapshot{
		Schema: health.StatusSchema, Version: "2.1.0", Status: "DEGRADED",
		Reason: "no applied or committed policy generation exists", Database: "ok",
		Managed: true,
	}
	if err := validateRuntimeSnapshot(bootstrap); err != nil {
		t.Fatalf("exact clean-host bootstrap state rejected: %v", err)
	}
	healthy := health.Snapshot{
		Schema: health.StatusSchema, Version: "2.1.0", Status: "HEALTHY",
		Active: true, PolicyMatch: true, KillSwitchEnforced: true,
	}
	if err := validateRuntimeSnapshot(healthy); err != nil {
		t.Fatalf("healthy daemon rejected: %v", err)
	}
	for _, snapshot := range []health.Snapshot{
		{Schema: health.StatusSchema, Version: "2.1.0", Status: "DEGRADED", Database: "degraded", Managed: true},
		{Schema: health.StatusSchema, Version: "2.1.0", Status: "DEGRADED", Reason: bootstrap.Reason, Database: "ok"},
		{Schema: health.StatusSchema, Status: "HEALTHY"},
		{Schema: health.StatusSchema, Version: "2.1.0", Status: "HEALTHY"},
	} {
		if err := validateRuntimeSnapshot(snapshot); err == nil {
			t.Fatalf("unsafe runtime status accepted: %#v", snapshot)
		}
	}
}

func TestRuntimeAPIReadinessUsesStatusAndAuthenticatedControl(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root peer credentials are required for the control-socket readiness proof")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(root, "status.sock")
	controlPath := filepath.Join(root, "control.sock")
	ctx, cancel := context.WithCancel(context.Background())
	server := &api.Server{
		Handler: setupAPIHandler{status: health.Snapshot{
			Schema: health.StatusSchema, Version: "2.1.0", Status: "HEALTHY",
			Active: true, PolicyMatch: true, KillSwitchEnforced: true,
		}},
		StatusPath: statusPath, ControlPath: controlPath,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	for deadline := time.Now().Add(time.Second); ; {
		if statusInfo, statusErr := os.Lstat(statusPath); statusErr == nil && statusInfo.Mode()&os.ModeSocket != 0 {
			if controlInfo, controlErr := os.Lstat(controlPath); controlErr == nil && controlInfo.Mode()&os.ModeSocket != 0 {
				break
			}
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("daemon API sockets did not start")
		}
		time.Sleep(time.Millisecond)
	}
	system := &System{Paths: Paths{StatusSocket: statusPath, ControlSocket: controlPath}}
	if err := system.runtimeAPIReady(context.Background()); err != nil {
		cancel()
		t.Fatalf("protected daemon API readiness failed: %v", err)
	}
	if _, err := api.Call(context.Background(), controlPath, api.Request{Op: "reconcile"}); err == nil || err.Error() != "not used" {
		cancel()
		t.Fatalf("fixture control handler accepted a non-status operation: %v", err)
	}
	cancel()
	<-done
}

func TestDockerBackupCapturesSocketPresenceExactly(t *testing.T) {
	runner := &systemRunner{outputs: map[string][]byte{
		"systemctl show --property=LoadState,ActiveState docker.service": []byte("LoadState=loaded\nActiveState=active\n"),
		"systemctl show --property=LoadState,ActiveState docker.socket":  []byte("LoadState=loaded\nActiveState=inactive\n"),
	}}
	system, plan, _ := configuredDockerPlan(t, runner, false)
	directory, err := system.Backup(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := readBackup(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := manifest.Units["docker.socket"]; !ok {
		t.Fatal("present Docker socket state was not captured")
	}
	runner.outputs["systemctl show --property=LoadState,ActiveState docker.socket"] = []byte("LoadState=not-found\nActiveState=inactive\n")
	system.Now = func() time.Time { return time.Now().Add(time.Second) }
	directory, err = system.Backup(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err = readBackup(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := manifest.Units["docker.socket"]; ok {
		t.Fatal("absent Docker socket was recorded as present")
	}
	runner.outputs["systemctl show --property=LoadState,ActiveState docker.socket"] = []byte("LoadState=loaded\nActiveState=failed\n")
	system.Now = func() time.Time { return time.Now().Add(2 * time.Second) }
	if _, err := system.Backup(context.Background(), plan); err == nil ||
		err.Error() != "SETUP_BACKUP_DOCKER_SOCKET_STATE_INVALID" {
		t.Fatalf("ambiguous Docker socket state accepted: %v", err)
	}
}

func TestFinalDependencyPublicationFailureBranches(t *testing.T) {
	t.Run("initramfs-manager", func(t *testing.T) {
		runner := &systemRunner{}
		system, paths := testSystem(t, runner)
		runner.fail = paths.InitramfsManager + " rebuild-enabled"
		plan := Plan{Summary: Summary{NetworkProducers: testNetworkProducers()}}
		if err := system.PublishFinalDependencies(context.Background(), plan); err == nil ||
			err.Error() != "SETUP_INITRAMFS_GUARD_FAILED" {
			t.Fatalf("manager error=%v", err)
		}
	})
	t.Run("dependency-target", func(t *testing.T) {
		runner := &systemRunner{}
		system, paths := testSystem(t, runner)
		if err := os.Remove(paths.SystemdDir); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(paths.SystemdDir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(paths.SystemdDir, []byte("not a directory\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		plan := Plan{Summary: Summary{NetworkProducers: testNetworkProducers()}}
		if err := system.PublishFinalDependencies(context.Background(), plan); err == nil ||
			err.Error() != "SETUP_FINAL_DEPENDENCY_PUBLISH_FAILED" {
			t.Fatalf("unsafe dependency target error=%v", err)
		}
	})
	t.Run("producer-target", func(t *testing.T) {
		runner := &systemRunner{}
		system, paths := testSystem(t, runner)
		plan, err := system.Prepare(context.Background(), "/provider.conf")
		if err != nil {
			t.Fatal(err)
		}
		parent := filepath.Join(paths.SystemdDir, "ifup@.service.d")
		if err := os.WriteFile(parent, []byte("not a directory\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := system.PublishFinalDependencies(context.Background(), plan); err == nil ||
			err.Error() != "SETUP_FINAL_DEPENDENCY_PUBLISH_FAILED" {
			t.Fatalf("unsafe producer target error=%v", err)
		}
	})
	t.Run("reload", func(t *testing.T) {
		runner := &systemRunner{fail: "systemctl daemon-reload"}
		system, _ := testSystem(t, runner)
		plan := Plan{Summary: Summary{NetworkProducers: testNetworkProducers()}}
		if err := system.PublishFinalDependencies(context.Background(), plan); err == nil ||
			err.Error() != "SETUP_FINAL_DEPENDENCY_RELOAD_FAILED" {
			t.Fatalf("dependency reload error=%v", err)
		}
	})
	t.Run("effective-graph", func(t *testing.T) {
		runner := &systemRunner{outputs: map[string][]byte{
			"systemctl show --property=Requires,BindsTo,After ifup@nftfw-probe.service": []byte("Requires=nftfw-enforcement-ready.service\nBindsTo=nftfw-enforcement-ready.service\nAfter=network-pre.target\n"),
		}}
		system, _ := testSystem(t, runner)
		plan := Plan{Summary: Summary{NetworkProducers: testNetworkProducers()}}
		if err := system.PublishFinalDependencies(context.Background(), plan); err == nil ||
			err.Error() != "SETUP_FINAL_DEPENDENCY_VERIFY_FAILED" {
			t.Fatalf("missing effective producer ordering accepted: %v", err)
		}
	})
}

func TestEngineAndSystemPrepareBeforePublishingFirstSetupJournal(t *testing.T) {
	for _, dryRunFirst := range []bool{false, true} {
		name := "direct"
		if dryRunFirst {
			name = "after-dry-run"
		}
		t.Run(name, func(t *testing.T) {
			runner := &systemRunner{}
			system, paths := testSystem(t, runner)
			journalPath := filepath.Join(paths.StateDir, "setup", "journal.json")
			cleanDiscover := system.Discover
			discoveries := 0
			system.Discover = func(ctx context.Context) (discovery.Snapshot, error) {
				discoveries++
				if _, err := os.Lstat(journalPath); err == nil {
					return discovery.Snapshot{}, errors.New("DISCOVERY_EXISTING_NFTFW_REQUIRES_ADOPT")
				} else if !errors.Is(err, os.ErrNotExist) {
					return discovery.Snapshot{}, errors.New("DISCOVERY_EXISTING_NFTFW_STATE_UNREADABLE")
				}
				return cleanDiscover(ctx)
			}
			engine := Engine{
				Executor: system, Journal: FileJournal{Path: journalPath},
				NewID: func() string { return "first-setup-order" },
				Now:   func() time.Time { return testTime() },
			}
			if dryRunFirst {
				if _, err := engine.DryRun(context.Background(), "/provider.conf"); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(journalPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("dry-run published a setup journal: %v", err)
				}
			}
			if _, err := engine.Run(context.Background(), "/provider.conf"); err != nil {
				t.Fatal(err)
			}
			wantDiscoveries := 1
			if dryRunFirst {
				wantDiscoveries = 2
			}
			if discoveries != wantDiscoveries {
				t.Fatalf("discoveries=%d want=%d", discoveries, wantDiscoveries)
			}
			journal, err := (FileJournal{Path: journalPath}).Read()
			if err != nil || journal.Status != "complete" || journal.Summary.Schema != "nftfw.setup-plan.v1" {
				t.Fatalf("first setup journal invalid: %#v %v", journal, err)
			}
		})
	}
}

func TestEngineAndSystemPreparationBoundaryFailuresDoNotMutate(t *testing.T) {
	t.Run("prepare", func(t *testing.T) {
		runner := &systemRunner{}
		system, paths := testSystem(t, runner)
		system.Discover = func(context.Context) (discovery.Snapshot, error) {
			return discovery.Snapshot{}, errors.New("DISCOVERY_COMPETING_FIREWALL")
		}
		journalPath := filepath.Join(paths.StateDir, "setup", "journal.json")
		_, err := (Engine{
			Executor: system, Journal: FileJournal{Path: journalPath},
		}).Run(context.Background(), "/provider.conf")
		if err == nil || err.Error() != "DISCOVERY_COMPETING_FIREWALL" {
			t.Fatalf("unexpected preparation refusal: %v", err)
		}
		if _, err := os.Lstat(journalPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("preparation refusal published a journal: %v", err)
		}
		assertNoSetupMutation(t, runner, paths)
	})

	t.Run("initial-journal", func(t *testing.T) {
		runner := &systemRunner{}
		system, paths := testSystem(t, runner)
		journalPath := filepath.Join(paths.StateDir, "setup", "journal.json")
		store := &recordingJournal{
			store: FileJournal{Path: journalPath}, failWrites: 1,
		}
		_, err := (Engine{Executor: system, Journal: store}).
			Run(context.Background(), "/provider.conf")
		if err == nil || err.Error() != "SETUP_JOURNAL_WRITE_FAILED" {
			t.Fatalf("unexpected journal refusal: %v", err)
		}
		if store.last.Summary.Schema != "nftfw.setup-plan.v1" {
			t.Fatalf("initial journal lacked prepared plan: %#v", store.last)
		}
		if _, err := os.Lstat(journalPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed journal write published state: %v", err)
		}
		assertNoSetupMutation(t, runner, paths)
	})

	t.Run("backup", func(t *testing.T) {
		runner := &systemRunner{fail: "sysctl -n"}
		system, paths := testSystem(t, runner)
		journalPath := filepath.Join(paths.StateDir, "setup", "journal.json")
		_, err := (Engine{
			Executor: system, Journal: FileJournal{Path: journalPath},
			NewID: func() string { return "backup-boundary" },
		}).Run(context.Background(), "/provider.conf")
		if err == nil || err.Error() != "SETUP_BACKUP_SYSCTL_FAILED" {
			t.Fatalf("unexpected backup refusal: %v", err)
		}
		journal, readErr := (FileJournal{Path: journalPath}).Read()
		if readErr != nil || journal.Status != "rolled_back" ||
			journal.Phase != PhaseFailed || journal.BackupDir != "" {
			t.Fatalf("backup refusal journal invalid: %#v %v", journal, readErr)
		}
		assertNoSetupMutation(t, runner, paths)
	})
}

func assertNoSetupMutation(t testing.TB, runner *systemRunner, paths Paths) {
	t.Helper()
	for _, path := range []string{paths.Config, paths.Intent, paths.VPN, paths.Sysctl} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("pre-mutation failure changed %s: %v", path, err)
		}
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(command, "systemctl enable") ||
			strings.HasPrefix(command, "systemctl start") ||
			strings.HasPrefix(command, "systemctl restart") ||
			strings.HasPrefix(command, "sysctl -w") ||
			strings.Contains(command, "nft --file") ||
			strings.Contains(command, "route replace") {
			t.Fatalf("pre-mutation failure executed %q", command)
		}
	}
}

func TestSystemRollbackBeforeProtectedMutationIsNoOp(t *testing.T) {
	for _, phase := range []Phase{PhaseInspect, PhaseBackup} {
		t.Run(string(phase), func(t *testing.T) {
			runner := &systemRunner{}
			system, _ := testSystem(t, runner)
			if err := system.Rollback(context.Background(), Plan{}, Journal{
				Phase: phase, Summary: Summary{Schema: "nftfw.setup-plan.v1"},
			}); err != nil {
				t.Fatal(err)
			}
			if len(runner.commands) != 0 {
				t.Fatalf("pre-mutation rollback changed system state: %v", runner.commands)
			}
		})
	}
}

func TestManagedDockerCompliantConfigDoesNotRestart(t *testing.T) {
	id := strings.Repeat("c", 64)
	runner := &systemRunner{outputs: map[string][]byte{
		"systemctl is-active --quiet docker.service": []byte("active\n"),
		"sysctl -n net.ipv4.ip_forward":              []byte("1\n"),
		"docker --host unix:///var/run/docker.sock network ls --no-trunc --format {{.ID}}\t{{.Name}}\t{{.Driver}}": []byte(
			id + "\tbridge\tbridge\n",
		),
		"docker --host unix:///var/run/docker.sock network inspect -- " + id: []byte(
			`[{"Id":"` + id + `","Name":"bridge","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{},"IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}]`,
		),
	}}
	system, paths := testSystem(t, runner)
	if err := os.MkdirAll(filepath.Dir(paths.DockerDaemon), 0o700); err != nil {
		t.Fatal(err)
	}
	compliant := []byte(`{
  "ip-forward": false,
  "ip-masq": false,
  "ip6tables": false,
  "iptables": false,
  "userland-proxy": false
}
`)
	if err := os.WriteFile(paths.DockerDaemon, compliant, 0o600); err != nil {
		t.Fatal(err)
	}
	system.Discover = func(context.Context) (discovery.Snapshot, error) {
		return discovery.Snapshot{
			OSID: "debian", OSVersion: "13", Architecture: "amd64",
			Uplink: "eth0", UplinkGateway: netip.MustParseAddr("192.168.1.1"),
			LANNetworks:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			ManagementTCP: []int{22}, DockerPresent: true, DockerClean: true,
			DockerNetworks: []config.DockerNetwork{{
				Name: "bridge", Driver: "bridge", BridgeInterface: "docker0",
				DynamicBridge: true, Subnets: []string{"172.17.0.0/16"},
				Gateways: []string{"172.17.0.1"},
			}},
		}, nil
	}
	system.ConfirmDockerRestart = func(Summary) error {
		return errors.New("confirmation must not be requested")
	}
	plan, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.DockerRestart {
		t.Fatal("compliant Docker daemon incorrectly requires restart")
	}
	if err := system.Install(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := system.ConfigureDocker(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	for _, command := range runner.commands {
		if command == "systemctl restart docker.service" {
			t.Fatal("idempotent Docker setup restarted Docker")
		}
	}
}

func TestDockerCandidateCheckFailsBeforeOwnershipWrite(t *testing.T) {
	id := strings.Repeat("d", 64)
	runner := &systemRunner{fail: "setup-candidate.nft"}
	system, paths := testSystem(t, runner)
	if err := os.MkdirAll(filepath.Dir(paths.DockerDaemon), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte(`{"iptables":true}`)
	if err := os.WriteFile(paths.DockerDaemon, original, 0o600); err != nil {
		t.Fatal(err)
	}
	system.Discover = func(context.Context) (discovery.Snapshot, error) {
		return discovery.Snapshot{
			OSID: "debian", OSVersion: "13", Architecture: "amd64",
			Uplink: "eth0", UplinkGateway: netip.MustParseAddr("192.168.1.1"),
			LANNetworks:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			ManagementTCP: []int{22}, DockerPresent: true, DockerClean: true,
			DockerNetworks: []config.DockerNetwork{{
				Name: "bridge", Driver: "bridge", BridgeInterface: "docker0",
				DynamicBridge: true, Subnets: []string{"172.17.0.0/16"},
				Gateways: []string{"172.17.0.1"},
			}},
		}, nil
	}
	plan, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	if err := system.Install(context.Background(), plan); err == nil ||
		err.Error() != "SETUP_POLICY_CHECK_FAILED" {
		t.Fatalf("invalid candidate did not stop install: %v", err)
	}
	if string(mustRead(t, paths.DockerDaemon)) != string(original) {
		t.Fatal("Docker ownership changed before nftables candidate validation")
	}
	if _, err := os.Lstat(paths.DockerDropIn); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Docker drop-in changed before candidate validation: %v", err)
	}
	_ = id
}

func TestInstallRejectsUnsafeDockerSocketOwnershipTarget(t *testing.T) {
	runner := &systemRunner{}
	system, plan, _ := configuredDockerPlan(t, runner, false)
	system.Paths.DockerDropIn = "relative/docker-access.conf"
	if err := system.Install(context.Background(), plan); err == nil {
		t.Fatal("relative Docker socket ownership target accepted")
	}
	if len(runner.commands) != 0 {
		t.Fatalf("command ran before Docker ownership target validation: %v", runner.commands)
	}
}

func TestInstallRefusesDockerWorkloadAppearingAfterPlanBeforeOwnershipWrite(t *testing.T) {
	runner := &systemRunner{}
	system, plan, paths := configuredDockerPlan(t, runner, false)
	private, err := privatePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	private.DockerData, private.DockerChanged, err = containers.ManagedDaemonConfig(paths.DockerDaemon)
	if err != nil || private.DockerChanged {
		t.Fatalf("test daemon projection failed: changed=%t err=%v", private.DockerChanged, err)
	}
	private.PolicyData = []byte("table inet nftfw_filter {}\n")
	containerID := strings.Repeat("9", 64)
	runner.outputs["docker --host unix:///var/run/docker.sock ps -q --no-trunc"] = nil
	runner.outputs["docker --host unix:///var/run/docker.sock ps -aq --no-trunc"] = []byte(containerID + "\n")
	originalDaemon := append([]byte(nil), mustRead(t, paths.DockerDaemon)...)
	if err := system.Install(context.Background(), plan); err == nil ||
		err.Error() != "SETUP_DOCKER_STATE_CHANGED_AFTER_PLAN" {
		t.Fatalf("post-plan Docker workload was not refused: %v", err)
	}
	if string(mustRead(t, paths.DockerDaemon)) != string(originalDaemon) {
		t.Fatal("Docker ownership changed after workload refusal")
	}
	for _, path := range []string{paths.Config, paths.Intent, paths.VPN, paths.Sysctl} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("managed file changed after workload refusal: %s: %v", path, err)
		}
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(command, "sysctl -w") || command == "systemctl daemon-reload" {
			t.Fatalf("host ownership mutation followed workload refusal: %s", command)
		}
	}
}

func TestManagedDockerOwnershipForwardingAndRollback(t *testing.T) {
	id := strings.Repeat("a", 64)
	runner := &systemRunner{outputs: map[string][]byte{
		"sysctl -n net.ipv4.ip_forward": []byte("1\n"),
		"docker --host unix:///var/run/docker.sock network ls --no-trunc --format {{.ID}}\t{{.Name}}\t{{.Driver}}": []byte(
			id + "\tcosmos-app\tbridge\n",
		),
		"docker --host unix:///var/run/docker.sock network inspect -- " + id: []byte(
			`[{"Id":"` + id + `","Name":"cosmos-app","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{},"IPAM":{"Config":[{"Subnet":"172.23.0.0/16","Gateway":"172.23.0.1"}]}}]`,
		),
	}}
	system, paths := testSystem(t, runner)
	if err := os.MkdirAll(filepath.Dir(paths.DockerDaemon), 0o700); err != nil {
		t.Fatal(err)
	}
	originalDaemon := []byte("{\n  \"data-root\": \"/srv/docker\",\n  \"iptables\": true\n}\n")
	if err := os.WriteFile(paths.DockerDaemon, originalDaemon, 0o600); err != nil {
		t.Fatal(err)
	}
	system.Discover = func(context.Context) (discovery.Snapshot, error) {
		return discovery.Snapshot{
			OSID: "debian", OSVersion: "13", Architecture: "amd64",
			Uplink: "eth0", UplinkGateway: netip.MustParseAddr("192.168.1.1"),
			LANNetworks:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			ManagementTCP: []int{22}, DockerPresent: true, DockerClean: true,
			DockerNetworks: []config.DockerNetwork{{
				Name: "cosmos-app", Driver: "bridge",
				BridgeInterface: "br-" + id[:12], DynamicBridge: true,
				Subnets: []string{"172.23.0.0/16"}, Gateways: []string{"172.23.0.1"},
			}},
		}, nil
	}
	confirmed := 0
	system.ConfirmDockerRestart = func(summary Summary) error {
		confirmed++
		if summary.DockerMode != "enabled" || len(summary.DockerNetworks) != 1 {
			return errors.New("unexpected Docker summary")
		}
		return nil
	}
	plan, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.DockerMode != "enabled" || !plan.Summary.DockerRestart ||
		len(plan.Summary.DockerNetworks) != 1 {
		t.Fatalf("Docker handoff missing from plan: %#v", plan.Summary)
	}
	private, err := privatePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !private.Config.Integrations.DockerEnabled ||
		len(private.Config.DockerNetworks) != 1 ||
		len(private.Config.Interfaces) != 3 {
		t.Fatalf("managed Docker policy not generated: %#v", private.Config)
	}
	backup, err := system.Backup(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := system.Install(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mustRead(t, paths.Sysctl)), "net.ipv4.ip_forward = 1") {
		t.Fatal("managed sysctl omitted IPv4 forwarding")
	}
	daemon := string(mustRead(t, paths.DockerDaemon))
	for _, expected := range []string{
		`"data-root": "/srv/docker"`, `"iptables": false`,
		`"ip-forward": false`, `"ip-masq": false`,
	} {
		if !strings.Contains(daemon, expected) {
			t.Fatalf("managed daemon config omitted %q: %s", expected, daemon)
		}
	}
	if _, err := os.Stat(paths.DockerDropIn); err != nil {
		t.Fatalf("Docker socket drop-in missing: %v", err)
	}
	if err := system.ConfigureDocker(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if confirmed != 1 ||
		!strings.Contains(strings.Join(runner.commands, "\n"), "systemctl restart docker.service") {
		t.Fatalf("Docker restart was not explicitly confirmed: confirmed=%d commands=%v", confirmed, runner.commands)
	}
	system.ValidateHook = nil
	system.Connectivity = func(context.Context) error { return nil }
	system.DNSLookup = func(context.Context, string) ([]string, error) {
		return []string{"198.51.100.1"}, nil
	}
	if err := system.Validate(context.Background(), plan, 7); err != nil {
		t.Fatalf("managed Docker final validation failed: %v", err)
	}
	if err := system.Rollback(context.Background(), plan, Journal{
		Phase: PhaseDocker, BackupDir: backup,
	}); err != nil {
		t.Fatal(err)
	}
	if string(mustRead(t, paths.DockerDaemon)) != string(originalDaemon) {
		t.Fatal("rollback did not restore the exact Docker daemon config")
	}
	if _, err := os.Stat(paths.DockerDropIn); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback did not remove the new Docker access drop-in: %v", err)
	}
}

func TestPostRebootRollbackRestoresDockerBeforeHoldRelease(t *testing.T) {
	runner := &systemRunner{}
	system, plan, paths := configuredDockerPlan(t, runner, false)
	runner.outputs["systemctl is-active --quiet docker.service"] = []byte("active\n")
	cmdline := filepath.Join(t.TempDir(), "cmdline")
	writeFixture(t, cmdline, []byte("root=/dev/test ro\n"), 0o600)
	system.Paths.ProcCmdline = cmdline
	backup, err := system.Backup(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := readBackup(backup)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Boot = &bootBackup{
		Schema: bootBackupSchema, PreBootID: testBootID1,
		MountSHA256:            strings.Repeat("a", 64),
		KernelSHA256:           strings.Repeat("b", 64),
		InitialGeneratedSHA256: strings.Repeat("c", 64),
		ResumeEndpointIPv4:     []string{"198.51.100.8"},
		ResumeDockerPresent:    true,
		ResumeDockerClean:      true,
		ResumeDockerNetworks:   plan.PrivateData.(*prepared).Intent.DockerNetworks,
	}
	if err := writeBackupManifest(manifest); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), mustRead(t, paths.DockerDaemon)...)
	writeFixture(t, paths.DockerDaemon, []byte("{\"iptables\":true}\n"), 0o600)
	writeFixture(t, paths.DockerHoldService, []byte(dockerServiceHoldDropInData), 0o644)
	writeFixture(t, paths.DockerHoldSocket, []byte(dockerSocketHoldDropInData), 0o644)
	if err := os.MkdirAll(filepath.Dir(paths.DockerHoldRelease), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := system.Rollback(context.Background(), plan, Journal{
		Phase: PhaseInstall, BackupDir: backup,
	}); err != nil {
		t.Fatalf("post-reboot Docker rollback failed: %v", err)
	}
	if !bytes.Equal(mustRead(t, paths.DockerDaemon), original) {
		t.Fatal("rollback released Docker before restoring its exact daemon config")
	}
	joined := strings.Join(runner.commands, "\n")
	reload := strings.Index(joined, "systemctl daemon-reload")
	dockerRestore := strings.Index(joined, "systemctl restart docker.service")
	if reload < 0 || dockerRestore < 0 || reload > dockerRestore {
		t.Fatalf("Docker hold release/restore ordering is unsafe:\n%s", joined)
	}
	for _, path := range []string{paths.DockerHoldReady, paths.DockerHoldRelease} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rollback retained Docker hold runtime state %s: %v", path, err)
		}
	}
}

func TestConfigureDockerRequiresImmediateRestartApproval(t *testing.T) {
	id := strings.Repeat("b", 64)
	runner := &systemRunner{outputs: map[string][]byte{
		"sysctl -n net.ipv4.ip_forward": []byte("1\n"),
		"docker --host unix:///var/run/docker.sock network ls --no-trunc --format {{.ID}}\t{{.Name}}\t{{.Driver}}": []byte(
			id + "\tbridge\tbridge\n",
		),
		"docker --host unix:///var/run/docker.sock network inspect -- " + id: []byte(
			`[{"Id":"` + id + `","Name":"bridge","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{},"IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}]`,
		),
	}}
	system, paths := testSystem(t, runner)
	if err := os.MkdirAll(filepath.Dir(paths.DockerDaemon), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.DockerDaemon, []byte(`{"iptables":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	system.Discover = func(context.Context) (discovery.Snapshot, error) {
		return discovery.Snapshot{
			OSID: "debian", OSVersion: "13", Architecture: "amd64",
			Uplink: "eth0", UplinkGateway: netip.MustParseAddr("192.168.1.1"),
			LANNetworks:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			ManagementTCP: []int{22}, DockerPresent: true, DockerClean: true,
			DockerNetworks: []config.DockerNetwork{{
				Name: "bridge", Driver: "bridge", BridgeInterface: "docker0",
				DynamicBridge: true, Subnets: []string{"172.17.0.0/16"},
				Gateways: []string{"172.17.0.1"},
			}},
		}, nil
	}
	plan, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	if err := system.Install(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := system.ConfigureDocker(context.Background(), plan); err == nil ||
		err.Error() != "SETUP_DOCKER_RESTART_CONFIRMATION_REQUIRED" {
		t.Fatalf("unapproved Docker restart accepted: %v", err)
	}
	for _, command := range runner.commands {
		if command == "systemctl restart docker.service" {
			t.Fatal("Docker restarted without immediate approval")
		}
	}
	_ = id
}

func TestResumeDockerConfirmationPrecedesHoldRelease(t *testing.T) {
	runner := &systemRunner{}
	system, plan, paths := configuredDockerPlan(t, runner, false)
	plan.ResumeReady = true
	writeFixture(t, paths.DockerHoldService, []byte(dockerServiceHoldDropInData), 0o644)
	writeFixture(t, paths.DockerHoldSocket, []byte(dockerSocketHoldDropInData), 0o644)
	if err := os.MkdirAll(filepath.Dir(paths.DockerHoldRelease), 0o750); err != nil {
		t.Fatal(err)
	}
	confirmed := 0
	system.ConfirmDockerRestart = func(Summary) error {
		confirmed++
		if _, err := os.Lstat(paths.DockerHoldRelease); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Docker hold was released before immediate confirmation: %v", err)
		}
		return nil
	}
	if err := system.ConfigureDocker(context.Background(), plan); err != nil {
		t.Fatalf("confirmed resume restart failed: %v", err)
	}
	if confirmed != 1 {
		t.Fatalf("resume restart confirmations=%d want=1", confirmed)
	}
	if present, err := protectedFixedRuntimeState(paths.DockerHoldRelease, dockerHoldReleaseData); err != nil || !present {
		t.Fatalf("confirmed resume did not release Docker exactly: %t %v", present, err)
	}
	if err := system.cleanupDockerHold(context.Background()); err != nil {
		t.Fatal(err)
	}

	declinedRunner := &systemRunner{}
	declined, declinedPlan, declinedPaths := configuredDockerPlan(t, declinedRunner, false)
	declinedPlan.ResumeReady = true
	writeFixture(t, declinedPaths.DockerHoldService, []byte(dockerServiceHoldDropInData), 0o644)
	writeFixture(t, declinedPaths.DockerHoldSocket, []byte(dockerSocketHoldDropInData), 0o644)
	declined.ConfirmDockerRestart = func(Summary) error { return errors.New("declined") }
	if err := declined.ConfigureDocker(context.Background(), declinedPlan); err == nil || err.Error() != "declined" {
		t.Fatalf("resume confirmation refusal was not preserved: %v", err)
	}
	if _, err := os.Lstat(declinedPaths.DockerHoldRelease); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("declined resume released Docker: %v", err)
	}
}

func TestResumeInstallRequiresInactiveGeneratedDockerHold(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "inactive", true: "active"}[active], func(t *testing.T) {
			runner := &systemRunner{}
			system, plan, paths := configuredDockerPlan(t, runner, false)
			plan.ResumeReady = true
			private, err := privatePlan(plan)
			if err != nil {
				t.Fatal(err)
			}
			private.DockerData, private.DockerChanged, err = containers.ManagedDaemonConfig(paths.DockerDaemon)
			if err != nil || private.DockerChanged {
				t.Fatalf("invalid resume fixture: changed=%t err=%v", private.DockerChanged, err)
			}
			private.PolicyData = []byte("table inet nftfw_filter {}\n")
			writeFixture(t, paths.DockerHoldService, []byte(dockerServiceHoldDropInData), 0o644)
			writeFixture(t, paths.DockerHoldSocket, []byte(dockerSocketHoldDropInData), 0o644)
			if active {
				runner.outputs["systemctl is-active --quiet docker.service"] = []byte("active\n")
			}
			err = system.Install(context.Background(), plan)
			if active {
				if err == nil || err.Error() != "SETUP_DOCKER_STARTED_BEFORE_OWNERSHIP" {
					t.Fatalf("early Docker start was accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("inactive generated Docker hold was refused: %v", err)
			}
		})
	}
}

func TestManagedDisabledSysctlNeverReenablesLoopback(t *testing.T) {
	data := string(renderSysctl([]string{"eth0"}, true, false))
	if !strings.Contains(data, "net.ipv6.conf.lo.disable_ipv6 = 1\n") ||
		strings.Contains(data, "net.ipv6.conf.lo.disable_ipv6 = 0") {
		t.Fatalf("managed disabled policy attempted to re-enable loopback IPv6: %q", data)
	}
	bootData := string(renderSysctl([]string{"eth0"}, true, true))
	if bootData != "# Managed by NFT Firewall V2.\nnet.ipv4.ip_forward = 1\n" {
		t.Fatalf("kernel-disabled policy retained unavailable IPv6 sysctls: %q", bootData)
	}
	runner := &systemRunner{}
	system, plan, paths := configuredDockerPlan(t, runner, false)
	plan.ResumeReady = true
	writeFixture(t, paths.DockerHoldService, []byte(dockerServiceHoldDropInData), 0o644)
	writeFixture(t, paths.DockerHoldSocket, []byte(dockerSocketHoldDropInData), 0o644)
	private, err := privatePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	private.PolicyData = []byte("table inet nftfw_filter {}\n")
	private.DockerData, private.DockerChanged, err = containers.ManagedDaemonConfig(system.Paths.DockerDaemon)
	if err != nil {
		t.Fatal(err)
	}
	if err := system.Install(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if strings.Contains(joined, "sysctl -w net.ipv6.conf.lo.disable_ipv6=0") ||
		!strings.Contains(joined, "sysctl -w net.ipv6.conf.lo.disable_ipv6=1") {
		t.Fatalf("runtime setup loopback IPv6 ownership is unsafe:\n%s", joined)
	}

	bootRunner := &systemRunner{}
	bootSystem, bootPlan, bootPaths := configuredDockerPlan(t, bootRunner, false)
	bootPlan.ResumeReady = true
	bootPlan.Summary.BootPolicy = ManagedBootPolicy
	writeFixture(t, bootPaths.DockerHoldService, []byte(dockerServiceHoldDropInData), 0o644)
	writeFixture(t, bootPaths.DockerHoldSocket, []byte(dockerSocketHoldDropInData), 0o644)
	bootPrivate, err := privatePlan(bootPlan)
	if err != nil {
		t.Fatal(err)
	}
	bootPrivate.PolicyData = []byte("table inet nftfw_filter {}\n")
	bootPrivate.DockerData, bootPrivate.DockerChanged, err =
		containers.ManagedDaemonConfig(bootSystem.Paths.DockerDaemon)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootSystem.Install(context.Background(), bootPlan); err != nil {
		t.Fatal(err)
	}
	bootCommands := strings.Join(bootRunner.commands, "\n")
	if strings.Contains(bootCommands, "sysctl -w net.ipv6.") ||
		!strings.Contains(bootCommands, "sysctl -w net.ipv4.ip_forward=1") {
		t.Fatalf("kernel-disabled resume touched an unavailable sysctl:\n%s", bootCommands)
	}
}

func TestConfigureDockerFailureBranches(t *testing.T) {
	t.Run("daemon-config", func(t *testing.T) {
		runner := &systemRunner{}
		system, plan, paths := configuredDockerPlan(t, runner, false)
		if err := os.Remove(paths.DockerDaemon); err != nil {
			t.Fatal(err)
		}
		if err := system.ConfigureDocker(context.Background(), plan); err == nil {
			t.Fatal("missing managed Docker daemon configuration accepted")
		}
	})

	t.Run("socket-drop-in", func(t *testing.T) {
		runner := &systemRunner{}
		system, plan, paths := configuredDockerPlan(t, runner, false)
		if err := os.WriteFile(paths.DockerDropIn, []byte("[Service]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := system.ConfigureDocker(context.Background(), plan); err == nil {
			t.Fatal("modified Docker socket drop-in accepted")
		}
	})

	t.Run("confirmation", func(t *testing.T) {
		runner := &systemRunner{}
		system, plan, _ := configuredDockerPlan(t, runner, true)
		system.ConfirmDockerRestart = func(Summary) error { return errors.New("declined") }
		if err := system.ConfigureDocker(context.Background(), plan); err == nil || err.Error() != "declined" {
			t.Fatalf("Docker restart refusal was not preserved: %v", err)
		}
	})

	t.Run("restart", func(t *testing.T) {
		runner := &systemRunner{fail: "systemctl restart docker.service"}
		system, plan, _ := configuredDockerPlan(t, runner, true)
		system.ConfirmDockerRestart = func(Summary) error { return nil }
		if err := system.ConfigureDocker(context.Background(), plan); err == nil ||
			err.Error() != "SETUP_DOCKER_RESTART_FAILED" {
			t.Fatalf("Docker restart failure was not bounded: %v", err)
		}
	})

	t.Run("post-restart-ownership", func(t *testing.T) {
		base := &systemRunner{}
		system, plan, paths := configuredDockerPlan(t, base, true)
		system.ConfirmDockerRestart = func(Summary) error { return nil }
		system.Runner = systemRunnerFunc(func(
			ctx context.Context, input []byte, name string, args ...string,
		) ([]byte, error) {
			output, err := base.Run(ctx, input, name, args...)
			if name == "systemctl" && strings.Join(args, " ") == "restart docker.service" {
				if removeErr := os.Remove(paths.DockerDaemon); removeErr != nil {
					return nil, removeErr
				}
			}
			return output, err
		})
		if err := system.ConfigureDocker(context.Background(), plan); err == nil {
			t.Fatal("Docker daemon ownership loss after restart accepted")
		}
	})

	t.Run("inactive", func(t *testing.T) {
		runner := &systemRunner{}
		system, plan, _ := configuredDockerPlan(t, runner, false)
		if err := system.ConfigureDocker(context.Background(), plan); err == nil ||
			err.Error() != "SETUP_DOCKER_INACTIVE" {
			t.Fatalf("inactive Docker accepted: %v", err)
		}
	})

	t.Run("forwarding", func(t *testing.T) {
		runner := &systemRunner{}
		system, plan, _ := configuredDockerPlan(t, runner, false)
		runner.outputs["systemctl is-active --quiet docker.service"] = []byte("active\n")
		runner.outputs["sysctl -n net.ipv4.ip_forward"] = []byte("0\n")
		if err := system.ConfigureDocker(context.Background(), plan); err == nil ||
			err.Error() != "SETUP_DOCKER_IPV4_FORWARDING_FAILED" {
			t.Fatalf("disabled forwarding accepted: %v", err)
		}
	})

	t.Run("topology", func(t *testing.T) {
		runner := &systemRunner{}
		system, plan, _ := configuredDockerPlan(t, runner, false)
		runner.outputs["systemctl is-active --quiet docker.service"] = []byte("active\n")
		runner.outputs["docker --host unix:///var/run/docker.sock network ls --no-trunc --format {{.ID}}\t{{.Name}}\t{{.Driver}}"] = nil
		if err := system.ConfigureDocker(context.Background(), plan); err == nil ||
			err.Error() != "SETUP_DOCKER_TOPOLOGY_CHANGED" {
			t.Fatalf("missing Docker topology accepted: %v", err)
		}
	})

	t.Run("oversized-topology", func(t *testing.T) {
		runner := &systemRunner{}
		system, plan, _ := configuredDockerPlan(t, runner, false)
		runner.outputs["systemctl is-active --quiet docker.service"] = []byte("active\n")
		runner.outputs["docker --host unix:///var/run/docker.sock network ls --no-trunc --format {{.ID}}\t{{.Name}}\t{{.Driver}}"] =
			make([]byte, (1<<20)+1)
		if err := system.ConfigureDocker(context.Background(), plan); err == nil ||
			err.Error() != "SETUP_DOCKER_TOPOLOGY_CHANGED" {
			t.Fatalf("oversized Docker topology accepted: %v", err)
		}
	})
}

func TestManagedDockerValidationFailureBranches(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *System, *systemRunner, Paths)
		code   string
	}{
		{
			name: "daemon-config",
			mutate: func(t *testing.T, _ *System, _ *systemRunner, paths Paths) {
				if err := os.Remove(paths.DockerDaemon); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "socket-drop-in",
			mutate: func(t *testing.T, _ *System, _ *systemRunner, paths Paths) {
				if err := os.WriteFile(paths.DockerDropIn, []byte("[Service]\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "forwarding",
			mutate: func(_ *testing.T, _ *System, runner *systemRunner, _ Paths) {
				runner.outputs["sysctl -n net.ipv4.ip_forward"] = []byte("0\n")
			},
			code: "SETUP_DOCKER_IPV4_FORWARDING_FAILED",
		},
		{
			name: "topology",
			mutate: func(_ *testing.T, _ *System, runner *systemRunner, _ Paths) {
				runner.outputs["docker --host unix:///var/run/docker.sock network ls --no-trunc --format {{.ID}}\t{{.Name}}\t{{.Driver}}"] = nil
			},
			code: "SETUP_DOCKER_VALIDATION_FAILED",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &systemRunner{}
			system, plan, paths := configuredDockerPlan(t, runner, false)
			system.ValidateHook = nil
			system.Connectivity = func(context.Context) error { return nil }
			test.mutate(t, system, runner, paths)
			err := system.Validate(context.Background(), plan, 7)
			if err == nil {
				t.Fatal("invalid managed Docker state accepted")
			}
			if test.code != "" && err.Error() != test.code {
				t.Fatalf("error=%v want=%s", err, test.code)
			}
		})
	}
}

func TestDockerRouteValidationRequiresManagedVPN(t *testing.T) {
	runner := &systemRunner{routeDevice: "eth0"}
	system, _ := testSystem(t, runner)
	err := system.validateDockerRouting(context.Background(), []containers.Network{{
		Name: "media", BridgeInterface: "br-media",
		CIDR: "172.20.0.0/24", Gateway: "172.20.0.1",
	}}, "nftfw0")
	if err == nil || err.Error() != "SETUP_DOCKER_ROUTE_VALIDATION_FAILED" {
		t.Fatalf("physical Docker route accepted: %v", err)
	}
	source, err := dockerRouteSource("172.20.0.0/30", "172.20.0.1")
	if err != nil || source.String() != "172.20.0.2" {
		t.Fatalf("unexpected Docker route probe source: %s %v", source, err)
	}
	if _, err := dockerRouteSource("172.20.0.0/31", "172.20.0.1"); err == nil {
		t.Fatal("Docker route probe accepted a subnet without a separate probe address")
	}
	if err := system.validateDockerRouting(context.Background(), []containers.Network{{
		Name: "media", BridgeInterface: "br-media", CIDR: "invalid", Gateway: "172.20.0.1",
	}}, "nftfw0"); err == nil || err.Error() != "SETUP_DOCKER_ROUTE_SOURCE_INVALID" {
		t.Fatalf("invalid Docker route source was not bounded: %v", err)
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

func TestGenerationCommittedInitializesDefaultsAndPreservesInjections(t *testing.T) {
	defaults := DefaultPaths()
	fresh := &System{}
	fresh.Status = func(context.Context) (health.Snapshot, error) {
		if fresh.Paths.StatusSocket != defaults.StatusSocket {
			t.Fatalf("fresh status socket=%q want=%q", fresh.Paths.StatusSocket, defaults.StatusSocket)
		}
		if fresh.Runner == nil {
			t.Fatal("fresh commit-state inspector did not initialize its runner")
		}
		return health.Snapshot{
			ActiveGeneration: 7, Active: true, PolicyMatch: true, KillSwitchEnforced: true,
		}, nil
	}
	committed, err := fresh.GenerationCommitted(context.Background(), 7)
	if err != nil || !committed {
		t.Fatalf("fresh committed generation not recognized: committed=%t err=%v", committed, err)
	}

	const injectedStatus = "/private/test/status.sock"
	injectedRunner := &systemRunner{}
	injected := &System{Paths: Paths{StatusSocket: injectedStatus}, Runner: injectedRunner}
	injected.Status = func(context.Context) (health.Snapshot, error) {
		if injected.Paths.StatusSocket != injectedStatus {
			t.Fatalf("injected status socket was overwritten: %q", injected.Paths.StatusSocket)
		}
		if injected.Runner != injectedRunner {
			t.Fatal("injected runner was overwritten")
		}
		return health.Snapshot{
			ActiveGeneration: 7, PendingGeneration: 8, Active: true,
			PolicyMatch: true, KillSwitchEnforced: true,
		}, nil
	}
	committed, err = injected.GenerationCommitted(context.Background(), 7)
	if err != nil || committed {
		t.Fatalf("pending generation was accepted as committed: committed=%t err=%v", committed, err)
	}
}

func TestGenerationCommittedFailsClosedOnUnavailableOrMalformedStatus(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-status.sock")
	system := &System{Paths: Paths{StatusSocket: missing}}
	if committed, err := system.GenerationCommitted(context.Background(), 7); err == nil ||
		err.Error() != "SETUP_COMMIT_STATE_UNKNOWN" || committed {
		t.Fatalf("missing status evidence did not fail closed: committed=%t err=%v", committed, err)
	}
	if system.Paths.StatusSocket != missing {
		t.Fatalf("missing injected status path was overwritten: %q", system.Paths.StatusSocket)
	}

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(root, "status.sock")
	controlPath := filepath.Join(root, "control.sock")
	ctx, cancel := context.WithCancel(context.Background())
	server := &api.Server{
		Handler:    setupAPIHandler{status: "not-a-health-snapshot"},
		StatusPath: statusPath, ControlPath: controlPath,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	for deadline := time.Now().Add(time.Second); ; {
		select {
		case err := <-done:
			cancel()
			t.Fatalf("malformed-status server failed: %v", err)
		default:
		}
		if _, err := os.Stat(statusPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("malformed-status socket did not start")
		}
		time.Sleep(time.Millisecond)
	}
	malformed := &System{Paths: Paths{StatusSocket: statusPath}}
	committed, err := malformed.GenerationCommitted(context.Background(), 7)
	if err == nil || err.Error() != "SETUP_COMMIT_STATE_UNKNOWN" || committed {
		cancel()
		<-done
		t.Fatalf("malformed status evidence did not fail closed: committed=%t err=%v", committed, err)
	}
	cancel()
	<-done
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

func TestPrepareRejectsUnsafeManagedDockerOwnershipTarget(t *testing.T) {
	runner := &systemRunner{}
	system, paths := testSystem(t, runner)
	id := strings.Repeat("f", 64)
	system.Discover = func(context.Context) (discovery.Snapshot, error) {
		return discovery.Snapshot{
			OSID: "debian", OSVersion: "13", Architecture: "amd64",
			Uplink: "eth0", UplinkGateway: netip.MustParseAddr("192.168.1.1"),
			LANNetworks:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			ManagementTCP: []int{22}, DockerPresent: true, DockerClean: true,
			DockerNetworks: []config.DockerNetwork{{
				Name: "media", Driver: "bridge", BridgeInterface: "br-" + id[:12],
				DynamicBridge: true, Subnets: []string{"172.20.0.0/16"},
				Gateways: []string{"172.20.0.1"},
			}},
		}, nil
	}
	if err := os.MkdirAll(filepath.Dir(paths.DockerDaemon), 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(filepath.Dir(paths.DockerDaemon), "operator.json")
	if err := os.WriteFile(source, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, paths.DockerDaemon); err != nil {
		t.Fatal(err)
	}
	if _, err := system.Prepare(context.Background(), "/provider.conf"); err == nil {
		t.Fatal("symlinked Docker ownership target accepted")
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
			name: "handoff-initramfs", fail: "rebuild-enabled",
			call: func(system *System, plan Plan) error {
				return system.PublishFinalDependencies(context.Background(), plan)
			},
			errorCode: "SETUP_INITRAMFS_GUARD_FAILED",
		},
		{
			name: "handoff-start", fail: "systemctl start nftfw-early.service",
			call: func(system *System, plan Plan) error {
				return system.PublishFinalDependencies(context.Background(), plan)
			},
			errorCode: "SETUP_EARLY_ENFORCEMENT_FAILED",
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

func (h setupAPIHandler) Control(_ context.Context, request api.Request) (any, error) {
	if request.Op == "status" {
		return h.status, nil
	}
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
	for _, phase := range []Phase{
		PhaseTunnel, PhaseValidate, PhaseCommit, PhaseHandoff, PhaseBoot, PhaseFinalize,
		PhaseComplete, PhaseRollback, PhaseFailed,
	} {
		if !phaseMayHaveTunnel(phase) {
			t.Fatalf("phase %s should permit tunnel cleanup", phase)
		}
	}
	for _, phase := range []Phase{
		PhaseInspect, PhaseBackup, PhaseGuard, PhaseInstall, PhaseDocker, PhaseRuntime, PhaseApply,
	} {
		if phaseMayHaveTunnel(phase) {
			t.Fatalf("phase %s unexpectedly permits tunnel cleanup", phase)
		}
	}
}

func TestManagedRollbackUsesCanonicalRoutingIdentityAndOriginPhase(t *testing.T) {
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
	runner.commands = nil
	if err := system.Rollback(context.Background(), plan, Journal{
		Phase: PhaseValidate, Status: "rolling_back", Generation: 7,
		BackupDir: backup, Summary: plan.Summary,
	}); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(runner.commands, "\n")
	for _, want := range []string{
		"ip -4 rule del pref 32765 not fwmark 0xca6c table 51820",
		"ip -4 rule del pref 32764 table main suppress_prefixlength 0",
		"ip -4 route flush table 51820",
		"ip link delete dev nftfw0",
	} {
		if !strings.Contains(commands, want) {
			t.Fatalf("managed rollback omitted canonical routing command %q:\n%s", want, commands)
		}
	}
}

func TestManagedRollbackRouteRejectsNoncanonicalRecoveryIdentity(t *testing.T) {
	valid := Summary{
		Schema: "nftfw.setup-plan.v1", VPNInterface: intent.VPNInterface,
		ResolverMode: string(routing.ResolverNone),
	}
	route, err := managedRollbackRoute(valid)
	if err != nil || route.Interface != intent.VPNInterface || route.Fwmark != intent.VPNFwmark ||
		route.Table != routing.DefaultTable || route.Resolver != routing.ResolverNone {
		t.Fatalf("canonical rollback route invalid: %#v %v", route, err)
	}
	for _, mutate := range []func(*Summary){
		func(summary *Summary) { summary.VPNInterface = "wg-attacker" },
		func(summary *Summary) { summary.VPNInterface = "" },
		func(summary *Summary) { summary.ResolverMode = "forged" },
	} {
		summary := valid
		mutate(&summary)
		if _, err := managedRollbackRoute(summary); err == nil ||
			err.Error() != "SETUP_ROLLBACK_PLAN_INVALID" {
			t.Fatalf("noncanonical rollback identity accepted: %#v err=%v", summary, err)
		}
	}
}

func TestRollbackReportsEachIncompleteRecoveryClass(t *testing.T) {
	t.Run("missing-backup", func(t *testing.T) {
		runner := &systemRunner{}
		system, _ := testSystem(t, runner)
		err := system.Rollback(context.Background(), Plan{}, Journal{
			Phase: PhaseGuard, Summary: Summary{Schema: "nftfw.setup-plan.v1"},
		})
		if err == nil || !strings.Contains(err.Error(), "BACKUP") {
			t.Fatalf("missing rollback backup not reported: %v", err)
		}
		if len(runner.commands) != 0 {
			t.Fatalf("missing backup boundary changed system state: %v", runner.commands)
		}
	})

	t.Run("invalid-plan", func(t *testing.T) {
		runner := &systemRunner{}
		system, _ := testSystem(t, runner)
		err := system.Rollback(context.Background(), Plan{}, Journal{
			Phase: PhaseGuard, BackupDir: t.TempDir(),
		})
		if err == nil || !strings.Contains(err.Error(), "PLAN") {
			t.Fatalf("invalid rollback plan not reported: %v", err)
		}
		if len(runner.commands) != 0 {
			t.Fatalf("invalid prepared-plan boundary changed system state: %v", runner.commands)
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
			Summary: Summary{
				Schema: "nftfw.setup-plan.v1", VPNInterface: intent.VPNInterface,
				ResolverMode: string(routing.ResolverNone), NetworkProducers: testNetworkProducers(),
			},
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
