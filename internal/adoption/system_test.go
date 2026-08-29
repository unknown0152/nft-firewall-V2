package adoption

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/intent"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

type readRunner func(context.Context, string, ...string) ([]byte, error)

func (r readRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r(ctx, name, args...)
}

func TestExposureSummaryUsesVPNIngressAndTrustedServices(t *testing.T) {
	value := config.Defaults()
	value.Interfaces = []config.Interface{
		{Name: "eth0", Role: "uplink", Zone: "wan", ProvenanceID: 1},
		{Name: "wg0", Role: "vpn", Zone: "vpn", ProvenanceID: 2},
		{Name: "br0", Role: "container", Zone: "containers", ProvenanceID: 3},
	}
	value.Zones = []config.Zone{
		{Name: "wan", Interfaces: []string{"eth0"}},
		{Name: "vpn", Interfaces: []string{"wg0"}},
		{Name: "containers", Interfaces: []string{"br0"}},
	}
	value.Services = []config.Service{
		{Name: "ssh", Protocol: "tcp", Ports: []int{2222}},
		{Name: "web", Protocol: "tcp", Ports: []int{443, 80}},
		{Name: "dns", Protocol: "udp", Ports: []int{53}},
	}
	value.Runtime.TrustedServices = []string{"ssh"}
	value.Policies = []config.Policy{
		{Name: "vpn-web", From: "vpn", To: "host", Service: "web", Action: "allow"},
		{Name: "vpn-dns", From: "vpn", To: "host", Service: "dns", Action: "allow"},
		{Name: "deny", From: "vpn", To: "host", Service: "ssh", Action: "deny"},
	}
	value.NAT = []config.NATRule{
		{Name: "vpn-nat", Source: "any", ExternalInterface: "wg0", Protocol: "tcp", ExternalPort: 8443, Destination: "172.19.0.2", DestinationPort: 443},
		{Name: "lan-nat", Source: "any", ExternalInterface: "eth0", Protocol: "tcp", ExternalPort: 8080, Destination: "172.19.0.2", DestinationPort: 80},
	}
	management, tcp, udp, valid := exposureSummary(value)
	if !reflect.DeepEqual(management, []int{2222}) ||
		!reflect.DeepEqual(tcp, []int{80, 443, 8443}) ||
		!reflect.DeepEqual(udp, []int{53}) || valid {
		t.Fatalf("unexpected summaries: %v %v %v valid=%t", management, tcp, udp, valid)
	}
	value.NAT = value.NAT[:1]
	_, _, _, valid = exposureSummary(value)
	if !valid {
		t.Fatal("VPN-only exposure was refused")
	}
}

func TestDockerCompatibilityPreservesSubnetGatewayPairs(t *testing.T) {
	configured := []config.DockerNetwork{{
		Name: "media", Driver: "bridge", BridgeInterface: "br-media",
		Subnets:  []string{"172.20.0.0/16", "172.19.0.0/16"},
		Gateways: []string{"172.20.0.1", "172.19.0.1"},
	}}
	observed := []config.DockerNetwork{{
		Name: "media", Driver: "bridge", BridgeInterface: "br-media", DynamicBridge: true,
		Subnets:  []string{"172.19.0.0/16", "172.20.0.0/16"},
		Gateways: []string{"172.19.0.1", "172.20.0.1"},
	}}
	if !dockerCompatibleSubset(configured, observed) {
		t.Fatal("same canonical Docker tuple rejected")
	}
	observed[0].Gateways[0] = "172.19.0.2"
	if dockerCompatibleSubset(configured, observed) {
		t.Fatal("changed Docker gateway accepted")
	}
	observed[0].Gateways[0] = "172.19.0.1"
	observed = append(observed, config.DockerNetwork{
		Name: "bridge", Driver: "bridge", BridgeInterface: "docker0",
		DynamicBridge: true, Subnets: []string{"172.17.0.0/16"},
		Gateways: []string{"172.17.0.1"},
	})
	if !dockerCompatibleSubset(configured, observed) {
		t.Fatal("eligible managed-mode addition was refused")
	}
}

func TestAdvancedDockerOwnershipClassification(t *testing.T) {
	configured := []config.DockerNetwork(nil)
	observed := []config.DockerNetwork{{
		Name: "media", Driver: "bridge", BridgeInterface: "br-media",
		DynamicBridge: true, Subnets: []string{"172.19.0.0/16"},
		Gateways: []string{"172.19.0.1"},
	}}
	if !dockerCompatibleSubset(configured, observed) || len(observed) == 0 {
		t.Fatal("strictly observed advanced-mode Docker topology was not adoptable")
	}
	observed[0].Driver = "overlay"
	if dockerCompatibleSubset([]config.DockerNetwork{{
		Name: "media", Driver: "bridge", BridgeInterface: "br-media",
		Subnets: []string{"172.19.0.0/16"}, Gateways: []string{"172.19.0.1"},
	}}, observed) {
		t.Fatal("unsupported Docker topology was accepted")
	}
}

func TestReadOnlyCommandClassifiers(t *testing.T) {
	var commands []string
	runner := readRunner(func(_ context.Context, name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		switch {
		case name == "dpkg-query":
			return []byte("2.1.0-1\n"), nil
		case name == "systemctl" && strings.Contains(command, "ActiveState"):
			return []byte("active\n"), nil
		case name == "systemctl" && strings.Contains(command, "UnitFileState"):
			return []byte("enabled\n"), nil
		case command == "ip -j -4 rule show":
			return []byte(`[{"priority":32766}]`), nil
		case command == "ip -j -4 route show table all":
			return []byte(`[{"dst":"default"}]`), nil
		case command == "sysctl -n net.ipv4.ip_forward":
			return []byte("1\n"), nil
		default:
			return nil, errors.New("unexpected")
		}
	})
	inspector := SystemInspector{Runner: runner}
	if version, err := inspector.installedVersion(context.Background()); err != nil || version != "2.1.0-1" {
		t.Fatalf("version=%q err=%v", version, err)
	}
	units, err := inspector.unitStates(context.Background())
	if err != nil || len(units) != len(adoptionUnits) || !units[0].Active || !units[0].Enabled {
		t.Fatalf("units=%#v err=%v", units, err)
	}
	if valid, digest := inspector.routingState(context.Background()); !valid || digest == "" {
		t.Fatal("valid routing snapshot rejected")
	}
	if enabled, valid := inspector.ipv4Forwarding(context.Background()); !enabled || !valid {
		t.Fatal("valid forwarding snapshot rejected")
	}
	for _, command := range commands {
		if mutatingCommand(command) {
			t.Fatalf("mutating command invoked: %s", command)
		}
	}
}

func TestUnitStateActiveAndEnabledPermutations(t *testing.T) {
	indexes := map[string]int{}
	for index, unit := range adoptionUnits {
		indexes[unit] = index
	}
	runner := readRunner(func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "systemctl" || len(args) != 4 {
			return nil, errors.New("unexpected command")
		}
		index, ok := indexes[args[3]]
		if !ok {
			return nil, errors.New("unexpected unit")
		}
		if args[1] == "--property=ActiveState" {
			if index%2 == 0 {
				return []byte("active\n"), nil
			}
			return []byte("inactive\n"), nil
		}
		if args[1] == "--property=UnitFileState" {
			if index%3 == 0 {
				return []byte("enabled\n"), nil
			}
			return []byte("disabled\n"), nil
		}
		return nil, errors.New("unexpected property")
	})
	units, err := (SystemInspector{Runner: runner}).unitStates(context.Background())
	if err != nil || len(units) != len(adoptionUnits) {
		t.Fatalf("unit permutations failed: %#v %v", units, err)
	}
	for index, unit := range units {
		if unit.Active != (index%2 == 0) || unit.Enabled != (index%3 == 0) {
			t.Fatalf("unit permutation changed at %d: %#v", index, unit)
		}
	}
}

func TestReadOnlyCommandFailuresAndStateParsers(t *testing.T) {
	failed := SystemInspector{Runner: readRunner(func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("secret endpoint")
	})}
	if _, err := failed.installedVersion(context.Background()); ErrorCode(err) != "ADOPTION_PACKAGE_VERSION_UNSUPPORTED" {
		t.Fatalf("unexpected version error: %v", err)
	}
	if _, err := failed.unitStates(context.Background()); ErrorCode(err) != "ADOPTION_UNIT_STATE_UNREADABLE" {
		t.Fatalf("unexpected unit error: %v", err)
	}
	if valid, _ := failed.routingState(context.Background()); valid {
		t.Fatal("failed routing inspection accepted")
	}
	if _, valid := failed.ipv4Forwarding(context.Background()); valid {
		t.Fatal("failed sysctl inspection accepted")
	}
	for _, value := range []string{"active", "inactive", "failed", "maintenance"} {
		if !allowedActiveState(value) {
			t.Fatalf("active state rejected: %s", value)
		}
	}
	if allowedActiveState("secret") || allowedUnitFileState("secret") {
		t.Fatal("unknown systemd state accepted")
	}
	if validJSONArray([]byte(`{}`), 2) || validJSONArray([]byte(`invalid`), 2) ||
		!validJSONArray([]byte(`[]`), 2) {
		t.Fatal("JSON array boundary failed")
	}
}

func TestPathAndRoutingAdapterSafety(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "intent.toml")
	if err := os.WriteFile(regular, []byte("managed=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if exists, err := pathExists(regular); err != nil || !exists {
		t.Fatalf("regular path result=%t err=%v", exists, err)
	}
	missing := filepath.Join(root, "missing")
	if exists, err := pathExists(missing); err != nil || exists {
		t.Fatalf("missing path result=%t err=%v", exists, err)
	}
	symlink := filepath.Join(root, "link")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := pathExists(symlink); err == nil {
		t.Fatal("symlinked intent accepted")
	}
	adapter := routingReadAdapter{Runner: readRunner(func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ok"), nil
	})}
	if _, err := adapter.Run(context.Background(), []byte("mutation"), "tool"); err == nil {
		t.Fatal("read-only adapter accepted stdin")
	}
	if output, err := adapter.Run(context.Background(), nil, "tool"); err != nil || string(output) != "ok" {
		t.Fatalf("read-only adapter rejected a read: %q %v", output, err)
	}
	nftRunner := readRunner(func(_ context.Context, name string, args ...string) ([]byte, error) {
		if output, ok := fixtureNFTTable(name, args...); ok {
			return output, nil
		}
		return nil, errors.New("unexpected nft command")
	})
	if _, err := readOwnedNFTTable(context.Background(), nftRunner, nft.Table{Family: "inet", Name: "foreign"}); err == nil {
		t.Fatal("read-only nft reader accepted foreign table")
	}
	if output, err := readOwnedNFTTable(context.Background(), nftRunner, nft.Table{Family: "inet", Name: "nftfw_filter"}); err != nil || len(output) == 0 {
		t.Fatalf("read-only nft adapter rejected owned table: %q %v", output, err)
	}
	if fingerprint, err := livePolicyFingerprint(context.Background(), nftRunner); err != nil || fingerprint == "" {
		t.Fatalf("read-only nft fingerprint failed: %q %v", fingerprint, err)
	}
	if _, err := pathExists("bad\x00path"); err == nil {
		t.Fatal("invalid intent path accepted")
	}
}

func TestSystemInspectorDetectsObservationRace(t *testing.T) {
	// The full inspector is covered in disposable E-R2 with exact 2.0.3 state.
	// This source gate proves the comparison primitive includes private digests.
	first := inspected{Observation: validObservation(), Fingerprint: digestStrings("one")}
	second := inspected{Observation: validObservation(), Fingerprint: digestStrings("two")}
	if first.Fingerprint == second.Fingerprint {
		t.Fatal("different protected observations had the same test fingerprint")
	}
}

func TestSystemInspectorClassifiesCleanAndManagedBeforeProtectedInspection(t *testing.T) {
	root := t.TempDir()
	paths := Paths{
		Root: root, Config: filepath.Join(root, "etc/nftfw/nftfw.toml"),
		Intent:       filepath.Join(root, "etc/nftfw/intent.toml"),
		DockerDaemon: filepath.Join(root, "etc/docker/daemon.json"),
	}
	inspector := SystemInspector{Paths: paths, Runner: readRunner(func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("early classification invoked a system command")
		return nil, nil
	})}
	observation, err := inspector.Inspect(context.Background(), filepath.Join(root, "missing-provider.conf"))
	if err != nil || !observation.Stable || observation.ExistingState || observation.Managed {
		t.Fatalf("clean classification failed: %#v %v", observation, err)
	}
	if _, err := (Planner{Inspector: inspector}).Plan(context.Background(), filepath.Join(root, "missing-provider.conf")); ErrorCode(err) != "ADOPTION_CLEAN_HOST_USE_SETUP" {
		t.Fatalf("clean planner code changed: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(paths.Intent), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Intent, []byte("managed=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	observation, err = inspector.Inspect(context.Background(), filepath.Join(root, "missing-provider.conf"))
	if err != nil || !observation.Stable || !observation.Managed {
		t.Fatalf("managed classification failed: %#v %v", observation, err)
	}
	if _, err := (Planner{Inspector: inspector}).Plan(context.Background(), filepath.Join(root, "missing-provider.conf")); ErrorCode(err) != "ADOPTION_ALREADY_MANAGED" {
		t.Fatalf("managed planner code changed: %v", err)
	}
}

func TestSystemHelperBoundaryCoverage(t *testing.T) {
	var empty SystemInspector
	empty.defaults()
	defaults := DefaultPaths()
	if empty.Paths != defaults || empty.Runner == nil {
		t.Fatalf("defaults not applied: %#v", empty.Paths)
	}
	customRunner := readRunner(func(context.Context, string, ...string) ([]byte, error) {
		return nil, nil
	})
	custom := SystemInspector{Paths: Paths{
		Root: "/root", Config: "/config", Intent: "/intent", DockerDaemon: "/docker",
	}, Runner: customRunner}
	custom.defaults()
	if custom.Paths.Root != "/root" || custom.Paths.Config != "/config" ||
		custom.Paths.Intent != "/intent" || custom.Paths.DockerDaemon != "/docker" {
		t.Fatal("custom paths were replaced by defaults")
	}
	if configUplink(config.Config{}) != "" {
		t.Fatal("missing uplink was invented")
	}
	if configVPNValid(config.Config{}) {
		t.Fatal("missing VPN interface was accepted")
	}
	vpnConfig := config.Config{WireGuard: config.WireGuardConfig{Interface: "wg0"}, Interfaces: []config.Interface{{Name: "wg0", Role: "vpn"}}}
	if !configVPNValid(vpnConfig) {
		t.Fatal("single matching VPN interface was refused")
	}
	vpnConfig.Interfaces = append(vpnConfig.Interfaces, config.Interface{Name: "wg1", Role: "vpn"})
	if configVPNValid(vpnConfig) {
		t.Fatal("multiple VPN interfaces were accepted")
	}
	if validJSONArray([]byte(`[{},{}]`), 1) {
		t.Fatal("oversized JSON array accepted")
	}
	if digestValue(make(chan int)) != "invalid" {
		t.Fatal("unencodable digest input accepted")
	}
	required := []provenance.Assignment{{Name: "eth0", ID: 1}}
	if exactActiveProvenance([]provenance.Assignment{{Name: "eth1", ID: 1}}, required) ||
		exactActiveProvenance([]provenance.Assignment{{Name: "eth0", ID: 1}, {Name: "old", ID: 2}}, required) ||
		!exactActiveProvenance([]provenance.Assignment{{Name: "eth0", ID: 1}, {Name: "old", ID: 2, Retired: true}}, required) {
		t.Fatal("exact active provenance boundary failed")
	}
	badActive := SystemInspector{Runner: readRunner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "ActiveState") {
			return []byte("unknown\n"), nil
		}
		return []byte("enabled\n"), nil
	})}
	if _, err := badActive.unitStates(context.Background()); ErrorCode(err) != "ADOPTION_UNIT_STATE_UNREADABLE" {
		t.Fatalf("invalid active state accepted: %v", err)
	}
	badEnabled := SystemInspector{Runner: readRunner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "ActiveState") {
			return []byte("inactive\n"), nil
		}
		return []byte("unknown\n"), nil
	})}
	if _, err := badEnabled.unitStates(context.Background()); ErrorCode(err) != "ADOPTION_UNIT_STATE_UNREADABLE" {
		t.Fatalf("invalid enabled state accepted: %v", err)
	}
}

func TestSystemInspectorExactSchema6FixtureIsNonMutating(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	stateRoot := filepath.Join(root, "var/lib/nftfw")
	database := filepath.Join(stateRoot, "generation-state/state.db")
	ledgerPath := filepath.Join(stateRoot, "provenance-ledger.db")
	configPath := filepath.Join(root, "etc/nftfw/nftfw.toml")
	intentPath := filepath.Join(root, "etc/nftfw/intent.toml")
	profilePath := filepath.Join(root, "provider.conf")
	if err := os.MkdirAll(filepath.Join(root, "etc/nftfw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=debian\nVERSION_ID=13\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := "[Interface]\nPrivateKey = " + testKey(1) + "\nAddress = 10.8.0.2/32\n" +
		"[Peer]\nPublicKey = " + testKey(2) + "\nAllowedIPs = 0.0.0.0/0\n" +
		"Endpoint = vpn.example.test:51820\n"
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	managedIntent := intent.Intent{
		Schema: intent.Schema, Managed: true, Uplink: "eth0", VPNInterface: intent.VPNInterface,
		LANNetworks: []string{"192.168.1.0/24"}, ManagementTCP: []int{22},
		VPNAddresses: []string{"10.8.0.2/32"}, EndpointHost: "vpn.example.test",
		EndpointPort: 51820, BootstrapIPv4: []string{"198.51.100.8/32"},
		ResolverMode: "none", DisableIPv6: true, PublicTCP: []int{443},
	}
	configured, err := managedIntent.Config()
	if err != nil {
		t.Fatal(err)
	}
	configured.State.Directory = stateRoot
	configured.State.Database = database
	configured.State.ProvenanceLedger = ledgerPath
	configData, err := intent.RenderConfig(configured)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := state.Open(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := provenance.Open(ctx, ledgerPath)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	assignments := requiredProvenance(configured)
	if err := ledger.Reserve(ctx, assignments); err != nil {
		t.Fatal(err)
	}
	script := "table inet nftfw_filter {}\n"
	digest := sha256.Sum256([]byte(script))
	checksum := hex.EncodeToString(digest[:])
	if err := store.SaveGenerationWithMetadata(ctx, 1, checksum, script, nil, nil, state.GenerationMetadata{
		BootID: "adoption-test-boot", Provenance: assignments,
	}); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := livePolicyFingerprint(ctx, readRunner(func(_ context.Context, name string, args ...string) ([]byte, error) {
		if output, ok := fixtureNFTTable(name, args...); ok {
			return output, nil
		}
		return nil, errors.New("unexpected nft fingerprint command")
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetObservedHash(ctx, 1, fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	var commands []string
	runner := readRunner(func(_ context.Context, name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		if output, ok := fixtureNFTTable(name, args...); ok {
			return output, nil
		}
		switch command {
		case "ip -j -4 route show default":
			return []byte(`[{"dev":"eth0","gateway":"192.168.1.1"}]`), nil
		case "ip -j -4 address show dev eth0":
			return []byte(`[{"addr_info":[{"family":"inet","local":"192.168.1.10","prefixlen":24,"scope":"global"}]}]`), nil
		case "ip -j link show":
			return []byte(`[{"ifname":"lo"},{"ifname":"eth0"},{"ifname":"nftfw0"}]`), nil
		case "ss -H -lntp":
			return []byte("LISTEN 0 128 192.168.1.10:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"), nil
		case "ip -j -6 route show default":
			return []byte(`[]`), nil
		case "nft -j list ruleset":
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}},{"table":{"family":"ip","name":"nftfw_nat"}},{"table":{"family":"ip6","name":"nftfw_filter6"}}]}`), nil
		case "docker --version":
			return nil, errors.New("not installed")
		case "dpkg-query -W -f=${Version} nft-firewall-v2":
			return []byte("2.0.3\n"), nil
		case "ip -j -4 rule show":
			return []byte(`[{"priority":32766}]`), nil
		case "ip -j -4 route show table all":
			return []byte(`[{"dst":"default","dev":"eth0"}]`), nil
		case "sysctl -n net.ipv4.ip_forward":
			return []byte("0\n"), nil
		}
		if name == "systemctl" && len(args) >= 3 && args[0] == "is-active" {
			return nil, errors.New("inactive")
		}
		if name == "systemctl" && len(args) == 4 && args[0] == "show" && args[1] == "--property=ActiveState" {
			return []byte("active\n"), nil
		}
		if name == "systemctl" && len(args) == 4 && args[0] == "show" && args[1] == "--property=UnitFileState" {
			return []byte("enabled\n"), nil
		}
		return nil, fmt.Errorf("unexpected read command %s", command)
	})
	before := treeSignature(t, root)
	planner := Planner{Inspector: SystemInspector{
		Paths: Paths{Root: root, Config: configPath, Intent: intentPath,
			DockerDaemon: filepath.Join(root, "etc/docker/daemon.json")},
		Runner: runner,
	}}
	plan, err := planner.Plan(ctx, profilePath)
	if err != nil {
		t.Fatal(err)
	}
	after := treeSignature(t, root)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("read-only inspector changed fixture\nbefore=%v\nafter=%v", before, after)
	}
	if plan.State.Schema != 6 || plan.State.Generation != 1 || plan.State.PolicyChecksum != checksum ||
		plan.CurrentMode != "advanced" || plan.LiveStateChanged || plan.RollbackRequired {
		t.Fatalf("unexpected integrated plan: %#v", plan)
	}
	for _, command := range commands {
		if mutatingCommand(command) {
			t.Fatalf("integrated inspector invoked mutation: %s", command)
		}
	}
}

func fixtureNFTTable(name string, args ...string) ([]byte, bool) {
	if name != "nft" || len(args) != 5 || args[0] != "-j" || args[1] != "list" || args[2] != "table" {
		return nil, false
	}
	valid := false
	for _, table := range nft.OwnedTables {
		if args[3] == table.Family && args[4] == table.Name {
			valid = true
			break
		}
	}
	if !valid {
		return nil, false
	}
	return []byte(fmt.Sprintf(`{"nftables":[{"table":{"family":%q,"name":%q}}]}`, args[3], args[4])), true
}

func mutatingCommand(command string) bool {
	fields := strings.Fields(command)
	if len(fields) < 2 {
		return false
	}
	mutating := map[string]bool{
		"start": true, "stop": true, "restart": true, "reload": true,
		"enable": true, "disable": true, "mask": true, "unmask": true,
		"add": true, "del": true, "delete": true, "replace": true,
		"set": true, "apply": true, "create": true, "remove": true,
		"up": true, "down": true, "flush": true,
	}
	for _, field := range fields[1:] {
		if mutating[field] || field == "-w" || field == "--file" {
			return true
		}
	}
	return false
}

func testKey(fill byte) string {
	value := make([]byte, 32)
	for index := range value {
		value[index] = fill
	}
	return base64.StdEncoding.EncodeToString(value)
}

func treeSignature(t *testing.T, root string) []string {
	t.Helper()
	var result []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		line := relative + "|" + info.Mode().String()
		if entry.Type().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(data)
			line += "|" + hex.EncodeToString(digest[:])
		}
		result = append(result, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(result)
	return result
}
