package discovery

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
)

type fakeRunner struct {
	outputs map[string][]byte
	errors  map[string]error
}

type changingWorkloadRunner struct {
	base  *fakeRunner
	calls map[string]int
}

func (r *changingWorkloadRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	if key == "docker --host unix:///var/run/docker.sock ps -q --no-trunc" ||
		key == "docker --host unix:///var/run/docker.sock ps -aq --no-trunc" {
		call := r.calls[key]
		r.calls[key] = call + 1
		if call > 0 {
			return []byte(strings.Repeat("e", 64) + "\n"), nil
		}
		return nil, nil
	}
	return r.base.Run(ctx, name, args...)
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	if err := r.errors[key]; err != nil {
		return nil, err
	}
	return append([]byte(nil), r.outputs[key]...), nil
}

func cleanDiscoveryRunner() *fakeRunner {
	return &fakeRunner{
		outputs: map[string][]byte{
			"ip -j -4 route show default": []byte(
				`[{"gateway":"192.168.50.1","dev":"enp1s0"}]`,
			),
			"ip -j -4 address show dev enp1s0": []byte(
				`[{"addr_info":[{"family":"inet","local":"192.168.50.221","prefixlen":24}]}]`,
			),
			"ip -j link show": []byte(
				`[{"ifname":"lo"},{"ifname":"enp1s0"},{"ifname":"wlan0"}]`,
			),
			"ss -H -lntp": []byte(
				`LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`,
			),
			"ip -j -6 route show default": []byte(`[]`),
			"nft -j list ruleset":         []byte(`{"nftables":[]}`),
		},
		errors: map[string]error{
			"systemctl is-active --quiet firewalld.service":            errors.New("inactive"),
			"systemctl is-active --quiet ufw.service":                  errors.New("inactive"),
			"systemctl is-active --quiet nftables.service":             errors.New("inactive"),
			"systemctl is-active --quiet netfilter-persistent.service": errors.New("inactive"),
			"docker --version": errors.New("not installed"),
			"docker --host unix:///var/run/docker.sock version --format {{.Server.Version}}": errors.New("not installed"),
		},
	}
}

func addCleanDocker(runner *fakeRunner) {
	delete(runner.errors, "docker --version")
	runner.outputs["docker --version"] = []byte("Docker version 29.0.0\n")
	delete(runner.errors, "docker --host unix:///var/run/docker.sock version --format {{.Server.Version}}")
	runner.outputs["docker --host unix:///var/run/docker.sock version --format {{.Server.Version}}"] = []byte("29.0.0\n")
	runner.outputs["docker --host unix:///var/run/docker.sock ps -q --no-trunc"] = nil
	runner.outputs["docker --host unix:///var/run/docker.sock ps -aq --no-trunc"] = nil
	runner.outputs["docker --host unix:///var/run/docker.sock network ls --filter type=custom -q"] = nil
	id := strings.Repeat("a", 64)
	runner.outputs["docker --host unix:///var/run/docker.sock network ls --no-trunc --format {{.ID}}\t{{.Name}}\t{{.Driver}}"] =
		[]byte(id + "\tbridge\tbridge\n" +
			strings.Repeat("b", 64) + "\thost\thost\n" +
			strings.Repeat("c", 64) + "\tnone\tnull\n")
	runner.outputs["docker --host unix:///var/run/docker.sock network inspect -- "+id] =
		[]byte(`[{"Id":"` + id + `","Name":"bridge","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{},"IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}]`)
	runner.outputs["ip -j link show dev docker0"] = []byte(`[{"ifname":"docker0"}]`)
}

func discoveryRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "etc", "os-release")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ID=debian\nVERSION_ID=\"13\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestInspectorDiscoverCleanHost(t *testing.T) {
	runner := cleanDiscoveryRunner()
	snapshot, err := (Inspector{Runner: runner, Root: discoveryRoot(t)}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.OSID != "debian" || snapshot.OSVersion != "13" ||
		snapshot.Uplink != "enp1s0" || snapshot.UplinkGateway.String() != "192.168.50.1" ||
		!reflect.DeepEqual(snapshot.NonLoopbackInterfaces, []string{"enp1s0", "wlan0"}) ||
		!reflect.DeepEqual(snapshot.ManagementTCP, []int{22}) ||
		snapshot.IPv6DefaultRoute || snapshot.DockerPresent || !snapshot.DockerClean {
		t.Fatalf("unexpected discovery snapshot: %#v", snapshot)
	}
}

func TestInspectorUsesRetainedDockerStateWithoutDaemonAccess(t *testing.T) {
	runner := cleanDiscoveryRunner()
	networks := []config.DockerNetwork{{
		Name: "bridge", Driver: "bridge", BridgeInterface: "docker0",
		DynamicBridge: true, Subnets: []string{"172.17.0.0/16"},
		Gateways: []string{"172.17.0.1"},
	}}
	snapshot, err := (Inspector{Runner: runner, Root: discoveryRoot(t)}).InspectWithDockerState(
		context.Background(), DockerState{Present: true, Clean: true, Networks: networks},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.DockerPresent || !snapshot.DockerClean ||
		!reflect.DeepEqual(snapshot.DockerNetworks, networks) ||
		!reflect.DeepEqual(snapshot.NonLoopbackInterfaces, []string{"docker0", "enp1s0", "wlan0"}) {
		t.Fatalf("retained Docker state was not projected exactly: %#v", snapshot)
	}
	snapshot.DockerNetworks[0].Subnets[0] = "192.0.2.0/24"
	if networks[0].Subnets[0] != "172.17.0.0/16" {
		t.Fatal("retained Docker snapshot was aliased")
	}
}

func TestInspectorDiscoverClassifiesDockerIPv6AndManagers(t *testing.T) {
	runner := cleanDiscoveryRunner()
	runner.outputs["ip -j -6 route show default"] = []byte(
		`[{"gateway":"2001:db8::1","dev":"enp1s0"}]`,
	)
	addCleanDocker(runner)
	delete(runner.errors, "systemctl is-active --quiet ufw.service")
	_, err := (Inspector{Runner: runner, Root: discoveryRoot(t)}).Discover(context.Background())
	if err == nil || err.Error() != "DISCOVERY_COMPETING_FIREWALL" {
		t.Fatalf("active firewall manager was not refused: %v", err)
	}
	delete(runner.outputs, "systemctl is-active --quiet ufw.service")
	runner.errors["systemctl is-active --quiet ufw.service"] = errors.New("inactive")
	snapshot, err := (Inspector{Runner: runner, Root: discoveryRoot(t)}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.IPv6DefaultRoute || !snapshot.DockerPresent || !snapshot.DockerClean ||
		len(snapshot.DockerNetworks) != 1 ||
		snapshot.DockerNetworks[0].BridgeInterface != "docker0" {
		t.Fatalf("optional state was not classified: %#v", snapshot)
	}
}

func TestInspectorDiscoverAllowsEligibleEmptyCustomBridge(t *testing.T) {
	runner := cleanDiscoveryRunner()
	addCleanDocker(runner)
	builtInID := strings.Repeat("a", 64)
	appID := strings.Repeat("d", 64)
	runner.outputs["docker --host unix:///var/run/docker.sock network ls --no-trunc --format {{.ID}}\t{{.Name}}\t{{.Driver}}"] =
		[]byte(builtInID + "\tbridge\tbridge\n" +
			appID + "\tmedia-app\tbridge\n" +
			strings.Repeat("b", 64) + "\thost\thost\n" +
			strings.Repeat("c", 64) + "\tnone\tnull\n")
	runner.outputs["docker --host unix:///var/run/docker.sock network inspect -- "+appID] =
		[]byte(`[{"Id":"` + appID + `","Name":"media-app","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{},"IPAM":{"Config":[{"Subnet":"172.23.0.0/16","Gateway":"172.23.0.1"}]}}]`)
	runner.outputs["ip -j link show dev br-"+appID[:12]] =
		[]byte(`[{"ifname":"br-` + appID[:12] + `"}]`)
	snapshot, err := (Inspector{Runner: runner, Root: discoveryRoot(t)}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.DockerPresent || !snapshot.DockerClean || len(snapshot.DockerNetworks) != 2 {
		t.Fatalf("eligible empty custom bridge was not classified clean: %#v", snapshot)
	}
}

func TestInspectorDiscoverRefusesRunningAndRetainedDockerWorkloads(t *testing.T) {
	id := strings.Repeat("f", 64)
	tests := []struct {
		name     string
		running  []byte
		retained []byte
	}{
		{name: "running", running: []byte(id + "\n"), retained: []byte(id + "\n")},
		{name: "retained-stopped", retained: []byte(id + "\n")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := cleanDiscoveryRunner()
			addCleanDocker(runner)
			runner.outputs["docker --host unix:///var/run/docker.sock ps -q --no-trunc"] = test.running
			runner.outputs["docker --host unix:///var/run/docker.sock ps -aq --no-trunc"] = test.retained
			_, err := (Inspector{Runner: runner, Root: discoveryRoot(t)}).Discover(context.Background())
			if err == nil || err.Error() != "DISCOVERY_DOCKER_WORKLOADS_REQUIRE_ADOPT" {
				t.Fatalf("Docker workload was not refused: %v", err)
			}
			if strings.Contains(err.Error(), id) {
				t.Fatalf("Docker refusal leaked a container identity: %v", err)
			}
		})
	}
}

func TestInspectorDiscoverRejectsChangingDockerWorkloads(t *testing.T) {
	runner := cleanDiscoveryRunner()
	addCleanDocker(runner)
	changing := &changingWorkloadRunner{base: runner, calls: map[string]int{}}
	_, err := (Inspector{Runner: changing, Root: discoveryRoot(t)}).Discover(context.Background())
	if err == nil || err.Error() != "DISCOVERY_DOCKER_STATE_CHANGED" {
		t.Fatalf("changing Docker workload observation was accepted: %v", err)
	}
}

func TestInspectorDiscoverCommandFailures(t *testing.T) {
	tests := []struct {
		command string
		code    string
	}{
		{"ip -j -4 route show default", "DISCOVERY_IPV4_DEFAULT_ROUTE_FAILED"},
		{"ip -j -4 address show dev enp1s0", "DISCOVERY_UPLINK_ADDRESS_FAILED"},
		{"ip -j link show", "DISCOVERY_LINK_INSPECTION_FAILED"},
		{"nft -j list ruleset", "DISCOVERY_NFTABLES_UNREADABLE"},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			runner := cleanDiscoveryRunner()
			runner.errors[test.command] = errors.New("failed")
			_, err := (Inspector{Runner: runner, Root: discoveryRoot(t)}).Discover(context.Background())
			if err == nil || err.Error() != test.code {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestInspectorHelpersAndExistingState(t *testing.T) {
	root := discoveryRoot(t)
	runner := cleanDiscoveryRunner()
	inspector := Inspector{Runner: runner, Root: root}
	if inspector.rootPath("/etc/os-release") != filepath.Join(root, "etc/os-release") {
		t.Fatal("root path projection changed")
	}
	if (Inspector{}).rootPath("/etc/os-release") != "/etc/os-release" ||
		(Inspector{Root: "/"}).rootPath("/etc/os-release") != "/etc/os-release" {
		t.Fatal("host root path projection changed")
	}
	if inspector.existingNFTFWState() {
		t.Fatal("empty root classified as existing NFTFW")
	}
	statePath := filepath.Join(root, "var/lib/nftfw/setup/journal.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !inspector.existingNFTFWState() {
		t.Fatal("existing NFTFW state was missed")
	}

	delete(runner.errors, "docker --version")
	runner.outputs["docker --version"] = []byte("Docker version 29\n")
	delete(runner.errors, "docker --host unix:///var/run/docker.sock version --format {{.Server.Version}}")
	runner.outputs["docker --host unix:///var/run/docker.sock version --format {{.Server.Version}}"] = []byte("29")
	runner.errors["docker --host unix:///var/run/docker.sock ps -aq --no-trunc"] = errors.New("unreadable")
	present, clean, networks, err := inspector.dockerState(context.Background())
	if !present || clean || len(networks) != 0 || err == nil {
		t.Fatalf("unreadable Docker state classified clean: present=%t clean=%t networks=%v err=%v", present, clean, networks, err)
	}
	delete(runner.errors, "docker --host unix:///var/run/docker.sock ps -aq --no-trunc")
	containerID := strings.Repeat("d", 64)
	runner.outputs["docker --host unix:///var/run/docker.sock ps -aq --no-trunc"] = []byte(containerID + "\n")
	runner.outputs["docker --host unix:///var/run/docker.sock network ls --filter type=custom -q"] = nil
	id := strings.Repeat("d", 64)
	runner.outputs["docker --host unix:///var/run/docker.sock network ls --no-trunc --format {{.ID}}\t{{.Name}}\t{{.Driver}}"] =
		[]byte(id + "\tbridge\tbridge\n")
	runner.outputs["docker --host unix:///var/run/docker.sock network inspect -- "+id] =
		[]byte(`[{"Id":"` + id + `","Name":"bridge","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{},"IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}]`)
	runner.outputs["ip -j link show dev docker0"] = []byte(`[{"ifname":"docker0"}]`)
	present, clean, networks, err = inspector.dockerState(context.Background())
	if !present || clean || err != nil || len(networks) != 1 {
		t.Fatalf("non-empty Docker state rejected: present=%t clean=%t networks=%v err=%v", present, clean, networks, err)
	}
}

func TestReadOSReleaseAndBoundedHelpers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(path, []byte("ID='debian'\nVERSION_ID=13\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, version, err := readOSRelease(path)
	if err != nil || id != "debian" || version != "13" {
		t.Fatalf("unexpected release: %q %q %v", id, version, err)
	}
	if err := os.WriteFile(path, []byte("ID=debian\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readOSRelease(path); err == nil {
		t.Fatal("incomplete release accepted")
	}
	if _, _, err := readOSRelease(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing release accepted")
	}
	if !hasJSONArrayItems([]byte(`[{}]`)) || hasJSONArrayItems([]byte(`[]`)) ||
		hasJSONArrayItems([]byte(`invalid`)) {
		t.Fatal("JSON array classification changed")
	}
	var buffer boundedBuffer
	if n, err := buffer.Write([]byte("abc")); err != nil || n != 3 ||
		string(buffer.Bytes()) != "abc" {
		t.Fatalf("bounded buffer write failed: n=%d err=%v", n, err)
	}
	copy := buffer.Bytes()
	copy[0] = 'z'
	if string(buffer.Bytes()) != "abc" {
		t.Fatal("bounded buffer exposed internal storage")
	}
	buffer.data = make([]byte, maxCommandOutput)
	if _, err := buffer.Write([]byte("x")); err == nil {
		t.Fatal("oversized command output accepted")
	}
}

func TestParseDockerContainerIDsIsBoundedAndCanonical(t *testing.T) {
	first := strings.Repeat("a", 64)
	full := strings.Repeat("b", 64)
	ids, err := parseDockerContainerIDs([]byte(full + "\n" + first + "\n"))
	if err != nil || !reflect.DeepEqual(ids, []string{first, full}) {
		t.Fatalf("valid Docker IDs were not canonicalized: ids=%v err=%v", ids, err)
	}
	if ids, err := parseDockerContainerIDs(nil); err != nil || len(ids) != 0 {
		t.Fatalf("empty workload observation rejected: ids=%v err=%v", ids, err)
	}
	for name, data := range map[string][]byte{
		"unsafe":    []byte("container-name\n"),
		"truncated": []byte(strings.Repeat("a", 12) + "\n"),
		"uppercase": []byte(strings.Repeat("A", 64) + "\n"),
		"duplicate": []byte(first + "\n" + first + "\n"),
		"oversized": make([]byte, maxCommandOutput+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseDockerContainerIDs(data); err == nil {
				t.Fatal("invalid Docker workload output accepted")
			}
		})
	}
}

func TestParseDefaultRouteAndPrivateNetworks(t *testing.T) {
	device, gateway, err := ParseDefaultRoute([]byte(`[{"dst":"default","gateway":"192.168.50.1","dev":"enp1s0"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if device != "enp1s0" || gateway != netip.MustParseAddr("192.168.50.1") {
		t.Fatalf("unexpected route: %s %s", device, gateway)
	}
	networks, err := ParsePrivateNetworks([]byte(`[{"addr_info":[{"family":"inet","local":"192.168.50.221","prefixlen":24,"scope":"global"},{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 1 || networks[0].String() != "192.168.50.0/24" {
		t.Fatalf("unexpected networks: %v", networks)
	}
}

func TestParseRejectsAmbiguousDefaultRoutes(t *testing.T) {
	input := `[{"gateway":"192.168.1.1","dev":"eth0"},{"gateway":"10.0.0.1","dev":"eth1"}]`
	if _, _, err := ParseDefaultRoute([]byte(input)); err == nil {
		t.Fatal("ambiguous default routes accepted")
	}
}

func TestParseSSHPorts(t *testing.T) {
	input := `LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
LISTEN 0 128 [::]:2222 [::]:* users:(("sshd",pid=1,fd=4))
LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("other",pid=2,fd=3))`
	ports := ParseSSHPorts([]byte(input))
	if len(ports) != 2 || ports[0] != 22 || ports[1] != 2222 {
		t.Fatalf("unexpected SSH ports: %v", ports)
	}
}

func TestParseNonLoopbackInterfaces(t *testing.T) {
	interfaces, err := ParseNonLoopbackInterfaces([]byte(`[
{"ifname":"lo"},{"ifname":"wlan0"},{"ifname":"eth0"},{"ifname":"eth0"}
]`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(interfaces, ",") != "eth0,wlan0" {
		t.Fatalf("unexpected interfaces: %v", interfaces)
	}
}

func TestForeignNFTables(t *testing.T) {
	clean := `{"nftables":[{"metainfo":{"json_schema_version":1}}]}`
	foreign, err := ForeignNFTables([]byte(clean))
	if err != nil || foreign {
		t.Fatalf("empty ruleset rejected: foreign=%t err=%v", foreign, err)
	}
	owned := `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`
	foreign, err = ForeignNFTables([]byte(owned))
	if err != nil || foreign {
		t.Fatalf("owned ruleset rejected: foreign=%t err=%v", foreign, err)
	}
	other := strings.Replace(owned, "nftfw_filter", "filter", 1)
	foreign, err = ForeignNFTables([]byte(other))
	if err != nil || !foreign {
		t.Fatalf("foreign ruleset accepted: foreign=%t err=%v", foreign, err)
	}
}

func TestNFTablesOwnershipDistinguishesOwnedAndForeign(t *testing.T) {
	owned, foreign, err := NFTablesOwnership([]byte(`{"nftables":[
{"table":{"family":"inet","name":"nftfw_filter"}},
{"table":{"family":"ip","name":"nftfw_nat"}}
]}`))
	if err != nil || !owned || foreign {
		t.Fatalf("unexpected owned classification: owned=%t foreign=%t err=%v", owned, foreign, err)
	}
	owned, foreign, err = NFTablesOwnership([]byte(`{"nftables":[
{"table":{"family":"inet","name":"nftfw_filter"}},
{"table":{"family":"inet","name":"foreign"}}
]}`))
	if err != nil || !owned || !foreign {
		t.Fatalf("unexpected mixed classification: owned=%t foreign=%t err=%v", owned, foreign, err)
	}
}

func TestCleanHostRejectsExistingNFTFWState(t *testing.T) {
	snapshot := Snapshot{
		OSID: "debian", OSVersion: "13", Architecture: "amd64",
		Uplink: "eth0", UplinkGateway: netip.MustParseAddr("192.168.1.1"),
		LANNetworks:        []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		DockerClean:        true,
		ExistingNFTFWState: true,
	}
	if err := snapshot.ValidateCleanHost(); err == nil ||
		err.Error() != "DISCOVERY_EXISTING_NFTFW_REQUIRES_ADOPT" {
		t.Fatalf("existing NFTFW state was accepted: %v", err)
	}
}

func TestValidateCleanHost(t *testing.T) {
	base := Snapshot{
		OSID: "debian", OSVersion: "13", Architecture: "amd64",
		Uplink: "eth0", UplinkGateway: netip.MustParseAddr("192.168.1.1"),
		LANNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		DockerClean: true,
	}
	if err := base.ValidateCleanHost(); err != nil {
		t.Fatal(err)
	}
	base.ForeignNFTables = true
	if err := base.ValidateCleanHost(); err == nil {
		t.Fatal("foreign firewall accepted")
	}
	base.ForeignNFTables = false
	base.DockerPresent = true
	base.DockerClean = false
	if err := base.ValidateCleanHost(); err == nil ||
		err.Error() != "DISCOVERY_DOCKER_WORKLOADS_REQUIRE_ADOPT" {
		t.Fatalf("non-clean Docker state was accepted: %v", err)
	}
}

func BenchmarkParsePrivateNetworks(b *testing.B) {
	data := []byte(`[{"addr_info":[{"family":"inet","local":"192.168.50.221","prefixlen":24,"scope":"global"}]}]`)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParsePrivateNetworks(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInspectorDiscover(b *testing.B) {
	root := b.TempDir()
	path := filepath.Join(root, "etc", "os-release")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ID=debian\nVERSION_ID=13\n"), 0o600); err != nil {
		b.Fatal(err)
	}
	inspector := Inspector{Runner: cleanDiscoveryRunner(), Root: root}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := inspector.Discover(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseDockerContainerIDs(b *testing.B) {
	data := []byte(strings.Repeat("a", 64) + "\n" + strings.Repeat("b", 64) + "\n")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseDockerContainerIDs(data); err != nil {
			b.Fatal(err)
		}
	}
}
