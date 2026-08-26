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
)

type fakeRunner struct {
	outputs map[string][]byte
	errors  map[string]error
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
			"docker version --format {{.Server.Version}}":              errors.New("not installed"),
		},
	}
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

func TestInspectorDiscoverClassifiesDockerIPv6AndManagers(t *testing.T) {
	runner := cleanDiscoveryRunner()
	runner.outputs["ip -j -6 route show default"] = []byte(
		`[{"gateway":"2001:db8::1","dev":"enp1s0"}]`,
	)
	delete(runner.errors, "docker version --format {{.Server.Version}}")
	runner.outputs["docker version --format {{.Server.Version}}"] = []byte("29.0.0\n")
	runner.outputs["docker ps -aq"] = nil
	runner.outputs["docker network ls --filter type=custom -q"] = nil
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
	if !snapshot.IPv6DefaultRoute || !snapshot.DockerPresent || !snapshot.DockerClean {
		t.Fatalf("optional state was not classified: %#v", snapshot)
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

	delete(runner.errors, "docker version --format {{.Server.Version}}")
	runner.outputs["docker version --format {{.Server.Version}}"] = []byte("29")
	runner.errors["docker ps -aq"] = errors.New("unreadable")
	present, clean := inspector.dockerState(context.Background())
	if !present || clean {
		t.Fatalf("unreadable Docker state classified clean: present=%t clean=%t", present, clean)
	}
	delete(runner.errors, "docker ps -aq")
	runner.outputs["docker ps -aq"] = []byte("container\n")
	runner.outputs["docker network ls --filter type=custom -q"] = nil
	present, clean = inspector.dockerState(context.Background())
	if !present || clean {
		t.Fatalf("non-empty Docker state classified clean: present=%t clean=%t", present, clean)
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
