package containers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/compiler"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/policy"
)

func secureDockerConfigPath(t testing.TB, body string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "docker")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "daemon.json")
	if body != "" {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestManagedDaemonConfigPreservesUnrelatedKeys(t *testing.T) {
	path := secureDockerConfigPath(t, `{
  "data-root": "/srv/docker",
  "log-opts": {"max-file": "3"},
  "iptables": true
}`)
	data, changed, err := ManagedDaemonConfig(path)
	if err != nil || !changed {
		t.Fatalf("managed daemon config failed: changed=%t err=%v", changed, err)
	}
	text := string(data)
	for _, expected := range []string{
		`"data-root": "/srv/docker"`,
		`"log-opts": {`,
		`"iptables": false`,
		`"ip6tables": false`,
		`"ip-forward": false`,
		`"ip-masq": false`,
		`"userland-proxy": false`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("managed daemon config omitted %q: %s", expected, text)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManagedDaemonConfig(path); err != nil {
		t.Fatal(err)
	}
	_, changed, err = ManagedDaemonConfig(path)
	if err != nil || changed {
		t.Fatalf("compliant daemon config was not idempotent: changed=%t err=%v", changed, err)
	}
}

func TestManagedDaemonConfigRejectsUnsafeAndAmbiguousInput(t *testing.T) {
	tests := []struct {
		name string
		body string
		code string
	}{
		{"duplicate", `{"iptables":false,"iptables":true}`, "DOCKER_DAEMON_CONFIG_INVALID"},
		{"array", `[]`, "DOCKER_DAEMON_CONFIG_NOT_OBJECT"},
		{"malformed", `{`, "DOCKER_DAEMON_CONFIG_INVALID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := secureDockerConfigPath(t, test.body)
			if _, _, err := ManagedDaemonConfig(path); err == nil || err.Error() != test.code {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
	empty := secureDockerConfigPath(t, "")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ManagedDaemonConfig(empty); err == nil ||
		err.Error() != "DOCKER_DAEMON_CONFIG_INVALID" {
		t.Fatalf("empty existing daemon config accepted: %v", err)
	}

	path := secureDockerConfigPath(t, "")
	target := filepath.Join(filepath.Dir(path), "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ManagedDaemonConfig(path); err == nil ||
		err.Error() != "DOCKER_DAEMON_CONFIG_FILE_UNSAFE" {
		t.Fatalf("symlink accepted: %v", err)
	}

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	targetDirectory := filepath.Join(root, "target")
	if err := os.Mkdir(targetDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(root, "docker")
	if err := os.Symlink(targetDirectory, parentLink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ManagedDaemonConfig(filepath.Join(parentLink, "daemon.json")); err == nil ||
		err.Error() != "DOCKER_DAEMON_CONFIG_PARENT_UNSAFE" {
		t.Fatalf("symlinked parent accepted: %v", err)
	}
}

func TestManagedDaemonConfigCreatesMissingFileProjection(t *testing.T) {
	path := secureDockerConfigPath(t, "")
	data, changed, err := ManagedDaemonConfig(path)
	if err != nil || !changed || len(data) == 0 {
		t.Fatalf("missing config projection failed: changed=%t err=%v", changed, err)
	}
}

func TestManagedDaemonConfigFingerprintBindsExistenceAndContent(t *testing.T) {
	path := secureDockerConfigPath(t, "")
	missing, err := ManagedDaemonConfigFingerprint(path)
	if err != nil || missing == "" {
		t.Fatalf("missing fingerprint failed: %q %v", missing, err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	present, err := ManagedDaemonConfigFingerprint(path)
	if err != nil || present == "" || present == missing {
		t.Fatalf("present fingerprint failed: %q %v", present, err)
	}
	if err := os.WriteFile(path, []byte("{\"log-level\":\"warn\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := ManagedDaemonConfigFingerprint(path)
	if err != nil || changed == present {
		t.Fatalf("changed fingerprint failed: %q %v", changed, err)
	}
}

func TestManagedDaemonConfigAcceptsMissingProtectedParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "docker", "daemon.json")
	data, changed, err := ManagedDaemonConfig(path)
	if err != nil || !changed || len(data) == 0 {
		t.Fatalf("missing protected parent was not projected: changed=%t err=%v", changed, err)
	}
}

func TestManagedDaemonConfigRejectsPermissionsSizeAndReadRace(t *testing.T) {
	path := secureDockerConfigPath(t, `{}`)
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ManagedDaemonConfig(path); err == nil ||
		err.Error() != "DOCKER_DAEMON_CONFIG_FILE_UNSAFE" {
		t.Fatalf("unsafe mode accepted: %v", err)
	}

	path = secureDockerConfigPath(t, strings.Repeat(" ", maxDaemonConfig+1))
	if _, _, err := ManagedDaemonConfig(path); err == nil ||
		err.Error() != "DOCKER_DAEMON_CONFIG_FILE_UNSAFE" {
		t.Fatalf("oversized config accepted: %v", err)
	}

	path = secureDockerConfigPath(t, `{}`)
	_, _, err := readProtectedDaemonFileWithHook(path, func() {
		if writeErr := os.WriteFile(path, []byte(`{"changed":true}`), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	})
	if err == nil || err.Error() != "DOCKER_DAEMON_CONFIG_CHANGED_DURING_READ" {
		t.Fatalf("change during read accepted: %v", err)
	}
}

func TestManagedSocketDropInRequiresExactProtectedContent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "docker-access.conf")
	if err := os.WriteFile(path, []byte(ManagedSocketDropIn), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManagedSocketDropIn(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[Service]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManagedSocketDropIn(path); err == nil ||
		err.Error() != "DOCKER_SOCKET_DROPIN_UNSAFE" {
		t.Fatalf("modified drop-in accepted: %v", err)
	}

	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked-parent")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManagedSocketDropInTarget(
		filepath.Join(link, "docker-access.conf"),
	); err == nil || err.Error() != "DOCKER_SOCKET_DROPIN_PARENT_UNSAFE" {
		t.Fatalf("symlinked drop-in parent accepted: %v", err)
	}
}

type managedDockerFixture struct {
	outputs map[string][]byte
	errors  map[string]error
}

func (f managedDockerFixture) run(
	_ context.Context, _ int64, name string, args ...string,
) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	if err := f.errors[key]; err != nil {
		return nil, err
	}
	value, ok := f.outputs[key]
	if !ok {
		return nil, errors.New("unexpected command: " + key)
	}
	return append([]byte(nil), value...), nil
}

func dockerDiscoveryFixture() managedDockerFixture {
	bridgeID := strings.Repeat("a", 64)
	appID := strings.Repeat("b", 64)
	hostID := strings.Repeat("c", 64)
	noneID := strings.Repeat("d", 64)
	return managedDockerFixture{outputs: map[string][]byte{
		"docker --host unix:///var/run/docker.sock network ls --no-trunc --format {{.ID}}\t{{.Name}}\t{{.Driver}}": []byte(
			bridgeID + "\tbridge\tbridge\n" +
				appID + "\tcosmos-app\tbridge\n" +
				hostID + "\thost\thost\n" +
				noneID + "\tnone\tnull\n",
		),
		"docker --host unix:///var/run/docker.sock network inspect -- " + bridgeID: []byte(
			`[{"Id":"` + bridgeID + `","Name":"bridge","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{},"IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}]`,
		),
		"docker --host unix:///var/run/docker.sock network inspect -- " + appID: []byte(
			`[{"Id":"` + appID + `","Name":"cosmos-app","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{},"IPAM":{"Config":[{"Subnet":"172.23.0.0/16","Gateway":"172.23.0.1"}]}}]`,
		),
		"ip -j link show dev docker0":          []byte(`[{"ifname":"docker0"}]`),
		"ip -j link show dev br-" + appID[:12]: []byte(`[{"ifname":"br-` + appID[:12] + `"}]`),
	}, errors: map[string]error{}}
}

func TestDiscoverNetworksIncludesBuiltInAndComposeBridges(t *testing.T) {
	fixture := dockerDiscoveryFixture()
	networks, err := (Observer{Run: fixture.run}).DiscoverNetworks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 2 || networks[0].Name != "bridge" ||
		networks[0].BridgeInterface != "docker0" || !networks[0].DynamicBridge ||
		networks[1].Name != "cosmos-app" ||
		!strings.HasPrefix(networks[1].BridgeInterface, "br-") {
		t.Fatalf("unexpected networks: %#v", networks)
	}
}

func TestDiscoverNetworksRejectsUnsupportedAndChangingTopology(t *testing.T) {
	fixture := dockerDiscoveryFixture()
	badID := strings.Repeat("e", 64)
	listKey := "docker --host unix:///var/run/docker.sock network ls --no-trunc --format {{.ID}}\t{{.Name}}\t{{.Driver}}"
	fixture.outputs[listKey] = []byte(badID + "\tmacvlan-net\tmacvlan\n")
	if _, err := (Observer{Run: fixture.run}).DiscoverNetworks(context.Background()); err == nil ||
		!strings.HasPrefix(err.Error(), "DOCKER_NETWORK_DRIVER_UNSUPPORTED_") {
		t.Fatalf("unsupported driver accepted: %v", err)
	}

	fixture = dockerDiscoveryFixture()
	appID := strings.Repeat("b", 64)
	fixture.outputs["docker --host unix:///var/run/docker.sock network inspect -- "+appID] =
		[]byte(`[{"Id":"` + strings.Repeat("f", 64) + `","Name":"cosmos-app","Driver":"bridge"}]`)
	if _, err := (Observer{Run: fixture.run}).DiscoverNetworks(context.Background()); err == nil ||
		err.Error() != "DOCKER_NETWORK_CHANGED_DURING_READ" {
		t.Fatalf("changing network accepted: %v", err)
	}

	fixture = dockerDiscoveryFixture()
	fixture.outputs["docker --host unix:///var/run/docker.sock network inspect -- "+appID] =
		[]byte(`[{"Id":"` + appID + `","Name":"cosmos-app","Driver":"bridge","EnableIPv6":false,"Options":{},"IPAM":{"Config":[{"Subnet":"172.23.0.0/16","Gateway":"172.23.0.1"}]}}]`)
	if _, err := (Observer{Run: fixture.run}).DiscoverNetworks(context.Background()); err == nil ||
		!strings.HasPrefix(err.Error(), "DOCKER_NETWORK_INSPECT_INCOMPLETE_") {
		t.Fatalf("incomplete network mode accepted: %v", err)
	}

	fixture = dockerDiscoveryFixture()
	fixture.outputs["docker --host unix:///var/run/docker.sock network inspect -- "+appID] =
		[]byte(`[{"Id":"` + appID + `","Name":"cosmos-app","Driver":"bridge","Internal":true,"EnableIPv6":false,"Options":{},"IPAM":{"Config":[{"Subnet":"172.23.0.0/16","Gateway":"172.23.0.1"}]}}]`)
	if _, err := (Observer{Run: fixture.run}).DiscoverNetworks(context.Background()); err == nil ||
		!strings.HasPrefix(err.Error(), "DOCKER_NETWORK_MODE_UNSUPPORTED_") {
		t.Fatalf("internal network accepted: %v", err)
	}

	fixture = dockerDiscoveryFixture()
	fixture.outputs["docker --host unix:///var/run/docker.sock network inspect -- "+appID] =
		[]byte(`[{"Id":"` + appID + `","Name":"cosmos-app","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{},"IPAM":{"Config":[{"Subnet":"172.23.0.0/31","Gateway":"172.23.0.1"}]}}]`)
	if _, err := (Observer{Run: fixture.run}).DiscoverNetworks(context.Background()); err == nil ||
		!strings.HasPrefix(err.Error(), "DOCKER_NETWORK_IPAM_INVALID_") {
		t.Fatalf("Docker subnet without a usable container address accepted: %v", err)
	}
}

func FuzzStrictDockerDaemonJSON(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"iptables":false,"iptables":true}`))
	f.Add([]byte(`{"data-root":"/srv/docker","features":{"containerd-snapshotter":true}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxDaemonConfig {
			return
		}
		var value any
		_ = decodeStrictJSON(data, &value)
	})
}

func BenchmarkManagedDaemonConfig(b *testing.B) {
	path := secureDockerConfigPath(b, `{
  "data-root": "/srv/docker",
  "log-driver": "local",
  "iptables": false,
  "ip6tables": false,
  "ip-forward": false,
  "ip-masq": false,
  "userland-proxy": false
}`)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, changed, err := ManagedDaemonConfig(path); err != nil || changed {
			b.Fatalf("managed daemon projection failed: changed=%t err=%v", changed, err)
		}
	}
}

func BenchmarkDiscoverManagedDockerNetworks(b *testing.B) {
	fixture := dockerDiscoveryFixture()
	observer := Observer{Run: fixture.run}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := observer.DiscoverNetworks(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func TestProjectObservedConfigPreservesStableProvenance(t *testing.T) {
	source := config.Defaults()
	source.Interfaces = []config.Interface{
		{Name: "eth0", Role: "uplink", Zone: "uplink", ProvenanceID: 1},
		{Name: "wg0", Role: "vpn", Zone: "vpn", ProvenanceID: 2},
		{
			Name: "br-old", Role: "container", Zone: "containers",
			CIDRs: []string{"172.23.0.0/16"}, ProvenanceName: "docker:cosmos-app",
			ProvenanceID: 3,
		},
	}
	source.Zones = []config.Zone{
		{Name: "uplink", Interfaces: []string{"eth0"}},
		{Name: "vpn", Interfaces: []string{"wg0"}},
		{Name: "containers", Interfaces: []string{"br-old"}, Networks: []string{"172.23.0.0/16"}},
	}
	source.Services = []config.Service{{Name: "all", Protocol: "any"}}
	source.Policies = []config.Policy{
		{Name: "containers-out", From: "containers", To: "any", Service: "all", Action: "allow"},
	}
	source.Integrations.DockerEnabled = true
	source.DockerNetworks = []config.DockerNetwork{{
		Name: "cosmos-app", Driver: "bridge", BridgeInterface: "br-old",
		DynamicBridge: true, Subnets: []string{"172.23.0.0/16"},
		Gateways: []string{"172.23.0.1"},
	}}
	projected, err := ProjectObservedConfig(source, []Network{{
		Name: "cosmos-app", Driver: "bridge", BridgeInterface: "br-new",
		CIDR: "172.23.0.0/16", Gateway: "172.23.0.1",
	}})
	if err != nil {
		t.Fatal(err)
	}
	var container config.Interface
	for _, configured := range projected.Interfaces {
		if configured.Role == "container" {
			container = configured
		}
	}
	if container.Name != "br-new" || container.ProvenanceName != "docker:cosmos-app" ||
		container.ProvenanceID != 3 || projected.DockerNetworks[0].BridgeInterface != "br-new" {
		t.Fatalf("dynamic projection changed stable identity: %#v %#v", container, projected.DockerNetworks)
	}
	effective, err := policy.Compile(projected)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := compiler.Compile(compiler.Input{
		Policy: effective, DockerNets: []string{"172.23.0.0/16"},
	}, 9)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(artifact.Script, `iifname "br-new"`) ||
		strings.Contains(artifact.Script, `iifname "br-old"`) {
		t.Fatalf("compiled artifact did not rebind the observed bridge:\n%s", artifact.Script)
	}
}

func legacyStaticDockerConfig() config.Config {
	source := config.Defaults()
	source.Interfaces = []config.Interface{
		{Name: "eth0", Role: "uplink", Zone: "uplink", ProvenanceID: 1},
		{Name: "wg0", Role: "vpn", Zone: "vpn", ProvenanceID: 2},
		{
			Name: "br-legacy", Role: "container", Zone: "containers",
			CIDRs: []string{"172.24.0.0/16"}, ProvenanceID: 3,
		},
	}
	source.Zones = []config.Zone{
		{Name: "uplink", Interfaces: []string{"eth0"}},
		{Name: "vpn", Interfaces: []string{"wg0"}},
		{Name: "containers", Interfaces: []string{"br-legacy"}, Networks: []string{"172.24.0.0/16"}},
	}
	source.Services = []config.Service{{Name: "all", Protocol: "any"}}
	source.Policies = []config.Policy{
		{Name: "containers-out", From: "containers", To: "any", Service: "all", Action: "allow"},
	}
	source.Integrations.DockerEnabled = true
	source.DockerNetworks = []config.DockerNetwork{{
		Name: "legacy", Driver: "bridge", BridgeInterface: "br-legacy",
		Subnets: []string{"172.24.0.0/16"}, Gateways: []string{"172.24.0.1"},
	}}
	return source
}

func legacyStaticObservation() []Network {
	return []Network{{
		Name: "legacy", Driver: "bridge", BridgeInterface: "br-legacy",
		CIDR: "172.24.0.0/16", Gateway: "172.24.0.1",
	}}
}

func TestProjectObservedConfigPreservesLegacyStaticAdvancedConfig(t *testing.T) {
	source := legacyStaticDockerConfig()
	if err := config.Validate(source); err != nil {
		t.Fatal(err)
	}
	projected, err := ProjectObservedConfig(source, legacyStaticObservation())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(projected, source) {
		t.Fatalf("legacy static projection changed the advanced config:\nbefore=%#v\nafter=%#v", source, projected)
	}
	container := projected.Interfaces[2]
	if config.InterfaceProvenanceName(container) != "br-legacy" ||
		container.ProvenanceName != "" || container.ProvenanceID != 3 {
		t.Fatalf("legacy provenance identity changed: %#v", container)
	}
	effective, err := policy.Compile(projected)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := compiler.Compile(compiler.Input{
		Policy: effective, DockerNets: []string{"172.24.0.0/16"},
	}, 9)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(artifact.Script, `iifname "br-legacy"`) {
		t.Fatalf("legacy static bridge was not compiled:\n%s", artifact.Script)
	}
}

func TestProjectObservedConfigDynamicCannotUseLegacyFallback(t *testing.T) {
	source := legacyStaticDockerConfig()
	source.DockerNetworks[0].DynamicBridge = true
	_, err := ProjectObservedConfig(source, []Network{{
		Name: "legacy", Driver: "bridge", BridgeInterface: "br-new",
		CIDR: "172.24.0.0/16", Gateway: "172.24.0.1",
	}})
	if err == nil || !strings.Contains(err.Error(), "DOCKER_PROVENANCE_INTERFACE_MISSING_LEGACY") {
		t.Fatalf("dynamic bridge used the legacy provenance fallback: %v", err)
	}
}

func TestProjectObservedConfigStaticCannotTranslateProvenanceIdentity(t *testing.T) {
	source := legacyStaticDockerConfig()
	source.Interfaces[2].ProvenanceName = "custom:legacy"
	_, err := ProjectObservedConfig(source, legacyStaticObservation())
	if err == nil || !strings.Contains(err.Error(), "DOCKER_STATIC_PROVENANCE_INVALID_LEGACY") {
		t.Fatalf("static projection translated an unrelated provenance identity: %v", err)
	}
	if source.Interfaces[2].Name != "br-legacy" ||
		source.Interfaces[2].ProvenanceName != "custom:legacy" || source.Interfaces[2].ProvenanceID != 3 {
		t.Fatalf("failed projection mutated provenance: %#v", source.Interfaces[2])
	}
}

func TestProjectObservedConfigMixedStaticAndDynamicPreservesLedgerIdentities(t *testing.T) {
	source := legacyStaticDockerConfig()
	source.Interfaces = append(source.Interfaces, config.Interface{
		Name: "br-old", Role: "container", Zone: "containers",
		CIDRs: []string{"172.25.0.0/16"}, ProvenanceName: "docker:managed",
		ProvenanceID: 4,
	})
	source.Zones[2].Interfaces = append(source.Zones[2].Interfaces, "br-old")
	source.Zones[2].Networks = append(source.Zones[2].Networks, "172.25.0.0/16")
	source.DockerNetworks = append(source.DockerNetworks, config.DockerNetwork{
		Name: "managed", Driver: "bridge", BridgeInterface: "br-old",
		DynamicBridge: true, Subnets: []string{"172.25.0.0/16"},
		Gateways: []string{"172.25.0.1"},
	})
	if err := config.Validate(source); err != nil {
		t.Fatal(err)
	}
	projected, err := ProjectObservedConfig(source, []Network{
		{
			Name: "legacy", Driver: "bridge", BridgeInterface: "br-legacy",
			CIDR: "172.24.0.0/16", Gateway: "172.24.0.1",
		},
		{
			Name: "managed", Driver: "bridge", BridgeInterface: "br-new",
			CIDR: "172.25.0.0/16", Gateway: "172.25.0.1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	before := map[string]uint8{}
	for _, configured := range source.Interfaces {
		before[config.InterfaceProvenanceName(configured)] = configured.ProvenanceID
	}
	after := map[string]uint8{}
	for _, configured := range projected.Interfaces {
		after[config.InterfaceProvenanceName(configured)] = configured.ProvenanceID
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("projection changed ledger identities: before=%v after=%v", before, after)
	}
	if projected.Interfaces[2].Name != "br-legacy" || projected.Interfaces[2].ProvenanceName != "" ||
		projected.Interfaces[3].Name != "br-new" ||
		projected.Interfaces[3].ProvenanceName != "docker:managed" {
		t.Fatalf("mixed projection crossed static/dynamic ownership: %#v", projected.Interfaces)
	}
	if source.Interfaces[3].Name != "br-old" {
		t.Fatal("projection mutated the source config")
	}
	if !reflect.DeepEqual(projected.Zones[2].Interfaces, []string{"br-legacy", "br-new"}) {
		t.Fatalf("mixed zone binding was not projected deterministically: %v", projected.Zones[2].Interfaces)
	}
}

func TestProjectObservedConfigRefusesTupleAndObservationDriftWithoutMutation(t *testing.T) {
	tests := map[string]func([]Network) []Network{
		"bridge":    func(values []Network) []Network { values[0].BridgeInterface = "br-drift"; return values },
		"driver":    func(values []Network) []Network { values[0].Driver = "overlay"; return values },
		"subnet":    func(values []Network) []Network { values[0].CIDR = "172.26.0.0/16"; return values },
		"gateway":   func(values []Network) []Network { values[0].Gateway = "172.24.0.2"; return values },
		"duplicate": func(values []Network) []Network { return append(values, values[0]) },
		"missing":   func([]Network) []Network { return nil },
		"unauthorized": func(values []Network) []Network {
			return append(values, Network{
				Name: "extra", Driver: "bridge", BridgeInterface: "br-extra",
				CIDR: "172.27.0.0/16", Gateway: "172.27.0.1",
			})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			source := legacyStaticDockerConfig()
			before := legacyStaticDockerConfig()
			if _, err := ProjectObservedConfig(source, mutate(legacyStaticObservation())); err == nil {
				t.Fatal("Docker observation drift was accepted")
			}
			if !reflect.DeepEqual(source, before) {
				t.Fatal("failed projection mutated the protected source config")
			}
		})
	}
}
