package intent

import (
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/compiler"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/discovery"
	"github.com/unknown0152/nft-firewall-v2/internal/policy"
	"github.com/unknown0152/nft-firewall-v2/internal/wgconfig"
)

func key(fill byte) string {
	value := make([]byte, 32)
	for i := range value {
		value[i] = fill
	}
	return base64.StdEncoding.EncodeToString(value)
}

func fixture(t testing.TB) Intent {
	t.Helper()
	profile, _, err := wgconfig.Parse([]byte(`[Interface]
PrivateKey = ` + key(1) + `
Address = 10.8.0.2/32
DNS = 1.1.1.1
[Peer]
PublicKey = ` + key(2) + `
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.test:51820
`))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := discovery.Snapshot{
		OSID: "debian", OSVersion: "13", Architecture: "amd64",
		Uplink: "eth0", UplinkGateway: netip.MustParseAddr("192.168.1.1"),
		LANNetworks:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		ManagementTCP: []int{22}, DockerClean: true,
	}
	value, err := New(snapshot, profile, []netip.Addr{netip.MustParseAddr("198.51.100.8")})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestGeneratedConfigIsValidAndVPNOnly(t *testing.T) {
	value := fixture(t)
	c, err := value.Config()
	if err != nil {
		t.Fatal(err)
	}
	effective, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := compiler.Compile(compiler.Input{
		Policy: effective, BootstrapV4: c.WireGuard.BootstrapIPs,
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`oifname "nftfw0"  accept comment "nftfw-policy:host-all-outbound"`,
		`ip saddr 192.168.1.0/24 tcp dport { 22 } accept comment "nftfw-policy:lan-management"`,
		`counter drop comment "nftfw:output-default-deny"`,
	} {
		if !strings.Contains(artifact.Script, want) {
			t.Fatalf("managed policy missing %q", want)
		}
	}
}

func TestGeneratedDockerConfigOwnsVPNOnlyForwarding(t *testing.T) {
	value := fixture(t)
	value.DockerEnabled = true
	value.DockerNetworks = []config.DockerNetwork{{
		Name: "cosmos-app", Driver: "bridge", BridgeInterface: "br-cosmos",
		DynamicBridge: true, Subnets: []string{"172.23.0.0/16"},
		Gateways: []string{"172.23.0.1"},
	}}
	c, err := value.Config()
	if err != nil {
		t.Fatal(err)
	}
	if !c.Integrations.DockerEnabled || len(c.DockerNetworks) != 1 ||
		len(c.Interfaces) != 3 ||
		config.InterfaceProvenanceName(c.Interfaces[2]) != "docker:cosmos-app" {
		t.Fatalf("managed Docker configuration missing: %#v", c)
	}
	effective, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := compiler.Compile(compiler.Input{
		Policy: effective, BootstrapV4: c.WireGuard.BootstrapIPs,
		DockerNets: []string{"172.23.0.0/16"},
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`iifname "br-cosmos" ip saddr 172.23.0.0/16 oifname "nftfw0"`,
		`iifname "br-cosmos" ip saddr 172.23.0.0/16 oifname "eth0" drop`,
		`iifname "br-cosmos" ip saddr 172.23.0.0/16 oifname "nftfw0" masquerade`,
		`nftfw-policy:containers-all-outbound`,
	} {
		if !strings.Contains(artifact.Script, expected) {
			t.Fatalf("Docker policy missing %q:\n%s", expected, artifact.Script)
		}
	}
}

func TestNewRefusesNonCleanDockerBeforeGeneratingIntent(t *testing.T) {
	profile, _, err := wgconfig.Parse([]byte(`[Interface]
PrivateKey = ` + key(1) + `
Address = 10.8.0.2/32
[Peer]
PublicKey = ` + key(2) + `
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.test:51820
`))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := discovery.Snapshot{
		OSID: "debian", OSVersion: "13", Architecture: "amd64",
		Uplink: "eth0", UplinkGateway: netip.MustParseAddr("192.168.1.1"),
		LANNetworks:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		DockerPresent: true, DockerClean: false,
	}
	_, err = New(snapshot, profile, []netip.Addr{netip.MustParseAddr("198.51.100.8")})
	if err == nil || err.Error() != "DISCOVERY_DOCKER_WORKLOADS_REQUIRE_ADOPT" {
		t.Fatalf("non-clean Docker state reached intent generation: %v", err)
	}
}

func TestManagedDockerSubnetsRejectIsolationOverlaps(t *testing.T) {
	tests := []struct {
		name   string
		subnet string
		code   string
	}{
		{"LAN", "192.168.1.0/25", "INTENT_DOCKER_SUBNET_OVERLAPS_LAN"},
		{"VPN", "10.8.0.0/24", "INTENT_DOCKER_SUBNET_OVERLAPS_VPN"},
		{"bootstrap", "198.51.100.0/24", "INTENT_DOCKER_SUBNET_OVERLAPS_BOOTSTRAP"},
		{"loopback", "127.20.0.0/16", "INTENT_DOCKER_SUBNET_OVERLAPS_RESERVED"},
		{"link-local", "169.254.20.0/24", "INTENT_DOCKER_SUBNET_OVERLAPS_RESERVED"},
		{"multicast", "224.20.0.0/16", "INTENT_DOCKER_SUBNET_OVERLAPS_RESERVED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := fixture(t)
			value.DockerEnabled = true
			value.DockerNetworks = []config.DockerNetwork{{
				Name: "media", Driver: "bridge", BridgeInterface: "br-media",
				DynamicBridge: true, Subnets: []string{test.subnet},
				Gateways: []string{strings.TrimSuffix(test.subnet, "0/24") + "1"},
			}}
			if err := value.Validate(); err == nil || err.Error() != test.code {
				t.Fatalf("overlap accepted or wrong code: %v", err)
			}
		})
	}
}

func TestManagedDockerSubnetsRejectEachOther(t *testing.T) {
	value := fixture(t)
	value.DockerEnabled = true
	value.DockerNetworks = []config.DockerNetwork{
		{
			Name: "one", Driver: "bridge", BridgeInterface: "br-one",
			DynamicBridge: true, Subnets: []string{"172.20.0.0/16"},
			Gateways: []string{"172.20.0.1"},
		},
		{
			Name: "two", Driver: "bridge", BridgeInterface: "br-two",
			DynamicBridge: true, Subnets: []string{"172.20.1.0/24"},
			Gateways: []string{"172.20.1.1"},
		},
	}
	if err := value.Validate(); err == nil ||
		err.Error() != "INTENT_DOCKER_SUBNET_OVERLAP_ONE_TWO" {
		t.Fatalf("overlapping Docker networks accepted: %v", err)
	}
}

func TestIntentRoundTripAndManagedChanges(t *testing.T) {
	value := fixture(t)
	if err := value.AddExposure("tcp", 443, 80); err != nil {
		t.Fatal(err)
	}
	if err := value.AddLAN("udp", 5353); err != nil {
		t.Fatal(err)
	}
	rendered, err := value.Render()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.PublicTCP) != 2 || decoded.PublicTCP[0] != 80 ||
		len(decoded.LANAllowUDP) != 1 || decoded.LANAllowUDP[0] != 5353 {
		t.Fatalf("unexpected decoded intent: %#v", decoded)
	}
	if err := decoded.RemoveExposure("tcp", 80); err != nil {
		t.Fatal(err)
	}
	if len(decoded.PublicTCP) != 1 || decoded.PublicTCP[0] != 443 {
		t.Fatalf("exposure removal failed: %v", decoded.PublicTCP)
	}
}

func TestIntentContainsNoVPNKeys(t *testing.T) {
	value := fixture(t)
	rendered, err := value.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{key(1), key(2), "PrivateKey", "PublicKey"} {
		if strings.Contains(string(rendered), secret) {
			t.Fatalf("managed intent contains VPN secret material")
		}
	}
}

func TestLoadAndRenderConfig(t *testing.T) {
	value := fixture(t)
	rendered, err := value.Render()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "intent.toml")
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	configValue, err := loaded.Config()
	if err != nil {
		t.Fatal(err)
	}
	configData, err := RenderConfig(configValue)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(configData), "Generated by NFT Firewall V2") {
		t.Fatal("generated configuration header missing")
	}
	if _, err := Load("relative.toml"); err == nil {
		t.Fatal("relative intent path accepted")
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("writable intent accepted")
	}
}

func TestIntentValidationRejectsUnsafeFields(t *testing.T) {
	base := fixture(t)
	mutations := []func(*Intent){
		func(i *Intent) { i.Schema = "unknown" },
		func(i *Intent) { i.Managed = false },
		func(i *Intent) { i.Uplink = "" },
		func(i *Intent) { i.VPNInterface = i.Uplink },
		func(i *Intent) { i.LANNetworks = nil },
		func(i *Intent) { i.LANNetworks = []string{"203.0.113.0/24"} },
		func(i *Intent) { i.VPNAddresses = []string{"::1/128"} },
		func(i *Intent) { i.BootstrapIPv4 = []string{"198.51.100.8/24"} },
		func(i *Intent) { i.EndpointPort = 0 },
		func(i *Intent) { i.ManagementTCP = []int{22, 22} },
		func(i *Intent) { i.DisableIPv6 = false },
		func(i *Intent) { i.ResolverMode = "unknown" },
		func(i *Intent) { i.DockerEnabled = true },
	}
	for index, mutate := range mutations {
		candidate := base
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatalf("unsafe intent mutation %d accepted: %#v", index, candidate)
		}
	}
}

func TestManagedPortMutationsAndValidation(t *testing.T) {
	value := fixture(t)
	if err := value.AddExposure("udp", 53); err != nil {
		t.Fatal(err)
	}
	if err := value.RemoveExposure("udp", 53); err != nil || len(value.PublicUDP) != 0 {
		t.Fatalf("UDP exposure removal failed: %v %v", value.PublicUDP, err)
	}
	if err := value.AddLAN("tcp", 8096); err != nil {
		t.Fatal(err)
	}
	if err := value.RemoveLAN("tcp", 8096); err != nil || len(value.LANAllowTCP) != 0 {
		t.Fatalf("LAN removal failed: %v %v", value.LANAllowTCP, err)
	}
	for _, operation := range []func() error{
		func() error { return value.AddExposure("icmp", 1) },
		func() error { return value.RemoveExposure("icmp", 1) },
		func() error { return value.AddLAN("icmp", 1) },
		func() error { return value.RemoveLAN("tcp", 0) },
	} {
		if err := operation(); err == nil {
			t.Fatal("invalid managed port mutation accepted")
		}
	}
}

func TestTCPMSSBounds(t *testing.T) {
	cases := map[int]int{0: 1360, 576: 536, 1420: 1360, 10000: 8960}
	for mtu, want := range cases {
		if got := tcpMSS(mtu); got != want {
			t.Fatalf("tcpMSS(%d)=%d want=%d", mtu, got, want)
		}
	}
}

func BenchmarkConfigGeneration(b *testing.B) {
	value := fixture(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := value.Config(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkManagedDockerConfigGeneration(b *testing.B) {
	value := fixture(b)
	value.DockerEnabled = true
	value.DockerNetworks = []config.DockerNetwork{
		{
			Name: "bridge", Driver: "bridge", BridgeInterface: "docker0",
			DynamicBridge: true, Subnets: []string{"172.17.0.0/16"},
			Gateways: []string{"172.17.0.1"},
		},
		{
			Name: "media", Driver: "bridge", BridgeInterface: "br-media",
			DynamicBridge: true, Subnets: []string{"172.20.0.0/16"},
			Gateways: []string{"172.20.0.1"},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := value.Config(); err != nil {
			b.Fatal(err)
		}
	}
}
