package config

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, text string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "nftfw.toml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const validTOML = `[system]
ipv6_mode = "disabled"
strict_vpn = true
[[interfaces]]
name = "eth0"
role = "uplink"
provenance_id = 1
[[interfaces]]
name = "wg0"
role = "vpn"
provenance_id = 2
[[zones]]
name = "lan"
networks = ["192.168.1.0/24"]
[[services]]
name = "ssh"
protocol = "tcp"
ports = [22]
[[policies]]
name = "lan-ssh"
from = "lan"
to = "host"
service = "ssh"
action = "allow"
[wireguard]
interface = "wg0"
endpoint_port = 51820
fwmark = "0xca6c"
[state]
directory = "/tmp/nftfw"
database = "/tmp/nftfw/generation-state/state.db"
provenance_ledger = "/tmp/nftfw/provenance-ledger.db"
`

func TestLoadRejectsUnknownKeys(t *testing.T) {
	p := writeConfig(t, validTOML+"\n[system.extra]\nvalue = true\n")
	if _, err := Load(p); err == nil {
		t.Fatal("unknown key accepted")
	}
}
func TestLoadValidatesTopology(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	if c.WireGuard.Interface != "wg0" || c.System.IPv6Mode != "disabled" {
		t.Fatalf("unexpected config: %#v", c)
	}
	if c.WireGuard.TCPMSS != 1360 {
		t.Fatalf("unexpected default TCP MSS: %d", c.WireGuard.TCPMSS)
	}
	if c.Runtime.SafeApplySeconds != 90 {
		t.Fatalf("unexpected default safe-apply timeout: %d", c.Runtime.SafeApplySeconds)
	}
}

func BenchmarkDecodeManagedScale(b *testing.B) {
	data := []byte(validTOML)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode(data); err != nil {
			b.Fatal(err)
		}
	}
}

func TestValidateRequiresExactCanonicalStatePaths(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.State.Database = "/tmp/nftfw/generation-state/../generation-state/state.db"
	if err := Validate(c); err == nil {
		t.Fatal("non-canonical generation database path accepted")
	}
	c, err = Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.State.ProvenanceLedger = "/tmp/nftfw/generation-state/../provenance-ledger.db"
	if err := Validate(c); err == nil {
		t.Fatal("non-canonical provenance ledger path accepted")
	}
	c, err = Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.State.Directory = "/tmp/nft%66w"
	c.State.Database = "/tmp/nft%66w/generation-state/state.db"
	c.State.ProvenanceLedger = "/tmp/nft%66w/provenance-ledger.db"
	if err := Validate(c); err == nil {
		t.Fatal("percent-encoded state root accepted")
	}
}

func TestValidateSafeApplyTimeoutBounds(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	for _, seconds := range []int{29, 601} {
		c.Runtime.SafeApplySeconds = seconds
		if err := Validate(c); err == nil {
			t.Fatalf("unsafe safe-apply timeout %d accepted", seconds)
		}
	}
	for _, seconds := range []int{30, 600} {
		c.Runtime.SafeApplySeconds = seconds
		if err := Validate(c); err != nil {
			t.Fatalf("safe-apply timeout %d rejected: %v", seconds, err)
		}
	}
}

func TestValidateRejectsUnsafeTCPMSS(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.WireGuard.TCPMSS = 535
	if err := Validate(c); err == nil {
		t.Fatal("undersized TCP MSS accepted")
	}
}

func TestValidateAcceptsAnyProtocolWithoutPorts(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.Services = append(c.Services, Service{Name: "all-outbound", Protocol: "any"})
	c.Policies = append(c.Policies, Policy{
		Name: "host-all-outbound", From: "host", To: "any",
		Service: "all-outbound", Action: "allow",
	})
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	c.Services[len(c.Services)-1].Ports = []int{443}
	if err := Validate(c); err == nil {
		t.Fatal("any service with ports was accepted")
	}
}

func TestValidateTrustedServicesAreExplicitAndTyped(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.Runtime.TrustedServices = []string{"ssh"}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	c.Runtime.TrustedServices = []string{"missing"}
	if err := Validate(c); err == nil {
		t.Fatal("unknown trusted service accepted")
	}
	c.Runtime.TrustedServices = []string{"ssh", "ssh"}
	if err := Validate(c); err == nil {
		t.Fatal("duplicate trusted service accepted")
	}
}
func TestValidateRejectsSlashZero(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.Zones[0].Networks = []string{"0.0.0.0/0"}
	if err := Validate(c); err == nil {
		t.Fatal("/0 accepted")
	}
}
func TestLoadRejectsWritableConfig(t *testing.T) {
	p := writeConfig(t, validTOML)
	if err := os.Chmod(p, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("writable config accepted")
	}
}

func TestLoadRejectsWritableParent(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "nftfw.toml")
	if err := os.WriteFile(path, []byte(validTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("configuration in group-writable parent accepted")
	}
}

func TestValidateRejectsUnsupportedNonStrictMode(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.System.StrictVPN = false
	if err := Validate(c); err == nil {
		t.Fatal("non-strict mode was accepted even though the compiler enforces strict egress")
	}
}

func TestValidateRejectsAmbiguousZonesAndPolicies(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.Zones = append(c.Zones, Zone{Name: "other", Networks: []string{"192.168.1.128/25"}})
	if err := Validate(c); err == nil {
		t.Fatal("overlapping zones accepted")
	}
	c, _ = Load(writeConfig(t, validTOML))
	c.Policies = append(c.Policies, Policy{Name: "duplicate", From: "lan", To: "host", Service: "ssh", Action: "deny"})
	if err := Validate(c); err == nil {
		t.Fatal("duplicate policy tuple accepted")
	}
}

func TestValidateRejectsUnknownAndEmptyInterfaceZones(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.Interfaces[0].Zone = "missing"
	if err := Validate(c); err == nil {
		t.Fatal("unknown interface zone accepted")
	}
	c, _ = Load(writeConfig(t, validTOML))
	c.Zones = append(c.Zones, Zone{Name: "empty"})
	if err := Validate(c); err == nil {
		t.Fatal("empty zone accepted")
	}
}

func TestValidateRejectsInterfaceAssignedToMultipleZones(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.Interfaces[0].Zone = "wan"
	c.Zones = append(c.Zones, Zone{Name: "wan"})
	c.Zones[0].Interfaces = []string{"eth0"}
	if err := Validate(c); err == nil {
		t.Fatal("uplink assigned to both wan and lan zones was accepted")
	} else if !strings.Contains(err.Error(), `interface "eth0" is assigned to multiple zones`) {
		t.Fatalf("unexpected cross-zone validation error: %v", err)
	}
}

func TestValidateAcceptsDuplicateSameZoneInterfaceDeclaration(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.Interfaces[0].Zone = "wan"
	c.Zones = append(c.Zones, Zone{Name: "wan", Interfaces: []string{"eth0", "eth0"}})
	if err := Validate(c); err != nil {
		t.Fatalf("duplicate declarations of the same zone membership were rejected: %v", err)
	}
}

func TestValidateThreatFeedURLExcludesCredentialsQueryAndFragment(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.Integrations.ThreatFeed = true
	c.ThreatFeeds = []ThreatFeedConfig{{Name: "example", URL: "https://feeds.example.invalid/addresses.txt"}}
	if err := Validate(c); err != nil {
		t.Fatalf("plain HTTPS threat feed URL was rejected: %v", err)
	}

	for _, rawURL := range []string{
		"https://user:password@feeds.example.invalid/addresses.txt",
		"https://feeds.example.invalid/addresses.txt?token=secret",
		"https://feeds.example.invalid/addresses.txt?",
		"https://feeds.example.invalid/addresses.txt#section",
		"https://feeds.example.invalid/addresses.txt#",
	} {
		c.ThreatFeeds[0].URL = rawURL
		if err := Validate(c); err == nil {
			t.Errorf("unsafe threat feed URL %q was accepted", rawURL)
		}
	}
}

func TestValidateRejectsHostPolicyToUplinkInterfaceZone(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.Zones = append(c.Zones, Zone{Name: "physical", Interfaces: []string{"eth0"}})
	c.Policies = append(c.Policies, Policy{Name: "host-physical", From: "host", To: "physical", Service: "ssh", Action: "allow"})
	if err := Validate(c); err == nil {
		t.Fatal("host output policy using the physical uplink as a destination zone was accepted")
	}
}

func TestValidateNATSchema(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.NAT = []NATRule{{Name: "web", Source: "any", ExternalInterface: "eth0", Protocol: "tcp", ExternalPort: 8443, Destination: "172.19.0.5", DestinationPort: 443}}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	c.NAT = append(c.NAT, NATRule{Name: "duplicate", Source: "any", ExternalInterface: "eth0", Protocol: "tcp", ExternalPort: 8443, Destination: "172.19.0.6", DestinationPort: 443})
	if err := Validate(c); err == nil {
		t.Fatal("conflicting NAT binding accepted")
	}
}

func TestValidateRequiresUniqueExplicitProvenanceIDs(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []uint8{0, 255} {
		c.Interfaces[0].ProvenanceID = invalid
		if err := Validate(c); err == nil {
			t.Fatalf("invalid provenance id %d accepted", invalid)
		}
	}
	for _, invalid := range []string{"-1", "256"} {
		malformed := strings.Replace(validTOML, "provenance_id = 1", "provenance_id = "+invalid, 1)
		if _, err := Load(writeConfig(t, malformed)); err == nil {
			t.Fatalf("out-of-range TOML provenance id %s decoded into uint8", invalid)
		}
	}
	c, _ = Load(writeConfig(t, validTOML))
	c.Interfaces[1].ProvenanceID = c.Interfaces[0].ProvenanceID
	if err := Validate(c); err == nil {
		t.Fatal("duplicate provenance id accepted")
	}
}

func TestValidateDockerStableTupleAndVPNNAT(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.Interfaces = append(c.Interfaces, Interface{
		Name: "br-media", Role: "container", Zone: "containers", ProvenanceID: 3,
		CIDRs: []string{"172.19.0.0/16", "fd00:19::/64"},
	})
	c.Zones = append(c.Zones, Zone{Name: "containers", Interfaces: []string{"br-media"}})
	c.Integrations.DockerEnabled = true
	c.DockerNetworks = []DockerNetwork{{
		Name: "media", Driver: "bridge", BridgeInterface: "br-media",
		Subnets: []string{"172.19.0.0/16", "fd00:19::/64"}, Gateways: []string{"172.19.0.1", "fd00:19::1"},
	}}
	c.NAT = []NATRule{{Name: "public-web", Source: "any", ExternalInterface: "wg0", Protocol: "tcp", ExternalPort: 443, Destination: "172.19.0.5", DestinationPort: 443}}
	if err := Validate(c); err != nil {
		t.Fatalf("valid Docker tuple or VPN NAT rejected: %v", err)
	}

	mutations := []struct {
		name string
		edit func(*Config)
	}{
		{"missing bridge option", func(c *Config) { c.DockerNetworks[0].BridgeInterface = "" }},
		{"wrong driver", func(c *Config) { c.DockerNetworks[0].Driver = "overlay" }},
		{"undeclared bridge", func(c *Config) { c.DockerNetworks[0].BridgeInterface = "br-other" }},
		{"subnet drift", func(c *Config) { c.DockerNetworks[0].Subnets[0] = "172.20.0.0/16" }},
		{"gateway drift", func(c *Config) { c.DockerNetworks[0].Gateways[0] = "172.20.0.1" }},
		{"missing gateway", func(c *Config) { c.DockerNetworks[0].Gateways = c.DockerNetworks[0].Gateways[:1] }},
	}
	for _, mutation := range mutations {
		candidate := c
		candidate.Interfaces = append([]Interface(nil), c.Interfaces...)
		candidate.DockerNetworks = append([]DockerNetwork(nil), c.DockerNetworks...)
		candidate.DockerNetworks[0].Subnets = append([]string(nil), c.DockerNetworks[0].Subnets...)
		candidate.DockerNetworks[0].Gateways = append([]string(nil), c.DockerNetworks[0].Gateways...)
		mutation.edit(&candidate)
		if err := Validate(candidate); err == nil {
			t.Errorf("%s accepted", mutation.name)
		}
	}
}

func TestWireGuardBootstrapRequiresHostPrefixes(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.WireGuard.BootstrapIPs = []string{"198.51.100.0/24"}
	if err := Validate(c); err == nil {
		t.Fatal("broad IPv4 bootstrap prefix accepted")
	}
	c.WireGuard.BootstrapIPs = nil
	c.WireGuard.BootstrapIPsV6 = []string{"2001:db8::/64"}
	if err := Validate(c); err == nil {
		t.Fatal("broad IPv6 bootstrap prefix accepted")
	}
}

func TestWireGuardBootstrapRequiresNonzeroMarkAndUnicast(t *testing.T) {
	c, err := Load(writeConfig(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	c.WireGuard.Fwmark = "0"
	if err := Validate(c); err == nil {
		t.Fatal("zero WireGuard fwmark accepted")
	}
	c.WireGuard.Fwmark = "0xca6c"
	for _, address := range []string{"127.0.0.1/32", "224.0.0.1/32"} {
		c.WireGuard.BootstrapIPs = []string{address}
		if err := Validate(c); err == nil {
			t.Fatalf("unsafe bootstrap address %s accepted", address)
		}
	}
}

func TestValidateBoundaryMatrix(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"ipv6 mode", func(c *Config) { c.System.IPv6Mode = "automatic" }},
		{"block claim minimum", func(c *Config) { c.Runtime.MaxBlockClaims = 0 }},
		{"set member maximum", func(c *Config) { c.Runtime.MaxSetMembers = 1000001 }},
		{"trusted service count", func(c *Config) {
			c.Runtime.TrustedServices = make([]string, 33)
		}},
		{"relative state root", func(c *Config) {
			c.State.Directory = "relative"
			c.State.Database = "relative/generation-state/state.db"
			c.State.ProvenanceLedger = "relative/provenance-ledger.db"
		}},
		{"notifications", func(c *Config) { c.Integrations.Notifications = true }},
		{"docker toggle mismatch", func(c *Config) { c.Integrations.DockerEnabled = true }},
		{"threat toggle mismatch", func(c *Config) { c.Integrations.ThreatFeed = true }},
		{"geo toggle mismatch", func(c *Config) { c.Integrations.GeoIP = true }},
		{"no interfaces", func(c *Config) { c.Interfaces = nil }},
		{"invalid interface name", func(c *Config) { c.Interfaces[0].Name = "bad/name" }},
		{"invalid interface role", func(c *Config) { c.Interfaces[0].Role = "internet" }},
		{"duplicate interface", func(c *Config) {
			c.Interfaces[1].Name = c.Interfaces[0].Name
		}},
		{"no uplink", func(c *Config) { c.Interfaces[0].Role = "lan" }},
		{"duplicate zone", func(c *Config) {
			c.Zones = append(c.Zones, c.Zones[0])
		}},
		{"zone unknown interface", func(c *Config) {
			c.Zones[0].Interfaces = []string{"missing0"}
		}},
		{"invalid service name", func(c *Config) { c.Services[0].Name = "bad/name" }},
		{"duplicate service", func(c *Config) {
			c.Services = append(c.Services, c.Services[0])
		}},
		{"invalid service protocol", func(c *Config) { c.Services[0].Protocol = "sctp" }},
		{"duplicate service port", func(c *Config) { c.Services[0].Ports = []int{22, 22} }},
		{"missing service ports", func(c *Config) { c.Services[0].Ports = nil }},
		{"invalid policy action", func(c *Config) { c.Policies[0].Action = "log" }},
		{"unknown policy source", func(c *Config) { c.Policies[0].From = "missing" }},
		{"unknown policy destination", func(c *Config) { c.Policies[0].To = "missing" }},
		{"unknown policy service", func(c *Config) { c.Policies[0].Service = "missing" }},
		{"missing WireGuard interface", func(c *Config) { c.WireGuard.Interface = "" }},
		{"WireGuard equals uplink", func(c *Config) { c.WireGuard.Interface = "eth0" }},
		{"WireGuard role mismatch", func(c *Config) { c.Interfaces[1].Role = "lan" }},
		{"WireGuard port", func(c *Config) { c.WireGuard.EndpointPort = 0 }},
		{"WireGuard mark format", func(c *Config) { c.WireGuard.Fwmark = "xyz" }},
		{"WireGuard mark overflow", func(c *Config) { c.WireGuard.Fwmark = "0x100000000" }},
		{"WireGuard keep recent", func(c *Config) { c.WireGuard.KeepRecent = 17 }},
		{"WireGuard hostname", func(c *Config) { c.WireGuard.EndpointHost = "-bad.example" }},
		{"WireGuard bootstrap hostname", func(c *Config) {
			c.WireGuard.BootstrapHosts = []string{"bad..example"}
		}},
		{"WireGuard config path", func(c *Config) {
			c.WireGuard.ConfigPath = "/etc/wireguard/other.conf"
		}},
		{"WireGuard handshake minimum", func(c *Config) {
			c.WireGuard.HandshakeSecond = 29
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, err := Load(writeConfig(t, validTOML))
			if err != nil {
				t.Fatal(err)
			}
			test.edit(&c)
			if err := Validate(c); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestHostnameAndHostPrefixHelpers(t *testing.T) {
	for _, hostname := range []string{"vpn.example", "a-b.example.test", "localhost"} {
		if !validHostname(hostname) {
			t.Fatalf("valid hostname rejected: %s", hostname)
		}
	}
	for _, hostname := range []string{"", "-vpn.example", "vpn-.example", "vpn..example", strings.Repeat("a", 254)} {
		if validHostname(hostname) {
			t.Fatalf("invalid hostname accepted: %q", hostname)
		}
	}
	_, host4, _ := net.ParseCIDR("192.0.2.1/32")
	_, network4, _ := net.ParseCIDR("192.0.2.0/24")
	_, host6, _ := net.ParseCIDR("2001:db8::1/128")
	if bitsHost(host4) != 1 || bitsHost(network4) != 0 ||
		bitsHost(host6) != 1 || bitsHost(&net.IPNet{}) != 0 {
		t.Fatal("host-prefix classification changed")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(validTOML))
	f.Add([]byte("[system]\nunknown=true\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Decode(data)
	})
}
