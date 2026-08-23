package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nftfw.toml")
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
[[interfaces]]
name = "wg0"
role = "vpn"
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
database = "/tmp/nftfw/state.db"
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

func FuzzDecode(f *testing.F) {
	f.Add([]byte(validTOML))
	f.Add([]byte("[system]\nunknown=true\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Decode(data)
	})
}
