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

func FuzzDecode(f *testing.F) {
	f.Add([]byte(validTOML))
	f.Add([]byte("[system]\nunknown=true\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Decode(data)
	})
}
