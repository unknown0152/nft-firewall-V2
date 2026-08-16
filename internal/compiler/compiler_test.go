package compiler

import (
	"strings"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/policy"
)

func testEffective(t *testing.T) policy.Effective {
	t.Helper()
	c := config.Defaults()
	c.Interfaces = []config.Interface{{Name: "eth0", Role: "uplink"}, {Name: "wg0", Role: "vpn"}}
	c.Zones = []config.Zone{{Name: "lan", Networks: []string{"192.168.1.0/24"}}}
	c.Services = []config.Service{{Name: "ssh", Protocol: "tcp", Ports: []int{22}}}
	c.Policies = []config.Policy{{Name: "lan-ssh", From: "lan", To: "host", Service: "ssh", Action: "allow"}}
	e, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func TestCompileOwnsOnlyNamedTables(t *testing.T) {
	a, err := Compile(Input{Policy: testEffective(t), BootstrapV4: []string{"198.51.100.10/32"}}, 7)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(a.Script, "flush ruleset") {
		t.Fatal("flush ruleset emitted")
	}
	for _, name := range []string{"table inet nftfw_filter", "table ip nftfw_nat", "table ip6 nftfw_filter6", "nftfw:input-default-deny", "nftfw:container-physical-deny", "nftfw:container-vpn-mss-out-v4", "nftfw:container-vpn-mss-in-v4", "nftfw:container-path-errors-v4"} {
		if !strings.Contains(a.Script, name) {
			t.Errorf("missing %s", name)
		}
	}
	if !strings.Contains(a.Script, `oifname "eth0" ct direction reply ct state established,related accept comment "nftfw:uplink-reply-only"`) {
		t.Fatal("narrow uplink reply rule missing")
	}
	if strings.Contains(a.Script, `oifname "eth0" ct state established,related accept`) {
		t.Fatal("broad uplink established exception emitted")
	}
	if strings.Count(a.Script, "nftfw:vpn-only-egress") != 1 {
		t.Fatal("unexpected VPN egress rule count")
	}
	if !strings.Contains(a.Script, `ip saddr @docker_nets oifname "wg0" tcp flags syn tcp option maxseg size set 1360`) ||
		!strings.Contains(a.Script, `iifname "wg0" ip daddr @docker_nets tcp flags syn tcp option maxseg size set 1360`) {
		t.Fatal("bidirectional container/VPN TCP MSS clamp missing")
	}
}
func TestCompilePolicyAndIPv6Mode(t *testing.T) {
	e := testEffective(t)
	a, err := Compile(Input{Policy: e}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Script, "nftfw-policy:lan-ssh") {
		t.Fatal("policy not compiled")
	}
	if !strings.Contains(a.Script, "table ip6 nftfw_filter6") || !strings.Contains(a.Script, "priority -300") {
		t.Fatal("IPv6 early drop missing")
	}
}

func TestNativeIPv6DoesNotPreemptInetPolicy(t *testing.T) {
	e := testEffective(t)
	e.Config.System.IPv6Mode = "native"
	a, err := Compile(Input{Policy: e}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Script, "nftfw:ipv6-mode-native") {
		t.Fatal("native IPv6 marker missing")
	}
	ip6 := a.Script[strings.Index(a.Script, "table ip6 nftfw_filter6"):]
	if strings.Contains(ip6, "hook input") || strings.Contains(ip6, "hook output") {
		t.Fatal("native IPv6 table preempts the family-neutral inet policy")
	}
	if !strings.Contains(a.Script, "nftfw:ipv6-neighbor-discovery") || !strings.Contains(a.Script, "ip6 hoplimit 255") {
		t.Fatal("bounded IPv6 neighbor discovery rules missing")
	}
}
func TestCompileRejectsRuntimeSlashZero(t *testing.T) {
	_, err := Compile(Input{Policy: testEffective(t), BlockedV4: []string{"0.0.0.0/0"}}, 1)
	if err == nil {
		t.Fatal("runtime /0 accepted")
	}
}

func TestTrustedSetIsSeparateFromBlockedSet(t *testing.T) {
	a, err := Compile(Input{Policy: testEffective(t), BlockedV4: []string{"203.0.113.9/32"}, TrustedV4: []string{"198.51.100.8/32"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Script, "set trusted_v4") || !strings.Contains(a.Script, "nftfw:trusted-services-v4") {
		t.Fatal("trusted set/rule missing")
	}
	if !strings.Contains(a.Script, "elements = { 203.0.113.9/32 }") {
		t.Fatal("blocked set missing")
	}
}

func TestAnyAndDenyPoliciesCompileToMatchingRules(t *testing.T) {
	e := testEffective(t)
	e.Config.Policies = []config.Policy{
		{Name: "host-ping", From: "host", To: "any", Service: "ping", Action: "allow"},
		{Name: "deny-ssh", From: "any", To: "host", Service: "ssh", Action: "deny"},
	}
	e.Config.Services = append(e.Config.Services, config.Service{Name: "ping", Protocol: "icmp"})
	e.Svcs["ping"] = config.Service{Name: "ping", Protocol: "icmp"}
	a, err := Compile(Input{Policy: e}, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"meta nfproto ipv4", "meta nfproto ipv6", "nftfw-policy:host-ping", "nftfw-policy:deny-ssh", "drop comment \"nftfw-policy:deny-ssh\""} {
		if !strings.Contains(a.Script, want) {
			t.Errorf("compiled policy is missing %q", want)
		}
	}
	if strings.Contains(a.Script, "oifname \"wg0\" accept comment \"nftfw:vpn-only-egress\"") {
		t.Fatal("compiler emitted a broad VPN allow instead of typed output policies")
	}
}

func TestContainerIPv6KillSwitchSet(t *testing.T) {
	a, err := Compile(Input{Policy: testEffective(t), DockerNets6: []string{"fd00:19::/64"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"set docker_nets6", "fd00:19::/64", "nftfw:container-physical-deny-v6"} {
		if !strings.Contains(a.Script, want) {
			t.Errorf("missing %q", want)
		}
	}
}
