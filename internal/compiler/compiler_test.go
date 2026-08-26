package compiler

import (
	"fmt"
	"strings"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/policy"
)

func testEffective(t testing.TB) policy.Effective {
	t.Helper()
	c := config.Defaults()
	c.Interfaces = []config.Interface{{Name: "eth0", Role: "uplink", ProvenanceID: 1}, {Name: "wg0", Role: "vpn", ProvenanceID: 2}}
	c.Zones = []config.Zone{{Name: "lan", Networks: []string{"192.168.1.0/24"}}}
	c.Services = []config.Service{{Name: "ssh", Protocol: "tcp", Ports: []int{22}}}
	c.Policies = []config.Policy{{Name: "lan-ssh", From: "lan", To: "host", Service: "ssh", Action: "allow"}}
	e, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func BenchmarkCompileStandard(b *testing.B) {
	effective := testEffective(b)
	input := Input{Policy: effective, BootstrapV4: []string{"198.51.100.10/32"}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Compile(input, 1); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompileMaximumPolicies(b *testing.B) {
	c := config.Defaults()
	c.Interfaces = []config.Interface{
		{Name: "eth0", Role: "uplink", ProvenanceID: 1},
		{Name: "wg0", Role: "vpn", ProvenanceID: 2},
	}
	for zone := 0; zone < 250; zone++ {
		c.Zones = append(c.Zones, config.Zone{
			Name:     fmt.Sprintf("zone-%03d", zone),
			Networks: []string{fmt.Sprintf("10.%d.%d.1/32", zone/256, zone%256)},
		})
	}
	for service := 0; service < 40; service++ {
		c.Services = append(c.Services, config.Service{
			Name:     fmt.Sprintf("service-%02d", service),
			Protocol: "tcp", Ports: []int{10000 + service},
		})
	}
	for zone := 0; zone < 250; zone++ {
		for service := 0; service < 40; service++ {
			c.Policies = append(c.Policies, config.Policy{
				Name: fmt.Sprintf("policy-%03d-%02d", zone, service),
				From: fmt.Sprintf("zone-%03d", zone), To: "any",
				Service: fmt.Sprintf("service-%02d", service), Action: "allow",
			})
		}
	}
	effective, err := policy.Compile(c)
	if err != nil {
		b.Fatal(err)
	}
	input := Input{Policy: effective}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Compile(input, 1); err != nil {
			b.Fatal(err)
		}
	}
}
func TestCompileOwnsOnlyNamedTables(t *testing.T) {
	a, err := Compile(Input{Policy: testEffective(t), BootstrapV4: []string{"198.51.100.10/32"}}, 7)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(a.Script, "flush ruleset") {
		t.Fatal("flush ruleset emitted")
	}
	for _, name := range []string{"table inet nftfw_filter", "table ip nftfw_nat", "table ip6 nftfw_filter6", "nftfw:input-default-deny", "nftfw:provenance-tag-input:eth0", "nftfw:provenance-tag-output:wg0", "nftfw:provenance-tag-forward:wg0", "nftfw:provenance-reply-output:wg0", "nftfw:provenance-reply-forward:eth0"} {
		if !strings.Contains(a.Script, name) {
			t.Errorf("missing %s", name)
		}
	}
	if !strings.Contains(a.Script, `oifname "eth0" ct mark & 0xff000000 == 0x01000000 ct direction reply ct state established,related accept comment "nftfw:provenance-reply-output:eth0"`) ||
		!strings.Contains(a.Script, `oifname "wg0" ct mark & 0xff000000 == 0x02000000 ct direction reply ct state established,related accept comment "nftfw:provenance-reply-output:wg0"`) {
		t.Fatal("exact per-ingress host reply rules missing")
	}
	if strings.Contains(a.Script, `ct state established,related accept comment "nftfw:forward-established"`) || strings.Contains(a.Script, `ct state established,related accept comment "nftfw:input-established"`) {
		t.Fatal("broad established exception emitted")
	}
	if strings.Index(a.Script, "nftfw:provenance-reply-forward:eth0") > strings.Index(a.Script, "nftfw:forward-physical-deny") {
		t.Fatal("published-service replies must be admitted before physical egress deny")
	}
	if strings.Count(a.Script, "nftfw:vpn-only-egress") != 1 {
		t.Fatal("unexpected VPN egress rule count")
	}
	tag := `iifname "eth0" ct direction original ct mark & 0xff000000 == 0x00000000 ct mark set (ct mark & 0x00ffffff) | 0x01000000 counter comment "nftfw:provenance-tag-input:eth0"`
	if !strings.Contains(a.Script, tag) || strings.Contains(tag, " accept ") {
		t.Fatal("write-once lower-bit-preserving provenance tag missing")
	}
}

func TestAnyProtocolOutboundIsPinnedToVPN(t *testing.T) {
	effective := testEffective(t)
	effective.Config.Services = append(effective.Config.Services, config.Service{Name: "all-outbound", Protocol: "any"})
	effective.Config.Policies = append(effective.Config.Policies, config.Policy{
		Name: "host-all-outbound", From: "host", To: "any",
		Service: "all-outbound", Action: "allow",
	})
	compiled, err := policy.Compile(effective.Config)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Compile(Input{Policy: compiled}, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"meta nfproto ipv4", "meta nfproto ipv6"} {
		want := family + ` oifname "wg0"  accept comment "nftfw-policy:host-all-outbound"`
		if !strings.Contains(artifact.Script, want) {
			t.Fatalf("all-protocol VPN-pinned rule missing %q", want)
		}
	}
}

func TestPublicVPNHostRepliesAreProvenancePinnedForTCPAndUDP(t *testing.T) {
	c := config.Defaults()
	c.WireGuard.Interface = "ovpn0"
	c.Interfaces = []config.Interface{{Name: "eth0", Role: "uplink", ProvenanceID: 1}, {Name: "ovpn0", Role: "vpn", Zone: "public-vpn", ProvenanceID: 2}}
	c.Zones = []config.Zone{{Name: "public-vpn", Interfaces: []string{"ovpn0"}}}
	c.Services = []config.Service{
		{Name: "https", Protocol: "tcp", Ports: []int{443}},
		{Name: "quic", Protocol: "udp", Ports: []int{443}},
	}
	c.Policies = []config.Policy{
		{Name: "public-https", From: "public-vpn", To: "host", Service: "https", Action: "allow"},
		{Name: "public-quic", From: "public-vpn", To: "host", Service: "quic", Action: "allow"},
	}
	e, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Compile(Input{Policy: e}, 1)
	if err != nil {
		t.Fatal(err)
	}
	input := a.Script[strings.Index(a.Script, "chain input"):strings.Index(a.Script, "chain output")]
	output := a.Script[strings.Index(a.Script, "chain output"):strings.Index(a.Script, "chain forward")]
	for _, want := range []string{
		`iifname "ovpn0" ct direction original ct mark & 0xff000000 == 0x00000000 ct mark set (ct mark & 0x00ffffff) | 0x02000000`,
		`iifname "ovpn0" meta nfproto ipv4 tcp dport { 443 } accept comment "nftfw-policy:public-https"`,
		`iifname "ovpn0" meta nfproto ipv4 udp dport { 443 } accept comment "nftfw-policy:public-quic"`,
	} {
		if !strings.Contains(input, want) {
			t.Errorf("input is missing %q", want)
		}
	}
	if strings.Index(input, "nftfw:provenance-tag-input:ovpn0") > strings.Index(input, "nftfw-policy:public-https") {
		t.Fatal("VPN ingress was accepted before provenance tagging")
	}
	if !strings.Contains(output, `oifname "ovpn0" ct mark & 0xff000000 == 0x02000000 ct direction reply ct state established,related accept`) {
		t.Fatal("VPN reply path is missing exact VPN provenance")
	}
	if !strings.Contains(output, `oifname "eth0" ct mark & 0xff000000 == 0x01000000 ct direction reply ct state established,related accept`) || strings.Contains(output, `oifname "eth0" ct direction reply ct state established,related accept`) {
		t.Fatal("physical reply path is not restricted to physical ingress provenance")
	}
}

func TestHostOriginatedInputRepliesRequireDeclaredIngress(t *testing.T) {
	a, err := Compile(Input{Policy: testEffective(t)}, 1)
	if err != nil {
		t.Fatal(err)
	}
	input := a.Script[strings.Index(a.Script, "chain input"):strings.Index(a.Script, "chain output")]
	output := a.Script[strings.Index(a.Script, "chain output"):strings.Index(a.Script, "chain forward")]
	for index, interfaceName := range []string{"eth0", "wg0"} {
		encoded := []string{"0x01000000", "0x02000000"}[index]
		want := `iifname "` + interfaceName + `" ct mark & 0xff000000 == ` + encoded + ` ct direction reply ct state established,related accept comment "nftfw:input-reply-only"`
		if !strings.Contains(input, want) {
			t.Fatalf("declared-interface input reply rule %q missing: %s", want, input)
		}
		outputTag := `oifname "` + interfaceName + `" ct direction original ct mark & 0xff000000 == 0x00000000 ct mark set (ct mark & 0x00ffffff) | ` + encoded + ` counter comment "nftfw:provenance-tag-output:` + interfaceName + `"`
		if !strings.Contains(output, outputTag) {
			t.Fatalf("host-output provenance rule %q missing: %s", outputTag, output)
		}
	}
	if strings.Contains(input, "\n        ct direction reply ct state established,related accept") {
		t.Fatal("input contains a reply exception that can match an undeclared ingress")
	}
	if got := strings.Count(input, `comment "nftfw:input-reply-only"`); got != 2 {
		t.Fatalf("input reply rule count=%d, want one per declared interface", got)
	}
}

func TestRoutedContainerRulesBindBridgeSubnetAndIngressProvenance(t *testing.T) {
	c := config.Defaults()
	c.WireGuard.Interface = "ovpn0"
	c.Interfaces = []config.Interface{
		{Name: "eth0", Role: "uplink", ProvenanceID: 1},
		{Name: "ovpn0", Role: "vpn", Zone: "public-vpn", ProvenanceID: 2},
		{Name: "br-media", Role: "container", Zone: "containers", CIDRs: []string{"172.19.0.0/16"}, ProvenanceID: 3},
	}
	c.Zones = []config.Zone{
		{Name: "public-vpn", Interfaces: []string{"ovpn0"}},
		{Name: "containers", Networks: []string{"172.19.0.0/16"}, Interfaces: []string{"br-media"}},
	}
	c.Services = []config.Service{{Name: "https", Protocol: "tcp", Ports: []int{443}}}
	c.Policies = []config.Policy{{Name: "vpn-container-web", From: "public-vpn", To: "containers", Service: "https", Action: "allow"}}
	c.NAT = []config.NATRule{{Name: "vpn-web", Source: "any", ExternalInterface: "ovpn0", Protocol: "tcp", ExternalPort: 443, Destination: "172.19.0.5", DestinationPort: 443}}
	c.Integrations.DockerEnabled = true
	c.DockerNetworks = []config.DockerNetwork{{Name: "media", Driver: "bridge", BridgeInterface: "br-media", Subnets: []string{"172.19.0.0/16"}, Gateways: []string{"172.19.0.1"}}}
	e, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Compile(Input{Policy: e, DockerNets: []string{"172.19.0.0/16"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`iifname "br-media" ip saddr 172.19.0.0/16 oifname "ovpn0" tcp flags syn`,
		`iifname "ovpn0" oifname "br-media" ip daddr 172.19.0.0/16 tcp flags syn`,
		`iifname "br-media" ip saddr 172.19.0.0/16 oifname "eth0" drop`,
		`iifname "br-media" ip saddr 172.19.0.0/16 oifname "ovpn0" masquerade`,
		`oifname "ovpn0" ct mark & 0xff000000 == 0x02000000 ct direction reply ct state established,related accept`,
	} {
		if !strings.Contains(a.Script, want) {
			t.Errorf("compiled routed-container policy is missing %q", want)
		}
	}
	if strings.Contains(a.Script, `ip saddr @docker_nets oifname "ovpn0"`) {
		t.Fatal("container authorization relies on an unbound CIDR set")
	}
}

func FuzzCompileRuntimePrefix(f *testing.F) {
	f.Add("203.0.113.8/32", uint64(1))
	f.Add("not-a-prefix", uint64(2))
	f.Fuzz(func(t *testing.T, raw string, generation uint64) {
		_, _ = Compile(Input{Policy: testEffective(t), BlockedV4: []string{raw}}, generation)
	})
}

func TestCompileRejectsBroadRuntimeBootstrapPrefix(t *testing.T) {
	if _, err := Compile(Input{Policy: testEffective(t), BootstrapV4: []string{"198.51.100.0/24"}}, 1); err == nil {
		t.Fatal("broad runtime bootstrap prefix accepted")
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
	e := testEffective(t)
	e.Config.Runtime.TrustedServices = []string{"ssh"}
	e.Config.Services = append(e.Config.Services, config.Service{Name: "untrusted-web", Protocol: "tcp", Ports: []int{8096}})
	e.Svcs["untrusted-web"] = config.Service{Name: "untrusted-web", Protocol: "tcp", Ports: []int{8096}}
	a, err := Compile(Input{Policy: e, BlockedV4: []string{"203.0.113.9/32"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Script, "set trusted_v4") || !strings.Contains(a.Script, "nftfw:trusted-services-v4") {
		t.Fatal("trusted set/rule missing")
	}
	trustedSection := a.Script[strings.Index(a.Script, "set trusted_v4"):strings.Index(a.Script, "set trusted_v6")]
	if strings.Contains(trustedSection, "elements =") {
		t.Fatal("committed generation contains a replayable trusted lease")
	}
	if !strings.Contains(a.Script, "elements = { 203.0.113.9/32 }") {
		t.Fatal("blocked set missing")
	}
	if strings.Contains(a.Script, "8096") {
		t.Fatal("temporary access opened a service absent from runtime.trusted_services")
	}
	trusted := strings.Index(a.Script, "nftfw:trusted-services-v4-tcp")
	established := strings.Index(a.Script, "nftfw:input-reply-only")
	blocked := strings.Index(a.Script, "nftfw:block-v4")
	if trusted < 0 || established < 0 || blocked < 0 || trusted > established || established > blocked {
		t.Fatalf("trusted recovery and established management must precede dynamic feed blocks: trusted=%d established=%d blocked=%d", trusted, established, blocked)
	}
}

func TestThreatBlocksCannotBreakWireGuardBootstrapOrEstablishedUplinkReplies(t *testing.T) {
	a, err := Compile(Input{
		Policy: testEffective(t), BlockedV4: []string{"8.8.8.0/24"},
		BootstrapV4: []string{"8.8.8.8/32"},
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	output := a.Script[strings.Index(a.Script, "chain output"):strings.Index(a.Script, "chain forward")]
	for _, marker := range []string{"nftfw:provenance-reply-output:eth0", "nftfw:wg-bootstrap-v4"} {
		if !strings.Contains(output, marker) || strings.Index(output, marker) > strings.Index(output, "nftfw:block-v4") {
			t.Fatalf("%s must precede dynamic output blocks", marker)
		}
	}
	forward := a.Script[strings.Index(a.Script, "chain forward"):]
	if strings.Index(forward, "nftfw:provenance-reply-forward:eth0") > strings.Index(forward, "nftfw:block-forward-source-v4") {
		t.Fatal("established published-service replies must precede dynamic forward blocks")
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

func TestPublicNamedDestinationIsPinnedToVPN(t *testing.T) {
	c := config.Defaults()
	c.Interfaces = []config.Interface{{Name: "eth0", Role: "uplink", ProvenanceID: 1}, {Name: "wg0", Role: "vpn", ProvenanceID: 2}}
	c.Zones = []config.Zone{{Name: "external-service", Networks: []string{"203.0.113.0/24"}}}
	c.Services = []config.Service{{Name: "https", Protocol: "tcp", Ports: []int{443}}}
	c.Policies = []config.Policy{{Name: "host-external", From: "host", To: "external-service", Service: "https", Action: "allow"}}
	e, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Compile(Input{Policy: e}, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := `ip daddr 203.0.113.0/24 oifname "wg0" tcp dport { 443 } accept`
	if !strings.Contains(a.Script, want) {
		t.Fatalf("public destination was not pinned to WireGuard: %s", a.Script)
	}
}

func TestContainerIPv6KillSwitchSet(t *testing.T) {
	e := testEffective(t)
	e.Config.Interfaces = append(e.Config.Interfaces, config.Interface{Name: "br-media", Role: "container", ProvenanceID: 3, CIDRs: []string{"fd00:19::/64"}})
	e.Config.Integrations.DockerEnabled = true
	e.Config.DockerNetworks = []config.DockerNetwork{{Name: "media", Driver: "bridge", BridgeInterface: "br-media", Subnets: []string{"fd00:19::/64"}, Gateways: []string{"fd00:19::1"}}}
	a, err := Compile(Input{Policy: e, DockerNets6: []string{"fd00:19::/64"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"set docker_nets6", "fd00:19::/64", `iifname "br-media" ip6 saddr fd00:19::/64 oifname "eth0" drop`, "nftfw:container-physical-deny-v6:br-media"} {
		if !strings.Contains(a.Script, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestInterfaceOnlyZoneCompilesToInterfaceSelectors(t *testing.T) {
	c := config.Defaults()
	c.Interfaces = []config.Interface{{Name: "eth0", Role: "uplink", ProvenanceID: 1}, {Name: "wg0", Role: "vpn", ProvenanceID: 2}, {Name: "lan0", Role: "lan", Zone: "lan", ProvenanceID: 3}}
	c.Zones = []config.Zone{{Name: "lan", Interfaces: []string{"lan0"}}}
	c.Services = []config.Service{{Name: "ssh", Protocol: "tcp", Ports: []int{22}}}
	c.Policies = []config.Policy{{Name: "lan-ssh", From: "lan", To: "host", Service: "ssh", Action: "allow"}}
	e, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Compile(Input{Policy: e}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Script, `iifname "lan0" meta nfproto ipv4 tcp dport { 22 } accept`) || !strings.Contains(a.Script, `iifname "lan0" meta nfproto ipv6 tcp dport { 22 } accept`) {
		t.Fatalf("interface-only zone was not compiled: %s", a.Script)
	}
	if strings.Count(a.Script, `iifname "lan0" meta nfproto ipv4 tcp dport { 22 } accept`) != 1 || strings.Count(a.Script, `iifname "lan0" meta nfproto ipv6 tcp dport { 22 } accept`) != 1 {
		t.Fatalf("duplicate same-zone declarations emitted duplicate interface selectors: %s", a.Script)
	}
}

func TestZoneNetworksAndInterfacesCompileAsConjunction(t *testing.T) {
	c := config.Defaults()
	c.Interfaces = []config.Interface{{Name: "eth0", Role: "uplink", ProvenanceID: 1}, {Name: "wg0", Role: "vpn", ProvenanceID: 2}, {Name: "lan0", Role: "lan", Zone: "lan", ProvenanceID: 3}}
	c.Zones = []config.Zone{{Name: "lan", Networks: []string{"192.168.1.0/24"}, Interfaces: []string{"lan0"}}}
	c.Services = []config.Service{{Name: "ssh", Protocol: "tcp", Ports: []int{22}}}
	c.Policies = []config.Policy{{Name: "lan-ssh", From: "lan", To: "host", Service: "ssh", Action: "allow"}}
	e, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Compile(Input{Policy: e}, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := `iifname "lan0" ip saddr 192.168.1.0/24 tcp dport { 22 } accept comment "nftfw-policy:lan-ssh"`
	if !strings.Contains(a.Script, want) {
		t.Fatalf("zone interface/network conjunction missing: %s", a.Script)
	}
	if strings.Contains(a.Script, `        ip saddr 192.168.1.0/24 tcp dport { 22 } accept`) {
		t.Fatal("network-only LAN rule can be spoofed through another ingress")
	}
}

func TestNATRequiresObservedContainerTargetAndDoesNotAllowForwarding(t *testing.T) {
	e := testEffective(t)
	e.Config.Interfaces = append(e.Config.Interfaces, config.Interface{Name: "br-media", Role: "container", ProvenanceID: 3, CIDRs: []string{"172.19.0.0/16"}})
	e.Config.Integrations.DockerEnabled = true
	e.Config.DockerNetworks = []config.DockerNetwork{{Name: "media", Driver: "bridge", BridgeInterface: "br-media", Subnets: []string{"172.19.0.0/16"}, Gateways: []string{"172.19.0.1"}}}
	e.Config.NAT = []config.NATRule{{Name: "web", Source: "any", ExternalInterface: "eth0", Protocol: "tcp", ExternalPort: 8443, Destination: "172.19.0.5", DestinationPort: 443}}
	if _, err := Compile(Input{Policy: e}, 1); err == nil {
		t.Fatal("NAT destination outside observed container networks accepted")
	}
	a, err := Compile(Input{Policy: e, DockerNets: []string{"172.19.0.0/16"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Script, `tcp dport 8443 dnat to 172.19.0.5:443 comment "nftfw-nat:web"`) {
		t.Fatalf("DNAT rule missing: %s", a.Script)
	}
	if strings.Contains(a.Script, `nftfw-nat:web" accept`) {
		t.Fatal("DNAT rule implicitly allowed forwarding")
	}
}

func TestNATSourceZoneRetainsInterfaceAndNetworkConjunction(t *testing.T) {
	c := config.Defaults()
	c.Interfaces = []config.Interface{
		{Name: "eth0", Role: "uplink", ProvenanceID: 1},
		{Name: "wg0", Role: "vpn", ProvenanceID: 2},
		{Name: "lan0", Role: "lan", Zone: "lan", ProvenanceID: 3},
		{Name: "br-media", Role: "container", Zone: "containers", CIDRs: []string{"172.19.0.0/16"}, ProvenanceID: 4},
	}
	c.Zones = []config.Zone{
		{Name: "lan", Networks: []string{"192.168.1.0/24"}, Interfaces: []string{"lan0"}},
		{Name: "containers", Networks: []string{"172.19.0.0/16"}, Interfaces: []string{"br-media"}},
	}
	c.Services = []config.Service{{Name: "https", Protocol: "tcp", Ports: []int{443}}}
	c.Policies = []config.Policy{{Name: "lan-container-web", From: "lan", To: "containers", Service: "https", Action: "allow"}}
	c.Integrations.DockerEnabled = true
	c.DockerNetworks = []config.DockerNetwork{{Name: "media", Driver: "bridge", BridgeInterface: "br-media", Subnets: []string{"172.19.0.0/16"}, Gateways: []string{"172.19.0.1"}}}
	c.NAT = []config.NATRule{{Name: "lan-web", Source: "lan", ExternalInterface: "lan0", Protocol: "tcp", ExternalPort: 8443, Destination: "172.19.0.5", DestinationPort: 443}}
	e, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Compile(Input{Policy: e, DockerNets: []string{"172.19.0.0/16"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := `iifname "lan0" ip saddr 192.168.1.0/24 tcp dport 8443 dnat to 172.19.0.5:443`
	if !strings.Contains(a.Script, want) {
		t.Fatalf("NAT source-zone interface/network conjunction missing: %s", a.Script)
	}
	if strings.Contains(a.Script, `        ip saddr 192.168.1.0/24 tcp dport 8443`) {
		t.Fatal("NAT source zone emitted a spoofable network-only selector")
	}
}
