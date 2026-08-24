package policy

import (
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
)

func TestExplainUsesCompilerModel(t *testing.T) {
	c := config.Defaults()
	c.Interfaces = []config.Interface{{Name: "eth0", Role: "uplink", ProvenanceID: 1}, {Name: "wg0", Role: "vpn", ProvenanceID: 2}}
	c.Zones = []config.Zone{{Name: "lan", Networks: []string{"192.168.1.0/24"}}}
	c.Services = []config.Service{{Name: "ssh", Protocol: "tcp", Ports: []int{22}}}
	c.Policies = []config.Policy{{Name: "lan-ssh", From: "lan", To: "host", Service: "ssh", Action: "allow"}}
	e, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	d := e.Explain(Query{From: "192.168.1.5", To: "host", Protocol: "tcp", Port: 22})
	if d.Action != "allow" || d.Matched == nil || d.Matched.Name != "lan-ssh" {
		t.Fatalf("unexpected allow: %#v", d)
	}
	d = e.Explain(Query{From: "lan", To: "host", Protocol: "tcp", Port: 22})
	if d.Action != "allow" || d.SourceZone != "lan" {
		t.Fatalf("named source zone was not explained: %#v", d)
	}
	d = e.Explain(Query{From: "203.0.113.5", To: "host", Protocol: "tcp", Port: 22})
	if d.Action != "deny" || d.Matched != nil {
		t.Fatalf("unexpected deny: %#v", d)
	}
}

func FuzzExplainAlwaysReturnsAVerdict(f *testing.F) {
	f.Add("192.168.1.5", "host", "tcp", 22)
	f.Add("invalid", "unknown", "udp", -1)
	f.Fuzz(func(t *testing.T, from, to, protocol string, port int) {
		c := config.Defaults()
		c.Interfaces = []config.Interface{{Name: "eth0", Role: "uplink", ProvenanceID: 1}, {Name: "wg0", Role: "vpn", ProvenanceID: 2}}
		c.Zones = []config.Zone{{Name: "lan", Networks: []string{"192.168.1.0/24"}}}
		c.Services = []config.Service{{Name: "ssh", Protocol: "tcp", Ports: []int{22}}}
		c.Policies = []config.Policy{{Name: "lan-ssh", From: "lan", To: "host", Service: "ssh", Action: "allow"}}
		e, err := Compile(c)
		if err != nil {
			t.Fatal(err)
		}
		decision := e.Explain(Query{From: from, To: to, Protocol: protocol, Port: port})
		if decision.Action != "allow" && decision.Action != "deny" {
			t.Fatalf("unexpected verdict %q", decision.Action)
		}
	})
}

func TestExplicitDenyPrecedesAllowDeterministically(t *testing.T) {
	c := config.Defaults()
	c.Interfaces = []config.Interface{{Name: "eth0", Role: "uplink", ProvenanceID: 1}, {Name: "wg0", Role: "vpn", ProvenanceID: 2}}
	c.Zones = []config.Zone{{Name: "lan", Networks: []string{"192.168.1.0/24"}}}
	c.Services = []config.Service{{Name: "ssh", Protocol: "tcp", Ports: []int{22}}}
	c.Policies = []config.Policy{
		{Name: "a-allow", From: "lan", To: "host", Service: "ssh", Action: "allow"},
		{Name: "z-deny", From: "any", To: "host", Service: "ssh", Action: "deny"},
	}
	e, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	d := e.Explain(Query{From: "192.168.1.2", To: "host", Protocol: "tcp", Port: 22})
	if d.Action != "deny" || d.Matched == nil || d.Matched.Name != "z-deny" {
		t.Fatalf("deny precedence not reflected by explanation: %#v", d)
	}
}

func TestExplainEffectiveMatchesRuntimePrecedenceAndIPv6Mode(t *testing.T) {
	c := config.Defaults()
	c.Interfaces = []config.Interface{{Name: "eth0", Role: "uplink", ProvenanceID: 1}, {Name: "wg0", Role: "vpn", ProvenanceID: 2}}
	c.Zones = []config.Zone{{Name: "lan", Networks: []string{"192.168.1.0/24"}}}
	c.Services = []config.Service{{Name: "ssh", Protocol: "tcp", Ports: []int{22}}}
	c.Runtime.TrustedServices = []string{"ssh"}
	c.Policies = []config.Policy{
		{Name: "deny-ssh", From: "any", To: "host", Service: "ssh", Action: "deny"},
		{Name: "allow-ssh", From: "lan", To: "host", Service: "ssh", Action: "allow"},
	}
	e, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	query := Query{From: "192.168.1.8", To: "host", Protocol: "tcp", Port: 22}
	decision := e.ExplainEffective(query, RuntimeContext{BlockedPrefixes: []string{"192.168.1.0/24"}, TrustedPrefixes: []string{"192.168.1.8/32"}})
	if decision.Action != "deny" || decision.Rule != "nftfw:block-source" {
		t.Fatalf("block did not precede temporary trust: %#v", decision)
	}
	decision = e.ExplainEffective(query, RuntimeContext{TrustedPrefixes: []string{"192.168.1.8/32"}})
	if decision.Action != "allow" || decision.Rule != "nftfw:trusted-services" {
		t.Fatalf("temporary trust did not match compiler precedence: %#v", decision)
	}
	decision = e.ExplainEffective(Query{From: "2001:db8::8", To: "host", Protocol: "tcp", Port: 22}, RuntimeContext{})
	if decision.Action != "deny" || decision.Rule != "nftfw:ipv6-mode-disabled" {
		t.Fatalf("disabled IPv6 mode was not explained: %#v", decision)
	}
}
