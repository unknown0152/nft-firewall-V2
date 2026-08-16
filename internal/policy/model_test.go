package policy

import (
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"testing"
)

func TestExplainUsesCompilerModel(t *testing.T) {
	c := config.Defaults()
	c.Interfaces = []config.Interface{{Name: "eth0", Role: "uplink"}, {Name: "wg0", Role: "vpn"}}
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
	d = e.Explain(Query{From: "203.0.113.5", To: "host", Protocol: "tcp", Port: 22})
	if d.Action != "deny" || d.Matched != nil {
		t.Fatalf("unexpected deny: %#v", d)
	}
}

func TestExplicitDenyPrecedesAllowDeterministically(t *testing.T) {
	c := config.Defaults()
	c.Interfaces = []config.Interface{{Name: "eth0", Role: "uplink"}, {Name: "wg0", Role: "vpn"}}
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
