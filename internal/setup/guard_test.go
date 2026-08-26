package setup

import (
	"strings"
	"testing"
)

func TestGuardPreservesOnlyLANManagementAndVPNBootstrap(t *testing.T) {
	script, err := renderGuard(
		"eth0", "nftfw0", "0xca6c", 51820,
		[]string{"198.51.100.8/32"}, []string{"192.168.1.0/24"}, []int{22},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`iifname "eth0" ip saddr @lan_v4 tcp dport { 22 }`,
		`oifname "eth0" meta mark 0xca6c ip daddr @endpoints_v4 udp dport 51820`,
		`iifname "nftfw0" counter drop comment "nftfw-setup:no-public-input"`,
		`oifname != "lo" oifname != "nftfw0" counter drop comment "nftfw-setup:physical-output-deny"`,
		`oifname != "nftfw0" counter drop comment "nftfw-setup:physical-forward-deny"`,
	} {
		if !strings.Contains(string(script), want) {
			t.Fatalf("guard missing %q", want)
		}
	}
	if strings.Contains(string(script), "flush ruleset") {
		t.Fatal("guard contains global flush")
	}
}

func TestGuardRejectsInvalidInputs(t *testing.T) {
	cases := []struct {
		uplink, vpn, mark string
		port              int
		endpoints, lan    []string
		management        []int
	}{
		{"", "nftfw0", "0xca6c", 51820, []string{"198.51.100.8/32"}, []string{"192.168.1.0/24"}, nil},
		{"eth0", "nftfw0", "0xca6c", 51820, []string{"198.51.100.8/24"}, []string{"192.168.1.0/24"}, nil},
		{"eth0", "nftfw0", "0xca6c", 51820, []string{"198.51.100.8/32"}, []string{"203.0.113.0/24"}, nil},
		{"eth0", "nftfw0", "0xca6c", 51820, []string{"198.51.100.8/32"}, []string{"192.168.1.0/24"}, []int{0}},
	}
	for index, test := range cases {
		if _, err := renderGuard(
			test.uplink, test.vpn, test.mark, test.port,
			test.endpoints, test.lan, test.management,
		); err == nil {
			t.Fatalf("invalid guard input %d accepted", index)
		}
	}
}
