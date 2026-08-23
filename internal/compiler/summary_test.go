package compiler

import (
	"reflect"
	"testing"
)

func TestSummarizeScriptReturnsSemanticObjectsAndSets(t *testing.T) {
	script := `table inet nftfw_filter {
  set blocked_v4 {
    type ipv4_addr; flags interval
    elements = { 203.0.113.8/32, 198.51.100.0/24 }
  }
  chain input {
    ip saddr 192.0.2.0/24 tcp dport 22 accept comment "nftfw-policy:lan-ssh"
    ip saddr 192.0.2.9/32 tcp dport 22 drop comment "nftfw-policy:deny-old"
  }
}
table ip nftfw_nat {
  chain prerouting { tcp dport 443 dnat to 172.19.0.2:443 comment "nftfw-nat:web" }
}
table ip6 nftfw_filter6 { chain mode_marker { comment "nftfw:ipv6-mode-vpn"; } }
`
	summary := SummarizeScript(script)
	if !reflect.DeepEqual(summary.Policies, map[string]string{"deny-old": "deny", "lan-ssh": "allow"}) {
		t.Fatalf("unexpected policies: %#v", summary.Policies)
	}
	if !reflect.DeepEqual(summary.NAT, []string{"web"}) || summary.IPv6Mode != "vpn" {
		t.Fatalf("unexpected NAT/mode summary: %#v", summary)
	}
	want := []string{"198.51.100.0/24", "203.0.113.8/32"}
	if !reflect.DeepEqual(summary.Sets["blocked_v4"], want) {
		t.Fatalf("unexpected set summary: %#v", summary.Sets)
	}
}
