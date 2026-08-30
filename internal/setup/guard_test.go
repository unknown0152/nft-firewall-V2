package setup

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const disposableNftTestMarker = "/run/nftfw-disposable-test-guest"

func TestGuardPreservesOnlyLANManagementAndVPNBootstrap(t *testing.T) {
	script, err := renderGuard(
		"eth0", "nftfw0", "0xca6c", 51820,
		[]string{"198.51.100.8/32"}, []string{"192.168.1.0/24"}, []int{22},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`set endpoints_v4 { type ipv4_addr; flags interval; elements = { 198.51.100.8/32 } }`,
		`set lan_v4 { type ipv4_addr; flags interval; elements = { 192.168.1.0/24 } }`,
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
	for _, forbidden := range []string{"flush ruleset", "delete table", "table ip ", "table ip6 "} {
		if strings.Contains(string(script), forbidden) {
			t.Fatalf("guard contains unrelated mutation %q", forbidden)
		}
	}
	if count := strings.Count(string(script), "table inet "); count != 1 {
		t.Fatalf("guard must own exactly one inet table, found %d", count)
	}
}

func TestGuardEndpointSetIsDeterministicAndPrefixSafe(t *testing.T) {
	first, err := renderGuard(
		"eth0", "nftfw0", "0xca6c", 51820,
		[]string{"203.0.113.9/32", "198.51.100.8/32"},
		[]string{"192.168.2.0/24", "10.0.0.0/8"},
		[]int{9090, 22},
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := renderGuard(
		"eth0", "nftfw0", "0xca6c", 51820,
		[]string{"198.51.100.8/32", "203.0.113.9/32"},
		[]string{"10.0.0.0/8", "192.168.2.0/24"},
		[]int{22, 9090},
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("equivalent guard inputs did not render deterministically")
	}
	want := `set endpoints_v4 { type ipv4_addr; flags interval; elements = { 198.51.100.8/32, 203.0.113.9/32 } }`
	if !strings.Contains(string(first), want) {
		t.Fatalf("guard endpoint set mismatch: missing %q", want)
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
		{"eth0", "nftfw0", "0xca6c", 51820, []string{"198.51.100.0/24"}, []string{"192.168.1.0/24"}, nil},
		{"eth0", "nftfw0", "0xca6c", 51820, []string{"198.51.100.8"}, []string{"192.168.1.0/24"}, nil},
		{"eth0", "nftfw0", "0xca6c", 51820, []string{"2001:db8::8/128"}, []string{"192.168.1.0/24"}, nil},
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

func TestGuardPassesRealNftablesParserInDisposableGuest(t *testing.T) {
	if os.Getenv("NFTFW_PRIVILEGED_NFT_TEST") != "disposable-approved" {
		t.Skip("real nftables regression requires explicit disposable-guest approval")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real nftables regression must run as root inside a disposable guest")
	}
	marker, err := os.Lstat(disposableNftTestMarker)
	if err != nil {
		t.Fatalf("disposable-guest marker is required: %v", err)
	}
	stat, ok := marker.Sys().(*syscall.Stat_t)
	if !marker.Mode().IsRegular() || marker.Mode().Perm()&0o077 != 0 || !ok || stat.Uid != 0 {
		t.Fatalf("unsafe disposable-guest marker mode %v", marker.Mode())
	}

	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatalf("nft binary is required in the disposable guest: %v", err)
	}
	if output, err := exec.Command(nft, "list", "table", "inet", "nftfw_setup_guard").CombinedOutput(); err == nil {
		t.Fatalf("refusing to replace pre-existing setup-guard table: %s", output)
	}

	script, err := renderGuard(
		"eth0", "nftfw0", "0xca6c", 51820,
		[]string{"203.0.113.9/32", "198.51.100.8/32"},
		[]string{"192.168.1.0/24", "10.0.0.0/8"},
		[]int{22, 9090},
	)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "setup-guard.nft")
	if err := os.WriteFile(path, script, 0o600); err != nil {
		t.Fatal(err)
	}
	runNft := func(arguments ...string) []byte {
		t.Helper()
		output, commandErr := exec.Command(nft, arguments...).CombinedOutput()
		if commandErr != nil {
			t.Fatalf("nft %s failed: %v: %s", strings.Join(arguments, " "), commandErr, output)
		}
		return output
	}
	runNft("--check", "--file", path)
	runNft("--file", path)
	removed := false
	t.Cleanup(func() {
		if removed {
			return
		}
		output, commandErr := exec.Command(nft, "delete", "table", "inet", "nftfw_setup_guard").CombinedOutput()
		if commandErr != nil {
			t.Errorf("cleanup of setup-guard table failed: %v: %s", commandErr, output)
		}
	})
	listed := string(runNft("list", "table", "inet", "nftfw_setup_guard"))
	if !strings.Contains(listed, "table inet nftfw_setup_guard") ||
		!strings.Contains(listed, "flags interval") {
		t.Fatalf("applied setup-guard table is incomplete: %s", listed)
	}
	runNft("delete", "table", "inet", "nftfw_setup_guard")
	removed = true
	if output, err := exec.Command(nft, "list", "table", "inet", "nftfw_setup_guard").CombinedOutput(); err == nil {
		t.Fatalf("setup-guard table remained after exact cleanup: %s", output)
	}
}
