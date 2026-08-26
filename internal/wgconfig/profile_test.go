package wgconfig

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(fill byte) string {
	value := make([]byte, 32)
	for i := range value {
		value[i] = fill
	}
	return base64.StdEncoding.EncodeToString(value)
}

func validProfile() string {
	return `[Interface]
PrivateKey = ` + testKey(1) + `
Address = 10.2.0.2/32
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = ` + testKey(2) + `
PresharedKey = ` + testKey(3) + `
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.test:51820
PersistentKeepalive = 25
`
}

func TestParseAndNormalize(t *testing.T) {
	profile, summary, err := Parse([]byte(validProfile()))
	if err != nil {
		t.Fatal(err)
	}
	if !summary.IPv4DefaultRoute || summary.AddressCount != 1 || summary.DNSCount != 1 ||
		!summary.HasMTU || !summary.HasPresharedKey || !summary.HasKeepalive {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	normalized, err := profile.NormalizedWGQuick("nftfw0")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Table = off", "AllowedIPs = 0.0.0.0/0", "Endpoint = vpn.example.test:51820"} {
		if !strings.Contains(string(normalized), want) {
			t.Fatalf("normalized profile missing %q", want)
		}
	}
	if _, _, err := Parse(normalized); err == nil {
		t.Fatal("provider parser accepted managed Table directive")
	}
	if _, _, err := ParseManaged(normalized); err != nil {
		t.Fatalf("managed parser rejected normalized profile: %v", err)
	}
	wg, err := profile.WGSetConfig(netip.MustParseAddr("198.51.100.8"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wg), "Address =") || strings.Contains(string(wg), "DNS =") ||
		!strings.Contains(string(wg), "Endpoint = 198.51.100.8:51820") {
		t.Fatal("unexpected wg setconf payload")
	}
}

func TestInterfaceAddressPreservesHostBits(t *testing.T) {
	input := strings.Replace(validProfile(), "10.2.0.2/32", "10.8.0.23/24", 1)
	profile, _, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if got := profile.Addresses[0].String(); got != "10.8.0.23/24" {
		t.Fatalf("interface host address was network-masked: %s", got)
	}
	normalized, err := profile.NormalizedWGQuick("nftfw0")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(normalized), "Address = 10.8.0.23/24") {
		t.Fatalf("normalized profile lost interface host bits:\n%s", normalized)
	}
}

func TestListFieldsRejectEmptyItems(t *testing.T) {
	replacements := [][2]string{
		{"Address = 10.2.0.2/32", "Address = 10.2.0.2/32,"},
		{"DNS = 1.1.1.1", "DNS = 1.1.1.1,,9.9.9.9"},
		{"AllowedIPs = 0.0.0.0/0", "AllowedIPs = ,0.0.0.0/0"},
	}
	for _, replacement := range replacements {
		data := bytes.Replace(
			[]byte(validProfile()), []byte(replacement[0]), []byte(replacement[1]), 1,
		)
		if _, _, err := Parse(data); err == nil {
			t.Fatalf("empty list item accepted in %q", replacement[1])
		}
	}
}

func TestParseRejectsUnsupportedProfiles(t *testing.T) {
	tests := map[string]string{
		"hook":          strings.Replace(validProfile(), "MTU = 1420", "PostUp = touch /tmp/no", 1),
		"unknown":       strings.Replace(validProfile(), "MTU = 1420", "Magic = yes", 1),
		"ipv6":          strings.Replace(validProfile(), "0.0.0.0/0", "::/0", 1),
		"split":         strings.Replace(validProfile(), "0.0.0.0/0", "10.0.0.0/8", 1),
		"second peer":   validProfile() + "\n[Peer]\nPublicKey = " + testKey(4),
		"duplicate key": strings.Replace(validProfile(), "Address = 10.2.0.2/32", "Address = 10.2.0.2/32\nAddress = 10.3.0.2/32", 1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Parse([]byte(input)); err == nil || !strings.HasPrefix(RedactedError(err), "VPN_") {
				t.Fatalf("unsafe profile accepted or unbounded error: %v", err)
			}
		})
	}
}

func TestReadRejectsWritableAndSymlinkProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "provider.conf")
	if err := os.WriteFile(path, []byte(validProfile()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(path); err == nil {
		t.Fatal("group-writable profile accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "provider-link.conf")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(link); err == nil {
		t.Fatal("symlink profile accepted")
	}
	normalized, err := func() ([]byte, error) {
		profile, _, parseErr := Parse([]byte(validProfile()))
		if parseErr != nil {
			return nil, parseErr
		}
		return profile.NormalizedWGQuick("nftfw0")
	}()
	if err != nil {
		t.Fatal(err)
	}
	managedPath := filepath.Join(dir, "managed.conf")
	if err := os.WriteFile(managedPath, normalized, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadManaged(managedPath); err != nil {
		t.Fatalf("managed profile read failed: %v", err)
	}
}

func TestProfileValidationBoundaries(t *testing.T) {
	replacements := map[string][2]string{
		"invalid private":    {"PrivateKey = " + testKey(1), "PrivateKey = invalid"},
		"invalid psk":        {"PresharedKey = " + testKey(3), "PresharedKey = invalid"},
		"missing address":    {"Address = 10.2.0.2/32", "Address = "},
		"ipv6 address":       {"10.2.0.2/32", "2001:db8::2/128"},
		"multiple allowed":   {"0.0.0.0/0", "0.0.0.0/0, 10.0.0.0/8"},
		"low mtu":            {"MTU = 1420", "MTU = 575"},
		"high mtu":           {"MTU = 1420", "MTU = 9001"},
		"high keepalive":     {"PersistentKeepalive = 25", "PersistentKeepalive = 65536"},
		"invalid endpoint":   {"vpn.example.test:51820", "-bad.example:51820"},
		"zero endpoint port": {"vpn.example.test:51820", "vpn.example.test:0"},
	}
	for name, replacement := range replacements {
		t.Run(name, func(t *testing.T) {
			input := strings.Replace(validProfile(), replacement[0], replacement[1], 1)
			if _, _, err := Parse([]byte(input)); err == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
}

func TestEndpointAndInterfaceValidation(t *testing.T) {
	for _, host := range []string{"vpn.example", "vpn.example.", "198.51.100.8"} {
		if !validEndpointHost(host) {
			t.Fatalf("valid endpoint rejected: %s", host)
		}
	}
	for _, host := range []string{"", "-bad.example", "bad-.example", "bad host", "::1"} {
		if validEndpointHost(host) {
			t.Fatalf("invalid endpoint accepted: %q", host)
		}
	}
	for _, name := range []string{"nftfw0", "wg-test_1"} {
		if !validInterfaceName(name) {
			t.Fatalf("valid interface rejected: %s", name)
		}
	}
	for _, name := range []string{"", "interface-name-too-long", "bad/name"} {
		if validInterfaceName(name) {
			t.Fatalf("invalid interface accepted: %q", name)
		}
	}
}

func TestProfileOutputRejectsInvalidDestinations(t *testing.T) {
	profile, _, err := Parse([]byte(validProfile()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profile.NormalizedWGQuick("bad/name"); err == nil {
		t.Fatal("invalid managed interface accepted")
	}
	if _, err := profile.WGSetConfig(netip.IPv6Loopback()); err == nil {
		t.Fatal("IPv6 endpoint accepted")
	}
}

func TestRedactedError(t *testing.T) {
	if RedactedError(nil) != "" {
		t.Fatal("nil error was not empty")
	}
	if got := RedactedError(os.ErrPermission); got != "VPN_PROFILE_ERROR" {
		t.Fatalf("unexpected generic redaction: %s", got)
	}
}

func BenchmarkParse(b *testing.B) {
	data := []byte(validProfile())
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := Parse(data); err != nil {
			b.Fatal(err)
		}
	}
}
