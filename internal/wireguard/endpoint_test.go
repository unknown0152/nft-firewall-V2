package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type fakeLookup struct {
	answers [][]net.IP
	err     error
	calls   int
}

func (f *fakeLookup) LookupIP(context.Context, string, string) ([]net.IP, error) {
	if f.err != nil {
		return nil, f.err
	}
	answer := f.answers[f.calls]
	if f.calls < len(f.answers)-1 {
		f.calls++
	}
	return answer, nil
}

func TestEndpointRolloverRetainsRecentAddress(t *testing.T) {
	lookup := &fakeLookup{answers: [][]net.IP{{net.ParseIP("198.51.100.10")}, {net.ParseIP("198.51.100.11")}}}
	r := &Resolver{Resolver: lookup, CachePath: filepath.Join(t.TempDir(), "endpoints.json"), Max: 4, KeepRecent: 1, MaxStale: time.Hour}
	first, err := r.Resolve(context.Background(), "vpn.example.test")
	if err != nil || !reflect.DeepEqual(first, []string{"198.51.100.10"}) {
		t.Fatalf("initial resolution: %v, %v", first, err)
	}
	second, err := r.Resolve(context.Background(), "vpn.example.test")
	if err != nil || !reflect.DeepEqual(second, []string{"198.51.100.11", "198.51.100.10"}) {
		t.Fatalf("rollover did not retain the old endpoint: %v, %v", second, err)
	}
	lookup.err = errors.New("dns unavailable")
	cached, err := r.Resolve(context.Background(), "vpn.example.test")
	if err == nil || !reflect.DeepEqual(cached, second) {
		t.Fatalf("DNS failure did not retain the bounded cache: %v, %v", cached, err)
	}
}

func TestEndpointCacheExpiresFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoints.json")
	r := &Resolver{Resolver: &fakeLookup{answers: [][]net.IP{{net.ParseIP("203.0.113.8")}}}, CachePath: path, MaxStale: time.Nanosecond}
	if _, err := r.Resolve(context.Background(), "vpn.example.test"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	r.Resolver = &fakeLookup{err: errors.New("dns unavailable")}
	if got, err := r.Resolve(context.Background(), "vpn.example.test"); err == nil || len(got) != 0 {
		t.Fatalf("stale endpoint cache accepted: %v, %v", got, err)
	}
}

func TestEndpointCacheRejectsSymlinkAndOversize(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"hosts":{"vpn.example.test":[{"address":"203.0.113.8","seen_at":"2099-01-01T00:00:00Z"}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if cache := (&Resolver{CachePath: link}).loadLocked(); len(cache.Hosts) != 0 {
		t.Fatal("symlinked endpoint cache accepted")
	}
	large := filepath.Join(dir, "large.json")
	if err := os.WriteFile(large, make([]byte, (1<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if cache := (&Resolver{CachePath: large}).loadLocked(); len(cache.Hosts) != 0 {
		t.Fatal("oversized endpoint cache accepted")
	}
}

func TestValidateRetainedCacheStrictlyRejectsAmbiguousEvidence(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "endpoints.json")
	canonical := func(cache Cache) []byte {
		t.Helper()
		encoded, err := json.MarshalIndent(cache, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return append(encoded, '\n')
	}
	valid := canonical(Cache{Hosts: map[string][]CachedIP{
		"vpn.example.test": {{
			Address: "198.51.100.8", SeenAt: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC),
		}},
	}})
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	cache, err := ValidateRetainedCache(path)
	if err != nil || len(cache.Hosts["vpn.example.test"]) != 1 {
		t.Fatalf("valid retained cache rejected: %#v %v", cache, err)
	}
	future := canonical(Cache{Hosts: map[string][]CachedIP{
		"vpn.example.test": {{Address: "198.51.100.8", SeenAt: time.Now().UTC().Add(time.Hour)}},
	}})
	duplicateAddress := canonical(Cache{Hosts: map[string][]CachedIP{
		"vpn.example.test": {
			{Address: "198.51.100.8", SeenAt: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)},
			{Address: "198.51.100.8", SeenAt: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)},
		},
	}})
	invalidAddress := canonical(Cache{Hosts: map[string][]CachedIP{
		"vpn.example.test": {{
			Address: "127.0.0.1", SeenAt: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC),
		}},
	}})
	for _, test := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"unknown-field", []byte(`{"hosts":{},"extra":true}`), 0o600},
		{"duplicate-key", []byte("{\"hosts\":{},\"hosts\":{}}\n"), 0o600},
		{"noncanonical", []byte(`{"hosts":{"vpn.example.test":[{"address":"198.51.100.8","seen_at":"2026-08-30T12:00:00Z"}]}}` + "\n"), 0o600},
		{"duplicate-address", duplicateAddress, 0o600},
		{"invalid-address", invalidAddress, 0o600},
		{"future-time", future, 0o600},
		{"unsafe-mode", valid, 0o644},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := filepath.Join(directory, test.name+".json")
			if err := os.WriteFile(candidate, test.data, test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(candidate, test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateRetainedCache(candidate); err == nil {
				t.Fatal("ambiguous retained cache accepted")
			}
		})
	}
	link := filepath.Join(directory, "strict-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRetainedCache(link); err == nil {
		t.Fatal("symlinked retained cache accepted")
	}
}

func TestEndpointResolverRejectsUnusableAnswersAndFutureCache(t *testing.T) {
	dir := t.TempDir()
	lookup := &fakeLookup{answers: [][]net.IP{{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0"), net.ParseIP("224.0.0.1")}}}
	r := &Resolver{Resolver: lookup, CachePath: filepath.Join(dir, "endpoints.json"), MaxStale: time.Hour}
	if got, err := r.Resolve(context.Background(), "vpn.example.test"); err == nil || len(got) != 0 {
		t.Fatalf("unusable DNS endpoint answer accepted: got=%v err=%v", got, err)
	}
	future := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)
	cache := `{"hosts":{"vpn.example.test":[{"address":"203.0.113.8","seen_at":"` + future + `"}]}}`
	if err := os.WriteFile(r.CachePath, []byte(cache), 0o600); err != nil {
		t.Fatal(err)
	}
	r.Resolver = &fakeLookup{err: errors.New("dns unavailable")}
	if got, err := r.Resolve(context.Background(), "vpn.example.test"); err == nil || len(got) != 0 {
		t.Fatalf("future-dated endpoint cache accepted: got=%v err=%v", got, err)
	}
}

func TestFamilySetsCanonicalizeAndSort(t *testing.T) {
	v4, v6 := FamilySets([]string{
		"2001:db8::2", "192.0.2.2", "invalid", "192.0.2.1", "2001:db8::1",
	})
	if !reflect.DeepEqual(v4, []string{"192.0.2.1/32", "192.0.2.2/32"}) ||
		!reflect.DeepEqual(v6, []string{"2001:db8::1/128", "2001:db8::2/128"}) {
		t.Fatalf("unexpected family sets: %v %v", v4, v6)
	}
}
