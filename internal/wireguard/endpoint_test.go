package wireguard

import (
	"context"
	"errors"
	"net"
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
