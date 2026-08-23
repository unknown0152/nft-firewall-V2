package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

type Resolver struct {
	Resolver   LookupResolver
	CachePath  string
	Max        int
	KeepRecent int
	MaxStale   time.Duration
	mu         sync.Mutex
}

type LookupResolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

type Cache struct {
	Hosts map[string][]CachedIP `json:"hosts"`
}
type CachedIP struct {
	Address string    `json:"address"`
	SeenAt  time.Time `json:"seen_at"`
}

func (r *Resolver) Resolve(ctx context.Context, host string) ([]string, error) {
	if host == "" {
		return nil, errors.New("endpoint host is empty")
	}
	max := r.Max
	if max <= 0 {
		max = 16
	}
	keep := r.KeepRecent
	if keep < 0 {
		keep = 0
	}
	res := r.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := res.LookupIP(ctx, "ip", host)
	if err != nil {
		return r.cached(host, keep, fmt.Errorf("resolve %s: %w", host, err))
	}
	seen := map[string]bool{}
	result := []string{}
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a.String())
		if err != nil || !usableEndpointAddress(ip) {
			continue
		}
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	if len(result) == 0 {
		return r.cached(host, keep, errors.New("resolver returned no valid addresses"))
	}
	sort.Strings(result)
	if len(result) > max {
		result = result[:max]
	}
	merged, recordErr := r.record(host, result)
	if recordErr != nil {
		return merged, fmt.Errorf("persist endpoint cache: %w", recordErr)
	}
	return merged, nil
}

func (r *Resolver) record(host string, addrs []string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cache := r.loadLocked()
	if cache.Hosts == nil {
		cache.Hosts = map[string][]CachedIP{}
	}
	old := cache.Hosts[host]
	now := time.Now().UTC()
	merged := []CachedIP{}
	seen := map[string]bool{}
	for _, a := range addrs {
		merged = append(merged, CachedIP{Address: a, SeenAt: now})
		seen[a] = true
	}
	recent := 0
	keep := r.KeepRecent
	if keep < 0 {
		keep = 0
	}
	max := r.Max
	if max <= 0 {
		max = 16
	}
	maxStale := r.MaxStale
	if maxStale <= 0 {
		maxStale = 24 * time.Hour
	}
	for _, a := range old {
		ip, parseErr := netip.ParseAddr(a.Address)
		validTime := !a.SeenAt.IsZero() && !a.SeenAt.After(now.Add(5*time.Minute)) && now.Sub(a.SeenAt) <= maxStale
		if parseErr == nil && usableEndpointAddress(ip) && validTime && !seen[ip.String()] && recent < keep && len(merged) < max {
			a.Address = ip.String()
			merged = append(merged, a)
			seen[a.Address] = true
			recent++
		}
	}
	if len(merged) > max {
		merged = merged[:max]
	}
	cache.Hosts[host] = merged
	if err := r.saveLocked(cache); err != nil {
		return cachedAddresses(merged), err
	}
	return cachedAddresses(merged), nil
}

func (r *Resolver) cached(host string, keep int, cause error) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cache := r.loadLocked()
	entries := cache.Hosts[host]
	result := []string{}
	now := time.Now().UTC()
	maxStale := r.MaxStale
	if maxStale <= 0 {
		maxStale = 24 * time.Hour
	}
	max := r.Max
	if max <= 0 {
		max = 16
	}
	for _, e := range entries {
		if len(result) >= max {
			break
		}
		if ip, err := netip.ParseAddr(e.Address); err == nil && usableEndpointAddress(ip) && !e.SeenAt.IsZero() && !e.SeenAt.After(now.Add(5*time.Minute)) && now.Sub(e.SeenAt) <= maxStale {
			result = append(result, ip.String())
		}
	}
	if len(result) > 0 {
		return result, fmt.Errorf("%w; using %d cached endpoint(s)", cause, len(result))
	}
	return nil, cause
}

func usableEndpointAddress(address netip.Addr) bool {
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsUnspecified() && !address.IsMulticast() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
}

func cachedAddresses(entries []CachedIP) []string {
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry.Address)
	}
	return result
}

func (r *Resolver) loadLocked() Cache {
	empty := Cache{Hosts: map[string][]CachedIP{}}
	if r.CachePath == "" {
		return empty
	}
	info, err := os.Lstat(r.CachePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() > 1<<20 {
		return empty
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return empty
	}
	f, err := os.OpenFile(r.CachePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return empty
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	closeErr := f.Close()
	if err != nil || closeErr != nil || len(b) > 1<<20 {
		return empty
	}
	var c Cache
	if json.Unmarshal(b, &c) != nil || c.Hosts == nil || len(c.Hosts) > 64 {
		return empty
	}
	return c
}
func (r *Resolver) saveLocked(c Cache) error {
	if r.CachePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.CachePath), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(r.CachePath), ".endpoint-*.tmp")
	if err != nil {
		return err
	}
	p := tmp.Name()
	defer os.Remove(p)
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(p, r.CachePath); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(r.CachePath))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func FamilySets(addrs []string) (v4, v6 []string) {
	for _, raw := range addrs {
		if ip, err := netip.ParseAddr(raw); err == nil {
			if ip.Is4() {
				v4 = append(v4, ip.String()+"/32")
			} else {
				v6 = append(v6, ip.String()+"/128")
			}
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return
}
