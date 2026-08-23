package threatintel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	// Threat data is untrusted policy input. A single feed item may cover no
	// more than one IPv4 /24 or one IPv6 /48. Aggregate coverage is bounded to
	// 4096 maximum-size items per family (/12 and /36 equivalents).
	minIPv4FeedBits     = 24
	minIPv6FeedBits     = 48
	maxIPv4CoverageBits = 12
	maxIPv6CoverageBits = 36
)

type Feed struct {
	URL        string
	MaxEntries int
	MaxBytes   int64
	Client     *http.Client
}

func (f Feed) Fetch(ctx context.Context) ([]string, error) {
	u, err := url.Parse(f.URL)
	if err != nil || strings.Contains(f.URL, "#") || !allowedFeedURL(u) {
		return nil, errors.New("threat feed URL is not permitted")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	max := f.MaxEntries
	if max <= 0 {
		max = 10000
	}
	bytes := f.MaxBytes
	if bytes <= 0 {
		bytes = 8 << 20
	}
	client := f.Client
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.DialContext = publicDialContext
		client = &http.Client{Timeout: 15 * time.Second, Transport: transport}
	}
	clientCopy := *client
	previousRedirect := clientCopy.CheckRedirect
	clientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many threat feed redirects")
		}
		if !allowedFeedURL(req.URL) {
			return errors.New("threat feed redirect is not permitted")
		}
		if previousRedirect != nil {
			return previousRedirect(req, via)
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, errors.New("create threat feed request failed")
	}
	resp, err := clientCopy.Do(req)
	if err != nil {
		// net/http's errors normally include the request URL. Do not propagate
		// them: paths and query values can contain credentials even when Feed is
		// constructed directly instead of through configuration validation.
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("threat feed request timed out")
		}
		return nil, errors.New("threat feed request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("feed HTTP status %d", resp.StatusCode)
	}
	r := io.LimitReader(resp.Body, bytes+1)
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, errors.New("read threat feed response failed")
	}
	if int64(len(body)) > bytes {
		return nil, errors.New("feed response exceeds byte limit")
	}
	return Parse(body, max)
}

func allowedFeedURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.Host != "" && u.Hostname() != "" &&
		u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawFragment == ""
}

var nonPublicFeedNetworks = func() []netip.Prefix {
	raw := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64",
		"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16",
		"fc00::/7", "fe80::/10", "ff00::/8",
	}
	result := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}()

func publicDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid threat feed network address")
	}
	resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, errors.New("threat feed DNS resolution failed")
	}
	dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, candidate := range resolved {
		candidate = candidate.Unmap()
		if !isPublicFeedAddress(candidate) {
			continue
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr != nil {
		return nil, errors.New("threat feed public endpoint connection failed")
	}
	return nil, errors.New("threat feed target resolved only to non-public addresses")
}

func isPublicFeedAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range nonPublicFeedNetworks {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var publicIPv6GlobalUnicast = netip.MustParsePrefix("2000::/3")

func isPublicFeedPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || prefix.Addr().Is4In6() {
		return false
	}
	prefix = prefix.Masked()
	address := prefix.Addr()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	if address.Is4() {
		if prefix.Bits() < minIPv4FeedBits {
			return false
		}
	} else {
		if prefix.Bits() < minIPv6FeedBits || !publicIPv6GlobalUnicast.Contains(address) {
			return false
		}
	}
	for _, reserved := range nonPublicFeedNetworks {
		if prefix.Overlaps(reserved) {
			return false
		}
	}
	return true
}

func Parse(body []byte, max int) ([]string, error) {
	if max <= 0 {
		max = 10000
	}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 1024), 64<<10)
	seen := map[string]bool{}
	result := []string{}
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			if ip, ipErr := netip.ParseAddr(line); ipErr == nil {
				p = netip.PrefixFrom(ip, ip.BitLen())
			} else {
				return nil, fmt.Errorf("invalid threat feed entry at line %d", lineNumber)
			}
		}
		if !isPublicFeedPrefix(p) {
			return nil, fmt.Errorf("threat feed entry at line %d is not an allowed public prefix", lineNumber)
		}
		canonical := p.Masked().String()
		if !seen[canonical] {
			seen[canonical] = true
			result = append(result, canonical)
			if len(result) > max {
				return nil, errors.New("feed entry limit exceeded")
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("scan threat feed response failed")
	}
	if err := Validate(result, nil); err != nil {
		return nil, err
	}
	return result, nil
}

// Validate applies whole-feed safety checks and ensures no entry can block a
// configured management, topology, or WireGuard bootstrap prefix. Addresses
// may be host IPs or CIDRs and are expected to have already passed Parse in
// normal operation; accepting both keeps direct callers fail-closed.
func Validate(addresses, protected []string) error {
	prefixes := make([]netip.Prefix, 0, len(addresses))
	for _, raw := range addresses {
		prefix, err := parsePrefix(raw)
		if err != nil || !isPublicFeedPrefix(prefix) {
			return errors.New("threat feed contains a prefix that is not public or is too broad")
		}
		prefixes = append(prefixes, prefix.Masked())
	}

	protectedPrefixes := make([]netip.Prefix, 0, len(protected))
	for _, raw := range protected {
		prefix, err := parsePrefix(raw)
		if err != nil {
			return errors.New("configured protected prefix is invalid")
		}
		protectedPrefixes = append(protectedPrefixes, prefix.Masked())
	}
	for _, candidate := range prefixes {
		for _, keep := range protectedPrefixes {
			if candidate.Overlaps(keep) {
				return errors.New("threat feed overlaps a configured protected prefix")
			}
		}
	}
	return validateAggregateCoverage(prefixes)
}

func parsePrefix(raw string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return prefix, nil
	}
	address, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(address, address.BitLen()), nil
}

func validateAggregateCoverage(prefixes []netip.Prefix) error {
	ordered := append([]netip.Prefix(nil), prefixes...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Addr().BitLen() != ordered[j].Addr().BitLen() {
			return ordered[i].Addr().BitLen() < ordered[j].Addr().BitLen()
		}
		if ordered[i].Bits() != ordered[j].Bits() {
			return ordered[i].Bits() < ordered[j].Bits()
		}
		return ordered[i].Addr().Less(ordered[j].Addr())
	})

	seen := make(map[netip.Prefix]struct{}, len(ordered))
	coverage := map[int]*big.Int{32: new(big.Int), 128: new(big.Int)}
	limits := map[int]*big.Int{
		32:  new(big.Int).Lsh(big.NewInt(1), 32-maxIPv4CoverageBits),
		128: new(big.Int).Lsh(big.NewInt(1), 128-maxIPv6CoverageBits),
	}
	for _, prefix := range ordered {
		prefix = prefix.Masked()
		familyBits := prefix.Addr().BitLen()
		minimum := minIPv6FeedBits
		if familyBits == 32 {
			minimum = minIPv4FeedBits
		}
		covered := false
		for bits := minimum; bits <= prefix.Bits(); bits++ {
			ancestor := netip.PrefixFrom(prefix.Addr(), bits).Masked()
			if _, ok := seen[ancestor]; ok {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		seen[prefix] = struct{}{}
		size := big.NewInt(1)
		for bit := prefix.Bits(); bit < familyBits; bit++ {
			size.Lsh(size, 1)
		}
		coverage[familyBits].Add(coverage[familyBits], size)
		if coverage[familyBits].Cmp(limits[familyBits]) > 0 {
			return errors.New("threat feed aggregate address coverage exceeds its safety limit")
		}
	}
	return nil
}
