package geo

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// LoadCIDRs reads an operator-supplied country database export. Country
// membership is deliberately outside the firewall core; callers attach a
// `geo/<country>` claim to each validated prefix.
func LoadCIDRs(path string, max int) ([]string, error) {
	if max <= 0 {
		max = 100000
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("GeoIP source must be a regular, non-symlink file")
	}
	if info.Size() > 64<<20 {
		return nil, fmt.Errorf("GeoIP source exceeds 64 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1024), 64<<10)
	seen := map[string]bool{}
	out := []string{}
	for s.Scan() {
		line := strings.TrimSpace(strings.SplitN(s.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil || p.Bits() == 0 {
			return nil, fmt.Errorf("invalid GeoIP CIDR %q", line)
		}
		if !seen[p.String()] {
			seen[p.String()] = true
			out = append(out, p.String())
			if len(out) > max {
				return nil, fmt.Errorf("GeoIP CIDR limit exceeded (%d)", max)
			}
		}
	}
	return out, s.Err()
}
