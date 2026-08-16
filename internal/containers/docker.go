package containers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Network struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}
type Observer struct {
	DockerBinary string
	DaemonConfig string
}

var dockerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func (o Observer) FirewallPolicy() (bool, string, error) {
	path := o.DaemonConfig
	if path == "" {
		path = "/etc/docker/daemon.json"
	}
	info, err := os.Lstat(path)
	if err != nil {
		return false, "Docker daemon config unavailable; Docker firewall ownership is unknown", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, "Docker daemon config must be a regular, non-symlink file", errors.New("unsafe daemon config path")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false, "Docker daemon config unavailable; Docker firewall ownership is unknown", err
	}
	var d map[string]any
	if err := json.Unmarshal(b, &d); err != nil {
		return false, "Docker daemon config is malformed", err
	}
	if d["iptables"] != false || d["ip6tables"] != false {
		return false, "Docker can manage firewall rules; iptables and ip6tables must be false", nil
	}
	return true, "Docker iptables=false and ip6tables=false", nil
}
func (o Observer) Networks(ctx context.Context) ([]Network, error) {
	bin := o.DockerBinary
	if bin == "" {
		bin = "docker"
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "network", "ls", "--format", "{{.Name}}").Output()
	if err != nil {
		return nil, err
	}
	var result []Network
	names := splitLines(string(out))
	if len(names) > 1024 {
		return nil, errors.New("Docker network count exceeds 1024")
	}
	for _, name := range names {
		if !dockerName.MatchString(name) {
			return nil, fmt.Errorf("Docker returned unsafe network name %q", name)
		}
		raw, err := exec.CommandContext(ctx, bin, "network", "inspect", "--", name).Output()
		if err != nil {
			return nil, fmt.Errorf("inspect Docker network %s: %w", name, err)
		}
		var items []struct {
			IPAM struct {
				Config []struct {
					Subnet string `json:"Subnet"`
				} `json:"Config"`
			} `json:"IPAM"`
		}
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, fmt.Errorf("decode Docker network %s: %w", name, err)
		}
		if len(items) != 1 {
			return nil, fmt.Errorf("decode Docker network %s: expected one object, got %d", name, len(items))
		}
		for _, item := range items {
			for _, c := range item.IPAM.Config {
				if p, err := netip.ParsePrefix(c.Subnet); err == nil && p.Bits() != 0 {
					result = append(result, Network{Name: name, CIDR: p.String()})
				}
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CIDR < result[j].CIDR })
	return result, nil
}
func ValidateDestination(ip string, nets []Network) error {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("invalid container address: %w", err)
	}
	for _, n := range nets {
		p, e := netip.ParsePrefix(n.CIDR)
		if e == nil && p.Contains(a) {
			return nil
		}
	}
	return errors.New("container destination is outside observed Docker networks")
}
func splitLines(s string) []string {
	var out []string
	for _, v := range strings.Split(s, "\n") {
		if strings.TrimSpace(v) != "" {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}
