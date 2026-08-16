package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
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
	if info.Mode().Perm()&0o022 != 0 || info.Size() > 1<<20 {
		return false, "Docker daemon config must be bounded and not group/other writable", errors.New("unsafe daemon config permissions or size")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return false, "Docker daemon config must be owned by the service user", errors.New("unsafe daemon config ownership")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, "Docker daemon config path is invalid", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved != abs {
		return false, "Docker daemon config path contains a symlink", errors.New("unsafe daemon config path")
	}
	parent, err := os.Stat(filepath.Dir(abs))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return false, "Docker daemon config parent is unsafe", errors.New("unsafe daemon config parent")
	}
	parentStat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != uint32(os.Geteuid()) {
		return false, "Docker daemon config parent has unsafe ownership", errors.New("unsafe daemon config parent ownership")
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
	out, err := boundedOutput(ctx, 128<<10, bin, "network", "ls", "--format", "{{.Name}}")
	if err != nil {
		return nil, err
	}
	var result []Network
	names := splitLines(string(out))
	if len(names) > 1024 {
		return nil, errors.New("docker network count exceeds 1024")
	}
	for _, name := range names {
		if !dockerName.MatchString(name) {
			return nil, fmt.Errorf("docker returned unsafe network name %q", name)
		}
		raw, err := boundedOutput(ctx, 1<<20, bin, "network", "inspect", "--", name)
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
				p, err := netip.ParsePrefix(c.Subnet)
				if err != nil || p.Bits() == 0 {
					return nil, fmt.Errorf("docker network %s returned invalid subnet", name)
				}
				result = append(result, Network{Name: name, CIDR: p.Masked().String()})
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CIDR < result[j].CIDR })
	return result, nil
}

func boundedOutput(ctx context.Context, limit int64, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &limitedBuffer{Buffer: &stderr, Remaining: 4096}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	out, readErr := io.ReadAll(io.LimitReader(pipe, limit+1))
	if int64(len(out)) > limit {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, errors.New("docker command output exceeds limit")
	}
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, readErr
	}
	if waitErr != nil {
		return nil, fmt.Errorf("docker command failed: %w", waitErr)
	}
	return out, nil
}

type limitedBuffer struct {
	Buffer    *bytes.Buffer
	Remaining int
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	if len(p) > w.Remaining {
		p = p[:w.Remaining]
	}
	if len(p) > 0 {
		_, _ = w.Buffer.Write(p)
		w.Remaining -= len(p)
	}
	return original, nil
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
