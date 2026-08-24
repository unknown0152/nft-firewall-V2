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

	"github.com/unknown0152/nft-firewall-v2/internal/config"
)

type Network struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Driver          string `json:"driver"`
	BridgeInterface string `json:"bridge_interface"`
	CIDR            string `json:"cidr"`
	Gateway         string `json:"gateway"`
}
type Observer struct {
	DockerBinary string
	DaemonConfig string
	Expected     []config.DockerNetwork
}

const localDockerHost = "unix:///var/run/docker.sock"

var dockerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var dockerID = regexp.MustCompile(`^[a-f0-9]{64}$`)

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
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
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
	if !ok || int64(parentStat.Uid) != int64(os.Geteuid()) {
		return false, "Docker daemon config parent has unsafe ownership", errors.New("unsafe daemon config parent ownership")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, "Docker daemon config unavailable; Docker firewall ownership is unknown", err
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	closeErr := f.Close()
	if err != nil || closeErr != nil || len(b) > 1<<20 {
		return false, "Docker daemon config could not be read safely", errors.New("bounded Docker daemon config read failed")
	}
	var d map[string]any
	if err := json.Unmarshal(b, &d); err != nil {
		return false, "docker daemon config is malformed", err
	}
	for _, option := range []string{"iptables", "ip6tables", "ip-forward", "ip-masq", "userland-proxy"} {
		if d[option] != false {
			return false, fmt.Sprintf("docker option %s must be explicitly false", option), nil
		}
	}
	return true, "docker firewall, forwarding, masquerade, and userland proxy ownership disabled", nil
}
func (o Observer) Networks(ctx context.Context) ([]Network, error) {
	if len(o.Expected) == 0 {
		return nil, errors.New("docker observation requires an explicit stable network authorization")
	}
	expected := make(map[string]config.DockerNetwork, len(o.Expected))
	for _, network := range o.Expected {
		if !dockerName.MatchString(network.Name) || network.Driver != "bridge" || !dockerName.MatchString(network.BridgeInterface) || len(network.BridgeInterface) > 15 || len(network.Subnets) == 0 || len(network.Subnets) != len(network.Gateways) {
			return nil, fmt.Errorf("invalid expected Docker network tuple %q", network.Name)
		}
		if _, duplicate := expected[network.Name]; duplicate {
			return nil, fmt.Errorf("duplicate expected Docker network %q", network.Name)
		}
		expected[network.Name] = network
	}
	bin := o.DockerBinary
	if bin == "" {
		bin = "docker"
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := boundedOutput(ctx, 128<<10, bin, "--host", localDockerHost, "network", "ls", "--no-trunc", "--format", "{{.ID}}\t{{.Name}}\t{{.Driver}}")
	if err != nil {
		return nil, err
	}
	var result []Network
	names := splitLines(string(out))
	if len(names) > 1024 {
		return nil, errors.New("docker network count exceeds 1024")
	}
	seenNames := map[string]bool{}
	seenIDs := map[string]bool{}
	for _, summary := range names {
		fields := strings.Split(summary, "\t")
		if len(fields) != 3 {
			return nil, errors.New("docker returned a malformed network summary")
		}
		id, name, driver := fields[0], fields[1], fields[2]
		if !dockerID.MatchString(id) || seenIDs[id] {
			return nil, errors.New("docker returned an invalid or duplicate full network ID")
		}
		seenIDs[id] = true
		if !dockerName.MatchString(name) {
			return nil, fmt.Errorf("docker returned unsafe network name %q", name)
		}
		if seenNames[name] {
			return nil, fmt.Errorf("docker returned duplicate network name %q", name)
		}
		seenNames[name] = true
		wanted, authorized := expected[name]
		if driver != "bridge" {
			if authorized {
				return nil, fmt.Errorf("docker network %s driver drifted from bridge to %s", name, driver)
			}
			continue
		}
		if !authorized {
			return nil, fmt.Errorf("undeclared routed Docker bridge %q", name)
		}
		raw, err := boundedOutput(ctx, 1<<20, bin, "--host", localDockerHost, "network", "inspect", "--", id)
		if err != nil {
			return nil, fmt.Errorf("inspect docker network %s by immutable observation ID: %w", name, err)
		}
		var items []struct {
			ID      string            `json:"Id"`
			Name    string            `json:"Name"`
			Driver  string            `json:"Driver"`
			Options map[string]string `json:"Options"`
			IPAM    struct {
				Config []struct {
					Subnet  string `json:"Subnet"`
					Gateway string `json:"Gateway"`
				} `json:"Config"`
			} `json:"IPAM"`
		}
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, fmt.Errorf("decode docker network %s: %w", name, err)
		}
		if len(items) != 1 {
			return nil, fmt.Errorf("decode docker network %s: expected one object, got %d", name, len(items))
		}
		item := items[0]
		bridgeName := item.Options["com.docker.network.bridge.name"]
		if item.ID != id || item.Name != name || item.Driver != driver || item.Driver != wanted.Driver || bridgeName != wanted.BridgeInterface {
			return nil, fmt.Errorf("docker network %s changed during inspection or its stable identity drifted", name)
		}
		expectedIPAM, err := canonicalIPAM(wanted.Subnets, wanted.Gateways)
		if err != nil {
			return nil, fmt.Errorf("expected docker network %s: %w", name, err)
		}
		observedIPAM := make(map[string]string, len(item.IPAM.Config))
		for _, ipam := range item.IPAM.Config {
			prefix, parseErr := netip.ParsePrefix(ipam.Subnet)
			gateway, gatewayErr := netip.ParseAddr(ipam.Gateway)
			if parseErr != nil || gatewayErr != nil || prefix.Bits() == 0 || !prefix.Contains(gateway) || gateway.Is4() != prefix.Addr().Is4() {
				return nil, fmt.Errorf("docker network %s returned invalid subnet/gateway", name)
			}
			canonicalPrefix := prefix.Masked().String()
			if _, duplicate := observedIPAM[canonicalPrefix]; duplicate {
				return nil, fmt.Errorf("docker network %s returned duplicate subnet %s", name, canonicalPrefix)
			}
			observedIPAM[canonicalPrefix] = gateway.String()
		}
		if !sameIPAM(expectedIPAM, observedIPAM) {
			return nil, fmt.Errorf("docker network %s subnet/gateway tuple drifted", name)
		}
		for cidr, gateway := range observedIPAM {
			result = append(result, Network{ID: id, Name: name, Driver: driver, BridgeInterface: bridgeName, CIDR: cidr, Gateway: gateway})
		}
	}
	for name := range expected {
		if !seenNames[name] {
			return nil, fmt.Errorf("configured Docker network %q is absent", name)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		return result[i].CIDR < result[j].CIDR
	})
	return result, nil
}

func canonicalIPAM(subnets, gateways []string) (map[string]string, error) {
	if len(subnets) == 0 || len(subnets) != len(gateways) {
		return nil, errors.New("one explicit gateway is required for every subnet")
	}
	result := make(map[string]string, len(subnets))
	for index, rawSubnet := range subnets {
		prefix, err := netip.ParsePrefix(rawSubnet)
		gateway, gatewayErr := netip.ParseAddr(gateways[index])
		if err != nil || gatewayErr != nil || prefix.Bits() == 0 || !prefix.Contains(gateway) || gateway.Is4() != prefix.Addr().Is4() {
			return nil, errors.New("invalid subnet/gateway pair")
		}
		canonical := prefix.Masked().String()
		if _, duplicate := result[canonical]; duplicate {
			return nil, errors.New("duplicate subnet")
		}
		result[canonical] = gateway.String()
	}
	return result, nil
}

func sameIPAM(expected, observed map[string]string) bool {
	if len(expected) != len(observed) {
		return false
	}
	for subnet, gateway := range expected {
		if observed[subnet] != gateway {
			return false
		}
	}
	return true
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
