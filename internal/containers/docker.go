package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strings"
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
	Run          func(context.Context, int64, string, ...string) ([]byte, error)
}

const localDockerHost = "unix:///var/run/docker.sock"

var dockerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var dockerID = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (o Observer) FirewallPolicy() (bool, string, error) {
	path := o.DaemonConfig
	if path == "" {
		path = "/etc/docker/daemon.json"
	}
	if err := ValidateManagedDaemonConfig(path); err != nil {
		if strings.HasPrefix(err.Error(), "DOCKER_DAEMON_OPTION_NOT_OWNED_") {
			return false, err.Error(), nil
		}
		return false, err.Error(), err
	}
	return true, "docker firewall, forwarding, masquerade, and userland proxy ownership disabled", nil
}
func (o Observer) Networks(ctx context.Context) ([]Network, error) {
	if len(o.Expected) == 0 || len(o.Expected) > 62 {
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
	out, err := o.output(ctx, 128<<10, bin, "--host", localDockerHost, "network", "ls", "--no-trunc", "--format", "{{.ID}}\t{{.Name}}\t{{.Driver}}")
	if err != nil {
		return nil, err
	}
	type authorizedSummary struct {
		id, name, driver string
		wanted           config.DockerNetwork
	}
	var authorizedSummaries []authorizedSummary
	names := splitLines(string(out))
	if len(names) > 1024 {
		return nil, errors.New("docker network count exceeds 1024")
	}
	seenNames := map[string]bool{}
	seenIDs := map[string]bool{}
	seenBridges := map[string]string{}
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
		authorizedSummaries = append(authorizedSummaries, authorizedSummary{
			id: id, name: name, driver: driver, wanted: wanted,
		})
	}
	for name := range expected {
		if !seenNames[name] {
			return nil, fmt.Errorf("configured Docker network %q is absent", name)
		}
	}
	if len(authorizedSummaries) != len(expected) {
		return nil, errors.New("docker authorized bridge observation is incomplete")
	}
	inspectArgs := []string{"--host", localDockerHost, "network", "inspect", "--"}
	for _, summary := range authorizedSummaries {
		inspectArgs = append(inspectArgs, summary.id)
	}
	inspectLimit := int64(len(authorizedSummaries)) * (1 << 20)
	raw, err := o.output(ctx, inspectLimit, bin, inspectArgs...)
	if err != nil {
		return nil, fmt.Errorf("inspect docker networks by immutable observation IDs: %w", err)
	}
	var inspected []inspectedNetwork
	if err := json.Unmarshal(raw, &inspected); err != nil {
		return nil, fmt.Errorf("decode docker network inspection: %w", err)
	}
	if len(inspected) != len(authorizedSummaries) {
		return nil, fmt.Errorf("decode docker network inspection: expected %d objects, got %d", len(authorizedSummaries), len(inspected))
	}
	byID := make(map[string]inspectedNetwork, len(inspected))
	for _, item := range inspected {
		if !dockerID.MatchString(item.ID) {
			return nil, errors.New("docker network inspection returned an invalid full network ID")
		}
		if _, duplicate := byID[item.ID]; duplicate {
			return nil, errors.New("docker network inspection returned a duplicate network ID")
		}
		byID[item.ID] = item
	}
	var result []Network
	for _, summary := range authorizedSummaries {
		item, present := byID[summary.id]
		if !present {
			return nil, fmt.Errorf("docker network %s changed during batched inspection", summary.name)
		}
		bridgeName := observedBridgeName(item.ID, item.Name, item.Options)
		expectedIPv6 := false
		for _, subnet := range summary.wanted.Subnets {
			prefix, parseErr := netip.ParsePrefix(subnet)
			expectedIPv6 = expectedIPv6 || parseErr == nil && prefix.Addr().Is6()
		}
		if item.ID != summary.id || item.Name != summary.name || item.Driver != summary.driver ||
			item.Driver != summary.wanted.Driver || !linuxInterfaceName.MatchString(bridgeName) ||
			(!summary.wanted.DynamicBridge && bridgeName != summary.wanted.BridgeInterface) ||
			item.Internal == nil || item.EnableIPv6 == nil ||
			*item.Internal || *item.EnableIPv6 != expectedIPv6 {
			return nil, fmt.Errorf("docker network %s changed during inspection or its stable identity drifted", summary.name)
		}
		if prior, duplicate := seenBridges[bridgeName]; duplicate && prior != summary.name {
			return nil, fmt.Errorf("docker bridge interface %s is shared by networks %s and %s", bridgeName, prior, summary.name)
		}
		if _, err := o.output(ctx, 64<<10, "ip", "-j", "link", "show", "dev", bridgeName); err != nil {
			return nil, fmt.Errorf("docker network %s bridge interface %s is absent", summary.name, bridgeName)
		}
		seenBridges[bridgeName] = summary.name
		expectedIPAM, err := canonicalIPAM(summary.wanted.Subnets, summary.wanted.Gateways)
		if err != nil {
			return nil, fmt.Errorf("expected docker network %s: %w", summary.name, err)
		}
		observedIPAM := make(map[string]string, len(item.IPAM.Config))
		for _, ipam := range item.IPAM.Config {
			prefix, parseErr := netip.ParsePrefix(ipam.Subnet)
			gateway, gatewayErr := netip.ParseAddr(ipam.Gateway)
			if parseErr != nil || gatewayErr != nil || prefix.Bits() == 0 || !prefix.Contains(gateway) || gateway.Is4() != prefix.Addr().Is4() {
				return nil, fmt.Errorf("docker network %s returned invalid subnet/gateway", summary.name)
			}
			canonicalPrefix := prefix.Masked().String()
			if _, duplicate := observedIPAM[canonicalPrefix]; duplicate {
				return nil, fmt.Errorf("docker network %s returned duplicate subnet %s", summary.name, canonicalPrefix)
			}
			observedIPAM[canonicalPrefix] = gateway.String()
		}
		if !sameIPAM(expectedIPAM, observedIPAM) {
			return nil, fmt.Errorf("docker network %s subnet/gateway tuple drifted", summary.name)
		}
		for cidr, gateway := range observedIPAM {
			result = append(result, Network{ID: summary.id, Name: summary.name, Driver: summary.driver, BridgeInterface: bridgeName, CIDR: cidr, Gateway: gateway})
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

func (o Observer) output(ctx context.Context, limit int64, bin string, args ...string) ([]byte, error) {
	if o.Run != nil {
		return o.Run(ctx, limit, bin, args...)
	}
	return boundedOutput(ctx, limit, bin, args...)
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
