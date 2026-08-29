// Package discovery turns live host facts into a bounded, typed setup input.
// It never mutates the host.
package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/containers"
)

const maxCommandOutput = 1 << 20

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	command := exec.CommandContext(commandCtx, name, args...)
	var output boundedBuffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type Snapshot struct {
	OSID                   string                 `json:"os_id"`
	OSVersion              string                 `json:"os_version"`
	Architecture           string                 `json:"architecture"`
	Uplink                 string                 `json:"uplink"`
	UplinkGateway          netip.Addr             `json:"uplink_gateway"`
	NonLoopbackInterfaces  []string               `json:"non_loopback_interfaces"`
	LANNetworks            []netip.Prefix         `json:"lan_networks"`
	ManagementTCP          []int                  `json:"management_tcp"`
	IPv6DefaultRoute       bool                   `json:"ipv6_default_route"`
	CompetingFirewallUnits []string               `json:"competing_firewall_units"`
	OwnedNFTables          bool                   `json:"owned_nftables"`
	ForeignNFTables        bool                   `json:"foreign_nftables"`
	ExistingNFTFWState     bool                   `json:"existing_nftfw_state"`
	DockerPresent          bool                   `json:"docker_present"`
	DockerClean            bool                   `json:"docker_clean"`
	DockerNetworks         []config.DockerNetwork `json:"docker_networks"`
}

type Inspector struct {
	Runner Runner
	Root   string
}

func (i Inspector) Discover(ctx context.Context) (Snapshot, error) {
	if i.Runner == nil {
		i.Runner = ExecRunner{}
	}
	osID, osVersion, err := readOSRelease(i.rootPath("/etc/os-release"))
	if err != nil {
		return Snapshot{}, err
	}
	v4Routes, err := i.Runner.Run(ctx, "ip", "-j", "-4", "route", "show", "default")
	if err != nil {
		return Snapshot{}, errors.New("DISCOVERY_IPV4_DEFAULT_ROUTE_FAILED")
	}
	uplink, gateway, err := ParseDefaultRoute(v4Routes)
	if err != nil {
		return Snapshot{}, err
	}
	addresses, err := i.Runner.Run(ctx, "ip", "-j", "-4", "address", "show", "dev", uplink)
	if err != nil {
		return Snapshot{}, errors.New("DISCOVERY_UPLINK_ADDRESS_FAILED")
	}
	lan, err := ParsePrivateNetworks(addresses)
	if err != nil {
		return Snapshot{}, err
	}
	linkData, err := i.Runner.Run(ctx, "ip", "-j", "link", "show")
	if err != nil {
		return Snapshot{}, errors.New("DISCOVERY_LINK_INSPECTION_FAILED")
	}
	interfaces, err := ParseNonLoopbackInterfaces(linkData)
	if err != nil {
		return Snapshot{}, err
	}
	listeners, _ := i.Runner.Run(ctx, "ss", "-H", "-lntp")
	management := ParseSSHPorts(listeners)
	v6Routes, _ := i.Runner.Run(ctx, "ip", "-j", "-6", "route", "show", "default")
	competing := i.activeFirewallManagers(ctx)
	ruleset, nftErr := i.Runner.Run(ctx, "nft", "-j", "list", "ruleset")
	if nftErr != nil {
		return Snapshot{}, errors.New("DISCOVERY_NFTABLES_UNREADABLE")
	}
	owned, foreign, err := NFTablesOwnership(ruleset)
	if err != nil {
		return Snapshot{}, err
	}
	dockerPresent, dockerClean, dockerNetworks, dockerErr := i.dockerState(ctx)
	if dockerErr != nil {
		return Snapshot{}, dockerErr
	}
	existingState := i.existingNFTFWState()
	snapshot := Snapshot{
		OSID: osID, OSVersion: osVersion, Architecture: runtime.GOARCH,
		Uplink: uplink, UplinkGateway: gateway,
		NonLoopbackInterfaces: interfaces, LANNetworks: lan,
		ManagementTCP: management, IPv6DefaultRoute: hasJSONArrayItems(v6Routes),
		CompetingFirewallUnits: competing, OwnedNFTables: owned,
		ForeignNFTables: foreign, ExistingNFTFWState: existingState,
		DockerPresent: dockerPresent, DockerClean: dockerClean,
		DockerNetworks: dockerNetworks,
	}
	if err := snapshot.ValidateCleanHost(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (s Snapshot) ValidateCleanHost() error {
	if s.OSID != "debian" || s.OSVersion != "13" {
		return errors.New("UNSUPPORTED_OS_REQUIRES_DEBIAN_13")
	}
	if s.Architecture != "amd64" && s.Architecture != "arm64" {
		return errors.New("UNSUPPORTED_ARCHITECTURE")
	}
	if s.Uplink == "" || !s.UplinkGateway.Is4() || len(s.LANNetworks) == 0 {
		return errors.New("DISCOVERY_NETWORK_AMBIGUOUS")
	}
	if len(s.NonLoopbackInterfaces) > 0 {
		foundUplink := false
		for _, name := range s.NonLoopbackInterfaces {
			if name == s.Uplink {
				foundUplink = true
			}
		}
		if !foundUplink {
			return errors.New("DISCOVERY_NETWORK_AMBIGUOUS")
		}
	}
	if len(s.CompetingFirewallUnits) > 0 || s.ForeignNFTables {
		return errors.New("DISCOVERY_COMPETING_FIREWALL")
	}
	if s.OwnedNFTables || s.ExistingNFTFWState {
		return errors.New("DISCOVERY_EXISTING_NFTFW_REQUIRES_ADOPT")
	}
	return nil
}

func ParseDefaultRoute(data []byte) (string, netip.Addr, error) {
	var routes []struct {
		Device  string `json:"dev"`
		Gateway string `json:"gateway"`
	}
	if len(data) == 0 || len(data) > maxCommandOutput || json.Unmarshal(data, &routes) != nil {
		return "", netip.Addr{}, errors.New("DISCOVERY_IPV4_DEFAULT_ROUTE_INVALID")
	}
	type candidate struct {
		device  string
		gateway netip.Addr
	}
	var candidates []candidate
	for _, route := range routes {
		gateway, err := netip.ParseAddr(route.Gateway)
		if route.Device == "" || err != nil || !gateway.Is4() || !usableAddress(gateway) {
			continue
		}
		candidates = append(candidates, candidate{device: route.Device, gateway: gateway})
	}
	if len(candidates) != 1 {
		return "", netip.Addr{}, errors.New("DISCOVERY_IPV4_DEFAULT_ROUTE_AMBIGUOUS")
	}
	return candidates[0].device, candidates[0].gateway, nil
}

func ParsePrivateNetworks(data []byte) ([]netip.Prefix, error) {
	var links []struct {
		Addresses []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
			Scope     string `json:"scope"`
		} `json:"addr_info"`
	}
	if len(data) == 0 || len(data) > maxCommandOutput || json.Unmarshal(data, &links) != nil {
		return nil, errors.New("DISCOVERY_UPLINK_ADDRESS_INVALID")
	}
	seen := map[string]bool{}
	var result []netip.Prefix
	for _, link := range links {
		for _, item := range link.Addresses {
			address, err := netip.ParseAddr(item.Local)
			if item.Family != "inet" || err != nil || !address.Is4() || !address.IsPrivate() ||
				item.PrefixLen < 1 || item.PrefixLen > 32 {
				continue
			}
			prefix := netip.PrefixFrom(address, item.PrefixLen).Masked()
			if !seen[prefix.String()] {
				seen[prefix.String()] = true
				result = append(result, prefix)
			}
		}
	}
	sort.Slice(result, func(a, b int) bool { return result[a].String() < result[b].String() })
	if len(result) == 0 {
		return nil, errors.New("DISCOVERY_PRIVATE_LAN_MISSING")
	}
	return result, nil
}

func ParseSSHPorts(data []byte) []int {
	seen := map[int]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(strings.ToLower(line), "sshd") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		address := fields[3]
		_, portText, err := net.SplitHostPort(address)
		if err != nil {
			index := strings.LastIndexByte(address, ':')
			if index < 0 {
				continue
			}
			portText = address[index+1:]
		}
		port, err := strconv.Atoi(portText)
		if err == nil && port > 0 && port <= 65535 {
			seen[port] = true
		}
	}
	result := make([]int, 0, len(seen))
	for port := range seen {
		result = append(result, port)
	}
	sort.Ints(result)
	return result
}

func ParseNonLoopbackInterfaces(data []byte) ([]string, error) {
	var links []struct {
		Name string `json:"ifname"`
	}
	if len(data) == 0 || len(data) > maxCommandOutput || json.Unmarshal(data, &links) != nil {
		return nil, errors.New("DISCOVERY_LINKS_INVALID")
	}
	seen := map[string]bool{}
	var result []string
	for _, link := range links {
		if link.Name == "" || link.Name == "lo" || seen[link.Name] {
			continue
		}
		seen[link.Name] = true
		result = append(result, link.Name)
	}
	sort.Strings(result)
	if len(result) == 0 {
		return nil, errors.New("DISCOVERY_LINKS_INVALID")
	}
	return result, nil
}

func ForeignNFTables(data []byte) (bool, error) {
	_, foreign, err := NFTablesOwnership(data)
	return foreign, err
}

func NFTablesOwnership(data []byte) (bool, bool, error) {
	var document struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if len(data) == 0 || len(data) > maxCommandOutput || json.Unmarshal(data, &document) != nil {
		return false, false, errors.New("DISCOVERY_NFTABLES_INVALID")
	}
	owned := false
	for _, object := range document.Objects {
		raw, ok := object["table"]
		if !ok {
			continue
		}
		var table struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		}
		if json.Unmarshal(raw, &table) != nil || table.Family == "" || table.Name == "" {
			return false, false, errors.New("DISCOVERY_NFTABLES_INVALID")
		}
		if (table.Family == "inet" && table.Name == "nftfw_filter") ||
			(table.Family == "ip" && table.Name == "nftfw_nat") ||
			(table.Family == "ip6" && table.Name == "nftfw_filter6") {
			owned = true
		} else {
			return owned, true, nil
		}
	}
	return owned, false, nil
}

func (i Inspector) activeFirewallManagers(ctx context.Context) []string {
	units := []string{"firewalld.service", "ufw.service", "nftables.service", "netfilter-persistent.service"}
	var result []string
	for _, unit := range units {
		if _, err := i.Runner.Run(ctx, "systemctl", "is-active", "--quiet", unit); err == nil {
			result = append(result, unit)
		}
	}
	return result
}

func (i Inspector) dockerState(ctx context.Context) (bool, bool, []config.DockerNetwork, error) {
	if _, err := i.Runner.Run(ctx, "docker", "--version"); err != nil {
		return false, true, nil, nil
	}
	if _, err := i.Runner.Run(ctx, "docker", "--host", "unix:///var/run/docker.sock",
		"version", "--format", "{{.Server.Version}}"); err != nil {
		return true, false, nil, errors.New("DISCOVERY_DOCKER_SOCKET_UNREADABLE")
	}
	containers, containerErr := i.Runner.Run(ctx, "docker", "--host",
		"unix:///var/run/docker.sock", "ps", "-aq")
	networks, networkErr := i.Runner.Run(ctx, "docker", "--host",
		"unix:///var/run/docker.sock", "network", "ls", "--filter", "type=custom", "-q")
	if containerErr != nil || networkErr != nil {
		return true, false, nil, errors.New("DISCOVERY_DOCKER_STATE_UNREADABLE")
	}
	observer := containerspkgObserver(i.Runner)
	discovered, err := observer.DiscoverNetworks(ctx)
	if err != nil {
		return true, false, nil, err
	}
	clean := strings.TrimSpace(string(containers)) == "" && strings.TrimSpace(string(networks)) == ""
	return true, clean, discovered, nil
}

func containerspkgObserver(runner Runner) containers.Observer {
	return containers.Observer{Run: func(
		ctx context.Context, limit int64, name string, args ...string,
	) ([]byte, error) {
		data, err := runner.Run(ctx, name, args...)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > limit {
			return nil, errors.New("DISCOVERY_DOCKER_OUTPUT_TOO_LARGE")
		}
		return data, nil
	}}
}

func (i Inspector) existingNFTFWState() bool {
	for _, path := range []string{
		"/etc/nftfw/intent.toml",
		"/etc/wireguard/nftfw0.conf",
		"/var/lib/nftfw/enforcement-enabled",
		"/var/lib/nftfw/provenance-ledger.db",
		"/var/lib/nftfw/generation-state/state.db",
		"/var/lib/nftfw/setup/journal.json",
	} {
		if _, err := os.Lstat(i.rootPath(path)); err == nil {
			return true
		}
	}
	return false
}

func (i Inspector) rootPath(path string) string {
	if i.Root == "" || i.Root == "/" {
		return path
	}
	return filepath.Join(i.Root, strings.TrimPrefix(path, "/"))
}

func readOSRelease(path string) (string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 64<<10 {
		return "", "", errors.New("DISCOVERY_OS_RELEASE_UNREADABLE")
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		values[strings.TrimSpace(key)] = value
	}
	if values["ID"] == "" || values["VERSION_ID"] == "" {
		return "", "", errors.New("DISCOVERY_OS_RELEASE_INVALID")
	}
	return values["ID"], values["VERSION_ID"], nil
}

func hasJSONArrayItems(data []byte) bool {
	var values []json.RawMessage
	return len(data) <= maxCommandOutput && json.Unmarshal(data, &values) == nil && len(values) > 0
}

func usableAddress(address netip.Addr) bool {
	return address.IsValid() && !address.IsUnspecified() && !address.IsLoopback() &&
		!address.IsMulticast() && !address.IsLinkLocalUnicast()
}

type boundedBuffer struct {
	data []byte
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > maxCommandOutput {
		return 0, fmt.Errorf("command output exceeds %d bytes", maxCommandOutput)
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *boundedBuffer) Bytes() []byte {
	return append([]byte(nil), b.data...)
}
