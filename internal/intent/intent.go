// Package intent owns the small, non-secret desired state used by managed
// setup and deterministically expands it into the advanced NFTFW policy.
package intent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/discovery"
	"github.com/unknown0152/nft-firewall-v2/internal/wgconfig"
)

const (
	Schema       = "nftfw.intent.v1"
	VPNInterface = "nftfw0"
	VPNFwmark    = "0xca6c"
	VPNConfig    = "/etc/wireguard/nftfw0.conf"
)

type Intent struct {
	Schema        string   `toml:"schema"`
	Managed       bool     `toml:"managed"`
	Uplink        string   `toml:"uplink"`
	VPNInterface  string   `toml:"vpn_interface"`
	LANNetworks   []string `toml:"lan_networks"`
	ManagementTCP []int    `toml:"management_tcp"`
	LANAllowTCP   []int    `toml:"lan_allow_tcp"`
	LANAllowUDP   []int    `toml:"lan_allow_udp"`
	PublicTCP     []int    `toml:"public_tcp"`
	PublicUDP     []int    `toml:"public_udp"`
	VPNAddresses  []string `toml:"vpn_addresses"`
	EndpointHost  string   `toml:"endpoint_host"`
	EndpointPort  int      `toml:"endpoint_port"`
	BootstrapIPv4 []string `toml:"bootstrap_ipv4"`
	DNS           []string `toml:"dns"`
	MTU           int      `toml:"mtu"`
	ResolverMode  string   `toml:"resolver_mode"`
	DisableIPv6   bool     `toml:"disable_ipv6"`
	DockerEnabled bool     `toml:"docker_enabled"`
}

func New(snapshot discovery.Snapshot, profile wgconfig.Profile, bootstrap []netip.Addr) (Intent, error) {
	if err := snapshot.ValidateCleanHost(); err != nil {
		return Intent{}, err
	}
	if len(bootstrap) == 0 || len(bootstrap) > 16 {
		return Intent{}, errors.New("INTENT_VPN_ENDPOINT_SET_INVALID")
	}
	result := Intent{
		Schema: Schema, Managed: true, Uplink: snapshot.Uplink,
		VPNInterface: VPNInterface, ManagementTCP: uniquePorts(snapshot.ManagementTCP),
		EndpointHost: profile.Peer.EndpointHost, EndpointPort: int(profile.Peer.EndpointPort),
		DisableIPv6: true, MTU: profile.MTU,
		DockerEnabled: snapshot.DockerPresent && snapshot.DockerClean,
	}
	for _, prefix := range snapshot.LANNetworks {
		result.LANNetworks = append(result.LANNetworks, prefix.Masked().String())
	}
	for _, prefix := range profile.Addresses {
		result.VPNAddresses = append(result.VPNAddresses, prefix.String())
	}
	for _, address := range profile.DNS {
		result.DNS = append(result.DNS, address.String())
	}
	seen := map[string]bool{}
	for _, address := range bootstrap {
		if !address.Is4() || !usableAddress(address) {
			return Intent{}, errors.New("INTENT_VPN_ENDPOINT_SET_INVALID")
		}
		value := netip.PrefixFrom(address, 32).String()
		if !seen[value] {
			seen[value] = true
			result.BootstrapIPv4 = append(result.BootstrapIPv4, value)
		}
	}
	result.canonicalize()
	if err := result.Validate(); err != nil {
		return Intent{}, err
	}
	return result, nil
}

func (i Intent) Validate() error {
	if i.Schema != Schema || !i.Managed {
		return errors.New("INTENT_SCHEMA_INVALID")
	}
	if i.Uplink == "" || i.VPNInterface != VPNInterface || i.Uplink == i.VPNInterface {
		return errors.New("INTENT_INTERFACE_INVALID")
	}
	if len(i.LANNetworks) == 0 || len(i.VPNAddresses) == 0 ||
		len(i.BootstrapIPv4) == 0 || i.EndpointHost == "" ||
		i.EndpointPort < 1 || i.EndpointPort > 65535 {
		return errors.New("INTENT_REQUIRED_FIELD_MISSING")
	}
	for _, raw := range i.LANNetworks {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() ||
			prefix.String() != prefix.Masked().String() {
			return errors.New("INTENT_LAN_NETWORK_INVALID")
		}
	}
	for _, raw := range i.VPNAddresses {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 {
			return errors.New("INTENT_VPN_ADDRESS_INVALID")
		}
	}
	for _, raw := range i.BootstrapIPv4 {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 {
			return errors.New("INTENT_BOOTSTRAP_INVALID")
		}
	}
	for _, ports := range [][]int{i.ManagementTCP, i.LANAllowTCP, i.LANAllowUDP, i.PublicTCP, i.PublicUDP} {
		if !validPorts(ports) {
			return errors.New("INTENT_PORT_INVALID")
		}
	}
	if !i.DisableIPv6 {
		return errors.New("INTENT_IPV6_MODE_UNSUPPORTED")
	}
	if i.ResolverMode != "" && i.ResolverMode != "none" &&
		i.ResolverMode != "resolvectl" && i.ResolverMode != "resolvconf" {
		return errors.New("INTENT_RESOLVER_INVALID")
	}
	return nil
}

func (i Intent) Config() (config.Config, error) {
	i.canonicalize()
	if err := i.Validate(); err != nil {
		return config.Config{}, err
	}
	c := config.Defaults()
	c.System.IPv6Mode = "disabled"
	c.System.StrictVPN = true
	c.Interfaces = []config.Interface{
		{Name: i.Uplink, Role: "uplink", Zone: "uplink", ProvenanceID: 1},
		{Name: i.VPNInterface, Role: "vpn", Zone: "public-vpn", CIDRs: append([]string(nil), i.VPNAddresses...), ProvenanceID: 2},
	}
	c.Zones = []config.Zone{
		{Name: "uplink", Interfaces: []string{i.Uplink}},
		{Name: "lan", Networks: append([]string(nil), i.LANNetworks...)},
		{Name: "public-vpn", Interfaces: []string{i.VPNInterface}},
	}
	c.Services = []config.Service{{Name: "all-outbound", Protocol: "any"}}
	c.Policies = []config.Policy{{
		Name: "host-all-outbound", From: "host", To: "any",
		Service: "all-outbound", Action: "allow",
	}}
	addServicePolicy(&c, "management-tcp", "tcp", i.ManagementTCP, "lan", "host", "lan-management")
	addServicePolicy(&c, "lan-allow-tcp", "tcp", i.LANAllowTCP, "lan", "host", "lan-allow-tcp")
	addServicePolicy(&c, "lan-allow-udp", "udp", i.LANAllowUDP, "lan", "host", "lan-allow-udp")
	addServicePolicy(&c, "public-tcp", "tcp", i.PublicTCP, "public-vpn", "host", "public-tcp")
	addServicePolicy(&c, "public-udp", "udp", i.PublicUDP, "public-vpn", "host", "public-udp")
	if len(i.ManagementTCP) > 0 {
		c.Runtime.TrustedServices = []string{"management-tcp"}
	}
	c.WireGuard.Interface = i.VPNInterface
	c.WireGuard.EndpointHost = i.EndpointHost
	c.WireGuard.EndpointPort = i.EndpointPort
	c.WireGuard.Fwmark = VPNFwmark
	c.WireGuard.BootstrapIPs = append([]string(nil), i.BootstrapIPv4...)
	c.WireGuard.BootstrapIPsV6 = nil
	c.WireGuard.BootstrapHosts = nil
	c.WireGuard.ConfigPath = VPNConfig
	c.WireGuard.TCPMSS = tcpMSS(i.MTU)
	c.Integrations.DockerEnabled = false
	c.DockerNetworks = nil
	if err := config.Validate(c); err != nil {
		return config.Config{}, fmt.Errorf("generated managed configuration: %w", err)
	}
	return c, nil
}

func (i Intent) Render() ([]byte, error) {
	i.canonicalize()
	if err := i.Validate(); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.WriteString("# Managed by NFT Firewall V2. Use nftfw commands; do not edit directly.\n")
	if err := toml.NewEncoder(&buffer).Encode(i); err != nil {
		return nil, fmt.Errorf("encode managed intent: %w", err)
	}
	return buffer.Bytes(), nil
}

func RenderConfig(c config.Config) ([]byte, error) {
	if err := config.Validate(c); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.WriteString("# Generated by NFT Firewall V2 managed setup.\n")
	buffer.WriteString("# Use nftfw expose/lan commands or switch explicitly to advanced mode.\n")
	if err := toml.NewEncoder(&buffer).Encode(c); err != nil {
		return nil, fmt.Errorf("encode generated configuration: %w", err)
	}
	return buffer.Bytes(), nil
}

func Decode(data []byte) (Intent, error) {
	var result Intent
	metadata, err := toml.Decode(string(data), &result)
	if err != nil {
		return Intent{}, errors.New("INTENT_DECODE_FAILED")
	}
	if len(metadata.Undecoded()) != 0 {
		return Intent{}, errors.New("INTENT_FIELD_UNSUPPORTED")
	}
	result.canonicalize()
	if err := result.Validate(); err != nil {
		return Intent{}, err
	}
	return result, nil
}

func Load(path string) (Intent, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Intent{}, errors.New("INTENT_PATH_INVALID")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Intent{}, errors.New("INTENT_READ_FAILED")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 ||
		info.Mode().Perm()&0o022 != 0 {
		return Intent{}, errors.New("INTENT_FILE_UNSAFE")
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return Intent{}, errors.New("INTENT_READ_FAILED")
	}
	return Decode(data)
}

func (i *Intent) AddExposure(protocol string, ports ...int) error {
	if protocol != "tcp" && protocol != "udp" {
		return errors.New("INTENT_PROTOCOL_INVALID")
	}
	if !validPorts(ports) {
		return errors.New("INTENT_PORT_INVALID")
	}
	if protocol == "tcp" {
		i.PublicTCP = uniquePorts(append(i.PublicTCP, ports...))
	} else {
		i.PublicUDP = uniquePorts(append(i.PublicUDP, ports...))
	}
	return i.Validate()
}

func (i *Intent) RemoveExposure(protocol string, ports ...int) error {
	if protocol != "tcp" && protocol != "udp" || !validPorts(ports) {
		return errors.New("INTENT_PORT_INVALID")
	}
	if protocol == "tcp" {
		i.PublicTCP = removePorts(i.PublicTCP, ports)
	} else {
		i.PublicUDP = removePorts(i.PublicUDP, ports)
	}
	return i.Validate()
}

func (i *Intent) AddLAN(protocol string, ports ...int) error {
	if protocol != "tcp" && protocol != "udp" || !validPorts(ports) {
		return errors.New("INTENT_PORT_INVALID")
	}
	if protocol == "tcp" {
		i.LANAllowTCP = uniquePorts(append(i.LANAllowTCP, ports...))
	} else {
		i.LANAllowUDP = uniquePorts(append(i.LANAllowUDP, ports...))
	}
	return i.Validate()
}

func (i *Intent) RemoveLAN(protocol string, ports ...int) error {
	if protocol != "tcp" && protocol != "udp" || !validPorts(ports) {
		return errors.New("INTENT_PORT_INVALID")
	}
	if protocol == "tcp" {
		i.LANAllowTCP = removePorts(i.LANAllowTCP, ports)
	} else {
		i.LANAllowUDP = removePorts(i.LANAllowUDP, ports)
	}
	return i.Validate()
}

func (i *Intent) canonicalize() {
	i.LANNetworks = uniqueStrings(i.LANNetworks)
	i.VPNAddresses = uniqueStrings(i.VPNAddresses)
	i.BootstrapIPv4 = uniqueStrings(i.BootstrapIPv4)
	i.DNS = uniqueStrings(i.DNS)
	i.ManagementTCP = uniquePorts(i.ManagementTCP)
	i.LANAllowTCP = uniquePorts(i.LANAllowTCP)
	i.LANAllowUDP = uniquePorts(i.LANAllowUDP)
	i.PublicTCP = uniquePorts(i.PublicTCP)
	i.PublicUDP = uniquePorts(i.PublicUDP)
}

func addServicePolicy(c *config.Config, name, protocol string, ports []int, from, to, policyName string) {
	if len(ports) == 0 {
		return
	}
	c.Services = append(c.Services, config.Service{Name: name, Protocol: protocol, Ports: append([]int(nil), ports...)})
	c.Policies = append(c.Policies, config.Policy{
		Name: policyName, From: from, To: to, Service: name, Action: "allow",
	})
}

func tcpMSS(mtu int) int {
	if mtu == 0 {
		return 1360
	}
	value := mtu - 60
	if value < 536 {
		return 536
	}
	if value > 8960 {
		return 8960
	}
	return value
}

func validPorts(ports []int) bool {
	seen := map[int]bool{}
	for _, port := range ports {
		if port < 1 || port > 65535 || seen[port] {
			return false
		}
		seen[port] = true
	}
	return true
}

func uniquePorts(values []int) []int {
	seen := map[int]bool{}
	var result []int
	for _, value := range values {
		if value >= 1 && value <= 65535 && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Ints(result)
	return result
}

func removePorts(current, remove []int) []int {
	blocked := map[int]bool{}
	for _, value := range remove {
		blocked[value] = true
	}
	var result []int
	for _, value := range current {
		if !blocked[value] {
			result = append(result, value)
		}
	}
	return uniquePorts(result)
}

func uniqueStrings(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && (len(result) == 0 || result[len(result)-1] != value) {
			result = append(result, value)
		}
	}
	return result
}

func usableAddress(address netip.Addr) bool {
	return address.IsValid() && !address.IsUnspecified() && !address.IsLoopback() &&
		!address.IsMulticast() && !address.IsLinkLocalUnicast()
}
