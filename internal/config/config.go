// Package config owns the side-effect-free, typed configuration contract.
// Loading a document never talks to nftables or changes OS state.
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
)

type Config struct {
	System         SystemConfig       `toml:"system"`
	Interfaces     []Interface        `toml:"interfaces"`
	Zones          []Zone             `toml:"zones"`
	Services       []Service          `toml:"services"`
	Policies       []Policy           `toml:"policies"`
	NAT            []NATRule          `toml:"nat"`
	WireGuard      WireGuardConfig    `toml:"wireguard"`
	Runtime        RuntimeConfig      `toml:"runtime"`
	State          StateConfig        `toml:"state"`
	Integrations   IntegrationsConfig `toml:"integrations"`
	DockerNetworks []DockerNetwork    `toml:"docker_networks"`
	ThreatFeeds    []ThreatFeedConfig `toml:"threat_feeds"`
	GeoSets        []GeoSetConfig     `toml:"geo_sets"`
}

type SystemConfig struct {
	IPv6Mode  string `toml:"ipv6_mode"`
	StrictVPN bool   `toml:"strict_vpn"`
}

type Interface struct {
	Name         string   `toml:"name"`
	Role         string   `toml:"role"`
	Zone         string   `toml:"zone"`
	CIDRs        []string `toml:"cidrs"`
	ProvenanceID uint8    `toml:"provenance_id"`
}

type Zone struct {
	Name       string   `toml:"name"`
	Networks   []string `toml:"networks"`
	Interfaces []string `toml:"interfaces"`
}

type Service struct {
	Name     string `toml:"name"`
	Protocol string `toml:"protocol"`
	Ports    []int  `toml:"ports"`
}

type Policy struct {
	Name    string `toml:"name"`
	From    string `toml:"from"`
	To      string `toml:"to"`
	Service string `toml:"service"`
	Action  string `toml:"action"`
}

type NATRule struct {
	Name              string `toml:"name"`
	Source            string `toml:"source"`
	ExternalInterface string `toml:"external_interface"`
	Protocol          string `toml:"protocol"`
	ExternalPort      int    `toml:"external_port"`
	Destination       string `toml:"destination"`
	DestinationPort   int    `toml:"destination_port"`
}

type WireGuardConfig struct {
	Interface       string   `toml:"interface"`
	EndpointHost    string   `toml:"endpoint_host"`
	EndpointPort    int      `toml:"endpoint_port"`
	Fwmark          string   `toml:"fwmark"`
	BootstrapIPs    []string `toml:"bootstrap_ips"`
	BootstrapIPsV6  []string `toml:"bootstrap_ips_v6"`
	BootstrapHosts  []string `toml:"bootstrap_hosts"`
	KeepRecent      int      `toml:"keep_recent"`
	TCPMSS          int      `toml:"tcp_mss"`
	ConfigPath      string   `toml:"config_path"`
	HandshakeSecond int      `toml:"handshake_timeout_seconds"`
}

type RuntimeConfig struct {
	MaxBlockClaims   int      `toml:"max_block_claims"`
	MaxSetMembers    int      `toml:"max_set_members"`
	SafeApplySeconds int      `toml:"safe_apply_timeout_seconds"`
	TrustedServices  []string `toml:"trusted_services"`
}

type StateConfig struct {
	Directory        string `toml:"directory"`
	Database         string `toml:"database"`
	ProvenanceLedger string `toml:"provenance_ledger"`
}

type IntegrationsConfig struct {
	DockerEnabled bool `toml:"docker_enabled"`
	ThreatFeed    bool `toml:"threat_feed"`
	GeoIP         bool `toml:"geoip"`
	Notifications bool `toml:"notifications"`
}

// DockerNetwork is the immutable authorization identity for one routed
// Docker bridge. Docker's generated network ID is deliberately absent: it is
// used only to make a single observation race-consistent and may change after
// an approved recreation of the same stable tuple.
type DockerNetwork struct {
	Name            string   `toml:"name"`
	Driver          string   `toml:"driver"`
	BridgeInterface string   `toml:"bridge_interface"`
	Subnets         []string `toml:"subnets"`
	Gateways        []string `toml:"gateways"`
}

type ThreatFeedConfig struct {
	Name           string `toml:"name"`
	URL            string `toml:"url"`
	MaxEntries     int    `toml:"max_entries"`
	MaxBytes       int64  `toml:"max_bytes"`
	MinEntries     int    `toml:"min_entries"`
	RefreshSeconds int    `toml:"refresh_seconds"`
}

type GeoSetConfig struct {
	Name           string `toml:"name"`
	Country        string `toml:"country"`
	CIDRFile       string `toml:"cidr_file"`
	MaxEntries     int    `toml:"max_entries"`
	MinEntries     int    `toml:"min_entries"`
	RefreshSeconds int    `toml:"refresh_seconds"`
}

var namePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{0,62}$`)
var ifacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
var dockerNetworkPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var fwmarkPattern = regexp.MustCompile(`^(0x[0-9a-fA-F]{1,8}|[0-9]{1,10})$`)
var countryPattern = regexp.MustCompile(`^[A-Za-z]{2}$`)

func Defaults() Config {
	return Config{
		System:    SystemConfig{IPv6Mode: "disabled", StrictVPN: true},
		WireGuard: WireGuardConfig{Interface: "wg0", EndpointPort: 51820, Fwmark: "0xca6c", KeepRecent: 2, TCPMSS: 1360, HandshakeSecond: 180},
		Runtime:   RuntimeConfig{MaxBlockClaims: 100000, MaxSetMembers: 65536, SafeApplySeconds: 90},
		State: StateConfig{
			Directory:        "/var/lib/nftfw",
			Database:         "/var/lib/nftfw/generation-state/state.db",
			ProvenanceLedger: "/var/lib/nftfw/provenance-ledger.db",
		},
	}
}

// Load decodes a strict TOML document. Unknown keys are rejected.
func Load(path string) (Config, error) {
	if err := secureConfigPath(path); err != nil {
		return Config{}, err
	}
	b, err := readConfigFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return Decode(b)
}

func readConfigFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("configuration changed to an unsafe file while opening")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return nil, errors.New("configuration changed ownership while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("configuration exceeds 1 MiB")
	}
	return b, nil
}

// Decode is the pure configuration parser used by validation tooling and
// fuzz tests. Filesystem ownership checks remain exclusively in Load.
func Decode(b []byte) (Config, error) {
	c := Defaults()
	md, err := toml.Decode(string(b), &c)
	if err != nil {
		return Config{}, fmt.Errorf("decode TOML: %w", err)
	}
	if unknown := md.Undecoded(); len(unknown) > 0 {
		keys := make([]string, 0, len(unknown))
		for _, k := range unknown {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return Config{}, fmt.Errorf("unknown configuration key(s): %s", strings.Join(keys, ", "))
	}
	if err := Validate(c); err != nil {
		return Config{}, err
	}
	return c, nil
}

func secureConfigPath(path string) error {
	if path == "" {
		return errors.New("config path is empty")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("configuration symlink is not allowed")
	}
	if !info.Mode().IsRegular() {
		return errors.New("configuration is not a regular file")
	}
	if info.Size() > 1<<20 {
		return errors.New("configuration exceeds 1 MiB")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("configuration is writable by group/other (%#o)", info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("configuration must be owned by the current service user")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("resolve config path components: %w", err)
	}
	if resolved != abs {
		return errors.New("configuration path contains a symlink")
	}
	parent := filepath.Dir(path)
	p, err := os.Stat(parent)
	if err != nil || !p.IsDir() || p.Mode().Perm()&0o022 != 0 {
		return errors.New("configuration parent must not be group/other writable")
	}
	pstat, ok := p.Sys().(*syscall.Stat_t)
	if !ok || int64(pstat.Uid) != int64(os.Geteuid()) {
		return errors.New("configuration parent must be owned by the current service user")
	}
	if abs == "/etc/nftfw/nftfw.toml" || strings.HasPrefix(abs, "/etc/nftfw/") {
		if !ok || stat.Uid != 0 {
			return errors.New("system configuration must be owned by root")
		}
		p, err := os.Stat(filepath.Dir(abs))
		if err != nil {
			return fmt.Errorf("stat system configuration directory: %w", err)
		}
		pstat, ok := p.Sys().(*syscall.Stat_t)
		if !ok || pstat.Uid != 0 || p.Mode().Perm()&0o022 != 0 {
			return errors.New("system configuration directory must be root-owned and not group/other writable")
		}
	}
	return nil
}

func Validate(c Config) error {
	if len(c.Interfaces) > provenance.MaxActive || len(c.DockerNetworks) > provenance.MaxActive || len(c.Zones) > 256 || len(c.Services) > 1024 || len(c.Policies) > 10000 || len(c.NAT) > 10000 || len(c.ThreatFeeds) > 64 || len(c.GeoSets) > 64 {
		return errors.New("configuration collection limit exceeded")
	}
	if c.System.IPv6Mode != "disabled" && c.System.IPv6Mode != "vpn" && c.System.IPv6Mode != "native" {
		return fmt.Errorf("system.ipv6_mode must be disabled, vpn, or native")
	}
	if !c.System.StrictVPN {
		return errors.New("system.strict_vpn=false is not implemented; V2 requires explicit strict VPN egress")
	}
	if c.Runtime.MaxBlockClaims <= 0 || c.Runtime.MaxBlockClaims > 1000000 {
		return fmt.Errorf("runtime.max_block_claims must be 1..1000000")
	}
	if c.Runtime.MaxSetMembers <= 0 || c.Runtime.MaxSetMembers > 1000000 {
		return fmt.Errorf("runtime.max_set_members must be 1..1000000")
	}
	if c.Runtime.SafeApplySeconds < 30 || c.Runtime.SafeApplySeconds > 600 {
		return fmt.Errorf("runtime.safe_apply_timeout_seconds must be 30..600")
	}
	if len(c.Runtime.TrustedServices) > 32 {
		return errors.New("runtime.trusted_services exceeds 32 entries")
	}
	if !filepath.IsAbs(c.State.Directory) || filepath.Clean(c.State.Directory) != c.State.Directory || filepath.Clean(c.State.Directory) == "/" || strings.ContainsAny(c.State.Directory, "?#%") {
		return errors.New("state.directory must be an absolute canonical non-root directory")
	}
	stateRoot := filepath.Clean(c.State.Directory)
	if c.State.Database != filepath.Join(stateRoot, "generation-state", "state.db") {
		return errors.New("state.database must be the canonical state.directory/generation-state/state.db")
	}
	if c.State.ProvenanceLedger != filepath.Join(stateRoot, "provenance-ledger.db") {
		return errors.New("state.provenance_ledger must be the separate state.directory/provenance-ledger.db")
	}
	if c.Integrations.Notifications {
		return errors.New("integrations.notifications is not implemented in the core; use a separate audit adapter")
	}
	if c.Integrations.DockerEnabled != (len(c.DockerNetworks) > 0) {
		return errors.New("integrations.docker_enabled must be true exactly when [[docker_networks]] entries are configured")
	}
	if c.Integrations.ThreatFeed != (len(c.ThreatFeeds) > 0) {
		return errors.New("integrations.threat_feed must be true exactly when [[threat_feeds]] entries are configured")
	}
	if c.Integrations.GeoIP != (len(c.GeoSets) > 0) {
		return errors.New("integrations.geoip must be true exactly when [[geo_sets]] entries are configured")
	}
	feedNames := map[string]bool{}
	for _, feed := range c.ThreatFeeds {
		if !namePattern.MatchString(feed.Name) || feedNames[feed.Name] {
			return fmt.Errorf("invalid or duplicate threat feed name %q", feed.Name)
		}
		feedNames[feed.Name] = true
		u, err := url.Parse(feed.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(feed.URL, "#") {
			return fmt.Errorf("threat feed %s must use an HTTPS URL without userinfo, query, or fragment", feed.Name)
		}
		if feed.MaxEntries < 0 || feed.MaxEntries > c.Runtime.MaxBlockClaims || feed.MinEntries < 0 || (feed.MaxEntries > 0 && feed.MinEntries > feed.MaxEntries) {
			return fmt.Errorf("threat feed %s has invalid entry bounds", feed.Name)
		}
		if feed.MaxBytes < 0 || feed.MaxBytes > 64<<20 || feed.RefreshSeconds < 0 || (feed.RefreshSeconds > 0 && feed.RefreshSeconds < 60) {
			return fmt.Errorf("threat feed %s has invalid byte/refresh bounds", feed.Name)
		}
	}
	geoNames := map[string]bool{}
	for _, set := range c.GeoSets {
		if !namePattern.MatchString(set.Name) || geoNames[set.Name] {
			return fmt.Errorf("invalid or duplicate GeoIP set name %q", set.Name)
		}
		geoNames[set.Name] = true
		if !countryPattern.MatchString(set.Country) {
			return fmt.Errorf("GeoIP set %s has invalid country identifier %q", set.Name, set.Country)
		}
		if !filepath.IsAbs(set.CIDRFile) {
			return fmt.Errorf("GeoIP set %s cidr_file must be absolute", set.Name)
		}
		if set.MaxEntries < 0 || set.MaxEntries > c.Runtime.MaxBlockClaims || set.MinEntries < 0 || (set.MaxEntries > 0 && set.MinEntries > set.MaxEntries) {
			return fmt.Errorf("GeoIP set %s has invalid entry bounds", set.Name)
		}
		if set.RefreshSeconds < 0 || (set.RefreshSeconds > 0 && set.RefreshSeconds < 60) {
			return fmt.Errorf("GeoIP set %s has invalid refresh interval", set.Name)
		}
	}
	if len(c.Interfaces) == 0 {
		return errors.New("at least one interface is required")
	}
	interfaces := map[string]Interface{}
	assignments := make([]provenance.Assignment, 0, len(c.Interfaces))
	for _, in := range c.Interfaces {
		if !ifacePattern.MatchString(in.Name) {
			return fmt.Errorf("interface %q has invalid name", in.Name)
		}
		if in.Role != "uplink" && in.Role != "vpn" && in.Role != "lan" && in.Role != "container" {
			return fmt.Errorf("interface %q has invalid role %q", in.Name, in.Role)
		}
		if _, ok := interfaces[in.Name]; ok {
			return fmt.Errorf("duplicate interface %q", in.Name)
		}
		if in.ProvenanceID < provenance.MinID || in.ProvenanceID > provenance.MaxID {
			return fmt.Errorf("interface %q provenance_id must be %d..%d", in.Name, provenance.MinID, provenance.MaxID)
		}
		assignments = append(assignments, provenance.Assignment{Name: in.Name, ID: in.ProvenanceID})
		interfaces[in.Name] = in
		for _, cidr := range in.CIDRs {
			if err := validateCIDR(cidr, true); err != nil {
				return fmt.Errorf("interface %s cidr: %w", in.Name, err)
			}
		}
	}
	if err := provenance.ValidateActive(assignments); err != nil {
		return err
	}
	if err := validateDockerNetworks(c.DockerNetworks, interfaces); err != nil {
		return err
	}
	uplinks := 0
	for _, in := range c.Interfaces {
		if in.Role == "uplink" {
			uplinks++
		}
	}
	if uplinks != 1 {
		return fmt.Errorf("exactly one uplink interface is required, got %d", uplinks)
	}
	zones := map[string]Zone{}
	interfaceZones := map[string]string{}
	assignInterfaceZone := func(interfaceName, zoneName string) error {
		if existing, ok := interfaceZones[interfaceName]; ok && existing != zoneName {
			return fmt.Errorf("interface %q is assigned to multiple zones %q and %q", interfaceName, existing, zoneName)
		}
		interfaceZones[interfaceName] = zoneName
		return nil
	}
	type zonePrefix struct {
		zone   string
		prefix netip.Prefix
	}
	var zonePrefixes []zonePrefix
	for _, z := range c.Zones {
		if !namePattern.MatchString(z.Name) {
			return fmt.Errorf("zone %q has invalid name", z.Name)
		}
		if _, ok := zones[z.Name]; ok {
			return fmt.Errorf("duplicate zone %q", z.Name)
		}
		zones[z.Name] = z
		for _, n := range z.Networks {
			if err := validateCIDR(n, true); err != nil {
				return fmt.Errorf("zone %s network: %w", z.Name, err)
			}
			prefix, _ := netip.ParsePrefix(n)
			prefix = prefix.Masked()
			for _, existing := range zonePrefixes {
				if prefix.Overlaps(existing.prefix) {
					return fmt.Errorf("zone %s network %s overlaps zone %s network %s", z.Name, prefix, existing.zone, existing.prefix)
				}
			}
			zonePrefixes = append(zonePrefixes, zonePrefix{zone: z.Name, prefix: prefix})
		}
		for _, name := range z.Interfaces {
			if _, ok := interfaces[name]; !ok {
				return fmt.Errorf("zone %s references unknown interface %q", z.Name, name)
			}
			if err := assignInterfaceZone(name, z.Name); err != nil {
				return err
			}
		}
	}
	for _, in := range c.Interfaces {
		if in.Zone != "" {
			if _, ok := zones[in.Zone]; !ok {
				return fmt.Errorf("interface %s references unknown zone %q", in.Name, in.Zone)
			}
			if err := assignInterfaceZone(in.Name, in.Zone); err != nil {
				return err
			}
		}
	}
	for name, zone := range zones {
		hasInterface := len(zone.Interfaces) > 0
		if !hasInterface {
			for _, in := range c.Interfaces {
				if in.Zone == name {
					hasInterface = true
					break
				}
			}
		}
		if len(zone.Networks) == 0 && !hasInterface {
			return fmt.Errorf("zone %s has no networks or interfaces", name)
		}
	}
	services := map[string]Service{}
	for _, s := range c.Services {
		if !namePattern.MatchString(s.Name) {
			return fmt.Errorf("service %q has invalid name", s.Name)
		}
		if _, ok := services[s.Name]; ok {
			return fmt.Errorf("duplicate service %q", s.Name)
		}
		if s.Protocol != "tcp" && s.Protocol != "udp" && s.Protocol != "icmp" && s.Protocol != "any" {
			return fmt.Errorf("service %s has invalid protocol %q", s.Name, s.Protocol)
		}
		if (s.Protocol == "icmp" || s.Protocol == "any") && len(s.Ports) != 0 {
			return fmt.Errorf("service %s: %s cannot have ports", s.Name, s.Protocol)
		}
		seenPorts := map[int]bool{}
		for _, p := range s.Ports {
			if p < 1 || p > 65535 || seenPorts[p] {
				return fmt.Errorf("service %s has invalid or duplicate port %d", s.Name, p)
			}
			seenPorts[p] = true
		}
		if s.Protocol != "icmp" && s.Protocol != "any" && len(s.Ports) == 0 {
			return fmt.Errorf("service %s must define at least one port", s.Name)
		}
		services[s.Name] = s
	}
	trustedSeen := map[string]bool{}
	for _, name := range c.Runtime.TrustedServices {
		service, ok := services[name]
		if !ok {
			return fmt.Errorf("runtime.trusted_services references unknown service %q", name)
		}
		if trustedSeen[name] {
			return fmt.Errorf("runtime.trusted_services contains duplicate service %q", name)
		}
		if service.Protocol != "tcp" && service.Protocol != "udp" {
			return fmt.Errorf("runtime.trusted_services service %q must use tcp or udp", name)
		}
		trustedSeen[name] = true
	}
	policyNames := map[string]bool{}
	policyFlows := map[string]string{}
	for _, p := range c.Policies {
		if !namePattern.MatchString(p.Name) || policyNames[p.Name] {
			return fmt.Errorf("invalid or duplicate policy %q", p.Name)
		}
		policyNames[p.Name] = true
		if p.Action != "allow" && p.Action != "deny" {
			return fmt.Errorf("policy %s action must be allow or deny", p.Name)
		}
		if p.From != "any" && p.From != "host" {
			if _, ok := zones[p.From]; !ok {
				return fmt.Errorf("policy %s references unknown source zone %q", p.Name, p.From)
			}
		}
		if p.To != "host" && p.To != "any" {
			if _, ok := zones[p.To]; !ok {
				return fmt.Errorf("policy %s references unknown destination zone %q", p.Name, p.To)
			}
		}
		if _, ok := services[p.Service]; !ok {
			return fmt.Errorf("policy %s references unknown service %q", p.Name, p.Service)
		}
		if (p.From == "host" || p.From == "any") && p.To != "host" && p.To != "any" {
			destination := zones[p.To]
			for _, interfaceName := range destination.Interfaces {
				if interfaces[interfaceName].Role == "uplink" {
					return fmt.Errorf("policy %s cannot use an uplink interface as a host destination zone", p.Name)
				}
			}
			for _, configured := range c.Interfaces {
				if configured.Zone == p.To && configured.Role == "uplink" {
					return fmt.Errorf("policy %s cannot use an uplink interface as a host destination zone", p.Name)
				}
			}
		}
		flow := p.From + "\x00" + p.To + "\x00" + p.Service
		if previous, ok := policyFlows[flow]; ok {
			return fmt.Errorf("policy %s duplicates flow tuple from policy %s", p.Name, previous)
		}
		policyFlows[flow] = p.Name
	}
	natNames := map[string]bool{}
	natBindings := map[string]string{}
	for _, rule := range c.NAT {
		if !namePattern.MatchString(rule.Name) || natNames[rule.Name] {
			return fmt.Errorf("invalid or duplicate NAT rule %q", rule.Name)
		}
		natNames[rule.Name] = true
		if rule.Source != "any" {
			sourceZone, ok := zones[rule.Source]
			if !ok {
				return fmt.Errorf("NAT rule %s references unknown source zone %q", rule.Name, rule.Source)
			}
			hasIPv4 := false
			for _, raw := range sourceZone.Networks {
				if prefix, err := netip.ParsePrefix(raw); err == nil && prefix.Addr().Is4() {
					hasIPv4 = true
					break
				}
			}
			if !hasIPv4 {
				return fmt.Errorf("NAT rule %s source zone must contain an IPv4 network or use source=any", rule.Name)
			}
		}
		incoming, ok := interfaces[rule.ExternalInterface]
		if !ok || (incoming.Role != "uplink" && incoming.Role != "lan" && incoming.Role != "vpn") {
			return fmt.Errorf("NAT rule %s external_interface must be a declared uplink, lan, or vpn interface", rule.Name)
		}
		if rule.Protocol != "tcp" && rule.Protocol != "udp" {
			return fmt.Errorf("NAT rule %s protocol must be tcp or udp", rule.Name)
		}
		if rule.ExternalPort < 1 || rule.ExternalPort > 65535 || rule.DestinationPort < 1 || rule.DestinationPort > 65535 {
			return fmt.Errorf("NAT rule %s has invalid port", rule.Name)
		}
		destination, err := netip.ParseAddr(rule.Destination)
		if err != nil || !destination.Is4() || destination.IsUnspecified() || destination.IsMulticast() {
			return fmt.Errorf("NAT rule %s destination must be a unicast IPv4 address", rule.Name)
		}
		binding := rule.ExternalInterface + "\x00" + rule.Protocol + "\x00" + fmt.Sprint(rule.ExternalPort) + "\x00" + rule.Source
		if previous, ok := natBindings[binding]; ok {
			return fmt.Errorf("NAT rule %s conflicts with rule %s", rule.Name, previous)
		}
		natBindings[binding] = rule.Name
	}
	if c.WireGuard.Interface == "" {
		return errors.New("wireguard.interface is required")
	}
	if !ifacePattern.MatchString(c.WireGuard.Interface) || c.WireGuard.Interface == "" {
		return fmt.Errorf("wireguard.interface %q is invalid", c.WireGuard.Interface)
	}
	uplink := ""
	for _, in := range c.Interfaces {
		if in.Role == "uplink" {
			uplink = in.Name
		}
	}
	if c.WireGuard.Interface == uplink {
		return errors.New("wireguard.interface cannot equal the uplink")
	}
	wgInterface, ok := interfaces[c.WireGuard.Interface]
	if !ok || wgInterface.Role != "vpn" {
		return fmt.Errorf("wireguard.interface %q must be declared with role vpn", c.WireGuard.Interface)
	}
	if c.WireGuard.EndpointPort < 1 || c.WireGuard.EndpointPort > 65535 {
		return errors.New("wireguard.endpoint_port must be 1..65535")
	}
	if !fwmarkPattern.MatchString(c.WireGuard.Fwmark) {
		return fmt.Errorf("wireguard.fwmark %q is invalid", c.WireGuard.Fwmark)
	}
	markBase := 10
	markValue := c.WireGuard.Fwmark
	if strings.HasPrefix(markValue, "0x") {
		markBase = 16
		markValue = strings.TrimPrefix(markValue, "0x")
	}
	parsedMark, err := strconv.ParseUint(markValue, markBase, 32)
	if err != nil {
		return fmt.Errorf("wireguard.fwmark %q exceeds 32 bits", c.WireGuard.Fwmark)
	}
	if parsedMark == 0 {
		return errors.New("wireguard.fwmark must be nonzero so bootstrap traffic cannot match ordinary unmarked UDP")
	}
	if c.WireGuard.KeepRecent < 0 || c.WireGuard.KeepRecent > 16 {
		return errors.New("wireguard.keep_recent must be 0..16")
	}
	if c.WireGuard.TCPMSS < 536 || c.WireGuard.TCPMSS > 8960 {
		return errors.New("wireguard.tcp_mss must be 536..8960")
	}
	if c.WireGuard.EndpointHost != "" {
		if endpoint, err := netip.ParseAddr(c.WireGuard.EndpointHost); err == nil {
			if !validEndpointAddress(endpoint) {
				return fmt.Errorf("wireguard.endpoint_host %q is not a usable unicast endpoint", c.WireGuard.EndpointHost)
			}
		} else if !validHostname(c.WireGuard.EndpointHost) {
			return fmt.Errorf("wireguard.endpoint_host %q is invalid", c.WireGuard.EndpointHost)
		}
	}
	if len(c.WireGuard.BootstrapIPs)+len(c.WireGuard.BootstrapIPsV6) > 64 || len(c.WireGuard.BootstrapHosts) > 16 {
		return errors.New("WireGuard bootstrap endpoint limits exceeded (64 addresses, 16 hosts)")
	}
	for _, raw := range c.WireGuard.BootstrapIPs {
		if err := validateCIDR(raw, true); err != nil {
			return fmt.Errorf("wireguard.bootstrap_ips: %w", err)
		}
		prefix, _ := netip.ParsePrefix(raw)
		if !prefix.Addr().Is4() || prefix.Bits() != 32 || !validEndpointAddress(prefix.Addr()) {
			return fmt.Errorf("wireguard.bootstrap_ips requires IPv4 host prefixes, got %q", raw)
		}
	}
	for _, raw := range c.WireGuard.BootstrapIPsV6 {
		if err := validateCIDR(raw, true); err != nil {
			return fmt.Errorf("wireguard.bootstrap_ips_v6: %w", err)
		}
		prefix, _ := netip.ParsePrefix(raw)
		if !prefix.Addr().Is6() || prefix.Bits() != 128 || !validEndpointAddress(prefix.Addr()) {
			return fmt.Errorf("wireguard.bootstrap_ips_v6 requires IPv6 host prefixes, got %q", raw)
		}
	}
	for _, h := range c.WireGuard.BootstrapHosts {
		if !validHostname(h) {
			return fmt.Errorf("wireguard.bootstrap_hosts %q is invalid", h)
		}
	}
	if c.WireGuard.ConfigPath != "" {
		if !filepath.IsAbs(c.WireGuard.ConfigPath) || filepath.Base(c.WireGuard.ConfigPath) != c.WireGuard.Interface+".conf" {
			return errors.New("wireguard.config_path must be an absolute <interface>.conf path")
		}
	}
	if c.WireGuard.HandshakeSecond < 30 || c.WireGuard.HandshakeSecond > 3600 {
		return errors.New("wireguard.handshake_timeout_seconds must be 30..3600")
	}
	if c.System.StrictVPN && c.WireGuard.Interface == "" {
		return errors.New("strict VPN mode requires wireguard.interface")
	}
	return nil
}

func validateDockerNetworks(networks []DockerNetwork, interfaces map[string]Interface) error {
	names := make(map[string]bool, len(networks))
	bridges := make(map[string]string, len(networks))
	type ownedPrefix struct {
		network string
		prefix  netip.Prefix
	}
	var prefixes []ownedPrefix
	for _, network := range networks {
		if !dockerNetworkPattern.MatchString(network.Name) || names[network.Name] {
			return fmt.Errorf("invalid or duplicate Docker network name %q", network.Name)
		}
		names[network.Name] = true
		if network.Driver != "bridge" {
			return fmt.Errorf("docker network %s driver must be bridge", network.Name)
		}
		if !ifacePattern.MatchString(network.BridgeInterface) {
			return fmt.Errorf("docker network %s has invalid bridge_interface %q", network.Name, network.BridgeInterface)
		}
		if prior, exists := bridges[network.BridgeInterface]; exists {
			return fmt.Errorf("docker bridge interface %q is shared by networks %s and %s", network.BridgeInterface, prior, network.Name)
		}
		bridges[network.BridgeInterface] = network.Name
		configuredInterface, exists := interfaces[network.BridgeInterface]
		if !exists || configuredInterface.Role != "container" {
			return fmt.Errorf("docker network %s bridge_interface %q must be a declared container interface", network.Name, network.BridgeInterface)
		}
		if len(network.Subnets) == 0 || len(network.Subnets) != len(network.Gateways) {
			return fmt.Errorf("docker network %s requires one explicit gateway for every subnet", network.Name)
		}
		if len(network.Subnets) > 16 {
			return fmt.Errorf("docker network %s exceeds 16 subnet/gateway pairs", network.Name)
		}
		canonicalSubnets := make([]string, 0, len(network.Subnets))
		seenSubnets := map[string]bool{}
		seenGateways := map[string]bool{}
		for index, rawSubnet := range network.Subnets {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(rawSubnet))
			if err != nil || prefix.Bits() == 0 {
				return fmt.Errorf("docker network %s has invalid subnet %q", network.Name, rawSubnet)
			}
			prefix = prefix.Masked()
			canonical := prefix.String()
			if strings.TrimSpace(rawSubnet) != canonical || seenSubnets[canonical] {
				return fmt.Errorf("docker network %s has non-canonical or duplicate subnet %q", network.Name, rawSubnet)
			}
			for _, prior := range prefixes {
				if prefix.Overlaps(prior.prefix) {
					return fmt.Errorf("docker network %s subnet %s overlaps docker network %s subnet %s", network.Name, prefix, prior.network, prior.prefix)
				}
			}
			prefixes = append(prefixes, ownedPrefix{network: network.Name, prefix: prefix})
			seenSubnets[canonical] = true
			canonicalSubnets = append(canonicalSubnets, canonical)

			rawGateway := strings.TrimSpace(network.Gateways[index])
			gateway, err := netip.ParseAddr(rawGateway)
			if err != nil || !gateway.IsValid() || gateway.IsUnspecified() || gateway.IsMulticast() || !prefix.Contains(gateway) || gateway.Is4() != prefix.Addr().Is4() {
				return fmt.Errorf("docker network %s gateway %q is not usable within subnet %s", network.Name, network.Gateways[index], prefix)
			}
			if gateway == prefix.Addr() || seenGateways[gateway.String()] || rawGateway != gateway.String() {
				return fmt.Errorf("docker network %s has non-canonical, duplicate, or network-address gateway %q", network.Name, network.Gateways[index])
			}
			seenGateways[gateway.String()] = true
		}
		configuredCIDRs := canonicalPrefixes(configuredInterface.CIDRs)
		for _, raw := range configuredInterface.CIDRs {
			prefix, _ := netip.ParsePrefix(strings.TrimSpace(raw))
			if strings.TrimSpace(raw) != prefix.Masked().String() {
				return fmt.Errorf("docker bridge interface %s CIDR %q must be a canonical subnet", network.BridgeInterface, raw)
			}
		}
		sort.Strings(canonicalSubnets)
		if len(configuredCIDRs) != len(canonicalSubnets) {
			return fmt.Errorf("docker network %s subnets do not match declared interface %s CIDRs", network.Name, network.BridgeInterface)
		}
		for index := range configuredCIDRs {
			if configuredCIDRs[index] != canonicalSubnets[index] {
				return fmt.Errorf("docker network %s subnets do not match declared interface %s CIDRs", network.Name, network.BridgeInterface)
			}
		}
	}
	return nil
}

func canonicalPrefixes(values []string) []string {
	result := make([]string, 0, len(values))
	for _, raw := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err == nil {
			result = append(result, prefix.Masked().String())
		}
	}
	sort.Strings(result)
	return result
}

func validEndpointAddress(address netip.Addr) bool {
	return address.IsValid() && !address.IsUnspecified() && !address.IsMulticast() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
}

func validateCIDR(raw string, allowHost bool) error {
	_, n, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil || n == nil {
		return fmt.Errorf("invalid CIDR %q", raw)
	}
	ones, _ := n.Mask.Size()
	if ones == 0 {
		return errors.New("/0 is not permitted")
	}
	if !allowHost && bitsHost(n) != 1 {
		return errors.New("host address required")
	}
	return nil
}

func bitsHost(n *net.IPNet) int {
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return 0
	}
	if ones == bits {
		return 1
	}
	return 0
}

func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, " /\\\t\r\n") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}
