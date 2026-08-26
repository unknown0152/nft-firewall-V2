// Package wgconfig parses and normalizes the deliberately small WireGuard
// provider-profile contract supported by managed NFTFW setup.
package wgconfig

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const MaxProfileBytes = 64 << 10

type Profile struct {
	PrivateKey string
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int
	Peer       Peer
}

type Peer struct {
	PublicKey           string
	PresharedKey        string
	AllowedIPs          []netip.Prefix
	EndpointHost        string
	EndpointPort        uint16
	PersistentKeepalive int
}

type Summary struct {
	AddressCount        int  `json:"address_count"`
	DNSCount            int  `json:"dns_count"`
	HasMTU              bool `json:"has_mtu"`
	HasPresharedKey     bool `json:"has_preshared_key"`
	HasKeepalive        bool `json:"has_keepalive"`
	IPv4DefaultRoute    bool `json:"ipv4_default_route"`
	SourceWorldReadable bool `json:"source_world_readable"`
}

func Read(path string) (Profile, Summary, error) {
	return read(path, false)
}

func ReadManaged(path string) (Profile, Summary, error) {
	return read(path, true)
}

func read(path string, managed bool) (Profile, Summary, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Profile{}, Summary{}, errors.New("VPN_PROFILE_PATH_INVALID")
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > MaxProfileBytes || info.Mode().Perm()&0o022 != 0 {
		return Profile{}, Summary{}, errors.New("VPN_PROFILE_FILE_UNSAFE")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || resolved != absolute {
		return Profile{}, Summary{}, errors.New("VPN_PROFILE_PATH_UNSAFE")
	}
	file, err := os.OpenFile(absolute, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Profile{}, Summary{}, errors.New("VPN_PROFILE_OPEN_FAILED")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != info.Size() {
		return Profile{}, Summary{}, errors.New("VPN_PROFILE_CHANGED")
	}
	data := make([]byte, before.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return Profile{}, Summary{}, errors.New("VPN_PROFILE_READ_FAILED")
	}
	after, err := file.Stat()
	if err != nil || !sameFile(before, after) {
		return Profile{}, Summary{}, errors.New("VPN_PROFILE_CHANGED")
	}
	profile, summary, err := parse(data, managed)
	summary.SourceWorldReadable = info.Mode().Perm()&0o004 != 0
	return profile, summary, err
}

func Parse(data []byte) (Profile, Summary, error) {
	return parse(data, false)
}

func ParseManaged(data []byte) (Profile, Summary, error) {
	return parse(data, true)
}

func parse(data []byte, managed bool) (Profile, Summary, error) {
	if len(data) == 0 || len(data) > MaxProfileBytes || strings.IndexByte(string(data), 0) >= 0 {
		return Profile{}, Summary{}, errors.New("VPN_PROFILE_SIZE_INVALID")
	}
	var profile Profile
	section := ""
	seenSections := map[string]bool{}
	seenKeys := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 1024), MaxProfileBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if name != "Interface" && name != "Peer" {
				return Profile{}, Summary{}, errors.New("VPN_PROFILE_SECTION_UNSUPPORTED")
			}
			if seenSections[name] {
				return Profile{}, Summary{}, errors.New("VPN_PROFILE_SECTION_DUPLICATE")
			}
			seenSections[name] = true
			section = name
			continue
		}
		if section == "" {
			return Profile{}, Summary{}, errors.New("VPN_PROFILE_SECTION_MISSING")
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Profile{}, Summary{}, errors.New("VPN_PROFILE_LINE_INVALID")
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		identity := section + "." + key
		if seenKeys[identity] {
			return Profile{}, Summary{}, errors.New("VPN_PROFILE_FIELD_DUPLICATE")
		}
		seenKeys[identity] = true
		if err := assign(&profile, section, key, value, managed); err != nil {
			return Profile{}, Summary{}, err
		}
	}
	if err := scanner.Err(); err != nil {
		return Profile{}, Summary{}, errors.New("VPN_PROFILE_READ_FAILED")
	}
	if !seenSections["Interface"] || !seenSections["Peer"] {
		return Profile{}, Summary{}, errors.New("VPN_PROFILE_SECTION_MISSING")
	}
	if err := validate(profile); err != nil {
		return Profile{}, Summary{}, err
	}
	return profile, Summary{
		AddressCount: len(profile.Addresses), DNSCount: len(profile.DNS),
		HasMTU: profile.MTU != 0, HasPresharedKey: profile.Peer.PresharedKey != "",
		HasKeepalive: profile.Peer.PersistentKeepalive != 0, IPv4DefaultRoute: true,
	}, nil
}

func assign(profile *Profile, section, key, value string, managed bool) error {
	if value == "" {
		return errors.New("VPN_PROFILE_VALUE_EMPTY")
	}
	switch section + "." + key {
	case "Interface.PrivateKey":
		profile.PrivateKey = value
	case "Interface.Address":
		prefixes, err := parsePrefixes(value, false)
		if err != nil {
			return errors.New("VPN_PROFILE_ADDRESS_INVALID")
		}
		profile.Addresses = prefixes
	case "Interface.DNS":
		values, err := splitList(value)
		if err != nil {
			return errors.New("VPN_PROFILE_DNS_UNSUPPORTED")
		}
		for _, raw := range values {
			address, err := netip.ParseAddr(raw)
			if err != nil || !address.Is4() || !usableAddress(address) {
				return errors.New("VPN_PROFILE_DNS_UNSUPPORTED")
			}
			profile.DNS = append(profile.DNS, address)
		}
	case "Interface.MTU":
		n, err := strconv.Atoi(value)
		if err != nil || n < 576 || n > 9000 {
			return errors.New("VPN_PROFILE_MTU_INVALID")
		}
		profile.MTU = n
	case "Peer.PublicKey":
		profile.Peer.PublicKey = value
	case "Peer.PresharedKey":
		profile.Peer.PresharedKey = value
	case "Peer.AllowedIPs":
		prefixes, err := parsePrefixes(value, true)
		if err != nil {
			return errors.New("VPN_PROFILE_ALLOWED_IPS_INVALID")
		}
		profile.Peer.AllowedIPs = prefixes
	case "Peer.Endpoint":
		host, portText, err := net.SplitHostPort(value)
		if err != nil || host == "" {
			return errors.New("VPN_PROFILE_ENDPOINT_INVALID")
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 || !validEndpointHost(host) {
			return errors.New("VPN_PROFILE_ENDPOINT_INVALID")
		}
		profile.Peer.EndpointHost, profile.Peer.EndpointPort = host, uint16(port)
	case "Peer.PersistentKeepalive":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 65535 {
			return errors.New("VPN_PROFILE_KEEPALIVE_INVALID")
		}
		profile.Peer.PersistentKeepalive = n
	case "Interface.Table":
		if managed && value == "off" {
			return nil
		}
		return errors.New("VPN_PROFILE_COMMAND_OR_ROUTE_UNSUPPORTED")
	case "Interface.PreUp", "Interface.PostUp", "Interface.PreDown", "Interface.PostDown",
		"Interface.SaveConfig":
		return errors.New("VPN_PROFILE_COMMAND_OR_ROUTE_UNSUPPORTED")
	default:
		return errors.New("VPN_PROFILE_FIELD_UNSUPPORTED")
	}
	return nil
}

func validate(profile Profile) error {
	if !validKey(profile.PrivateKey) || !validKey(profile.Peer.PublicKey) ||
		(profile.Peer.PresharedKey != "" && !validKey(profile.Peer.PresharedKey)) {
		return errors.New("VPN_PROFILE_KEY_INVALID")
	}
	if len(profile.Addresses) == 0 || len(profile.Peer.AllowedIPs) == 0 ||
		profile.Peer.EndpointHost == "" || profile.Peer.EndpointPort == 0 {
		return errors.New("VPN_PROFILE_REQUIRED_FIELD_MISSING")
	}
	for _, prefix := range profile.Addresses {
		if !prefix.Addr().Is4() || prefix.Bits() == 0 || !usableAddress(prefix.Addr()) {
			return errors.New("VPN_PROFILE_ADDRESS_UNSUPPORTED")
		}
	}
	if len(profile.Peer.AllowedIPs) != 1 {
		return errors.New("VPN_PROFILE_DEFAULT_ROUTE_REQUIRED")
	}
	allowed := profile.Peer.AllowedIPs[0]
	if !allowed.Addr().Is4() {
		return errors.New("VPN_PROFILE_IPV6_UNSUPPORTED")
	}
	if allowed.Bits() != 0 {
		return errors.New("VPN_PROFILE_SPLIT_TUNNEL_UNSUPPORTED")
	}
	return nil
}

func (profile Profile) NormalizedWGQuick(interfaceName string) ([]byte, error) {
	if !validInterfaceName(interfaceName) {
		return nil, errors.New("VPN_INTERFACE_INVALID")
	}
	if err := validate(profile); err != nil {
		return nil, err
	}
	var builder strings.Builder
	builder.WriteString("[Interface]\nPrivateKey = " + profile.PrivateKey + "\n")
	builder.WriteString("Address = " + joinPrefixes(profile.Addresses) + "\n")
	if len(profile.DNS) > 0 {
		dns := make([]string, len(profile.DNS))
		for i, address := range profile.DNS {
			dns[i] = address.String()
		}
		builder.WriteString("DNS = " + strings.Join(dns, ", ") + "\n")
	}
	if profile.MTU != 0 {
		builder.WriteString("MTU = " + strconv.Itoa(profile.MTU) + "\n")
	}
	builder.WriteString("Table = off\n\n[Peer]\nPublicKey = " + profile.Peer.PublicKey + "\n")
	if profile.Peer.PresharedKey != "" {
		builder.WriteString("PresharedKey = " + profile.Peer.PresharedKey + "\n")
	}
	builder.WriteString("AllowedIPs = 0.0.0.0/0\n")
	builder.WriteString("Endpoint = " + net.JoinHostPort(profile.Peer.EndpointHost, strconv.Itoa(int(profile.Peer.EndpointPort))) + "\n")
	if profile.Peer.PersistentKeepalive != 0 {
		builder.WriteString("PersistentKeepalive = " + strconv.Itoa(profile.Peer.PersistentKeepalive) + "\n")
	}
	return []byte(builder.String()), nil
}

func (profile Profile) WGSetConfig(endpointAddress netip.Addr) ([]byte, error) {
	if !endpointAddress.Is4() || !usableAddress(endpointAddress) {
		return nil, errors.New("VPN_ENDPOINT_ADDRESS_INVALID")
	}
	if err := validate(profile); err != nil {
		return nil, err
	}
	var builder strings.Builder
	builder.WriteString("[Interface]\nPrivateKey = " + profile.PrivateKey + "\n\n")
	builder.WriteString("[Peer]\nPublicKey = " + profile.Peer.PublicKey + "\n")
	if profile.Peer.PresharedKey != "" {
		builder.WriteString("PresharedKey = " + profile.Peer.PresharedKey + "\n")
	}
	builder.WriteString("AllowedIPs = 0.0.0.0/0\n")
	builder.WriteString("Endpoint = " + net.JoinHostPort(endpointAddress.String(), strconv.Itoa(int(profile.Peer.EndpointPort))) + "\n")
	if profile.Peer.PersistentKeepalive != 0 {
		builder.WriteString("PersistentKeepalive = " + strconv.Itoa(profile.Peer.PersistentKeepalive) + "\n")
	}
	return []byte(builder.String()), nil
}

func parsePrefixes(value string, mask bool) ([]netip.Prefix, error) {
	values, err := splitList(value)
	if err != nil {
		return nil, err
	}
	result := make([]netip.Prefix, 0, len(values))
	seen := map[string]bool{}
	for _, raw := range values {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, err
		}
		if mask {
			prefix = prefix.Masked()
		}
		canonical := prefix.String()
		if seen[canonical] {
			return nil, errors.New("duplicate prefix")
		}
		seen[canonical] = true
		result = append(result, prefix)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result, nil
}

func splitList(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			return nil, errors.New("empty list item")
		}
		result = append(result, trimmed)
	}
	if len(result) == 0 {
		return nil, errors.New("empty list")
	}
	return result, nil
}

func validKey(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.StdEncoding.EncodeToString(decoded) == value
}

func validEndpointHost(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Is4() && usableAddress(address)
	}
	if len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, " /\\\t\r\n") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}

func usableAddress(address netip.Addr) bool {
	return address.IsValid() && !address.IsUnspecified() && !address.IsLoopback() &&
		!address.IsMulticast() && !address.IsLinkLocalUnicast()
}

func validInterfaceName(value string) bool {
	if len(value) < 1 || len(value) > 15 {
		return false
	}
	for _, r := range value {
		if !(r == '-' || r == '_' || r == '.' || r >= 'a' && r <= 'z' ||
			r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func joinPrefixes(prefixes []netip.Prefix) string {
	values := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		values[i] = prefix.String()
	}
	return strings.Join(values, ", ")
}

func sameFile(left, right os.FileInfo) bool {
	lstat, lok := left.Sys().(*syscall.Stat_t)
	rstat, rok := right.Sys().(*syscall.Stat_t)
	return lok && rok && lstat.Dev == rstat.Dev && lstat.Ino == rstat.Ino &&
		lstat.Size == rstat.Size && lstat.Mtim == rstat.Mtim && lstat.Ctim == rstat.Ctim
}

func RedactedError(err error) string {
	if err == nil {
		return ""
	}
	if strings.HasPrefix(err.Error(), "VPN_") {
		return err.Error()
	}
	return "VPN_PROFILE_ERROR"
}
