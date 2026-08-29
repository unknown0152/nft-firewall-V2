package containers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
)

const maxDaemonConfig = 1 << 20

const ManagedSocketDropIn = `[Service]
InaccessiblePaths=
`

var linuxInterfaceName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// ManagedDaemonConfig returns a deterministic daemon.json with Docker's
// firewall, forwarding, masquerade, and proxy mutation disabled. The kernel
// forwarding value remains owned separately by NFTFW.
func ManagedDaemonConfig(path string) ([]byte, bool, error) {
	value, existed, err := readDaemonObject(path)
	if err != nil {
		return nil, false, err
	}
	for _, option := range []string{
		"iptables", "ip6tables", "ip-forward", "ip-masq", "userland-proxy",
	} {
		value[option] = false
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, false, errors.New("DOCKER_DAEMON_CONFIG_ENCODE_FAILED")
	}
	data = append(data, '\n')
	if !existed {
		return data, true, nil
	}
	current, _, err := readProtectedDaemonFile(path)
	if err != nil {
		return nil, false, err
	}
	var currentValue any
	if err := decodeStrictJSON(current, &currentValue); err != nil {
		return nil, false, err
	}
	return data, !semanticJSONEqual(currentValue, value), nil
}

// ValidateManagedDaemonConfig proves that all five Docker mutation controls
// are explicitly false while retaining a strict, duplicate-free JSON object.
func ValidateManagedDaemonConfig(path string) error {
	value, existed, err := readDaemonObject(path)
	if err != nil {
		return err
	}
	if !existed {
		return errors.New("DOCKER_DAEMON_CONFIG_MISSING")
	}
	for _, option := range []string{
		"iptables", "ip6tables", "ip-forward", "ip-masq", "userland-proxy",
	} {
		if configured, ok := value[option].(bool); !ok || configured {
			return fmt.Errorf("DOCKER_DAEMON_OPTION_NOT_OWNED_%s",
				strings.ToUpper(strings.ReplaceAll(option, "-", "_")))
		}
	}
	return nil
}

// ManagedDaemonConfigFingerprint returns a private digest of the exact
// protected source file, including whether it exists. Adoption planning uses
// this only to prove that two observations saw the same daemon ownership
// input; the digest is never included in operator output.
func ManagedDaemonConfigFingerprint(path string) (string, error) {
	data, existed, err := readProtectedDaemonFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	if existed {
		_, _ = digest.Write([]byte{1})
	} else {
		_, _ = digest.Write([]byte{0})
	}
	_, _ = digest.Write(data)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func readDaemonObject(path string) (map[string]any, bool, error) {
	data, existed, err := readProtectedDaemonFile(path)
	if err != nil || !existed {
		return map[string]any{}, existed, err
	}
	var value any
	if err := decodeStrictJSON(data, &value); err != nil {
		return nil, false, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, false, errors.New("DOCKER_DAEMON_CONFIG_NOT_OBJECT")
	}
	return object, true, nil
}

func readProtectedDaemonFile(path string) ([]byte, bool, error) {
	return readProtectedDaemonFileWithHook(path, nil)
}

func readProtectedDaemonFileWithHook(path string, afterRead func()) ([]byte, bool, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, false, errors.New("DOCKER_DAEMON_CONFIG_PATH_INVALID")
	}
	if err := validateProtectedParent(path, "DOCKER_DAEMON_CONFIG_PARENT_UNSAFE"); err != nil {
		return nil, false, err
	}
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm()&0o022 != 0 || before.Size() < 0 || before.Size() > maxDaemonConfig {
		return nil, false, errors.New("DOCKER_DAEMON_CONFIG_FILE_UNSAFE")
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int64(beforeStat.Uid) != int64(os.Geteuid()) {
		return nil, false, errors.New("DOCKER_DAEMON_CONFIG_FILE_UNSAFE")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false, errors.New("DOCKER_DAEMON_CONFIG_READ_FAILED")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxDaemonConfig+1))
	if afterRead != nil {
		afterRead()
	}
	after, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || len(data) > maxDaemonConfig {
		return nil, false, errors.New("DOCKER_DAEMON_CONFIG_READ_FAILED")
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || beforeStat.Dev != afterStat.Dev || beforeStat.Ino != afterStat.Ino ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, false, errors.New("DOCKER_DAEMON_CONFIG_CHANGED_DURING_READ")
	}
	return data, true, nil
}

func validateProtectedParent(path, code string) error {
	parent := filepath.Dir(path)
	existing := parent
	for {
		info, err := os.Lstat(existing)
		if err == nil {
			resolved, resolveErr := filepath.EvalSymlinks(existing)
			if resolveErr != nil || resolved != existing || !info.IsDir() ||
				info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
				return errors.New(code)
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
				return errors.New(code)
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) || existing == filepath.Dir(existing) {
			return errors.New(code)
		}
		existing = filepath.Dir(existing)
	}
}

// ValidateManagedSocketDropInTarget verifies that the drop-in can be created
// only below a protected, non-symlinked systemd path.
func ValidateManagedSocketDropInTarget(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("DOCKER_SOCKET_DROPIN_PATH_INVALID")
	}
	if err := validateProtectedParent(path, "DOCKER_SOCKET_DROPIN_PARENT_UNSAFE"); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("DOCKER_SOCKET_DROPIN_UNSAFE")
	}
	return nil
}

// ValidateManagedSocketDropIn verifies the exact systemd sandbox exception
// used by managed Docker integration.
func ValidateManagedSocketDropIn(path string) error {
	if err := ValidateManagedSocketDropInTarget(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 || info.Size() != int64(len(ManagedSocketDropIn)) {
		return errors.New("DOCKER_SOCKET_DROPIN_UNSAFE")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("DOCKER_SOCKET_DROPIN_UNSAFE")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("DOCKER_SOCKET_DROPIN_READ_FAILED")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, int64(len(ManagedSocketDropIn))+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || string(data) != ManagedSocketDropIn {
		return errors.New("DOCKER_SOCKET_DROPIN_INVALID")
	}
	return nil
}

func decodeStrictJSON(data []byte, destination *any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder)
	if err != nil {
		return errors.New("DOCKER_DAEMON_CONFIG_INVALID")
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return errors.New("DOCKER_DAEMON_CONFIG_INVALID")
	}
	*destination = value
	return nil
}

func decodeJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("object key is not a string")
			}
			if _, duplicate := object[key]; duplicate {
				return nil, errors.New("duplicate object key")
			}
			value, err := decodeJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("unterminated object")
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			value, err := decodeJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("unterminated array")
		}
		return array, nil
	default:
		return nil, errors.New("unexpected delimiter")
	}
}

func semanticJSONEqual(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

// DiscoverNetworks returns every locally routed, eligible IPv4 Docker bridge
// as a canonical authorization tuple. Unsupported or ambiguous networks stop
// setup before any host mutation.
func (o Observer) DiscoverNetworks(ctx context.Context) ([]config.DockerNetwork, error) {
	summaries, err := o.listNetworks(ctx)
	if err != nil {
		return nil, err
	}
	var result []config.DockerNetwork
	bridges := map[string]string{}
	for _, summary := range summaries {
		if summary.Name == "host" {
			if summary.Driver != "host" {
				return nil, errors.New("DOCKER_NETWORK_BUILTIN_HOST_INVALID")
			}
			continue
		}
		if summary.Name == "none" {
			if summary.Driver != "null" {
				return nil, errors.New("DOCKER_NETWORK_BUILTIN_NONE_INVALID")
			}
			continue
		}
		if summary.Driver != "bridge" {
			return nil, fmt.Errorf("DOCKER_NETWORK_DRIVER_UNSUPPORTED_%s",
				sanitizeErrorName(summary.Name))
		}
		item, err := o.inspectNetwork(ctx, summary)
		if err != nil {
			return nil, err
		}
		if item.Internal == nil || item.EnableIPv6 == nil {
			return nil, fmt.Errorf("DOCKER_NETWORK_INSPECT_INCOMPLETE_%s",
				sanitizeErrorName(summary.Name))
		}
		if *item.Internal || *item.EnableIPv6 {
			return nil, fmt.Errorf("DOCKER_NETWORK_MODE_UNSUPPORTED_%s",
				sanitizeErrorName(summary.Name))
		}
		bridge := observedBridgeName(item.ID, item.Name, item.Options)
		if !linuxInterfaceName.MatchString(bridge) {
			return nil, fmt.Errorf("DOCKER_NETWORK_BRIDGE_INVALID_%s",
				sanitizeErrorName(summary.Name))
		}
		if prior, duplicate := bridges[bridge]; duplicate {
			return nil, fmt.Errorf("DOCKER_NETWORK_BRIDGE_SHARED_%s_%s",
				sanitizeErrorName(prior), sanitizeErrorName(summary.Name))
		}
		if _, err := o.output(ctx, 64<<10, "ip", "-j", "link", "show", "dev", bridge); err != nil {
			return nil, fmt.Errorf("DOCKER_NETWORK_BRIDGE_MISSING_%s",
				sanitizeErrorName(summary.Name))
		}
		subnets, gateways, err := dockerIPv4IPAM(item)
		if err != nil {
			return nil, fmt.Errorf("DOCKER_NETWORK_IPAM_INVALID_%s",
				sanitizeErrorName(summary.Name))
		}
		bridges[bridge] = summary.Name
		result = append(result, config.DockerNetwork{
			Name: summary.Name, Driver: "bridge", BridgeInterface: bridge,
			DynamicBridge: true, Subnets: subnets, Gateways: gateways,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	if len(result) == 0 || len(result) > 62 {
		return nil, errors.New("DOCKER_NETWORK_COUNT_UNSUPPORTED")
	}
	return result, nil
}

type networkSummary struct {
	ID     string
	Name   string
	Driver string
}

type inspectedNetwork struct {
	ID         string            `json:"Id"`
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Internal   *bool             `json:"Internal"`
	EnableIPv6 *bool             `json:"EnableIPv6"`
	Options    map[string]string `json:"Options"`
	IPAM       struct {
		Config []struct {
			Subnet  string `json:"Subnet"`
			Gateway string `json:"Gateway"`
		} `json:"Config"`
	} `json:"IPAM"`
}

func (o Observer) listNetworks(ctx context.Context) ([]networkSummary, error) {
	bin := o.DockerBinary
	if bin == "" {
		bin = "docker"
	}
	out, err := o.output(ctx, 128<<10, bin, "--host", localDockerHost,
		"network", "ls", "--no-trunc", "--format", "{{.ID}}\t{{.Name}}\t{{.Driver}}")
	if err != nil {
		return nil, errors.New("DOCKER_NETWORK_LIST_FAILED")
	}
	lines := splitLines(string(out))
	if len(lines) == 0 || len(lines) > 1024 {
		return nil, errors.New("DOCKER_NETWORK_LIST_INVALID")
	}
	ids := map[string]bool{}
	names := map[string]bool{}
	result := make([]networkSummary, 0, len(lines))
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || !dockerID.MatchString(fields[0]) ||
			!dockerName.MatchString(fields[1]) || ids[fields[0]] || names[fields[1]] {
			return nil, errors.New("DOCKER_NETWORK_LIST_INVALID")
		}
		ids[fields[0]], names[fields[1]] = true, true
		result = append(result, networkSummary{ID: fields[0], Name: fields[1], Driver: fields[2]})
	}
	return result, nil
}

func (o Observer) inspectNetwork(ctx context.Context, summary networkSummary) (inspectedNetwork, error) {
	bin := o.DockerBinary
	if bin == "" {
		bin = "docker"
	}
	raw, err := o.output(ctx, 1<<20, bin, "--host", localDockerHost,
		"network", "inspect", "--", summary.ID)
	if err != nil {
		return inspectedNetwork{}, errors.New("DOCKER_NETWORK_INSPECT_FAILED")
	}
	var items []inspectedNetwork
	if json.Unmarshal(raw, &items) != nil || len(items) != 1 {
		return inspectedNetwork{}, errors.New("DOCKER_NETWORK_INSPECT_INVALID")
	}
	item := items[0]
	if item.ID != summary.ID || item.Name != summary.Name || item.Driver != summary.Driver {
		return inspectedNetwork{}, errors.New("DOCKER_NETWORK_CHANGED_DURING_READ")
	}
	return item, nil
}

func observedBridgeName(id, name string, options map[string]string) string {
	if configured := options["com.docker.network.bridge.name"]; configured != "" {
		return configured
	}
	if name == "bridge" {
		return "docker0"
	}
	if len(id) >= 12 {
		return "br-" + id[:12]
	}
	return ""
}

func dockerIPv4IPAM(item inspectedNetwork) ([]string, []string, error) {
	type pair struct {
		subnet  string
		gateway string
	}
	var pairs []pair
	seen := map[string]bool{}
	for _, value := range item.IPAM.Config {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value.Subnet))
		gateway, gatewayErr := netip.ParseAddr(strings.TrimSpace(value.Gateway))
		if err != nil || gatewayErr != nil || !prefix.Addr().Is4() ||
			!gateway.Is4() || prefix.Bits() == 0 || prefix.Bits() > 30 ||
			!prefix.Contains(gateway) ||
			gateway == prefix.Masked().Addr() || gateway == lastIPv4Address(prefix) {
			return nil, nil, errors.New("invalid IPv4 IPAM")
		}
		subnet := prefix.Masked().String()
		if seen[subnet] {
			return nil, nil, errors.New("duplicate IPv4 IPAM")
		}
		seen[subnet] = true
		pairs = append(pairs, pair{subnet: subnet, gateway: gateway.String()})
	}
	if len(pairs) == 0 || len(pairs) > 16 {
		return nil, nil, errors.New("unsupported IPv4 IPAM count")
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].subnet < pairs[j].subnet })
	subnets := make([]string, len(pairs))
	gateways := make([]string, len(pairs))
	for index, value := range pairs {
		subnets[index], gateways[index] = value.subnet, value.gateway
	}
	return subnets, gateways, nil
}

func lastIPv4Address(prefix netip.Prefix) netip.Addr {
	prefix = prefix.Masked()
	raw := prefix.Addr().As4()
	value := binary.BigEndian.Uint32(raw[:])
	hostBits := uint(32 - prefix.Bits())
	value |= uint32(1<<hostBits) - 1
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], value)
	return netip.AddrFrom4(result)
}

func sanitizeErrorName(value string) string {
	var builder strings.Builder
	for _, character := range strings.ToUpper(value) {
		if character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('_')
		}
		if builder.Len() >= 48 {
			break
		}
	}
	if builder.Len() == 0 {
		return "UNKNOWN"
	}
	return builder.String()
}

// ProjectObservedConfig updates only dynamic Docker bridge bindings after
// Observer.Networks has proved the stable name/driver/subnet/gateway tuple.
// The immutable provenance identity and ID remain unchanged.
func ProjectObservedConfig(source config.Config, observed []Network) (config.Config, error) {
	if !source.Integrations.DockerEnabled {
		return source, nil
	}
	type projection struct {
		bridge  string
		subnets []string
	}
	byName := map[string]projection{}
	for _, network := range observed {
		current := byName[network.Name]
		if current.bridge != "" && current.bridge != network.BridgeInterface {
			return config.Config{}, errors.New("DOCKER_NETWORK_BRIDGE_AMBIGUOUS")
		}
		current.bridge = network.BridgeInterface
		current.subnets = append(current.subnets, network.CIDR)
		byName[network.Name] = current
	}
	result := source
	result.Interfaces = append([]config.Interface(nil), source.Interfaces...)
	result.Zones = append([]config.Zone(nil), source.Zones...)
	result.DockerNetworks = append([]config.DockerNetwork(nil), source.DockerNetworks...)
	replacements := map[string]string{}
	for index := range result.DockerNetworks {
		network := &result.DockerNetworks[index]
		current, ok := byName[network.Name]
		if !ok || !linuxInterfaceName.MatchString(current.bridge) {
			return config.Config{}, fmt.Errorf("DOCKER_NETWORK_ABSENT_%s", sanitizeErrorName(network.Name))
		}
		sort.Strings(current.subnets)
		oldBridge := network.BridgeInterface
		if !network.DynamicBridge && oldBridge != current.bridge {
			return config.Config{}, fmt.Errorf("DOCKER_NETWORK_BRIDGE_DRIFT_%s", sanitizeErrorName(network.Name))
		}
		network.BridgeInterface = current.bridge
		network.Subnets = append([]string(nil), current.subnets...)
		found := false
		for interfaceIndex := range result.Interfaces {
			configured := &result.Interfaces[interfaceIndex]
			if config.InterfaceProvenanceName(*configured) != "docker:"+network.Name {
				continue
			}
			if configured.Role != "container" {
				return config.Config{}, errors.New("DOCKER_PROVENANCE_ROLE_INVALID")
			}
			configured.Name = current.bridge
			configured.CIDRs = append([]string(nil), current.subnets...)
			found = true
			break
		}
		if !found {
			return config.Config{}, fmt.Errorf("DOCKER_PROVENANCE_INTERFACE_MISSING_%s",
				sanitizeErrorName(network.Name))
		}
		replacements[oldBridge] = current.bridge
	}
	for index := range result.Zones {
		zone := &result.Zones[index]
		zone.Interfaces = append([]string(nil), zone.Interfaces...)
		for interfaceIndex, name := range zone.Interfaces {
			if replacement := replacements[name]; replacement != "" {
				zone.Interfaces[interfaceIndex] = replacement
			}
		}
		sort.Strings(zone.Interfaces)
	}
	if err := config.Validate(result); err != nil {
		return config.Config{}, fmt.Errorf("project observed Docker bindings: %w", err)
	}
	return result, nil
}
