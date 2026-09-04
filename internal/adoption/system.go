package adoption

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/containers"
	"github.com/unknown0152/nft-firewall-v2/internal/discovery"
	"github.com/unknown0152/nft-firewall-v2/internal/netgate"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
	"github.com/unknown0152/nft-firewall-v2/internal/routing"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/wgconfig"
)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type Paths struct {
	Root         string
	Config       string
	Intent       string
	DockerDaemon string
}

func DefaultPaths() Paths {
	return Paths{
		Root: "/", Config: "/etc/nftfw/nftfw.toml",
		Intent: "/etc/nftfw/intent.toml", DockerDaemon: "/etc/docker/daemon.json",
	}
}

// SystemInspector owns only read-only dependencies. Inspect deliberately
// repeats the complete observation and refuses if either the sanitized facts
// or the private digests differ.
type SystemInspector struct {
	Paths  Paths
	Runner Runner
}

type inspected struct {
	Observation Observation
	Fingerprint string
}

func (s SystemInspector) Inspect(ctx context.Context, vpnPath string) (Observation, error) {
	s.defaults()
	first, err := s.inspectOnce(ctx, vpnPath)
	if err != nil {
		return Observation{}, err
	}
	second, err := s.inspectOnce(ctx, vpnPath)
	if err != nil {
		return Observation{}, fail("ADOPTION_OBSERVATION_CHANGED")
	}
	if first.Fingerprint != second.Fingerprint || !reflect.DeepEqual(first.Observation, second.Observation) {
		second.Observation.Stable = false
		return second.Observation, nil
	}
	second.Observation.Stable = true
	return second.Observation, nil
}

func (s *SystemInspector) defaults() {
	defaults := DefaultPaths()
	if s.Paths.Root == "" {
		s.Paths.Root = defaults.Root
	}
	if s.Paths.Config == "" {
		s.Paths.Config = defaults.Config
	}
	if s.Paths.Intent == "" {
		s.Paths.Intent = defaults.Intent
	}
	if s.Paths.DockerDaemon == "" {
		s.Paths.DockerDaemon = defaults.DockerDaemon
	}
	if s.Runner == nil {
		s.Runner = discovery.ExecRunner{}
	}
}

func (s SystemInspector) inspectOnce(ctx context.Context, vpnPath string) (inspected, error) {
	managed, err := pathExists(s.Paths.Intent)
	if err != nil {
		return inspected{}, fail("ADOPTION_INTENT_STATE_UNREADABLE")
	}
	if managed {
		observation := Observation{Managed: true, ExistingState: true}
		return inspected{Observation: observation, Fingerprint: digestValue(observation)}, nil
	}
	configExists, err := pathExists(s.Paths.Config)
	if err != nil {
		return inspected{}, fail("ADOPTION_CONFIG_INVALID")
	}
	if !configExists {
		observation := Observation{ExistingState: false}
		return inspected{Observation: observation, Fingerprint: digestValue(observation)}, nil
	}
	profile, profileSummary, err := wgconfig.Read(vpnPath)
	if err != nil {
		return inspected{}, fail("ADOPTION_PROFILE_UNSUPPORTED")
	}
	configured, err := config.Load(s.Paths.Config)
	if err != nil {
		return inspected{}, fail("ADOPTION_CONFIG_INVALID")
	}
	store, err := state.OpenReadOnly(ctx, configured.State.Database)
	if err != nil {
		return inspected{}, fail("ADOPTION_STATE_INVALID")
	}
	defer store.Close()
	if err := store.QuickCheck(ctx); err != nil {
		return inspected{}, fail("ADOPTION_STATE_INVALID")
	}
	pending := false
	if _, pendingErr := store.Pending(ctx); pendingErr == nil {
		pending = true
	} else if !errors.Is(pendingErr, sql.ErrNoRows) {
		return inspected{}, fail("ADOPTION_STATE_INVALID")
	}
	committed, err := store.LastKnownGood(ctx)
	if err != nil {
		return inspected{}, fail("ADOPTION_STATE_INVALID")
	}
	if _, err := store.ReadScript(committed); err != nil {
		return inspected{}, fail("ADOPTION_STATE_INVALID")
	}
	pointer, enabled, err := state.ReadEnforcementPointer(configured.State.Directory)
	if err != nil || !enabled || pointer == nil {
		return inspected{}, fail("ADOPTION_STATE_INVALID")
	}
	snapshot, err := state.LoadVerifiedGenerationSnapshot(configured.State.Directory, pointer.Generation)
	if err != nil {
		return inspected{}, fail("ADOPTION_STATE_INVALID")
	}
	pointerMatches := snapshot.Pointer().Equal(pointer) && committed.ID == pointer.Generation &&
		committed.Checksum == pointer.PolicyChecksum &&
		committed.SnapshotChecksum == pointer.SnapshotChecksum
	livePolicyFingerprint, livePolicyErr := livePolicyFingerprint(ctx, s.Runner)
	livePolicyMatches := livePolicyErr == nil && committed.ObservedHash != "" &&
		livePolicyFingerprint == committed.ObservedHash

	ledger, err := provenance.OpenReadOnly(ctx, configured.State.ProvenanceLedger)
	if err != nil {
		return inspected{}, fail("ADOPTION_PROVENANCE_INVALID")
	}
	defer ledger.Close()
	required := requiredProvenance(configured)
	provenanceValid := ledger.ValidateRequired(ctx, required) == nil
	assignments, assignmentErr := ledger.Assignments(ctx)
	ledgerDigest, digestErr := ledger.Digest(ctx)
	if assignmentErr != nil || digestErr != nil {
		return inspected{}, fail("ADOPTION_PROVENANCE_INVALID")
	}
	activeProvenance := 0
	for _, assignment := range assignments {
		if !assignment.Retired {
			activeProvenance++
		}
	}
	provenanceValid = provenanceValid && exactActiveProvenance(assignments, required)

	host, err := (discovery.Inspector{Runner: s.Runner, Root: s.Paths.Root}).Inspect(ctx)
	if err != nil {
		return inspected{}, fail("ADOPTION_DISCOVERY_FAILED")
	}
	installedVersion, err := s.installedVersion(ctx)
	if err != nil {
		return inspected{}, err
	}
	units, err := s.unitStates(ctx, installedVersion)
	if err != nil {
		return inspected{}, err
	}
	networkProducers, err := netgate.Discover(ctx, netgateReadAdapter{s.Runner})
	if err != nil {
		return inspected{}, fail("ADOPTION_NETWORK_PRODUCER_UNSUPPORTED")
	}
	resolver, resolverErr := routing.DetectResolver(
		ctx, routingReadAdapter{s.Runner}, len(profile.DNS) > 0,
	)
	routingValid, routeDigest := s.routingState(ctx)
	uplinkMatches := configUplink(configured) == host.Uplink
	management, publicTCP, publicUDP, exposureValid := exposureSummary(configured)
	dockerConfigured := len(configured.DockerNetworks)
	dockerObserved := len(host.DockerNetworks)
	dockerTopologyValid := dockerCompatibleSubset(configured.DockerNetworks, host.DockerNetworks)
	dockerDaemonDigest := "not-owned"
	dockerRestartRequired := false
	if host.DockerPresent {
		daemonData, daemonChanged, daemonErr := containers.ManagedDaemonConfig(s.Paths.DockerDaemon)
		daemonFingerprint, fingerprintErr := containers.ManagedDaemonConfigFingerprint(s.Paths.DockerDaemon)
		dockerTopologyValid = dockerTopologyValid && daemonErr == nil && fingerprintErr == nil
		if daemonErr == nil && fingerprintErr == nil {
			dockerRestartRequired = daemonChanged
			dockerDaemonDigest = digestStrings(string(daemonData), daemonFingerprint)
		}
	}
	if configured.Integrations.DockerEnabled {
		dockerTopologyValid = dockerTopologyValid && !dockerRestartRequired &&
			containers.ValidateManagedDaemonConfig(s.Paths.DockerDaemon) == nil
	} else if !host.DockerPresent {
		dockerTopologyValid = true
	} else {
		// An advanced 2.0.3 configuration may not yet carry Amendment F's
		// explicit Docker tuples. Strict discovery has nevertheless proved
		// every observed network eligible, so the worksheet can describe the
		// later ownership transfer even while workloads are active.
		dockerTopologyValid = dockerTopologyValid && dockerObserved > 0
	}
	ipv4Forwarding, forwardingValid := s.ipv4Forwarding(ctx)
	if !forwardingValid {
		return inspected{}, fail("ADOPTION_SYSCTL_UNREADABLE")
	}

	profileDigest := digestValue(profile)
	configDigest := digestValue(configured)
	discoveryDigest := digestValue(host)
	fingerprint := digestStrings(
		profileDigest, configDigest, discoveryDigest, ledgerDigest, routeDigest,
		installedVersion, digestValue(units), digestValue(committed),
		digestValue(pointer), livePolicyFingerprint, dockerDaemonDigest, digestValue(networkProducers),
	)
	return inspected{Observation: Observation{
		InstalledVersion: installedVersion, Managed: managed, ExistingState: true,
		OSID: host.OSID, OSVersion: host.OSVersion, Architecture: host.Architecture,
		NetworkValid:  host.Uplink != "" && host.UplinkGateway.Is4() && configVPNValid(configured),
		UplinkMatches: uplinkMatches, LANNetworkCount: len(host.LANNetworks),
		ManagementTCP: management, IPv6Mode: configured.System.IPv6Mode,
		IPv6DefaultRoute: host.IPv6DefaultRoute,
		ResolverMode:     string(resolver), ResolverValid: resolverErr == nil,
		RoutingValid: routingValid, ExposureValid: exposureValid,
		FirewallOwned: host.OwnedNFTables, ForeignNFTables: host.ForeignNFTables,
		CompetingFirewalls: append([]string(nil), host.CompetingFirewallUnits...),
		StateValid:         true, StateSchema: CurrentStateSchema,
		Generation: committed.ID, PolicyChecksum: committed.Checksum,
		EnforcementEnabled: enabled, PointerMatches: pointerMatches,
		LivePolicyMatches: livePolicyMatches,
		PendingGeneration: pending, ProvenanceValid: provenanceValid,
		ProvenanceActive: activeProvenance,
		DockerPresent:    host.DockerPresent, DockerClean: host.DockerClean,
		DockerConfigured: dockerConfigured, DockerObserved: dockerObserved,
		DockerTopologyValid:   dockerTopologyValid,
		IPv4Forwarding:        ipv4Forwarding && forwardingValid,
		DockerRestartRequired: dockerRestartRequired,
		PublicTCP:             publicTCP, PublicUDP: publicUDP, Units: units,
		NetworkProducers: networkProducers,
		Profile: ProfileSummary{
			AddressCount: profileSummary.AddressCount, DNSCount: profileSummary.DNSCount,
			HasMTU: profileSummary.HasMTU, HasPresharedKey: profileSummary.HasPresharedKey,
			HasKeepalive:        profileSummary.HasKeepalive,
			IPv4DefaultRoute:    profileSummary.IPv4DefaultRoute,
			SourceWorldReadable: profileSummary.SourceWorldReadable,
		},
	}, Fingerprint: fingerprint}, nil
}

func pathExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("unsafe path")
	}
	return true, nil
}

func (s SystemInspector) installedVersion(ctx context.Context) (string, error) {
	output, err := s.Runner.Run(ctx, "dpkg-query", "-W", "-f=${Version}", "nft-firewall-v2")
	value := strings.TrimSpace(string(output))
	if err != nil || !compatibleVersion(value) {
		return "", fail("ADOPTION_PACKAGE_VERSION_UNSUPPORTED")
	}
	return value, nil
}

var adoptionUnits = []string{
	"nftfw-early.service", "nftfw-enforcement-ready.service", "nftfwd.service",
	"nftfw-managed-rollback.timer", "nftfw-rollback.timer",
	"nftfw-setup-rollback.timer", "nftfw-vpn.service", "nftfw-web.service",
}

var legacyAbsentUnits = map[string]bool{
	"nftfw-managed-rollback.timer": true,
	"nftfw-setup-rollback.timer":   true,
	"nftfw-vpn.service":            true,
}

type observedUnitState struct {
	ID, Names, LoadState, ActiveState, UnitFileState, FragmentPath string
}

func (s SystemInspector) unitStates(ctx context.Context, installedVersion string) ([]UnitState, error) {
	result := make([]UnitState, 0, len(adoptionUnits))
	for _, unit := range adoptionUnits {
		output, err := s.Runner.Run(ctx, "systemctl", "show",
			"--property=Id,Names,LoadState,ActiveState,UnitFileState,FragmentPath", unit)
		if err != nil {
			return nil, fail("ADOPTION_UNIT_STATE_UNREADABLE")
		}
		observed, err := parseUnitState(output)
		if err != nil || observed.ID != unit || observed.Names != unit {
			return nil, fail("ADOPTION_UNIT_STATE_UNREADABLE")
		}
		if canonicalLegacyUnitAbsence(observed, unit, installedVersion) {
			result = append(result, UnitState{Name: unit})
			continue
		}
		if observed.LoadState != "loaded" || !allowedActiveState(observed.ActiveState) ||
			!allowedUnitFileState(observed.UnitFileState) ||
			!canonicalVendorUnitPath(observed.FragmentPath, unit) {
			return nil, fail("ADOPTION_UNIT_STATE_UNREADABLE")
		}
		result = append(result, UnitState{
			Name: unit, Active: observed.ActiveState == "active",
			Enabled: observed.UnitFileState == "enabled" || observed.UnitFileState == "enabled-runtime",
		})
	}
	return result, nil
}

func parseUnitState(data []byte) (observedUnitState, error) {
	if len(data) == 0 || len(data) > 4096 || !strings.HasSuffix(string(data), "\n") {
		return observedUnitState{}, errors.New("invalid unit state")
	}
	values := map[string]string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] || strings.ContainsAny(value, "\r\n") {
			return observedUnitState{}, errors.New("invalid unit state")
		}
		switch key {
		case "Id", "Names", "LoadState", "ActiveState", "UnitFileState", "FragmentPath":
			seen[key] = true
			values[key] = value
		default:
			return observedUnitState{}, errors.New("invalid unit state")
		}
	}
	for _, key := range []string{"Id", "Names", "LoadState", "ActiveState", "UnitFileState", "FragmentPath"} {
		if _, ok := values[key]; !ok {
			return observedUnitState{}, errors.New("invalid unit state")
		}
	}
	return observedUnitState{
		ID: values["Id"], Names: values["Names"], LoadState: values["LoadState"],
		ActiveState: values["ActiveState"], UnitFileState: values["UnitFileState"],
		FragmentPath: values["FragmentPath"],
	}, nil
}

func canonicalLegacyUnitAbsence(observed observedUnitState, unit, installedVersion string) bool {
	return legacyAbsentUnits[unit] && strings.HasPrefix(installedVersion, "2.0.3") &&
		observed.LoadState == "not-found" && observed.ActiveState == "inactive" &&
		observed.UnitFileState == "" && observed.FragmentPath == ""
}

func canonicalVendorUnitPath(path, unit string) bool {
	return path == "/usr/lib/systemd/system/"+unit || path == "/lib/systemd/system/"+unit
}

func allowedActiveState(value string) bool {
	switch value {
	case "active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance":
		return true
	default:
		return false
	}
}

func allowedUnitFileState(value string) bool {
	switch value {
	case "enabled", "enabled-runtime", "disabled", "static", "indirect", "masked",
		"masked-runtime", "generated", "transient", "linked", "linked-runtime":
		return true
	default:
		return false
	}
}

func (s SystemInspector) routingState(ctx context.Context) (bool, string) {
	rules, rulesErr := s.Runner.Run(ctx, "ip", "-j", "-4", "rule", "show")
	routes, routesErr := s.Runner.Run(ctx, "ip", "-j", "-4", "route", "show", "table", "all")
	if rulesErr != nil || routesErr != nil || !validJSONArray(rules, 4096) || !validJSONArray(routes, 65536) {
		return false, ""
	}
	return true, digestStrings(string(rules), string(routes))
}

func validJSONArray(data []byte, limit int) bool {
	if len(data) == 0 || len(data) > 1<<20 {
		return false
	}
	var values []json.RawMessage
	return json.Unmarshal(data, &values) == nil && len(values) <= limit
}

func (s SystemInspector) ipv4Forwarding(ctx context.Context) (bool, bool) {
	output, err := s.Runner.Run(ctx, "sysctl", "-n", "net.ipv4.ip_forward")
	value := strings.TrimSpace(string(output))
	return value == "1", err == nil && (value == "0" || value == "1")
}

type routingReadAdapter struct{ Runner }

func (a routingReadAdapter) Run(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	if len(input) != 0 {
		return nil, errors.New("read-only adoption runner rejects stdin")
	}
	return a.Runner.Run(ctx, name, args...)
}

type netgateReadAdapter struct{ Runner }

func (a netgateReadAdapter) Run(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	if len(input) != 0 {
		return nil, errors.New("read-only adoption runner rejects stdin")
	}
	return a.Runner.Run(ctx, name, args...)
}

func livePolicyFingerprint(ctx context.Context, runner Runner) (string, error) {
	digest := sha256.New()
	for _, table := range nft.OwnedTables {
		data, err := readOwnedNFTTable(ctx, runner, table)
		if err != nil {
			return "", err
		}
		canonical, err := nft.CanonicalOwnedTableJSON(data, table)
		if err != nil {
			return "", err
		}
		_, _ = digest.Write(canonical)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func readOwnedNFTTable(ctx context.Context, runner Runner, table nft.Table) ([]byte, error) {
	owned := false
	for _, candidate := range nft.OwnedTables {
		if candidate == table {
			owned = true
			break
		}
	}
	if !owned {
		return nil, errors.New("read-only adoption nft reader rejects table")
	}
	return runner.Run(ctx, "nft", "-j", "list", "table", table.Family, table.Name)
}

func requiredProvenance(value config.Config) []provenance.Assignment {
	result := make([]provenance.Assignment, 0, len(value.Interfaces))
	for _, configured := range value.Interfaces {
		result = append(result, provenance.Assignment{
			Name: config.InterfaceProvenanceName(configured), ID: configured.ProvenanceID,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func exactActiveProvenance(have, required []provenance.Assignment) bool {
	expected := map[string]uint8{}
	for _, assignment := range required {
		expected[assignment.Name] = assignment.ID
	}
	active := 0
	for _, assignment := range have {
		if assignment.Retired {
			continue
		}
		active++
		if expected[assignment.Name] != assignment.ID {
			return false
		}
	}
	return active == len(expected)
}

func configUplink(value config.Config) string {
	for _, configured := range value.Interfaces {
		if configured.Role == "uplink" {
			return configured.Name
		}
	}
	return ""
}

func configVPNValid(value config.Config) bool {
	count := 0
	name := ""
	for _, configured := range value.Interfaces {
		if configured.Role == "vpn" {
			count++
			name = configured.Name
		}
	}
	return count == 1 && name == value.WireGuard.Interface
}

func exposureSummary(value config.Config) ([]int, []int, []int, bool) {
	services := map[string]config.Service{}
	for _, service := range value.Services {
		services[service.Name] = service
	}
	managementSet := map[int]bool{}
	for _, name := range value.Runtime.TrustedServices {
		for _, port := range services[name].Ports {
			managementSet[port] = true
		}
	}
	vpnInterfaces := map[string]bool{}
	vpnZones := map[string]bool{}
	for _, configured := range value.Interfaces {
		if configured.Role == "vpn" {
			vpnInterfaces[configured.Name] = true
			if configured.Zone != "" {
				vpnZones[configured.Zone] = true
			}
		}
	}
	for _, zone := range value.Zones {
		for _, interfaceName := range zone.Interfaces {
			if vpnInterfaces[interfaceName] {
				vpnZones[zone.Name] = true
			}
		}
	}
	tcpSet, udpSet := map[int]bool{}, map[int]bool{}
	valid := true
	for _, policy := range value.Policies {
		if policy.Action != "allow" || policy.To != "host" {
			continue
		}
		if policy.From == "any" {
			valid = false
			continue
		}
		if !vpnZones[policy.From] {
			continue
		}
		service := services[policy.Service]
		target := tcpSet
		if service.Protocol == "udp" {
			target = udpSet
		} else if service.Protocol != "tcp" {
			valid = false
			continue
		}
		for _, port := range service.Ports {
			target[port] = true
		}
	}
	for _, rule := range value.NAT {
		if !vpnInterfaces[rule.ExternalInterface] {
			valid = false
			continue
		}
		if rule.Protocol == "tcp" {
			tcpSet[rule.ExternalPort] = true
		} else if rule.Protocol == "udp" {
			udpSet[rule.ExternalPort] = true
		}
	}
	return sortedPortSet(managementSet), sortedPortSet(tcpSet), sortedPortSet(udpSet), valid
}

func sortedPortSet(values map[int]bool) []int {
	result := make([]int, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Ints(result)
	return result
}

func dockerCompatibleSubset(configured, observed []config.DockerNetwork) bool {
	left := canonicalDocker(configured)
	right := canonicalDocker(observed)
	byName := make(map[string]config.DockerNetwork, len(right))
	for _, network := range right {
		byName[network.Name] = network
	}
	for _, network := range left {
		if current, ok := byName[network.Name]; !ok || !reflect.DeepEqual(network, current) {
			return false
		}
	}
	return true
}

func canonicalDocker(values []config.DockerNetwork) []config.DockerNetwork {
	result := append([]config.DockerNetwork(nil), values...)
	for index := range result {
		type pair struct{ subnet, gateway string }
		pairs := make([]pair, len(result[index].Subnets))
		for pairIndex := range pairs {
			pairs[pairIndex] = pair{
				subnet:  result[index].Subnets[pairIndex],
				gateway: result[index].Gateways[pairIndex],
			}
		}
		sort.Slice(pairs, func(a, b int) bool { return pairs[a].subnet < pairs[b].subnet })
		result[index].Subnets = make([]string, len(pairs))
		result[index].Gateways = make([]string, len(pairs))
		for pairIndex, value := range pairs {
			result[index].Subnets[pairIndex] = value.subnet
			result[index].Gateways[pairIndex] = value.gateway
		}
		// DynamicBridge is a managed-runtime behavior, not part of an advanced
		// topology's semantic network tuple.
		result[index].DynamicBridge = false
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func digestValue(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "invalid"
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func digestStrings(values ...string) string {
	digest := sha256.New()
	for _, value := range values {
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(value))
	}
	return hex.EncodeToString(digest.Sum(nil))
}
