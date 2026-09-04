// Package adoption builds a deterministic, non-mutating worksheet for an
// existing compatible NFTFW installation. It deliberately has no writer,
// transaction, service-control, firewall, routing, or Docker mutation API.
package adoption

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/unknown0152/nft-firewall-v2/internal/netgate"
)

const (
	Schema             = "nftfw.adoption-plan.v1"
	CurrentStateSchema = 6
)

// Error contains only a stable, non-secret refusal code.
type Error struct {
	Code string
}

func (e Error) Error() string { return e.Code }

func fail(code string) error { return Error{Code: code} }

// ErrorCode reduces every failure to a bounded code so filesystem paths,
// endpoints, database details, and provider material cannot reach CLI output.
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var adoptionError Error
	if errors.As(err, &adoptionError) && validCode(adoptionError.Code) {
		return adoptionError.Code
	}
	return "ADOPTION_INSPECTION_FAILED"
}

func validCode(value string) bool {
	if !strings.HasPrefix(value, "ADOPTION_") || len(value) > 96 {
		return false
	}
	for _, character := range value {
		if character != '_' && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}

// OperatorError is the complete ordinary-operator refusal contract. It never
// appends an underlying error and therefore cannot disclose protected input.
func OperatorError(err error) error {
	return fmt.Errorf("%s: adoption planning failed; live state changed: NO; rollback required: NO; next: sudo nftfw setup adopt --vpn /path/to/provider.conf --dry-run; detailed log: sudo journalctl -u nftfwd (the planner writes no log)", ErrorCode(err))
}

type ProfileSummary struct {
	AddressCount        int  `json:"address_count"`
	DNSCount            int  `json:"dns_count"`
	HasMTU              bool `json:"has_mtu"`
	HasPresharedKey     bool `json:"has_preshared_key"`
	HasKeepalive        bool `json:"has_keepalive"`
	IPv4DefaultRoute    bool `json:"ipv4_default_route"`
	SourceWorldReadable bool `json:"source_world_readable"`
}

type UnitState struct {
	Name    string `json:"name"`
	Active  bool   `json:"active"`
	Enabled bool   `json:"enabled"`
}

// Observation contains only sanitized facts. A SystemInspector converts raw
// host data to this form before it crosses the package boundary.
type Observation struct {
	InstalledVersion string
	Managed          bool
	ExistingState    bool
	OSID             string
	OSVersion        string
	Architecture     string

	NetworkValid       bool
	NetworkProducers   []string
	UplinkMatches      bool
	LANNetworkCount    int
	ManagementTCP      []int
	IPv6Mode           string
	IPv6DefaultRoute   bool
	ResolverMode       string
	ResolverValid      bool
	RoutingValid       bool
	ExposureValid      bool
	FirewallOwned      bool
	ForeignNFTables    bool
	CompetingFirewalls []string

	StateValid         bool
	StateSchema        int
	Generation         uint64
	PolicyChecksum     string
	EnforcementEnabled bool
	PointerMatches     bool
	LivePolicyMatches  bool
	PendingGeneration  bool
	ProvenanceValid    bool
	ProvenanceActive   int

	DockerPresent         bool
	DockerClean           bool
	DockerConfigured      int
	DockerObserved        int
	DockerTopologyValid   bool
	IPv4Forwarding        bool
	DockerRestartRequired bool

	PublicTCP []int
	PublicUDP []int
	Units     []UnitState
	Profile   ProfileSummary
	Stable    bool
}

type Inspector interface {
	Inspect(context.Context, string) (Observation, error)
}

type Planner struct {
	Inspector Inspector
}

type StateSummary struct {
	Schema            int    `json:"schema"`
	Generation        uint64 `json:"generation"`
	PolicyChecksum    string `json:"policy_checksum"`
	Enforcement       string `json:"enforcement"`
	LivePolicy        string `json:"live_policy"`
	Provenance        string `json:"provenance"`
	ActiveProvenance  int    `json:"active_provenance"`
	PendingGeneration bool   `json:"pending_generation"`
}

type NetworkSummary struct {
	Uplink           string `json:"uplink"`
	LANNetworkCount  int    `json:"lan_network_count"`
	ManagementTCP    []int  `json:"management_tcp"`
	Resolver         string `json:"resolver"`
	IPv6Mode         string `json:"ipv6_mode"`
	IPv6DefaultRoute bool   `json:"ipv6_default_route"`
	ProducerCount    int    `json:"producer_count"`
}

type DockerSummary struct {
	Present            bool   `json:"present"`
	ActiveWorkloads    bool   `json:"active_workloads"`
	ConfiguredNetworks int    `json:"configured_networks"`
	ObservedNetworks   int    `json:"observed_networks"`
	Topology           string `json:"topology"`
	IPv4Forwarding     bool   `json:"ipv4_forwarding"`
	RestartRequired    bool   `json:"restart_required"`
}

type OwnershipChange struct {
	Area                     string `json:"area"`
	Current                  string `json:"current"`
	Proposed                 string `json:"proposed"`
	Interruption             string `json:"interruption"`
	SeparateApprovalRequired bool   `json:"separate_approval_required"`
}

type Plan struct {
	Schema           string            `json:"schema"`
	Status           string            `json:"status"`
	InstalledVersion string            `json:"installed_version"`
	CurrentMode      string            `json:"current_mode"`
	TargetMode       string            `json:"target_mode"`
	State            StateSummary      `json:"state"`
	Network          NetworkSummary    `json:"network"`
	Docker           DockerSummary     `json:"docker"`
	Profile          ProfileSummary    `json:"profile"`
	PublicTCP        []int             `json:"public_tcp"`
	PublicUDP        []int             `json:"public_udp"`
	Units            []UnitState       `json:"units"`
	OwnershipChanges []OwnershipChange `json:"ownership_changes"`
	BackupInputs     []string          `json:"backup_inputs"`
	RollbackBounds   []string          `json:"rollback_boundaries"`
	LiveStateChanged bool              `json:"live_state_changed"`
	RollbackRequired bool              `json:"rollback_required"`
	NextStep         string            `json:"next_step"`
	DetailedLog      string            `json:"detailed_log"`
}

func (p Planner) Plan(ctx context.Context, vpnPath string) (Plan, error) {
	if p.Inspector == nil || strings.TrimSpace(vpnPath) == "" {
		return Plan{}, fail("ADOPTION_INPUT_INVALID")
	}
	observation, err := p.Inspector.Inspect(ctx, vpnPath)
	if err != nil {
		return Plan{}, err
	}
	if err := validate(observation); err != nil {
		return Plan{}, err
	}
	management := canonicalPorts(observation.ManagementTCP)
	publicTCP := canonicalPorts(observation.PublicTCP)
	publicUDP := canonicalPorts(observation.PublicUDP)
	units := append([]UnitState(nil), observation.Units...)
	sort.Slice(units, func(i, j int) bool { return units[i].Name < units[j].Name })
	dockerTopology := "absent"
	if observation.DockerPresent {
		dockerTopology = "verified"
	}
	return Plan{
		Schema: Schema, Status: "READY_FOR_SEPARATE_LIVE_PLAN",
		InstalledVersion: observation.InstalledVersion,
		CurrentMode:      "advanced", TargetMode: "managed",
		State: StateSummary{
			Schema: observation.StateSchema, Generation: observation.Generation,
			PolicyChecksum: observation.PolicyChecksum, Enforcement: "verified",
			LivePolicy: "verified",
			Provenance: "verified", ActiveProvenance: observation.ProvenanceActive,
			PendingGeneration: false,
		},
		Network: NetworkSummary{
			Uplink: "verified-single-ipv4", LANNetworkCount: observation.LANNetworkCount,
			ManagementTCP: management, Resolver: observation.ResolverMode,
			IPv6Mode: observation.IPv6Mode, IPv6DefaultRoute: observation.IPv6DefaultRoute,
			ProducerCount: len(observation.NetworkProducers),
		},
		Docker: DockerSummary{
			Present:            observation.DockerPresent,
			ActiveWorkloads:    observation.DockerPresent && !observation.DockerClean,
			ConfiguredNetworks: observation.DockerConfigured,
			ObservedNetworks:   observation.DockerObserved,
			Topology:           dockerTopology, IPv4Forwarding: observation.IPv4Forwarding,
			RestartRequired: observation.DockerRestartRequired,
		},
		Profile: observation.Profile, PublicTCP: publicTCP, PublicUDP: publicUDP,
		Units: units, OwnershipChanges: ownershipChanges(
			observation.DockerPresent, observation.DockerRestartRequired,
		),
		BackupInputs:     backupInputs(observation.DockerPresent),
		RollbackBounds:   rollbackBounds(observation.DockerRestartRequired),
		LiveStateChanged: false, RollbackRequired: false,
		NextStep:    "Retain advanced mode or prepare a separately approved Stage E-L plan from this local worksheet.",
		DetailedLog: "sudo journalctl -u nftfwd (the planner writes no log)",
	}, nil
}

func validate(o Observation) error {
	if !o.Stable {
		return fail("ADOPTION_OBSERVATION_CHANGED")
	}
	if o.Managed {
		return fail("ADOPTION_ALREADY_MANAGED")
	}
	if !o.ExistingState {
		return fail("ADOPTION_CLEAN_HOST_USE_SETUP")
	}
	if o.OSID != "debian" || o.OSVersion != "13" {
		return fail("ADOPTION_OS_UNSUPPORTED")
	}
	if o.Architecture != "amd64" && o.Architecture != "arm64" {
		return fail("ADOPTION_ARCHITECTURE_UNSUPPORTED")
	}
	if !compatibleVersion(o.InstalledVersion) {
		return fail("ADOPTION_PACKAGE_VERSION_UNSUPPORTED")
	}
	if o.Profile.AddressCount < 1 || !o.Profile.IPv4DefaultRoute {
		return fail("ADOPTION_PROFILE_UNSUPPORTED")
	}
	if !o.NetworkValid || !o.UplinkMatches || o.LANNetworkCount < 1 {
		return fail("ADOPTION_NETWORK_AMBIGUOUS")
	}
	if netgate.ValidateUnits(o.NetworkProducers) != nil {
		return fail("ADOPTION_NETWORK_PRODUCER_UNSUPPORTED")
	}
	if !o.ExposureValid {
		return fail("ADOPTION_EXPOSURE_UNSUPPORTED")
	}
	if !o.FirewallOwned || o.ForeignNFTables || len(o.CompetingFirewalls) != 0 {
		return fail("ADOPTION_FIREWALL_OWNERSHIP_AMBIGUOUS")
	}
	if !o.StateValid || o.StateSchema != CurrentStateSchema || o.Generation == 0 ||
		!validSHA256(o.PolicyChecksum) || !o.EnforcementEnabled || !o.PointerMatches {
		return fail("ADOPTION_STATE_INVALID")
	}
	if !o.LivePolicyMatches {
		return fail("ADOPTION_POLICY_IDENTITY_MISMATCH")
	}
	if o.PendingGeneration {
		return fail("ADOPTION_PENDING_GENERATION")
	}
	if !o.ProvenanceValid || o.ProvenanceActive < 1 {
		return fail("ADOPTION_PROVENANCE_INVALID")
	}
	if !o.RoutingValid {
		return fail("ADOPTION_ROUTING_AMBIGUOUS")
	}
	if !o.ResolverValid || (o.ResolverMode != "none" && o.ResolverMode != "resolvectl" && o.ResolverMode != "resolvconf") {
		return fail("ADOPTION_RESOLVER_UNSUPPORTED")
	}
	if o.IPv6Mode != "disabled" {
		return fail("ADOPTION_IPV6_MODE_UNSUPPORTED")
	}
	if o.DockerConfigured < 0 || o.DockerObserved < 0 ||
		(o.DockerRestartRequired && !o.DockerPresent) ||
		(o.DockerPresent && (!o.DockerTopologyValid || o.DockerObserved < 1)) ||
		(o.DockerConfigured > 0 && (!o.DockerPresent || o.DockerObserved < o.DockerConfigured)) {
		return fail("ADOPTION_DOCKER_TOPOLOGY_UNSUPPORTED")
	}
	if !validPorts(o.ManagementTCP) || !validPorts(o.PublicTCP) || !validPorts(o.PublicUDP) ||
		!validUnits(o.Units) {
		return fail("ADOPTION_OBSERVATION_INVALID")
	}
	return nil
}

func compatibleVersion(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && !strings.ContainsRune(".+:~_-", character) {
			return false
		}
	}
	for _, release := range []string{"2.0.3", "2.1.0"} {
		if value == release || strings.HasPrefix(value, release+"-") ||
			strings.HasPrefix(value, release+"+") || strings.HasPrefix(value, release+"~") {
			return true
		}
	}
	return false
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}

func validPorts(values []int) bool {
	seen := map[int]bool{}
	for _, value := range values {
		if value < 1 || value > 65535 || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func canonicalPorts(values []int) []int {
	result := append([]int(nil), values...)
	sort.Ints(result)
	return result
}

func validUnits(values []UnitState) bool {
	if len(values) != len(adoptionUnits) {
		return false
	}
	allowed := make(map[string]bool, len(adoptionUnits))
	for _, name := range adoptionUnits {
		allowed[name] = true
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !allowed[value.Name] || seen[value.Name] {
			return false
		}
		seen[value.Name] = true
	}
	return true
}

func ownershipChanges(dockerPresent, dockerRestart bool) []OwnershipChange {
	result := []OwnershipChange{
		{Area: "firewall", Current: "advanced NFTFW", Proposed: "managed NFTFW", Interruption: "safe apply; no management or public-service interruption expected after validation", SeparateApprovalRequired: true},
		{Area: "vpn", Current: "existing WireGuard owner", Proposed: "managed nftfw-vpn", Interruption: "brief VPN and Internet interruption", SeparateApprovalRequired: true},
		{Area: "routing", Current: "existing policy routes", Proposed: "managed policy routes", Interruption: "coupled to VPN and Internet transfer", SeparateApprovalRequired: true},
		{Area: "resolver", Current: "existing resolver owner", Proposed: "managed VPN resolver", Interruption: "bounded DNS interruption", SeparateApprovalRequired: true},
		{Area: "sysctl", Current: "existing host values", Proposed: "managed IPv6 and forwarding values", Interruption: "none expected after validation", SeparateApprovalRequired: true},
		{Area: "boot", Current: "advanced NFTFW units", Proposed: "managed early protection", Interruption: "none until separately approved reboot", SeparateApprovalRequired: true},
		{Area: "network-producers", Current: "existing Debian network manager", Proposed: "readiness-gated managed ownership", Interruption: "none until separately approved reboot", SeparateApprovalRequired: true},
	}
	if dockerPresent {
		interruption := "none"
		if dockerRestart {
			interruption = "one separately confirmed Docker restart"
		}
		result = append(result, OwnershipChange{
			Area: "docker", Current: "existing Docker network ownership",
			Proposed:                 "NFTFW forwarding and eligible bridge ownership",
			Interruption:             interruption,
			SeparateApprovalRequired: true,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Area < result[j].Area })
	return result
}

func backupInputs(dockerPresent bool) []string {
	result := []string{
		"advanced configuration", "generation database", "enforcement pointer and snapshots",
		"monotonic provenance ledger", "WireGuard profile and routing state",
		"systemd unit states", "resolver and sysctl state",
		"network-producer unit fragments and dependency drop-ins",
	}
	if dockerPresent {
		result = append(result, "Docker daemon, socket-access, and network ownership state")
	}
	return result
}

func rollbackBounds(dockerRestart bool) []string {
	result := []string{
		"before ownership transfer", "after fail-closed guard", "after VPN transfer",
	}
	if dockerRestart {
		result = append(result, "after confirmed Docker restart")
	}
	return append(result, "after safe firewall apply", "after boot handoff")
}

// Human renders the same fields as JSON without exposing raw topology.
func (p Plan) Human() string {
	var output strings.Builder
	line := func(label, value string) { output.WriteString(label + ": " + value + "\n") }
	line("NFT Firewall V2 existing-host adoption plan", p.Schema)
	line("Status", p.Status)
	line("Installed package", p.InstalledVersion)
	line("Current mode", strings.ToUpper(p.CurrentMode))
	line("Target mode", strings.ToUpper(p.TargetMode)+" (SEPARATE STAGE E-L)")
	line("State", "schema "+strconv.Itoa(p.State.Schema)+", generation "+strconv.FormatUint(p.State.Generation, 10)+", policy "+p.State.PolicyChecksum)
	line("Enforcement", strings.ToUpper(p.State.Enforcement))
	line("Live policy", strings.ToUpper(p.State.LivePolicy))
	line("Provenance", strings.ToUpper(p.State.Provenance)+" (active "+strconv.Itoa(p.State.ActiveProvenance)+")")
	line("Pending generation", boolText(p.State.PendingGeneration))
	line("Network", p.Network.Uplink+", LAN networks "+strconv.Itoa(p.Network.LANNetworkCount))
	line("Network producers", strconv.Itoa(p.Network.ProducerCount)+" supported, readiness gating proposed")
	line("Management TCP", formatPorts(p.Network.ManagementTCP))
	line("Resolver", strings.ToUpper(p.Network.Resolver))
	line("IPv6", strings.ToUpper(p.Network.IPv6Mode))
	line("IPv6 default route", boolText(p.Network.IPv6DefaultRoute))
	line("Public TCP", formatPorts(p.PublicTCP))
	line("Public UDP", formatPorts(p.PublicUDP))
	line("VPN profile", "addresses "+strconv.Itoa(p.Profile.AddressCount)+", DNS "+strconv.Itoa(p.Profile.DNSCount)+", MTU "+boolText(p.Profile.HasMTU)+", preshared key "+boolText(p.Profile.HasPresharedKey)+", keepalive "+boolText(p.Profile.HasKeepalive)+", IPv4 default "+boolText(p.Profile.IPv4DefaultRoute)+", source world-readable "+boolText(p.Profile.SourceWorldReadable))
	line("Docker", p.Docker.Topology+" (present "+boolText(p.Docker.Present)+", active workloads "+boolText(p.Docker.ActiveWorkloads)+", configured "+strconv.Itoa(p.Docker.ConfiguredNetworks)+", observed "+strconv.Itoa(p.Docker.ObservedNetworks)+", IPv4 forwarding "+boolText(p.Docker.IPv4Forwarding)+", restart "+boolText(p.Docker.RestartRequired)+")")
	line("Units", strconv.Itoa(len(p.Units)))
	for _, unit := range p.Units {
		line("  "+unit.Name, "active "+boolText(unit.Active)+", enabled "+boolText(unit.Enabled))
	}
	line("Ownership changes", strconv.Itoa(len(p.OwnershipChanges))+" REQUIRE SEPARATE APPROVAL")
	for _, change := range p.OwnershipChanges {
		line("  "+change.Area, change.Current+" -> "+change.Proposed+"; interruption "+change.Interruption+"; separate approval "+boolText(change.SeparateApprovalRequired))
	}
	line("Backup inputs", strconv.Itoa(len(p.BackupInputs)))
	for _, input := range p.BackupInputs {
		line("  backup", input)
	}
	line("Rollback boundaries", strconv.Itoa(len(p.RollbackBounds)))
	for _, boundary := range p.RollbackBounds {
		line("  rollback", boundary)
	}
	line("Live state changed", "NO")
	line("Rollback required", "NO")
	line("Next safe step", p.NextStep)
	line("Detailed log", p.DetailedLog)
	return output.String()
}

func boolText(value bool) string {
	return strings.ToUpper(strconv.FormatBool(value))
}

func formatPorts(values []int) string {
	if len(values) == 0 {
		return "NONE"
	}
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.Itoa(value)
	}
	return strings.Join(parts, ",")
}
