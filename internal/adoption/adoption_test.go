package adoption

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type fixedInspector struct {
	observation Observation
	err         error
}

func (f fixedInspector) Inspect(context.Context, string) (Observation, error) {
	return f.observation, f.err
}

func validObservation() Observation {
	return Observation{
		InstalledVersion: "2.0.3", ExistingState: true,
		OSID: "debian", OSVersion: "13", Architecture: "amd64",
		NetworkValid: true, UplinkMatches: true, LANNetworkCount: 1,
		ManagementTCP: []int{2222, 22}, IPv6Mode: "disabled",
		ResolverMode: "none", ResolverValid: true, RoutingValid: true, ExposureValid: true,
		FirewallOwned: true, StateValid: true, StateSchema: CurrentStateSchema,
		Generation: 7, PolicyChecksum: strings.Repeat("a", 64),
		EnforcementEnabled: true, PointerMatches: true, LivePolicyMatches: true,
		ProvenanceValid: true, ProvenanceActive: 3,
		DockerClean: true, DockerTopologyValid: true,
		PublicTCP: []int{443, 80}, PublicUDP: []int{51820},
		Units: []UnitState{
			{Name: "nftfw-early.service", Active: true, Enabled: true},
			{Name: "nftfw-enforcement-ready.service", Active: true, Enabled: true},
			{Name: "nftfw-managed-rollback.timer", Active: true, Enabled: true},
			{Name: "nftfw-rollback.timer", Active: true, Enabled: true},
			{Name: "nftfw-setup-rollback.timer", Active: true, Enabled: true},
			{Name: "nftfw-vpn.service", Active: true, Enabled: true},
			{Name: "nftfwd.service", Active: true, Enabled: true},
			{Name: "nftfw-web.service", Active: true, Enabled: true},
		},
		Profile: ProfileSummary{AddressCount: 1, IPv4DefaultRoute: true},
		Stable:  true,
	}
}

func TestPlannerBuildsDeterministicRedactedWorksheet(t *testing.T) {
	observation := validObservation()
	planner := Planner{Inspector: fixedInspector{observation: observation}}
	first, err := planner.Plan(context.Background(), "/protected/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	second, err := planner.Plan(context.Background(), "/protected/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) || first.Human() != second.Human() {
		t.Fatal("adoption worksheet is not deterministic")
	}
	wantHuman := `NFT Firewall V2 existing-host adoption plan: nftfw.adoption-plan.v1
Status: READY_FOR_SEPARATE_LIVE_PLAN
Installed package: 2.0.3
Current mode: ADVANCED
Target mode: MANAGED (SEPARATE STAGE E-L)
State: schema 6, generation 7, policy aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Enforcement: VERIFIED
Live policy: VERIFIED
Provenance: VERIFIED (active 3)
Pending generation: FALSE
Network: verified-single-ipv4, LAN networks 1
Management TCP: 22,2222
Resolver: NONE
IPv6: DISABLED
IPv6 default route: FALSE
Public TCP: 80,443
Public UDP: 51820
VPN profile: addresses 1, DNS 0, MTU FALSE, preshared key FALSE, keepalive FALSE, IPv4 default TRUE, source world-readable FALSE
Docker: absent (present FALSE, active workloads FALSE, configured 0, observed 0, IPv4 forwarding FALSE, restart FALSE)
Units: 8
  nftfw-early.service: active TRUE, enabled TRUE
  nftfw-enforcement-ready.service: active TRUE, enabled TRUE
  nftfw-managed-rollback.timer: active TRUE, enabled TRUE
  nftfw-rollback.timer: active TRUE, enabled TRUE
  nftfw-setup-rollback.timer: active TRUE, enabled TRUE
  nftfw-vpn.service: active TRUE, enabled TRUE
  nftfw-web.service: active TRUE, enabled TRUE
  nftfwd.service: active TRUE, enabled TRUE
Ownership changes: 6 REQUIRE SEPARATE APPROVAL
  boot: advanced NFTFW units -> managed early protection; interruption none until separately approved reboot; separate approval TRUE
  firewall: advanced NFTFW -> managed NFTFW; interruption safe apply; no management or public-service interruption expected after validation; separate approval TRUE
  resolver: existing resolver owner -> managed VPN resolver; interruption bounded DNS interruption; separate approval TRUE
  routing: existing policy routes -> managed policy routes; interruption coupled to VPN and Internet transfer; separate approval TRUE
  sysctl: existing host values -> managed IPv6 and forwarding values; interruption none expected after validation; separate approval TRUE
  vpn: existing WireGuard owner -> managed nftfw-vpn; interruption brief VPN and Internet interruption; separate approval TRUE
Backup inputs: 7
  backup: advanced configuration
  backup: generation database
  backup: enforcement pointer and snapshots
  backup: monotonic provenance ledger
  backup: WireGuard profile and routing state
  backup: systemd unit states
  backup: resolver and sysctl state
Rollback boundaries: 5
  rollback: before ownership transfer
  rollback: after fail-closed guard
  rollback: after VPN transfer
  rollback: after safe firewall apply
  rollback: after boot handoff
Live state changed: NO
Rollback required: NO
Next safe step: Retain advanced mode or prepare a separately approved Stage E-L plan from this local worksheet.
Detailed log: sudo journalctl -u nftfwd (the planner writes no log)
`
	if first.Human() != wantHuman {
		t.Fatalf("human worksheet changed:\n%s", first.Human())
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(firstJSON)); got != "262d8ed3fe417121ff7e277d72ab33c11f7538a185d6eb73d0d45a5a56920ca9" {
		t.Fatalf("JSON worksheet golden digest changed: %s", got)
	}
	if first.Schema != Schema || first.Status != "READY_FOR_SEPARATE_LIVE_PLAN" ||
		first.LiveStateChanged || first.RollbackRequired ||
		!reflect.DeepEqual(first.Network.ManagementTCP, []int{22, 2222}) ||
		!reflect.DeepEqual(first.PublicTCP, []int{80, 443}) {
		t.Fatalf("unexpected worksheet: %#v", first)
	}
	combined := string(firstJSON) + first.Human()
	for _, forbidden := range []string{
		"private-key-material", "vpn.example.test", "198.51.100.8",
		"container-id", "image-name", "volume-name", "/protected/provider.conf",
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("worksheet disclosed %q", forbidden)
		}
	}
}

func TestPlannerAddsDockerOwnershipWithoutNames(t *testing.T) {
	observation := validObservation()
	observation.DockerPresent = true
	observation.DockerClean = false
	observation.DockerConfigured = 2
	observation.DockerObserved = 2
	observation.DockerRestartRequired = true
	plan, err := (Planner{Inspector: fixedInspector{observation: observation}}).
		Plan(context.Background(), "/vpn.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Docker.ActiveWorkloads || plan.Docker.Topology != "verified" ||
		plan.Docker.ConfiguredNetworks != 2 || !plan.Docker.RestartRequired {
		t.Fatalf("Docker summary missing: %#v", plan.Docker)
	}
	found := false
	for _, change := range plan.OwnershipChanges {
		if change.Area == "docker" {
			found = change.Interruption == "one separately confirmed Docker restart"
		}
	}
	if !found {
		t.Fatal("Docker ownership change missing")
	}
	if !reflect.DeepEqual(plan.BackupInputs[len(plan.BackupInputs)-1:], []string{"Docker daemon, socket-access, and network ownership state"}) ||
		!reflect.DeepEqual(plan.RollbackBounds[len(plan.RollbackBounds)-3:], []string{"after confirmed Docker restart", "after safe firewall apply", "after boot handoff"}) {
		t.Fatalf("Docker backup/rollback boundaries missing: %#v %#v", plan.BackupInputs, plan.RollbackBounds)
	}
}

func TestPlannerRefusesEveryUnsupportedClassification(t *testing.T) {
	tests := []struct {
		name string
		code string
		edit func(*Observation)
	}{
		{"changed", "ADOPTION_OBSERVATION_CHANGED", func(o *Observation) { o.Stable = false }},
		{"managed", "ADOPTION_ALREADY_MANAGED", func(o *Observation) { o.Managed = true }},
		{"clean", "ADOPTION_CLEAN_HOST_USE_SETUP", func(o *Observation) { o.ExistingState = false }},
		{"os", "ADOPTION_OS_UNSUPPORTED", func(o *Observation) { o.OSVersion = "12" }},
		{"arch", "ADOPTION_ARCHITECTURE_UNSUPPORTED", func(o *Observation) { o.Architecture = "riscv64" }},
		{"version", "ADOPTION_PACKAGE_VERSION_UNSUPPORTED", func(o *Observation) { o.InstalledVersion = "2.0.2" }},
		{"profile", "ADOPTION_PROFILE_UNSUPPORTED", func(o *Observation) { o.Profile.IPv4DefaultRoute = false }},
		{"network", "ADOPTION_NETWORK_AMBIGUOUS", func(o *Observation) { o.UplinkMatches = false }},
		{"exposure", "ADOPTION_EXPOSURE_UNSUPPORTED", func(o *Observation) { o.ExposureValid = false }},
		{"owner", "ADOPTION_FIREWALL_OWNERSHIP_AMBIGUOUS", func(o *Observation) { o.FirewallOwned = false }},
		{"foreign", "ADOPTION_FIREWALL_OWNERSHIP_AMBIGUOUS", func(o *Observation) { o.ForeignNFTables = true }},
		{"competing", "ADOPTION_FIREWALL_OWNERSHIP_AMBIGUOUS", func(o *Observation) { o.CompetingFirewalls = []string{"ufw.service"} }},
		{"state", "ADOPTION_STATE_INVALID", func(o *Observation) { o.PointerMatches = false }},
		{"live-policy", "ADOPTION_POLICY_IDENTITY_MISMATCH", func(o *Observation) { o.LivePolicyMatches = false }},
		{"schema", "ADOPTION_STATE_INVALID", func(o *Observation) { o.StateSchema = 5 }},
		{"checksum", "ADOPTION_STATE_INVALID", func(o *Observation) { o.PolicyChecksum = "bad" }},
		{"pending", "ADOPTION_PENDING_GENERATION", func(o *Observation) { o.PendingGeneration = true }},
		{"provenance", "ADOPTION_PROVENANCE_INVALID", func(o *Observation) { o.ProvenanceValid = false }},
		{"routing", "ADOPTION_ROUTING_AMBIGUOUS", func(o *Observation) { o.RoutingValid = false }},
		{"resolver", "ADOPTION_RESOLVER_UNSUPPORTED", func(o *Observation) { o.ResolverValid = false }},
		{"ipv6", "ADOPTION_IPV6_MODE_UNSUPPORTED", func(o *Observation) { o.IPv6Mode = "native" }},
		{"docker-missing", "ADOPTION_DOCKER_TOPOLOGY_UNSUPPORTED", func(o *Observation) { o.DockerConfigured = 1 }},
		{"docker-unobserved", "ADOPTION_DOCKER_TOPOLOGY_UNSUPPORTED", func(o *Observation) { o.DockerPresent, o.DockerObserved = true, 0 }},
		{"docker-restart-without-docker", "ADOPTION_DOCKER_TOPOLOGY_UNSUPPORTED", func(o *Observation) { o.DockerRestartRequired = true }},
		{"ports", "ADOPTION_OBSERVATION_INVALID", func(o *Observation) { o.PublicTCP = []int{443, 443} }},
		{"units", "ADOPTION_OBSERVATION_INVALID", func(o *Observation) { o.Units = []UnitState{{Name: "docker.service"}} }},
		{"invented-unit", "ADOPTION_OBSERVATION_INVALID", func(o *Observation) { o.Units = []UnitState{{Name: "nftfw-secret.service"}} }},
		{"missing-unit", "ADOPTION_OBSERVATION_INVALID", func(o *Observation) { o.Units = o.Units[:len(o.Units)-1] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := validObservation()
			test.edit(&observation)
			_, err := (Planner{Inspector: fixedInspector{observation: observation}}).
				Plan(context.Background(), "/vpn.conf")
			if ErrorCode(err) != test.code {
				t.Fatalf("code=%q want=%q err=%v", ErrorCode(err), test.code, err)
			}
		})
	}
}

func TestPlannerInputAndInspectorFailuresAreRedacted(t *testing.T) {
	if _, err := (Planner{}).Plan(context.Background(), "/vpn.conf"); ErrorCode(err) != "ADOPTION_INPUT_INVALID" {
		t.Fatalf("missing inspector code=%q", ErrorCode(err))
	}
	secret := "private-key-material vpn.example.test 198.51.100.8"
	planner := Planner{Inspector: fixedInspector{err: errors.New(secret)}}
	_, err := planner.Plan(context.Background(), "/vpn.conf")
	operator := OperatorError(err).Error()
	if ErrorCode(err) != "ADOPTION_INSPECTION_FAILED" || strings.Contains(operator, secret) ||
		!strings.Contains(operator, "live state changed: NO") ||
		!strings.Contains(operator, "rollback required: NO") ||
		!strings.Contains(operator, "sudo nftfw setup adopt") ||
		!strings.Contains(operator, "sudo journalctl -u nftfwd") {
		t.Fatalf("unsafe operator error: %s", operator)
	}
}

func TestVersionAndCodeBoundaries(t *testing.T) {
	for _, value := range []string{"2.0.3", "2.0.3-1", "2.1.0", "2.1.0~rc1", "2.1.0+meta"} {
		if !compatibleVersion(value) {
			t.Fatalf("compatible version rejected: %q", value)
		}
	}
	for _, value := range []string{"", "2.0.2", "12.1.0", "2.1.0 bad", strings.Repeat("a", 65)} {
		if compatibleVersion(value) {
			t.Fatalf("unsupported version accepted: %q", value)
		}
	}
	if ErrorCode(Error{Code: "ADOPTION_SAFE"}) != "ADOPTION_SAFE" ||
		ErrorCode(Error{Code: "ADOPTION_bad"}) != "ADOPTION_INSPECTION_FAILED" {
		t.Fatal("error code boundary failed")
	}
	if (Error{Code: "ADOPTION_DIRECT"}).Error() != "ADOPTION_DIRECT" {
		t.Fatal("adoption error changed")
	}
	if got := (Plan{Schema: Schema, Docker: DockerSummary{Topology: "absent"}}).Human(); !strings.Contains(got, "Public TCP: NONE") {
		t.Fatal("empty port rendering changed")
	}
}

func FuzzAdoptionErrorRedaction(f *testing.F) {
	f.Add("private-key-material")
	f.Add("vpn.example.test:51820")
	f.Add("198.51.100.8")
	f.Fuzz(func(t *testing.T, raw string) {
		untrusted := "\x00NFTFW-UNTRUSTED-BEGIN\x00" + raw + "\x00NFTFW-UNTRUSTED-END\x00"
		message := OperatorError(errors.New(untrusted)).Error()
		if strings.Contains(message, "\x00NFTFW-UNTRUSTED-") {
			t.Fatal("untrusted error reached operator output")
		}
		if len(message) > 512 {
			t.Fatal("operator error is unbounded")
		}
	})
}

func BenchmarkAdoptionPlan(b *testing.B) {
	planner := Planner{Inspector: fixedInspector{observation: validObservation()}}
	for b.Loop() {
		if _, err := planner.Plan(context.Background(), "/vpn.conf"); err != nil {
			b.Fatal(err)
		}
	}
}
