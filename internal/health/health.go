package health

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/version"
	"github.com/unknown0152/nft-firewall-v2/internal/wireguard"
)

const StatusSchema = "nftfw.status.v2"

type Snapshot struct {
	Schema                 string                   `json:"schema"`
	Version                string                   `json:"version"`
	Status                 string                   `json:"status"`
	Reason                 string                   `json:"reason"`
	Active                 bool                     `json:"active"`
	PolicyMatch            bool                     `json:"policy_match"`
	ActiveGeneration       uint64                   `json:"active_generation,omitempty"`
	PendingGeneration      uint64                   `json:"pending_generation,omitempty"`
	PendingDeadline        *time.Time               `json:"pending_deadline,omitempty"`
	OwnedTables            []nft.Table              `json:"owned_tables,omitempty"`
	Drift                  bool                     `json:"drift"`
	Database               string                   `json:"database"`
	Integrations           []state.IntegrationState `json:"integrations,omitempty"`
	KillSwitch             string                   `json:"kill_switch"`
	KillSwitchEnforced     bool                     `json:"kill_switch_enforced"`
	PolicyChecksum         string                   `json:"policy_checksum,omitempty"`
	PolicyHash             string                   `json:"policy_hash,omitempty"`
	IPv6Mode               string                   `json:"ipv6_mode"`
	ZoneCount              int                      `json:"zone_count"`
	PolicyCount            int                      `json:"policy_count"`
	BlockClaims            int                      `json:"block_claims"`
	BlockedAddresses       int                      `json:"blocked_addresses"`
	ClaimsBySource         map[string]int           `json:"claims_by_source,omitempty"`
	ClaimsDesiredRev       uint64                   `json:"claims_desired_revision"`
	ClaimsAppliedRev       uint64                   `json:"claims_applied_revision"`
	WireGuard              wireguard.Observation    `json:"wireguard"`
	RecentAudit            []map[string]any         `json:"recent_audit,omitempty"`
	ProvenanceMask         string                   `json:"provenance_mask"`
	ProvenanceKeepMask     string                   `json:"provenance_keep_mask"`
	ProvenanceLedger       string                   `json:"provenance_ledger"`
	ProvenanceDigest       string                   `json:"provenance_digest,omitempty"`
	ProvenanceActive       int                      `json:"provenance_active"`
	ProvenanceRetired      int                      `json:"provenance_retired"`
	ProvenanceMappings     []provenance.Assignment  `json:"provenance_mappings,omitempty"`
	ProvenanceAuditScope   string                   `json:"provenance_audit_scope"`
	ProvenanceAuditStatus  string                   `json:"provenance_audit_status"`
	ProvenanceForeignRules int                      `json:"provenance_foreign_rules"`
}

type Provider struct {
	Store                  *state.Store
	Backend                *nft.Backend
	WG                     *wireguard.Controller
	WGName                 string
	WGHealthyWithin        time.Duration
	IPv6Mode               string
	ZoneCount              int
	PolicyCount            int
	ActiveIntegrations     map[string]bool
	Ledger                 *provenance.Ledger
	RequireProvenance      bool
	AuditForeignProvenance bool
}

func (p Provider) Snapshot(ctx context.Context) (Snapshot, error) {
	if p.Store == nil || p.Backend == nil {
		return Snapshot{}, errors.New("health provider is not configured")
	}
	s := Snapshot{
		Schema: StatusSchema, Version: version.Current().Version,
		Status: "HEALTHY", Database: "ok", KillSwitch: "enforced",
		IPv6Mode: p.IPv6Mode, ZoneCount: p.ZoneCount, PolicyCount: p.PolicyCount,
		ClaimsBySource: map[string]int{}, ProvenanceMask: "0xff000000",
		ProvenanceKeepMask: "0x00ffffff", ProvenanceLedger: "unavailable",
	}
	degrade := func(reason string) {
		s.Status = "DEGRADED"
		if s.Reason == "" {
			s.Reason = reason
		}
	}
	if err := p.Store.QuickCheck(ctx); err != nil {
		s.Database = "degraded"
		degrade("database integrity check failed")
	}
	if p.Ledger != nil {
		assignments, assignmentErr := p.Ledger.Assignments(ctx)
		digest, digestErr := p.Ledger.Digest(ctx)
		if assignmentErr != nil || digestErr != nil {
			s.ProvenanceLedger = "degraded"
			degrade("monotonic provenance ledger validation failed")
		} else {
			s.ProvenanceLedger = "ok"
			s.ProvenanceDigest = digest
			s.ProvenanceMappings = assignments
			for _, assignment := range assignments {
				if assignment.Retired {
					s.ProvenanceRetired++
				} else {
					s.ProvenanceActive++
				}
			}
			if p.RequireProvenance && s.ProvenanceActive == 0 {
				degrade("monotonic provenance ledger has no active mappings")
			}
		}
	} else if p.RequireProvenance {
		degrade("monotonic provenance ledger is unavailable")
	}
	if p.AuditForeignProvenance {
		s.ProvenanceAuditScope = nft.ProvenanceCollisionScope
		foreignAudit, auditErr := p.Backend.AuditForeignProvenanceMask(ctx)
		if auditErr != nil {
			s.ProvenanceAuditStatus = "degraded"
			degrade("foreign provenance ownership audit failed: " + auditErr.Error())
		} else {
			s.ProvenanceAuditStatus = "ok"
			s.ProvenanceForeignRules = foreignAudit.ForeignRules
		}
	}
	var expected *state.Generation
	expectedArtifactValid := false
	expected, expectedErr := p.Store.ExpectedGeneration(ctx)
	if expectedErr == nil {
		if _, readErr := p.Store.ReadScript(expected); readErr != nil {
			s.Drift = true
			degrade("expected generation artifact validation failed: " + readErr.Error())
		} else {
			expectedArtifactValid = true
			s.ActiveGeneration = expected.ID
			s.PolicyChecksum = expected.Checksum
			s.PolicyHash = expected.Checksum
		}
	} else if errors.Is(expectedErr, sql.ErrNoRows) {
		s.Drift = true
		degrade("no applied or committed policy generation exists")
	} else {
		s.Drift = true
		degrade("expected generation read failed: " + expectedErr.Error())
	}
	ownedHealthy := false
	fingerprintMatches := false
	owned, err := p.Backend.ListOwned(ctx)
	if err != nil {
		s.Drift = true
		degrade(err.Error())
	} else {
		s.OwnedTables = owned
		if len(owned) != len(p.Backend.Owned) {
			s.Drift = true
		}
		if len(owned) == len(p.Backend.Owned) {
			ok, detail, integrityErr := p.Backend.Integrity(ctx)
			if integrityErr != nil {
				s.Drift = true
				degrade("owned table integrity inspection failed: " + integrityErr.Error())
			} else if !ok {
				s.Drift = true
				degrade(detail)
			} else {
				ownedHealthy = true
			}
		}
		if ownedHealthy && expected != nil && expectedArtifactValid {
			if expected.ObservedHash == "" {
				s.Drift = true
				degrade(fmt.Sprintf("generation %d lacks an observed-state fingerprint", expected.ID))
			} else if observedHash, fingerprintErr := p.Backend.Fingerprint(ctx); fingerprintErr != nil {
				s.Drift = true
				degrade("owned table fingerprint failed: " + fingerprintErr.Error())
			} else if observedHash != expected.ObservedHash {
				s.Drift = true
				degrade(fmt.Sprintf("owned nftables fingerprint differs from generation %d", expected.ID))
			} else {
				fingerprintMatches = true
			}
		}
		if s.Drift {
			if s.Reason == "" {
				degrade(fmt.Sprintf("owned table count %d/%d", len(owned), len(p.Backend.Owned)))
			}
		}
	}
	s.Active = expected != nil && expectedArtifactValid && ownedHealthy
	s.PolicyMatch = s.Active && fingerprintMatches && !s.Drift
	s.KillSwitchEnforced = s.PolicyMatch
	if !s.KillSwitchEnforced {
		s.KillSwitch = "degraded"
	}
	claimCount := -1
	if claims, err := p.Store.Claims(ctx, time.Now().UTC()); err == nil {
		claimCount = len(claims)
		for _, claim := range claims {
			s.ClaimsBySource[claim.Source]++
			if !strings.HasPrefix(claim.Source, "allow") {
				s.BlockClaims++
			}
		}
		s.BlockedAddresses = len(state.EffectiveAddresses(claims, "ipv4")) + len(state.EffectiveAddresses(claims, "ipv6"))
	} else {
		degrade("claim state read failed: " + err.Error())
	}
	if publication, err := p.Store.ClaimPublicationState(ctx); err != nil {
		degrade("runtime claim publication state read failed: " + err.Error())
	} else {
		s.ClaimsDesiredRev = publication.DesiredRevision
		s.ClaimsAppliedRev = publication.AppliedRevision
		if publication.DesiredRevision != publication.AppliedRevision {
			degrade("runtime claim sets are not synchronized")
		}
	}
	if p.WG != nil && p.WGName != "" {
		s.WireGuard = p.WG.Observe(ctx, p.WGName, p.WGHealthyWithin)
		if !s.WireGuard.Healthy {
			degrade("WireGuard " + s.WireGuard.Reason)
		}
	}
	if audit, err := p.Store.RecentAudit(ctx, 20); err == nil {
		s.RecentAudit = audit
	}
	if g, err := p.Store.Pending(ctx); err == nil {
		s.PendingGeneration = g.ID
		s.PendingDeadline = g.RollbackDeadline
	}
	if integrations, err := p.Store.IntegrationStates(ctx); err == nil {
		runtimeClaimsSeen := false
		seen := map[string]bool{}
		for _, integration := range integrations {
			if p.ActiveIntegrations != nil && !p.ActiveIntegrations[integration.Name] {
				continue
			}
			s.Integrations = append(s.Integrations, integration)
			seen[integration.Name] = true
			if integration.Name == "runtime/claims" {
				runtimeClaimsSeen = true
				if integration.EntryCount != claimCount {
					degrade("runtime claim publication count differs from durable claims")
				}
			}
			if integration.Status != "healthy" {
				degrade("integration " + integration.Name + " is degraded")
			}
		}
		if !runtimeClaimsSeen {
			degrade("runtime claim publication state is missing")
		}
		for name := range p.ActiveIntegrations {
			if !seen[name] {
				degrade("integration " + name + " has not completed its first health check")
			}
		}
	} else {
		degrade("integration state read failed: " + err.Error())
	}
	return s, nil
}
