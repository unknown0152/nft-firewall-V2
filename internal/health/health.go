package health

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/wireguard"
)

type Snapshot struct {
	Status            string                   `json:"status"`
	Reason            string                   `json:"reason"`
	ActiveGeneration  uint64                   `json:"active_generation,omitempty"`
	PendingGeneration uint64                   `json:"pending_generation,omitempty"`
	PendingDeadline   *time.Time               `json:"pending_deadline,omitempty"`
	OwnedTables       []nft.Table              `json:"owned_tables,omitempty"`
	Drift             bool                     `json:"drift"`
	Database          string                   `json:"database"`
	Integrations      []state.IntegrationState `json:"integrations,omitempty"`
	KillSwitch        string                   `json:"kill_switch"`
	PolicyChecksum    string                   `json:"policy_checksum,omitempty"`
	IPv6Mode          string                   `json:"ipv6_mode"`
	ZoneCount         int                      `json:"zone_count"`
	PolicyCount       int                      `json:"policy_count"`
	BlockClaims       int                      `json:"block_claims"`
	BlockedAddresses  int                      `json:"blocked_addresses"`
	ClaimsBySource    map[string]int           `json:"claims_by_source,omitempty"`
	WireGuard         wireguard.Observation    `json:"wireguard"`
	RecentAudit       []map[string]any         `json:"recent_audit,omitempty"`
}

type Provider struct {
	Store           *state.Store
	Backend         *nft.Backend
	WG              *wireguard.Controller
	WGName          string
	WGHealthyWithin time.Duration
	IPv6Mode        string
	ZoneCount       int
	PolicyCount     int
}

func (p Provider) Snapshot(ctx context.Context) (Snapshot, error) {
	if p.Store == nil || p.Backend == nil {
		return Snapshot{}, errors.New("health provider is not configured")
	}
	s := Snapshot{Status: "HEALTHY", Database: "ok", KillSwitch: "enforced", IPv6Mode: p.IPv6Mode, ZoneCount: p.ZoneCount, PolicyCount: p.PolicyCount, ClaimsBySource: map[string]int{}}
	if err := p.Store.QuickCheck(ctx); err != nil {
		s.Status = "DEGRADED"
		s.Database = "degraded"
		s.Reason = "database integrity check failed"
	}
	owned, err := p.Backend.ListOwned(ctx)
	if err != nil {
		s.Status = "DEGRADED"
		s.Reason = err.Error()
	} else {
		s.OwnedTables = owned
		s.Drift = len(owned) != len(p.Backend.Owned)
		if !s.Drift {
			ok, detail, integrityErr := p.Backend.Integrity(ctx)
			if integrityErr != nil {
				s.Drift = true
				s.Reason = "owned table integrity inspection failed: " + integrityErr.Error()
			} else if !ok {
				s.Drift = true
				s.Reason = detail
			}
		}
		if s.Drift {
			s.Status = "DEGRADED"
			s.KillSwitch = "degraded"
			if s.Reason == "" {
				s.Reason = fmt.Sprintf("owned table count %d/%d", len(owned), len(p.Backend.Owned))
			}
		}
	}
	if g, err := p.Store.LastKnownGood(ctx); err == nil {
		s.ActiveGeneration = g.ID
		s.PolicyChecksum = g.Checksum
	} else if !errors.Is(err, sql.ErrNoRows) {
		s.Status = "DEGRADED"
		s.Reason = "database generation read failed: " + err.Error()
	}
	if claims, err := p.Store.Claims(ctx, time.Now().UTC()); err == nil {
		for _, claim := range claims {
			s.ClaimsBySource[claim.Source]++
			if !strings.HasPrefix(claim.Source, "allow") {
				s.BlockClaims++
			}
		}
		s.BlockedAddresses = len(state.EffectiveAddresses(claims, "ipv4")) + len(state.EffectiveAddresses(claims, "ipv6"))
	} else {
		s.Status = "DEGRADED"
		s.Reason = "claim state read failed: " + err.Error()
	}
	if p.WG != nil && p.WGName != "" {
		s.WireGuard = p.WG.Observe(ctx, p.WGName, p.WGHealthyWithin)
		if !s.WireGuard.Healthy {
			s.Status = "DEGRADED"
			if s.Reason == "" {
				s.Reason = "WireGuard " + s.WireGuard.Reason
			}
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
		s.Integrations = integrations
		for _, integration := range integrations {
			if integration.Status != "healthy" {
				s.Status = "DEGRADED"
				if s.Reason == "" {
					s.Reason = "integration " + integration.Name + " is degraded"
				}
			}
		}
	} else {
		s.Status = "DEGRADED"
		s.Reason = "integration state read failed: " + err.Error()
	}
	return s, nil
}
