package health

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
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
}

type Provider struct {
	Store   *state.Store
	Backend *nft.Backend
}

func (p Provider) Snapshot(ctx context.Context) (Snapshot, error) {
	if p.Store == nil || p.Backend == nil {
		return Snapshot{}, errors.New("health provider is not configured")
	}
	s := Snapshot{Status: "HEALTHY", Database: "ok"}
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
			if s.Reason == "" {
				s.Reason = fmt.Sprintf("owned table count %d/%d", len(owned), len(p.Backend.Owned))
			}
		}
	}
	if g, err := p.Store.LastKnownGood(ctx); err == nil {
		s.ActiveGeneration = g.ID
	} else if !errors.Is(err, sql.ErrNoRows) {
		s.Status = "DEGRADED"
		s.Reason = "database generation read failed: " + err.Error()
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
