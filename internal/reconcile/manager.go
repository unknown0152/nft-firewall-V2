// Package reconcile is the durable desired/observed/effective state controller.
package reconcile

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/compiler"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

type Manager struct {
	Backend     *nft.Backend
	Store       *state.Store
	SafeTTL     time.Duration
	Now         func() time.Time
	HealthCheck func(context.Context) error
}

type Result struct {
	Generation uint64
	Checksum   string
	Deadline   *time.Time
	Committed  bool
}

func (m *Manager) Apply(ctx context.Context, artifact compiler.Artifact, safe bool) (Result, error) {
	if m == nil || m.Backend == nil || m.Store == nil {
		return Result{}, errors.New("reconcile manager is not configured")
	}
	if pending, err := m.Store.Pending(ctx); err == nil && pending != nil {
		return Result{}, fmt.Errorf("generation %d is still pending; commit or roll it back first", pending.ID)
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Result{}, err
	}
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	previous, err := m.Store.LastKnownGood(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Result{}, err
	}
	var prevID *uint64
	if previous != nil {
		prevID = &previous.ID
	}
	var deadline *time.Time
	if safe {
		ttl := m.SafeTTL
		if ttl <= 0 {
			ttl = 90 * time.Second
		}
		d := now().UTC().Add(ttl)
		deadline = &d
	}
	if err := m.Store.SaveGeneration(ctx, artifact.Generation, artifact.Checksum, artifact.Script, prevID, deadline); err != nil {
		return Result{}, fmt.Errorf("persist pending generation: %w", err)
	}
	if err := m.Backend.Apply(ctx, artifact.Script); err != nil {
		_ = m.Store.MarkRolledBack(ctx, artifact.Generation)
		_ = m.Store.Audit(ctx, "system", "generation_apply_failed", fmt.Sprintf("generation=%d error=%v", artifact.Generation, err))
		return Result{}, err
	}
	if err := m.Store.MarkApplied(ctx, artifact.Generation); err != nil {
		return Result{}, err
	}
	if m.HealthCheck != nil {
		if err := m.HealthCheck(ctx); err != nil {
			rollbackErr := m.Rollback(ctx, artifact.Generation)
			_ = m.Store.Audit(ctx, "system", "generation_health_failed", fmt.Sprintf("generation=%d", artifact.Generation))
			if rollbackErr != nil {
				return Result{}, fmt.Errorf("candidate health check failed: %w; rollback also failed: %v", err, rollbackErr)
			}
			return Result{}, fmt.Errorf("candidate health check failed and was rolled back: %w", err)
		}
	}
	result := Result{Generation: artifact.Generation, Checksum: artifact.Checksum, Deadline: deadline, Committed: !safe}
	if !safe {
		if err := m.Store.Commit(ctx, artifact.Generation); err != nil {
			return Result{}, err
		}
	}
	_ = m.Store.Audit(ctx, "system", "generation_applied", fmt.Sprintf("generation=%d safe=%t", artifact.Generation, safe))
	return result, nil
}

func (m *Manager) Commit(ctx context.Context, id uint64) error {
	pending, err := m.Store.Pending(ctx)
	if err != nil {
		return err
	}
	if pending.ID != id {
		return fmt.Errorf("generation %d is not pending", id)
	}
	return m.Store.Commit(ctx, id)
}

func (m *Manager) Rollback(ctx context.Context, id uint64) error {
	g, err := generationByID(m.Store, id)
	if err != nil {
		return err
	}
	if g.PreviousID == nil {
		if err := m.Backend.DestroyOwned(ctx); err != nil {
			return err
		}
	} else {
		prev, err := generationByID(m.Store, *g.PreviousID)
		if err != nil {
			return err
		}
		script, err := m.Store.ReadScript(prev)
		if err != nil {
			return err
		}
		if err := m.Backend.Apply(ctx, script); err != nil {
			return err
		}
	}
	if err := m.Store.MarkRolledBack(ctx, id); err != nil {
		return err
	}
	return m.Store.Audit(ctx, "system", "generation_rolled_back", fmt.Sprintf("generation=%d", id))
}

func (m *Manager) RollbackExpired(ctx context.Context) (bool, error) {
	pending, err := m.Store.Pending(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	if pending.RollbackDeadline == nil || now().UTC().Before(*pending.RollbackDeadline) {
		return false, nil
	}
	if err := m.Rollback(ctx, pending.ID); err != nil {
		return false, err
	}
	return true, nil
}

type Drift struct {
	OwnedTables []nft.Table `json:"owned_tables"`
	Missing     bool        `json:"missing"`
	Repaired    bool        `json:"repaired"`
	Detail      string      `json:"detail"`
}

func (m *Manager) Reconcile(ctx context.Context, repair bool) (Drift, error) {
	observed, err := m.Backend.ListOwned(ctx)
	if err != nil {
		return Drift{}, err
	}
	expected := len(m.Backend.Owned)
	d := Drift{OwnedTables: observed}
	if len(observed) != expected {
		d.Missing = true
		d.Detail = fmt.Sprintf("owned table count %d/%d", len(observed), expected)
	}
	if !d.Missing {
		ok, detail, inspectErr := m.Backend.Integrity(ctx)
		if inspectErr != nil {
			return d, inspectErr
		}
		if !ok {
			d.Missing = true
			d.Detail = detail
		}
	}
	if d.Missing && repair {
		g, err := m.Store.LastKnownGood(ctx)
		if err != nil {
			return d, err
		}
		script, err := m.Store.ReadScript(g)
		if err != nil {
			return d, err
		}
		if err := m.Backend.Apply(ctx, script); err != nil {
			return d, err
		}
		d.Repaired = true
		_ = m.Store.Audit(ctx, "system", "drift_repaired", d.Detail)
	}
	return d, nil
}

func generationByID(s *state.Store, id uint64) (*state.Generation, error) {
	row := s.DB.QueryRow("SELECT id,checksum,script_path,status,created_at,rollback_deadline,previous_id FROM generations WHERE id=?", id)
	return scan(row)
}
func scan(row interface{ Scan(...any) error }) (*state.Generation, error) {
	var g state.Generation
	var created string
	var deadline sql.NullString
	var prev sql.NullInt64
	if err := row.Scan(&g.ID, &g.Checksum, &g.ScriptPath, &g.Status, &created, &deadline, &prev); err != nil {
		return nil, err
	}
	g.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if deadline.Valid {
		t, e := time.Parse(time.RFC3339Nano, deadline.String)
		if e == nil {
			g.RollbackDeadline = &t
		}
	}
	if prev.Valid {
		v := uint64(prev.Int64)
		g.PreviousID = &v
	}
	return &g, nil
}
