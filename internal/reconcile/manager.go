// Package reconcile is the durable desired/observed/effective state controller.
package reconcile

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
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
	SafeGuard   func(context.Context) error
	mu          sync.Mutex
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireNoPending(ctx); err != nil {
		return Result{}, err
	}
	if safe {
		if m.SafeGuard == nil {
			return Result{}, errors.New("safe apply requires an independent rollback guard")
		}
		if err := m.SafeGuard(ctx); err != nil {
			return Result{}, fmt.Errorf("safe apply refused: %w", err)
		}
	}
	release, err := m.acquireProcessLock()
	if err != nil {
		return Result{}, err
	}
	defer release()
	if err := m.requireNoPending(ctx); err != nil {
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
		_ = m.restore(ctx, previous)
		_ = m.Store.MarkRolledBack(ctx, artifact.Generation)
		return Result{}, err
	}
	if err := m.recordFingerprint(ctx, artifact.Generation); err != nil {
		_ = m.restore(ctx, previous)
		_ = m.Store.MarkRolledBack(ctx, artifact.Generation)
		return Result{}, fmt.Errorf("record applied nftables fingerprint: %w", err)
	}
	if m.HealthCheck != nil {
		if err := m.HealthCheck(ctx); err != nil {
			rollbackErr := m.rollbackLocked(ctx, artifact.Generation)
			_ = m.Store.Audit(ctx, "system", "generation_health_failed", fmt.Sprintf("generation=%d", artifact.Generation))
			if rollbackErr != nil {
				return Result{}, fmt.Errorf("candidate health check failed: %w; rollback also failed: %v", err, rollbackErr)
			}
			return Result{}, fmt.Errorf("candidate health check failed and was rolled back: %w", err)
		}
	}
	result := Result{Generation: artifact.Generation, Checksum: artifact.Checksum, Deadline: deadline, Committed: !safe}
	if !safe {
		if err := m.commitLocked(ctx, artifact.Generation); err != nil {
			return Result{}, err
		}
	}
	_ = m.Store.Audit(ctx, "system", "generation_applied", fmt.Sprintf("generation=%d safe=%t", artifact.Generation, safe))
	return result, nil
}

func (m *Manager) restore(ctx context.Context, previous *state.Generation) error {
	if previous == nil {
		return m.Backend.DestroyOwned(ctx)
	}
	script, err := m.Store.ReadScript(previous)
	if err != nil {
		return err
	}
	if err := m.Backend.Apply(ctx, script); err != nil {
		return err
	}
	return m.recordFingerprint(ctx, previous.ID)
}

func (m *Manager) recordFingerprint(ctx context.Context, id uint64) error {
	hash, err := m.Backend.Fingerprint(ctx)
	if err != nil {
		return err
	}
	return m.Store.SetObservedHash(ctx, id, hash)
}

func (m *Manager) Commit(ctx context.Context, id uint64) error {
	if m == nil || m.Backend == nil || m.Store == nil {
		return errors.New("reconcile manager is not configured")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.acquireProcessLock()
	if err != nil {
		return err
	}
	defer release()
	pending, err := m.Store.Pending(ctx)
	if err != nil {
		return err
	}
	if pending.ID != id {
		return fmt.Errorf("generation %d is not pending", id)
	}
	if pending.Status != "applied" {
		return fmt.Errorf("generation %d was persisted but not applied and cannot be committed", id)
	}
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	if pending.RollbackDeadline != nil && !now().UTC().Before(*pending.RollbackDeadline) {
		if rollbackErr := m.rollbackLocked(ctx, id); rollbackErr != nil {
			return fmt.Errorf("generation %d expired and rollback failed: %w", id, rollbackErr)
		}
		return fmt.Errorf("generation %d expired and was rolled back", id)
	}
	observedHash, err := m.Backend.Fingerprint(ctx)
	if err != nil || pending.ObservedHash == "" || observedHash != pending.ObservedHash {
		rollbackErr := m.rollbackLocked(ctx, id)
		if rollbackErr != nil {
			return fmt.Errorf("generation %d integrity verification failed and rollback failed: %v", id, rollbackErr)
		}
		return fmt.Errorf("generation %d integrity verification failed and was rolled back", id)
	}
	return m.commitLocked(ctx, id)
}

func (m *Manager) commitLocked(ctx context.Context, id uint64) error {
	g, err := generationByID(m.Store, id)
	if err != nil {
		return err
	}
	script, err := m.Store.ReadScript(g)
	if err != nil {
		return fmt.Errorf("read committed generation: %w", err)
	}
	if err := m.Store.Commit(ctx, id); err != nil {
		rollbackErr := m.rollbackLocked(ctx, id)
		if rollbackErr != nil {
			return fmt.Errorf("commit generation: %w; rollback also failed: %v", err, rollbackErr)
		}
		return fmt.Errorf("commit generation: %w; generation was rolled back", err)
	}
	if err := m.Store.PublishActive(script, g.Checksum); err != nil {
		rollbackErr := m.rollbackLocked(ctx, id)
		if rollbackErr != nil {
			return fmt.Errorf("publish active boot snapshot: %w; rollback also failed: %v", err, rollbackErr)
		}
		return fmt.Errorf("publish active boot snapshot: %w; generation was rolled back", err)
	}
	return nil
}

func (m *Manager) Rollback(ctx context.Context, id uint64) error {
	if m == nil || m.Backend == nil || m.Store == nil {
		return errors.New("reconcile manager is not configured")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.acquireProcessLock()
	if err != nil {
		return err
	}
	defer release()
	return m.rollbackLocked(ctx, id)
}

func (m *Manager) rollbackLocked(ctx context.Context, id uint64) error {
	g, err := generationByID(m.Store, id)
	if err != nil {
		return err
	}
	if g.Status == "rolled_back" {
		return nil
	}
	if g.Status == "committed" {
		latest, latestErr := m.Store.LastKnownGood(ctx)
		if latestErr != nil {
			return latestErr
		}
		if latest.ID != id {
			return fmt.Errorf("generation %d is historical; active committed generation is %d", id, latest.ID)
		}
	} else if g.Status != "pending" && g.Status != "applied" {
		return fmt.Errorf("generation %d has unsupported rollback status %s", id, g.Status)
	}
	var previous *state.Generation
	var previousScript string
	if g.PreviousID == nil {
		fallbackChecksum := sha256.Sum256([]byte(nft.EmergencyDenyScript))
		if err := m.Store.PublishActive(nft.EmergencyDenyScript, hex.EncodeToString(fallbackChecksum[:])); err != nil {
			return fmt.Errorf("publish first-generation rollback fallback: %w", err)
		}
	} else {
		previous, err = generationByID(m.Store, *g.PreviousID)
		if err != nil {
			return err
		}
		previousScript, err = m.Store.ReadScript(previous)
		if err != nil {
			return err
		}
		// Publish the rollback target before changing the kernel. A crash at any
		// later point will therefore restore the safer previous generation.
		if err := m.Store.PublishActive(previousScript, previous.Checksum); err != nil {
			return fmt.Errorf("publish rollback boot snapshot: %w", err)
		}
	}
	if previous == nil {
		if err := m.Backend.DestroyOwned(ctx); err != nil {
			m.restoreCommittedAfterFailedRollback(ctx, g)
			return err
		}
	} else if err := m.Backend.Apply(ctx, previousScript); err != nil {
		m.restoreCommittedAfterFailedRollback(ctx, g)
		return err
	}
	if err := m.Store.MarkRolledBack(ctx, id); err != nil {
		m.restoreCommittedAfterFailedRollback(ctx, g)
		return err
	}
	if previous == nil {
		// Clear only after the first generation is absent from the kernel and
		// SQLite records the rollback. Until then, early boot restores the
		// emergency default-deny snapshot published above.
		if err := m.Store.ClearActive(); err != nil {
			return fmt.Errorf("clear active boot snapshot: %w", err)
		}
	}
	return m.Store.Audit(ctx, "system", "generation_rolled_back", fmt.Sprintf("generation=%d", id))
}

func (m *Manager) restoreCommittedAfterFailedRollback(ctx context.Context, g *state.Generation) {
	if g == nil || g.Status != "committed" {
		return
	}
	script, err := m.Store.ReadScript(g)
	if err != nil {
		return
	}
	_ = m.Store.PublishActive(script, g.Checksum)
	_ = m.Backend.Apply(ctx, script)
}

func (m *Manager) RollbackExpired(ctx context.Context) (bool, error) {
	if m == nil || m.Backend == nil || m.Store == nil {
		return false, errors.New("reconcile manager is not configured")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.acquireProcessLock()
	if err != nil {
		return false, err
	}
	defer release()
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
	if err := m.rollbackLocked(ctx, pending.ID); err != nil {
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
	if m == nil || m.Backend == nil || m.Store == nil {
		return Drift{}, errors.New("reconcile manager is not configured")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.acquireProcessLock()
	if err != nil {
		return Drift{}, err
	}
	defer release()
	pending, pendingErr := m.Store.Pending(ctx)
	if pendingErr == nil && pending.Status == "pending" {
		drift := Drift{Missing: true, Detail: fmt.Sprintf("generation %d was not fully applied before process exit", pending.ID)}
		if repair {
			if err := m.rollbackLocked(ctx, pending.ID); err != nil {
				return drift, err
			}
			drift.Repaired = true
		}
		return drift, nil
	} else if pendingErr != nil && !errors.Is(pendingErr, sql.ErrNoRows) {
		return Drift{}, pendingErr
	}
	observed, err := m.Backend.ListOwned(ctx)
	if err != nil {
		return Drift{}, err
	}
	expectedCount := len(m.Backend.Owned)
	d := Drift{OwnedTables: observed}
	if len(observed) != expectedCount {
		d.Missing = true
		d.Detail = fmt.Sprintf("owned table count %d/%d", len(observed), expectedCount)
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
	expected, expectedErr := m.expectedGeneration(ctx)
	if expectedErr != nil && !errors.Is(expectedErr, sql.ErrNoRows) {
		return d, expectedErr
	}
	if !d.Missing && expected != nil {
		if expected.ObservedHash == "" {
			d.Missing = true
			d.Detail = fmt.Sprintf("generation %d lacks an observed-state fingerprint", expected.ID)
		} else {
			observedHash, fingerprintErr := m.Backend.Fingerprint(ctx)
			if fingerprintErr != nil {
				return d, fingerprintErr
			}
			if observedHash != expected.ObservedHash {
				d.Missing = true
				d.Detail = fmt.Sprintf("owned nftables fingerprint differs from generation %d", expected.ID)
			}
		}
	}
	if d.Missing && repair {
		_ = m.Store.Audit(ctx, "system", "drift_detected", d.Detail)
		if pendingErr == nil && pending.Status == "applied" {
			if err := m.rollbackLocked(ctx, pending.ID); err != nil {
				return d, err
			}
			d.Repaired = true
			d.Detail = fmt.Sprintf("pending generation %d lost integrity and was rolled back", pending.ID)
			return d, nil
		}
		g := expected
		if g == nil {
			g, err = m.Store.LastKnownGood(ctx)
		}
		if err != nil || g == nil {
			return d, err
		}
		script, err := m.Store.ReadScript(g)
		if err != nil {
			return d, err
		}
		if err := m.Backend.Apply(ctx, script); err != nil {
			return d, err
		}
		if err := m.recordFingerprint(ctx, g.ID); err != nil {
			return d, err
		}
		d.Repaired = true
		_ = m.Store.Audit(ctx, "system", "drift_repaired", d.Detail)
	} else if d.Missing {
		_ = m.Store.Audit(ctx, "system", "drift_detected", d.Detail)
	}
	return d, nil
}

func (m *Manager) requireNoPending(ctx context.Context) error {
	pending, err := m.Store.Pending(ctx)
	if err == nil {
		return fmt.Errorf("generation %d is still pending; commit or roll it back first", pending.ID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

func (m *Manager) acquireProcessLock() (func(), error) {
	path := filepath.Join(m.Store.Dir, ".controller.lock")
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, errors.New("controller lock path is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open controller lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("controller lock is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		file.Close()
		return nil, errors.New("controller lock has unsafe ownership")
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, fmt.Errorf("lock controller state: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func (m *Manager) expectedGeneration(ctx context.Context) (*state.Generation, error) {
	return m.Store.ExpectedGeneration(ctx)
}

func generationByID(s *state.Store, id uint64) (*state.Generation, error) {
	row := s.DB.QueryRow("SELECT id,checksum,observed_hash,script_path,status,created_at,rollback_deadline,previous_id FROM generations WHERE id=?", id)
	return scan(row)
}
func scan(row interface{ Scan(...any) error }) (*state.Generation, error) {
	var g state.Generation
	var created string
	var deadline sql.NullString
	var prev sql.NullInt64
	if err := row.Scan(&g.ID, &g.Checksum, &g.ObservedHash, &g.ScriptPath, &g.Status, &created, &deadline, &prev); err != nil {
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
