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
	PostRestore func(context.Context) error
	mu          sync.Mutex
}

type Result struct {
	Generation uint64
	Checksum   string
	Deadline   *time.Time
	Committed  bool
}

const mutationRecoveryTimeout = 20 * time.Second

const (
	runtimeRestoreAttemptTimeout = 12 * time.Second
	emergencyDenyAttemptTimeout  = 8 * time.Second
)

func mutationRecoveryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), mutationRecoveryTimeout)
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
	release, err := m.acquireProcessLock(ctx)
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
	} else if err := m.Backend.ProtectFirstUse(ctx); err != nil {
		return Result{}, fmt.Errorf("first-use ownership check: %w", err)
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
		_ = m.Store.Audit(ctx, "system", "generation_apply_failed", fmt.Sprintf("generation=%d error=%v", artifact.Generation, err))
		if nft.MutationAttempted(err) {
			recoveryCtx, cancel := mutationRecoveryContext(ctx)
			defer cancel()
			cause := fmt.Errorf("apply candidate generation %d: %w", artifact.Generation, err)
			if previous == nil {
				return Result{}, m.recoverFirstApplyExecutionFailure(recoveryCtx, artifact.Generation, cause)
			}
			return Result{}, m.recoverPostApplyFailure(recoveryCtx, artifact.Generation, previous, cause)
		}
		if markErr := m.Store.MarkRolledBack(ctx, artifact.Generation); markErr != nil {
			return Result{}, errors.Join(err, fmt.Errorf("record non-mutating apply rejection: %w", markErr))
		}
		return Result{}, err
	}
	if err := m.Store.MarkApplied(ctx, artifact.Generation); err != nil {
		recoveryCtx, cancel := mutationRecoveryContext(ctx)
		defer cancel()
		cause := fmt.Errorf("mark generation applied: %w", err)
		return Result{}, m.recoverPostApplyFailure(recoveryCtx, artifact.Generation, previous, cause)
	}
	if err := m.recordFingerprint(ctx, artifact.Generation); err != nil {
		recoveryCtx, cancel := mutationRecoveryContext(ctx)
		defer cancel()
		cause := fmt.Errorf("record applied nftables fingerprint: %w", err)
		return Result{}, m.recoverPostApplyFailure(recoveryCtx, artifact.Generation, previous, cause)
	}
	if m.HealthCheck != nil {
		if err := m.HealthCheck(ctx); err != nil {
			recoveryCtx, cancel := mutationRecoveryContext(ctx)
			defer cancel()
			rollbackErr := m.rollbackLocked(recoveryCtx, artifact.Generation)
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

// recoverPostApplyFailure handles failures after the candidate reached the
// kernel. A candidate remains pending/applied until restoration is confirmed;
// that durable state lets startup reconciliation retry instead of forgetting a
// possibly active candidate. Rollback errors are joined with the original
// failure so neither side of the incident is hidden.
func (m *Manager) recoverPostApplyFailure(ctx context.Context, id uint64, previous *state.Generation, cause error) error {
	if restoreErr := m.restore(ctx, previous); restoreErr != nil {
		return errors.Join(cause, fmt.Errorf("restore previous generation: %w", restoreErr))
	}
	if markErr := m.Store.MarkRolledBack(ctx, id); markErr != nil {
		return errors.Join(cause, fmt.Errorf("record confirmed rollback: %w", markErr))
	}
	return cause
}

func (m *Manager) recoverFirstApplyExecutionFailure(ctx context.Context, id uint64, cause error) error {
	existing, err := m.Backend.ExistingOwned(ctx)
	if err != nil {
		return errors.Join(cause, fmt.Errorf("inspect uncertain first apply: %w", err))
	}
	if len(existing) > 0 {
		return errors.Join(cause, errors.New("first apply left unverified product-named nft tables; refusing automatic deletion"))
	}
	if err := m.Store.MarkRolledBack(ctx, id); err != nil {
		return errors.Join(cause, fmt.Errorf("record confirmed empty first apply rollback: %w", err))
	}
	return cause
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
	if err := m.recordFingerprint(ctx, previous.ID); err != nil {
		return err
	}
	return m.restoreRuntimeOrDeny(ctx)
}

func (m *Manager) restoreRuntimeOrDeny(ctx context.Context) error {
	if m.PostRestore == nil {
		return nil
	}
	restoreCtx, restoreCancel := context.WithTimeout(ctx, runtimeRestoreAttemptTimeout)
	err := m.PostRestore(restoreCtx)
	restoreCancel()
	if err != nil {
		_ = m.Store.Audit(ctx, "system", "runtime_state_restore_failed", "emergency default-deny policy requested")
		denyCtx, denyCancel := context.WithTimeout(context.WithoutCancel(ctx), emergencyDenyAttemptTimeout)
		defer denyCancel()
		if denyErr := m.Backend.Apply(denyCtx, nft.EmergencyDenyScript); denyErr != nil {
			return fmt.Errorf("restore runtime state: %w; emergency deny also failed: %v", err, denyErr)
		}
		return fmt.Errorf("restore runtime state: %w; emergency default-deny policy installed", err)
	}
	return nil
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
	release, err := m.acquireProcessLock(ctx)
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
		recoveryCtx, cancel := mutationRecoveryContext(ctx)
		defer cancel()
		if rollbackErr := m.rollbackLocked(recoveryCtx, id); rollbackErr != nil {
			return fmt.Errorf("generation %d expired and rollback failed: %w", id, rollbackErr)
		}
		return fmt.Errorf("generation %d expired and was rolled back", id)
	}
	observedHash, err := m.Backend.Fingerprint(ctx)
	if err != nil || pending.ObservedHash == "" || observedHash != pending.ObservedHash {
		recoveryCtx, cancel := mutationRecoveryContext(ctx)
		defer cancel()
		rollbackErr := m.rollbackLocked(recoveryCtx, id)
		if rollbackErr != nil {
			return fmt.Errorf("generation %d integrity verification failed and rollback failed: %v", id, rollbackErr)
		}
		return fmt.Errorf("generation %d integrity verification failed and was rolled back", id)
	}
	return m.commitLocked(ctx, id)
}

func (m *Manager) commitLocked(ctx context.Context, id uint64) error {
	g, err := generationByID(ctx, m.Store, id)
	if err != nil {
		return err
	}
	script, err := m.Store.ReadScript(g)
	if err != nil {
		return fmt.Errorf("read committed generation: %w", err)
	}
	if err := m.Store.Commit(ctx, id); err != nil {
		recoveryCtx, cancel := mutationRecoveryContext(ctx)
		defer cancel()
		rollbackErr := m.rollbackLocked(recoveryCtx, id)
		if rollbackErr != nil {
			return fmt.Errorf("commit generation: %w; rollback also failed: %v", err, rollbackErr)
		}
		return fmt.Errorf("commit generation: %w; generation was rolled back", err)
	}
	if err := m.Store.PublishActive(script, g.Checksum); err != nil {
		recoveryCtx, cancel := mutationRecoveryContext(ctx)
		defer cancel()
		rollbackErr := m.rollbackLocked(recoveryCtx, id)
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
	release, err := m.acquireProcessLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	return m.rollbackLocked(ctx, id)
}

func (m *Manager) rollbackLocked(ctx context.Context, id uint64) error {
	g, err := generationByID(ctx, m.Store, id)
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
	firstPendingWithoutEstablishedOwnership := g.PreviousID == nil && g.Status == "pending"
	if firstPendingWithoutEstablishedOwnership {
		existing, inspectErr := m.Backend.ExistingOwned(ctx)
		if inspectErr != nil {
			return fmt.Errorf("inspect ambiguous first-generation pending ownership: %w", inspectErr)
		}
		if len(existing) > 0 {
			return errors.New("first-generation pending state has unverified product-named nft tables; refusing automatic deletion")
		}
	}
	var previous *state.Generation
	var previousScript string
	if g.PreviousID == nil && !firstPendingWithoutEstablishedOwnership {
		fallbackChecksum := sha256.Sum256([]byte(nft.EmergencyDenyScript))
		if err := m.Store.PublishActive(nft.EmergencyDenyScript, hex.EncodeToString(fallbackChecksum[:])); err != nil {
			return fmt.Errorf("publish first-generation rollback fallback: %w", err)
		}
	} else if g.PreviousID != nil {
		previous, err = generationByID(ctx, m.Store, *g.PreviousID)
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
	if previous != nil {
		if err := m.Backend.Apply(ctx, previousScript); err != nil {
			if recoveryErr := m.restoreCommittedAfterFailedRollback(ctx, g); recoveryErr != nil {
				return errors.Join(err, fmt.Errorf("restore committed generation after failed rollback: %w", recoveryErr))
			}
			return err
		}
	} else if !firstPendingWithoutEstablishedOwnership {
		if err := m.Backend.DestroyOwned(ctx); err != nil {
			if recoveryErr := m.restoreCommittedAfterFailedRollback(ctx, g); recoveryErr != nil {
				return errors.Join(err, fmt.Errorf("restore committed generation after failed rollback: %w", recoveryErr))
			}
			return err
		}
	}
	recoveryCtx, cancel := mutationRecoveryContext(ctx)
	defer cancel()
	if previous != nil {
		if err := m.restoreRuntimeOrDeny(recoveryCtx); err != nil {
			return err
		}
	}
	if err := m.Store.MarkRolledBack(recoveryCtx, id); err != nil {
		if recoveryErr := m.restoreCommittedAfterFailedRollback(recoveryCtx, g); recoveryErr != nil {
			return errors.Join(err, fmt.Errorf("restore committed generation after rollback bookkeeping failure: %w", recoveryErr))
		}
		return err
	}
	if previous == nil {
		// Clear only after SQLite records the rollback. Applied/committed first
		// generations published emergency deny before kernel deletion; an
		// unverified pending first generation never publishes or deletes tables.
		if err := m.Store.ClearActive(); err != nil {
			return fmt.Errorf("clear active boot snapshot: %w", err)
		}
	}
	return m.Store.Audit(recoveryCtx, "system", "generation_rolled_back", fmt.Sprintf("generation=%d", id))
}

func (m *Manager) restoreCommittedAfterFailedRollback(ctx context.Context, g *state.Generation) error {
	if g == nil || g.Status != "committed" {
		return nil
	}
	recoveryCtx, cancel := mutationRecoveryContext(ctx)
	defer cancel()
	script, err := m.Store.ReadScript(g)
	if err != nil {
		return err
	}
	if err := m.Store.PublishActive(script, g.Checksum); err != nil {
		return err
	}
	if err := m.Backend.Apply(recoveryCtx, script); err != nil {
		return err
	}
	return m.restoreRuntimeOrDeny(recoveryCtx)
}

func (m *Manager) RollbackExpired(ctx context.Context) (bool, error) {
	if m == nil || m.Backend == nil || m.Store == nil {
		return false, errors.New("reconcile manager is not configured")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.acquireProcessLock(ctx)
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
	release, err := m.acquireProcessLock(ctx)
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
		recoveryCtx, cancel := mutationRecoveryContext(ctx)
		defer cancel()
		if err := m.recordFingerprint(recoveryCtx, g.ID); err != nil {
			return d, err
		}
		if err := m.restoreRuntimeOrDeny(recoveryCtx); err != nil {
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

func (m *Manager) acquireProcessLock(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("wait for controller lock: %w", err)
	}
	path := filepath.Join(m.Store.Dir, ".controller.lock")
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, errors.New("controller lock path is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open controller lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("controller lock is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		file.Close()
		return nil, errors.New("controller lock has unsafe ownership")
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	retry := time.NewTicker(10 * time.Millisecond)
	defer retry.Stop()
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
				return nil, fmt.Errorf("wait for controller lock: %w", ctxErr)
			}
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			file.Close()
			return nil, fmt.Errorf("lock controller state: %w", err)
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, fmt.Errorf("wait for controller lock: %w", ctx.Err())
		case <-retry.C:
		}
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func (m *Manager) expectedGeneration(ctx context.Context) (*state.Generation, error) {
	return m.Store.ExpectedGeneration(ctx)
}

func generationByID(ctx context.Context, s *state.Store, id uint64) (*state.Generation, error) {
	row := s.DB.QueryRowContext(ctx, "SELECT id,checksum,observed_hash,script_path,status,created_at,rollback_deadline,previous_id FROM generations WHERE id=?", id)
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
		if prev.Int64 <= 0 {
			return nil, errors.New("generation has an invalid previous generation reference")
		}
		v := uint64(prev.Int64)
		g.PreviousID = &v
	}
	return &g, nil
}
