// Package reconcile is the durable desired/observed/effective state controller.
package reconcile

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/compiler"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

type Manager struct {
	Backend          *nft.Backend
	Store            *state.Store
	SafeTTL          time.Duration
	Now              func() time.Time
	HealthCheck      func(context.Context) error
	SafeGuard        func(context.Context) error
	SafeGuardLocked  func(context.Context) error
	ForeignMarkGuard func(context.Context) error
	PostRestore      func(context.Context) error
	// MutationLockDir is the shared volatile runtime directory used by every
	// daemon, early-recovery, verifier-adjacent, and timer process. Production
	// callers set it to state.DefaultMutationLockDir.
	MutationLockDir string
	mu              sync.Mutex
}

type safeGuardPreflightContextKey struct{}

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

func (m *Manager) auditForeignMarkOwnership(ctx context.Context) error {
	if m.ForeignMarkGuard == nil {
		return errors.New("foreign conntrack-mark ownership guard is unavailable")
	}
	if err := m.ForeignMarkGuard(ctx); err != nil {
		return fmt.Errorf("foreign conntrack-mark ownership audit: %w", err)
	}
	return nil
}

// installOwnedGeneration is the single mutation seam for a compiled or
// restored generation. Every caller already holds the common process mutation
// lock; this final audit is deliberately adjacent to Backend.Apply. It cannot
// serialize an independent privileged nft writer, which remains an explicit
// trusted-root/runtime-writer boundary.
func (m *Manager) installOwnedGeneration(ctx context.Context, script string) error {
	if err := m.auditForeignMarkOwnership(ctx); err != nil {
		return err
	}
	return m.Backend.Apply(ctx, script)
}

// PreflightSafeApply starts and proves the independent rollback path before a
// caller takes the common process mutation lock. The returned context is the
// only marker Apply accepts as proof that this exact preflight completed.
func (m *Manager) PreflightSafeApply(ctx context.Context) (context.Context, error) {
	if m == nil || m.SafeGuard == nil || m.SafeGuardLocked == nil {
		return nil, errors.New("safe apply requires preflight and locked rollback-guard verification")
	}
	if err := m.SafeGuard(ctx); err != nil {
		return nil, fmt.Errorf("safe apply refused: %w", err)
	}
	return context.WithValue(ctx, safeGuardPreflightContextKey{}, true), nil
}

func safeGuardPreflightComplete(ctx context.Context) bool {
	complete, _ := ctx.Value(safeGuardPreflightContextKey{}).(bool)
	return complete
}

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
	if safe && !safeGuardPreflightComplete(ctx) {
		preflightCtx, err := m.PreflightSafeApply(ctx)
		if err != nil {
			return Result{}, err
		}
		ctx = preflightCtx
	}
	release, err := m.acquireProcessLock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()
	ctx = state.WithMutationLock(ctx)
	if err := m.requireNoPending(ctx); err != nil {
		return Result{}, err
	}
	if safe {
		if m.SafeGuardLocked == nil {
			return Result{}, errors.New("safe apply requires locked rollback-guard verification")
		}
		if err := m.SafeGuardLocked(ctx); err != nil {
			return Result{}, fmt.Errorf("safe apply locked revalidation refused: %w", err)
		}
	}
	if err := m.auditForeignMarkOwnership(ctx); err != nil {
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
	bootID, err := state.CurrentBootID()
	if err != nil {
		return Result{}, fmt.Errorf("read creating boot id: %w", err)
	}
	metadata := state.GenerationMetadata{BootID: bootID, Provenance: artifact.Provenance}
	if err := m.Store.SaveGenerationWithMetadata(ctx, artifact.Generation, artifact.Checksum, artifact.Script, prevID, deadline, metadata); err != nil {
		return Result{}, fmt.Errorf("persist pending generation: %w", err)
	}
	if err := m.installOwnedGeneration(ctx, artifact.Script); err != nil {
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
	if err := m.installOwnedGeneration(ctx, script); err != nil {
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
	ctx = state.WithMutationLock(ctx)
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
	if g.Status != "applied" {
		return fmt.Errorf("generation %d status %s cannot be committed", id, g.Status)
	}
	snapshot, err := state.LoadGenerationSnapshot(m.Store.Dir, id)
	if err != nil {
		return fmt.Errorf("read immutable generation snapshot: %w", err)
	}
	current, exists, err := state.ReadEnforcementPointer(m.Store.Dir)
	if err != nil {
		return err
	}
	if snapshot.Previous == nil {
		if exists {
			return errors.New("first commit requires an absent enforcement pointer")
		}
	} else if !exists || !snapshot.Previous.Equal(current) {
		return errors.New("current enforcement pointer does not match generation's recorded predecessor")
	}
	// A foreign privileged writer can claim the reserved conntrack-mark byte
	// during the safe-apply TTL. Re-audit while the cooperative mutation lock is
	// held and before either durable commit preparation or pointer publication.
	// The final deadline read must remain the last I/O before the pointer rename.
	if err := m.auditForeignMarkOwnership(ctx); err != nil {
		return err
	}
	if _, err := m.Store.PrepareCommit(ctx, id); err != nil {
		return fmt.Errorf("durably prepare generation commit: %w", err)
	}
	preparedPointer, err := state.PrepareEnforcementPointer(m.Store.Dir, snapshot.Pointer())
	if err != nil {
		return fmt.Errorf("prepare enforcement pointer after durable commit state: %w", err)
	}
	defer state.CancelPreparedPointer(preparedPointer)
	// This is the final persisted-deadline read. Until the rename below, only
	// the injected/userspace clock is consulted; no intervening I/O occurs.
	deadline, err := m.Store.PreparedDeadline(ctx, id)
	if err != nil {
		return fmt.Errorf("read final commit deadline: %w", err)
	}
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	if deadline != nil && !now().UTC().Before(*deadline) {
		if err := state.CancelPreparedPointer(preparedPointer); err != nil {
			return fmt.Errorf("generation %d expired; cancel prepared pointer: %w", id, err)
		}
		if err := m.rollbackLocked(ctx, id); err != nil {
			return fmt.Errorf("generation %d expired and rollback failed: %w", id, err)
		}
		return fmt.Errorf("generation %d expired and was rolled back", id)
	}
	if err := state.PublishPreparedPointer(preparedPointer); err != nil {
		return fmt.Errorf("publish enforcement pointer: %w", err)
	}
	if err := m.Store.FinalizeCommit(ctx, id); err != nil {
		// The pointer is the linearization point. Never roll it back after a
		// successful rename; recovery idempotently finalizes commit_prepared.
		return fmt.Errorf("enforcement pointer published; generation finalization requires recovery: %w", err)
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
	ctx = state.WithMutationLock(ctx)
	return m.rollbackLocked(ctx, id)
}

func (m *Manager) rollbackLocked(ctx context.Context, id uint64) error {
	// Gate even idempotent/no-install rollback decisions. A foreign reservation
	// collision makes the resulting enforcement state unsafe to authorize.
	if err := m.auditForeignMarkOwnership(ctx); err != nil {
		return err
	}
	g, err := generationByID(ctx, m.Store, id)
	if err != nil {
		return err
	}
	if g.Status == "rolled_back" {
		return nil
	}
	if g.Status == "committed" {
		return fmt.Errorf("generation %d is committed; rollback is restricted to pending safe-apply generations", id)
	}
	if g.Status != "pending" && g.Status != "applied" && g.Status != "commit_prepared" {
		return fmt.Errorf("generation %d has unsupported rollback status %s", id, g.Status)
	}
	snapshot, err := state.LoadVerifiedGenerationSnapshot(m.Store.Dir, id)
	if err != nil {
		return fmt.Errorf("load verified rollback generation snapshot: %w", err)
	}
	if err := m.validateGenerationSnapshot(ctx, g, snapshot, g.Status == "commit_prepared"); err != nil {
		return fmt.Errorf("validate rollback generation snapshot: %w", err)
	}
	currentPointer, pointerExists, err := state.ReadEnforcementPointer(m.Store.Dir)
	if err != nil {
		return err
	}
	newPointer := snapshot.Pointer()
	if g.Status == "commit_prepared" && newPointer.Equal(currentPointer) {
		// The atomic pointer rename won. A timer or operator racing afterward
		// may only finalize; it must never move the pointer back.
		if err := m.Store.FinalizeCommit(ctx, id); err != nil {
			return fmt.Errorf("finalize already-published generation %d: %w", id, err)
		}
		return fmt.Errorf("generation %d commit pointer was already published", id)
	}
	if snapshot.Previous == nil {
		if pointerExists {
			return errors.New("pending first generation has an unexpected enforcement pointer")
		}
	} else if !pointerExists || !snapshot.Previous.Equal(currentPointer) {
		return errors.New("pending generation predecessor pointer is ambiguous")
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
	if g.PreviousID != nil {
		previous, err = generationByID(ctx, m.Store, *g.PreviousID)
		if err != nil {
			return err
		}
		if snapshot.Previous == nil || previous.Status != "committed" {
			return errors.New("rollback predecessor is not the exact committed generation")
		}
		previousSnapshot, snapshotErr := state.EnsurePublishedGenerationDurable(m.Store.Dir, *snapshot.Previous)
		if snapshotErr != nil {
			return fmt.Errorf("load durable rollback predecessor snapshot: %w", snapshotErr)
		}
		if err := m.validateGenerationSnapshot(ctx, previous, previousSnapshot, false); err != nil {
			return fmt.Errorf("validate rollback predecessor snapshot: %w", err)
		}
		previousScript = previousSnapshot.Script
	}
	if previous != nil {
		if err := m.installOwnedGeneration(ctx, previousScript); err != nil {
			return err
		}
	} else if !firstPendingWithoutEstablishedOwnership {
		if err := m.Backend.DestroyOwned(ctx); err != nil {
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
		return err
	}
	if previous == nil {
		// Clear only after SQLite records the rollback. An applied first
		// generation published emergency deny before kernel deletion; an
		// unverified pending first generation never publishes or deletes tables.
		if err := m.Store.ClearActive(); err != nil {
			return fmt.Errorf("clear active boot snapshot: %w", err)
		}
	}
	return m.Store.Audit(recoveryCtx, "system", "generation_rolled_back", fmt.Sprintf("generation=%d", id))
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
	ctx = state.WithMutationLock(ctx)
	if err := m.auditForeignMarkOwnership(ctx); err != nil {
		return false, err
	}
	pending, err := m.Store.Pending(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if pending.Status != "commit_prepared" {
		stale, staleErr := m.pendingIsStale(pending)
		if staleErr != nil {
			return false, staleErr
		}
		if !stale {
			return false, nil
		}
	}
	pointer, pointerExists, err := state.ReadEnforcementPointer(m.Store.Dir)
	if err != nil {
		return false, err
	}
	result, recoveryErr := m.recoverPendingAtBoot(state.WithMutationLock(ctx), pending, pointer, pointerExists)
	rolledBack := result.Action == "rolled_back_to_predecessor" || result.Action == "rolled_back_first_generation"
	if recoveryErr != nil {
		return rolledBack, recoveryErr
	}
	if result.Action == "finalized_prepared_commit" {
		return false, nil
	}
	return rolledBack, nil
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
	ctx = state.WithMutationLock(ctx)
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
		if err := m.installOwnedGeneration(ctx, script); err != nil {
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
	if state.MutationLockHeld(ctx) {
		return func() {}, nil
	}
	if m.MutationLockDir == "" {
		return nil, errors.New("cross-process mutation lock directory is not configured")
	}
	return state.AcquireMutationLock(ctx, m.MutationLockDir)
}

func (m *Manager) expectedGeneration(ctx context.Context) (*state.Generation, error) {
	return m.Store.ExpectedGeneration(ctx)
}

func generationByID(ctx context.Context, s *state.Store, id uint64) (*state.Generation, error) {
	return s.Generation(ctx, id)
}
