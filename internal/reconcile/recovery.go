package reconcile

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

type RecoveryResult struct {
	Generation uint64
	Action     string
	Ready      bool
}

// RecoverAtBoot resolves the durable database/pointer state machine under the
// same process lock used by apply, commit, and the independent rollback timer.
// It never guesses between a candidate, its exact predecessor, and a third
// pointer state.
func (m *Manager) RecoverAtBoot(ctx context.Context) (RecoveryResult, error) {
	if m == nil || m.Backend == nil || m.Store == nil {
		return RecoveryResult{}, errors.New("recovery manager is not configured")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.acquireProcessLock(ctx)
	if err != nil {
		return RecoveryResult{}, err
	}
	defer release()
	return m.recoverAtBootLocked(state.WithMutationLock(ctx))
}

func (m *Manager) recoverAtBootLocked(ctx context.Context) (RecoveryResult, error) {
	// Readiness and rollback decisions are unsafe when another ruleset owns the
	// reserved provenance byte, even when the owned generation already matches
	// and no Backend.Apply would otherwise be required.
	if err := m.auditForeignMarkOwnership(ctx); err != nil {
		return RecoveryResult{}, err
	}
	pointer, pointerExists, err := state.ReadEnforcementPointer(m.Store.Dir)
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("read authoritative enforcement pointer: %w", err)
	}
	pending, pendingErr := m.Store.Pending(ctx)
	if pendingErr != nil && !errors.Is(pendingErr, sql.ErrNoRows) {
		return RecoveryResult{}, pendingErr
	}
	if pendingErr == nil {
		return m.recoverPendingAtBoot(ctx, pending, pointer, pointerExists)
	}
	if !pointerExists {
		return RecoveryResult{}, errors.New("no committed enforcement pointer exists")
	}
	generation, err := m.Store.Generation(ctx, pointer.Generation)
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("resolve committed pointer generation: %w", err)
	}
	if generation.Status != "committed" {
		return RecoveryResult{}, fmt.Errorf("enforcement pointer references generation %d with status %s", generation.ID, generation.Status)
	}
	latest, err := m.Store.LastKnownGood(ctx)
	if err != nil || latest.ID != generation.ID {
		if err != nil {
			return RecoveryResult{}, err
		}
		return RecoveryResult{}, errors.New("enforcement pointer is not the latest committed generation")
	}
	snapshot, err := state.EnsurePublishedGenerationDurable(m.Store.Dir, *pointer)
	if err != nil {
		return RecoveryResult{}, err
	}
	if err := m.validateGenerationSnapshot(ctx, generation, snapshot, false); err != nil {
		return RecoveryResult{}, err
	}
	if err := m.establishAndVerify(ctx, generation, snapshot); err != nil {
		return RecoveryResult{}, fmt.Errorf("restore committed generation %d: %w", generation.ID, err)
	}
	if err := m.requirePointer(*pointer); err != nil {
		return RecoveryResult{}, err
	}
	if err := m.Store.AuditDurable(ctx, "system", "generation_boot_restored", fmt.Sprintf("generation=%d", generation.ID)); err != nil {
		return RecoveryResult{}, err
	}
	return RecoveryResult{Generation: generation.ID, Action: "restored_committed", Ready: true}, nil
}

func (m *Manager) recoverPendingAtBoot(ctx context.Context, pending *state.Generation, pointer *state.EnforcementPointer, pointerExists bool) (RecoveryResult, error) {
	snapshot, err := state.LoadVerifiedGenerationSnapshot(m.Store.Dir, pending.ID)
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("load pending immutable snapshot: %w", err)
	}
	if err := m.validateGenerationSnapshot(ctx, pending, snapshot, pending.Status == "commit_prepared"); err != nil {
		return RecoveryResult{}, err
	}
	newPointer := snapshot.Pointer()
	if pending.Status == "commit_prepared" {
		if pointerExists && newPointer.Equal(pointer) {
			durableSnapshot, err := state.EnsurePublishedGenerationDurable(m.Store.Dir, newPointer)
			if err != nil {
				return RecoveryResult{}, err
			}
			if err := m.establishAndVerify(ctx, pending, durableSnapshot); err != nil {
				return RecoveryResult{}, fmt.Errorf("restore published prepared generation %d: %w", pending.ID, err)
			}
			if err := m.requirePointer(newPointer); err != nil {
				return RecoveryResult{}, err
			}
			if err := m.Store.FinalizeCommit(ctx, pending.ID); err != nil {
				return RecoveryResult{}, fmt.Errorf("finalize recovered commit: %w", err)
			}
			return RecoveryResult{Generation: pending.ID, Action: "finalized_prepared_commit", Ready: true}, nil
		}
		if !pointerMatchesPrevious(snapshot.Previous, pointer, pointerExists) {
			return RecoveryResult{}, errors.New("prepared generation observed an ambiguous third pointer state")
		}
		return m.restorePredecessorAndRollback(ctx, pending, snapshot)
	}
	if pending.Status != "pending" && pending.Status != "applied" {
		return RecoveryResult{}, fmt.Errorf("unsupported pending recovery status %s", pending.Status)
	}
	if !pointerMatchesPrevious(snapshot.Previous, pointer, pointerExists) {
		return RecoveryResult{}, errors.New("ordinary pending generation does not match its exact predecessor pointer")
	}
	stale, err := m.pendingIsStale(pending)
	if err != nil {
		return RecoveryResult{}, err
	}
	if !stale {
		return RecoveryResult{}, fmt.Errorf("generation %d is still live on its creating boot and before its deadline", pending.ID)
	}
	return m.restorePredecessorAndRollback(ctx, pending, snapshot)
}

func (m *Manager) pendingIsStale(generation *state.Generation) (bool, error) {
	bootID, err := state.CurrentBootID()
	if err != nil {
		return false, fmt.Errorf("read current boot id: %w", err)
	}
	if generation.BootID == "" {
		return false, errors.New("pending generation has no creating boot id")
	}
	if generation.BootID != bootID {
		return true, nil
	}
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	return generation.RollbackDeadline != nil && !now().UTC().Before(*generation.RollbackDeadline), nil
}

func (m *Manager) restorePredecessorAndRollback(ctx context.Context, candidate *state.Generation, candidateSnapshot state.GenerationSnapshot) (RecoveryResult, error) {
	if candidateSnapshot.Previous == nil {
		return m.rollbackFirstGenerationAtBoot(ctx, candidate)
	}
	previousPointer := *candidateSnapshot.Previous
	previous, err := m.Store.Generation(ctx, previousPointer.Generation)
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("resolve pending predecessor generation: %w", err)
	}
	if previous.Status != "committed" || previous.Checksum != previousPointer.PolicyChecksum || previous.SnapshotChecksum != previousPointer.SnapshotChecksum {
		return RecoveryResult{}, errors.New("pending predecessor is not the exact committed generation")
	}
	previousSnapshot, err := state.EnsurePublishedGenerationDurable(m.Store.Dir, previousPointer)
	if err != nil {
		return RecoveryResult{}, err
	}
	if err := m.validateGenerationSnapshot(ctx, previous, previousSnapshot, false); err != nil {
		return RecoveryResult{}, err
	}
	if err := m.establishAndVerify(ctx, previous, previousSnapshot); err != nil {
		return RecoveryResult{}, fmt.Errorf("restore predecessor generation %d: %w", previous.ID, err)
	}
	if err := m.restoreRuntimeOrDeny(ctx); err != nil {
		return RecoveryResult{}, fmt.Errorf("restore predecessor runtime state: %w", err)
	}
	if err := m.requirePointer(previousPointer); err != nil {
		return RecoveryResult{}, err
	}
	if err := m.Store.FinalizeRecoveryRollback(ctx, candidate.ID, fmt.Sprintf("generation=%d predecessor=%d", candidate.ID, previous.ID)); err != nil {
		return RecoveryResult{}, err
	}
	return RecoveryResult{Generation: previous.ID, Action: "rolled_back_to_predecessor", Ready: true}, nil
}

func (m *Manager) rollbackFirstGenerationAtBoot(ctx context.Context, candidate *state.Generation) (RecoveryResult, error) {
	existing, err := m.Backend.ExistingOwned(ctx)
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("inspect first-generation recovery state: %w", err)
	}
	if len(existing) > 0 {
		if len(existing) != len(m.Backend.Owned) || candidate.ObservedHash == "" {
			return RecoveryResult{}, errors.New("first pending generation left ambiguous product-named nftables state")
		}
		ok, detail, err := m.Backend.Integrity(ctx)
		if err != nil || !ok {
			if err != nil {
				return RecoveryResult{}, err
			}
			return RecoveryResult{}, fmt.Errorf("first pending generation cannot be safely removed: %s", detail)
		}
		fingerprint, err := m.Backend.Fingerprint(ctx)
		if err != nil || fingerprint != candidate.ObservedHash {
			if err != nil {
				return RecoveryResult{}, err
			}
			return RecoveryResult{}, errors.New("first pending generation fingerprint is ambiguous")
		}
		if err := m.Backend.DestroyOwned(ctx); err != nil {
			return RecoveryResult{}, fmt.Errorf("remove verified first pending generation: %w", err)
		}
		remaining, err := m.Backend.ExistingOwned(ctx)
		if err != nil || len(remaining) != 0 {
			if err != nil {
				return RecoveryResult{}, err
			}
			return RecoveryResult{}, errors.New("verified first pending generation remained after removal")
		}
	}
	if err := m.Store.FinalizeRecoveryRollback(ctx, candidate.ID, fmt.Sprintf("generation=%d predecessor=ABSENT", candidate.ID)); err != nil {
		return RecoveryResult{}, err
	}
	return RecoveryResult{Generation: candidate.ID, Action: "rolled_back_first_generation", Ready: false}, errors.New("first pending generation was rolled back without a committed predecessor; readiness remains blocked")
}

func (m *Manager) validateGenerationSnapshot(ctx context.Context, generation *state.Generation, snapshot state.GenerationSnapshot, prepared bool) error {
	pointer := snapshot.Pointer()
	if generation == nil || generation.ID != snapshot.Generation || generation.Checksum != snapshot.Checksum || generation.SnapshotChecksum != pointer.SnapshotChecksum || generation.BootID != snapshot.BootID {
		return errors.New("generation database row does not match its immutable snapshot")
	}
	expectedScript := filepath.Join(m.Store.Dir, "generations", fmt.Sprintf("%020d.nft", generation.ID))
	expectedSnapshot := filepath.Join(m.Store.Dir, "generations", fmt.Sprintf("%020d.snapshot.json", generation.ID))
	if generation.ScriptPath != expectedScript || generation.SnapshotPath != expectedSnapshot {
		return errors.New("generation database paths do not name the immutable generation files")
	}
	script, err := m.Store.ReadScript(generation)
	if err != nil || script != snapshot.Script {
		if err != nil {
			return err
		}
		return errors.New("generation script and immutable snapshot disagree")
	}
	if snapshot.Previous == nil {
		if generation.PreviousID != nil || prepared && (generation.PreparedPriorID != nil || generation.PreparedPriorSum != "" || generation.PreparedPriorSnapshotSum != "") {
			return errors.New("first generation contains an unexpected predecessor")
		}
		return nil
	}
	if generation.PreviousID == nil || *generation.PreviousID != snapshot.Previous.Generation {
		return errors.New("generation predecessor id disagrees with immutable snapshot")
	}
	previous, err := m.Store.Generation(ctx, snapshot.Previous.Generation)
	if err != nil || previous.Checksum != snapshot.Previous.PolicyChecksum || previous.SnapshotChecksum != snapshot.Previous.SnapshotChecksum {
		if err != nil {
			return err
		}
		return errors.New("generation predecessor checksum disagrees with immutable snapshot")
	}
	if prepared && (generation.PreparedPriorID == nil || *generation.PreparedPriorID != snapshot.Previous.Generation || generation.PreparedPriorSum != snapshot.Previous.PolicyChecksum || generation.PreparedPriorSnapshotSum != snapshot.Previous.SnapshotChecksum) {
		return errors.New("prepared predecessor tuple disagrees with immutable snapshot")
	}
	return nil
}

func (m *Manager) establishAndVerify(ctx context.Context, generation *state.Generation, snapshot state.GenerationSnapshot) error {
	if err := m.auditForeignMarkOwnership(ctx); err != nil {
		return err
	}
	if generation.ObservedHash == "" {
		return errors.New("generation has no persisted observed-state fingerprint")
	}
	if ok, _, err := m.Backend.Integrity(ctx); err == nil && ok {
		if fingerprint, fingerprintErr := m.Backend.Fingerprint(ctx); fingerprintErr == nil && fingerprint == generation.ObservedHash {
			return nil
		}
	}
	if err := m.installOwnedGeneration(ctx, snapshot.Script); err != nil {
		return err
	}
	ok, detail, err := m.Backend.Integrity(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("owned nftables integrity failed: %s", detail)
	}
	fingerprint, err := m.Backend.Fingerprint(ctx)
	if err != nil {
		return err
	}
	if fingerprint != generation.ObservedHash {
		return errors.New("restored nftables fingerprint does not match durable generation")
	}
	return nil
}

func (m *Manager) requirePointer(expected state.EnforcementPointer) error {
	pointer, exists, err := state.ReadEnforcementPointer(m.Store.Dir)
	if err != nil {
		return err
	}
	if !exists || !expected.Equal(pointer) {
		return errors.New("authoritative enforcement pointer changed during recovery")
	}
	return nil
}

func pointerMatchesPrevious(previous *state.EnforcementPointer, observed *state.EnforcementPointer, observedExists bool) bool {
	if previous == nil {
		return !observedExists
	}
	return observedExists && previous.Equal(observed)
}

// VerifyEnforcement is deliberately nonmutating. Callers open Store with
// state.OpenReadOnly and hold the common process lock before invoking it.
func VerifyEnforcement(ctx context.Context, store *state.Store, backend *nft.Backend) error {
	if store == nil || backend == nil {
		return errors.New("enforcement verifier is not configured")
	}
	if _, err := backend.AuditForeignProvenanceMask(ctx); err != nil {
		return fmt.Errorf("foreign conntrack-mark ownership audit before live verification: %w", err)
	}
	baseline, err := captureEnforcementEvidence(ctx, store)
	if err != nil {
		return fmt.Errorf("capture enforcement evidence before live verification: %w", err)
	}
	ok, detail, err := backend.Integrity(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("owned nftables integrity failed: %s", detail)
	}
	fingerprint, err := backend.Fingerprint(ctx)
	if err != nil {
		return err
	}
	if baseline.observedHash == "" || fingerprint != baseline.observedHash {
		return errors.New("live nftables fingerprint does not match committed generation")
	}
	between, err := captureEnforcementEvidence(ctx, store)
	if err != nil {
		return fmt.Errorf("revalidate enforcement evidence between live samples: %w", err)
	}
	if err := compareEnforcementEvidence(baseline, between); err != nil {
		return err
	}
	finalOK, finalDetail, err := backend.Integrity(ctx)
	if err != nil {
		return err
	}
	if !finalOK {
		return fmt.Errorf("owned nftables integrity changed during verification: %s", finalDetail)
	}
	finalFingerprint, err := backend.Fingerprint(ctx)
	if err != nil {
		return err
	}
	if _, err := backend.AuditForeignProvenanceMask(ctx); err != nil {
		return fmt.Errorf("foreign conntrack-mark ownership audit after live verification: %w", err)
	}
	after, err := captureEnforcementEvidence(ctx, store)
	if err != nil {
		return fmt.Errorf("revalidate enforcement evidence after live verification: %w", err)
	}
	if err := compareEnforcementEvidence(baseline, after); err != nil {
		return err
	}
	if finalFingerprint != fingerprint || finalFingerprint != baseline.observedHash {
		return errors.New("live nftables fingerprint changed during verification")
	}
	return nil
}
