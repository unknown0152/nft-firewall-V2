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
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

type preparedRecoveryFixture struct {
	manager   *Manager
	store     *state.Store
	runner    *runner
	candidate *state.Generation
	new       state.EnforcementPointer
	previous  *state.EnforcementPointer
}

func newPreparedRecoveryFixture(t *testing.T, withPredecessor bool) *preparedRecoveryFixture {
	t.Helper()
	ctx := context.Background()
	manager, store, fake := newManager(t)
	manager.SafeTTL = time.Minute
	base := time.Date(2036, time.January, 2, 3, 4, 5, 0, time.UTC)
	manager.Now = func() time.Time { return base }

	var previous *state.EnforcementPointer
	candidateID := uint64(1)
	if withPredecessor {
		if _, err := manager.Apply(ctx, artifact(1), false); err != nil {
			store.Close()
			t.Fatalf("commit predecessor generation: %v", err)
		}
		pointer, exists, err := state.ReadEnforcementPointer(store.Dir)
		if err != nil || !exists {
			store.Close()
			t.Fatalf("read committed predecessor pointer: exists=%t err=%v", exists, err)
		}
		copy := *pointer
		previous = &copy
		candidateID = 2
	}

	if _, err := manager.Apply(ctx, artifact(candidateID), true); err != nil {
		store.Close()
		t.Fatalf("apply recovery candidate: %v", err)
	}
	prepared, err := store.PrepareCommit(ctx, candidateID)
	if err != nil {
		store.Close()
		t.Fatalf("durably prepare candidate commit: %v", err)
	}
	snapshot, err := state.LoadGenerationSnapshot(store.Dir, candidateID)
	if err != nil {
		store.Close()
		t.Fatalf("load prepared candidate snapshot: %v", err)
	}
	return &preparedRecoveryFixture{
		manager: manager, store: store, runner: fake, candidate: prepared,
		new: snapshot.Pointer(), previous: previous,
	}
}

func publishRecoveryPointer(t *testing.T, root string, pointer state.EnforcementPointer) {
	t.Helper()
	prepared, err := state.PrepareEnforcementPointer(root, pointer)
	if err != nil {
		t.Fatalf("prepare test enforcement pointer: %v", err)
	}
	defer func() {
		if err := state.CancelPreparedPointer(prepared); err != nil {
			t.Errorf("clean prepared test pointer: %v", err)
		}
	}()
	if err := state.PublishPreparedPointer(prepared); err != nil {
		t.Fatalf("publish test enforcement pointer: %v", err)
	}
}

func TestRecoverCommitPreparedUsesExactPointerState(t *testing.T) {
	ctx := context.Background()

	t.Run("published candidate finalizes even at an expired deadline", func(t *testing.T) {
		fixture := newPreparedRecoveryFixture(t, true)
		defer fixture.store.Close()
		publishRecoveryPointer(t, fixture.store.Dir, fixture.new)
		fixture.runner.owned = false
		beforeApply := fixture.runner.applyCalls
		fixture.manager.Now = func() time.Time {
			return fixture.candidate.RollbackDeadline.Add(time.Hour)
		}

		result, err := fixture.manager.RecoverAtBoot(ctx)
		if err != nil {
			t.Fatalf("recover published prepared commit: %v", err)
		}
		if result.Generation != fixture.candidate.ID || result.Action != "finalized_prepared_commit" || !result.Ready {
			t.Fatalf("wrong prepared-commit recovery result: %+v", result)
		}
		if fixture.runner.applyCalls != beforeApply+1 || !fixture.runner.owned {
			t.Fatalf("published candidate was not re-established exactly once: calls=%d want=%d owned=%t", fixture.runner.applyCalls, beforeApply+1, fixture.runner.owned)
		}
		generation, err := fixture.store.Generation(ctx, fixture.candidate.ID)
		if err != nil || generation.Status != "committed" || generation.RollbackDeadline != nil {
			t.Fatalf("prepared candidate was not finalized: generation=%+v err=%v", generation, err)
		}
		if pending, err := fixture.store.Pending(ctx); !errors.Is(err, sql.ErrNoRows) || pending != nil {
			t.Fatalf("finalized candidate remains pending: pending=%+v err=%v", pending, err)
		}
		pointer, exists, err := state.ReadEnforcementPointer(fixture.store.Dir)
		if err != nil || !exists || !fixture.new.Equal(pointer) {
			t.Fatalf("published candidate pointer moved during finalization: pointer=%+v exists=%t err=%v", pointer, exists, err)
		}
	})

	t.Run("exact predecessor rolls prepared candidate back", func(t *testing.T) {
		fixture := newPreparedRecoveryFixture(t, true)
		defer fixture.store.Close()
		fixture.runner.owned = false
		beforeApply := fixture.runner.applyCalls
		runtimeRestores := 0
		fixture.manager.PostRestore = func(context.Context) error {
			runtimeRestores++
			return nil
		}

		result, err := fixture.manager.RecoverAtBoot(ctx)
		if err != nil {
			t.Fatalf("recover prepared candidate from exact predecessor: %v", err)
		}
		if result.Generation != fixture.previous.Generation || result.Action != "rolled_back_to_predecessor" || !result.Ready {
			t.Fatalf("wrong predecessor recovery result: %+v", result)
		}
		if fixture.runner.applyCalls != beforeApply+1 || !fixture.runner.owned || runtimeRestores != 1 {
			t.Fatalf("predecessor was not restored exactly once: apply_calls=%d want=%d owned=%t runtime_restores=%d", fixture.runner.applyCalls, beforeApply+1, fixture.runner.owned, runtimeRestores)
		}
		generation, err := fixture.store.Generation(ctx, fixture.candidate.ID)
		if err != nil || generation.Status != "rolled_back" {
			t.Fatalf("prepared candidate was not rolled back: generation=%+v err=%v", generation, err)
		}
		if pending, err := fixture.store.Pending(ctx); !errors.Is(err, sql.ErrNoRows) || pending != nil {
			t.Fatalf("rolled-back prepared candidate remains pending: pending=%+v err=%v", pending, err)
		}
		pointer, exists, err := state.ReadEnforcementPointer(fixture.store.Dir)
		if err != nil || !exists || !fixture.previous.Equal(pointer) {
			t.Fatalf("exact predecessor pointer changed: pointer=%+v exists=%t err=%v", pointer, exists, err)
		}
	})

	t.Run("exact absent predecessor rolls first prepared candidate back", func(t *testing.T) {
		fixture := newPreparedRecoveryFixture(t, false)
		defer fixture.store.Close()
		beforeApply := fixture.runner.applyCalls

		result, err := fixture.manager.RecoverAtBoot(ctx)
		if err == nil || !strings.Contains(err.Error(), "readiness remains blocked") {
			t.Fatalf("first-generation rollback did not block readiness: result=%+v err=%v", result, err)
		}
		if result.Generation != fixture.candidate.ID || result.Action != "rolled_back_first_generation" || result.Ready {
			t.Fatalf("wrong absent-predecessor recovery result: %+v", result)
		}
		if fixture.runner.applyCalls != beforeApply+1 || fixture.runner.owned {
			t.Fatalf("verified first-generation tables were not destroyed exactly once: calls=%d want=%d owned=%t", fixture.runner.applyCalls, beforeApply+1, fixture.runner.owned)
		}
		generation, generationErr := fixture.store.Generation(ctx, fixture.candidate.ID)
		if generationErr != nil || generation.Status != "rolled_back" {
			t.Fatalf("first prepared candidate was not rolled back: generation=%+v err=%v", generation, generationErr)
		}
		if pointer, exists, pointerErr := state.ReadEnforcementPointer(fixture.store.Dir); pointerErr != nil || exists || pointer != nil {
			t.Fatalf("ABSENT predecessor was replaced by a pointer: pointer=%+v exists=%t err=%v", pointer, exists, pointerErr)
		}
	})

	t.Run("third pointer fails without durable or nft mutation", func(t *testing.T) {
		fixture := newPreparedRecoveryFixture(t, true)
		defer fixture.store.Close()
		third := fixture.new
		third.Generation = 999
		third.SnapshotChecksum = strings.Repeat("a", sha256.Size*2)
		third.PolicyChecksum = strings.Repeat("b", sha256.Size*2)
		publishRecoveryPointer(t, fixture.store.Dir, third)
		beforeTree := recoveryTreeDigest(t, fixture.store.Dir)
		beforeCounters := [...]int{fixture.runner.applyCalls, fixture.runner.ownedListCalls, fixture.runner.tableListCalls}
		beforeOwned := fixture.runner.owned

		result, err := fixture.manager.RecoverAtBoot(ctx)
		if err == nil || !strings.Contains(err.Error(), "ambiguous third pointer state") {
			t.Fatalf("third pointer was not rejected precisely: result=%+v err=%v", result, err)
		}
		if afterTree := recoveryTreeDigest(t, fixture.store.Dir); afterTree != beforeTree {
			t.Fatalf("third-pointer rejection changed durable state: before=%s after=%s", beforeTree, afterTree)
		}
		afterCounters := [...]int{fixture.runner.applyCalls, fixture.runner.ownedListCalls, fixture.runner.tableListCalls}
		if afterCounters != beforeCounters || fixture.runner.owned != beforeOwned {
			t.Fatalf("third-pointer rejection touched nft state: counters=%v want=%v owned=%t want=%t", afterCounters, beforeCounters, fixture.runner.owned, beforeOwned)
		}
		generation, generationErr := fixture.store.Generation(ctx, fixture.candidate.ID)
		if generationErr != nil || generation.Status != "commit_prepared" {
			t.Fatalf("third-pointer rejection changed prepared row: generation=%+v err=%v", generation, generationErr)
		}
		pointer, exists, pointerErr := state.ReadEnforcementPointer(fixture.store.Dir)
		if pointerErr != nil || !exists || !third.Equal(pointer) {
			t.Fatalf("third pointer changed during rejection: pointer=%+v exists=%t err=%v", pointer, exists, pointerErr)
		}
	})
}

func TestRecoverForeignBootOrdinaryPendingRollsBackDespiteFutureDeadline(t *testing.T) {
	ctx := context.Background()
	manager, store, fake := newManager(t)
	defer store.Close()
	if _, err := manager.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	prior, exists, err := state.ReadEnforcementPointer(store.Dir)
	if err != nil || !exists {
		t.Fatalf("read predecessor pointer: exists=%t err=%v", exists, err)
	}
	future := time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC)
	previousID := uint64(1)
	if err := store.SaveGenerationWithMetadata(ctx, 2, artifact(2).Checksum, artifact(2).Script, &previousID, &future, reconcileGenerationMetadata(t, "foreign-boot")); err != nil {
		t.Fatal(err)
	}
	fake.owned = false
	beforeApply := fake.applyCalls
	manager.Now = func() time.Time { return future.Add(-time.Hour) }
	runtimeRestores := 0
	manager.PostRestore = func(context.Context) error {
		runtimeRestores++
		return nil
	}

	result, err := manager.RecoverAtBoot(ctx)
	if err != nil {
		t.Fatalf("foreign-boot pending recovery: %v", err)
	}
	if result.Generation != 1 || result.Action != "rolled_back_to_predecessor" || !result.Ready {
		t.Fatalf("wrong foreign-boot recovery result: %+v", result)
	}
	if fake.applyCalls != beforeApply+1 || !fake.owned || runtimeRestores != 1 {
		t.Fatalf("foreign-boot recovery did not restore predecessor: calls=%d want=%d owned=%t runtime_restores=%d", fake.applyCalls, beforeApply+1, fake.owned, runtimeRestores)
	}
	if pending, err := store.Pending(ctx); !errors.Is(err, sql.ErrNoRows) || pending != nil {
		t.Fatalf("foreign-boot generation remains pending: pending=%+v err=%v", pending, err)
	}
	generation, err := store.Generation(ctx, 2)
	if err != nil || generation.Status != "rolled_back" {
		t.Fatalf("foreign-boot generation was not rolled back: generation=%+v err=%v", generation, err)
	}
	pointer, exists, err := state.ReadEnforcementPointer(store.Dir)
	if err != nil || !exists || !prior.Equal(pointer) {
		t.Fatalf("foreign-boot recovery changed predecessor pointer: pointer=%+v exists=%t err=%v", pointer, exists, err)
	}
}

func TestOrdinaryPendingDeadlineBoundary(t *testing.T) {
	ctx := context.Background()
	bootID, err := state.CurrentBootID()
	if err != nil {
		t.Fatalf("read test boot id: %v", err)
	}
	deadline := time.Date(2037, time.February, 3, 4, 5, 6, 700, time.UTC)

	for _, test := range []struct {
		name      string
		now       time.Time
		wantStale bool
	}{
		{name: "one nanosecond before deadline remains live", now: deadline.Add(-time.Nanosecond), wantStale: false},
		{name: "exact deadline is stale", now: deadline, wantStale: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, store, fake := newManager(t)
			defer store.Close()
			if _, err := manager.Apply(ctx, artifact(1), false); err != nil {
				t.Fatal(err)
			}
			prior, exists, err := state.ReadEnforcementPointer(store.Dir)
			if err != nil || !exists {
				t.Fatalf("read deadline predecessor: exists=%t err=%v", exists, err)
			}
			previousID := uint64(1)
			if err := store.SaveGenerationWithMetadata(ctx, 2, artifact(2).Checksum, artifact(2).Script, &previousID, &deadline, reconcileGenerationMetadata(t, bootID)); err != nil {
				t.Fatal(err)
			}
			manager.Now = func() time.Time { return test.now }

			if !test.wantStale {
				beforeTree := recoveryTreeDigest(t, store.Dir)
				beforeCounters := [...]int{fake.applyCalls, fake.ownedListCalls, fake.tableListCalls}
				result, err := manager.RecoverAtBoot(ctx)
				if err == nil || !strings.Contains(err.Error(), "still live on its creating boot and before its deadline") {
					t.Fatalf("pre-deadline pending was not retained: result=%+v err=%v", result, err)
				}
				if afterTree := recoveryTreeDigest(t, store.Dir); afterTree != beforeTree {
					t.Fatalf("pre-deadline recovery changed durable state: before=%s after=%s", beforeTree, afterTree)
				}
				afterCounters := [...]int{fake.applyCalls, fake.ownedListCalls, fake.tableListCalls}
				if afterCounters != beforeCounters {
					t.Fatalf("pre-deadline recovery touched nft state: counters=%v want=%v", afterCounters, beforeCounters)
				}
				pending, pendingErr := store.Pending(ctx)
				if pendingErr != nil || pending.ID != 2 || pending.Status != "pending" {
					t.Fatalf("pre-deadline row changed: pending=%+v err=%v", pending, pendingErr)
				}
				return
			}

			fake.owned = false
			beforeApply := fake.applyCalls
			result, err := manager.RecoverAtBoot(ctx)
			if err != nil {
				t.Fatalf("at-deadline recovery failed: %v", err)
			}
			if result.Generation != 1 || result.Action != "rolled_back_to_predecessor" || !result.Ready {
				t.Fatalf("wrong at-deadline recovery result: %+v", result)
			}
			if fake.applyCalls != beforeApply+1 || !fake.owned {
				t.Fatalf("at-deadline recovery did not restore predecessor: calls=%d want=%d owned=%t", fake.applyCalls, beforeApply+1, fake.owned)
			}
			if pending, err := store.Pending(ctx); !errors.Is(err, sql.ErrNoRows) || pending != nil {
				t.Fatalf("at-deadline generation remains pending: pending=%+v err=%v", pending, err)
			}
			pointer, exists, err := state.ReadEnforcementPointer(store.Dir)
			if err != nil || !exists || !prior.Equal(pointer) {
				t.Fatalf("at-deadline recovery changed predecessor pointer: pointer=%+v exists=%t err=%v", pointer, exists, err)
			}
		})
	}
}

type secondSampleDriftRunner struct {
	tableReads       int
	driftServed      bool
	mutationAttempts int
}

func (r *secondSampleDriftRunner) Run(_ context.Context, args ...string) (string, string, error) {
	if len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "ruleset" {
		return `{"nftables":[{"metainfo":{"json_schema_version":1}}]}`, "", nil
	}
	if len(args) >= 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		return `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}},{"table":{"family":"ip","name":"nftfw_nat"}},{"table":{"family":"ip6","name":"nftfw_filter6"}}]}`, "", nil
	}
	if len(args) == 5 && args[0] == "-j" && args[1] == "list" && args[2] == "table" {
		r.tableReads++
		result := recoveryOwnedTableJSON(args[3], args[4])
		if r.tableReads >= 10 && args[3] == "inet" && args[4] == "nftfw_filter" {
			r.driftServed = true
			result = strings.TrimSuffix(result, "]}") + fmt.Sprintf(`,{"rule":{"family":%q,"table":%q,"chain":"input","comment":"nftfw:second-sample-drift"}}]}`, args[3], args[4])
		}
		return result, "", nil
	}
	if len(args) > 0 && (args[0] == "--file" || args[0] == "--check") {
		r.mutationAttempts++
		return "", "unexpected verifier mutation", errors.New("unexpected verifier mutation")
	}
	return "", "unexpected verifier command", fmt.Errorf("unexpected verifier command: %v", args)
}

func TestVerifyEnforcementRejectsSecondSampleFingerprintDrift(t *testing.T) {
	ctx := context.Background()
	manager, store, _ := newManager(t)
	if _, err := manager.Apply(ctx, artifact(1), false); err != nil {
		store.Close()
		t.Fatal(err)
	}
	databasePath := store.Path
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	readOnly, err := state.OpenReadOnly(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	fake := &secondSampleDriftRunner{}

	err = VerifyEnforcement(ctx, readOnly, nft.New(fake))
	if err == nil || !strings.Contains(err.Error(), "live nftables fingerprint changed during verification") {
		t.Fatalf("second-sample fingerprint drift was not rejected: %v", err)
	}
	if !fake.driftServed || fake.tableReads != 12 {
		t.Fatalf("test did not reach the complete second fingerprint sample: drift=%t table_reads=%d", fake.driftServed, fake.tableReads)
	}
	if fake.mutationAttempts != 0 {
		t.Fatalf("verifier attempted an nft mutation: %d", fake.mutationAttempts)
	}
}

func TestRecoverCommittedPointerDurablyAuditsBeforeReady(t *testing.T) {
	ctx := context.Background()
	manager, store, _ := newManager(t)
	defer store.Close()
	if _, err := manager.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	result, err := manager.RecoverAtBoot(ctx)
	if err != nil || !result.Ready || result.Action != "restored_committed" {
		t.Fatalf("committed recovery did not become ready: result=%+v err=%v", result, err)
	}

	mainImage, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	crashRoot := secureTestDir(t)
	crashDatabaseDirectory := filepath.Join(crashRoot, "generation-state")
	if err := os.Mkdir(crashDatabaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	crashDatabasePath := filepath.Join(crashDatabaseDirectory, "state.db")
	if err := os.WriteFile(crashDatabasePath, mainImage, 0o600); err != nil {
		t.Fatal(err)
	}
	crashStore, err := state.OpenReadOnly(ctx, crashDatabasePath)
	if err != nil {
		t.Fatalf("open post-crash main database image: %v", err)
	}
	defer crashStore.Close()
	var count int
	if err := crashStore.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit WHERE event=? AND detail=?", "generation_boot_restored", "generation=1").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("Ready=true audit was not durable in the standalone main image: count=%d", count)
	}
}

func TestRecoveryAndReadinessRejectForeignMarkCollisionWithoutMutation(t *testing.T) {
	ctx := context.Background()
	manager, store, fake := newManager(t)
	if _, err := manager.Apply(ctx, artifact(1), false); err != nil {
		store.Close()
		t.Fatal(err)
	}
	baselineApplies := fake.applyCalls
	manager.ForeignMarkGuard = func(guardCtx context.Context) error {
		_, err := manager.Backend.AuditForeignProvenanceMask(guardCtx)
		return err
	}
	fake.foreignMarkCollision = true
	result, err := manager.RecoverAtBoot(ctx)
	if err == nil || !strings.Contains(err.Error(), "reserved conntrack-mark") || result.Ready {
		store.Close()
		t.Fatalf("no-op committed recovery accepted foreign mark collision: result=%+v err=%v", result, err)
	}
	if fake.applyCalls != baselineApplies {
		store.Close()
		t.Fatalf("collision recovery mutated nftables: got=%d want=%d", fake.applyCalls, baselineApplies)
	}
	if _, err := manager.RollbackExpired(ctx); err == nil || !strings.Contains(err.Error(), "reserved conntrack-mark") {
		store.Close()
		t.Fatalf("no-op rollback decision accepted foreign mark collision: %v", err)
	}
	if fake.applyCalls != baselineApplies {
		store.Close()
		t.Fatalf("collision rollback decision mutated nftables: got=%d want=%d", fake.applyCalls, baselineApplies)
	}
	databasePath := store.Path
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	readOnly, err := state.OpenReadOnly(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	if err := VerifyEnforcement(ctx, readOnly, nft.New(fake)); err == nil || !strings.Contains(err.Error(), "reserved conntrack-mark") {
		t.Fatalf("readiness verifier accepted foreign mark collision: %v", err)
	}
	if fake.applyCalls != baselineApplies {
		t.Fatalf("collision verifier mutated nftables: got=%d want=%d", fake.applyCalls, baselineApplies)
	}
}

type evidenceMutationRunner struct {
	tableReads       int
	mutateAt         int
	mutate           func() error
	mutationErr      error
	mutationAttempts int
}

func (r *evidenceMutationRunner) Run(_ context.Context, args ...string) (string, string, error) {
	if len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "ruleset" {
		return `{"nftables":[{"metainfo":{"json_schema_version":1}}]}`, "", nil
	}
	if len(args) >= 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		return `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}},{"table":{"family":"ip","name":"nftfw_nat"}},{"table":{"family":"ip6","name":"nftfw_filter6"}}]}`, "", nil
	}
	if len(args) == 5 && args[0] == "-j" && args[1] == "list" && args[2] == "table" {
		r.tableReads++
		if r.tableReads == r.mutateAt && r.mutate != nil {
			r.mutationErr = r.mutate()
			if r.mutationErr != nil {
				return "", "evidence mutation fixture failed", r.mutationErr
			}
		}
		return recoveryOwnedTableJSON(args[3], args[4]), "", nil
	}
	if len(args) > 0 && (args[0] == "--file" || args[0] == "--check") {
		r.mutationAttempts++
		return "", "unexpected verifier mutation", errors.New("unexpected verifier mutation")
	}
	return "", "unexpected verifier command", fmt.Errorf("unexpected verifier command: %v", args)
}

func TestVerifyEnforcementRevalidatesAllDurableEvidenceAroundLiveSamples(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name      string
		kind      string
		mutateAt  int
		wantError string
	}{
		{name: "database main file between samples", kind: "database", mutateAt: 6, wantError: "state database main file changed during verification"},
		{name: "snapshot bytes between samples", kind: "snapshot", mutateAt: 6, wantError: "immutable generation snapshot changed during verification"},
		{name: "script between samples", kind: "script", mutateAt: 6, wantError: "generation script"},
		{name: "provenance ledger between samples", kind: "ledger", mutateAt: 6, wantError: "provenance ledger changed during verification"},
		{name: "pointer bytes between samples", kind: "pointer", mutateAt: 6, wantError: "enforcement pointer changed during verification"},
		{name: "pointer bytes after second sample", kind: "pointer", mutateAt: 12, wantError: "enforcement pointer changed during verification"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, store, _ := newManager(t)
			if _, err := manager.Apply(ctx, artifact(1), false); err != nil {
				store.Close()
				t.Fatal(err)
			}
			generation, err := store.Generation(ctx, 1)
			if err != nil {
				store.Close()
				t.Fatal(err)
			}
			databasePath := store.Path
			root := store.Dir
			pointerPath := filepath.Join(root, "enforcement-enabled")
			ledgerPath := filepath.Join(root, "provenance-ledger.db")
			if test.kind == "ledger" {
				ledger, err := provenance.Open(ctx, ledgerPath)
				if err != nil {
					store.Close()
					t.Fatal(err)
				}
				if err := ledger.Reserve(ctx, []provenance.Assignment{{Name: "eth0", ID: 1}}); err != nil {
					ledger.Close()
					store.Close()
					t.Fatal(err)
				}
				if err := ledger.Close(); err != nil {
					store.Close()
					t.Fatal(err)
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			mutate := func() error {
				switch test.kind {
				case "database":
					writable, err := state.OpenRecovery(ctx, databasePath)
					if err != nil {
						return err
					}
					if err := writable.AuditDurable(ctx, "test", "verifier_database_drift", "between-samples"); err != nil {
						writable.Close()
						return err
					}
					return writable.Close()
				case "snapshot":
					data, err := os.ReadFile(generation.SnapshotPath)
					if err != nil {
						return err
					}
					return os.WriteFile(generation.SnapshotPath, append(data, '\n'), 0o600)
				case "script":
					data, err := os.ReadFile(generation.ScriptPath)
					if err != nil {
						return err
					}
					return os.WriteFile(generation.ScriptPath, append(data, '\n'), 0o600)
				case "ledger":
					ledger, err := provenance.Open(ctx, ledgerPath)
					if err != nil {
						return err
					}
					if err := ledger.Reserve(ctx, []provenance.Assignment{{Name: "lan0", ID: 2}}); err != nil {
						ledger.Close()
						return err
					}
					return ledger.Close()
				case "pointer":
					data, err := os.ReadFile(pointerPath)
					if err != nil {
						return err
					}
					return os.WriteFile(pointerPath, append(data, ' '), 0o600)
				default:
					return fmt.Errorf("unknown evidence mutation %q", test.kind)
				}
			}

			readOnly, err := state.OpenReadOnly(ctx, databasePath)
			if err != nil {
				t.Fatal(err)
			}
			defer readOnly.Close()
			fake := &evidenceMutationRunner{mutateAt: test.mutateAt, mutate: mutate}
			err = VerifyEnforcement(ctx, readOnly, nft.New(fake))
			if fake.mutationErr != nil {
				t.Fatalf("evidence mutation fixture failed: %v", fake.mutationErr)
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("durable evidence drift was not rejected precisely: err=%v want_substring=%q", err, test.wantError)
			}
			if fake.tableReads != test.mutateAt {
				t.Fatalf("verifier continued live sampling after evidence drift: table_reads=%d want=%d", fake.tableReads, test.mutateAt)
			}
			if fake.mutationAttempts != 0 {
				t.Fatalf("verifier attempted nft mutation after evidence drift: %d", fake.mutationAttempts)
			}
		})
	}
}

func recoveryTreeDigest(t *testing.T, root string) string {
	t.Helper()
	hash := sha256.New()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(hash, "%s\x00%s\x00%#o\x00", relative, entry.Type(), info.Mode().Perm())
		if !entry.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, _ = hash.Write(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
