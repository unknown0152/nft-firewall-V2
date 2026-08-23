package reconcile

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/compiler"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

type runner struct {
	failApply            bool
	failApplyCount       int
	failCheck            bool
	tamper               bool
	applyCalls           int
	failApplyAt          int
	tableListCalls       int
	failTableListAt      int
	foreignCollision     bool
	markOwnedOnFailure   bool
	ownedListCalls       int
	collisionAtOwnedList int
	cancelOnApply        context.CancelFunc
}

type denyContextRunner struct {
	fileCalls int
	fileError error
}

func (r *denyContextRunner) Run(ctx context.Context, args ...string) (string, string, error) {
	if len(args) >= 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		return `{"nftables":[]}`, "", nil
	}
	if len(args) > 0 && args[0] == "--file" {
		r.fileCalls++
		r.fileError = ctx.Err()
	}
	return "", "", nil
}

func (r *runner) Run(_ context.Context, args ...string) (string, string, error) {
	if len(args) >= 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		r.ownedListCalls++
		if r.foreignCollision || r.collisionAtOwnedList > 0 && r.ownedListCalls >= r.collisionAtOwnedList {
			return `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`, "", nil
		}
		return `{"nftables":[]}`, "", nil
	}
	if len(args) == 5 && args[0] == "-j" && args[1] == "list" && args[2] == "table" {
		r.tableListCalls++
		if r.failTableListAt > 0 && r.tableListCalls == r.failTableListAt {
			return "", "synthetic fingerprint failure", sql.ErrConnDone
		}
		if r.tamper {
			return fmt.Sprintf(`{"nftables":[{"table":{"family":%q,"name":%q,"comment":"tampered"}}]}`, args[3], args[4]), "", nil
		}
		return fmt.Sprintf(`{"nftables":[{"table":{"family":%q,"name":%q}}]}`, args[3], args[4]), "", nil
	}
	if len(args) > 0 && args[0] == "--file" {
		r.applyCalls++
		fail := r.failApply || r.failApplyAt > 0 && r.applyCalls == r.failApplyAt || r.failApplyCount > 0
		if r.failApplyCount > 0 {
			r.failApplyCount--
		}
		if fail {
			if r.markOwnedOnFailure {
				r.foreignCollision = true
			}
			return "", "synthetic apply failure", sql.ErrConnDone
		}
		if r.cancelOnApply != nil {
			cancel := r.cancelOnApply
			r.cancelOnApply = nil
			cancel()
		}
	}
	if len(args) > 0 && args[0] == "--check" && r.failCheck {
		return "", "synthetic check failure", sql.ErrConnDone
	}
	return "", "", nil
}

func TestSuccessfulKernelApplyUsesDetachedRecoveryAfterCallerCancellation(t *testing.T) {
	m, store, runner := newManager(t)
	defer store.Close()
	if _, err := m.Apply(context.Background(), artifact(1), false); err != nil {
		t.Fatal(err)
	}
	baseline := runner.applyCalls
	ctx, cancel := context.WithCancel(context.Background())
	runner.cancelOnApply = cancel
	_, err := m.Apply(ctx, artifact(2), true)
	if err == nil || !strings.Contains(err.Error(), "mark generation applied") {
		t.Fatalf("caller cancellation after kernel apply was not reported: %v", err)
	}
	if runner.applyCalls != baseline+2 {
		t.Fatalf("detached recovery did not restore the previous generation: got %d apply calls, want %d", runner.applyCalls, baseline+2)
	}
	if pending, pendingErr := store.Pending(context.Background()); !errors.Is(pendingErr, sql.ErrNoRows) || pending != nil {
		t.Fatalf("detached recovery did not finalize the confirmed rollback: pending=%#v err=%v", pending, pendingErr)
	}
}

func TestEmergencyDenyGetsIndependentContextAfterRuntimeRestoreTimeout(t *testing.T) {
	store, err := state.Open(context.Background(), filepath.Join(secureTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runner := &denyContextRunner{}
	manager := &Manager{
		Backend: nft.New(runner),
		Store:   store,
		PostRestore: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err = manager.restoreRuntimeOrDeny(ctx)
	if err == nil || !strings.Contains(err.Error(), "emergency default-deny policy installed") {
		t.Fatalf("runtime timeout did not install emergency deny: %v", err)
	}
	if runner.fileCalls != 1 || runner.fileError != nil {
		t.Fatalf("emergency deny inherited expired context: calls=%d context_error=%v", runner.fileCalls, runner.fileError)
	}
}

func TestApplyExecutionFailureRequiresConfirmedRecovery(t *testing.T) {
	ctx := context.Background()

	t.Run("established generation is restored", func(t *testing.T) {
		m, store, runner := newManager(t)
		defer store.Close()
		if _, err := m.Apply(ctx, artifact(1), false); err != nil {
			t.Fatal(err)
		}
		baseline := runner.applyCalls
		runner.failApplyCount = 1
		runner.markOwnedOnFailure = true
		if _, err := m.Apply(ctx, artifact(2), true); err == nil || !strings.Contains(err.Error(), "apply candidate generation 2") {
			t.Fatalf("ambiguous execution failure was lost: %v", err)
		}
		if runner.applyCalls != baseline+2 {
			t.Fatalf("candidate and restore were not both attempted: got %d want %d", runner.applyCalls, baseline+2)
		}
		if pending, err := store.Pending(ctx); !errors.Is(err, sql.ErrNoRows) || pending != nil {
			t.Fatalf("confirmed restore was not finalized: pending=%#v err=%v", pending, err)
		}
	})

	t.Run("failed restoration retains pending generation", func(t *testing.T) {
		m, store, runner := newManager(t)
		defer store.Close()
		if _, err := m.Apply(ctx, artifact(1), false); err != nil {
			t.Fatal(err)
		}
		runner.failApplyCount = 2
		runner.markOwnedOnFailure = true
		_, err := m.Apply(ctx, artifact(2), true)
		if err == nil || !strings.Contains(err.Error(), "restore previous generation") {
			t.Fatalf("restore failure was not reported: %v", err)
		}
		pending, pendingErr := store.Pending(ctx)
		if pendingErr != nil || pending.ID != 2 || pending.Status != "pending" {
			t.Fatalf("uncertain candidate was not retained: pending=%#v err=%v", pending, pendingErr)
		}
	})

	t.Run("first execution failure with tables remains pending", func(t *testing.T) {
		m, store, runner := newManager(t)
		defer store.Close()
		runner.failApplyCount = 1
		runner.markOwnedOnFailure = true
		_, err := m.Apply(ctx, artifact(1), false)
		if err == nil || !strings.Contains(err.Error(), "refusing automatic deletion") {
			t.Fatalf("ambiguous first execution was not preserved: %v", err)
		}
		pending, pendingErr := store.Pending(ctx)
		if pendingErr != nil || pending.ID != 1 || pending.Status != "pending" {
			t.Fatalf("ambiguous first candidate was not retained: pending=%#v err=%v", pending, pendingErr)
		}
	})

	t.Run("first execution failure with no tables is finalized", func(t *testing.T) {
		m, store, runner := newManager(t)
		defer store.Close()
		runner.failApplyCount = 1
		if _, err := m.Apply(ctx, artifact(1), false); err == nil || !strings.Contains(err.Error(), "apply candidate generation 1") {
			t.Fatalf("execution failure was not reported: %v", err)
		}
		if runner.applyCalls != 1 {
			t.Fatalf("unexpected mutation attempts: %d", runner.applyCalls)
		}
		if pending, err := store.Pending(ctx); !errors.Is(err, sql.ErrNoRows) || pending != nil {
			t.Fatalf("confirmed-empty failure was not finalized: pending=%#v err=%v", pending, err)
		}
	})

	t.Run("preflight collision does not trigger recovery mutation", func(t *testing.T) {
		m, store, runner := newManager(t)
		defer store.Close()
		runner.collisionAtOwnedList = 2
		_, err := m.Apply(ctx, artifact(1), false)
		if err == nil || !strings.Contains(err.Error(), "first-use") {
			t.Fatalf("preflight collision was not reported: %v", err)
		}
		if runner.applyCalls != 0 {
			t.Fatalf("preflight rejection mutated nftables: %d calls", runner.applyCalls)
		}
		if pending, err := store.Pending(ctx); !errors.Is(err, sql.ErrNoRows) || pending != nil {
			t.Fatalf("non-mutating rejection left pending state: pending=%#v err=%v", pending, err)
		}
	})
}

func TestPostApplyStateFailuresOnlyFinalizeConfirmedRollback(t *testing.T) {
	ctx := context.Background()
	t.Run("mark applied restore succeeds", func(t *testing.T) {
		m, store, _ := newManager(t)
		defer store.Close()
		if _, err := m.Apply(ctx, artifact(1), false); err != nil {
			t.Fatal(err)
		}
		if _, err := store.DB.ExecContext(ctx, `CREATE TRIGGER fail_mark_applied BEFORE UPDATE OF status ON generations WHEN NEW.id=2 AND NEW.status='applied' BEGIN SELECT RAISE(FAIL, 'mark applied blocked'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Apply(ctx, artifact(2), true); err == nil || !strings.Contains(err.Error(), "mark generation applied") {
			t.Fatalf("mark-applied failure was lost: %v", err)
		}
		if pending, err := store.Pending(ctx); !errors.Is(err, sql.ErrNoRows) || pending != nil {
			t.Fatalf("confirmed rollback was not finalized: pending=%#v err=%v", pending, err)
		}
	})

	t.Run("mark applied restore fails", func(t *testing.T) {
		m, store, runner := newManager(t)
		defer store.Close()
		if _, err := m.Apply(ctx, artifact(1), false); err != nil {
			t.Fatal(err)
		}
		if _, err := store.DB.ExecContext(ctx, `CREATE TRIGGER fail_mark_applied BEFORE UPDATE OF status ON generations WHEN NEW.id=2 AND NEW.status='applied' BEGIN SELECT RAISE(FAIL, 'mark applied blocked'); END`); err != nil {
			t.Fatal(err)
		}
		runner.failApplyAt = runner.applyCalls + 2 // candidate apply, then failed restore
		_, err := m.Apply(ctx, artifact(2), true)
		if err == nil || !strings.Contains(err.Error(), "mark generation applied") || !strings.Contains(err.Error(), "restore previous generation") || !strings.Contains(err.Error(), "synthetic apply failure") {
			t.Fatalf("joined post-apply/restore error incomplete: %v", err)
		}
		pending, pendingErr := store.Pending(ctx)
		if pendingErr != nil || pending.ID != 2 || pending.Status != "pending" {
			t.Fatalf("failed restore did not retain recoverable pending state: %#v %v", pending, pendingErr)
		}
	})

	t.Run("confirmed restore rollback record fails", func(t *testing.T) {
		m, store, runner := newManager(t)
		defer store.Close()
		if _, err := m.Apply(ctx, artifact(1), false); err != nil {
			t.Fatal(err)
		}
		if _, err := store.DB.ExecContext(ctx, `
CREATE TRIGGER fail_mark_applied BEFORE UPDATE OF status ON generations WHEN NEW.id=2 AND NEW.status='applied' BEGIN SELECT RAISE(FAIL, 'mark applied blocked'); END;
CREATE TRIGGER fail_mark_rolled_back BEFORE UPDATE OF status ON generations WHEN NEW.id=2 AND NEW.status='rolled_back' BEGIN SELECT RAISE(FAIL, 'mark rollback blocked'); END;`); err != nil {
			t.Fatal(err)
		}
		_, err := m.Apply(ctx, artifact(2), true)
		if err == nil || !strings.Contains(err.Error(), "mark generation applied") || !strings.Contains(err.Error(), "record confirmed rollback") || !strings.Contains(err.Error(), "mark rollback blocked") {
			t.Fatalf("joined post-apply/rollback-record error incomplete: %v", err)
		}
		if runner.applyCalls != 3 {
			t.Fatalf("rollback record was attempted without a confirmed restore: apply calls=%d", runner.applyCalls)
		}
		pending, pendingErr := store.Pending(ctx)
		if pendingErr != nil || pending.ID != 2 || pending.Status != "pending" {
			t.Fatalf("failed rollback record did not retain recoverable state: %#v %v", pending, pendingErr)
		}
	})

	t.Run("fingerprint restore fails", func(t *testing.T) {
		m, store, runner := newManager(t)
		defer store.Close()
		if _, err := m.Apply(ctx, artifact(1), false); err != nil {
			t.Fatal(err)
		}
		runner.failTableListAt = runner.tableListCalls + 1
		runner.failApplyAt = runner.applyCalls + 2 // candidate apply, then failed restore
		_, err := m.Apply(ctx, artifact(2), true)
		if err == nil || !strings.Contains(err.Error(), "record applied nftables fingerprint") || !strings.Contains(err.Error(), "restore previous generation") || !strings.Contains(err.Error(), "synthetic apply failure") {
			t.Fatalf("joined fingerprint/restore error incomplete: %v", err)
		}
		pending, pendingErr := store.Pending(ctx)
		if pendingErr != nil || pending.ID != 2 || pending.Status != "applied" {
			t.Fatalf("failed restore did not retain applied candidate for recovery: %#v %v", pending, pendingErr)
		}
	})
}
func artifact(id uint64) compiler.Artifact {
	script := "table inet nftfw_filter { }\ntable ip nftfw_nat { }\ntable ip6 nftfw_filter6 { }\n"
	sum := sha256.Sum256([]byte(script))
	return compiler.Artifact{Generation: id, Checksum: hex.EncodeToString(sum[:]), Script: script}
}
func newManager(t *testing.T) (*Manager, *state.Store, *runner) {
	t.Helper()
	s, err := state.Open(context.Background(), filepath.Join(secureTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{}
	return &Manager{Backend: nft.New(r), Store: s, SafeTTL: time.Millisecond, SafeGuard: func(context.Context) error { return nil }}, s, r
}
func TestSafeApplyCommitAndTimeoutRollback(t *testing.T) {
	ctx := context.Background()
	m, s, _ := newManager(t)
	defer s.Close()
	restores := 0
	m.PostRestore = func(context.Context) error { restores++; return nil }
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	res, err := m.Apply(ctx, artifact(2), true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Deadline == nil || res.Committed {
		t.Fatalf("bad safe result: %#v", res)
	}
	time.Sleep(3 * time.Millisecond)
	ok, err := m.RollbackExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expired candidate not rolled back")
	}
	if restores != 1 {
		t.Fatalf("rollback restored generation without runtime state: calls=%d", restores)
	}
	g, err := s.LastKnownGood(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if g.ID != 1 {
		t.Fatalf("last known good changed: %d", g.ID)
	}
}

func TestReconcileRestoresRuntimeStateAndFailsClosedOnError(t *testing.T) {
	ctx := context.Background()
	m, store, _ := newManager(t)
	defer store.Close()
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	restores := 0
	m.PostRestore = func(context.Context) error { restores++; return nil }
	drift, err := m.Reconcile(ctx, true)
	if err != nil || !drift.Repaired || restores != 1 {
		t.Fatalf("reconcile did not restore runtime state: drift=%#v calls=%d err=%v", drift, restores, err)
	}
	m.PostRestore = func(context.Context) error { return errors.New("synthetic runtime failure") }
	if _, err := m.Reconcile(ctx, true); err == nil || !strings.Contains(err.Error(), "emergency default-deny") {
		t.Fatalf("runtime restore failure did not fail closed: %v", err)
	}
}
func TestSafeApplyCommit(t *testing.T) {
	ctx := context.Background()
	m, s, _ := newManager(t)
	defer s.Close()
	m.SafeTTL = time.Minute
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(ctx, artifact(2), true); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(ctx, 2); err != nil {
		t.Fatal(err)
	}
	g, err := s.LastKnownGood(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if g.ID != 2 {
		t.Fatalf("committed generation %d", g.ID)
	}
}

func TestCommittedSnapshotTracksCommitAndRollback(t *testing.T) {
	ctx := context.Background()
	m, store, _ := newManager(t)
	defer store.Close()
	m.SafeTTL = time.Minute
	first := artifact(1)
	second := artifact(2)
	if _, err := m.Apply(ctx, first, false); err != nil {
		t.Fatal(err)
	}
	assertActiveScript(t, store.Dir, first.Script)
	if _, err := m.Apply(ctx, second, true); err != nil {
		t.Fatal(err)
	}
	assertActiveScript(t, store.Dir, first.Script)
	if err := m.Commit(ctx, second.Generation); err != nil {
		t.Fatal(err)
	}
	assertActiveScript(t, store.Dir, second.Script)
	if err := m.Rollback(ctx, second.Generation); err != nil {
		t.Fatal(err)
	}
	assertActiveScript(t, store.Dir, first.Script)
}

func TestFirstGenerationRollbackClearsBootEnforcement(t *testing.T) {
	ctx := context.Background()
	m, store, _ := newManager(t)
	defer store.Close()
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	if err := m.Rollback(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, enabled, err := state.LoadActiveSnapshot(store.Dir); err != nil || enabled {
		t.Fatalf("boot enforcement remains after first-generation rollback: enabled=%t err=%v", enabled, err)
	}
}

func TestFirstUseProtectionRearmsAfterFirstGenerationRollback(t *testing.T) {
	ctx := context.Background()
	m, store, runner := newManager(t)
	defer store.Close()
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	if err := m.Rollback(ctx, 1); err != nil {
		t.Fatal(err)
	}
	runner.foreignCollision = true
	if _, err := m.Apply(ctx, artifact(2), false); err == nil || !strings.Contains(err.Error(), "first-use nft table collision") {
		t.Fatalf("second ownership attempt accepted a foreign product-named table: %v", err)
	}
	if next, err := store.NextGeneration(ctx); err != nil || next != 2 {
		t.Fatalf("collision was persisted as a candidate: next=%d err=%v", next, err)
	}
}

func TestFirstPendingRecoveryPreservesUnverifiedProductNamedTable(t *testing.T) {
	ctx := context.Background()
	m, store, runner := newManager(t)
	defer store.Close()
	candidate := artifact(1)
	if err := store.SaveGeneration(ctx, candidate.Generation, candidate.Checksum, candidate.Script, nil, nil); err != nil {
		t.Fatal(err)
	}
	runner.foreignCollision = true
	if _, err := m.Reconcile(ctx, true); err == nil || !strings.Contains(err.Error(), "refusing automatic deletion") {
		t.Fatalf("ambiguous first-generation collision was not preserved: %v", err)
	}
	if runner.applyCalls != 0 {
		t.Fatalf("ambiguous table reached an nft mutation: apply calls=%d", runner.applyCalls)
	}
	pending, err := store.Pending(ctx)
	if err != nil || pending.ID != candidate.Generation || pending.Status != "pending" {
		t.Fatalf("ambiguous pending state was not retained for operator recovery: %#v %v", pending, err)
	}
}

func TestFirstPendingRecoveryWithNoTablesFinalizesWithoutMutation(t *testing.T) {
	ctx := context.Background()
	m, store, runner := newManager(t)
	defer store.Close()
	candidate := artifact(1)
	if err := store.SaveGeneration(ctx, candidate.Generation, candidate.Checksum, candidate.Script, nil, nil); err != nil {
		t.Fatal(err)
	}
	drift, err := m.Reconcile(ctx, true)
	if err != nil || !drift.Repaired {
		t.Fatalf("empty first-generation pending state was not finalized: %#v %v", drift, err)
	}
	if runner.applyCalls != 0 {
		t.Fatalf("empty first-generation recovery mutated nftables: apply calls=%d", runner.applyCalls)
	}
	if pending, err := store.Pending(ctx); !errors.Is(err, sql.ErrNoRows) || pending != nil {
		t.Fatalf("empty first-generation pending state remains: %#v %v", pending, err)
	}
	if _, enabled, err := state.LoadActiveSnapshot(store.Dir); err != nil || enabled {
		t.Fatalf("empty first-generation recovery published a boot policy: enabled=%t err=%v", enabled, err)
	}
}

func TestReconcileRollsBackDriftedPendingCandidate(t *testing.T) {
	ctx := context.Background()
	m, store, runner := newManager(t)
	defer store.Close()
	m.SafeTTL = time.Minute
	first := artifact(1)
	if _, err := m.Apply(ctx, first, false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(ctx, artifact(2), true); err != nil {
		t.Fatal(err)
	}
	runner.tamper = true
	drift, err := m.Reconcile(ctx, true)
	if err != nil || !drift.Repaired || !strings.Contains(drift.Detail, "rolled back") {
		t.Fatalf("drifted candidate was not rolled back: %#v %v", drift, err)
	}
	active, err := store.LastKnownGood(ctx)
	if err != nil || active.ID != 1 {
		t.Fatalf("known-good generation changed: %#v %v", active, err)
	}
	assertActiveScript(t, store.Dir, first.Script)
}

func assertActiveScript(t *testing.T, directory, want string) {
	t.Helper()
	got, enabled, err := state.LoadActiveSnapshot(directory)
	if err != nil || !enabled || got != want {
		t.Fatalf("active snapshot mismatch: enabled=%t got=%q want=%q err=%v", enabled, got, want, err)
	}
}

func TestCommitRejectsExpiredOrTamperedCandidate(t *testing.T) {
	ctx := context.Background()
	m, store, runner := newManager(t)
	defer store.Close()
	now := time.Now().UTC()
	m.Now = func() time.Time { return now }
	m.SafeTTL = time.Second
	if _, err := m.Apply(ctx, artifact(1), true); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if err := m.Commit(ctx, 1); err == nil {
		t.Fatal("expired candidate was committed")
	}
	if pending, err := store.Pending(ctx); !errors.Is(err, sql.ErrNoRows) || pending != nil {
		t.Fatalf("expired candidate remained pending: %#v %v", pending, err)
	}

	now = now.Add(time.Second)
	if _, err := m.Apply(ctx, artifact(2), true); err != nil {
		t.Fatal(err)
	}
	runner.tamper = true
	if err := m.Commit(ctx, 2); err == nil {
		t.Fatal("tampered candidate was committed")
	}
	if pending, err := store.Pending(ctx); !errors.Is(err, sql.ErrNoRows) || pending != nil {
		t.Fatalf("tampered candidate remained pending: %#v %v", pending, err)
	}
}
func TestApplyFailureRetainsCommitted(t *testing.T) {
	ctx := context.Background()
	m, s, r := newManager(t)
	defer s.Close()
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	r.failApply = true
	if _, err := m.Apply(ctx, artifact(2), true); err == nil {
		t.Fatal("apply failure accepted")
	}
	g, err := s.LastKnownGood(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if g.ID != 1 {
		t.Fatalf("committed generation changed: %d", g.ID)
	}
}

func TestRollbackRejectsHistoricalCommittedGeneration(t *testing.T) {
	ctx := context.Background()
	m, store, _ := newManager(t)
	defer store.Close()
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(ctx, artifact(2), false); err != nil {
		t.Fatal(err)
	}
	if err := m.Rollback(ctx, 1); err == nil {
		t.Fatal("historical generation rollback was accepted")
	}
	active, err := store.LastKnownGood(ctx)
	if err != nil || active.ID != 2 {
		t.Fatalf("active generation changed: %#v %v", active, err)
	}
}

func TestHealthFailureRollsBackCandidate(t *testing.T) {
	ctx := context.Background()
	m, s, _ := newManager(t)
	defer s.Close()
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	m.HealthCheck = func(context.Context) error { return context.Canceled }
	if _, err := m.Apply(ctx, artifact(2), true); err == nil {
		t.Fatal("unhealthy candidate accepted")
	}
	g, err := s.LastKnownGood(ctx)
	if err != nil || g.ID != 1 {
		t.Fatalf("known-good generation was not restored: %#v, %v", g, err)
	}
}

func TestPendingGenerationSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t)
	path := filepath.Join(dir, "state.db")
	s, err := state.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{}
	past := time.Now().Add(-time.Hour)
	m := &Manager{Backend: nft.New(r), Store: s, SafeTTL: time.Minute, Now: func() time.Time { return past }, SafeGuard: func(context.Context) error { return nil }}
	if _, err := m.Apply(ctx, artifact(1), true); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = state.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m = &Manager{Backend: nft.New(r), Store: s}
	ok, err := m.RollbackExpired(ctx)
	if err != nil || !ok {
		t.Fatalf("restarted controller did not roll back persistent pending generation: ok=%t err=%v", ok, err)
	}
	if err := m.Rollback(ctx, 1); err != nil {
		t.Fatalf("rollback was not idempotent: %v", err)
	}
}

func TestKernelCheckFailureRetainsCommitted(t *testing.T) {
	ctx := context.Background()
	m, s, r := newManager(t)
	defer s.Close()
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	r.failCheck = true
	if _, err := m.Apply(ctx, artifact(2), true); err == nil {
		t.Fatal("kernel check failure accepted")
	}
	g, err := s.LastKnownGood(ctx)
	if err != nil || g.ID != 1 {
		t.Fatalf("known-good generation changed after check failure: %#v, %v", g, err)
	}
}

func TestSafeApplyRequiresIndependentGuard(t *testing.T) {
	m, s, _ := newManager(t)
	defer s.Close()
	m.SafeGuard = nil
	if _, err := m.Apply(context.Background(), artifact(1), true); err == nil {
		t.Fatal("safe apply without independent rollback guard was accepted")
	}
	m.SafeGuard = func(context.Context) error { return context.Canceled }
	if _, err := m.Apply(context.Background(), artifact(1), true); err == nil {
		t.Fatal("safe apply with failed rollback guard was accepted")
	}
}

func TestPersistedButUnappliedGenerationRollsBackOnStartup(t *testing.T) {
	ctx := context.Background()
	m, store, _ := newManager(t)
	defer store.Close()
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	previous := uint64(1)
	if err := store.SaveGeneration(ctx, 2, artifact(2).Checksum, artifact(2).Script, &previous, &deadline); err != nil {
		t.Fatal(err)
	}
	drift, err := m.Reconcile(ctx, true)
	if err != nil || !drift.Repaired {
		t.Fatalf("incomplete candidate was not rolled back: %#v %v", drift, err)
	}
	pending, err := store.Pending(ctx)
	if !errors.Is(err, sql.ErrNoRows) || pending != nil {
		t.Fatalf("incomplete candidate remains pending: %#v %v", pending, err)
	}
}

func TestCommitRejectsPersistedButUnappliedGeneration(t *testing.T) {
	ctx := context.Background()
	m, store, _ := newManager(t)
	defer store.Close()
	if err := store.SaveGeneration(ctx, 1, artifact(1).Checksum, artifact(1).Script, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(ctx, 1); err == nil {
		t.Fatal("unapplied generation was committed")
	}
}
