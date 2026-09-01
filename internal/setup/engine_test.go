package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeExecutor struct {
	calls               []string
	events              *[]string
	failAt              string
	failCalls           map[string]bool
	prepareErr          error
	generationCommitted bool
	commitInspectErr    error
	rollbackJournals    []Journal
	recoveryJournals    []Journal
}

func (f *fakeExecutor) call(name string) error {
	f.calls = append(f.calls, name)
	if f.events != nil {
		*f.events = append(*f.events, name)
	}
	if f.failAt == name || f.failCalls[name] {
		return errors.New("SETUP_INJECTED_FAILURE")
	}
	return nil
}

func (f *fakeExecutor) Prepare(context.Context, string) (Plan, error) {
	err := f.call("prepare")
	if f.prepareErr != nil {
		err = f.prepareErr
	}
	return Plan{Summary: Summary{Schema: "nftfw.setup-plan.v1"}}, err
}
func (f *fakeExecutor) Backup(context.Context, Plan) (string, error) {
	return "/backup", f.call("backup")
}
func (f *fakeExecutor) StartGuard(context.Context, Plan) error { return f.call("guard") }
func (f *fakeExecutor) Install(context.Context, Plan) error    { return f.call("install") }
func (f *fakeExecutor) ConfigureDocker(context.Context, Plan) error {
	return f.call("docker")
}
func (f *fakeExecutor) StartRuntime(context.Context, Plan) error { return f.call("runtime") }
func (f *fakeExecutor) ApplySafe(context.Context, Plan) (uint64, error) {
	return 7, f.call("apply")
}
func (f *fakeExecutor) StartTunnel(context.Context, Plan) error      { return f.call("tunnel") }
func (f *fakeExecutor) Validate(context.Context, Plan, uint64) error { return f.call("validate") }
func (f *fakeExecutor) Commit(context.Context, Plan, uint64) error   { return f.call("commit") }
func (f *fakeExecutor) PublishFinalDependencies(context.Context, Plan) error {
	return f.call("handoff")
}
func (f *fakeExecutor) EnableBoot(context.Context, Plan) error { return f.call("boot") }
func (f *fakeExecutor) Finalize(context.Context, Plan) error   { return f.call("finalize") }

func (f *fakeExecutor) Rollback(_ context.Context, _ Plan, journal Journal) error {
	f.rollbackJournals = append(f.rollbackJournals, journal)
	return f.call("rollback")
}
func (f *fakeExecutor) RecoverCommitted(_ context.Context, _ Plan, journal Journal) error {
	f.recoveryJournals = append(f.recoveryJournals, journal)
	return f.call("recover-committed")
}
func (f *fakeExecutor) GenerationCommitted(context.Context, uint64) (bool, error) {
	f.calls = append(f.calls, "inspect-commit")
	return f.generationCommitted, f.commitInspectErr
}

type recordingJournal struct {
	store      FileJournal
	events     *[]string
	failWrites int
	writes     int
	last       Journal
}

func (r *recordingJournal) Write(journal Journal) error {
	return r.recordWrite(journal, func() error { return r.store.Write(journal) })
}

func (r *recordingJournal) Begin(journal Journal, prior string) error {
	return r.recordWrite(journal, func() error { return r.store.Begin(journal, prior) })
}

func (r *recordingJournal) recordWrite(journal Journal, write func() error) error {
	r.writes++
	r.last = journal
	if r.events != nil {
		*r.events = append(*r.events, "journal:"+string(journal.Phase))
	}
	if r.failWrites == r.writes {
		return errors.New("injected journal failure")
	}
	return write()
}

func (r *recordingJournal) Read() (Journal, error) {
	return r.store.Read()
}

func TestRunCompletesInExactOrder(t *testing.T) {
	events := []string{}
	executor := &fakeExecutor{events: &events}
	journal := &recordingJournal{
		store:  testFileJournal(t),
		events: &events,
	}
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	engine := Engine{
		Executor: executor, Journal: journal, Now: func() time.Time {
			now = now.Add(time.Second)
			return now
		},
		NewID: func() string { return "transaction-1" },
	}
	if _, err := engine.Run(context.Background(), "/vpn.conf"); err != nil {
		t.Fatal(err)
	}
	want := "prepare,backup,guard,install,docker,runtime,apply,tunnel,validate,commit,handoff,boot,finalize"
	if strings.Join(executor.calls, ",") != want {
		t.Fatalf("calls=%v want=%s", executor.calls, want)
	}
	if len(events) < 2 || events[0] != "prepare" || events[1] != "journal:inspect" {
		t.Fatalf("preparation did not precede initial journal publication: %v", events)
	}
	final, err := journal.Read()
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != "complete" || final.Phase != PhaseComplete || final.Generation != 7 ||
		final.BackupDir != "/backup" {
		t.Fatalf("unexpected final journal: %#v", final)
	}
}

func TestPreparationFailureDoesNotJournalOrRollback(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{name: "bounded", err: errors.New("DISCOVERY_COMPETING_FIREWALL"), want: "DISCOVERY_COMPETING_FIREWALL"},
		{name: "redacted", err: errors.New("provider secret was invalid"), want: "SETUP_FAILED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal.json")
			executor := &fakeExecutor{prepareErr: test.err}
			_, err := (Engine{
				Executor: executor, Journal: FileJournal{Path: path},
			}).Run(context.Background(), "/vpn.conf")
			if err == nil || err.Error() != test.want {
				t.Fatalf("unexpected preparation error: %v", err)
			}
			if strings.Join(executor.calls, ",") != "prepare" {
				t.Fatalf("preparation failure entered mutation or rollback: %v", executor.calls)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("preparation failure published a journal: %v", err)
			}
		})
	}
}

func TestInvalidPreparedPlanDoesNotJournalOrRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	executor := &fakeExecutor{}
	executor.prepareErr = nil
	// Override the fake's otherwise valid summary through a narrow adapter.
	invalid := invalidPlanExecutor{fakeExecutor: executor}
	_, err := (Engine{Executor: invalid, Journal: FileJournal{Path: path}}).
		Run(context.Background(), "/vpn.conf")
	if err == nil || err.Error() != "SETUP_PLAN_INVALID" {
		t.Fatalf("unexpected invalid-plan error: %v", err)
	}
	if strings.Join(executor.calls, ",") != "prepare" {
		t.Fatalf("invalid plan entered mutation or rollback: %v", executor.calls)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid plan published a journal: %v", err)
	}
}

type invalidPlanExecutor struct {
	*fakeExecutor
}

func (i invalidPlanExecutor) Prepare(ctx context.Context, path string) (Plan, error) {
	plan, err := i.fakeExecutor.Prepare(ctx, path)
	plan.Summary.Schema = "wrong"
	return plan, err
}

func TestInitialJournalFailureDoesNotMutateOrRollback(t *testing.T) {
	events := []string{}
	executor := &fakeExecutor{events: &events}
	journal := &recordingJournal{
		store:      testFileJournal(t),
		events:     &events,
		failWrites: 1,
	}
	_, err := (Engine{Executor: executor, Journal: journal}).
		Run(context.Background(), "/vpn.conf")
	if err == nil || err.Error() != "SETUP_JOURNAL_WRITE_FAILED" {
		t.Fatalf("unexpected initial journal error: %v", err)
	}
	if strings.Join(executor.calls, ",") != "prepare" {
		t.Fatalf("journal failure entered mutation or rollback: %v", executor.calls)
	}
	if strings.Join(events, ",") != "prepare,journal:inspect" {
		t.Fatalf("unexpected initial journal boundary: %v", events)
	}
	if journal.last.Summary.Schema != "nftfw.setup-plan.v1" {
		t.Fatalf("initial journal omitted the prepared summary: %#v", journal.last)
	}
}

func TestFailureAlwaysRollsBack(t *testing.T) {
	executor := &fakeExecutor{failAt: "tunnel"}
	journal := testFileJournal(t)
	engine := Engine{
		Executor: executor, Journal: journal,
		NewID: func() string { return "transaction-2" },
	}
	if _, err := engine.Run(context.Background(), "/vpn.conf"); err == nil ||
		err.Error() != "SETUP_INJECTED_FAILURE" {
		t.Fatalf("unexpected error: %v", err)
	}
	if executor.calls[len(executor.calls)-1] != "rollback" {
		t.Fatalf("rollback not last: %v", executor.calls)
	}
	final, err := journal.Read()
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != "rolled_back" || final.Phase != PhaseFailed ||
		final.ErrorCode != "SETUP_INJECTED_FAILURE" {
		t.Fatalf("unexpected failure journal: %#v", final)
	}
}

func TestBackupFailureStopsBeforeProtectedMutationWithoutRollback(t *testing.T) {
	executor := &fakeExecutor{failAt: "backup"}
	journal := testFileJournal(t)
	_, err := (Engine{
		Executor: executor, Journal: journal,
		NewID: func() string { return "backup-failure" },
	}).Run(context.Background(), "/vpn.conf")
	if err == nil || err.Error() != "SETUP_INJECTED_FAILURE" {
		t.Fatalf("unexpected backup failure: %v", err)
	}
	if strings.Join(executor.calls, ",") != "prepare,backup" {
		t.Fatalf("backup failure entered protected mutation or rollback: %v", executor.calls)
	}
	final, readErr := journal.Read()
	if readErr != nil || final.Status != "rolled_back" || final.Phase != PhaseFailed ||
		final.BackupDir != "" {
		t.Fatalf("unexpected pre-mutation journal: %#v %v", final, readErr)
	}
}

func TestExpiredJournalTriggersIndependentRollback(t *testing.T) {
	executor := &fakeExecutor{}
	store := testFileJournal(t)
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	if err := store.Write(Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "transaction-3",
		Phase: PhaseTunnel, Status: "running", StartedAt: now.Add(-time.Hour),
		UpdatedAt: now.Add(-time.Hour), Deadline: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	engine := Engine{Executor: executor, Journal: store, Now: func() time.Time { return now }}
	rolledBack, err := engine.RollbackExpired(context.Background(), Plan{})
	if !rolledBack || err == nil || err.Error() != "SETUP_DEADLINE_EXPIRED" {
		t.Fatalf("unexpected expiry result: rolledBack=%t err=%v", rolledBack, err)
	}
	if executor.calls[len(executor.calls)-1] != "rollback" {
		t.Fatalf("expired setup did not roll back: %v", executor.calls)
	}
}

func TestExpiredPreMutationJournalDoesNotInvokeRollback(t *testing.T) {
	executor := &fakeExecutor{}
	store := testFileJournal(t)
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	if err := store.Write(Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "pre-mutation",
		Phase: PhaseInspect, Status: "running", StartedAt: now.Add(-time.Hour),
		UpdatedAt: now.Add(-time.Hour), Deadline: now.Add(-time.Minute),
		Summary: Summary{Schema: "nftfw.setup-plan.v1"},
	}); err != nil {
		t.Fatal(err)
	}
	engine := Engine{Executor: executor, Journal: store, Now: func() time.Time { return now }}
	terminalized, err := engine.RollbackExpired(context.Background(), Plan{})
	if !terminalized || err == nil || err.Error() != "SETUP_DEADLINE_EXPIRED" {
		t.Fatalf("unexpected pre-mutation expiry result: terminalized=%t err=%v", terminalized, err)
	}
	if len(executor.calls) != 0 {
		t.Fatalf("pre-mutation expiry invoked executor rollback: %v", executor.calls)
	}
	final, readErr := store.Read()
	if readErr != nil || final.Status != "rolled_back" || final.Phase != PhaseFailed {
		t.Fatalf("pre-mutation expiry not terminal: %#v %v", final, readErr)
	}
}

func TestPostCommitFailureRecoversForward(t *testing.T) {
	executor := &fakeExecutor{failAt: "boot"}
	journal := testFileJournal(t)
	engine := Engine{
		Executor: executor, Journal: journal,
		NewID: func() string { return "transaction-4" },
	}
	if _, err := engine.Run(context.Background(), "/vpn.conf"); err == nil ||
		err.Error() != "SETUP_COMMITTED_RECOVERED" {
		t.Fatalf("unexpected error: %v", err)
	}
	if executor.calls[len(executor.calls)-1] != "recover-committed" ||
		strings.Contains(strings.Join(executor.calls, ","), "rollback") {
		t.Fatalf("committed setup used destructive rollback: %v", executor.calls)
	}
	final, err := journal.Read()
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != "complete" || !final.Committed {
		t.Fatalf("committed recovery did not finalize: %#v", final)
	}
}

func TestFinalDependencyPublicationFailureRecoversForward(t *testing.T) {
	executor := &fakeExecutor{failAt: "handoff"}
	journal := testFileJournal(t)
	_, err := (Engine{
		Executor: executor, Journal: journal,
		NewID: func() string { return "handoff-recovery" },
	}).Run(context.Background(), "/vpn.conf")
	if err == nil || err.Error() != "SETUP_COMMITTED_RECOVERED" {
		t.Fatalf("unexpected handoff recovery result: %v", err)
	}
	want := "prepare,backup,guard,install,docker,runtime,apply,tunnel,validate,commit,handoff,recover-committed"
	if strings.Join(executor.calls, ",") != want {
		t.Fatalf("handoff failure crossed an unsafe recovery boundary: %v", executor.calls)
	}
	final, readErr := journal.Read()
	if readErr != nil || final.Status != "complete" || !final.Committed {
		t.Fatalf("handoff recovery journal invalid: %#v %v", final, readErr)
	}
}

func TestExpiredJournalRecoversForwardAcrossCommitJournalGap(t *testing.T) {
	executor := &fakeExecutor{generationCommitted: true}
	store := testFileJournal(t)
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	if err := store.Write(Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "transaction-5",
		Phase: PhaseCommit, Status: "running", StartedAt: now.Add(-time.Hour),
		UpdatedAt: now.Add(-time.Hour), Deadline: now.Add(-time.Minute),
		Generation: 7,
	}); err != nil {
		t.Fatal(err)
	}
	engine := Engine{Executor: executor, Journal: store, Now: func() time.Time { return now }}
	rolledBack, err := engine.RollbackExpired(context.Background(), Plan{})
	if !rolledBack || err == nil || err.Error() != "SETUP_COMMITTED_RECOVERED" {
		t.Fatalf("unexpected recovery result: attempted=%t err=%v", rolledBack, err)
	}
	if strings.Join(executor.calls, ",") != "inspect-commit,recover-committed" {
		t.Fatalf("commit journal gap used destructive rollback: %v", executor.calls)
	}
	final, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != "complete" || !final.Committed {
		t.Fatalf("commit journal gap did not recover forward: %#v", final)
	}
}

func TestUnknownCommitStateFailsWithoutDestructiveRollback(t *testing.T) {
	executor := &fakeExecutor{commitInspectErr: errors.New("unavailable")}
	store := testFileJournal(t)
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	if err := store.Write(Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "transaction-6",
		Phase: PhaseCommit, Status: "running", StartedAt: now.Add(-time.Hour),
		UpdatedAt: now.Add(-time.Hour), Deadline: now.Add(-time.Minute),
		Generation: 7,
	}); err != nil {
		t.Fatal(err)
	}
	engine := Engine{Executor: executor, Journal: store, Now: func() time.Time { return now }}
	_, err := engine.RollbackExpired(context.Background(), Plan{})
	if err == nil || err.Error() != "SETUP_COMMIT_STATE_UNKNOWN" {
		t.Fatalf("unknown commit state did not fail closed: %v", err)
	}
	if strings.Contains(strings.Join(executor.calls, ","), "rollback") {
		t.Fatalf("unknown commit state triggered destructive rollback: %v", executor.calls)
	}
}

func TestDryRunAndEngineInputValidation(t *testing.T) {
	executor := &fakeExecutor{}
	engine := Engine{Executor: executor}
	if _, err := engine.DryRun(context.Background(), "/vpn.conf"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(executor.calls, ",") != "prepare" {
		t.Fatalf("dry run called unexpected phases: %v", executor.calls)
	}
	if _, err := (Engine{}).DryRun(context.Background(), "/vpn.conf"); err == nil {
		t.Fatal("dry run without executor accepted")
	}
	if _, err := (Engine{Executor: executor}).Run(context.Background(), "/vpn.conf"); err == nil {
		t.Fatal("run without journal accepted")
	}
	if _, err := (Engine{Journal: testFileJournal(t)}).
		Run(context.Background(), "/vpn.conf"); err == nil {
		t.Fatal("run without executor accepted")
	}
}

func TestEveryMutationPhaseFailureRollsBack(t *testing.T) {
	for _, test := range []struct {
		name  string
		phase Phase
	}{
		{name: "guard", phase: PhaseGuard},
		{name: "install", phase: PhaseInstall},
		{name: "docker", phase: PhaseDocker},
		{name: "runtime", phase: PhaseRuntime},
		{name: "apply", phase: PhaseApply},
		{name: "tunnel", phase: PhaseTunnel},
		{name: "validate", phase: PhaseValidate},
		{name: "commit", phase: PhaseCommit},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor := &fakeExecutor{failAt: test.name}
			store := testFileJournal(t)
			engine := Engine{Executor: executor, Journal: store, NewID: func() string { return test.name }}
			if _, err := engine.Run(context.Background(), "/vpn.conf"); err == nil {
				t.Fatal("injected phase failure was ignored")
			}
			if executor.calls[len(executor.calls)-1] != "rollback" {
				t.Fatalf("phase %s did not roll back: %v", test.name, executor.calls)
			}
			if len(executor.rollbackJournals) != 1 || executor.rollbackJournals[0].Phase != test.phase ||
				executor.rollbackJournals[0].Status != "rolling_back" {
				t.Fatalf("phase %s origin was not preserved: %#v", test.name, executor.rollbackJournals)
			}
		})
	}
}

func TestRecoveryTransitionWriteFailurePrecedesMutation(t *testing.T) {
	for _, test := range []struct {
		name       string
		committed  bool
		generation uint64
	}{
		{name: "rollback", generation: 7},
		{name: "committed", committed: true, generation: 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := testFileJournal(t)
			journal := Journal{
				Schema: "nftfw.setup-journal.v1", Transaction: test.name,
				Phase: PhaseValidate, Status: "running", StartedAt: testTime(),
				UpdatedAt: testTime(), Deadline: testTime().Add(time.Minute),
				BackupDir: "/backup", Generation: test.generation,
				Committed: test.committed, Summary: Summary{Schema: "nftfw.setup-plan.v1"},
			}
			if err := base.Write(journal); err != nil {
				t.Fatal(err)
			}
			store := &recordingJournal{store: base, failWrites: 1}
			executor := &fakeExecutor{}
			if err := (Engine{Executor: executor, Journal: store}).fail(
				context.Background(), Plan{}, journal, errors.New("SETUP_INJECTED_FAILURE"),
			); err == nil || err.Error() != "SETUP_RECOVERY_TRANSITION_WRITE_FAILED" {
				t.Fatalf("transition write failure=%v", err)
			}
			calls := strings.Join(executor.calls, ",")
			if strings.Contains(calls, "rollback") || strings.Contains(calls, "recover-committed") {
				t.Fatalf("recovery mutated before its transition was durable: %v", executor.calls)
			}
		})
	}
}

func TestRecoveryResultWriteFailureRemainsSafelyRetryable(t *testing.T) {
	base := testFileJournal(t)
	journal := Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "result-write",
		Phase: PhaseValidate, Status: "rolling_back", StartedAt: testTime(),
		UpdatedAt: testTime(), Deadline: testTime().Add(time.Minute),
		BackupDir: "/backup", Generation: 7, Summary: Summary{Schema: "nftfw.setup-plan.v1"},
	}
	if err := base.Write(journal); err != nil {
		t.Fatal(err)
	}
	store := &recordingJournal{store: base, failWrites: 2}
	executor := &fakeExecutor{commitInspectErr: errors.New("must not inspect known uncommitted state")}
	err := (Engine{Executor: executor, Journal: store}).fail(
		context.Background(), Plan{}, journal, errors.New("SETUP_INJECTED_FAILURE"),
	)
	if err == nil || err.Error() != "SETUP_RECOVERY_RESULT_WRITE_FAILED" {
		t.Fatalf("result write failure=%v", err)
	}
	if strings.Join(executor.calls, ",") != "rollback" {
		t.Fatalf("known uncommitted retry was reclassified or skipped: %v", executor.calls)
	}
	current, readErr := base.Read()
	if readErr != nil || current.Status != "rolling_back" || current.Phase != PhaseValidate {
		t.Fatalf("failed result publication lost retry evidence: %#v %v", current, readErr)
	}
}

func TestRecoveryTransitionsResumeAfterSecondProcessDeath(t *testing.T) {
	for _, test := range []struct {
		name      string
		journal   Journal
		wantCalls string
	}{
		{
			name: "rolling-back",
			journal: Journal{Phase: PhaseValidate, Status: "rolling_back", Generation: 7,
				BackupDir: "/backup", Summary: Summary{Schema: "nftfw.setup-plan.v1"}},
			wantCalls: "rollback",
		},
		{
			name: "rollback-failed",
			journal: Journal{Phase: PhaseValidate, Status: "rollback_failed", Generation: 7,
				BackupDir: "/backup", Summary: Summary{Schema: "nftfw.setup-plan.v1"}},
			wantCalls: "rollback",
		},
		{
			name: "recovering-committed",
			journal: Journal{Phase: PhaseCommit, Status: "recovering_committed", Generation: 7,
				Committed: true, BackupDir: "/backup", Summary: Summary{Schema: "nftfw.setup-plan.v1"}},
			wantCalls: "recover-committed",
		},
		{
			name: "committed-recovery-failed",
			journal: Journal{Phase: PhaseCommit, Status: "committed_recovery_failed", Generation: 7,
				Committed: true, BackupDir: "/backup", Summary: Summary{Schema: "nftfw.setup-plan.v1"}},
			wantCalls: "recover-committed",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.journal.Schema = "nftfw.setup-journal.v1"
			test.journal.Transaction = test.name
			test.journal.StartedAt = testTime().Add(-2 * time.Minute)
			test.journal.UpdatedAt = testTime()
			test.journal.Deadline = testTime().Add(-time.Minute)
			store := testFileJournal(t)
			if err := store.Write(test.journal); err != nil {
				t.Fatal(err)
			}
			executor := &fakeExecutor{commitInspectErr: errors.New("classified transition must not re-inspect")}
			attempted, err := (Engine{Executor: executor, Journal: store, Now: testTime}).
				RollbackExpired(context.Background(), Plan{})
			if !attempted || err == nil {
				t.Fatalf("transition was not resumed: attempted=%t err=%v", attempted, err)
			}
			if strings.Join(executor.calls, ",") != test.wantCalls {
				t.Fatalf("resume calls=%v want=%s", executor.calls, test.wantCalls)
			}
		})
	}
}

func TestRollbackAndCommittedRecoveryFailuresRemainRecorded(t *testing.T) {
	rollbackExecutor := &fakeExecutor{failCalls: map[string]bool{"tunnel": true, "rollback": true}}
	rollbackStore := testFileJournal(t)
	if _, err := (Engine{
		Executor: rollbackExecutor, Journal: rollbackStore,
		NewID: func() string { return "rollback-failure" },
	}).Run(context.Background(), "/vpn.conf"); err == nil {
		t.Fatal("rollback failure was hidden")
	}
	rollbackJournal, err := rollbackStore.Read()
	if err != nil {
		t.Fatal(err)
	}
	if rollbackJournal.Status != "rollback_failed" {
		t.Fatalf("rollback failure status=%s", rollbackJournal.Status)
	}

	recoveryExecutor := &fakeExecutor{failAt: "boot"}
	recoveryStore := testFileJournal(t)
	recoveryExecutor.failAt = "recover-committed"
	journal := Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "recovery-failure",
		Phase: PhaseBoot, Status: "running", StartedAt: testTime(),
		UpdatedAt: testTime(), Deadline: testTime().Add(time.Minute),
		Generation: 7, Committed: true,
	}
	if err := recoveryStore.Write(journal); err != nil {
		t.Fatal(err)
	}
	engine := Engine{Executor: recoveryExecutor, Journal: recoveryStore}
	if err := engine.fail(context.Background(), Plan{}, journal, errors.New("SETUP_BOOT_FAILED")); err == nil {
		t.Fatal("committed recovery failure was hidden")
	}
	recoveryJournal, err := recoveryStore.Read()
	if err != nil {
		t.Fatal(err)
	}
	if recoveryJournal.Status != "committed_recovery_failed" {
		t.Fatalf("recovery failure status=%s", recoveryJournal.Status)
	}
}

func TestRollbackExpiredNoOpStates(t *testing.T) {
	executor := &fakeExecutor{}
	store := testFileJournal(t)
	now := testTime()
	for _, journal := range []Journal{
		{
			Schema: "nftfw.setup-journal.v1", Transaction: "complete",
			Phase: PhaseComplete, Status: "complete", StartedAt: now.Add(-2 * time.Minute),
			UpdatedAt: now, Deadline: now.Add(-time.Minute),
		},
		{
			Schema: "nftfw.setup-journal.v1", Transaction: "running",
			Phase: PhaseGuard, Status: "running", StartedAt: now,
			UpdatedAt: now, Deadline: now.Add(time.Minute),
		},
	} {
		if err := store.Write(journal); err != nil {
			t.Fatal(err)
		}
		attempted, err := (Engine{
			Executor: executor, Journal: store, Now: func() time.Time { return now },
		}).RollbackExpired(context.Background(), Plan{})
		if err != nil || attempted {
			t.Fatalf("unexpected rollback attempt: attempted=%t err=%v", attempted, err)
		}
	}
	if _, err := (Engine{}).RollbackExpired(context.Background(), Plan{}); err == nil {
		t.Fatal("incomplete rollback engine accepted")
	}
}

func TestErrorCodeRedactsUnboundedErrors(t *testing.T) {
	if errorCode(nil) != "" || errorCode(errors.New("SETUP_VALID")) != "SETUP_VALID" {
		t.Fatal("valid setup error code changed")
	}
	if errorCode(errors.New("contains secret material")) != "SETUP_FAILED" {
		t.Fatal("unbounded error was not redacted")
	}
}
