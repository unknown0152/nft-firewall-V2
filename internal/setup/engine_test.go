package setup

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeExecutor struct {
	calls               []string
	failAt              string
	failCalls           map[string]bool
	generationCommitted bool
	commitInspectErr    error
}

func (f *fakeExecutor) call(name string) error {
	f.calls = append(f.calls, name)
	if f.failAt == name || f.failCalls[name] {
		return errors.New("SETUP_INJECTED_FAILURE")
	}
	return nil
}

func (f *fakeExecutor) Prepare(context.Context, string) (Plan, error) {
	return Plan{Summary: Summary{Schema: "nftfw.setup-plan.v1"}}, f.call("prepare")
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
func (f *fakeExecutor) StartTunnel(context.Context, Plan) error       { return f.call("tunnel") }
func (f *fakeExecutor) Validate(context.Context, Plan, uint64) error  { return f.call("validate") }
func (f *fakeExecutor) Commit(context.Context, Plan, uint64) error    { return f.call("commit") }
func (f *fakeExecutor) EnableBoot(context.Context, Plan) error        { return f.call("boot") }
func (f *fakeExecutor) Finalize(context.Context, Plan) error          { return f.call("finalize") }
func (f *fakeExecutor) Rollback(context.Context, Plan, Journal) error { return f.call("rollback") }
func (f *fakeExecutor) RecoverCommitted(context.Context, Plan, Journal) error {
	return f.call("recover-committed")
}
func (f *fakeExecutor) GenerationCommitted(context.Context, uint64) (bool, error) {
	f.calls = append(f.calls, "inspect-commit")
	return f.generationCommitted, f.commitInspectErr
}

func TestRunCompletesInExactOrder(t *testing.T) {
	executor := &fakeExecutor{}
	journal := FileJournal{Path: filepath.Join(t.TempDir(), "journal.json")}
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
	want := "prepare,backup,guard,install,docker,runtime,apply,tunnel,validate,commit,boot,finalize"
	if strings.Join(executor.calls, ",") != want {
		t.Fatalf("calls=%v want=%s", executor.calls, want)
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

func TestFailureAlwaysRollsBack(t *testing.T) {
	executor := &fakeExecutor{failAt: "tunnel"}
	journal := FileJournal{Path: filepath.Join(t.TempDir(), "journal.json")}
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

func TestExpiredJournalTriggersIndependentRollback(t *testing.T) {
	executor := &fakeExecutor{}
	path := filepath.Join(t.TempDir(), "journal.json")
	store := FileJournal{Path: path}
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

func TestPostCommitFailureRecoversForward(t *testing.T) {
	executor := &fakeExecutor{failAt: "boot"}
	journal := FileJournal{Path: filepath.Join(t.TempDir(), "journal.json")}
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

func TestExpiredJournalRecoversForwardAcrossCommitJournalGap(t *testing.T) {
	executor := &fakeExecutor{generationCommitted: true}
	path := filepath.Join(t.TempDir(), "journal.json")
	store := FileJournal{Path: path}
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
	path := filepath.Join(t.TempDir(), "journal.json")
	store := FileJournal{Path: path}
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
	if _, err := (Engine{Journal: FileJournal{Path: filepath.Join(t.TempDir(), "journal.json")}}).
		Run(context.Background(), "/vpn.conf"); err == nil {
		t.Fatal("run without executor accepted")
	}
}

func TestEveryPreCommitPhaseFailureRollsBack(t *testing.T) {
	for _, phase := range []string{
		"prepare", "backup", "guard", "install", "docker", "runtime", "apply", "tunnel", "validate", "commit",
	} {
		t.Run(phase, func(t *testing.T) {
			executor := &fakeExecutor{failAt: phase}
			store := FileJournal{Path: filepath.Join(t.TempDir(), "journal.json")}
			engine := Engine{Executor: executor, Journal: store, NewID: func() string { return phase }}
			if _, err := engine.Run(context.Background(), "/vpn.conf"); err == nil {
				t.Fatal("injected phase failure was ignored")
			}
			if executor.calls[len(executor.calls)-1] != "rollback" {
				t.Fatalf("phase %s did not roll back: %v", phase, executor.calls)
			}
		})
	}
}

func TestRollbackAndCommittedRecoveryFailuresRemainRecorded(t *testing.T) {
	rollbackExecutor := &fakeExecutor{failCalls: map[string]bool{"tunnel": true, "rollback": true}}
	rollbackStore := FileJournal{Path: filepath.Join(t.TempDir(), "journal.json")}
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
	recoveryStore := FileJournal{Path: filepath.Join(t.TempDir(), "journal.json")}
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
	path := filepath.Join(t.TempDir(), "journal.json")
	store := FileJournal{Path: path}
	now := testTime()
	for _, journal := range []Journal{
		{
			Schema: "nftfw.setup-journal.v1", Transaction: "complete",
			Phase: PhaseComplete, Status: "complete", StartedAt: now,
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
