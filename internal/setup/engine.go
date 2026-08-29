// Package setup coordinates the one-file managed installation as a durable,
// phase-recorded transaction.
package setup

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type Phase string

const (
	PhaseInspect  Phase = "inspect"
	PhaseBackup   Phase = "backup"
	PhaseGuard    Phase = "guard"
	PhaseInstall  Phase = "install"
	PhaseDocker   Phase = "docker"
	PhaseRuntime  Phase = "runtime"
	PhaseApply    Phase = "apply"
	PhaseTunnel   Phase = "tunnel"
	PhaseValidate Phase = "validate"
	PhaseCommit   Phase = "commit"
	PhaseBoot     Phase = "boot"
	PhaseFinalize Phase = "finalize"
	PhaseComplete Phase = "complete"
	PhaseRollback Phase = "rollback"
	PhaseFailed   Phase = "failed"
)

type Plan struct {
	VPNSource   string
	Summary     Summary
	PrivateData any
}

type Summary struct {
	Schema            string   `json:"schema"`
	Uplink            string   `json:"uplink"`
	VPNInterface      string   `json:"vpn_interface"`
	IPv6Interfaces    []string `json:"ipv6_interfaces"`
	LANNetworks       []string `json:"lan_networks"`
	ManagementTCP     []int    `json:"management_tcp"`
	PublicTCP         []int    `json:"public_tcp"`
	PublicUDP         []int    `json:"public_udp"`
	IPv6Mode          string   `json:"ipv6_mode"`
	DockerMode        string   `json:"docker_mode"`
	DockerNetworks    []string `json:"docker_networks,omitempty"`
	DockerRestart     bool     `json:"docker_restart_required"`
	ResolverMode      string   `json:"resolver_mode"`
	SourceModeWarning bool     `json:"source_mode_warning"`
}

type Journal struct {
	Schema      string    `json:"schema"`
	Transaction string    `json:"transaction"`
	Phase       Phase     `json:"phase"`
	Status      string    `json:"status"`
	StartedAt   time.Time `json:"started_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Deadline    time.Time `json:"deadline"`
	BackupDir   string    `json:"backup_dir,omitempty"`
	Generation  uint64    `json:"generation,omitempty"`
	Committed   bool      `json:"committed,omitempty"`
	Summary     Summary   `json:"summary"`
	ErrorCode   string    `json:"error_code,omitempty"`
}

type Executor interface {
	Prepare(context.Context, string) (Plan, error)
	Backup(context.Context, Plan) (string, error)
	StartGuard(context.Context, Plan) error
	Install(context.Context, Plan) error
	ConfigureDocker(context.Context, Plan) error
	StartRuntime(context.Context, Plan) error
	ApplySafe(context.Context, Plan) (uint64, error)
	StartTunnel(context.Context, Plan) error
	Validate(context.Context, Plan, uint64) error
	Commit(context.Context, Plan, uint64) error
	EnableBoot(context.Context, Plan) error
	Finalize(context.Context, Plan) error
	Rollback(context.Context, Plan, Journal) error
	RecoverCommitted(context.Context, Plan, Journal) error
}

type JournalStore interface {
	Write(Journal) error
	Read() (Journal, error)
}

type CommitInspector interface {
	GenerationCommitted(context.Context, uint64) (bool, error)
}

type Engine struct {
	Executor Executor
	Journal  JournalStore
	Now      func() time.Time
	NewID    func() string
	Timeout  time.Duration
}

func (e Engine) DryRun(ctx context.Context, vpnPath string) (Plan, error) {
	if e.Executor == nil {
		return Plan{}, errors.New("SETUP_EXECUTOR_MISSING")
	}
	return e.Executor.Prepare(ctx, vpnPath)
}

func (e Engine) Run(ctx context.Context, vpnPath string) (Plan, error) {
	if e.Executor == nil || e.Journal == nil {
		return Plan{}, errors.New("SETUP_ENGINE_INCOMPLETE")
	}
	// Preparation is strictly read-only. It must finish before the transaction
	// journal is created because clean-host discovery deliberately classifies
	// any existing setup journal as NFTFW state requiring explicit recovery.
	// A preparation failure therefore has nothing to roll back.
	plan, err := e.Executor.Prepare(ctx, vpnPath)
	if err != nil {
		return Plan{}, errors.New(errorCode(err))
	}
	if plan.Summary.Schema != "nftfw.setup-plan.v1" {
		return Plan{}, errors.New("SETUP_PLAN_INVALID")
	}
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	newID := func() string { return fmt.Sprintf("%d", now().UTC().UnixNano()) }
	if e.NewID != nil {
		newID = e.NewID
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	started := now().UTC()
	journal := Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: newID(),
		Phase: PhaseInspect, Status: "running", StartedAt: started,
		UpdatedAt: started, Deadline: started.Add(timeout), Summary: plan.Summary,
	}
	// Publishing the initial journal is the durable boundary immediately before
	// the first mutation-capable phase. If publication fails, no setup phase has
	// run and rollback would have neither a backup nor changed state to restore.
	if err := e.Journal.Write(journal); err != nil {
		return Plan{}, errors.New("SETUP_JOURNAL_WRITE_FAILED")
	}
	steps := []struct {
		phase Phase
		run   func() error
	}{
		{PhaseBackup, func() error {
			backup, err := e.Executor.Backup(ctx, plan)
			if err == nil {
				journal.BackupDir = backup
			}
			return err
		}},
		{PhaseGuard, func() error { return e.Executor.StartGuard(ctx, plan) }},
		{PhaseInstall, func() error { return e.Executor.Install(ctx, plan) }},
		{PhaseDocker, func() error { return e.Executor.ConfigureDocker(ctx, plan) }},
		{PhaseRuntime, func() error { return e.Executor.StartRuntime(ctx, plan) }},
		{PhaseApply, func() error {
			generation, err := e.Executor.ApplySafe(ctx, plan)
			if err == nil {
				journal.Generation = generation
			}
			return err
		}},
		{PhaseTunnel, func() error { return e.Executor.StartTunnel(ctx, plan) }},
		{PhaseValidate, func() error { return e.Executor.Validate(ctx, plan, journal.Generation) }},
		{PhaseCommit, func() error {
			if err := e.Executor.Commit(ctx, plan, journal.Generation); err != nil {
				return err
			}
			journal.Committed = true
			return nil
		}},
		{PhaseBoot, func() error { return e.Executor.EnableBoot(ctx, plan) }},
		{PhaseFinalize, func() error { return e.Executor.Finalize(ctx, plan) }},
	}
	for _, step := range steps {
		if !now().UTC().Before(journal.Deadline) {
			return Plan{}, e.fail(ctx, plan, journal, errors.New("SETUP_DEADLINE_EXPIRED"))
		}
		journal.Phase, journal.UpdatedAt = step.phase, now().UTC()
		if err := e.Journal.Write(journal); err != nil {
			return Plan{}, e.fail(ctx, plan, journal, errors.New("SETUP_JOURNAL_WRITE_FAILED"))
		}
		if err := step.run(); err != nil {
			return Plan{}, e.fail(ctx, plan, journal, err)
		}
		journal.UpdatedAt = now().UTC()
		if err := e.Journal.Write(journal); err != nil {
			return Plan{}, e.fail(ctx, plan, journal, errors.New("SETUP_JOURNAL_WRITE_FAILED"))
		}
	}
	journal.Phase, journal.Status, journal.UpdatedAt = PhaseComplete, "complete", now().UTC()
	journal.ErrorCode = ""
	if err := e.Journal.Write(journal); err != nil {
		return Plan{}, errors.New("SETUP_FINAL_JOURNAL_WRITE_FAILED")
	}
	return plan, nil
}

func (e Engine) RollbackExpired(ctx context.Context, plan Plan) (bool, error) {
	if e.Executor == nil || e.Journal == nil {
		return false, errors.New("SETUP_ENGINE_INCOMPLETE")
	}
	journal, err := e.Journal.Read()
	if err != nil {
		return false, err
	}
	if journal.Status != "running" {
		return false, nil
	}
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	if now().UTC().Before(journal.Deadline) {
		return false, nil
	}
	return true, e.fail(ctx, plan, journal, errors.New("SETUP_DEADLINE_EXPIRED"))
}

func (e Engine) fail(ctx context.Context, plan Plan, journal Journal, cause error) error {
	if journalBeforeProtectedMutation(journal) {
		journal.Phase, journal.Status = PhaseFailed, "rolled_back"
		journal.ErrorCode = errorCode(cause)
		journal.UpdatedAt = time.Now().UTC()
		if e.Now != nil {
			journal.UpdatedAt = e.Now().UTC()
		}
		_ = e.Journal.Write(journal)
		return errors.New(errorCode(cause))
	}
	if !journal.Committed && journal.Generation != 0 {
		if inspector, ok := e.Executor.(CommitInspector); ok {
			inspectionCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			committed, err := inspector.GenerationCommitted(inspectionCtx, journal.Generation)
			cancel()
			if err != nil {
				journal.Status = "commit_state_unknown"
				journal.ErrorCode = "SETUP_COMMIT_STATE_UNKNOWN"
				_ = e.Journal.Write(journal)
				return errors.New("SETUP_COMMIT_STATE_UNKNOWN")
			}
			journal.Committed = committed
		}
	}
	if journal.Committed {
		journal.Status = "recovering_committed"
		journal.ErrorCode = errorCode(cause)
		_ = e.Journal.Write(journal)
		recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if err := e.Executor.RecoverCommitted(recoveryCtx, plan, journal); err != nil {
			journal.Status = "committed_recovery_failed"
			_ = e.Journal.Write(journal)
			return fmt.Errorf("%s; SETUP_COMMITTED_RECOVERY_FAILED", errorCode(cause))
		}
		journal.Phase, journal.Status, journal.UpdatedAt = PhaseComplete, "complete", time.Now().UTC()
		if e.Now != nil {
			journal.UpdatedAt = e.Now().UTC()
		}
		_ = e.Journal.Write(journal)
		return errors.New("SETUP_COMMITTED_RECOVERED")
	}
	journal.Phase, journal.Status = PhaseRollback, "rolling_back"
	journal.ErrorCode = errorCode(cause)
	journal.UpdatedAt = time.Now().UTC()
	if e.Now != nil {
		journal.UpdatedAt = e.Now().UTC()
	}
	_ = e.Journal.Write(journal)
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	rollbackErr := e.Executor.Rollback(rollbackCtx, plan, journal)
	journal.Phase, journal.UpdatedAt = PhaseFailed, time.Now().UTC()
	if e.Now != nil {
		journal.UpdatedAt = e.Now().UTC()
	}
	if rollbackErr != nil {
		journal.Status = "rollback_failed"
		_ = e.Journal.Write(journal)
		return fmt.Errorf("%s; SETUP_ROLLBACK_FAILED", errorCode(cause))
	}
	journal.Status = "rolled_back"
	_ = e.Journal.Write(journal)
	return errors.New(errorCode(cause))
}

func journalBeforeProtectedMutation(journal Journal) bool {
	if journal.Committed || journal.Generation != 0 || journal.BackupDir != "" {
		return false
	}
	return journal.Phase == PhaseInspect || journal.Phase == PhaseBackup
}

func errorCode(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 0 && len(value) <= 96 {
		valid := true
		for _, r := range value {
			if !(r == '_' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				valid = false
				break
			}
		}
		if valid {
			return value
		}
	}
	return "SETUP_FAILED"
}
