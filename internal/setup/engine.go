// Package setup coordinates the one-file managed installation as a durable,
// phase-recorded transaction.
package setup

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"time"
)

type Phase string

const (
	PhaseInspect  Phase = "inspect"
	PhaseBackup   Phase = "backup"
	PhaseBootPrep Phase = "boot_prepare"
	PhaseGuard    Phase = "guard"
	PhaseInstall  Phase = "install"
	PhaseDocker   Phase = "docker"
	PhaseRuntime  Phase = "runtime"
	PhaseApply    Phase = "apply"
	PhaseTunnel   Phase = "tunnel"
	PhaseValidate Phase = "validate"
	PhaseCommit   Phase = "commit"
	PhaseHandoff  Phase = "handoff"
	PhaseBoot     Phase = "boot"
	PhaseFinalize Phase = "finalize"
	PhaseComplete Phase = "complete"
	PhaseRollback Phase = "rollback"
	PhaseFailed   Phase = "failed"
)

type Plan struct {
	VPNSource          string
	Summary            Summary
	PrivateData        any
	PriorJournalSHA256 string
	ResumeJournal      *Journal
	ResumeReady        bool
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
	BootPolicy        string   `json:"boot_policy,omitempty"`
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
	PublishFinalDependencies(context.Context, Plan) error
	EnableBoot(context.Context, Plan) error
	Finalize(context.Context, Plan) error
	GenerationCommitted(context.Context, uint64) (bool, error)
	Rollback(context.Context, Plan, Journal) error
	RecoverCommitted(context.Context, Plan, Journal) error
}

type bootTransactionExecutor interface {
	BootTransactionRequired(Plan) bool
	PrepareBoot(context.Context, Plan) error
	VerifyBootResume(context.Context, Plan) error
}

var (
	ErrRebootRequired         = errors.New("SETUP_REBOOT_REQUIRED")
	ErrRollbackRebootRequired = errors.New("SETUP_ROLLBACK_REBOOT_REQUIRED")
)

type JournalStore interface {
	Begin(Journal, string) error
	Write(Journal) error
	Read() (Journal, error)
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
	journal := Journal{}
	bootExecutor, bootRequired := e.Executor.(bootTransactionExecutor)
	bootRequired = bootRequired && bootExecutor.BootTransactionRequired(plan)
	if plan.ResumeJournal != nil {
		journal = *plan.ResumeJournal
		if !bootRequired || !rebootRequiredJournal(journal) ||
			!reflect.DeepEqual(journal.Summary, plan.Summary) {
			return Plan{}, errors.New("SETUP_RESUME_STATE_INVALID")
		}
		if !plan.ResumeReady {
			return plan, ErrRebootRequired
		}
		journal.Status, journal.ErrorCode = "resume_ready", ""
		journal.UpdatedAt, journal.Deadline = started, started.Add(timeout)
		if err := e.Journal.Write(journal); err != nil {
			return Plan{}, errors.New("SETUP_JOURNAL_WRITE_FAILED")
		}
		if err := bootExecutor.VerifyBootResume(ctx, plan); err != nil {
			return Plan{}, e.fail(ctx, plan, journal, err)
		}
		journal.Status, journal.UpdatedAt = "running", now().UTC()
		if err := e.Journal.Write(journal); err != nil {
			return Plan{}, e.fail(ctx, plan, journal, errors.New("SETUP_JOURNAL_WRITE_FAILED"))
		}
	} else {
		journal = Journal{
			Schema: "nftfw.setup-journal.v1", Transaction: newID(),
			Phase: PhaseInspect, Status: "running", StartedAt: started,
			UpdatedAt: started, Deadline: started.Add(timeout), Summary: plan.Summary,
		}
		// Publishing the initial journal is the durable boundary immediately before
		// the first mutation-capable phase. If publication fails, no setup phase has
		// run and rollback would have neither a backup nor changed state to restore.
		if err := e.Journal.Begin(journal, plan.PriorJournalSHA256); err != nil {
			return Plan{}, errors.New("SETUP_JOURNAL_WRITE_FAILED")
		}
		journal.Phase, journal.UpdatedAt = PhaseBackup, now().UTC()
		if err := e.Journal.Write(journal); err != nil {
			return Plan{}, e.fail(ctx, plan, journal, errors.New("SETUP_JOURNAL_WRITE_FAILED"))
		}
		backup, backupErr := e.Executor.Backup(ctx, plan)
		if backupErr != nil {
			return Plan{}, e.fail(ctx, plan, journal, backupErr)
		}
		journal.BackupDir, journal.UpdatedAt = backup, now().UTC()
		if err := e.Journal.Write(journal); err != nil {
			return Plan{}, e.fail(ctx, plan, journal, errors.New("SETUP_JOURNAL_WRITE_FAILED"))
		}
		if bootRequired {
			journal.Phase, journal.UpdatedAt = PhaseBootPrep, now().UTC()
			if err := e.Journal.Write(journal); err != nil {
				return Plan{}, e.fail(ctx, plan, journal, errors.New("SETUP_JOURNAL_WRITE_FAILED"))
			}
			if err := bootExecutor.PrepareBoot(ctx, plan); err != nil {
				return Plan{}, e.fail(ctx, plan, journal, err)
			}
			journal.Status, journal.ErrorCode, journal.UpdatedAt = "reboot_required", "", now().UTC()
			if err := e.Journal.Write(journal); err != nil {
				return Plan{}, e.fail(ctx, plan, journal, errors.New("SETUP_JOURNAL_WRITE_FAILED"))
			}
			return plan, ErrRebootRequired
		}
	}
	steps := []struct {
		phase Phase
		run   func() error
	}{
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
		{PhaseHandoff, func() error { return e.Executor.PublishFinalDependencies(ctx, plan) }},
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
	if !journalNeedsRecovery(journal.Status) {
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
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	if journalBeforeProtectedMutation(journal) {
		journal.Phase, journal.Status = PhaseFailed, "rolled_back"
		journal.ErrorCode = errorCode(cause)
		journal.UpdatedAt = now().UTC()
		if err := e.Journal.Write(journal); err != nil {
			return errors.New("SETUP_RECOVERY_RESULT_WRITE_FAILED")
		}
		return errors.New(errorCode(cause))
	}
	uncommittedKnown := journal.Status == "rolling_back" || journal.Status == "rollback_failed"
	if !journal.Committed && !uncommittedKnown && journal.Generation != 0 {
		inspectionCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		committed, inspectionErr := e.Executor.GenerationCommitted(inspectionCtx, journal.Generation)
		cancel()
		if inspectionErr != nil {
			journal.Status = "commit_state_unknown"
			journal.ErrorCode = "SETUP_COMMIT_STATE_UNKNOWN"
			journal.UpdatedAt = now().UTC()
			if writeErr := e.Journal.Write(journal); writeErr != nil {
				return errors.New("SETUP_RECOVERY_RESULT_WRITE_FAILED")
			}
			return errors.New("SETUP_COMMIT_STATE_UNKNOWN")
		}
		journal.Committed = committed
	}
	if journal.Committed {
		journal.Status = "recovering_committed"
		journal.ErrorCode = errorCode(cause)
		journal.UpdatedAt = now().UTC()
		if err := e.Journal.Write(journal); err != nil {
			return errors.New("SETUP_RECOVERY_TRANSITION_WRITE_FAILED")
		}
		recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		recoveryErr := e.Executor.RecoverCommitted(recoveryCtx, plan, journal)
		cancel()
		if recoveryErr != nil {
			journal.Status = "committed_recovery_failed"
			journal.ErrorCode = errorCode(recoveryErr)
			journal.UpdatedAt = now().UTC()
			if err := e.Journal.Write(journal); err != nil {
				return errors.New("SETUP_RECOVERY_RESULT_WRITE_FAILED")
			}
			return fmt.Errorf("%s; SETUP_COMMITTED_RECOVERY_FAILED", errorCode(cause))
		}
		journal.Phase, journal.Status, journal.UpdatedAt = PhaseComplete, "complete", now().UTC()
		journal.ErrorCode = ""
		if err := e.Journal.Write(journal); err != nil {
			return errors.New("SETUP_RECOVERY_RESULT_WRITE_FAILED")
		}
		return errors.New("SETUP_COMMITTED_RECOVERED")
	}
	// Status records the recovery transition while Phase retains the durable
	// originating setup phase needed for exact tunnel cleanup after another
	// process death. No schema extension is required.
	journal.Status = "rolling_back"
	journal.ErrorCode = errorCode(cause)
	journal.UpdatedAt = now().UTC()
	if err := e.Journal.Write(journal); err != nil {
		return errors.New("SETUP_RECOVERY_TRANSITION_WRITE_FAILED")
	}
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	rollbackErr := e.Executor.Rollback(rollbackCtx, plan, journal)
	cancel()
	journal.UpdatedAt = now().UTC()
	if errors.Is(rollbackErr, ErrRollbackRebootRequired) {
		journal.Phase, journal.Status = PhaseFailed, "rollback_reboot_required"
		journal.ErrorCode = ""
		if err := e.Journal.Write(journal); err != nil {
			return errors.New("SETUP_RECOVERY_RESULT_WRITE_FAILED")
		}
		return ErrRollbackRebootRequired
	}
	if rollbackErr != nil {
		journal.Status = "rollback_failed"
		journal.ErrorCode = errorCode(rollbackErr)
		if err := e.Journal.Write(journal); err != nil {
			return errors.New("SETUP_RECOVERY_RESULT_WRITE_FAILED")
		}
		return fmt.Errorf("%s; SETUP_ROLLBACK_FAILED", errorCode(cause))
	}
	journal.Phase, journal.Status = PhaseFailed, "rolled_back"
	if err := e.Journal.Write(journal); err != nil {
		return errors.New("SETUP_RECOVERY_RESULT_WRITE_FAILED")
	}
	return errors.New(errorCode(cause))
}

func journalNeedsRecovery(status string) bool {
	switch status {
	case "running", "resume_ready", "rolling_back", "recovering_committed", "rollback_failed",
		"commit_state_unknown", "committed_recovery_failed":
		return true
	default:
		return false
	}
}

func journalBeforeProtectedMutation(journal Journal) bool {
	if journal.Committed || journal.Generation != 0 || journal.BackupDir != "" {
		return false
	}
	return journal.Phase == PhaseInspect || journal.Phase == PhaseBackup
}

func rebootRequiredJournal(journal Journal) bool {
	return journal.Schema == "nftfw.setup-journal.v1" &&
		journalIdentityPattern.MatchString(journal.Transaction) &&
		journal.Phase == PhaseBootPrep &&
		(journal.Status == "reboot_required" || journal.Status == "resume_ready") &&
		!journal.Committed && journal.Generation == 0 && journal.BackupDir != "" &&
		filepath.IsAbs(journal.BackupDir) && filepath.Clean(journal.BackupDir) == journal.BackupDir &&
		journal.Summary.Schema == "nftfw.setup-plan.v1" && journal.ErrorCode == ""
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
