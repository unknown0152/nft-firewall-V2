package recovery

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/reconcile"
)

type Controller struct{ Manager *reconcile.Manager }

func (c Controller) RollbackExpired(ctx context.Context) (bool, error) {
	if c.Manager == nil {
		return false, nil
	}
	return c.Manager.RollbackExpired(ctx)
}

type SystemdGuard struct {
	Timer   string
	Service string
	StateDB string
	Run     func(context.Context, ...string) error
	Inspect func(context.Context, ...string) (string, error)
}

// Verify refuses safe apply unless a separately scheduled rollback path is
// both enabled for boot and active now.
func (g SystemdGuard) Verify(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	timer := g.Timer
	if timer == "" {
		timer = "nftfw-rollback.timer"
	}
	service := g.Service
	if service == "" {
		service = "nftfw-rollback.service"
	}
	run := g.Run
	if run == nil {
		run = func(ctx context.Context, args ...string) error {
			return exec.CommandContext(ctx, "systemctl", args...).Run()
		}
	}
	stateDB := g.StateDB
	if stateDB == "" {
		stateDB = "/var/lib/nftfw/state.db"
	}
	inspect := g.Inspect
	if inspect == nil {
		inspect = func(ctx context.Context, args ...string) (string, error) {
			output, err := exec.CommandContext(ctx, "systemctl", args...).Output()
			if len(output) > 64<<10 {
				return "", errors.New("systemd service description exceeds safety limit")
			}
			return string(output), err
		}
	}
	if err := run(ctx, "is-enabled", "--quiet", timer); err != nil {
		return errors.New("independent rollback timer is not enabled")
	}
	if err := run(ctx, "is-active", "--quiet", timer); err != nil {
		return errors.New("independent rollback timer is not active")
	}
	execStart, err := inspect(ctx, "show", "--property=ExecStart", "--value", service)
	if err != nil || !execStartUsesStateDB(execStart, stateDB) {
		return fmt.Errorf("independent rollback service does not protect state database %s", stateDB)
	}
	// A timer can remain active while its service is unexecutable or its
	// sandbox refers to a missing path. Starting the no-op service before a
	// candidate exists proves the independent process can actually run.
	if err := run(ctx, "start", "--quiet", service); err != nil {
		return errors.New("independent rollback service failed its preflight")
	}
	return nil
}

func execStartUsesStateDB(execStart, stateDB string) bool {
	fields := strings.Fields(execStart)
	for index, field := range fields {
		if field == "--state-db" && index+1 < len(fields) {
			return strings.TrimSuffix(fields[index+1], ";") == stateDB
		}
	}
	return false
}
