package recovery

import (
	"context"
	"errors"
	"os/exec"

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
	Unit string
	Run  func(context.Context, ...string) error
}

// Verify refuses safe apply unless a separately scheduled rollback path is
// both enabled for boot and active now.
func (g SystemdGuard) Verify(ctx context.Context) error {
	unit := g.Unit
	if unit == "" {
		unit = "nftfw-rollback.timer"
	}
	run := g.Run
	if run == nil {
		run = func(ctx context.Context, args ...string) error {
			return exec.CommandContext(ctx, "systemctl", args...).Run()
		}
	}
	if err := run(ctx, "is-enabled", "--quiet", unit); err != nil {
		return errors.New("independent rollback timer is not enabled")
	}
	if err := run(ctx, "is-active", "--quiet", unit); err != nil {
		return errors.New("independent rollback timer is not active")
	}
	return nil
}
