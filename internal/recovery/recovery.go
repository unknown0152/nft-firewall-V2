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
	Timer   string
	Service string
	Run     func(context.Context, ...string) error
}

// Verify refuses safe apply unless a separately scheduled rollback path is
// both enabled for boot and active now.
func (g SystemdGuard) Verify(ctx context.Context) error {
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
	if err := run(ctx, "is-enabled", "--quiet", timer); err != nil {
		return errors.New("independent rollback timer is not enabled")
	}
	if err := run(ctx, "is-active", "--quiet", timer); err != nil {
		return errors.New("independent rollback timer is not active")
	}
	// A timer can remain active while its service is unexecutable or its
	// sandbox refers to a missing path. Starting the no-op service before a
	// candidate exists proves the independent process can actually run.
	if err := run(ctx, "start", "--quiet", service); err != nil {
		return errors.New("independent rollback service failed its preflight")
	}
	return nil
}
