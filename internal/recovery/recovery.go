package recovery

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
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
	Timer    string
	Service  string
	StateDir string
	Run      func(context.Context, ...string) error
	Inspect  func(context.Context, ...string) (string, error)
}

// Preflight proves that the independently scheduled rollback executable can
// actually run. It must be called before taking NFTFW's process mutation lock,
// because the oneshot service deliberately takes that same lock.
func (g SystemdGuard) Preflight(ctx context.Context) error {
	return g.verify(ctx, true)
}

// Revalidate repeats the timer and exact unit-argv identity checks without
// starting the service. Callers run it under NFTFW's process mutation lock so
// a changed unit cannot be used after an earlier successful preflight.
func (g SystemdGuard) Revalidate(ctx context.Context) error {
	return g.verify(ctx, false)
}

// Verify is the standalone check used by callers that hold no mutation lock.
func (g SystemdGuard) Verify(ctx context.Context) error {
	if err := g.Preflight(ctx); err != nil {
		return err
	}
	return g.Revalidate(ctx)
}

func (g SystemdGuard) verify(ctx context.Context, startService bool) error {
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
	stateDir := g.StateDir
	if stateDir == "" {
		stateDir = "/var/lib/nftfw"
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
	if err != nil || !execStartUsesStateDir(execStart, stateDir) {
		return fmt.Errorf("independent rollback service does not protect canonical state root %s", stateDir)
	}
	if startService {
		// A timer can remain active while its service is unexecutable or its
		// sandbox refers to a missing path. Starting the no-op service before a
		// candidate exists proves the independent process can actually run.
		if err := run(ctx, "start", "--quiet", service); err != nil {
			return errors.New("independent rollback service failed its preflight")
		}
	}
	return nil
}

func execStartUsesStateDir(execStart, stateDir string) bool {
	if len(execStart) == 0 || len(execStart) > 64<<10 || !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir || stateDir == "/" || strings.ContainsAny(stateDir, "?#; \t\r\n") {
		return false
	}
	const marker = "argv[]="
	if strings.Count(execStart, marker) != 1 {
		return false
	}
	remainder := execStart[strings.Index(execStart, marker)+len(marker):]
	terminator := strings.Index(remainder, " ;")
	if terminator < 0 {
		return false
	}
	fields := strings.Fields(strings.TrimSpace(remainder[:terminator]))
	expected := []string{"/usr/lib/nftfw/nftfwd", "--rollback-expired", "--state-dir", stateDir}
	if len(fields) != len(expected) {
		return false
	}
	for index := range expected {
		if fields[index] != expected[index] {
			return false
		}
	}
	return true
}
