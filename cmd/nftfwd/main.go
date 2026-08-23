package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/app"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/reconcile"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

func main() {
	config := flag.String("config", "/etc/nftfw/nftfw.toml", "configuration path")
	status := flag.String("status-socket", "/run/nftfw/status.sock", "read-only socket")
	control := flag.String("control-socket", "/run/nftfw/control.sock", "mutation socket")
	expired := flag.Bool("rollback-expired", false, "rollback an expired pending generation and exit")
	stateDB := flag.String("state-db", "/var/lib/nftfw/state.db", "state database for rollback-only mode")
	restoreActive := flag.Bool("restore-active", false, "restore the independently verified active snapshot and exit")
	stateDir := flag.String("state-dir", "/var/lib/nftfw", "state directory for early-boot restore mode")
	flag.Parse()
	if flag.NArg() != 0 || (*expired && *restoreActive) {
		fmt.Fprintln(os.Stderr, "nftfwd: invalid arguments")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if *restoreActive {
		if err := restoreAtBoot(ctx, *stateDir); err != nil {
			fmt.Fprintln(os.Stderr, "nftfwd early boot:", err)
			os.Exit(1)
		}
		return
	}
	if *expired {
		rt, runtimeErr := app.OpenQuiet(ctx, *config, nil)
		if runtimeErr == nil && filepath.Clean(rt.Store.Path) == filepath.Clean(*stateDB) {
			defer rt.Close()
			ok, err := rt.RollbackExpired(ctx)
			if err != nil {
				fmt.Fprintln(os.Stderr, "nftfwd rollback:", err)
				os.Exit(1)
			}
			if ok {
				fmt.Println("expired generation rolled back")
			}
			return
		}
		if rt != nil {
			_ = rt.Close()
		}
		rolledBack, fallbackErr := rollbackExpiredWithoutRuntime(ctx, *stateDB, nft.New(nil))
		if fallbackErr != nil {
			fmt.Fprintln(os.Stderr, "nftfwd rollback: configured runtime unavailable and fallback failed:", fallbackErr)
			os.Exit(1)
		}
		if rolledBack {
			fmt.Fprintln(os.Stderr, "nftfwd rollback: configured runtime unavailable; rolled back the expired generation and left runtime-set publication degraded")
		}
		return
	}
	rt, err := app.Open(ctx, *config, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nftfwd:", err)
		os.Exit(1)
	}
	defer rt.Close()
	if drift, reconcileErr := rt.Reconcile(ctx, true); reconcileErr != nil && !errors.Is(reconcileErr, sql.ErrNoRows) {
		fmt.Fprintln(os.Stderr, "nftfwd: initial reconciliation failed:", reconcileErr)
		os.Exit(1)
	} else if drift.Repaired {
		fmt.Fprintln(os.Stderr, "nftfwd: restored committed firewall generation at startup")
	}
	existing, inspectErr := rt.Backend.ExistingOwned(ctx)
	if inspectErr != nil {
		fmt.Fprintln(os.Stderr, "nftfwd: startup owned-table inspection failed:", inspectErr)
		os.Exit(1)
	}
	if existing["inet/"+nft.FilterTable] {
		if refreshErr := rt.RestoreRuntimeState(ctx); refreshErr != nil {
			fmt.Fprintln(os.Stderr, "nftfwd: startup runtime-state reconciliation failed:", refreshErr)
			os.Exit(1)
		}
	}
	server := &api.Server{Handler: rt, StatusPath: *status, ControlPath: *control}
	if err := rt.RefreshWireGuardHealth(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "nftfwd WireGuard health:", err)
	}
	go rollbackLoop(ctx, rt)
	if err := server.Serve(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "nftfwd:", err)
		os.Exit(1)
	}
}

// rollbackExpiredWithoutRuntime is the narrow recovery path used when the
// configured runtime cannot be opened. A healthy database requires durable,
// actually expired pending state; configuration failure alone never authorizes
// mutation. If SQLite itself cannot be opened, the independently checksummed
// committed snapshot is restored conservatively. Runtime claim publication is
// marked dirty whenever the database is available because this path cannot
// safely reconstruct mutable sets.
func rollbackExpiredWithoutRuntime(ctx context.Context, databasePath string, backend *nft.Backend) (bool, error) {
	absDatabasePath, err := filepath.Abs(databasePath)
	if err != nil {
		return false, fmt.Errorf("resolve rollback state path: %w", err)
	}
	// Fast-path the guard's synchronous preflight without taking the claim
	// publication lock. An actionable result is always reopened and rechecked
	// under that lock, so this read cannot authorize a mutation by itself.
	probe, probeErr := state.Open(ctx, absDatabasePath)
	if probeErr == nil {
		expired, inspectErr := hasExpiredPending(ctx, probe)
		closeErr := probe.Close()
		if inspectErr != nil {
			return false, inspectErr
		}
		if closeErr != nil {
			return false, closeErr
		}
		if !expired {
			return false, nil
		}
	} else if ctx.Err() != nil {
		return false, fmt.Errorf("open rollback state: %w", ctx.Err())
	}
	releaseClaims, err := state.AcquireClaimPublicationLock(ctx, filepath.Dir(absDatabasePath))
	if err != nil {
		return false, err
	}
	defer releaseClaims()
	databasePath = absDatabasePath
	store, err := state.Open(ctx, databasePath)
	if err != nil {
		if ctx.Err() != nil {
			return false, fmt.Errorf("open rollback state: %w", ctx.Err())
		}
		// A corrupt/unavailable database cannot prove whether a safe-apply
		// deadline is still pending. Conservatively restore the independently
		// checksummed committed snapshot immediately. This branch is deliberately
		// limited to state-open failure; configuration errors with a healthy DB
		// still require an actually expired pending generation below.
		if fallbackErr := restoreRollbackFallback(ctx, filepath.Dir(databasePath), backend); fallbackErr != nil {
			return false, errors.Join(fmt.Errorf("open rollback state: %w", err), fmt.Errorf("restore committed fallback: %w", fallbackErr))
		}
		return true, nil
	}
	defer store.Close()
	expired, err := hasExpiredPending(ctx, store)
	if err != nil {
		return false, err
	}
	if !expired {
		return false, nil
	}
	if _, err := store.PrepareClaimPublication(ctx); err != nil {
		return false, fmt.Errorf("mark runtime claims unpublished before fallback rollback: %w", err)
	}
	manager := &reconcile.Manager{Backend: backend, Store: store}
	rolledBack, err := manager.RollbackExpired(ctx)
	if err != nil {
		return false, err
	}
	if !rolledBack {
		return false, errors.New("expired pending generation changed before fallback rollback")
	}
	return true, nil
}

func hasExpiredPending(ctx context.Context, store *state.Store) (bool, error) {
	pending, err := store.Pending(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect pending rollback state: %w", err)
	}
	return pending.RollbackDeadline != nil && !time.Now().UTC().Before(*pending.RollbackDeadline), nil
}

func restoreRollbackFallback(ctx context.Context, directory string, backend *nft.Backend) error {
	script, enabled, err := state.LoadActiveSnapshot(directory)
	if err != nil {
		if !enabled {
			return fmt.Errorf("active state is unreadable without a verified enforcement marker; refusing nftables mutation: %w", err)
		}
		if applyErr := backend.Apply(ctx, nft.EmergencyDenyScript); applyErr != nil {
			return fmt.Errorf("invalid active snapshot and emergency deny failed: %w", applyErr)
		}
		return nil
	}
	if !enabled {
		existing, inspectErr := backend.ExistingOwned(ctx)
		if inspectErr != nil {
			return fmt.Errorf("inspect unverified product-named nft tables: %w", inspectErr)
		}
		if len(existing) > 0 {
			return errors.New("no verified enforcement marker exists; refusing automatic deletion of product-named nft tables")
		}
		return nil
	}
	return backend.Apply(ctx, script)
}

func restoreAtBoot(ctx context.Context, directory string) error {
	script, enabled, err := state.LoadActiveSnapshot(directory)
	backend := nft.New(nil)
	if err != nil {
		if !enabled {
			return fmt.Errorf("active state is unreadable without a verified enforcement marker; refusing nftables mutation: %w", err)
		}
		if applyErr := backend.Apply(ctx, nft.EmergencyDenyScript); applyErr != nil {
			return fmt.Errorf("active snapshot is invalid and emergency deny failed: %w", applyErr)
		}
		return errors.New("active snapshot is invalid; emergency default-deny policy installed")
	}
	if !enabled {
		return nil
	}
	if err := backend.Apply(ctx, script); err != nil {
		if fallbackErr := backend.Apply(ctx, nft.EmergencyDenyScript); fallbackErr != nil {
			return fmt.Errorf("active snapshot restore and emergency deny both failed: %w", fallbackErr)
		}
		return errors.New("active snapshot restore failed; emergency default-deny policy installed")
	}
	fmt.Println("committed firewall snapshot restored")
	return nil
}

func rollbackLoop(ctx context.Context, rt *app.Runtime) {
	rollbackTicker := time.NewTicker(5 * time.Second)
	reconcileTicker := time.NewTicker(30 * time.Second)
	endpointTicker := time.NewTicker(60 * time.Second)
	claimTicker := time.NewTicker(15 * time.Second)
	integrationTicker := time.NewTicker(60 * time.Second)
	defer rollbackTicker.Stop()
	defer reconcileTicker.Stop()
	defer endpointTicker.Stop()
	defer claimTicker.Stop()
	defer integrationTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-rollbackTicker.C:
			if _, err := rt.RollbackExpired(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "nftfwd rollback:", err)
			}
		case <-reconcileTicker.C:
			drift, err := rt.Reconcile(ctx, true)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				fmt.Fprintln(os.Stderr, "nftfwd reconcile:", err)
			} else if drift.Repaired {
				fmt.Fprintln(os.Stderr, "nftfwd: repaired owned firewall drift:", drift.Detail)
			}
		case <-endpointTicker.C:
			if _, err := rt.RefreshEndpoints(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "nftfwd endpoint refresh:", err)
			}
			if err := rt.RefreshWireGuardHealth(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "nftfwd WireGuard health:", err)
			}
		case <-claimTicker.C:
			if _, err := rt.RefreshClaimSets(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "nftfwd claim refresh:", err)
			}
			if _, err := rt.RefreshContainerSets(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "nftfwd container refresh:", err)
			}
		case <-integrationTicker.C:
			if err := rt.RefreshIntegrations(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "nftfwd integration refresh:", err)
			}
		}
	}
}
