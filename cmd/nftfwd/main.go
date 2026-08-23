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
		st, err := state.Open(ctx, *stateDB)
		if err != nil {
			if fallbackErr := restoreRollbackFallback(ctx, filepath.Dir(*stateDB), nft.New(nil)); fallbackErr != nil {
				fmt.Fprintln(os.Stderr, "nftfwd rollback: state unavailable and fallback failed:", fallbackErr)
				os.Exit(1)
			}
			fmt.Fprintln(os.Stderr, "nftfwd rollback: state unavailable; restored the independent committed fallback")
			return
		}
		defer st.Close()
		manager := &reconcile.Manager{Backend: nft.New(nil), Store: st}
		ok, err := manager.RollbackExpired(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "nftfwd rollback:", err)
			os.Exit(1)
		}
		if ok {
			fmt.Println("expired generation rolled back")
		}
		return
	}
	rt, err := app.Open(ctx, *config, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nftfwd:", err)
		os.Exit(1)
	}
	defer rt.Close()
	if drift, reconcileErr := rt.Manager.Reconcile(ctx, true); reconcileErr != nil && !errors.Is(reconcileErr, sql.ErrNoRows) {
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

func restoreRollbackFallback(ctx context.Context, directory string, backend *nft.Backend) error {
	script, enabled, err := state.LoadActiveSnapshot(directory)
	if err != nil {
		if applyErr := backend.Apply(ctx, nft.EmergencyDenyScript); applyErr != nil {
			return fmt.Errorf("invalid active snapshot and emergency deny failed: %w", applyErr)
		}
		return nil
	}
	if !enabled {
		return backend.DestroyOwned(ctx)
	}
	return backend.Apply(ctx, script)
}

func restoreAtBoot(ctx context.Context, directory string) error {
	script, enabled, err := state.LoadActiveSnapshot(directory)
	backend := nft.New(nil)
	if err != nil {
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
			drift, err := rt.Manager.Reconcile(ctx, true)
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
