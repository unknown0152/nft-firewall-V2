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
	"strings"
	"syscall"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/app"
	"github.com/unknown0152/nft-firewall-v2/internal/bootguard"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/reconcile"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/version"
)

func main() {
	if err := candidateStartupGuard(); err != nil {
		fmt.Fprintln(os.Stderr, "nftfwd:", err)
		os.Exit(1)
	}
	config := flag.String("config", "/etc/nftfw/nftfw.toml", "configuration path")
	status := flag.String("status-socket", "/run/nftfw/status.sock", "read-only socket")
	control := flag.String("control-socket", "/run/nftfw/control.sock", "mutation socket")
	expired := flag.Bool("rollback-expired", false, "rollback an expired pending generation and exit")
	restoreActive := flag.Bool("restore-active", false, "restore the independently verified active snapshot and exit")
	recoverCommit := flag.Bool("recover-commit-publication", false, "resolve a durable commit publication during early restore")
	resolveStale := flag.Bool("resolve-stale-pending", false, "resolve stale pending state during early restore")
	verifyEnforcement := flag.Bool("verify-enforcement", false, "strictly verify committed live enforcement without mutation")
	handoffGuard := flag.Bool("handoff-initramfs-guard", false, "remove the exact initramfs deny guard after enforcement verification")
	stateDir := flag.String("state-dir", "/var/lib/nftfw", "state directory for early-boot restore mode")
	flag.Parse()
	specialModes := 0
	for _, enabled := range []bool{*expired, *restoreActive, *verifyEnforcement, *handoffGuard} {
		if enabled {
			specialModes++
		}
	}
	if flag.NArg() != 0 || specialModes > 1 || *restoreActive && (!*recoverCommit || !*resolveStale) || !*restoreActive && (*recoverCommit || *resolveStale) {
		fmt.Fprintln(os.Stderr, "nftfwd: invalid arguments")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if *handoffGuard {
		if err := handoffInitramfsGuard(ctx, *stateDir, nft.OSRunner{}); err != nil {
			fmt.Fprintln(os.Stderr, "nftfwd initramfs handoff:", err)
			os.Exit(1)
		}
		return
	}
	if *restoreActive {
		result, err := recoverAtBoot(ctx, *stateDir, state.DefaultMutationLockDir, nft.New(nil))
		if err != nil {
			fmt.Fprintln(os.Stderr, "nftfwd early boot:", err)
			os.Exit(1)
		}
		fmt.Printf("firewall recovery complete: generation=%d action=%s\n", result.Generation, result.Action)
		return
	}
	if *verifyEnforcement {
		if err := verifyEnforcementState(ctx, *stateDir, state.DefaultMutationLockDir, nft.New(nil)); err != nil {
			fmt.Fprintln(os.Stderr, "nftfwd enforcement verification:", err)
			os.Exit(1)
		}
		fmt.Println("committed firewall enforcement verified")
		return
	}
	if *expired {
		rolledBack, rollbackErr := rollbackExpiredStatic(ctx, *stateDir, state.DefaultMutationLockDir, nft.New(nil))
		if rollbackErr != nil {
			fmt.Fprintln(os.Stderr, "nftfwd rollback:", rollbackErr)
			os.Exit(1)
		}
		if rolledBack {
			fmt.Println("stale or expired generation rolled back")
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

func handoffInitramfsGuard(ctx context.Context, stateDirectory string, runner bootguard.Runner) error {
	return handoffInitramfsGuardAt(ctx, stateDirectory, state.DefaultMutationLockDir, runner)
}

func handoffInitramfsGuardAt(ctx context.Context, stateDirectory, lockDirectory string, runner bootguard.Runner) error {
	if _, err := canonicalStateDatabase(stateDirectory); err != nil {
		return err
	}
	release, err := state.AcquireMutationLock(ctx, lockDirectory)
	if err != nil {
		return err
	}
	defer release()
	_, err = bootguard.Handoff(state.WithMutationLock(ctx), runner)
	return err
}

func candidateStartupGuard() error {
	info := version.Current()
	if info.Version == "" || info.Commit == "" || info.Date == "" || info.BuildDisposition == "" {
		return errors.New("build identity is incomplete; refusing startup")
	}
	if version.IsStageRCandidateOnly() {
		return errors.New("stage R candidate-only build is quarantined and cannot start")
	}
	return nil
}

func canonicalStateDatabase(stateDirectory string) (string, error) {
	clean := filepath.Clean(stateDirectory)
	if !filepath.IsAbs(stateDirectory) || clean != stateDirectory || clean == "/" || strings.ContainsAny(stateDirectory, "?#%") {
		return "", errors.New("state directory must be an absolute, canonical, non-root path")
	}
	return filepath.Join(clean, "generation-state", "state.db"), nil
}

func foreignMarkGuard(backend *nft.Backend) func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := backend.AuditForeignProvenanceMask(ctx)
		return err
	}
}

// rollbackExpiredStatic is intentionally independent of configuration,
// daemon sockets, and the provenance writer. It locks before opening the
// existing current-schema database, never migrates, and uses the same exact
// pointer recovery protocol as the daemon and early boot.
func rollbackExpiredStatic(ctx context.Context, stateDirectory, lockDirectory string, backend *nft.Backend) (bool, error) {
	databasePath, err := canonicalStateDatabase(stateDirectory)
	if err != nil {
		return false, err
	}
	release, err := state.AcquireMutationLock(ctx, lockDirectory)
	if err != nil {
		return false, err
	}
	defer release()
	store, err := state.OpenRecovery(ctx, databasePath)
	if err != nil {
		openErr := fmt.Errorf("open current-schema rollback state: %w", err)
		if restoreErr := restoreVerifiedPointerWithoutDatabase(state.WithMutationLock(ctx), stateDirectory, backend); restoreErr != nil {
			return false, errors.Join(openErr, restoreErr)
		}
		return false, errors.Join(openErr, errors.New("verified pointer snapshot restored, but no database recovery transition was authorized"))
	}
	defer store.Close()
	manager := &reconcile.Manager{Backend: backend, Store: store, ForeignMarkGuard: foreignMarkGuard(backend), MutationLockDir: lockDirectory}
	rolledBack, recoveryErr := manager.RollbackExpired(state.WithMutationLock(ctx))
	if rolledBack {
		if _, err := store.PrepareClaimPublication(ctx); err != nil {
			return true, errors.Join(recoveryErr, fmt.Errorf("mark runtime claims unpublished after rollback: %w", err))
		}
	}
	return rolledBack, recoveryErr
}

func recoverAtBoot(ctx context.Context, stateDirectory, lockDirectory string, backend *nft.Backend) (reconcile.RecoveryResult, error) {
	databasePath, err := canonicalStateDatabase(stateDirectory)
	if err != nil {
		return reconcile.RecoveryResult{}, err
	}
	release, err := state.AcquireMutationLock(ctx, lockDirectory)
	if err != nil {
		return reconcile.RecoveryResult{}, err
	}
	defer release()
	store, err := state.OpenRecovery(ctx, databasePath)
	if err != nil {
		openErr := fmt.Errorf("open current-schema recovery state: %w", err)
		if restoreErr := restoreVerifiedPointerWithoutDatabase(state.WithMutationLock(ctx), stateDirectory, backend); restoreErr != nil {
			return reconcile.RecoveryResult{}, errors.Join(openErr, restoreErr)
		}
		return reconcile.RecoveryResult{}, errors.Join(openErr, errors.New("verified pointer snapshot restored, but readiness remains blocked until database recovery"))
	}
	defer store.Close()
	manager := &reconcile.Manager{Backend: backend, Store: store, ForeignMarkGuard: foreignMarkGuard(backend), MutationLockDir: lockDirectory}
	return manager.RecoverAtBoot(state.WithMutationLock(ctx))
}

func verifyEnforcementState(ctx context.Context, stateDirectory, lockDirectory string, backend *nft.Backend) error {
	databasePath, err := canonicalStateDatabase(stateDirectory)
	if err != nil {
		return err
	}
	release, err := state.AcquireMutationLock(ctx, lockDirectory)
	if err != nil {
		return err
	}
	defer release()
	store, err := state.OpenReadOnly(ctx, databasePath)
	if err != nil {
		return fmt.Errorf("open read-only enforcement state: %w", err)
	}
	defer store.Close()
	return reconcile.VerifyEnforcement(ctx, store, backend)
}

// restoreVerifiedPointerWithoutDatabase re-establishes only the independently
// checksummed pointer snapshot when SQLite cannot be trusted. It never guesses
// or records a generation transition and always leaves the caller returning
// nonzero, so readiness remains blocked for operator recovery.
func restoreVerifiedPointerWithoutDatabase(ctx context.Context, stateDirectory string, backend *nft.Backend) error {
	if _, err := backend.AuditForeignProvenanceMask(ctx); err != nil {
		return fmt.Errorf("foreign conntrack-mark ownership audit before database-failure restore: %w", err)
	}
	script, enabled, err := state.LoadActiveSnapshot(stateDirectory)
	if err != nil {
		return fmt.Errorf("load verified enforcement pointer without database: %w", err)
	}
	if !enabled {
		return errors.New("database is unavailable and no verified enforcement pointer exists; refusing nftables mutation")
	}
	// Re-audit immediately before installation. The shared lock serializes
	// nftfw processes, but cannot exclude an independent privileged nft writer.
	if _, err := backend.AuditForeignProvenanceMask(ctx); err != nil {
		return fmt.Errorf("foreign conntrack-mark ownership audit before database-failure install: %w", err)
	}
	if err := backend.Apply(ctx, script); err != nil {
		return fmt.Errorf("restore verified pointer snapshot without database: %w", err)
	}
	ok, detail, err := backend.Integrity(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("restored pointer snapshot failed owned-table integrity: %s", detail)
	}
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
