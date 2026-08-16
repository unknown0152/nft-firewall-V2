package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/app"
)

func main() {
	config := flag.String("config", "/etc/nftfw/nftfw.toml", "configuration path")
	status := flag.String("status-socket", "/run/nftfw/status.sock", "read-only socket")
	control := flag.String("control-socket", "/run/nftfw/control.sock", "mutation socket")
	expired := flag.Bool("rollback-expired", false, "rollback an expired pending generation and exit")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	rt, err := app.Open(ctx, *config, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nftfwd:", err)
		os.Exit(1)
	}
	defer rt.Close()
	if *expired {
		ok, err := rt.RollbackExpired(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "nftfwd:", err)
			os.Exit(1)
		}
		if ok {
			fmt.Println("expired generation rolled back")
		}
		return
	}
	if drift, reconcileErr := rt.Manager.Reconcile(ctx, true); reconcileErr != nil && !errors.Is(reconcileErr, sql.ErrNoRows) {
		fmt.Fprintln(os.Stderr, "nftfwd: initial reconciliation failed:", reconcileErr)
		os.Exit(1)
	} else if drift.Repaired {
		fmt.Fprintln(os.Stderr, "nftfwd: restored committed firewall generation at startup")
	}
	server := &api.Server{Handler: rt, StatusPath: *status, ControlPath: *control}
	go rollbackLoop(ctx, rt)
	if err := server.Serve(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "nftfwd:", err)
		os.Exit(1)
	}
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
		case <-claimTicker.C:
			if _, err := rt.RefreshClaimSets(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "nftfwd claim refresh:", err)
			}
		case <-integrationTicker.C:
			if err := rt.RefreshIntegrations(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "nftfwd integration refresh:", err)
			}
		}
	}
}
