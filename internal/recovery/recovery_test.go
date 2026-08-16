package recovery

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestSystemdGuardRequiresEnabledAndActiveTimer(t *testing.T) {
	var calls [][]string
	guard := SystemdGuard{Run: func(_ context.Context, args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		return nil
	}, Inspect: func(context.Context, ...string) (string, error) {
		return "argv[]=/usr/lib/nftfw/nftfwd --rollback-expired --state-db /var/lib/nftfw/state.db ;", nil
	}}
	if err := guard.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"is-enabled", "--quiet", "nftfw-rollback.timer"}, {"is-active", "--quiet", "nftfw-rollback.timer"}, {"start", "--quiet", "nftfw-rollback.service"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("unexpected systemd checks: %#v", calls)
	}
	guard.Run = func(_ context.Context, args ...string) error {
		if args[0] == "is-active" {
			return errors.New("inactive")
		}
		return nil
	}
	if err := guard.Verify(context.Background()); err == nil {
		t.Fatal("inactive rollback timer accepted")
	}
	guard.Run = func(_ context.Context, args ...string) error {
		if args[0] == "start" {
			return errors.New("service failed")
		}
		return nil
	}
	if err := guard.Verify(context.Background()); err == nil {
		t.Fatal("failed rollback service preflight accepted")
	}
	guard.Run = func(context.Context, ...string) error { return nil }
	guard.StateDB = "/var/lib/nftfw/other.db"
	if err := guard.Verify(context.Background()); err == nil {
		t.Fatal("rollback service protecting a different database was accepted")
	}
}

func TestExecStartStateDBMatchIsExact(t *testing.T) {
	line := "argv[]=/usr/lib/nftfw/nftfwd --rollback-expired --state-db /var/lib/nftfw/state.db ;"
	if !execStartUsesStateDB(line, "/var/lib/nftfw/state.db") {
		t.Fatal("exact rollback database was not recognized")
	}
	if execStartUsesStateDB(line, "/var/lib/nftfw/state") {
		t.Fatal("partial rollback database match was accepted")
	}
}
