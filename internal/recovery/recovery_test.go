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
}
