package recovery

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestSystemdGuardRequiresEnabledAndActiveTimer(t *testing.T) {
	var calls [][]string
	inspectCalls := 0
	guard := SystemdGuard{Run: func(_ context.Context, args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		return nil
	}, Inspect: func(context.Context, ...string) (string, error) {
		inspectCalls++
		return "{ path=/usr/lib/nftfw/nftfwd ; argv[]=/usr/lib/nftfw/nftfwd --rollback-expired --state-dir /var/lib/nftfw ; ignore_errors=no ; }", nil
	}}
	if err := guard.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"is-enabled", "--quiet", "nftfw-rollback.timer"},
		{"is-active", "--quiet", "nftfw-rollback.timer"},
		{"start", "--quiet", "nftfw-rollback.service"},
		{"is-enabled", "--quiet", "nftfw-rollback.timer"},
		{"is-active", "--quiet", "nftfw-rollback.timer"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("unexpected systemd checks: %#v", calls)
	}
	if inspectCalls != 2 {
		t.Fatalf("unit identity was not revalidated: calls=%d", inspectCalls)
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
	guard.StateDir = "/var/lib/nftfw/other"
	if err := guard.Verify(context.Background()); err == nil {
		t.Fatal("rollback service protecting a different database was accepted")
	}
}

func TestExecStartStateDirMatchIsExact(t *testing.T) {
	line := "{ path=/usr/lib/nftfw/nftfwd ; argv[]=/usr/lib/nftfw/nftfwd --rollback-expired --state-dir /var/lib/nftfw ; ignore_errors=no ; }"
	if !execStartUsesStateDir(line, "/var/lib/nftfw") {
		t.Fatal("exact rollback state root was not recognized")
	}
	for _, invalid := range []string{
		"argv[]=/usr/lib/nftfw/nftfwd --rollback-expired --state-dir /var/lib/nft ;",
		"argv[]=/usr/lib/nftfw/nftfwd --state-dir /var/lib/nftfw ;",
		"argv[]=/usr/local/bin/nftfwd --rollback-expired --state-dir /var/lib/nftfw ;",
		"argv[]=/usr/lib/nftfw/nftfwd --restore-active --rollback-expired --state-dir /var/lib/nftfw ;",
		"argv[]=/usr/lib/nftfw/nftfwd --rollback-expired --state-dir /var/lib/nftfw --extra ;",
		"argv[]=/usr/lib/nftfw/nftfwd --rollback-expired --state-dir /var/lib/nftfw ; argv[]=/usr/lib/nftfw/nftfwd --rollback-expired --state-dir /var/lib/nftfw ;",
		"argv[]=/usr/lib/nftfw/nftfwd --rollback-expired --state-dir /var/lib/nftfw",
	} {
		if execStartUsesStateDir(invalid, "/var/lib/nftfw") {
			t.Fatalf("unsafe ExecStart presentation was accepted: %s", invalid)
		}
	}
}

func TestSystemdGuardSplitsExecutablePreflightFromLockedRevalidation(t *testing.T) {
	var starts int
	guard := SystemdGuard{
		Run: func(_ context.Context, args ...string) error {
			if len(args) > 0 && args[0] == "start" {
				starts++
			}
			return nil
		},
		Inspect: func(context.Context, ...string) (string, error) {
			return "argv[]=/usr/lib/nftfw/nftfwd --rollback-expired --state-dir /var/lib/nftfw ;", nil
		},
	}
	if err := guard.Preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	if starts != 1 {
		t.Fatalf("preflight start count=%d, want 1", starts)
	}
	if err := guard.Revalidate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if starts != 1 {
		t.Fatalf("locked revalidation started the rollback service: count=%d", starts)
	}
}
