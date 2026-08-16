package reconcile

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/compiler"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

type runner struct {
	failApply bool
	failCheck bool
}

func (r *runner) Run(_ context.Context, args ...string) (string, string, error) {
	if len(args) >= 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		return `{"nftables":[]}`, "", nil
	}
	if len(args) == 5 && args[0] == "-j" && args[1] == "list" && args[2] == "table" {
		return fmt.Sprintf(`{"nftables":[{"table":{"family":%q,"name":%q}}]}`, args[3], args[4]), "", nil
	}
	if len(args) > 0 && args[0] == "--file" && r.failApply {
		return "", "synthetic", sql.ErrConnDone
	}
	if len(args) > 0 && args[0] == "--check" && r.failCheck {
		return "", "synthetic check failure", sql.ErrConnDone
	}
	return "", "", nil
}
func artifact(id uint64) compiler.Artifact {
	script := "table inet nftfw_filter { }\ntable ip nftfw_nat { }\ntable ip6 nftfw_filter6 { }\n"
	sum := sha256.Sum256([]byte(script))
	return compiler.Artifact{Generation: id, Checksum: hex.EncodeToString(sum[:]), Script: script}
}
func newManager(t *testing.T) (*Manager, *state.Store, *runner) {
	t.Helper()
	s, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{}
	return &Manager{Backend: nft.New(r), Store: s, SafeTTL: time.Millisecond, SafeGuard: func(context.Context) error { return nil }}, s, r
}
func TestSafeApplyCommitAndTimeoutRollback(t *testing.T) {
	ctx := context.Background()
	m, s, _ := newManager(t)
	defer s.Close()
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	res, err := m.Apply(ctx, artifact(2), true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Deadline == nil || res.Committed {
		t.Fatalf("bad safe result: %#v", res)
	}
	time.Sleep(3 * time.Millisecond)
	ok, err := m.RollbackExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expired candidate not rolled back")
	}
	g, err := s.LastKnownGood(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if g.ID != 1 {
		t.Fatalf("last known good changed: %d", g.ID)
	}
}
func TestSafeApplyCommit(t *testing.T) {
	ctx := context.Background()
	m, s, _ := newManager(t)
	defer s.Close()
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(ctx, artifact(2), true); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(ctx, 2); err != nil {
		t.Fatal(err)
	}
	g, err := s.LastKnownGood(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if g.ID != 2 {
		t.Fatalf("committed generation %d", g.ID)
	}
}
func TestApplyFailureRetainsCommitted(t *testing.T) {
	ctx := context.Background()
	m, s, r := newManager(t)
	defer s.Close()
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	r.failApply = true
	if _, err := m.Apply(ctx, artifact(2), true); err == nil {
		t.Fatal("apply failure accepted")
	}
	g, err := s.LastKnownGood(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if g.ID != 1 {
		t.Fatalf("committed generation changed: %d", g.ID)
	}
}

func TestHealthFailureRollsBackCandidate(t *testing.T) {
	ctx := context.Background()
	m, s, _ := newManager(t)
	defer s.Close()
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	m.HealthCheck = func(context.Context) error { return context.Canceled }
	if _, err := m.Apply(ctx, artifact(2), true); err == nil {
		t.Fatal("unhealthy candidate accepted")
	}
	g, err := s.LastKnownGood(ctx)
	if err != nil || g.ID != 1 {
		t.Fatalf("known-good generation was not restored: %#v, %v", g, err)
	}
}

func TestPendingGenerationSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := state.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{}
	past := time.Now().Add(-time.Hour)
	m := &Manager{Backend: nft.New(r), Store: s, SafeTTL: time.Minute, Now: func() time.Time { return past }, SafeGuard: func(context.Context) error { return nil }}
	if _, err := m.Apply(ctx, artifact(1), true); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = state.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m = &Manager{Backend: nft.New(r), Store: s}
	ok, err := m.RollbackExpired(ctx)
	if err != nil || !ok {
		t.Fatalf("restarted controller did not roll back persistent pending generation: ok=%t err=%v", ok, err)
	}
	if err := m.Rollback(ctx, 1); err != nil {
		t.Fatalf("rollback was not idempotent: %v", err)
	}
}

func TestKernelCheckFailureRetainsCommitted(t *testing.T) {
	ctx := context.Background()
	m, s, r := newManager(t)
	defer s.Close()
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	r.failCheck = true
	if _, err := m.Apply(ctx, artifact(2), true); err == nil {
		t.Fatal("kernel check failure accepted")
	}
	g, err := s.LastKnownGood(ctx)
	if err != nil || g.ID != 1 {
		t.Fatalf("known-good generation changed after check failure: %#v, %v", g, err)
	}
}

func TestSafeApplyRequiresIndependentGuard(t *testing.T) {
	m, s, _ := newManager(t)
	defer s.Close()
	m.SafeGuard = nil
	if _, err := m.Apply(context.Background(), artifact(1), true); err == nil {
		t.Fatal("safe apply without independent rollback guard was accepted")
	}
	m.SafeGuard = func(context.Context) error { return context.Canceled }
	if _, err := m.Apply(context.Background(), artifact(1), true); err == nil {
		t.Fatal("safe apply with failed rollback guard was accepted")
	}
}

func TestPersistedButUnappliedGenerationRollsBackOnStartup(t *testing.T) {
	ctx := context.Background()
	m, store, _ := newManager(t)
	defer store.Close()
	if _, err := m.Apply(ctx, artifact(1), false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	previous := uint64(1)
	if err := store.SaveGeneration(ctx, 2, artifact(2).Checksum, artifact(2).Script, &previous, &deadline); err != nil {
		t.Fatal(err)
	}
	drift, err := m.Reconcile(ctx, true)
	if err != nil || !drift.Repaired {
		t.Fatalf("incomplete candidate was not rolled back: %#v %v", drift, err)
	}
	pending, err := store.Pending(ctx)
	if !errors.Is(err, sql.ErrNoRows) || pending != nil {
		t.Fatalf("incomplete candidate remains pending: %#v %v", pending, err)
	}
}

func TestCommitRejectsPersistedButUnappliedGeneration(t *testing.T) {
	ctx := context.Background()
	m, store, _ := newManager(t)
	defer store.Close()
	if err := store.SaveGeneration(ctx, 1, artifact(1).Checksum, artifact(1).Script, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(ctx, 1); err == nil {
		t.Fatal("unapplied generation was committed")
	}
}
