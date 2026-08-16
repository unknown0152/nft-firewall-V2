package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

func TestIntegrationRefreshScheduleUsesDurableState(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runtime := &Runtime{Store: store}
	if !runtime.integrationDue(ctx, "threatfeed/test", 60) {
		t.Fatal("new integration was not due")
	}
	if err := store.SetIntegrationState(ctx, "threatfeed/test", "healthy", 4, true); err != nil {
		t.Fatal(err)
	}
	if runtime.integrationDue(ctx, "threatfeed/test", 60) {
		t.Fatal("fresh integration was refreshed before its interval")
	}
	old := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := store.DB.ExecContext(ctx, "UPDATE integration_state SET updated_at=? WHERE name=?", old, "threatfeed/test"); err != nil {
		t.Fatal(err)
	}
	if !runtime.integrationDue(ctx, "threatfeed/test", 60) {
		t.Fatal("stale integration was not due")
	}
}

func TestClaimExpiryBounds(t *testing.T) {
	if expires, err := claimExpiry(0); err != nil || expires != nil {
		t.Fatalf("permanent expiry rejected: %v %v", expires, err)
	}
	if expires, err := claimExpiry(60); err != nil || expires == nil || time.Until(*expires) <= 0 {
		t.Fatalf("temporary expiry rejected: %v %v", expires, err)
	}
	if _, err := claimExpiry(365*24*60*60 + 1); err == nil {
		t.Fatal("unbounded claim expiry accepted")
	}
}
