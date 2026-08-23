package blocks

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

func TestBlockCannotClaimAllowProvenance(t *testing.T) {
	if _, err := (Service{}).AddAllow(context.Background(), "203.0.113.9", "lease", "admin", nil); err == nil {
		t.Fatal("nil allow store accepted")
	}
	store, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service := Service{Store: store, Max: 10}
	if _, err := service.Add(context.Background(), "203.0.113.9", "allow", "ambiguous", "admin", nil); err == nil {
		t.Fatal("block request accepted reserved allow provenance")
	}
	expires := time.Now().UTC().Add(time.Minute)
	if _, err := service.AddAllow(context.Background(), "203.0.113.9", "lease", "admin", &expires); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AddAllow(context.Background(), "203.0.113.10", "permanent", "admin", nil); err == nil {
		t.Fatal("permanent temporary-access claim accepted")
	}
}

func TestConcurrentClaimLimitIsTransactional(t *testing.T) {
	store, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service := Service{Store: store, Max: 5}
	var wait sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 1; i <= 20; i++ {
		wait.Add(1)
		go func(value int) {
			defer wait.Done()
			if _, err := service.Add(context.Background(), fmt.Sprintf("198.51.100.%d", value), "manual", "limit", "admin", nil); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}(i)
	}
	wait.Wait()
	if successes != 5 {
		t.Fatalf("transactional limit admitted %d claims, want 5", successes)
	}
}

func TestBlockCanonicalizesPrefix(t *testing.T) {
	store, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service := Service{Store: store, Max: 10}
	if _, err := service.Add(context.Background(), "203.0.113.27/24", "manual", "range", "admin", nil); err != nil {
		t.Fatal(err)
	}
	claims, err := store.Claims(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 || claims[0].Address != "203.0.113.0/24" {
		t.Fatalf("prefix was not canonicalized: %#v", claims)
	}
}

func TestOperatorCannotRemoveIntegrationClaim(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	feedID, err := store.AddClaim(ctx, state.Claim{Address: "203.0.113.8/32", Family: "ipv4", Source: "threatfeed/example", Reason: "feed", Actor: "integration"})
	if err != nil {
		t.Fatal(err)
	}
	service := Service{Store: store, Max: 10}
	if err := service.Remove(ctx, feedID, "admin"); err == nil {
		t.Fatal("operator removed an integration-owned claim")
	}
	manualID, err := service.Add(ctx, "203.0.113.9", "manual", "operator", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Remove(ctx, manualID, "admin"); err != nil {
		t.Fatal(err)
	}
	claims, err := store.Claims(ctx, time.Now())
	if err != nil || len(claims) != 1 || claims[0].ID != feedID {
		t.Fatalf("unexpected claims after operator removal: %#v err=%v", claims, err)
	}
}

func TestTypedOperatorRemovalDoesNotCrossAllowAndBlockClaims(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service := Service{Store: store, Max: 10}
	blockID, err := service.Add(ctx, "203.0.113.10", "manual", "block", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Minute)
	allowID, err := service.AddAllow(ctx, "203.0.113.11", "allow", "admin", &expires)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RemoveAllow(ctx, blockID, "admin"); err == nil {
		t.Fatal("allow removal deleted a manual block")
	}
	if err := service.RemoveBlock(ctx, allowID, "admin"); err == nil {
		t.Fatal("block removal deleted an allow lease")
	}
}
