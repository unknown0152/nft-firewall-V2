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
	store, err := state.Open(context.Background(), filepath.Join(secureTestDir(t), "state.db"))
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
	store, err := state.Open(context.Background(), filepath.Join(secureTestDir(t), "state.db"))
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
	store, err := state.Open(context.Background(), filepath.Join(secureTestDir(t), "state.db"))
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
	store, err := state.Open(ctx, filepath.Join(secureTestDir(t), "state.db"))
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
	store, err := state.Open(ctx, filepath.Join(secureTestDir(t), "state.db"))
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

func TestEffectiveProjectsIPv4AndIPv6Blocks(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(ctx, filepath.Join(secureTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service := Service{Store: store, Max: 10}
	if _, err := service.Add(ctx, "192.0.2.10", "manual", "v4", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Add(ctx, "2001:db8::10", "manual", "v6", "admin", nil); err != nil {
		t.Fatal(err)
	}
	v4, v6, err := service.Effective(ctx)
	if err != nil || len(v4) != 1 || v4[0] != "192.0.2.10/32" ||
		len(v6) != 1 || v6[0] != "2001:db8::10/128" {
		t.Fatalf("unexpected effective blocks: %v %v %v", v4, v6, err)
	}
	if _, _, err := (Service{}).Effective(ctx); err == nil {
		t.Fatal("effective blocks accepted a nil store")
	}
}
