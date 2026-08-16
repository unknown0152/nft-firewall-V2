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
	store, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service := Service{Store: store, Max: 10}
	if _, err := service.Add(context.Background(), "203.0.113.9", "allow", "ambiguous", "admin", nil); err == nil {
		t.Fatal("block request accepted reserved allow provenance")
	}
	if _, err := service.AddAllow(context.Background(), "203.0.113.9", "lease", "admin", nil); err != nil {
		t.Fatal(err)
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
