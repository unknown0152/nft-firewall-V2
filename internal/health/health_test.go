package health

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

type emptyRulesetRunner struct{}

func (emptyRulesetRunner) Run(context.Context, ...string) (string, string, error) {
	return `{"nftables":[]}`, "", nil
}

func TestSnapshotFailsClosedWhenOwnedTablesAreAbsent(t *testing.T) {
	store, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot, err := (Provider{Store: store, Backend: nft.New(emptyRulesetRunner{}), IPv6Mode: "disabled"}).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != "DEGRADED" || snapshot.KillSwitch != "degraded" || !snapshot.Drift || !strings.Contains(snapshot.Reason, "owned table count") {
		t.Fatalf("missing firewall did not produce a fail-closed health result: %#v", snapshot)
	}
}
