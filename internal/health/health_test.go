package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

func saveHealthGeneration(t *testing.T, store *state.Store, id uint64, checksum, script string) {
	t.Helper()
	ctx := context.Background()
	assignments := []provenance.Assignment{{Name: "eth0", ID: 1}}
	ledger, err := provenance.Open(ctx, filepath.Join(store.Dir, "provenance-ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve(ctx, assignments); err != nil {
		ledger.Close()
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	bootID, err := state.CurrentBootID()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveGenerationWithMetadata(ctx, id, checksum, script, nil, nil, state.GenerationMetadata{BootID: bootID, Provenance: assignments}); err != nil {
		t.Fatal(err)
	}
}

type emptyRulesetRunner struct{}

func (emptyRulesetRunner) Run(context.Context, ...string) (string, string, error) {
	return `{"nftables":[]}`, "", nil
}

func TestSnapshotFailsClosedWhenOwnedTablesAreAbsent(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(context.Background(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot, err := (Provider{Store: store, Backend: nft.New(emptyRulesetRunner{}), IPv6Mode: "disabled"}).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != "DEGRADED" || snapshot.Active || snapshot.PolicyMatch || snapshot.KillSwitchEnforced || snapshot.KillSwitch != "degraded" || !snapshot.Drift {
		t.Fatalf("missing firewall did not produce a fail-closed health result: %#v", snapshot)
	}
	if !strings.Contains(snapshot.Reason, "no applied or committed policy generation") {
		t.Fatalf("missing generation reason was not reported: %#v", snapshot)
	}
	if snapshot.Schema != StatusSchema || snapshot.Version == "" {
		t.Fatalf("status contract metadata is missing: %#v", snapshot)
	}
}

type healthyRulesetRunner struct{}

func (healthyRulesetRunner) Run(_ context.Context, args ...string) (string, string, error) {
	joined := strings.Join(args, " ")
	if joined == "-j list tables" {
		return `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}},{"table":{"family":"ip","name":"nftfw_nat"}},{"table":{"family":"ip6","name":"nftfw_filter6"}}]}`, "", nil
	}
	if len(args) == 5 && strings.Join(args[:3], " ") == "-j list table" {
		switch args[3] + "/" + args[4] {
		case "inet/nftfw_filter":
			return `{"nftables":[
{"table":{"family":"inet","name":"nftfw_filter"}},
{"chain":{"family":"inet","table":"nftfw_filter","name":"input","type":"filter","hook":"input","policy":"drop"}},
{"chain":{"family":"inet","table":"nftfw_filter","name":"output","type":"filter","hook":"output","policy":"drop"}},
{"chain":{"family":"inet","table":"nftfw_filter","name":"forward","type":"filter","hook":"forward","policy":"drop"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"input","comment":"nftfw:input-default-deny"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"input","comment":"nftfw:input-reply-only"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"output","comment":"nftfw:output-default-deny"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"forward","comment":"nftfw:forward-default-deny"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"forward","comment":"nftfw:forward-physical-deny"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"forward","comment":"nftfw:container-vpn-mss-out-v4"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"forward","comment":"nftfw:container-vpn-mss-out-v6"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"forward","comment":"nftfw:container-vpn-mss-in-v4"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"forward","comment":"nftfw:container-vpn-mss-in-v6"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"output","comment":"nftfw:vpn-only-egress"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"input","comment":"nftfw:provenance-tag-input:eth0"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"output","comment":"nftfw:provenance-tag-output:eth0"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"forward","comment":"nftfw:provenance-tag-forward:eth0"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"output","comment":"nftfw:provenance-reply-output:eth0"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"forward","comment":"nftfw:provenance-reply-forward:eth0"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"input","comment":"nftfw:provenance-tag-input:wg0"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"output","comment":"nftfw:provenance-tag-output:wg0"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"forward","comment":"nftfw:provenance-tag-forward:wg0"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"output","comment":"nftfw:provenance-reply-output:wg0"}},
{"rule":{"family":"inet","table":"nftfw_filter","chain":"forward","comment":"nftfw:provenance-reply-forward:wg0"}}
]}`, "", nil
		case "ip/nftfw_nat":
			return `{"nftables":[
{"table":{"family":"ip","name":"nftfw_nat"}},
{"chain":{"family":"ip","table":"nftfw_nat","name":"prerouting","type":"nat","hook":"prerouting","policy":"accept"}},
{"chain":{"family":"ip","table":"nftfw_nat","name":"postrouting","type":"nat","hook":"postrouting","policy":"accept"}},
{"rule":{"family":"ip","table":"nftfw_nat","chain":"prerouting","comment":"nftfw:dnat-chain"}},
{"rule":{"family":"ip","table":"nftfw_nat","chain":"postrouting","comment":"nftfw:vpn-only-nat"}}
]}`, "", nil
		case "ip6/nftfw_filter6":
			return `{"nftables":[
{"table":{"family":"ip6","name":"nftfw_filter6"}},
{"chain":{"family":"ip6","table":"nftfw_filter6","name":"input","type":"filter","hook":"input","policy":"drop"}},
{"chain":{"family":"ip6","table":"nftfw_filter6","name":"output","type":"filter","hook":"output","policy":"drop"}},
{"chain":{"family":"ip6","table":"nftfw_filter6","name":"forward","type":"filter","hook":"forward","policy":"drop"}},
{"rule":{"family":"ip6","table":"nftfw_filter6","chain":"input","comment":"nftfw:ipv6-mode-disabled"}}
]}`, "", nil
		}
	}
	return "", "unexpected command: " + joined, nil
}

func TestSnapshotStatusContractDistinguishesPolicyFromOverallHealth(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(ctx, filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	backend := nft.New(healthyRulesetRunner{})
	fingerprint, err := backend.Fingerprint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	script := "add table inet nftfw_filter\n"
	sum := sha256.Sum256([]byte(script))
	checksum := hex.EncodeToString(sum[:])
	saveHealthGeneration(t, store, 1, checksum, script)
	if err := store.SetObservedHash(ctx, 1, fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, 1); err != nil {
		t.Fatal(err)
	}
	publication, err := store.ClaimPublicationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkClaimsPublished(ctx, publication.DesiredRevision, 0); err != nil {
		t.Fatal(err)
	}

	provider := Provider{Store: store, Backend: backend, IPv6Mode: "disabled", ZoneCount: 2, PolicyCount: 3}
	snapshot, err := provider.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != "HEALTHY" || !snapshot.Active || !snapshot.PolicyMatch || !snapshot.KillSwitchEnforced {
		t.Fatalf("healthy policy was not represented by strict booleans: %#v", snapshot)
	}
	if snapshot.ActiveGeneration != 1 || snapshot.PolicyHash != checksum || snapshot.PolicyChecksum != checksum {
		t.Fatalf("active policy identity is inconsistent: %#v", snapshot)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var contract map[string]any
	if err := json.Unmarshal(encoded, &contract); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"active", "policy_match", "kill_switch_enforced"} {
		if _, ok := contract[field].(bool); !ok {
			t.Fatalf("contract field %q is not a JSON boolean: %s", field, encoded)
		}
	}

	if err := store.SetIntegrationState(ctx, "threat-feed/test", "degraded", 0, false); err != nil {
		t.Fatal(err)
	}
	snapshot, err = provider.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != "DEGRADED" || !snapshot.Active || !snapshot.PolicyMatch || !snapshot.KillSwitchEnforced {
		t.Fatalf("integration health incorrectly changed verified kernel-policy state: %#v", snapshot)
	}
}
