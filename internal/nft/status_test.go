package nft

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type statusRulesetRunner struct {
	mu        sync.Mutex
	documents []string
	calls     [][]string
	err       error
	next      int
	record    bool
}

func (r *statusRulesetRunner) Run(_ context.Context, args ...string) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.record {
		r.calls = append(r.calls, append([]string(nil), args...))
	}
	if r.err != nil {
		return "", "synthetic status failure", r.err
	}
	if len(r.documents) == 0 {
		return "", "", errors.New("no status document")
	}
	index := r.next
	r.next++
	if index >= len(r.documents) {
		index = len(r.documents) - 1
	}
	return r.documents[index], "", nil
}

func statusRuleset(missingMarker, unsafePolicy, foreignCollision bool) string {
	objects := []string{`{"metainfo":{"json_schema_version":1}}`}
	addTable := func(family, table string) {
		objects = append(objects, fmt.Sprintf(`{"table":{"family":%q,"name":%q}}`, family, table))
	}
	addChain := func(family, table, chain, kind, hook, policy string) {
		objects = append(objects, fmt.Sprintf(
			`{"chain":{"family":%q,"table":%q,"name":%q,"type":%q,"hook":%q,"policy":%q}}`,
			family, table, chain, kind, hook, policy,
		))
	}
	addRule := func(family, table, chain, comment, expression string) {
		if expression == "" {
			expression = `[]`
		}
		objects = append(objects, fmt.Sprintf(
			`{"rule":{"family":%q,"table":%q,"chain":%q,"comment":%q,"expr":%s}}`,
			family, table, chain, comment, expression,
		))
	}

	addTable("inet", FilterTable)
	filterPolicy := "drop"
	if unsafePolicy {
		filterPolicy = "accept"
	}
	for _, chain := range []string{"input", "output", "forward"} {
		addChain("inet", FilterTable, chain, "filter", chain, filterPolicy)
	}
	for _, marker := range [][2]string{
		{"input", "nftfw:input-default-deny"},
		{"input", "nftfw:input-reply-only"},
		{"output", "nftfw:output-default-deny"},
		{"forward", "nftfw:forward-default-deny"},
		{"forward", "nftfw:forward-physical-deny"},
		{"output", "nftfw:vpn-only-egress"},
	} {
		if !missingMarker || marker[1] != "nftfw:vpn-only-egress" {
			addRule("inet", FilterTable, marker[0], marker[1], "")
		}
	}
	for _, name := range []string{"eth0", "wg0"} {
		for _, marker := range [][2]string{
			{"input", "nftfw:provenance-tag-input:"},
			{"output", "nftfw:provenance-tag-output:"},
			{"forward", "nftfw:provenance-tag-forward:"},
			{"output", "nftfw:provenance-reply-output:"},
			{"forward", "nftfw:provenance-reply-forward:"},
		} {
			addRule("inet", FilterTable, marker[0], marker[1]+name, "")
		}
	}

	addTable("ip", NATTable)
	addChain("ip", NATTable, "prerouting", "nat", "prerouting", "accept")
	addRule("ip", NATTable, "prerouting", "nftfw:dnat-chain", "")
	addChain("ip", NATTable, "postrouting", "nat", "postrouting", "accept")
	addRule("ip", NATTable, "postrouting", "nftfw:vpn-only-nat", "")

	addTable("ip6", Filter6)
	for _, chain := range []string{"input", "output", "forward"} {
		addChain("ip6", Filter6, chain, "filter", chain, "drop")
	}
	addRule("ip6", Filter6, "input", "nftfw:ipv6-mode-disabled", "")

	if foreignCollision {
		addTable("inet", "foreign")
		addChain("inet", "foreign", "input", "filter", "input", "accept")
		addRule("inet", "foreign", "input", "foreign", `[{"match":{"op":"==","left":{"ct":{"key":"mark"}},"right":0}}]`)
	}
	return `{"nftables":[` + strings.Join(objects, ",") + `]}`
}

func TestInspectStatusUsesOneImmutableRulesetSnapshot(t *testing.T) {
	runner := &statusRulesetRunner{documents: []string{statusRuleset(false, false, false)}, record: true}
	inspection, err := New(runner).InspectStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.IntegrityOK || inspection.Fingerprint == "" || inspection.ForeignProvenanceErr != nil ||
		len(inspection.Owned) != len(OwnedTables) {
		t.Fatalf("complete status inspection failed: %#v", inspection)
	}
	if want := [][]string{{"-j", "list", "ruleset"}}; !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("status did not use exactly one ruleset read: %#v", runner.calls)
	}
}

func TestInspectStatusAdjacentSnapshotNeverInheritsHealthyState(t *testing.T) {
	runner := &statusRulesetRunner{record: true, documents: []string{
		statusRuleset(false, false, false),
		statusRuleset(true, false, false),
		statusRuleset(false, true, false),
		statusRuleset(false, false, true),
	}}
	backend := New(runner)
	first, err := backend.InspectStatus(context.Background())
	if err != nil || !first.IntegrityOK || first.ForeignProvenanceErr != nil {
		t.Fatalf("healthy first snapshot failed: %#v %v", first, err)
	}
	second, err := backend.InspectStatus(context.Background())
	if err != nil || second.IntegrityOK || !strings.Contains(second.IntegrityDetail, "missing") {
		t.Fatalf("marker removal inherited healthy state: %#v %v", second, err)
	}
	third, err := backend.InspectStatus(context.Background())
	if err != nil || third.IntegrityOK || !strings.Contains(third.IntegrityDetail, "unsafe") {
		t.Fatalf("unsafe policy inherited healthy state: %#v %v", third, err)
	}
	fourth, err := backend.InspectStatus(context.Background())
	if err != nil || !fourth.IntegrityOK || fourth.ForeignProvenanceErr == nil {
		t.Fatalf("foreign collision was hidden or contaminated owned state: %#v %v", fourth, err)
	}
	if len(runner.calls) != 4 {
		t.Fatalf("adjacent requests did not perform four fresh reads: %d", len(runner.calls))
	}
}

func TestInspectStatusFailsClosedOnReadAndDocumentErrors(t *testing.T) {
	runner := &statusRulesetRunner{documents: []string{`{"nftables":null}`}, record: true}
	if _, err := New(runner).InspectStatus(context.Background()); err == nil {
		t.Fatal("null ruleset document was accepted")
	}
	runner = &statusRulesetRunner{documents: []string{"ignored"}, err: context.DeadlineExceeded, record: true}
	if _, err := New(runner).InspectStatus(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runner failure was not preserved: %v", err)
	}
}

func BenchmarkInspectStatusSnapshot(b *testing.B) {
	runner := &statusRulesetRunner{documents: []string{statusRuleset(false, false, false)}}
	backend := New(runner)
	b.ReportAllocs()
	for b.Loop() {
		inspection, err := backend.InspectStatus(context.Background())
		if err != nil || !inspection.IntegrityOK || inspection.ForeignProvenanceErr != nil {
			b.Fatalf("status inspection failed: %#v %v", inspection, err)
		}
	}
}

func FuzzOwnedTableDocumentsNeverPanics(f *testing.F) {
	f.Add([]byte(statusRuleset(false, false, false)))
	f.Add([]byte(`{"nftables":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ownedTableDocuments(data, OwnedTables)
	})
}
