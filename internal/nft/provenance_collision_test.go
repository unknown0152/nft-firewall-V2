package nft

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
)

type provenanceRulesetRunner struct {
	stdout string
	stderr string
	err    error
	calls  [][]string
}

func (r *provenanceRulesetRunner) Run(_ context.Context, args ...string) (string, string, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	return r.stdout, r.stderr, r.err
}

func TestAuditForeignProvenanceMaskReadsFullRulesetAndIgnoresOwnedTables(t *testing.T) {
	runner := &provenanceRulesetRunner{stdout: provenanceRuleset(
		provenanceRule("inet", FilterTable, "input", 10,
			`[{"match":{"op":"==","left":{"&":[{"ct":{"key":"mark"}},4278190080]},"right":16777216}}]`),
		provenanceRule("inet", "foreign_filter", "input", 11,
			`[{"match":{"op":"==","left":{"&":[{"ct":{"key":"mark"}},16777215]},"right":1}}]`),
		provenanceRule("ip", "foreign_nat", "postrouting", 12,
			`[{"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":7}}]`),
	)}

	audit, err := New(runner).AuditForeignProvenanceMask(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if audit.CollisionScope != ProvenanceCollisionScope || audit.ReservedMask != provenance.Mask {
		t.Fatalf("audit lost its explicit scope/mask: %#v", audit)
	}
	if audit.ForeignRules != 2 || audit.OwnedRulesIgnored != 1 || audit.CollidingRules != 0 {
		t.Fatalf("unexpected audit counts: %#v", audit)
	}
	wantCalls := [][]string{{"-j", "list", "ruleset"}}
	if !reflect.DeepEqual(runner.calls, wantCalls) {
		t.Fatalf("audit was not one read-only full-ruleset query: %#v", runner.calls)
	}
}

func TestAuditForeignProvenanceMaskRejectsEveryReservedAccessClass(t *testing.T) {
	tests := []struct {
		name   string
		expr   string
		reason string
	}{
		{
			name:   "whole mark read",
			expr:   `[{"match":{"op":"==","left":{"ct":{"key":"mark"}},"right":0}}]`,
			reason: "without a disjoint constant mask",
		},
		{
			name:   "reserved-byte mask",
			expr:   `[{"match":{"op":"==","left":{"&":[{"ct":{"key":"mark"}},4278190080]},"right":0}}]`,
			reason: "mask overlaps",
		},
		{
			name:   "one reserved bit",
			expr:   `[{"match":{"op":"==","left":{"&":[{"ct":{"key":"mark"}},16777216]},"right":0}}]`,
			reason: "mask overlaps",
		},
		{
			name:   "mangle write even when assigning zero",
			expr:   `[{"mangle":{"key":{"ct":{"key":"mark"}},"value":0}}]`,
			reason: "writes the reserved",
		},
		{
			name:   "ct set write",
			expr:   `[{"ct":{"key":"mark","set":0}}]`,
			reason: "writes the reserved",
		},
		{
			name:   "symbolic mask",
			expr:   `[{"match":{"op":"==","left":{"&":[{"ct":{"key":"mark"}},"@foreign_masks"]},"right":0}}]`,
			reason: "unverifiable",
		},
		{
			name:   "shifted mark",
			expr:   `[{"match":{"op":"==","left":{">>":[{"ct":{"key":"mark"}},24]},"right":1}}]`,
			reason: "without a disjoint constant mask",
		},
		{
			name:   "opaque xtables compat",
			expr:   `[{"xt":{"type":"target","name":"CONNMARK"}}]`,
			reason: "unverifiable conntrack-mark semantics",
		},
		{
			name:   "multi operand mask touches reserved byte",
			expr:   `[{"match":{"op":"==","left":{"&":[{"ct":{"key":"mark"}},16777215,4278190080]},"right":0}}]`,
			reason: "mask overlaps",
		},
	}

	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &provenanceRulesetRunner{stdout: provenanceRuleset(
				provenanceRule("inet", "foreign", "input", 100+index, test.expr),
			)}
			audit, err := New(runner).AuditForeignProvenanceMask(context.Background())
			if err == nil {
				t.Fatal("reserved conntrack-mark use passed the audit")
			}
			for _, required := range []string{ProvenanceCollisionScope, "mask=0xff000000", test.reason, `"inet"/"foreign"/"input"`} {
				if !strings.Contains(err.Error(), required) {
					t.Fatalf("collision error lacks %q: %v", required, err)
				}
			}
			if audit.CollidingRules != 1 || audit.ForeignRules != 1 {
				t.Fatalf("unexpected collision counts: %#v", audit)
			}
		})
	}
}

func TestForeignProvenanceAuditAllowsOnlyProvablyDisjointReads(t *testing.T) {
	for _, expr := range []string{
		`[{"match":{"op":"==","left":{"&":[{"ct":{"key":"mark"}},16777215]},"right":1}}]`,
		`[{"match":{"op":"==","left":{"&":[{"ct":{"key":"mark"}},"0x00ffffff"]},"right":1}}]`,
		`[{"match":{"op":"==","left":{"&":[255,{"ct":{"key":"mark"}}]},"right":1}}]`,
		`[{"match":{"op":"==","left":{"&":[{"ct":{"key":"mark"}},16777215,65535,255]},"right":1}}]`,
		`[{"match":{"op":"==","left":{"|":[{"&":[{"ct":{"key":"mark"}},65535]},1]},"right":1}}]`,
		`[{"mangle":{"key":{"meta":{"key":"mark"}},"value":{"&":[{"ct":{"key":"mark"}},16777215]}}}]`,
		`[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}}]`,
	} {
		audit, collision, err := auditForeignProvenanceRulesetJSON(
			[]byte(provenanceRuleset(provenanceRule("inet", "foreign", "input", 1, expr))),
			OwnedTables,
		)
		if err != nil || collision != nil || audit.CollidingRules != 0 {
			t.Fatalf("provably disjoint expression was rejected: expr=%s audit=%#v collision=%#v err=%v", expr, audit, collision, err)
		}
	}
}

func TestForeignProvenanceAuditMatchesOwnedTableAsExactFamilyNameTuple(t *testing.T) {
	ruleset := provenanceRuleset(
		provenanceRule("inet", FilterTable, "input", 1,
			`[{"match":{"op":"==","left":{"ct":{"key":"mark"}},"right":0}}]`),
		provenanceRule("ip", FilterTable, "input", 2,
			`[{"match":{"op":"==","left":{"ct":{"key":"mark"}},"right":0}}]`),
	)
	audit, collision, err := auditForeignProvenanceRulesetJSON([]byte(ruleset), OwnedTables)
	if err != nil {
		t.Fatal(err)
	}
	if audit.OwnedRulesIgnored != 1 || audit.ForeignRules != 1 || audit.CollidingRules != 1 {
		t.Fatalf("family/name ownership boundary was broadened: %#v", audit)
	}
	if collision == nil || collision.location.family != "ip" {
		t.Fatalf("wrong rule reported as foreign collision: %#v", collision)
	}
}

func TestForeignProvenanceAuditScansPastAnEarlierCollision(t *testing.T) {
	expr := `[
		{"match":{"op":"==","left":{"ct":{"key":"mark"}},"right":0}},
		{"match":{"op":"==","left":{"ct":"malformed"},"right":0}}
	]`
	_, _, err := auditForeignProvenanceRulesetJSON(
		[]byte(provenanceRuleset(provenanceRule("inet", "foreign", "input", 1, expr))),
		OwnedTables,
	)
	if err == nil || !strings.Contains(err.Error(), "ct descriptor is not an object") {
		t.Fatalf("later malformed expression was hidden by an earlier collision: %v", err)
	}
}

func TestForeignProvenanceAuditFailsClosedOnRulesetAndRunnerErrors(t *testing.T) {
	malformed := []string{
		``,
		`{}`,
		`{"nftables":null}`,
		`{"nftables":[]}`,
		`{"nftables":[],"extra":true}`,
		`{"nftables":[{"metainfo":{"json_schema_version":2}}]}`,
		`{"nftables":[{"metainfo":{"json_schema_version":1}},{"metainfo":{"json_schema_version":1}}]}`,
		`{"nftables":[{"metainfo":{"json_schema_version":1}},{"add":{"rule":{"family":"inet","table":"foreign","chain":"input","expr":[]}}}]}`,
		`{"nftables":[{"metainfo":{"json_schema_version":1}},{"future-object":{}}]}`,
		`{"nftables":[{"rule":{},"table":{}}]}`,
		`{"nftables":[{"metainfo":{"json_schema_version":1}},{"rule":{"family":"inet","table":"foreign","chain":"input"}}]}`,
		`{"nftables":[{"metainfo":{"json_schema_version":1}},{"rule":{"family":"inet","table":"foreign","chain":"input","expr":{}}}]}`,
		`{"nftables":[{"metainfo":{"json_schema_version":1}},{"rule":{"family":"inet","table":"foreign","chain":"input","expr":[{"mangle":{"key":{"ct":{"key":"mark"}}}}]}}]}`,
	}
	for _, document := range malformed {
		if _, _, err := auditForeignProvenanceRulesetJSON([]byte(document), OwnedTables); err == nil {
			t.Fatalf("malformed ruleset passed audit: %s", document)
		}
	}

	runner := &provenanceRulesetRunner{stderr: "permission denied", err: errors.New("exit status 1")}
	audit, err := New(runner).AuditForeignProvenanceMask(context.Background())
	if err == nil || !strings.Contains(err.Error(), ProvenanceCollisionScope) || audit.CollisionScope != ProvenanceCollisionScope {
		t.Fatalf("runner failure did not fail closed with scope: audit=%#v err=%v", audit, err)
	}
	if !reflect.DeepEqual(runner.calls, [][]string{{"-j", "list", "ruleset"}}) {
		t.Fatalf("runner failure caused unexpected calls: %#v", runner.calls)
	}
}

func TestForeignProvenanceAuditAcceptsCanonicalSchemaV1ListObjectKinds(t *testing.T) {
	var objects []string
	objects = append(objects, `{"metainfo":{"version":"test","json_schema_version":1}}`)
	for _, kind := range []string{
		"table", "chain", "set", "map", "element", "flowtable", "counter", "quota",
		"ct helper", "ct timeout", "ct expectation", "limit", "secmark", "synproxy",
	} {
		objects = append(objects, fmt.Sprintf(`{%q:{}}`, kind))
	}
	document := `{"nftables":[` + strings.Join(objects, ",") + `]}`
	audit, collision, err := auditForeignProvenanceRulesetJSON([]byte(document), OwnedTables)
	if err != nil || collision != nil || audit.ForeignRules != 0 || audit.CollidingRules != 0 {
		t.Fatalf("canonical schema-v1 list vocabulary was rejected: audit=%#v collision=%#v err=%v", audit, collision, err)
	}
}

func TestForeignProvenanceAuditCountsAllCollidingRules(t *testing.T) {
	runner := &provenanceRulesetRunner{stdout: provenanceRuleset(
		provenanceRule("inet", "one", "input", 41,
			`[{"match":{"op":"==","left":{"ct":{"key":"mark"}},"right":0}}]`),
		provenanceRule("inet", "two", "forward", 42,
			`[{"mangle":{"key":{"ct":{"key":"mark"}},"value":0}}]`),
	)}
	audit, err := New(runner).AuditForeignProvenanceMask(context.Background())
	if err == nil || audit.CollidingRules != 2 || !strings.Contains(err.Error(), "2 foreign rule(s)") || !strings.Contains(err.Error(), "handle=41") {
		t.Fatalf("audit did not inspect/count the full colliding ruleset: audit=%#v err=%v", audit, err)
	}
}

func FuzzForeignProvenanceRulesetJSONNeverPanics(f *testing.F) {
	f.Add([]byte(`{"nftables":[{"metainfo":{"json_schema_version":1}}]}`))
	f.Add([]byte(provenanceRuleset(provenanceRule("inet", "foreign", "input", 1,
		`[{"match":{"op":"==","left":{"&":[{"ct":{"key":"mark"}},16777215]},"right":0}}]`))))
	f.Add([]byte(provenanceRuleset(provenanceRule("inet", "foreign", "input", 2,
		`[{"mangle":{"key":{"ct":{"key":"mark"}},"value":0}}]`))))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = auditForeignProvenanceRulesetJSON(data, OwnedTables)
	})
}

func provenanceRule(family, table, chain string, handle int, expr string) string {
	return fmt.Sprintf(
		`{"rule":{"family":%q,"table":%q,"chain":%q,"handle":%d,"expr":%s}}`,
		family, table, chain, handle, expr,
	)
}

func provenanceRuleset(rules ...string) string {
	objects := append([]string{`{"metainfo":{"json_schema_version":1}}`}, rules...)
	return `{"nftables":[` + strings.Join(objects, ",") + `]}`
}
