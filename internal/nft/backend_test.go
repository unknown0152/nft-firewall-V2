package nft

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

func lockedMutationContext() context.Context {
	return state.WithMutationLock(context.Background())
}

type fakeRunner struct {
	calls   [][]string
	tables  string
	fail    bool
	scripts []string
}

func TestMutationLockWaitHonorsContext(t *testing.T) {
	runner := &fakeRunner{}
	backend := New(runner)
	release, err := backend.acquireMutationLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	ctx = state.WithMutationLock(ctx)
	err = backend.ReplaceSets(ctx, map[string][]string{"blocked_v4": {"198.51.100.7/32"}})
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "wait for nft mutation lock") {
		t.Fatalf("contended mutation ignored context deadline: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled mutation reached nft runner: %#v", runner.calls)
	}
}

func TestEveryExportedNFTMutationRequiresGlobalLockMarker(t *testing.T) {
	fake := &fakeRunner{tables: `{"nftables":[]}`}
	backend := New(fake)
	for _, test := range []struct {
		name string
		call func() error
	}{
		{name: "apply", call: func() error { return backend.Apply(context.Background(), "table inet nftfw_filter { }\n") }},
		{name: "destroy", call: func() error { return backend.DestroyOwned(context.Background()) }},
		{name: "update set", call: func() error { return backend.UpdateSet(context.Background(), "blocked_v4", true, nil) }},
		{name: "replace sets", call: func() error { return backend.ReplaceSets(context.Background(), nil) }},
		{name: "replace containers", call: func() error { return backend.ReplaceContainerNetworks(context.Background(), nil, nil) }},
		{name: "replace claims", call: func() error { return backend.ReplaceClaimSets(context.Background(), nil, nil, nil, nil) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err == nil || !strings.Contains(err.Error(), "global mutation lock") {
				t.Fatalf("unlocked mutation was not rejected: %v", err)
			}
		})
	}
	if len(fake.calls) != 0 {
		t.Fatalf("unlocked mutations reached nft runner: %#v", fake.calls)
	}
}

func (f *fakeRunner) Run(_ context.Context, args ...string) (string, string, error) {
	f.calls = append(f.calls, args)
	if len(args) >= 2 && (args[0] == "--file" || args[0] == "--check") {
		if data, err := os.ReadFile(args[len(args)-1]); err == nil {
			f.scripts = append(f.scripts, string(data))
		}
	}
	if len(args) >= 3 && args[0] == "-j" {
		return f.tables, "", nil
	}
	if f.fail {
		return "", "synthetic failure", context.Canceled
	}
	return "", "", nil
}
func TestValidateScriptRejectsGlobalFlush(t *testing.T) {
	for _, script := range []string{
		"flush ruleset\n",
		"  FlUsH\t\tRuLeSeT ;\n",
		"FLUSH\nRULESET\n",
	} {
		if err := validateScript(script); err == nil {
			t.Fatalf("global flush accepted: %q", script)
		}
	}
	if err := validateScript("table inet other { }"); err == nil {
		t.Fatal("unowned table accepted")
	}
	for _, script := range []string{
		"add chain inet other bad",
		"CrEaTe set inet other bad { type ipv4_addr; }",
		"rename chain inet other old new",
		"add chain inet nftfw_filter okay;CrEaTe chain inet other bad",
		"include \"/tmp/rules\"",
		"add element inet other blocked { 192.0.2.1 }",
		"rename table inet nftfw_filter escaped_name",
		"reset rules inet other",
		"RESET COUNTERS inet other",
		"reset flowtables inet other",
		"list table inet nftfw_filter",
		"list ruleset",
		"get element inet nftfw_filter blocked_v4 { 192.0.2.1 }",
		"import ruleset",
		"export ruleset",
		"monitor ruleset",
		"describe tcp flags",
		`add rule inet nftfw_filter input counter comment "#"; destroy table inet foreign`,
		`add rule inet nftfw_filter input counter comment "safe\\"; destroy table inet foreign; #"`,
		`add rule inet nftfw_filter input counter comment "unterminated #`,
		"flu\\\nsh ruleset",
		"incl\\\nude \"/tmp/foreign.nft\"",
		"add chain inet nftfw_filter okay; dest\\\nroy table inet foreign",
		`table inet nftfw_filter { include "/tmp/foreign.nft" }`,
	} {
		if err := validateScript(script); err == nil {
			t.Fatalf("unsafe script accepted: %s", script)
		}
	}
	if err := validateScript(`add rule inet nftfw_filter input counter comment "# retained inside quoted text"`); err != nil {
		t.Fatalf("quoted hash in an owned statement was parsed as a comment: %v", err)
	}
	if err := validateScript(`add rule inet nftfw_filter input counter comment "include table foreign; # is inert quoted text"`); err != nil {
		t.Fatalf("quoted nft keywords were interpreted as commands: %v", err)
	}
}

func TestFirstUseProtectionRefusesExistingAndRacedTableCollisions(t *testing.T) {
	ctx := lockedMutationContext()
	existing := `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`
	f := &fakeRunner{tables: existing}
	b := New(f)
	if err := b.ProtectFirstUse(ctx); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("existing first-use collision accepted: %v", err)
	}
	if len(f.scripts) != 0 {
		t.Fatalf("collision check mutated nftables: %#v", f.scripts)
	}

	f.tables = `{"nftables":[]}`
	if err := b.ProtectFirstUse(ctx); err != nil {
		t.Fatal(err)
	}
	// Recheck at candidate/apply time so a table appearing after the initial
	// inspection cannot be destroyed as though the product owned it.
	f.tables = existing
	script := "table inet nftfw_filter { }\n"
	if err := b.CheckCandidate(ctx, script); err == nil {
		t.Fatal("raced collision passed candidate validation")
	}
	if err := b.Apply(ctx, script); err == nil {
		t.Fatal("raced collision was destroyed by first apply")
	}
	if len(f.scripts) != 0 {
		t.Fatalf("raced collision reached nft execution: %#v", f.scripts)
	}

	f.tables = `{"nftables":[]}`
	if err := b.Apply(ctx, script); err != nil {
		t.Fatal(err)
	}
	// The one-shot guard disarms only after success; later reconciliation may
	// replace the now-established product table.
	f.tables = existing
	if err := b.Apply(ctx, script); err != nil {
		t.Fatalf("successful first use did not disarm collision guard: %v", err)
	}
	if len(f.scripts) != 4 || !strings.HasPrefix(f.scripts[2], "destroy table inet nftfw_filter\n") {
		t.Fatalf("unexpected guarded apply transactions: %#v", f.scripts)
	}
}

func TestEmergencyDenyScriptIsOwnedAndFailClosed(t *testing.T) {
	if err := validateScript(EmergencyDenyScript); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"table inet nftfw_filter", "table ip nftfw_nat", "table ip6 nftfw_filter6", "policy drop"} {
		if !strings.Contains(EmergencyDenyScript, required) {
			t.Fatalf("emergency script lacks %q", required)
		}
	}
	if strings.Contains(EmergencyDenyScript, "ct state established") || strings.Contains(EmergencyDenyScript, "masquerade") {
		t.Fatal("emergency script contains an egress-capable exception")
	}
}

func TestBoundedStringWriterCapsCommandOutput(t *testing.T) {
	w := boundedStringWriter{remaining: 4}
	input := []byte("123456")
	n, err := w.Write(input)
	if err != nil || n != len(input) || w.String() != "1234" || !w.exceeded {
		t.Fatalf("unexpected bounded writer result: n=%d value=%q exceeded=%t err=%v", n, w.String(), w.exceeded, err)
	}
}

func TestReplaceClaimSetsEncodesKernelTimeoutAtomically(t *testing.T) {
	f := &fakeRunner{}
	b := New(f)
	if err := b.ReplaceClaimSets(lockedMutationContext(), []string{"203.0.113.8/32"}, nil, []TimedElement{{Prefix: "198.51.100.4/32", TimeoutSeconds: 90}}, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.scripts) != 2 || f.scripts[0] != f.scripts[1] {
		t.Fatalf("claim set check/apply transactions differ: %#v", f.scripts)
	}
	for _, want := range []string{"flush set inet nftfw_filter blocked_v4", "203.0.113.8/32", "198.51.100.4/32 timeout 90s"} {
		if !strings.Contains(f.scripts[0], want) {
			t.Fatalf("claim transaction lacks %q: %s", want, f.scripts[0])
		}
	}
	if err := b.ReplaceClaimSets(lockedMutationContext(), nil, nil, []TimedElement{{Prefix: "198.51.100.4/32", TimeoutSeconds: -1}}, nil); err == nil {
		t.Fatal("negative kernel lease timeout accepted")
	}
}
func TestApplyDestroysOnlyOwnedTables(t *testing.T) {
	f := &fakeRunner{tables: `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}},{"table":{"family":"ip","name":"third_party"}}]}`}
	b := New(f)
	script := "table inet nftfw_filter { }\n"
	if err := b.Apply(lockedMutationContext(), script); err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, call := range f.calls {
		if strings.Contains(strings.Join(call, " "), "--file") {
			seen = true
		}
	}
	if !seen {
		t.Fatal("apply call missing")
	}
	if len(f.scripts) != 2 || !strings.HasPrefix(f.scripts[0], "destroy table inet nftfw_filter\n") || strings.Contains(f.scripts[0], "third_party") || f.scripts[0] != f.scripts[1] {
		t.Fatalf("check/apply did not use the exact owned-table transaction: %#v", f.scripts)
	}
}

func TestCheckCandidateUsesApplyTransactionWithoutApplying(t *testing.T) {
	f := &fakeRunner{tables: `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`}
	if err := New(f).CheckCandidate(context.Background(), "table inet nftfw_filter { }\n"); err != nil {
		t.Fatal(err)
	}
	if len(f.scripts) != 1 || !strings.HasPrefix(f.scripts[0], "destroy table inet nftfw_filter\n") {
		t.Fatalf("candidate check did not model replacement: %#v", f.scripts)
	}
	for _, call := range f.calls {
		if len(call) > 0 && call[0] == "--file" {
			t.Fatal("candidate check applied the transaction")
		}
	}
}
func TestDestroyOwnedNoopsWhenAbsent(t *testing.T) {
	f := &fakeRunner{tables: `{"nftables":[]}`}
	if err := New(f).DestroyOwned(lockedMutationContext()); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("unexpected calls: %#v", f.calls)
	}
}

func TestReplaceSetsRejectsWrongFamilyAndUsesOneApply(t *testing.T) {
	f := &fakeRunner{}
	b := New(f)
	if err := b.ReplaceSets(lockedMutationContext(), map[string][]string{"wg_bootstrap_v4": {"2001:db8::1/128"}}); err == nil {
		t.Fatal("wrong-family endpoint accepted")
	}
	if err := b.ReplaceSets(lockedMutationContext(), map[string][]string{"wg_bootstrap_v4": {"198.51.100.10/32"}, "wg_bootstrap_v6": {"2001:db8::10/128"}}); err != nil {
		t.Fatal(err)
	}
	var checks, applies int
	for _, call := range f.calls {
		if len(call) > 0 && call[0] == "--check" {
			checks++
		}
		if len(call) > 0 && call[0] == "--file" {
			applies++
		}
	}
	if checks != 1 || applies != 1 {
		t.Fatalf("runtime sets were not one checked transaction: checks=%d applies=%d calls=%v", checks, applies, f.calls)
	}
}

func TestReplaceContainerNetworksUsesOneCrossTableTransaction(t *testing.T) {
	f := &fakeRunner{}
	if err := New(f).ReplaceContainerNetworks(lockedMutationContext(), []string{"172.19.0.0/16"}, []string{"fd00:19::/64"}); err != nil {
		t.Fatal(err)
	}
	if len(f.scripts) != 2 || f.scripts[0] != f.scripts[1] {
		t.Fatalf("container update was not checked and applied as one transaction: %#v", f.scripts)
	}
	for _, want := range []string{"flush set inet nftfw_filter docker_nets", "flush set ip nftfw_nat docker_nets_nat", "172.19.0.0/16", "fd00:19::/64"} {
		if !strings.Contains(f.scripts[0], want) {
			t.Fatalf("container transaction missing %q: %s", want, f.scripts[0])
		}
	}
}

type integrityRunner struct {
	missingMarker bool
	unsafePolicy  bool
}

func (r integrityRunner) Run(_ context.Context, args ...string) (string, string, error) {
	if len(args) == 3 {
		return `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}},{"table":{"family":"ip","name":"nftfw_nat"}},{"table":{"family":"ip6","name":"nftfw_filter6"}}]}`, "", nil
	}
	family, name := args[len(args)-2], args[len(args)-1]
	policy := "drop"
	if r.unsafePolicy && family == "inet" {
		policy = "accept"
	}
	var objects []string
	addChain := func(chain, typ, hook, chainPolicy, comment string) {
		objects = append(objects, fmt.Sprintf(`{"chain":{"family":%q,"table":%q,"name":%q,"type":%q,"hook":%q,"policy":%q,"comment":%q}}`, family, name, chain, typ, hook, chainPolicy, comment))
	}
	addRule := func(chain, comment string) {
		objects = append(objects, fmt.Sprintf(`{"rule":{"family":%q,"table":%q,"chain":%q,"comment":%q}}`, family, name, chain, comment))
	}
	switch family + "/" + name {
	case "inet/nftfw_filter":
		for _, chain := range []string{"input", "output", "forward"} {
			addChain(chain, "filter", chain, policy, "")
		}
		for _, item := range [][2]string{{"input", "nftfw:input-default-deny"}, {"input", "nftfw:input-reply-only"}, {"output", "nftfw:output-default-deny"}, {"forward", "nftfw:forward-default-deny"}, {"forward", "nftfw:forward-physical-deny"}, {"output", "nftfw:vpn-only-egress"}} {
			if !r.missingMarker || item[1] != "nftfw:vpn-only-egress" {
				addRule(item[0], item[1])
			}
		}
		for _, interfaceName := range []string{"eth0", "wg0"} {
			for _, marker := range [][2]string{
				{"input", "nftfw:provenance-tag-input:"},
				{"output", "nftfw:provenance-tag-output:"},
				{"forward", "nftfw:provenance-tag-forward:"},
				{"output", "nftfw:provenance-reply-output:"},
				{"forward", "nftfw:provenance-reply-forward:"},
			} {
				addRule(marker[0], marker[1]+interfaceName)
			}
		}
	case "ip/nftfw_nat":
		addChain("prerouting", "nat", "prerouting", "accept", "")
		addRule("prerouting", "nftfw:dnat-chain")
		addChain("postrouting", "nat", "postrouting", "accept", "")
		addRule("postrouting", "nftfw:vpn-only-nat")
	case "ip6/nftfw_filter6":
		for _, chain := range []string{"input", "output", "forward"} {
			addChain(chain, "filter", chain, "drop", "")
		}
		addRule("input", "nftfw:ipv6-mode-disabled")
	}
	return `{"nftables":[` + strings.Join(objects, ",") + `]}`, "", nil
}
func TestIntegrityDetectsRuleTampering(t *testing.T) {
	ok, _, err := New(integrityRunner{}).Integrity(context.Background())
	if err != nil || !ok {
		t.Fatalf("clean integrity failed: ok=%t err=%v", ok, err)
	}
	ok, detail, err := New(integrityRunner{missingMarker: true}).Integrity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ok || !strings.Contains(detail, "missing") {
		t.Fatalf("tampering not detected: ok=%t detail=%s", ok, detail)
	}
	ok, detail, err = New(integrityRunner{unsafePolicy: true}).Integrity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ok || !strings.Contains(detail, "unsafe") {
		t.Fatalf("unsafe base-chain policy not detected: ok=%t detail=%s", ok, detail)
	}
}

func FuzzValidateScript(f *testing.F) {
	f.Add("table inet nftfw_filter { }\n")
	f.Add("flush ruleset\n")
	f.Fuzz(func(t *testing.T, script string) {
		_ = validateScript(script)
	})
}
