// Package nft is the only package allowed to mutate nftables.
package nft

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Runner interface {
	Run(ctx context.Context, args ...string) (stdout, stderr string, err error)
}

type OSRunner struct{ Binary string }

const (
	maxNFTStdout = 32 << 20
	maxNFTStderr = 1 << 20
)

func (r OSRunner) Run(ctx context.Context, args ...string) (string, string, error) {
	bin := r.Binary
	if bin == "" {
		bin = "nft"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	var out, errOut boundedStringWriter
	out.remaining = maxNFTStdout
	errOut.remaining = maxNFTStderr
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	if out.exceeded || errOut.exceeded {
		return out.String(), errOut.String(), errors.New("nft command output exceeded its safety limit")
	}
	return out.String(), errOut.String(), err
}

type boundedStringWriter struct {
	strings.Builder
	remaining int
	exceeded  bool
}

func (w *boundedStringWriter) Write(p []byte) (int, error) {
	original := len(p)
	if len(p) > w.remaining {
		p = p[:w.remaining]
		w.exceeded = true
	}
	if len(p) > 0 {
		_, _ = w.Builder.Write(p)
		w.remaining -= len(p)
	}
	return original, nil
}

type Backend struct {
	Runner  Runner
	TempDir string
	Timeout time.Duration
	Owned   []Table
	mu      sync.Mutex
}

type Table struct{ Family, Name string }

const (
	FilterTable = "nftfw_filter"
	NATTable    = "nftfw_nat"
	Filter6     = "nftfw_filter6"
)

var OwnedTables = []Table{{"inet", "nftfw_filter"}, {"ip", "nftfw_nat"}, {"ip6", "nftfw_filter6"}}

func New(r Runner) *Backend {
	if r == nil {
		r = OSRunner{}
	}
	return &Backend{Runner: r, Timeout: 15 * time.Second, Owned: append([]Table(nil), OwnedTables...)}
}

func (b *Backend) Check(ctx context.Context, script string) error {
	if err := validateScript(script); err != nil {
		return err
	}
	path, cleanup, err := b.tempScript(script, "nftfw-check-")
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	_, stderr, runErr := b.Runner.Run(ctx, "--check", "--file", path)
	if runErr != nil {
		return fmt.Errorf("nft --check failed: %s: %w", strings.TrimSpace(stderr), runErr)
	}
	return nil
}

func (b *Backend) Apply(ctx context.Context, script string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := validateScript(script); err != nil {
		return err
	}
	owned, err := b.ExistingOwned(ctx)
	if err != nil {
		return fmt.Errorf("inspect owned nft tables: %w", err)
	}
	transaction := prependDestroy(script, owned, b.Owned)
	if err := validateScript(transaction); err != nil {
		return err
	}
	if err := b.Check(ctx, transaction); err != nil {
		return err
	}
	path, cleanup, err := b.tempScript(transaction, "nftfw-apply-")
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	_, stderr, runErr := b.Runner.Run(ctx, "--file", path)
	if runErr != nil {
		return fmt.Errorf("nft apply failed: %s: %w", strings.TrimSpace(stderr), runErr)
	}
	return nil
}

// CheckCandidate validates the exact destroy-owned/create transaction Apply
// would execute, but does not mutate nftables.
func (b *Backend) CheckCandidate(ctx context.Context, script string) error {
	if err := validateScript(script); err != nil {
		return err
	}
	owned, err := b.ExistingOwned(ctx)
	if err != nil {
		return fmt.Errorf("inspect owned nft tables: %w", err)
	}
	transaction := prependDestroy(script, owned, b.Owned)
	if err := validateScript(transaction); err != nil {
		return err
	}
	return b.Check(ctx, transaction)
}

// DestroyOwned removes only tables belonging to this product. It is used when
// rolling back the first generation or uninstalling with explicit intent.
func (b *Backend) DestroyOwned(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	existing, err := b.ExistingOwned(ctx)
	if err != nil {
		return err
	}
	var script strings.Builder
	for _, t := range b.Owned {
		if existing[t.Family+"/"+t.Name] {
			fmt.Fprintf(&script, "destroy table %s %s\n", t.Family, t.Name)
		}
	}
	if script.Len() == 0 {
		return nil
	}
	path, cleanup, err := b.tempScript(script.String(), "nftfw-destroy-")
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	_, stderr, runErr := b.Runner.Run(ctx, "--file", path)
	if runErr != nil {
		return fmt.Errorf("destroy owned tables failed: %s: %w", strings.TrimSpace(stderr), runErr)
	}
	return nil
}

func (b *Backend) UpdateSet(ctx context.Context, name string, add bool, elements []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	allowed := map[string]string{"blocked_v4": "ipv4", "blocked_v6": "ipv6", "trusted_v4": "ipv4", "trusted_v6": "ipv6", "wg_bootstrap_v4": "ipv4", "wg_bootstrap_v6": "ipv6", "docker_nets": "ipv4", "docker_nets6": "ipv6"}
	family, ok := allowed[name]
	if !ok {
		return fmt.Errorf("set %q is not owned", name)
	}
	if len(elements) == 0 {
		return nil
	}
	clean := make([]string, 0, len(elements))
	for _, raw := range elements {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.Bits() == 0 {
			return fmt.Errorf("invalid set element %q", raw)
		}
		if (family == "ipv4" && !p.Addr().Is4()) || (family == "ipv6" && !p.Addr().Is6()) {
			return fmt.Errorf("set %s contains wrong-family element %q", name, raw)
		}
		if strings.HasPrefix(name, "wg_bootstrap_") && p.Bits() != p.Addr().BitLen() {
			return fmt.Errorf("set %s requires host-prefix elements", name)
		}
		clean = append(clean, raw)
	}
	action := "delete"
	if add {
		action = "add"
	}
	script := fmt.Sprintf("%s element inet %s %s { %s }\n", action, FilterTable, name, strings.Join(clean, ", "))
	if err := validateScript(script); err != nil {
		return err
	}
	if err := b.Check(ctx, script); err != nil {
		return err
	}
	path, cleanup, err := b.tempScript(script, "nftfw-set-")
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	_, stderr, runErr := b.Runner.Run(ctx, "--file", path)
	if runErr != nil {
		return fmt.Errorf("nft set update failed: %s: %w", strings.TrimSpace(stderr), runErr)
	}
	return nil
}

// ReplaceSets atomically replaces bounded runtime-set contents without
// recompiling chains. Only compiler-owned inet sets are accepted.
func (b *Backend) ReplaceSets(ctx context.Context, sets map[string][]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	allowed := map[string]string{
		"blocked_v4": "ipv4", "blocked_v6": "ipv6", "trusted_v4": "ipv4", "trusted_v6": "ipv6",
		"wg_bootstrap_v4": "ipv4", "wg_bootstrap_v6": "ipv6", "docker_nets": "ipv4", "docker_nets6": "ipv6",
	}
	names := make([]string, 0, len(sets))
	for name := range sets {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("set %q is not owned", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	var script strings.Builder
	for _, name := range names {
		values := append([]string(nil), sets[name]...)
		sort.Strings(values)
		for _, raw := range values {
			p, err := netip.ParsePrefix(raw)
			if err != nil || p.Bits() == 0 {
				return fmt.Errorf("invalid set element %q", raw)
			}
			if (allowed[name] == "ipv4" && !p.Addr().Is4()) || (allowed[name] == "ipv6" && !p.Addr().Is6()) {
				return fmt.Errorf("set %s contains wrong-family element %q", name, raw)
			}
			if strings.HasPrefix(name, "wg_bootstrap_") && p.Bits() != p.Addr().BitLen() {
				return fmt.Errorf("set %s requires host-prefix elements", name)
			}
		}
		fmt.Fprintf(&script, "flush set inet %s %s\n", FilterTable, name)
		if len(values) > 0 {
			fmt.Fprintf(&script, "add element inet %s %s { %s }\n", FilterTable, name, strings.Join(values, ", "))
		}
	}
	if script.Len() == 0 {
		return nil
	}
	if err := b.Check(ctx, script.String()); err != nil {
		return err
	}
	path, cleanup, err := b.tempScript(script.String(), "nftfw-sets-")
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	_, stderr, runErr := b.Runner.Run(ctx, "--file", path)
	if runErr != nil {
		return fmt.Errorf("nft set replacement failed: %s: %w", strings.TrimSpace(stderr), runErr)
	}
	return nil
}

// ReplaceContainerNetworks updates filter and NAT membership in one atomic
// transaction so a recreated bridge never has split enforcement state.
func (b *Backend) ReplaceContainerNetworks(ctx context.Context, v4, v6 []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	sets := []struct {
		family string
		table  string
		name   string
		values []string
		ipv4   bool
	}{
		{"inet", FilterTable, "docker_nets", v4, true},
		{"inet", FilterTable, "docker_nets6", v6, false},
		{"ip", NATTable, "docker_nets_nat", v4, true},
	}
	var script strings.Builder
	for _, set := range sets {
		values := append([]string(nil), set.values...)
		sort.Strings(values)
		for _, raw := range values {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Bits() == 0 || prefix.Addr().Is4() != set.ipv4 {
				return fmt.Errorf("invalid container network %q", raw)
			}
		}
		fmt.Fprintf(&script, "flush set %s %s %s\n", set.family, set.table, set.name)
		if len(values) > 0 {
			fmt.Fprintf(&script, "add element %s %s %s { %s }\n", set.family, set.table, set.name, strings.Join(values, ", "))
		}
	}
	if err := b.Check(ctx, script.String()); err != nil {
		return err
	}
	path, cleanup, err := b.tempScript(script.String(), "nftfw-containers-")
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	_, stderr, runErr := b.Runner.Run(ctx, "--file", path)
	if runErr != nil {
		return fmt.Errorf("nft container set replacement failed: %s: %w", strings.TrimSpace(stderr), runErr)
	}
	return nil
}

func (b *Backend) ListOwned(ctx context.Context) ([]Table, error) {
	out, stderr, err := b.Runner.Run(ctx, "-j", "list", "tables")
	if err != nil {
		return nil, fmt.Errorf("nft list tables: %s: %w", strings.TrimSpace(stderr), err)
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, fmt.Errorf("decode nft JSON: %w", err)
	}
	owned := map[string]bool{}
	for _, t := range b.Owned {
		owned[t.Family+"/"+t.Name] = true
	}
	result := make([]Table, 0)
	for _, obj := range doc.Nftables {
		raw, ok := obj["table"]
		if !ok {
			continue
		}
		var t struct{ Family, Name string }
		if json.Unmarshal(raw, &t) != nil {
			continue
		}
		if owned[t.Family+"/"+t.Name] {
			result = append(result, Table{t.Family, t.Name})
		}
	}
	return result, nil
}

func (b *Backend) ExistingOwned(ctx context.Context) (map[string]bool, error) {
	items, err := b.ListOwned(ctx)
	if err != nil {
		return nil, err
	}
	result := make(map[string]bool, len(items))
	for _, t := range items {
		result[t.Family+"/"+t.Name] = true
	}
	return result, nil
}

// Integrity checks the structural markers owned by the compiler. It detects
// deletion or modification of a V2 table without inspecting unrelated tables.
func (b *Backend) Integrity(ctx context.Context) (bool, string, error) {
	owned, err := b.ExistingOwned(ctx)
	if err != nil {
		return false, "table inspection failed", err
	}
	for _, t := range b.Owned {
		if !owned[t.Family+"/"+t.Name] {
			return false, fmt.Sprintf("owned table %s/%s is missing", t.Family, t.Name), nil
		}
	}
	for _, table := range b.Owned {
		out, stderr, runErr := b.Runner.Run(ctx, "-j", "list", "table", table.Family, table.Name)
		if runErr != nil {
			return false, fmt.Sprintf("cannot inspect %s/%s: %s", table.Family, table.Name, strings.TrimSpace(stderr)), runErr
		}
		ok, detail, parseErr := validateOwnedTableJSON([]byte(out), table)
		if parseErr != nil {
			return false, fmt.Sprintf("cannot decode %s/%s", table.Family, table.Name), parseErr
		}
		if !ok {
			return false, detail, nil
		}
	}
	return true, "owned table markers intact", nil
}

type observedChain struct {
	Family  string `json:"family"`
	Table   string `json:"table"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Hook    string `json:"hook"`
	Policy  string `json:"policy"`
	Comment string `json:"comment"`
}

type observedRule struct {
	Family  string `json:"family"`
	Table   string `json:"table"`
	Chain   string `json:"chain"`
	Comment string `json:"comment"`
}

// validateOwnedTableJSON reasons about nft's structured representation. In
// particular, base-chain policy is a JSON field and is not rendered as the
// literal text "policy drop" in JSON output.
func validateOwnedTableJSON(data []byte, table Table) (bool, string, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return false, "", fmt.Errorf("decode nft JSON: %w", err)
	}
	chains := make(map[string]observedChain)
	comments := make(map[string]bool)
	for _, object := range doc.Nftables {
		if raw, ok := object["chain"]; ok {
			var chain observedChain
			if err := json.Unmarshal(raw, &chain); err != nil {
				return false, "", fmt.Errorf("decode chain: %w", err)
			}
			if chain.Family == table.Family && chain.Table == table.Name {
				chains[chain.Name] = chain
				if chain.Comment != "" {
					comments[chain.Comment] = true
				}
			}
		}
		if raw, ok := object["rule"]; ok {
			var rule observedRule
			if err := json.Unmarshal(raw, &rule); err != nil {
				return false, "", fmt.Errorf("decode rule: %w", err)
			}
			if rule.Family == table.Family && rule.Table == table.Name && rule.Comment != "" {
				comments[rule.Comment] = true
			}
		}
	}
	requireComment := func(comment string) (bool, string) {
		if comments[comment] {
			return true, ""
		}
		return false, fmt.Sprintf("marker %q missing from %s/%s", comment, table.Family, table.Name)
	}
	requireBaseChain := func(name, typ, hook, policy string) (bool, string) {
		chain, ok := chains[name]
		if !ok {
			return false, fmt.Sprintf("base chain %q missing from %s/%s", name, table.Family, table.Name)
		}
		if chain.Type != typ || chain.Hook != hook || chain.Policy != policy {
			return false, fmt.Sprintf("base chain %q has unsafe type/hook/policy in %s/%s", name, table.Family, table.Name)
		}
		return true, ""
	}

	switch table {
	case (Table{"inet", FilterTable}):
		for _, chain := range []string{"input", "output", "forward"} {
			if ok, detail := requireBaseChain(chain, "filter", chain, "drop"); !ok {
				return false, detail, nil
			}
		}
		for _, comment := range []string{
			"nftfw:input-default-deny",
			"nftfw:output-default-deny",
			"nftfw:forward-default-deny",
			"nftfw:forward-physical-deny",
			"nftfw:container-vpn-mss-out-v4",
			"nftfw:container-vpn-mss-out-v6",
			"nftfw:container-vpn-mss-in-v4",
			"nftfw:container-vpn-mss-in-v6",
			"nftfw:forward-uplink-reply-only",
			"nftfw:vpn-only-egress",
		} {
			if ok, detail := requireComment(comment); !ok {
				return false, detail, nil
			}
		}
	case (Table{"ip", NATTable}):
		if ok, detail := requireBaseChain("prerouting", "nat", "prerouting", "accept"); !ok {
			return false, detail, nil
		}
		if ok, detail := requireComment("nftfw:dnat-chain"); !ok {
			return false, detail, nil
		}
		if ok, detail := requireBaseChain("postrouting", "nat", "postrouting", "accept"); !ok {
			return false, detail, nil
		}
		if ok, detail := requireComment("nftfw:vpn-only-nat"); !ok {
			return false, detail, nil
		}
	case (Table{"ip6", Filter6}):
		mode := ""
		for comment := range comments {
			if strings.HasPrefix(comment, "nftfw:ipv6-mode-") {
				mode = strings.TrimPrefix(comment, "nftfw:ipv6-mode-")
				break
			}
		}
		if mode == "" {
			return false, fmt.Sprintf("IPv6 mode marker missing from %s/%s", table.Family, table.Name), nil
		}
		if mode == "disabled" {
			for _, chain := range []string{"input", "output", "forward"} {
				if ok, detail := requireBaseChain(chain, "filter", chain, "drop"); !ok {
					return false, detail, nil
				}
			}
		} else if mode != "vpn" && mode != "native" {
			return false, fmt.Sprintf("invalid IPv6 mode marker in %s/%s", table.Family, table.Name), nil
		}
	default:
		return false, fmt.Sprintf("unexpected owned table %s/%s", table.Family, table.Name), nil
	}
	return true, "", nil
}

func validateScript(script string) error {
	if strings.TrimSpace(script) == "" {
		return errors.New("empty nft script")
	}
	clean := stripNftComments(script)
	lower := strings.ToLower(clean)
	if strings.Contains(lower, "flush ruleset") {
		return errors.New("flush ruleset is forbidden")
	}
	for _, line := range strings.Split(clean, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		parts := strings.Fields(trim)
		if parts[0] == "include" || parts[0] == "define" || parts[0] == "redefine" {
			return fmt.Errorf("nft directive %q is forbidden", parts[0])
		}
		for i, token := range parts {
			if token == "table" {
				if i+2 >= len(parts) || !isOwnedFamilyName(parts[i+1], strings.TrimSuffix(parts[i+2], ";")) {
					return fmt.Errorf("script addresses malformed or unowned table")
				}
			}
		}
		if len(parts) >= 4 && isObjectCommand(parts[0], parts[1]) {
			if !isOwnedFamilyName(parts[2], strings.TrimSuffix(parts[3], ";")) {
				return fmt.Errorf("script command addresses unowned table %s/%s", parts[2], parts[3])
			}
		}
	}
	return nil
}

func isObjectCommand(command, object string) bool {
	commands := map[string]bool{"add": true, "delete": true, "destroy": true, "flush": true, "insert": true, "replace": true, "reset": true}
	objects := map[string]bool{"chain": true, "rule": true, "set": true, "map": true, "element": true, "counter": true, "quota": true, "flowtable": true}
	return commands[command] && objects[object]
}

func stripNftComments(script string) string {
	var b strings.Builder
	for _, line := range strings.Split(script, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func isOwnedFamilyName(family, name string) bool {
	for _, t := range OwnedTables {
		if t.Family == family && t.Name == name {
			return true
		}
	}
	return false
}

func prependDestroy(script string, existing map[string]bool, owned []Table) string {
	var b strings.Builder
	for _, t := range owned {
		if existing[t.Family+"/"+t.Name] {
			fmt.Fprintf(&b, "destroy table %s %s\n", t.Family, t.Name)
		}
	}
	b.WriteString(script)
	return b.String()
}

func (b *Backend) tempScript(script, prefix string) (string, func(), error) {
	dir := b.TempDir
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	f, err := os.CreateTemp(dir, prefix+"*.nft")
	if err != nil {
		return "", nil, err
	}
	path := f.Name()
	cleanup := func() { _ = f.Close(); _ = os.Remove(path) }
	if err := f.Chmod(0o600); err != nil {
		cleanup()
		return "", nil, err
	}
	if _, err := f.WriteString(script); err != nil {
		cleanup()
		return "", nil, err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", nil, err
	}
	return filepath.Clean(path), cleanup, nil
}
