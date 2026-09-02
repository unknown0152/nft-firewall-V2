package nft

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
)

// ProvenanceCollisionScope is deliberately narrower than a host-wide
// conntrack-mark writer audit. This package can inspect netfilter rules, but it
// cannot prove anything about current conntrack entries, tc, OVS, BPF, other
// network namespaces, or privileged userspace writers.
const ProvenanceCollisionScope = "NETFILTER_RULES_ONLY"

const (
	maxProvenanceAuditDepth = 64
	maxProvenanceAuditNodes = 2_000_000
)

// listRulesetObjectKinds is the schema-v1 object vocabulary emitted by
// `nft -j list ruleset`. Command objects are intentionally absent: accepting
// an add/list/replace wrapper (or a future unknown object kind) could hide a
// rule from this read-only whole-ruleset audit.
var listRulesetObjectKinds = map[string]struct{}{
	"metainfo":       {},
	"table":          {},
	"chain":          {},
	"rule":           {},
	"set":            {},
	"map":            {},
	"element":        {},
	"flowtable":      {},
	"counter":        {},
	"quota":          {},
	"ct helper":      {},
	"ct timeout":     {},
	"ct expectation": {},
	"limit":          {},
	"secmark":        {},
	"synproxy":       {},
}

// ForeignProvenanceAudit describes one read-only nftables ruleset snapshot.
// A non-nil error always makes the snapshot unusable, including when
// CollidingRules is nonzero.
type ForeignProvenanceAudit struct {
	CollisionScope    string
	ReservedMask      uint32
	ForeignRules      int
	OwnedRulesIgnored int
	CollidingRules    int
}

// AuditForeignProvenanceMask reads the complete nft JSON ruleset and rejects
// foreign rules whose expressions use NFTFW's reserved conntrack-mark byte.
// Product-owned tables are excluded because their mark contract is verified
// separately by the compiler and owned-table integrity checks.
//
// This method is read-only. A deployment caller must still provide the
// cross-process serialization and repeated-snapshot checks required to rule
// out a concurrent ruleset change.
func (b *Backend) AuditForeignProvenanceMask(ctx context.Context) (ForeignProvenanceAudit, error) {
	base := ForeignProvenanceAudit{
		CollisionScope: ProvenanceCollisionScope,
		ReservedMask:   provenance.Mask,
	}
	if b == nil || b.Runner == nil {
		return base, fmt.Errorf("foreign provenance audit scope=%s: nft runner is required", ProvenanceCollisionScope)
	}

	commandCtx, cancel := b.commandContext(ctx)
	defer cancel()
	out, stderr, err := b.Runner.Run(commandCtx, "-j", "list", "ruleset")
	if err != nil {
		detail := strings.TrimSpace(stderr)
		if detail == "" {
			return base, fmt.Errorf("foreign provenance audit scope=%s: list nft ruleset: %w", ProvenanceCollisionScope, err)
		}
		return base, fmt.Errorf("foreign provenance audit scope=%s: list nft ruleset: %s: %w", ProvenanceCollisionScope, detail, err)
	}

	return foreignProvenanceAuditFromJSON([]byte(out), b.Owned)
}

func foreignProvenanceAuditFromJSON(data []byte, owned []Table) (ForeignProvenanceAudit, error) {
	audit, first, err := auditForeignProvenanceRulesetJSON(data, owned)
	if err != nil {
		return audit, fmt.Errorf("foreign provenance audit scope=%s: %w", ProvenanceCollisionScope, err)
	}
	if audit.CollidingRules == 0 {
		return audit, nil
	}
	if first == nil {
		return audit, fmt.Errorf("foreign provenance audit scope=%s mask=0x%08x: collision count has no rule location", ProvenanceCollisionScope, provenance.Mask)
	}
	return audit, fmt.Errorf(
		"foreign provenance audit scope=%s mask=0x%08x: %d foreign rule(s) collide; first %s: %s",
		ProvenanceCollisionScope, provenance.Mask, audit.CollidingRules, first.location.String(), first.reason,
	)
}

type provenanceRuleLocation struct {
	family    string
	table     string
	chain     string
	handle    uint64
	hasHandle bool
	ordinal   int
}

func (l provenanceRuleLocation) String() string {
	if l.hasHandle {
		return fmt.Sprintf("rule %q/%q/%q handle=%d", l.family, l.table, l.chain, l.handle)
	}
	return fmt.Sprintf("rule %q/%q/%q ordinal=%d", l.family, l.table, l.chain, l.ordinal)
}

type provenanceCollision struct {
	location provenanceRuleLocation
	reason   string
}

func auditForeignProvenanceRulesetJSON(data []byte, owned []Table) (ForeignProvenanceAudit, *provenanceCollision, error) {
	audit := ForeignProvenanceAudit{
		CollisionScope: ProvenanceCollisionScope,
		ReservedMask:   provenance.Mask,
	}
	if len(data) > maxNFTStdout {
		return audit, nil, fmt.Errorf("nft ruleset JSON exceeds %d-byte safety limit", maxNFTStdout)
	}

	var document map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&document); err != nil {
		return audit, nil, fmt.Errorf("decode nft ruleset JSON: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return audit, nil, fmt.Errorf("decode nft ruleset JSON: %w", err)
	}
	if len(document) != 1 {
		return audit, nil, fmt.Errorf("nft ruleset JSON must contain only the nftables document")
	}
	rawObjects, ok := document["nftables"]
	if !ok {
		return audit, nil, fmt.Errorf("nft ruleset JSON has no nftables array")
	}
	var objects []json.RawMessage
	if err := json.Unmarshal(rawObjects, &objects); err != nil || objects == nil {
		if err == nil {
			err = fmt.Errorf("nftables value is not an array")
		}
		return audit, nil, fmt.Errorf("decode nftables array: %w", err)
	}

	ownedTables := make(map[string]struct{}, len(owned))
	for _, table := range owned {
		ownedTables[table.Family+"\x00"+table.Name] = struct{}{}
	}

	type decodedObject struct {
		kind string
		body json.RawMessage
	}
	decoded := make([]decodedObject, 0, len(objects))
	metainfoCount := 0
	for objectIndex, rawObject := range objects {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(rawObject, &object); err != nil {
			return audit, nil, fmt.Errorf("decode nftables object %d: %w", objectIndex, err)
		}
		if len(object) != 1 {
			return audit, nil, fmt.Errorf("nftables object %d must contain exactly one object kind", objectIndex)
		}
		var kind string
		var body json.RawMessage
		for candidate, rawBody := range object {
			kind, body = candidate, rawBody
		}
		if _, supported := listRulesetObjectKinds[kind]; !supported {
			return audit, nil, fmt.Errorf("nftables object %d has unsupported list-ruleset kind %q", objectIndex, kind)
		}
		var bodyObject map[string]json.RawMessage
		if err := json.Unmarshal(body, &bodyObject); err != nil || bodyObject == nil {
			if err == nil {
				err = fmt.Errorf("object body is not an object")
			}
			return audit, nil, fmt.Errorf("decode nftables %s object %d: %w", kind, objectIndex, err)
		}
		if kind == "metainfo" {
			metainfoCount++
			rawVersion, ok := bodyObject["json_schema_version"]
			if !ok {
				return audit, nil, fmt.Errorf("nftables metainfo object %d has no json_schema_version", objectIndex)
			}
			var version int
			if err := json.Unmarshal(rawVersion, &version); err != nil || version != 1 {
				return audit, nil, fmt.Errorf("nftables metainfo object %d has unsupported json_schema_version", objectIndex)
			}
		}
		decoded = append(decoded, decodedObject{kind: kind, body: body})
	}
	if metainfoCount != 1 {
		return audit, nil, fmt.Errorf("nft ruleset JSON must contain exactly one schema-v1 metainfo object, got %d", metainfoCount)
	}

	scanner := provenanceExpressionScanner{}
	var first *provenanceCollision
	ruleOrdinal := 0
	for _, object := range decoded {
		if object.kind != "rule" {
			continue
		}
		ruleOrdinal++

		location, rawExpressions, err := decodeProvenanceAuditRule(object.body, ruleOrdinal)
		if err != nil {
			return audit, first, fmt.Errorf("decode nft rule %d: %w", ruleOrdinal, err)
		}
		if _, isOwned := ownedTables[location.family+"\x00"+location.table]; isOwned {
			audit.OwnedRulesIgnored++
			continue
		}
		audit.ForeignRules++

		var expressions []any
		expressionDecoder := json.NewDecoder(bytes.NewReader(rawExpressions))
		expressionDecoder.UseNumber()
		if err := expressionDecoder.Decode(&expressions); err != nil || expressions == nil {
			if err == nil {
				err = fmt.Errorf("expr is not an array")
			}
			return audit, first, fmt.Errorf("%s has invalid expr: %w", location.String(), err)
		}
		if err := requireJSONEOF(expressionDecoder); err != nil {
			return audit, first, fmt.Errorf("%s has invalid expr: %w", location.String(), err)
		}

		reason, err := scanner.inspect(expressions, 0)
		if err != nil {
			return audit, first, fmt.Errorf("inspect %s: %w", location.String(), err)
		}
		if reason != "" {
			audit.CollidingRules++
			if first == nil {
				first = &provenanceCollision{location: location, reason: reason}
			}
		}
	}
	return audit, first, nil
}

func decodeProvenanceAuditRule(raw json.RawMessage, ordinal int) (provenanceRuleLocation, json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return provenanceRuleLocation{}, nil, err
	}
	requireString := func(name string) (string, error) {
		rawValue, ok := fields[name]
		if !ok {
			return "", fmt.Errorf("missing %s", name)
		}
		var value string
		if err := json.Unmarshal(rawValue, &value); err != nil || value == "" {
			return "", fmt.Errorf("invalid %s", name)
		}
		if len(value) > 1024 {
			return "", fmt.Errorf("%s exceeds safety limit", name)
		}
		return value, nil
	}

	family, err := requireString("family")
	if err != nil {
		return provenanceRuleLocation{}, nil, err
	}
	table, err := requireString("table")
	if err != nil {
		return provenanceRuleLocation{}, nil, err
	}
	chain, err := requireString("chain")
	if err != nil {
		return provenanceRuleLocation{}, nil, err
	}
	rawExpressions, ok := fields["expr"]
	if !ok {
		return provenanceRuleLocation{}, nil, fmt.Errorf("missing expr")
	}

	location := provenanceRuleLocation{family: family, table: table, chain: chain, ordinal: ordinal}
	if rawHandle, ok := fields["handle"]; ok {
		if err := json.Unmarshal(rawHandle, &location.handle); err != nil {
			return provenanceRuleLocation{}, nil, fmt.Errorf("invalid handle")
		}
		location.hasHandle = true
	}
	return location, rawExpressions, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

type provenanceExpressionScanner struct {
	nodes int
}

// inspect returns the first collision reason while continuing through sibling
// expressions. The latter matters because a malformed later expression must
// still fail the audit instead of being hidden behind an earlier collision.
func (s *provenanceExpressionScanner) inspect(value any, depth int) (string, error) {
	s.nodes++
	if s.nodes > maxProvenanceAuditNodes {
		return "", fmt.Errorf("expression node count exceeds safety limit")
	}
	if depth > maxProvenanceAuditDepth {
		return "", fmt.Errorf("expression nesting exceeds safety limit")
	}

	switch typed := value.(type) {
	case []any:
		var first string
		for _, child := range typed {
			reason, err := s.inspect(child, depth+1)
			if err != nil {
				return "", err
			}
			if first == "" {
				first = reason
			}
		}
		return first, nil
	case map[string]any:
		if len(typed) == 1 {
			if body, ok := typed["&"]; ok {
				return s.inspectAnd(body, depth+1)
			}
		}
		// libnftables cannot expose the parameters of an xtables-compat
		// statement. In particular, CONNMARK reads and writes ct mark behind
		// this opaque shape, so no xt statement can be proven disjoint here.
		if _, opaque := typed["xt"]; opaque {
			return "foreign xtables-compat expression has unverifiable conntrack-mark semantics", nil
		}

		isMark, isWrite, err := classifyCTMarkDescriptor(typed)
		if err != nil {
			return "", err
		}
		if isMark {
			if isWrite {
				return "foreign expression writes the reserved conntrack-mark byte", nil
			}
			return "foreign expression reads conntrack mark without a disjoint constant mask", nil
		}

		var first string
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := typed[key]
			if key == "mangle" {
				reason, err := s.inspectMangle(child, depth+1)
				if err != nil {
					return "", err
				}
				if first == "" {
					first = reason
				}
				continue
			}
			reason, err := s.inspect(child, depth+1)
			if err != nil {
				return "", err
			}
			if first == "" {
				first = reason
			}
		}
		return first, nil
	default:
		return "", nil
	}
}

func (s *provenanceExpressionScanner) inspectAnd(body any, depth int) (string, error) {
	operands, ok := body.([]any)
	if !ok || len(operands) < 2 {
		// An unexpected bitwise shape cannot gain an exemption. Recursing finds
		// any nested ct-mark descriptor and treats it as unmasked.
		return s.inspect(body, depth+1)
	}

	markIndex := -1
	for index, operand := range operands {
		canonical, err := canonicalCTMarkRead(operand)
		if err != nil {
			return "", err
		}
		if canonical {
			if markIndex != -1 {
				return "foreign expression combines multiple conntrack-mark reads in one mask", nil
			}
			markIndex = index
		}
	}
	if markIndex != -1 {
		for index, operand := range operands {
			if index == markIndex {
				continue
			}
			mask, ok := markUint32Constant(operand)
			if !ok {
				return "foreign expression uses an unverifiable conntrack-mark mask", nil
			}
			if mask&provenance.Mask != 0 {
				return "foreign expression mask overlaps the reserved conntrack-mark byte", nil
			}
		}
		return "", nil
	}

	var first string
	for _, operand := range operands {
		reason, err := s.inspect(operand, depth+1)
		if err != nil {
			return "", err
		}
		if first == "" {
			first = reason
		}
	}
	return first, nil
}

func (s *provenanceExpressionScanner) inspectMangle(value any, depth int) (string, error) {
	body, ok := value.(map[string]any)
	if !ok {
		return "", fmt.Errorf("mangle expression is not an object")
	}
	key, hasKey := body["key"]
	assigned, hasValue := body["value"]
	if !hasKey || !hasValue || len(body) != 2 {
		return "", fmt.Errorf("mangle expression must contain exactly key and value")
	}

	isMark, _, err := ctMarkDescriptorValue(key)
	if err != nil {
		return "", err
	}
	first := ""
	if isMark {
		first = "foreign expression writes the reserved conntrack-mark byte"
	} else {
		first, err = s.inspect(key, depth+1)
		if err != nil {
			return "", err
		}
	}
	reason, err := s.inspect(assigned, depth+1)
	if err != nil {
		return "", err
	}
	if first == "" {
		first = reason
	}
	return first, nil
}

func classifyCTMarkDescriptor(value map[string]any) (isMark, isWrite bool, err error) {
	isMark, body, err := ctMarkDescriptor(value)
	if err != nil || !isMark {
		return isMark, false, err
	}
	_, isWrite = body["set"]
	return true, isWrite, nil
}

func ctMarkDescriptorValue(value any) (bool, map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return false, nil, nil
	}
	return ctMarkDescriptor(object)
}

func ctMarkDescriptor(value map[string]any) (bool, map[string]any, error) {
	rawCT, ok := value["ct"]
	if !ok {
		return false, nil, nil
	}
	body, ok := rawCT.(map[string]any)
	if !ok {
		return false, nil, fmt.Errorf("ct descriptor is not an object")
	}
	rawKey, ok := body["key"]
	if !ok {
		return false, nil, fmt.Errorf("ct descriptor has no key")
	}
	key, ok := rawKey.(string)
	if !ok {
		return false, nil, fmt.Errorf("ct descriptor key is not a string")
	}
	return key == "mark", body, nil
}

func canonicalCTMarkRead(value any) (bool, error) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != 1 {
		return false, nil
	}
	isMark, body, err := ctMarkDescriptor(object)
	if err != nil || !isMark {
		return false, err
	}
	for key := range body {
		switch key {
		case "key", "family", "dir":
		default:
			return false, nil
		}
	}
	return true, nil
}

func markUint32Constant(value any) (uint32, bool) {
	var text string
	switch typed := value.(type) {
	case json.Number:
		text = typed.String()
	case string:
		text = typed
	default:
		return 0, false
	}
	if text == "" || strings.TrimSpace(text) != text || strings.HasPrefix(text, "-") {
		return 0, false
	}
	base := 10
	if strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X") {
		base = 0
	}
	parsed, err := strconv.ParseUint(text, base, 32)
	if err != nil {
		return 0, false
	}
	return uint32(parsed), true
}
