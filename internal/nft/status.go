package nft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// StatusInspection is one immutable nftables ruleset observation used by the
// health path. Integrity, fingerprint, ownership, and foreign-provenance
// results are derived from the same kernel snapshot so status does not spawn
// a sequence of independently raced nft processes.
type StatusInspection struct {
	Owned                []Table
	IntegrityOK          bool
	IntegrityDetail      string
	Fingerprint          string
	ForeignProvenance    ForeignProvenanceAudit
	ForeignProvenanceErr error
}

// InspectStatus reads nftables exactly once and derives every read-only
// firewall status result from that bounded JSON document. A malformed or
// unsupported whole-ruleset document invalidates the complete observation.
// A well-formed foreign provenance collision is returned separately so the
// caller can report it without hiding independently verified owned state.
func (b *Backend) InspectStatus(ctx context.Context) (StatusInspection, error) {
	if b == nil || b.Runner == nil {
		return StatusInspection{}, errors.New("nft status inspection requires a runner")
	}
	commandCtx, cancel := b.commandContext(ctx)
	defer cancel()
	out, stderr, err := b.Runner.Run(commandCtx, "-j", "list", "ruleset")
	if err != nil {
		detail := strings.TrimSpace(stderr)
		if detail == "" {
			return StatusInspection{}, fmt.Errorf("nft status inspection: list ruleset: %w", err)
		}
		return StatusInspection{}, fmt.Errorf("nft status inspection: list ruleset: %s: %w", detail, err)
	}
	data := []byte(out)
	audit, auditErr := foreignProvenanceAuditFromJSON(data, b.Owned)
	documents, observed, err := ownedTableDocuments(data, b.Owned)
	if err != nil {
		return StatusInspection{}, fmt.Errorf("nft status inspection: %w", err)
	}
	inspection := StatusInspection{
		Owned:                observed,
		IntegrityDetail:      "owned table markers intact",
		ForeignProvenance:    audit,
		ForeignProvenanceErr: auditErr,
	}
	present := make(map[string]bool, len(observed))
	for _, table := range observed {
		present[table.Family+"/"+table.Name] = true
	}
	for _, table := range b.Owned {
		key := table.Family + "/" + table.Name
		if !present[key] {
			inspection.IntegrityDetail = fmt.Sprintf("owned table %s is missing", key)
			return inspection, nil
		}
		ok, detail, validateErr := validateOwnedTableJSON(documents[key], table)
		if validateErr != nil {
			return StatusInspection{}, fmt.Errorf("nft status inspection: cannot decode %s: %w", key, validateErr)
		}
		if !ok {
			inspection.IntegrityDetail = detail
			return inspection, nil
		}
	}
	hash := sha256.New()
	for _, table := range b.Owned {
		key := table.Family + "/" + table.Name
		canonical, canonicalErr := canonicalOwnedJSON(documents[key], table)
		if canonicalErr != nil {
			return StatusInspection{}, fmt.Errorf("nft status inspection: fingerprint %s: %w", key, canonicalErr)
		}
		_, _ = hash.Write(canonical)
	}
	inspection.IntegrityOK = true
	inspection.Fingerprint = hex.EncodeToString(hash.Sum(nil))
	return inspection, nil
}

func ownedTableDocuments(data []byte, owned []Table) (map[string][]byte, []Table, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, nil, fmt.Errorf("decode ruleset JSON: %w", err)
	}
	if len(document) != 1 {
		return nil, nil, errors.New("ruleset JSON must contain only the nftables document")
	}
	var objects []json.RawMessage
	if raw, ok := document["nftables"]; !ok {
		return nil, nil, errors.New("ruleset JSON has no nftables array")
	} else if err := json.Unmarshal(raw, &objects); err != nil || objects == nil {
		return nil, nil, errors.New("ruleset nftables value is not an array")
	}
	wanted := make(map[string]Table, len(owned))
	selected := make(map[string][]json.RawMessage, len(owned))
	seenTables := make(map[string]bool, len(owned))
	for _, table := range owned {
		key := table.Family + "/" + table.Name
		wanted[key] = table
	}
	for index, raw := range objects {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || len(object) != 1 {
			return nil, nil, fmt.Errorf("invalid nftables object %d", index)
		}
		var kind string
		var body json.RawMessage
		for kind, body = range object {
		}
		if kind == "metainfo" {
			for key := range wanted {
				selected[key] = append(selected[key], raw)
			}
			continue
		}
		var identity struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
		}
		if err := json.Unmarshal(body, &identity); err != nil || identity.Family == "" {
			return nil, nil, fmt.Errorf("invalid %s identity in nftables object %d", kind, index)
		}
		tableName := identity.Table
		if kind == "table" {
			tableName = identity.Name
		}
		if tableName == "" {
			return nil, nil, fmt.Errorf("missing %s table identity in nftables object %d", kind, index)
		}
		key := identity.Family + "/" + tableName
		if _, ok := wanted[key]; !ok {
			continue
		}
		selected[key] = append(selected[key], raw)
		if kind == "table" {
			if seenTables[key] {
				return nil, nil, fmt.Errorf("duplicate owned table object %s", key)
			}
			seenTables[key] = true
		}
	}
	result := make(map[string][]byte, len(owned))
	observed := make([]Table, 0, len(owned))
	for _, table := range owned {
		key := table.Family + "/" + table.Name
		encoded, err := json.Marshal(struct {
			Nftables []json.RawMessage `json:"nftables"`
		}{Nftables: selected[key]})
		if err != nil {
			return nil, nil, fmt.Errorf("encode owned table document %s: %w", key, err)
		}
		result[key] = encoded
		if seenTables[key] {
			observed = append(observed, table)
		}
	}
	return result, observed, nil
}
