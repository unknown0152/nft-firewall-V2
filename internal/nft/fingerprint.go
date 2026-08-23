package nft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Fingerprint returns a stable digest of every owned nftables object. Kernel
// handles, packet counters, and runtime-set elements are intentionally omitted.
func (b *Backend) Fingerprint(ctx context.Context) (string, error) {
	hash := sha256.New()
	for _, table := range b.Owned {
		out, stderr, err := b.Runner.Run(ctx, "-j", "list", "table", table.Family, table.Name)
		if err != nil {
			return "", fmt.Errorf("fingerprint %s/%s: %s: %w", table.Family, table.Name, stderr, err)
		}
		canonical, err := canonicalOwnedJSON([]byte(out), table)
		if err != nil {
			return "", err
		}
		_, _ = hash.Write(canonical)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func canonicalOwnedJSON(data []byte, table Table) ([]byte, error) {
	var document struct {
		Nftables []map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("decode fingerprint JSON for %s/%s: %w", table.Family, table.Name, err)
	}
	normalized := make([]map[string]any, 0, len(document.Nftables))
	for _, object := range document.Nftables {
		if _, volatile := object["metainfo"]; volatile {
			continue
		}
		if _, volatile := object["element"]; volatile {
			continue
		}
		for kind, value := range object {
			entry, ok := value.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid %s object in fingerprint JSON", kind)
			}
			if entry["family"] != table.Family {
				return nil, fmt.Errorf("fingerprint JSON contains an unexpected %s object", kind)
			}
			if kind == "table" && entry["name"] != table.Name || kind != "table" && entry["table"] != table.Name {
				return nil, fmt.Errorf("fingerprint JSON contains an unexpected %s object", kind)
			}
			delete(entry, "handle")
			if kind == "set" {
				delete(entry, "elem")
			}
			stripVolatileValues(entry)
		}
		normalized = append(normalized, object)
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("fingerprint JSON for %s/%s contains no owned objects", table.Family, table.Name)
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("encode fingerprint JSON: %w", err)
	}
	return canonical, nil
}

func stripVolatileValues(value any) {
	switch typed := value.(type) {
	case map[string]any:
		delete(typed, "handle")
		for key, child := range typed {
			if key == "counter" {
				if counter, ok := child.(map[string]any); ok {
					delete(counter, "packets")
					delete(counter, "bytes")
				}
			}
			stripVolatileValues(child)
		}
	case []any:
		for _, child := range typed {
			stripVolatileValues(child)
		}
	}
}
