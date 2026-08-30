// Package bootguard validates and removes the initramfs-only deny guard after
// committed NFTFW enforcement has been independently verified.
package bootguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	TableFamily  = "inet"
	TableName    = "nftfw_initramfs_guard"
	TableComment = "nftfw:initramfs-guard:v1"
)

type Runner interface {
	Run(context.Context, ...string) (string, string, error)
}

type document struct {
	NFTables []map[string]json.RawMessage `json:"nftables"`
}

type tableObject struct {
	Family  string `json:"family"`
	Name    string `json:"name"`
	Comment string `json:"comment"`
	Handle  int    `json:"handle,omitempty"`
}

type chainObject struct {
	Family   string `json:"family"`
	Table    string `json:"table"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Hook     string `json:"hook"`
	Priority int    `json:"prio"`
	Policy   string `json:"policy"`
	Comment  string `json:"comment"`
	Handle   int    `json:"handle,omitempty"`
}

var expectedChains = map[string]chainObject{
	"input_guard": {
		Family: TableFamily, Table: TableName, Name: "input_guard", Type: "filter",
		Hook: "input", Priority: -310, Policy: "drop", Comment: "nftfw:initramfs-input:v1",
	},
	"output_guard": {
		Family: TableFamily, Table: TableName, Name: "output_guard", Type: "filter",
		Hook: "output", Priority: -310, Policy: "drop", Comment: "nftfw:initramfs-output:v1",
	},
	"forward_guard": {
		Family: TableFamily, Table: TableName, Name: "forward_guard", Type: "filter",
		Hook: "forward", Priority: -310, Policy: "drop", Comment: "nftfw:initramfs-forward:v1",
	},
}

// Handoff removes only the exact initramfs guard. Absence is the normal case
// during the first live setup transaction; any colliding or extended table is
// treated as foreign and left untouched.
func Handoff(ctx context.Context, runner Runner) (bool, error) {
	if runner == nil {
		return false, errors.New("initramfs guard runner is missing")
	}
	present, err := tablePresent(ctx, runner)
	if err != nil || !present {
		return false, err
	}
	out, _, err := runner.Run(ctx, "--json", "list", "table", TableFamily, TableName)
	if err != nil {
		return false, fmt.Errorf("inspect initramfs guard: %w", err)
	}
	if err := validateExact([]byte(out)); err != nil {
		return false, err
	}
	_, _, deleteErr := runner.Run(ctx, "delete", "table", TableFamily, TableName)
	present, inspectErr := tablePresent(ctx, runner)
	if inspectErr != nil {
		return false, errors.Join(deleteErr, fmt.Errorf("verify initramfs guard removal: %w", inspectErr))
	}
	if present {
		if deleteErr == nil {
			deleteErr = errors.New("guard remains present")
		}
		return false, fmt.Errorf("remove initramfs guard: %w", deleteErr)
	}
	return true, nil
}

func tablePresent(ctx context.Context, runner Runner) (bool, error) {
	out, _, err := runner.Run(ctx, "--json", "list", "tables")
	if err != nil {
		return false, fmt.Errorf("list nftables tables: %w", err)
	}
	doc, err := decode([]byte(out))
	if err != nil {
		return false, err
	}
	present := false
	for _, object := range doc.NFTables {
		raw, ok := object["table"]
		if !ok {
			if _, metadata := object["metainfo"]; metadata && len(object) == 1 {
				continue
			}
			return false, errors.New("unexpected object while listing nftables tables")
		}
		if len(object) != 1 {
			return false, errors.New("ambiguous nftables table object")
		}
		var table tableObject
		if json.Unmarshal(raw, &table) != nil || table.Family == "" || table.Name == "" {
			return false, errors.New("invalid nftables table object")
		}
		if table.Family == TableFamily && table.Name == TableName {
			if present {
				return false, errors.New("duplicate initramfs guard table")
			}
			present = true
		}
	}
	return present, nil
}

func validateExact(data []byte) error {
	doc, err := decode(data)
	if err != nil {
		return err
	}
	tableSeen := false
	chains := map[string]bool{}
	for _, object := range doc.NFTables {
		if len(object) != 1 {
			return errors.New("ambiguous initramfs guard object")
		}
		if _, metadata := object["metainfo"]; metadata {
			continue
		}
		if raw, ok := object["table"]; ok {
			var table tableObject
			if tableSeen || decodeStrict(raw, &table) != nil ||
				table.Family != TableFamily || table.Name != TableName || table.Comment != TableComment {
				return errors.New("initramfs guard table identity is invalid")
			}
			tableSeen = true
			continue
		}
		if raw, ok := object["chain"]; ok {
			var chain chainObject
			if decodeStrict(raw, &chain) != nil {
				return errors.New("initramfs guard chain is invalid")
			}
			expected, known := expectedChains[chain.Name]
			chain.Handle = 0
			if !known || chains[chain.Name] || chain != expected {
				return errors.New("initramfs guard chain identity is invalid")
			}
			chains[chain.Name] = true
			continue
		}
		return errors.New("initramfs guard contains an unexpected object")
	}
	if !tableSeen || len(chains) != len(expectedChains) {
		return errors.New("initramfs guard is incomplete")
	}
	return nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("multiple or malformed JSON values")
	}
	return nil
}

func decode(data []byte) (document, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return document{}, errors.New("nftables guard output is empty or oversized")
	}
	var doc document
	if json.Unmarshal(data, &doc) != nil || doc.NFTables == nil {
		return document{}, errors.New("nftables guard output is invalid")
	}
	return doc, nil
}
