package bootguard

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeRunner struct {
	present bool
	table   string
	tables  string
	fail    string
	calls   []string
}

func (f *fakeRunner) Run(_ context.Context, args ...string) (string, string, error) {
	command := strings.Join(args, " ")
	f.calls = append(f.calls, command)
	if f.fail != "" && strings.Contains(command, f.fail) {
		return "", "", errors.New("injected")
	}
	switch command {
	case "--json list tables":
		if f.tables != "" {
			return f.tables, "", nil
		}
		if f.present {
			return `{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"nftfw_initramfs_guard"}}]}`, "", nil
		}
		return `{"nftables":[{"metainfo":{"json_schema_version":1}}]}`, "", nil
	case "--json list table inet nftfw_initramfs_guard":
		return f.table, "", nil
	case "delete table inet nftfw_initramfs_guard":
		f.present = false
		return "", "", nil
	default:
		return "", "", errors.New("unexpected command")
	}
}

func exactTable() string {
	return `{"nftables":[
{"metainfo":{"json_schema_version":1}},
{"table":{"family":"inet","name":"nftfw_initramfs_guard","handle":1,"comment":"nftfw:initramfs-guard:v1"}},
{"chain":{"family":"inet","table":"nftfw_initramfs_guard","name":"input_guard","handle":2,"type":"filter","hook":"input","prio":-310,"policy":"drop","comment":"nftfw:initramfs-input:v1"}},
{"chain":{"family":"inet","table":"nftfw_initramfs_guard","name":"output_guard","handle":3,"type":"filter","hook":"output","prio":-310,"policy":"drop","comment":"nftfw:initramfs-output:v1"}},
{"chain":{"family":"inet","table":"nftfw_initramfs_guard","name":"forward_guard","handle":4,"type":"filter","hook":"forward","prio":-310,"policy":"drop","comment":"nftfw:initramfs-forward:v1"}}
]}`
}

func TestHandoffExactOrAbsent(t *testing.T) {
	if removed, err := Handoff(context.Background(), nil); err == nil || removed {
		t.Fatalf("nil runner accepted: removed=%t err=%v", removed, err)
	}
	absent := &fakeRunner{}
	if removed, err := Handoff(context.Background(), absent); err != nil || removed {
		t.Fatalf("absent guard result: removed=%t err=%v", removed, err)
	}
	present := &fakeRunner{present: true, table: exactTable()}
	if removed, err := Handoff(context.Background(), present); err != nil || !removed || present.present {
		t.Fatalf("exact guard result: removed=%t err=%v present=%t", removed, err, present.present)
	}
	want := "--json list tables,--json list table inet nftfw_initramfs_guard,delete table inet nftfw_initramfs_guard,--json list tables"
	if strings.Join(present.calls, ",") != want {
		t.Fatalf("handoff command boundary changed: %v", present.calls)
	}
}

func TestHandoffRejectsForeignOrAmbiguousGuard(t *testing.T) {
	for _, mutation := range []func(string) string{
		func(value string) string { return strings.Replace(value, TableComment, "foreign", 1) },
		func(value string) string { return strings.Replace(value, `"policy":"drop"`, `"policy":"accept"`, 1) },
		func(value string) string {
			return strings.Replace(value, `]}`, `,{"rule":{"family":"inet","table":"nftfw_initramfs_guard","chain":"input_guard"}}]}`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `"comment":"nftfw:initramfs-input:v1"`, `"comment":"nftfw:initramfs-input:v1","flags":[]`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `{"chain":{"family":"inet","table":"nftfw_initramfs_guard","name":"forward_guard"`, `{"chain":{"family":"inet","table":"nftfw_initramfs_guard","name":"other"`, 1)
		},
	} {
		runner := &fakeRunner{present: true, table: mutation(exactTable())}
		if removed, err := Handoff(context.Background(), runner); err == nil || removed || !runner.present {
			t.Fatalf("foreign guard was changed: removed=%t err=%v", removed, err)
		}
		if strings.Contains(strings.Join(runner.calls, ","), "delete table") {
			t.Fatalf("foreign guard reached deletion: %v", runner.calls)
		}
	}
}

func TestHandoffRejectsMalformedTableInventory(t *testing.T) {
	for _, inventory := range []string{
		`{}`,
		`{"nftables":null}`,
		`{"nftables":[{"chain":{"family":"inet","table":"foreign","name":"input"}}]}`,
		`{"nftables":[{"table":{"family":"","name":"invalid"}}]}`,
		`{"nftables":[{"table":{"family":"inet","name":"nftfw_initramfs_guard"}},{"table":{"family":"inet","name":"nftfw_initramfs_guard"}}]}`,
		`{"nftables":[{"table":{"family":"inet","name":"nftfw_initramfs_guard"},"rule":{}}]}`,
	} {
		runner := &fakeRunner{tables: inventory}
		if removed, err := Handoff(context.Background(), runner); err == nil || removed {
			t.Fatalf("malformed inventory accepted: %s removed=%t err=%v", inventory, removed, err)
		}
	}
	runner := &fakeRunner{tables: strings.Repeat("x", (1<<20)+1)}
	if removed, err := Handoff(context.Background(), runner); err == nil || removed {
		t.Fatalf("oversized inventory accepted: removed=%t err=%v", removed, err)
	}
}

func TestHandoffFailureBoundaries(t *testing.T) {
	for _, fail := range []string{"list tables", "list table", "delete table"} {
		runner := &fakeRunner{present: true, table: exactTable(), fail: fail}
		removed, err := Handoff(context.Background(), runner)
		if fail == "delete table" {
			// A failed command with confirmed absence would be accepted, but this
			// fake retains the table and therefore must fail.
			runner.present = true
		}
		if err == nil || removed {
			t.Fatalf("failure %q accepted: removed=%t err=%v", fail, removed, err)
		}
	}
}
