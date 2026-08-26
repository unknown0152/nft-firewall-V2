package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

func TestLoggerRecordsAndReadsAudit(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(context.Background(), filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	logger := Logger{Store: store}
	if err := logger.Record(context.Background(), "operator", "test", "detail"); err != nil {
		t.Fatal(err)
	}
	records, err := logger.Recent(context.Background(), 10)
	if err != nil || len(records) != 1 || records[0]["event"] != "test" {
		t.Fatalf("unexpected audit records: %#v %v", records, err)
	}
	if err := (Logger{}).Record(context.Background(), "operator", "ignored", "detail"); err != nil {
		t.Fatal(err)
	}
}
