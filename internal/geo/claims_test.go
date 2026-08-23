package geo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCIDRsCanonicalizesAndRejectsWritableInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geo.txt")
	if err := os.WriteFile(path, []byte("203.0.113.4/24\n203.0.113.9/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCIDRs(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("unexpected canonical GeoIP data: %v", got)
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCIDRs(path, 10); err == nil {
		t.Fatal("writable GeoIP input accepted")
	}
}
