package containers

import (
	"os"
	"testing"
)

func secureTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("secure temporary directory: %v", err)
	}
	return dir
}
