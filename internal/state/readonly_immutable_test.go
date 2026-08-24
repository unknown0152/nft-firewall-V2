package state

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenReadOnlyImmutableDoesNotCreateSidecarsOrChangeDatabase(t *testing.T) {
	ctx := context.Background()
	root := secureTestDir(t)
	databaseDirectory := filepath.Join(root, "generation-state")
	if err := os.Mkdir(databaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(databaseDirectory, "state.db")
	writable, err := Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writable.Audit(ctx, "test", "immutable_ro_fixture", "source-only"); err != nil {
		writable.Close()
		t.Fatal(err)
	}
	if err := writable.Close(); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSQLiteSidecars(t, databasePath)

	readOnly, err := OpenReadOnly(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	var migrationCount int
	if err := readOnly.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&migrationCount); err != nil {
		readOnly.Close()
		t.Fatal(err)
	}
	if migrationCount != currentSchemaVersion {
		readOnly.Close()
		t.Fatalf("read-only fixture schema count=%d want=%d", migrationCount, currentSchemaVersion)
	}
	if _, err := readOnly.DB.ExecContext(ctx, "CREATE TABLE forbidden_read_only_mutation(value TEXT)"); err == nil {
		readOnly.Close()
		t.Fatal("immutable read-only database accepted a write")
	}
	assertNoSQLiteSidecars(t, databasePath)
	during, err := os.ReadFile(databasePath)
	if err != nil {
		readOnly.Close()
		t.Fatal(err)
	}
	if !bytes.Equal(before, during) {
		readOnly.Close()
		t.Fatal("immutable read-only open changed database content while open")
	}
	if err := readOnly.Close(); err != nil {
		t.Fatal(err)
	}

	assertNoSQLiteSidecars(t, databasePath)
	after, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("immutable read-only close changed database content")
	}
}

func assertNoSQLiteSidecars(t *testing.T, databasePath string) {
	t.Helper()
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		path := databasePath + suffix
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("immutable read-only database created sidecar %s", filepath.Base(path))
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat SQLite sidecar %s: %v", filepath.Base(path), err)
		}
	}
}

func TestAuditDurableIsPresentInStandaloneMainDatabaseImage(t *testing.T) {
	ctx := context.Background()
	root := secureTestDir(t)
	databaseDirectory := filepath.Join(root, "generation-state")
	if err := os.Mkdir(databaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(databaseDirectory, "state.db")
	store, err := Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AuditDurable(ctx, "system", "durable_recovery_probe", "ready=true"); err != nil {
		t.Fatal(err)
	}

	// Copy only the main database while the writer remains open. The copy has
	// no WAL/SHM files and models the authoritative image available after a
	// crash that loses all sidecars.
	mainImage, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	crashRoot := secureTestDir(t)
	crashDatabaseDirectory := filepath.Join(crashRoot, "generation-state")
	if err := os.Mkdir(crashDatabaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	crashDatabasePath := filepath.Join(crashDatabaseDirectory, "state.db")
	if err := os.WriteFile(crashDatabasePath, mainImage, 0o600); err != nil {
		t.Fatal(err)
	}
	crashStore, err := OpenReadOnly(ctx, crashDatabasePath)
	if err != nil {
		t.Fatalf("open standalone durable main image: %v", err)
	}
	defer crashStore.Close()
	var count int
	if err := crashStore.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit WHERE actor=? AND event=? AND detail=?", "system", "durable_recovery_probe", "ready=true").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("durable audit missing from standalone main image: count=%d", count)
	}
}

func TestOpenReadOnlyRejectsUnsafeDatabaseDirectoryWithoutMutation(t *testing.T) {
	ctx := context.Background()
	newFixture := func(t *testing.T) (string, string, []byte) {
		t.Helper()
		root := secureTestDir(t)
		databaseDirectory := filepath.Join(root, "generation-state")
		if err := os.Mkdir(databaseDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		databasePath := filepath.Join(databaseDirectory, "state.db")
		store, err := Open(ctx, databasePath)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(databasePath)
		if err != nil {
			t.Fatal(err)
		}
		return databaseDirectory, databasePath, contents
	}

	t.Run("group writable mode", func(t *testing.T) {
		databaseDirectory, databasePath, before := newFixture(t)
		if err := os.Chmod(databaseDirectory, 0o770); err != nil {
			t.Fatal(err)
		}
		if store, err := OpenReadOnly(ctx, databasePath); err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
			if store != nil {
				store.Close()
			}
			t.Fatalf("unsafe database directory mode accepted: %v", err)
		}
		after, err := os.ReadFile(databasePath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("mode refusal changed database content")
		}
		assertNoSQLiteSidecars(t, databasePath)
	})

	t.Run("symlink parent", func(t *testing.T) {
		databaseDirectory, databasePath, before := newFixture(t)
		realRoot := filepath.Dir(databaseDirectory)
		aliasParent := secureTestDir(t)
		aliasRoot := filepath.Join(aliasParent, "state-alias")
		if err := os.Symlink(realRoot, aliasRoot); err != nil {
			t.Fatal(err)
		}
		aliasPath := filepath.Join(aliasRoot, "generation-state", "state.db")
		if store, err := OpenReadOnly(ctx, aliasPath); err == nil || !strings.Contains(err.Error(), "contains a symlink") {
			if store != nil {
				store.Close()
			}
			t.Fatalf("symlink database parent accepted: %v", err)
		}
		after, err := os.ReadFile(databasePath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("symlink-parent refusal changed database content")
		}
		assertNoSQLiteSidecars(t, databasePath)
	})

	t.Run("foreign owner metadata", func(t *testing.T) {
		databaseDirectory, databasePath, before := newFixture(t)
		info, err := os.Stat(databaseDirectory)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateOwnedDirectoryInfo(info, os.Geteuid()+1); err == nil || !strings.Contains(err.Error(), "unsafe ownership") {
			t.Fatalf("foreign directory owner metadata accepted: %v", err)
		}
		after, err := os.ReadFile(databasePath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("owner refusal changed database content")
		}
		assertNoSQLiteSidecars(t, databasePath)
	})
}
