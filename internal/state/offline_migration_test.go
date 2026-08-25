package state

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLegacyV1Database(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
PRAGMA journal_mode=DELETE;
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE generations (
 id INTEGER PRIMARY KEY,
 checksum TEXT NOT NULL,
 script_path TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','applied','committed','rolled_back')),
 created_at TEXT NOT NULL,
 rollback_deadline TEXT,
 previous_id INTEGER REFERENCES generations(id)
);
CREATE INDEX generations_status_idx ON generations(status);
CREATE TABLE claims (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 address TEXT NOT NULL,
 family TEXT NOT NULL CHECK(family IN ('ipv4','ipv6')),
 source TEXT NOT NULL,
 reason TEXT NOT NULL,
 actor TEXT NOT NULL,
 created_at TEXT NOT NULL,
 expires_at TEXT
);
CREATE INDEX claims_address_idx ON claims(address, family);
CREATE TABLE audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 created_at TEXT NOT NULL,
 actor TEXT NOT NULL,
 event TEXT NOT NULL,
 detail TEXT NOT NULL
);
INSERT INTO schema_migrations VALUES(1, '2026-01-01T00:00:00Z');
INSERT INTO generations(id,checksum,script_path,status,created_at)
VALUES(1, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '/legacy/one.nft', 'committed', '2026-01-01T00:00:00Z');
INSERT INTO claims(address,family,source,reason,actor,created_at)
VALUES('203.0.113.9/32','ipv4','manual','legacy-proof','r2','2026-01-01T00:00:00Z');
`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func advanceLegacyDatabase(t *testing.T, path string, target int) {
	t.Helper()
	if target < 1 || target > 5 {
		t.Fatalf("unsupported fixture target %d", target)
	}
	if target == 1 {
		return
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if target >= 2 {
		if _, err := db.Exec(`
CREATE TABLE integration_state (
 name TEXT PRIMARY KEY,
 status TEXT NOT NULL,
 entry_count INTEGER NOT NULL CHECK(entry_count >= 0),
 last_success TEXT,
 updated_at TEXT NOT NULL
);
INSERT INTO schema_migrations VALUES(2, '2026-01-02T00:00:00Z');
`); err != nil {
			t.Fatal(err)
		}
	}
	if target >= 3 {
		if _, err := db.Exec(`
ALTER TABLE generations ADD COLUMN observed_hash TEXT NOT NULL DEFAULT '';
INSERT INTO schema_migrations VALUES(3, '2026-01-03T00:00:00Z');
`); err != nil {
			t.Fatal(err)
		}
	}
	if target >= 4 {
		if _, err := db.Exec(`
CREATE TRIGGER audit_prune_after_insert
AFTER INSERT ON audit
BEGIN
 DELETE FROM audit WHERE id <= NEW.id - 10000;
END;
INSERT INTO schema_migrations VALUES(4, '2026-01-04T00:00:00Z');
`); err != nil {
			t.Fatal(err)
		}
	}
	if target >= 5 {
		if _, err := db.Exec(`
CREATE TABLE runtime_claim_publication (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 desired_revision INTEGER NOT NULL CHECK(desired_revision>=0),
 applied_revision INTEGER NOT NULL CHECK(applied_revision>=0),
 updated_at TEXT NOT NULL
);
INSERT INTO runtime_claim_publication VALUES(1,1,0,'2026-01-05T00:00:00Z');
INSERT INTO integration_state(name,status,entry_count,last_success,updated_at)
VALUES('runtime/claims','degraded',0,NULL,'2026-01-05T00:00:00Z');
INSERT INTO schema_migrations VALUES(5, '2026-01-05T00:00:00Z');
`); err != nil {
			t.Fatal(err)
		}
	}
}

func heldMigrationContext(t *testing.T) (context.Context, func()) {
	t.Helper()
	lockDir := secureTestDir(t)
	release, err := AcquireMutationLock(context.Background(), lockDir)
	if err != nil {
		t.Fatal(err)
	}
	return WithMutationLock(context.Background()), release
}

func TestOfflineMigrationV1ToV6PreservesSourceAndBackup(t *testing.T) {
	root := secureTestDir(t)
	source := filepath.Join(root, "legacy.db")
	backup := filepath.Join(root, "backups", "legacy-v1.db")
	destination := filepath.Join(root, "generation-state", "state.db")
	writeLegacyV1Database(t, source)
	sourceBefore, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	ctx, release := heldMigrationContext(t)
	defer release()
	result, err := MigrateOffline(ctx, source, backup, destination)
	if err != nil {
		t.Fatal(err)
	}
	if result.SourceSchema != 1 || result.SourceSHA256 == "" ||
		result.SourceSHA256 != result.BackupSHA256 || result.DestinationSHA256 == "" {
		t.Fatalf("unexpected migration result: %#v", result)
	}
	sourceAfter, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	backupBytes, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sourceBefore, sourceAfter) || !bytes.Equal(sourceBefore, backupBytes) {
		t.Fatal("offline migration changed the source or produced a non-identical backup")
	}
	if info, err := os.Stat(backup); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode is unsafe: info=%v err=%v", info, err)
	}
	if info, err := os.Stat(destination); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("destination mode is unsafe: info=%v err=%v", info, err)
	}
	store, err := OpenReadOnly(context.Background(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var history string
	if err := store.DB.QueryRowContext(
		context.Background(),
		"SELECT group_concat(version, ',') FROM (SELECT version FROM schema_migrations ORDER BY version)",
	).Scan(&history); err != nil {
		t.Fatal(err)
	}
	if history != "1,2,3,4,5,6" {
		t.Fatalf("migration history=%q", history)
	}
	var claims int
	if err := store.DB.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM claims WHERE reason='legacy-proof'").Scan(&claims); err != nil || claims != 1 {
		t.Fatalf("legacy claim not preserved: count=%d err=%v", claims, err)
	}
	var bootID, status string
	if err := store.DB.QueryRowContext(context.Background(), "SELECT boot_id,status FROM generations WHERE id=1").Scan(&bootID, &status); err != nil {
		t.Fatal(err)
	}
	if bootID != "legacy-v2.0.1" || status != "committed" {
		t.Fatalf("legacy generation migration mismatch: boot=%q status=%q", bootID, status)
	}
}

func TestOfflineMigrationEverySupportedLegacySchema(t *testing.T) {
	for version := 1; version <= 5; version++ {
		t.Run(fmt.Sprintf("schema-%d", version), func(t *testing.T) {
			root := secureTestDir(t)
			source := filepath.Join(root, "legacy.db")
			writeLegacyV1Database(t, source)
			advanceLegacyDatabase(t, source, version)
			ctx, release := heldMigrationContext(t)
			defer release()
			result, err := MigrateOffline(
				ctx,
				source,
				filepath.Join(root, "backup.db"),
				filepath.Join(root, "generation-state", "state.db"),
			)
			if err != nil {
				t.Fatal(err)
			}
			if result.SourceSchema != version {
				t.Fatalf("source schema=%d want=%d", result.SourceSchema, version)
			}
			store, err := OpenReadOnly(context.Background(), filepath.Join(root, "generation-state", "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOfflineMigrationRequiresLockAndRefusesUnsafeInputs(t *testing.T) {
	t.Run("lock marker", func(t *testing.T) {
		root := secureTestDir(t)
		source := filepath.Join(root, "legacy.db")
		writeLegacyV1Database(t, source)
		_, err := MigrateOffline(
			context.Background(),
			source,
			filepath.Join(root, "backup.db"),
			filepath.Join(root, "state.db"),
		)
		if err == nil || !strings.Contains(err.Error(), "global mutation lock") {
			t.Fatalf("migration without lock marker: %v", err)
		}
	})
	t.Run("sqlite sidecar", func(t *testing.T) {
		root := secureTestDir(t)
		source := filepath.Join(root, "legacy.db")
		writeLegacyV1Database(t, source)
		if err := os.WriteFile(source+"-wal", nil, 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, release := heldMigrationContext(t)
		defer release()
		_, err := MigrateOffline(ctx, source, filepath.Join(root, "backup.db"), filepath.Join(root, "state.db"))
		if err == nil || !strings.Contains(err.Error(), "sidecar") {
			t.Fatalf("migration accepted a sidecar: %v", err)
		}
	})
	t.Run("unknown object", func(t *testing.T) {
		root := secureTestDir(t)
		source := filepath.Join(root, "legacy.db")
		writeLegacyV1Database(t, source)
		db, err := sql.Open("sqlite", source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("CREATE TABLE injected(value TEXT)"); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		ctx, release := heldMigrationContext(t)
		defer release()
		_, err = MigrateOffline(ctx, source, filepath.Join(root, "backup.db"), filepath.Join(root, "state.db"))
		if err == nil || !strings.Contains(err.Error(), "object inventory") {
			t.Fatalf("migration accepted an unknown object: %v", err)
		}
	})
	t.Run("weakened constraint", func(t *testing.T) {
		root := secureTestDir(t)
		source := filepath.Join(root, "legacy.db")
		writeLegacyV1Database(t, source)
		db, err := sql.Open("sqlite", source)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec(`
ALTER TABLE claims RENAME TO claims_old;
CREATE TABLE claims (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 address TEXT NOT NULL,
 family TEXT NOT NULL,
 source TEXT NOT NULL,
 reason TEXT NOT NULL,
 actor TEXT NOT NULL,
 created_at TEXT NOT NULL,
 expires_at TEXT
);
INSERT INTO claims SELECT * FROM claims_old;
DROP TABLE claims_old;
CREATE INDEX claims_address_idx ON claims(address, family);
`)
		if err != nil {
			db.Close()
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		ctx, release := heldMigrationContext(t)
		defer release()
		_, err = MigrateOffline(ctx, source, filepath.Join(root, "backup.db"), filepath.Join(root, "state.db"))
		if err == nil || !strings.Contains(err.Error(), "claim family constraint") {
			t.Fatalf("migration accepted a weakened constraint: %v", err)
		}
	})
	t.Run("current schema", func(t *testing.T) {
		root := secureTestDir(t)
		source := filepath.Join(root, "current.db")
		store, err := Open(context.Background(), source)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		ctx, release := heldMigrationContext(t)
		defer release()
		_, err = MigrateOffline(ctx, source, filepath.Join(root, "backup.db"), filepath.Join(root, "state.db"))
		if err == nil || !strings.Contains(err.Error(), "schema 1..5") {
			t.Fatalf("migration accepted current schema: %v", err)
		}
	})
	t.Run("active destination root", func(t *testing.T) {
		root := secureTestDir(t)
		source := filepath.Join(root, "legacy.db")
		writeLegacyV1Database(t, source)
		if err := os.WriteFile(filepath.Join(root, activeMarkerName), []byte("enabled\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, release := heldMigrationContext(t)
		defer release()
		_, err := MigrateOffline(
			ctx,
			source,
			filepath.Join(root, "backup.db"),
			filepath.Join(root, "generation-state", "state.db"),
		)
		if err == nil || !strings.Contains(err.Error(), "enforcement-enabled") {
			t.Fatalf("migration accepted an active destination root: %v", err)
		}
	})
}

func TestOfflineMigrationNeverOverwritesOutput(t *testing.T) {
	root := secureTestDir(t)
	source := filepath.Join(root, "legacy.db")
	backup := filepath.Join(root, "backup.db")
	destination := filepath.Join(root, "state.db")
	writeLegacyV1Database(t, source)
	if err := os.WriteFile(destination, []byte("retain"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, release := heldMigrationContext(t)
	defer release()
	if _, err := MigrateOffline(ctx, source, backup, destination); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("migration overwrote or accepted an existing destination: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil || string(got) != "retain" {
		t.Fatalf("existing destination changed: %q err=%v", got, err)
	}
	if _, err := os.Stat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup was created before output preflight completed: %v", err)
	}
}
