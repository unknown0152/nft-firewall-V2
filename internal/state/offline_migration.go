package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// OfflineMigrationResult records non-secret identities for the source,
// byte-identical backup, and migrated schema-6 destination.
type OfflineMigrationResult struct {
	SourceSchema      int
	SourceSHA256      string
	BackupSHA256      string
	DestinationSHA256 string
}

const maxOfflineMigrationDatabaseBytes int64 = 8 << 30

// MigrateOffline copies one exact supported legacy database to a protected
// backup, migrates a separate destination, and leaves the source unchanged.
// The caller must hold and mark the shared NFTFW mutation lock.
func MigrateOffline(ctx context.Context, source, backup, destination string) (OfflineMigrationResult, error) {
	var result OfflineMigrationResult
	if !MutationLockHeld(ctx) {
		return result, errors.New("offline state migration requires the held global mutation lock")
	}
	sourcePath, err := validateOfflineSourcePath(source)
	if err != nil {
		return result, err
	}
	backupPath, err := prepareOfflineOutputPath(backup)
	if err != nil {
		return result, fmt.Errorf("prepare offline migration backup: %w", err)
	}
	destinationPath, err := prepareOfflineOutputPath(destination)
	if err != nil {
		return result, fmt.Errorf("prepare offline migration destination: %w", err)
	}
	if sourcePath == backupPath || sourcePath == destinationPath || backupPath == destinationPath {
		return result, errors.New("offline migration source, backup, and destination must be distinct")
	}
	if err := validateOfflineDestinationRoot(destinationPath); err != nil {
		return result, err
	}

	sourceSchema, sourceDigest, err := inspectLegacyDatabase(ctx, sourcePath)
	if err != nil {
		return result, err
	}
	result.SourceSchema = sourceSchema
	result.SourceSHA256 = sourceDigest

	backupDigest, err := copyRegularFileExclusive(sourcePath, backupPath)
	if err != nil {
		return result, fmt.Errorf("create byte-identical legacy backup: %w", err)
	}
	result.BackupSHA256 = backupDigest
	if backupDigest != sourceDigest {
		return result, errors.New("legacy database changed while its protected backup was created")
	}
	backupSchema, checkedBackupDigest, err := inspectLegacyDatabase(ctx, backupPath)
	if err != nil {
		return result, fmt.Errorf("verify protected legacy backup: %w", err)
	}
	if backupSchema != sourceSchema || checkedBackupDigest != sourceDigest {
		return result, errors.New("protected legacy backup identity mismatch")
	}

	work, err := createMigrationWorkFile(backupPath, filepath.Dir(destinationPath))
	if err != nil {
		return result, err
	}
	defer removeMigrationWorkFiles(work)
	if err := migrateOfflineWork(ctx, work, sourceSchema); err != nil {
		return result, err
	}
	verified, err := OpenReadOnly(ctx, work)
	if err != nil {
		return result, fmt.Errorf("verify migrated schema-6 destination: %w", err)
	}
	if err := verified.QuickCheck(ctx); err != nil {
		verified.Close()
		return result, fmt.Errorf("verify migrated database integrity: %w", err)
	}
	if err := verified.Close(); err != nil {
		return result, err
	}
	destinationDigest, err := hashRegularFile(work)
	if err != nil {
		return result, err
	}
	finalSourceDigest, err := hashRegularFile(sourcePath)
	if err != nil {
		return result, err
	}
	if finalSourceDigest != sourceDigest {
		return result, errors.New("legacy source changed during offline migration")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(sourcePath + suffix); err == nil {
			return result, errors.New("legacy source acquired a SQLite sidecar during offline migration")
		} else if !errors.Is(err, os.ErrNotExist) {
			return result, err
		}
	}
	if err := publishMigrationWorkFile(work, destinationPath); err != nil {
		return result, err
	}
	result.DestinationSHA256 = destinationDigest
	return result, nil
}

func validateOfflineSourcePath(path string) (string, error) {
	abs, err := validateExistingDatabasePath(path)
	if err != nil {
		return "", fmt.Errorf("offline migration source: %w", err)
	}
	if err := validateReadOnlyStateFile(abs); err != nil {
		return "", fmt.Errorf("offline migration source: %w", err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(abs + suffix); err == nil {
			return "", fmt.Errorf("offline migration source has a SQLite %s sidecar; create a clean backup with the prior release first", strings.TrimPrefix(suffix, "-"))
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return abs, nil
}

func prepareOfflineOutputPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil || abs != path || strings.ContainsAny(abs, "?#%") || !databaseNamePattern.MatchString(filepath.Base(abs)) {
		return "", errors.New("output path is invalid")
	}
	parent := filepath.Dir(abs)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return "", errors.New("output directory contains a symlink")
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return "", errors.New("output directory is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return "", errors.New("output directory has unsafe ownership")
	}
	for _, candidate := range []string{abs, abs + "-wal", abs + "-shm", abs + "-journal"} {
		if _, err := os.Lstat(candidate); err == nil {
			return "", fmt.Errorf("output already exists: %s", filepath.Base(candidate))
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return abs, nil
}

func validateOfflineDestinationRoot(destination string) error {
	root := stateRootForDatabase(destination)
	for _, name := range []string{activeMarkerName, activeSnapshotName} {
		path := filepath.Join(root, name)
		if _, err := os.Lstat(path); err == nil {
			return errors.New("offline migration destination belongs to an enforcement-enabled or legacy-active state root")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func inspectLegacyDatabase(ctx context.Context, path string) (int, string, error) {
	digest, err := hashRegularFile(path)
	if err != nil {
		return 0, "", err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		return 0, "", fmt.Errorf("open legacy database read-only: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA query_only=ON"} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			return 0, "", fmt.Errorf("legacy database %s: %w", pragma, err)
		}
	}
	if err := validateMigrationHistory(ctx, db, false); err != nil {
		return 0, "", err
	}
	var version int
	if err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&version); err != nil {
		return 0, "", err
	}
	if version < 1 || version >= currentSchemaVersion {
		return 0, "", fmt.Errorf("offline migration requires exact legacy schema 1..%d, found %d", currentSchemaVersion-1, version)
	}
	var integrity string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		if err != nil {
			return 0, "", err
		}
		return 0, "", fmt.Errorf("legacy SQLite quick_check: %s", integrity)
	}
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return 0, "", err
	}
	if rows.Next() {
		rows.Close()
		return 0, "", errors.New("legacy database contains a foreign-key violation")
	}
	if err := rows.Close(); err != nil {
		return 0, "", err
	}
	if err := validateLegacyObjects(ctx, db, version); err != nil {
		return 0, "", err
	}
	return version, digest, nil
}

func validateLegacyObjects(ctx context.Context, db *sql.DB, version int) error {
	expected := []string{
		"index:claims_address_idx",
		"index:generations_status_idx",
		"table:audit",
		"table:claims",
		"table:generations",
		"table:schema_migrations",
	}
	if version >= 2 {
		expected = append(expected, "table:integration_state")
	}
	if version >= 4 {
		expected = append(expected, "trigger:audit_prune_after_insert")
	}
	if version >= 5 {
		expected = append(expected, "table:runtime_claim_publication")
	}
	sort.Strings(expected)
	rows, err := db.QueryContext(ctx, "SELECT type || ':' || name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type || ':' || name")
	if err != nil {
		return err
	}
	defer rows.Close()
	var observed []string
	for rows.Next() {
		var object string
		if err := rows.Scan(&object); err != nil {
			return err
		}
		observed = append(observed, object)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if strings.Join(observed, "\n") != strings.Join(expected, "\n") {
		return errors.New("legacy database object inventory is not an exact supported schema")
	}
	expectedColumns := map[string][]string{
		"schema_migrations": {"version", "applied_at"},
		"generations":       {"id", "checksum", "script_path", "status", "created_at", "rollback_deadline", "previous_id"},
		"claims":            {"id", "address", "family", "source", "reason", "actor", "created_at", "expires_at"},
		"audit":             {"id", "created_at", "actor", "event", "detail"},
	}
	if version >= 2 {
		expectedColumns["integration_state"] = []string{"name", "status", "entry_count", "last_success", "updated_at"}
	}
	if version >= 3 {
		expectedColumns["generations"] = append(expectedColumns["generations"], "observed_hash")
	}
	if version >= 5 {
		expectedColumns["runtime_claim_publication"] = []string{"singleton", "desired_revision", "applied_revision", "updated_at"}
	}
	for table, columns := range expectedColumns {
		if err := validateLegacyColumns(ctx, db, table, columns); err != nil {
			return err
		}
	}
	for index, columns := range map[string][]string{
		"claims_address_idx":     {"address", "family"},
		"generations_status_idx": {"status"},
	} {
		if err := validateLegacyIndex(ctx, db, index, columns); err != nil {
			return err
		}
	}
	if version >= 4 {
		var trigger string
		if err := db.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='audit_prune_after_insert'").Scan(&trigger); err != nil {
			return err
		}
		if !strings.Contains(trigger, "DELETE FROM audit") || !strings.Contains(trigger, "NEW.id - 10000") {
			return errors.New("legacy audit retention trigger is not the exact supported contract")
		}
	}
	return nil
}

func validateLegacyColumns(ctx context.Context, db *sql.DB, table string, expected []string) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info("`+strings.ReplaceAll(table, `"`, `""`)+`")`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var observed []string
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return err
		}
		observed = append(observed, name)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if strings.Join(observed, "\n") != strings.Join(expected, "\n") {
		return fmt.Errorf("legacy table %s columns are not the exact supported schema", table)
	}
	return nil
}

func validateLegacyIndex(ctx context.Context, db *sql.DB, index string, expected []string) error {
	rows, err := db.QueryContext(ctx, `PRAGMA index_info("`+strings.ReplaceAll(index, `"`, `""`)+`")`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var observed []string
	for rows.Next() {
		var sequence, cid int
		var name string
		if err := rows.Scan(&sequence, &cid, &name); err != nil {
			return err
		}
		observed = append(observed, name)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if strings.Join(observed, "\n") != strings.Join(expected, "\n") {
		return fmt.Errorf("legacy index %s columns are not the exact supported schema", index)
	}
	return nil
}

func copyRegularFileExclusive(source, destination string) (string, error) {
	input, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("offline migration input is not a protected regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return "", errors.New("offline migration input has unsafe ownership")
	}
	if err := syscall.Flock(int(input.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return "", errors.New("offline migration input is busy")
	}
	defer syscall.Flock(int(input.Fd()), syscall.LOCK_UN)

	parent := filepath.Dir(destination)
	tmp, err := os.CreateTemp(parent, "nftfw-offline-copy-*.db")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	first := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, first), input); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	second := sha256.New()
	if _, err := io.Copy(second, input); err != nil {
		return "", err
	}
	firstDigest := hex.EncodeToString(first.Sum(nil))
	if firstDigest != hex.EncodeToString(second.Sum(nil)) {
		return "", errors.New("offline migration input changed while it was copied")
	}
	if err := os.Link(tmpPath, destination); err != nil {
		return "", fmt.Errorf("publish protected copy without overwrite: %w", err)
	}
	if err := syncDirectory(parent); err != nil {
		return "", err
	}
	return firstDigest, nil
}

func createMigrationWorkFile(source, parent string) (string, error) {
	input, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer input.Close()
	work, err := os.CreateTemp(parent, "nftfw-migration-work-*.db")
	if err != nil {
		return "", err
	}
	path := work.Name()
	if err := work.Chmod(0o600); err != nil {
		work.Close()
		os.Remove(path)
		return "", err
	}
	if _, err := io.Copy(work, input); err != nil {
		work.Close()
		os.Remove(path)
		return "", err
	}
	if err := work.Sync(); err != nil {
		work.Close()
		os.Remove(path)
		return "", err
	}
	if err := work.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func migrateOfflineWork(ctx context.Context, path string, sourceSchema int) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
	} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return fmt.Errorf("offline migration %s: %w", pragma, err)
		}
	}
	if err := validateWritableSchemaConstraints(ctx, db, sourceSchema); err != nil {
		db.Close()
		return fmt.Errorf("validate legacy schema constraints: %w", err)
	}
	store := &Store{
		DB:                   db,
		Dir:                  stateRootForDatabase(path),
		DBDir:                filepath.Dir(path),
		Path:                 path,
		allowLegacyMigration: true,
	}
	if err := store.migrate(ctx); err != nil {
		store.Close()
		return fmt.Errorf("migrate schema %d to %d: %w", sourceSchema, currentSchemaVersion, err)
	}
	if err := validateWritableSchemaConstraints(ctx, db, currentSchemaVersion); err != nil {
		store.Close()
		return fmt.Errorf("validate migrated schema-6 constraints: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		store.Close()
		return fmt.Errorf("checkpoint migrated database: %w", err)
	}
	if err := store.syncDatabase(); err != nil {
		store.Close()
		return err
	}
	if err := store.Close(); err != nil {
		return err
	}
	return nil
}

func validateWritableSchemaConstraints(ctx context.Context, db *sql.DB, version int) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	expectRefusal := func(name, statement string, args ...any) error {
		if _, err := tx.ExecContext(ctx, statement, args...); err == nil {
			return fmt.Errorf("%s constraint is absent", name)
		}
		return nil
	}
	if err := expectRefusal(
		"schema migration uniqueness",
		"INSERT INTO schema_migrations(version,applied_at) VALUES(1,'duplicate')",
	); err != nil {
		return err
	}
	if err := expectRefusal(
		"claim family",
		"INSERT INTO claims(address,family,source,reason,actor,created_at) VALUES('invalid','invalid','r2','r2','r2','r2')",
	); err != nil {
		return err
	}
	var maximumGeneration int64
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM generations").Scan(&maximumGeneration); err != nil {
		return err
	}
	if maximumGeneration > int64(^uint64(0)>>1)-2 {
		return errors.New("generation identifier space is exhausted")
	}
	generationID := maximumGeneration + 1
	missingPreviousID := maximumGeneration + 2
	if version < currentSchemaVersion {
		if err := expectRefusal(
			"legacy generation status",
			"INSERT INTO generations(id,checksum,script_path,status,created_at) VALUES(?,?,?,?,?)",
			generationID, strings.Repeat("a", 64), "/r2/invalid.nft", "invalid", "r2",
		); err != nil {
			return err
		}
		if err := expectRefusal(
			"legacy generation foreign key",
			"INSERT INTO generations(id,checksum,script_path,status,created_at,previous_id) VALUES(?,?,?,?,?,?)",
			generationID, strings.Repeat("a", 64), "/r2/foreign-key.nft", "pending", "r2", missingPreviousID,
		); err != nil {
			return err
		}
		if version >= 3 {
			if _, err := tx.ExecContext(
				ctx,
				"INSERT INTO generations(id,checksum,script_path,status,created_at) VALUES(?,?,?,?,?)",
				generationID, strings.Repeat("a", 64), "/r2/probe.nft", "pending", "r2",
			); err != nil {
				return err
			}
			if err := expectRefusal(
				"legacy observed fingerprint",
				"UPDATE generations SET observed_hash=NULL WHERE id=?",
				generationID,
			); err != nil {
				return err
			}
		}
	} else {
		if err := expectRefusal(
			"schema-6 generation status",
			"INSERT INTO generations(id,checksum,script_path,status,created_at,boot_id) VALUES(?,?,?,?,?,?)",
			generationID, strings.Repeat("a", 64), "/r2/invalid.nft", "invalid", "r2", "r2",
		); err != nil {
			return err
		}
		if err := expectRefusal(
			"schema-6 generation foreign key",
			"INSERT INTO generations(id,checksum,script_path,status,created_at,boot_id,previous_id) VALUES(?,?,?,?,?,?,?)",
			generationID, strings.Repeat("a", 64), "/r2/foreign-key.nft", "pending", "r2", "r2", missingPreviousID,
		); err != nil {
			return err
		}
		if _, err := tx.ExecContext(
			ctx,
			"INSERT INTO generations(id,checksum,script_path,status,created_at,boot_id) VALUES(?,?,?,?,?,?)",
			generationID, strings.Repeat("a", 64), "/r2/probe.nft", "pending", "r2", "r2",
		); err != nil {
			return err
		}
		if err := expectRefusal(
			"schema-6 observed fingerprint",
			"UPDATE generations SET observed_hash=NULL WHERE id=?",
			generationID,
		); err != nil {
			return err
		}
	}
	if version >= 2 {
		if _, err := tx.ExecContext(ctx, "DELETE FROM integration_state WHERE name='nftfw-r2-constraint-probe'"); err != nil {
			return err
		}
		if err := expectRefusal(
			"integration entry count",
			"INSERT INTO integration_state(name,status,entry_count,updated_at) VALUES('nftfw-r2-constraint-probe','degraded',-1,'r2')",
		); err != nil {
			return err
		}
	}
	if version >= 4 {
		var maximum int64
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM audit").Scan(&maximum); err != nil {
			return err
		}
		if maximum > int64(^uint64(0)>>1)-MaxAuditRows-1 {
			return errors.New("audit identifier space cannot prove bounded retention")
		}
		oldID := maximum + 1
		newID := oldID + MaxAuditRows
		if _, err := tx.ExecContext(
			ctx,
			"INSERT INTO audit(id,created_at,actor,event,detail) VALUES(?,?,?,?,?)",
			oldID, "r2", "r2", "r2", "r2",
		); err != nil {
			return err
		}
		if _, err := tx.ExecContext(
			ctx,
			"INSERT INTO audit(id,created_at,actor,event,detail) VALUES(?,?,?,?,?)",
			newID, "r2", "r2", "r2", "r2",
		); err != nil {
			return err
		}
		var retained int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit WHERE id=?", oldID).Scan(&retained); err != nil {
			return err
		}
		if retained != 0 {
			return errors.New("audit retention trigger did not prune the bounded predecessor")
		}
	}
	if version >= 5 {
		if err := expectRefusal(
			"runtime claim revision",
			"UPDATE runtime_claim_publication SET desired_revision=-1 WHERE singleton=1",
		); err != nil {
			return err
		}
	}
	return nil
}

func publishMigrationWorkFile(work, destination string) error {
	if err := os.Link(work, destination); err != nil {
		return fmt.Errorf("publish migrated database without overwrite: %w", err)
	}
	return syncDirectory(filepath.Dir(destination))
}

func removeMigrationWorkFiles(path string) {
	for _, candidate := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		_ = os.Remove(candidate)
	}
}

func hashRegularFile(path string) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		info.Size() <= 0 || info.Size() > maxOfflineMigrationDatabaseBytes {
		return "", errors.New("state file is not a protected regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return "", errors.New("state file has unsafe ownership")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
