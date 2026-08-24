package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// OpenReadOnly opens an existing generation database without creating files,
// running migrations, changing journal mode, or writing recovery state.
func OpenReadOnly(ctx context.Context, path string) (*Store, error) {
	abs, err := validateExistingDatabasePath(path)
	if err != nil {
		return nil, err
	}
	if err := validateReadOnlyStateFile(abs); err != nil {
		return nil, err
	}
	dbDir := filepath.Dir(abs)
	if err := validateOwnedDirectory(dbDir); err != nil {
		return nil, fmt.Errorf("read-only database directory: %w", err)
	}
	root := stateRootForDatabase(abs)
	if err := validateStateRoot(root); err != nil {
		return nil, err
	}
	// immutable=1 prevents SQLite from creating or updating WAL/SHM/lock
	// sidecars. Every writable transition checkpoints and fsyncs before it
	// reports success, so the main database is the authoritative RO image.
	db, err := sql.Open("sqlite", "file:"+abs+"?mode=ro&immutable=1")
	if err != nil {
		return nil, fmt.Errorf("open read-only state database: %w", err)
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA query_only=ON"} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("read-only state database %s: %w", pragma, err)
		}
	}
	if err := validateMigrationHistory(ctx, db, true); err != nil {
		db.Close()
		return nil, err
	}
	store := &Store{DB: db, Dir: root, DBDir: dbDir, Path: abs}
	if err := store.QuickCheck(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

// OpenRecovery opens an existing current-schema database for the narrow early
// recovery and static timer paths. It never creates or migrates state. This
// keeps package upgrades and recovery as separate, reviewable operations.
func OpenRecovery(ctx context.Context, path string) (*Store, error) {
	abs, err := validateExistingDatabasePath(path)
	if err != nil {
		return nil, err
	}
	if err := validateReadOnlyStateFile(abs); err != nil {
		return nil, err
	}
	dbDir := filepath.Dir(abs)
	if err := validateOwnedDirectory(dbDir); err != nil {
		return nil, fmt.Errorf("recovery database directory: %w", err)
	}
	root := stateRootForDatabase(abs)
	if err := validateStateRoot(root); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+abs+"?mode=rw")
	if err != nil {
		return nil, fmt.Errorf("open recovery state database: %w", err)
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA synchronous=FULL"} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("recovery state database %s: %w", pragma, err)
		}
	}
	var journalMode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil || strings.ToLower(journalMode) != "wal" {
		db.Close()
		if err != nil {
			return nil, fmt.Errorf("read recovery journal mode: %w", err)
		}
		return nil, fmt.Errorf("recovery database journal mode %q is not wal", journalMode)
	}
	if err := validateMigrationHistory(ctx, db, true); err != nil {
		db.Close()
		return nil, err
	}
	store := &Store{DB: db, Dir: root, DBDir: dbDir, Path: abs}
	if err := store.QuickCheck(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func validateExistingDatabasePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil || abs != path || strings.ContainsAny(abs, "?#%") || !databaseNamePattern.MatchString(filepath.Base(abs)) {
		return "", errors.New("existing state database path is invalid")
	}
	return abs, nil
}

func validateReadOnlyStateFile(path string) error {
	for _, candidate := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) && candidate != path {
			continue
		}
		if err != nil {
			return fmt.Errorf("stat read-only state file: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("read-only state file %s has unsafe type or permissions", filepath.Base(candidate))
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
			return fmt.Errorf("read-only state file %s has unsafe ownership", filepath.Base(candidate))
		}
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return errors.New("read-only state database directory contains a symlink")
	}
	return nil
}

type migrationHistoryReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func validateMigrationHistory(ctx context.Context, db migrationHistoryReader, requireCurrent bool) error {
	rows, err := db.QueryContext(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return fmt.Errorf("read state migration history: %w", err)
	}
	defer rows.Close()
	expected := 1
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return err
		}
		if version != expected {
			return fmt.Errorf("state migration history is not contiguous at version %d (found %d)", expected, version)
		}
		expected++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	current := expected - 1
	if requireCurrent && current != currentSchemaVersion {
		return fmt.Errorf("state schema version %d is not the required version %d", current, currentSchemaVersion)
	}
	if current > currentSchemaVersion {
		return fmt.Errorf("state schema version %d is newer than supported version %d", current, currentSchemaVersion)
	}
	return nil
}
