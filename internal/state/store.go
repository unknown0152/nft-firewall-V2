// Package state persists generations, safe-apply leases, dynamic claims, and audit records.
package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	DB   *sql.DB
	Dir  string
	Path string
	mu   sync.Mutex
}

const (
	currentSchemaVersion = 5
	MaxAuditRows         = 10000
)

var databaseNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var claimSourcePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{0,63}(/[a-zA-Z0-9_.-]{1,64})?$`)

type Generation struct {
	ID               uint64
	Checksum         string
	ObservedHash     string
	ScriptPath       string
	Status           string
	CreatedAt        time.Time
	RollbackDeadline *time.Time
	PreviousID       *uint64
}

type Claim struct {
	ID        int64
	Address   string
	Family    string
	Source    string
	Reason    string
	Actor     string
	CreatedAt time.Time
	ExpiresAt *time.Time
}

type IntegrationState struct {
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	EntryCount  int        `json:"entry_count"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type ClaimPublication struct {
	DesiredRevision uint64
	AppliedRevision uint64
}

func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("state database path is empty")
	}
	path, err := prepareStatePath(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	for _, stmt := range []string{"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL"} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("sqlite %s: %w", stmt, err)
		}
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := restrictRegularFile(path+suffix, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			db.Close()
			return nil, err
		}
	}
	s := &Store{DB: db, Dir: filepath.Dir(path), Path: path}
	if _, markerErr := os.Stat(filepath.Join(s.Dir, activeMarkerName)); markerErr == nil {
		var requiredTables int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('schema_migrations','generations')").Scan(&requiredTables); err != nil || requiredTables != 2 {
			db.Close()
			return nil, errors.New("enforced state database lacks required generation schema")
		}
		var committed int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM generations WHERE status='committed'").Scan(&committed); err != nil || committed == 0 {
			db.Close()
			return nil, errors.New("enforced state database has no committed generation")
		}
	}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func prepareStatePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve state database path: %w", err)
	}
	if !databaseNamePattern.MatchString(filepath.Base(abs)) {
		return "", errors.New("state database filename contains unsupported characters")
	}
	parent := filepath.Dir(abs)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return "", fmt.Errorf("create state directory: %w", err)
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("resolve state directory: %w", err)
	}
	if resolvedParent != parent {
		return "", errors.New("state directory path contains a symlink")
	}
	parentInfo, err := os.Stat(parent)
	if err != nil {
		return "", fmt.Errorf("stat state directory: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 {
		return "", errors.New("state directory must be a directory and not group/other writable")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || int64(parentStat.Uid) != int64(os.Geteuid()) {
		return "", errors.New("state directory must be owned by the current service user")
	}
	databaseExists := false
	var databaseSize int64
	for _, candidate := range []string{abs, abs + "-wal", abs + "-shm", abs + "-journal"} {
		if info, statErr := os.Lstat(candidate); statErr == nil {
			if candidate == abs {
				databaseExists = true
				databaseSize = info.Size()
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return "", fmt.Errorf("state file %s must be regular and non-symlink", filepath.Base(candidate))
			}
			stat, valid := info.Sys().(*syscall.Stat_t)
			if !valid || int64(stat.Uid) != int64(os.Geteuid()) {
				return "", fmt.Errorf("state file %s has unsafe ownership", filepath.Base(candidate))
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", fmt.Errorf("stat state file: %w", statErr)
		}
	}
	marker := filepath.Join(parent, activeMarkerName)
	if markerInfo, markerErr := os.Lstat(marker); markerErr == nil {
		markerStat, valid := markerInfo.Sys().(*syscall.Stat_t)
		if markerInfo.Mode()&os.ModeSymlink != 0 || !markerInfo.Mode().IsRegular() || markerInfo.Mode().Perm()&0o077 != 0 || !valid || int64(markerStat.Uid) != int64(os.Geteuid()) {
			return "", errors.New("enforcement marker has unsafe type, permissions, or ownership")
		}
		if !databaseExists || databaseSize == 0 {
			return "", errors.New("state database is missing while firewall enforcement is enabled; restore state instead of creating an empty database")
		}
	} else if !errors.Is(markerErr, os.ErrNotExist) {
		return "", fmt.Errorf("stat enforcement marker: %w", markerErr)
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", fmt.Errorf("create state database: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return "", fmt.Errorf("secure state database: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return abs, nil
}

func restrictRegularFile(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("state file %s is not a regular file", filepath.Base(path))
	}
	return os.Chmod(path, mode)
}

func (s *Store) Close() error {
	if s == nil || s.DB == nil {
		return nil
	}
	return s.DB.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`)
	if err != nil {
		return fmt.Errorf("create migrations: %w", err)
	}
	var version int
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&version); err != nil {
		return err
	}
	if version > currentSchemaVersion {
		return fmt.Errorf("state schema version %d is newer than supported version %d", version, currentSchemaVersion)
	}
	if version < 1 {
		_, err = tx.ExecContext(ctx, `
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
INSERT INTO schema_migrations(version, applied_at) VALUES(1, datetime('now'));`)
		if err != nil {
			return fmt.Errorf("migration 1: %w", err)
		}
	}
	if version < 2 {
		_, err = tx.ExecContext(ctx, `
CREATE TABLE integration_state (
 name TEXT PRIMARY KEY,
 status TEXT NOT NULL,
 entry_count INTEGER NOT NULL CHECK(entry_count >= 0),
 last_success TEXT,
 updated_at TEXT NOT NULL
);
INSERT INTO schema_migrations(version, applied_at) VALUES(2, datetime('now'));`)
		if err != nil {
			return fmt.Errorf("migration 2: %w", err)
		}
	}
	if version < 3 {
		_, err = tx.ExecContext(ctx, `
ALTER TABLE generations ADD COLUMN observed_hash TEXT NOT NULL DEFAULT '';
INSERT INTO schema_migrations(version, applied_at) VALUES(3, datetime('now'));`)
		if err != nil {
			return fmt.Errorf("migration 3: %w", err)
		}
	}
	if version < 4 {
		migration := fmt.Sprintf(`
DELETE FROM audit
WHERE id < COALESCE((SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET %d), 0);
CREATE TRIGGER audit_prune_after_insert
AFTER INSERT ON audit
BEGIN
 DELETE FROM audit WHERE id <= NEW.id - %d;
END;
INSERT INTO schema_migrations(version, applied_at) VALUES(4, datetime('now'));`, MaxAuditRows-1, MaxAuditRows)
		if _, err = tx.ExecContext(ctx, migration); err != nil {
			return fmt.Errorf("migration 4: %w", err)
		}
	}
	if version < 5 {
		_, err = tx.ExecContext(ctx, `
CREATE TABLE runtime_claim_publication (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 desired_revision INTEGER NOT NULL CHECK(desired_revision>=0),
 applied_revision INTEGER NOT NULL CHECK(applied_revision>=0),
 updated_at TEXT NOT NULL
);
INSERT INTO runtime_claim_publication(singleton,desired_revision,applied_revision,updated_at)
VALUES(1,1,0,datetime('now'));
INSERT INTO integration_state(name,status,entry_count,last_success,updated_at)
VALUES('runtime/claims','degraded',(SELECT COUNT(*) FROM claims WHERE expires_at IS NULL OR expires_at>strftime('%Y-%m-%dT%H:%M:%fZ','now')),NULL,datetime('now'))
ON CONFLICT(name) DO UPDATE SET status='degraded',entry_count=excluded.entry_count,updated_at=excluded.updated_at;
INSERT INTO schema_migrations(version, applied_at) VALUES(5, datetime('now'));`)
		if err != nil {
			return fmt.Errorf("migration 5: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}

func (s *Store) NextGeneration(ctx context.Context) (uint64, error) {
	var max uint64
	if err := s.DB.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM generations").Scan(&max); err != nil {
		return 0, err
	}
	return max + 1, nil
}

func (s *Store) SaveGeneration(ctx context.Context, id uint64, checksum, script string, previous *uint64, deadline *time.Time) error {
	if id == 0 {
		return errors.New("generation id must be positive")
	}
	if len(script) > maxActiveSnapshot {
		return errors.New("generation script exceeds 32 MiB")
	}
	if !validScriptChecksum(script, checksum) {
		return errors.New("generation script checksum is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	genDir := filepath.Join(s.Dir, "generations")
	if err := os.MkdirAll(genDir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(genDir, fmt.Sprintf("%020d.nft", id))
	tmp, err := os.CreateTemp(genDir, ".generation-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(script); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, path); err != nil {
		return err
	}
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	if err := syncDirectory(genDir); err != nil {
		return err
	}
	now := time.Now().UTC()
	var deadlineText any
	if deadline != nil {
		deadlineText = deadline.UTC().Format(time.RFC3339Nano)
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO generations(id,checksum,script_path,status,created_at,rollback_deadline,previous_id) VALUES(?,?,?,?,?,?,?)`, id, checksum, path, "pending", now.Format(time.RFC3339Nano), deadlineText, previous)
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func (s *Store) MarkApplied(ctx context.Context, id uint64) error {
	_, err := s.DB.ExecContext(ctx, "UPDATE generations SET status='applied' WHERE id=?", id)
	return err
}

func (s *Store) SetObservedHash(ctx context.Context, id uint64, hash string) error {
	decoded, err := hex.DecodeString(hash)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("observed nftables hash is malformed")
	}
	result, err := s.DB.ExecContext(ctx, "UPDATE generations SET observed_hash=? WHERE id=?", hash, id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return sql.ErrNoRows
	}
	return nil
}
func (s *Store) Commit(ctx context.Context, id uint64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE generations SET status='rolled_back' WHERE status='pending' AND id<>?", id); err != nil {
		tx.Rollback()
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE generations SET status='committed', rollback_deadline=NULL WHERE id=?", id); err != nil {
		tx.Rollback()
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return s.Audit(ctx, "system", "generation_committed", fmt.Sprintf("generation=%d", id))
}
func (s *Store) MarkRolledBack(ctx context.Context, id uint64) error {
	_, err := s.DB.ExecContext(ctx, "UPDATE generations SET status='rolled_back' WHERE id=?", id)
	return err
}

func (s *Store) Pending(ctx context.Context) (*Generation, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT id,checksum,observed_hash,script_path,status,created_at,rollback_deadline,previous_id FROM generations WHERE status IN ('pending','applied') ORDER BY id DESC LIMIT 1`)
	return scanGeneration(row)
}

func (s *Store) LastKnownGood(ctx context.Context) (*Generation, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT id,checksum,observed_hash,script_path,status,created_at,rollback_deadline,previous_id FROM generations WHERE status='committed' ORDER BY id DESC LIMIT 1`)
	return scanGeneration(row)
}

// ExpectedGeneration is the generation that should currently be represented
// in the kernel. A merely persisted (status=pending) candidate is excluded.
func (s *Store) ExpectedGeneration(ctx context.Context) (*Generation, error) {
	pending, err := s.Pending(ctx)
	if err == nil && pending.Status == "applied" {
		return pending, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return s.LastKnownGood(ctx)
}

func scanGeneration(row interface{ Scan(...any) error }) (*Generation, error) {
	var g Generation
	var created string
	var previous sql.NullInt64
	var deadlineVal sql.NullString
	if err := row.Scan(&g.ID, &g.Checksum, &g.ObservedHash, &g.ScriptPath, &g.Status, &created, &deadlineVal, &previous); err != nil {
		return nil, err
	}
	var err error
	g.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return nil, err
	}
	if deadlineVal.Valid {
		t, e := time.Parse(time.RFC3339Nano, deadlineVal.String)
		if e != nil {
			return nil, e
		}
		g.RollbackDeadline = &t
	}
	if previous.Valid {
		if previous.Int64 <= 0 {
			return nil, errors.New("generation has an invalid previous generation reference")
		}
		v := uint64(previous.Int64)
		g.PreviousID = &v
	}
	return &g, nil
}

func (s *Store) ReadScript(g *Generation) (string, error) {
	if g == nil {
		return "", errors.New("nil generation")
	}
	expectedDir := filepath.Join(s.Dir, "generations") + string(os.PathSeparator)
	abs, err := filepath.Abs(g.ScriptPath)
	if err != nil || !strings.HasPrefix(abs, expectedDir) {
		return "", errors.New("generation script path escapes the state directory")
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxActiveSnapshot {
		return "", errors.New("generation script has unsafe type or permissions")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return "", errors.New("generation script has unsafe ownership")
	}
	f, err := os.OpenFile(abs, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxActiveSnapshot+1))
	closeErr := f.Close()
	if err != nil || closeErr != nil || len(b) > maxActiveSnapshot {
		return "", errors.New("generation script bounded read failed")
	}
	want, err := hex.DecodeString(g.Checksum)
	if err != nil || len(want) != sha256.Size {
		return "", errors.New("generation checksum is malformed")
	}
	got := sha256.Sum256(b)
	if !equalBytes(got[:], want) {
		return "", errors.New("generation script checksum mismatch")
	}
	return string(b), nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *Store) AddClaim(ctx context.Context, c Claim) (int64, error) {
	return s.AddClaimBounded(ctx, c, 0)
}

func (s *Store) AddClaimBounded(ctx context.Context, c Claim, max int) (int64, error) {
	if err := ValidateClaim(c.Address, c.Family); err != nil {
		return 0, err
	}
	if err := validateClaimMetadata(c); err != nil {
		return 0, err
	}
	if c.Reason == "" {
		c.Reason = "unspecified"
	}
	now := time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	var expires any
	if c.ExpiresAt != nil {
		expires = c.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if max > 0 {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM claims WHERE expires_at IS NULL OR expires_at>?", now.Format(time.RFC3339Nano)).Scan(&count); err != nil {
			return 0, err
		}
		if count >= max {
			return 0, fmt.Errorf("claim limit reached (%d)", max)
		}
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO claims(address,family,source,reason,actor,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`, c.Address, c.Family, c.Source, c.Reason, c.Actor, c.CreatedAt.UTC().Format(time.RFC3339Nano), expires)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit(created_at,actor,event,detail) VALUES(?,?,?,?)", now.Format(time.RFC3339Nano), c.Actor, "claim_added", fmt.Sprintf("id=%d address=%s source=%s", id, c.Address, c.Source)); err != nil {
		return 0, err
	}
	if err := markClaimPublicationDirtyTx(ctx, tx, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *Store) RemoveClaim(ctx context.Context, id int64, actor string) error {
	if id <= 0 {
		return errors.New("claim id must be positive")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "DELETE FROM claims WHERE id=?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit(created_at,actor,event,detail) VALUES(?,?,?,?)", now.Format(time.RFC3339Nano), actor, "claim_removed", fmt.Sprintf("id=%d", id)); err != nil {
		return err
	}
	if err := markClaimPublicationDirtyTx(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

// RemoveOperatorClaim prevents the manual control API from deleting claims
// owned by integrations. Integration claims are replaced atomically by source.
func (s *Store) RemoveOperatorClaim(ctx context.Context, id int64, actor, kind string) error {
	if id <= 0 {
		return errors.New("claim id must be positive")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var source string
	if err := tx.QueryRowContext(ctx, "SELECT source FROM claims WHERE id=?", id).Scan(&source); err != nil {
		return err
	}
	allowed := kind == "block" && source == "manual" || kind == "allow" && isAllowSource(source)
	if !allowed {
		return fmt.Errorf("claim %d with source %s cannot be removed as %s", id, source, kind)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM claims WHERE id=?", id); err != nil {
		return err
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit(created_at,actor,event,detail) VALUES(?,?,?,?)", now.Format(time.RFC3339Nano), actor, "claim_removed", fmt.Sprintf("id=%d", id)); err != nil {
		return err
	}
	if err := markClaimPublicationDirtyTx(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

// ReplaceSourceClaims atomically replaces exactly one integration's claims.
// Validation completes before the old claims are touched.
func (s *Store) ReplaceSourceClaims(ctx context.Context, source, reason, actor string, addresses []string) (int, error) {
	return s.ReplaceSourceClaimsBounded(ctx, source, reason, actor, addresses, 0)
}

func (s *Store) ReplaceSourceClaimsBounded(ctx context.Context, source, reason, actor string, addresses []string, max int) (int, error) {
	if source == "" || actor == "" {
		return 0, errors.New("claim source and actor are required")
	}
	if len(source) > 129 || len(actor) > 128 || len(reason) > 1024 {
		return 0, errors.New("claim source, actor, or reason exceeds its size limit")
	}
	if !claimSourcePattern.MatchString(source) || isAllowSource(source) {
		return 0, errors.New("integration claim source is invalid or reserved for temporary access")
	}
	if reason == "" {
		reason = "integration"
	}
	canonical := make([]string, 0, len(addresses))
	seen := map[string]bool{}
	for _, raw := range addresses {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			if ip, ipErr := netip.ParseAddr(raw); ipErr == nil {
				p = netip.PrefixFrom(ip, ip.BitLen())
			} else {
				return 0, fmt.Errorf("invalid replacement claim %q", raw)
			}
		}
		if p.Bits() == 0 {
			return 0, errors.New("replacement claim /0 is forbidden")
		}
		value := p.Masked().String()
		if !seen[value] {
			seen[value] = true
			canonical = append(canonical, value)
		}
	}
	sort.Strings(canonical)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM claims WHERE source=?", source); err != nil {
		return 0, err
	}
	if max > 0 {
		var remaining int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM claims WHERE expires_at IS NULL OR expires_at>?", time.Now().UTC().Format(time.RFC3339Nano)).Scan(&remaining); err != nil {
			return 0, err
		}
		if remaining+len(canonical) > max {
			return 0, fmt.Errorf("claim limit would be exceeded (%d)", max)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, address := range canonical {
		family := "ipv6"
		p, _ := netip.ParsePrefix(address)
		if p.Addr().Is4() {
			family = "ipv4"
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO claims(address,family,source,reason,actor,created_at,expires_at) VALUES(?,?,?,?,?,?,NULL)`, address, family, source, reason, actor, now); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit(created_at,actor,event,detail) VALUES(?,?,?,?)", now, actor, "claim_source_replaced", fmt.Sprintf("source=%s entries=%d", source, len(canonical))); err != nil {
		return 0, err
	}
	parsedNow, err := time.Parse(time.RFC3339Nano, now)
	if err != nil {
		return 0, err
	}
	if err := markClaimPublicationDirtyTx(ctx, tx, parsedNow); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(canonical), nil
}

func (s *Store) Claims(ctx context.Context, now time.Time) ([]Claim, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,address,family,source,reason,actor,created_at,expires_at FROM claims WHERE expires_at IS NULL OR expires_at>? ORDER BY address,source,id`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanClaims(rows)
}

func (s *Store) ClaimsWithPublication(ctx context.Context, now time.Time) ([]Claim, ClaimPublication, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, ClaimPublication{}, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,address,family,source,reason,actor,created_at,expires_at FROM claims WHERE expires_at IS NULL OR expires_at>? ORDER BY address,source,id`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, ClaimPublication{}, err
	}
	claims, scanErr := scanClaims(rows)
	closeErr := rows.Close()
	if scanErr != nil {
		return nil, ClaimPublication{}, scanErr
	}
	if closeErr != nil {
		return nil, ClaimPublication{}, closeErr
	}
	var publication ClaimPublication
	if err := tx.QueryRowContext(ctx, `SELECT desired_revision,applied_revision FROM runtime_claim_publication WHERE singleton=1`).Scan(&publication.DesiredRevision, &publication.AppliedRevision); err != nil {
		return nil, ClaimPublication{}, err
	}
	if publication.AppliedRevision > publication.DesiredRevision {
		return nil, ClaimPublication{}, errors.New("runtime claim publication revision is invalid")
	}
	if err := tx.Commit(); err != nil {
		return nil, ClaimPublication{}, err
	}
	return claims, publication, nil
}

func (s *Store) ClaimPublicationState(ctx context.Context) (ClaimPublication, error) {
	var publication ClaimPublication
	err := s.DB.QueryRowContext(ctx, `SELECT desired_revision,applied_revision FROM runtime_claim_publication WHERE singleton=1`).Scan(&publication.DesiredRevision, &publication.AppliedRevision)
	if err == nil && publication.AppliedRevision > publication.DesiredRevision {
		err = errors.New("runtime claim publication revision is invalid")
	}
	return publication, err
}

func (s *Store) PrepareClaimPublication(ctx context.Context) (uint64, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var publication ClaimPublication
	if err := tx.QueryRowContext(ctx, `SELECT desired_revision,applied_revision FROM runtime_claim_publication WHERE singleton=1`).Scan(&publication.DesiredRevision, &publication.AppliedRevision); err != nil {
		return 0, err
	}
	if publication.AppliedRevision > publication.DesiredRevision {
		return 0, errors.New("runtime claim publication revision is invalid")
	}
	now := time.Now().UTC()
	if publication.DesiredRevision == publication.AppliedRevision {
		if err := markClaimPublicationDirtyTx(ctx, tx, now); err != nil {
			return 0, err
		}
		publication.DesiredRevision++
	} else if err := markRuntimeClaimsDegradedTx(ctx, tx, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return publication.DesiredRevision, nil
}

func (s *Store) MarkClaimsPublished(ctx context.Context, revision uint64, count int) error {
	if count < 0 {
		return errors.New("runtime claim count is invalid")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE runtime_claim_publication SET applied_revision=?,updated_at=? WHERE singleton=1 AND desired_revision=?`, revision, time.Now().UTC().Format(time.RFC3339Nano), revision)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return errors.New("runtime claims changed during publication")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO integration_state(name,status,entry_count,last_success,updated_at) VALUES('runtime/claims','healthy',?,?,?)
ON CONFLICT(name) DO UPDATE SET status='healthy',entry_count=excluded.entry_count,last_success=excluded.last_success,updated_at=excluded.updated_at`, count, now, now); err != nil {
		return err
	}
	return tx.Commit()
}

func markClaimPublicationDirtyTx(ctx context.Context, tx *sql.Tx, now time.Time) error {
	nowText := now.UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE runtime_claim_publication SET desired_revision=desired_revision+1,updated_at=? WHERE singleton=1`, nowText)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return errors.New("runtime claim publication state is missing")
	}
	return markRuntimeClaimsDegradedTx(ctx, tx, now)
}

func markRuntimeClaimsDegradedTx(ctx context.Context, tx *sql.Tx, now time.Time) error {
	nowText := now.UTC().Format(time.RFC3339Nano)
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM claims WHERE expires_at IS NULL OR expires_at>?`, nowText).Scan(&count); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO integration_state(name,status,entry_count,last_success,updated_at) VALUES('runtime/claims','degraded',?,NULL,?)
ON CONFLICT(name) DO UPDATE SET status='degraded',entry_count=excluded.entry_count,updated_at=excluded.updated_at`, count, nowText)
	return err
}

func (s *Store) RestoreClaim(ctx context.Context, claim Claim, actor string) error {
	if claim.ID <= 0 || actor == "" {
		return errors.New("restored claim id and actor are required")
	}
	if err := ValidateClaim(claim.Address, claim.Family); err != nil {
		return err
	}
	if err := validateClaimMetadata(claim); err != nil {
		return err
	}
	var expires any
	if claim.ExpiresAt != nil {
		expires = claim.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO claims(id,address,family,source,reason,actor,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)`, claim.ID, claim.Address, claim.Family, claim.Source, claim.Reason, claim.Actor, claim.CreatedAt.UTC().Format(time.RFC3339Nano), expires); err != nil {
		return err
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(created_at,actor,event,detail) VALUES(?,?,?,?)`, now.Format(time.RFC3339Nano), actor, "claim_restored", fmt.Sprintf("id=%d", claim.ID)); err != nil {
		return err
	}
	if err := markClaimPublicationDirtyTx(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ClaimsPage(ctx context.Context, now time.Time, limit, offset int) ([]Claim, error) {
	if limit < 1 || limit > 1000 || offset < 0 || offset > 1000000 {
		return nil, errors.New("invalid claim page bounds")
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,address,family,source,reason,actor,created_at,expires_at FROM claims WHERE expires_at IS NULL OR expires_at>? ORDER BY address,source,id LIMIT ? OFFSET ?`, now.UTC().Format(time.RFC3339Nano), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanClaims(rows)
}

func (s *Store) ActiveClaimCount(ctx context.Context, now time.Time) (int, error) {
	var count int
	err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM claims WHERE expires_at IS NULL OR expires_at>?", now.UTC().Format(time.RFC3339Nano)).Scan(&count)
	return count, err
}

type claimRows interface {
	Next() bool
	Scan(...any) error
	Err() error
}

func scanClaims(rows claimRows) ([]Claim, error) {
	result := []Claim{}
	for rows.Next() {
		var c Claim
		var created string
		var expires sql.NullString
		if err := rows.Scan(&c.ID, &c.Address, &c.Family, &c.Source, &c.Reason, &c.Actor, &created, &expires); err != nil {
			return nil, err
		}
		var err error
		c.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, errors.New("claim has invalid creation timestamp")
		}
		if expires.Valid {
			t, parseErr := time.Parse(time.RFC3339Nano, expires.String)
			if parseErr != nil {
				return nil, errors.New("claim has invalid expiry timestamp")
			}
			c.ExpiresAt = &t
		}
		if err := ValidateClaim(c.Address, c.Family); err != nil {
			return nil, fmt.Errorf("invalid persisted claim %d: %w", c.ID, err)
		}
		if err := validateClaimMetadata(c); err != nil {
			return nil, fmt.Errorf("invalid persisted claim %d: %w", c.ID, err)
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func (s *Store) ClaimCountExcludingSource(ctx context.Context, source string) (int, error) {
	var count int
	err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM claims WHERE source<>?", source).Scan(&count)
	return count, err
}

func EffectiveAddresses(claims []Claim, family string) []string {
	seen := map[string]bool{}
	for _, c := range claims {
		if c.Family == family && !isAllowSource(c.Source) {
			seen[c.Address] = true
		}
	}
	result := make([]string, 0, len(seen))
	for a := range seen {
		result = append(result, a)
	}
	sort.Strings(result)
	return result
}

func EffectiveAddressesFrom(claims []Claim, family, sourcePrefix string) []string {
	seen := map[string]bool{}
	for _, c := range claims {
		if c.Family == family && (sourcePrefix == "" || (sourcePrefix == "allow" && isAllowSource(c.Source)) || strings.HasPrefix(c.Source, sourcePrefix+"/")) {
			seen[c.Address] = true
		}
	}
	result := make([]string, 0, len(seen))
	for a := range seen {
		result = append(result, a)
	}
	sort.Strings(result)
	return result
}

func ValidateClaim(address, family string) error {
	if family != "ipv4" && family != "ipv6" {
		return errors.New("claim family must be ipv4 or ipv6")
	}
	p, err := netip.ParsePrefix(address)
	if err != nil {
		a, e := netip.ParseAddr(address)
		if e != nil {
			return fmt.Errorf("invalid claim address %q", address)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Bits() == 0 {
		return errors.New("claim /0 is forbidden")
	}
	if family == "ipv4" && !p.Addr().Is4() {
		return errors.New("claim family/address mismatch")
	}
	if family == "ipv6" && !p.Addr().Is6() {
		return errors.New("claim family/address mismatch")
	}
	return nil
}

func validateClaimMetadata(c Claim) error {
	if !claimSourcePattern.MatchString(c.Source) || c.Actor == "" {
		return errors.New("claim source or actor is invalid")
	}
	if len(c.Actor) > 128 || len(c.Reason) > 1024 {
		return errors.New("claim actor or reason exceeds its size limit")
	}
	if isAllowSource(c.Source) && c.ExpiresAt == nil {
		return errors.New("temporary access claim requires an expiry")
	}
	return nil
}

func isAllowSource(source string) bool {
	return source == "allow" || strings.HasPrefix(source, "allow/")
}

func (s *Store) PurgeExpiredClaims(ctx context.Context, now time.Time) (int64, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now = now.UTC()
	result, err := tx.ExecContext(ctx, "DELETE FROM claims WHERE expires_at IS NOT NULL AND expires_at<=?", now.Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if count > 0 {
		if _, err := tx.ExecContext(ctx, "INSERT INTO audit(created_at,actor,event,detail) VALUES(?,?,?,?)", now.Format(time.RFC3339Nano), "system", "expired_claims_purged", fmt.Sprintf("count=%d", count)); err != nil {
			return 0, err
		}
		if err := markClaimPublicationDirtyTx(ctx, tx, now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) Audit(ctx context.Context, actor, event, detail string) error {
	if actor == "" || event == "" || len(actor) > 128 || len(event) > 128 {
		return errors.New("audit actor or event is invalid")
	}
	if len(detail) > 4096 {
		detail = detail[:4096]
	}
	_, err := s.DB.ExecContext(ctx, "INSERT INTO audit(created_at,actor,event,detail) VALUES(?,?,?,?)", time.Now().UTC().Format(time.RFC3339Nano), actor, event, detail)
	return err
}

func (s *Store) RecentAudit(ctx context.Context, limit int) ([]map[string]any, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT created_at,actor,event,detail FROM audit ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []map[string]any{}
	for rows.Next() {
		var ts, actor, event, detail string
		if err := rows.Scan(&ts, &actor, &event, &detail); err != nil {
			return nil, err
		}
		result = append(result, map[string]any{"created_at": ts, "actor": actor, "event": event, "detail": detail})
	}
	return result, rows.Err()
}

func (s *Store) SetIntegrationState(ctx context.Context, name, status string, count int, success bool) error {
	if name == "" || (status != "healthy" && status != "degraded") || count < 0 {
		return errors.New("invalid integration state")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var last any
	if success {
		last = now
	} else {
		var existing sql.NullString
		_ = s.DB.QueryRowContext(ctx, "SELECT last_success FROM integration_state WHERE name=?", name).Scan(&existing)
		if existing.Valid {
			last = existing.String
		}
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO integration_state(name,status,entry_count,last_success,updated_at) VALUES(?,?,?,?,?)
ON CONFLICT(name) DO UPDATE SET status=excluded.status,entry_count=excluded.entry_count,last_success=excluded.last_success,updated_at=excluded.updated_at`, name, status, count, last, now)
	return err
}

func (s *Store) IntegrationStates(ctx context.Context) ([]IntegrationState, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT name,status,entry_count,last_success,updated_at FROM integration_state ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []IntegrationState
	for rows.Next() {
		var item IntegrationState
		var success sql.NullString
		var updated string
		if err := rows.Scan(&item.Name, &item.Status, &item.EntryCount, &success, &updated); err != nil {
			return nil, err
		}
		item.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		if success.Valid {
			t, parseErr := time.Parse(time.RFC3339Nano, success.String)
			if parseErr == nil {
				item.LastSuccess = &t
			}
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) RetireInactiveIntegrations(ctx context.Context, active map[string]bool) (int64, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT source FROM claims WHERE source LIKE 'threatfeed/%' OR source LIKE 'geo/%' ORDER BY source`)
	if err != nil {
		return 0, err
	}
	var inactiveSources []string
	for rows.Next() {
		var source string
		if err := rows.Scan(&source); err != nil {
			rows.Close()
			return 0, err
		}
		if !active[source] {
			inactiveSources = append(inactiveSources, source)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	var removedClaims int64
	for _, source := range inactiveSources {
		result, err := tx.ExecContext(ctx, `DELETE FROM claims WHERE source=?`, source)
		if err != nil {
			return 0, err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		removedClaims += count
	}
	rows, err = tx.QueryContext(ctx, `SELECT name FROM integration_state ORDER BY name`)
	if err != nil {
		return 0, err
	}
	var inactiveStates []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return 0, err
		}
		managed := name == "docker" || strings.HasPrefix(name, "wireguard/") || strings.HasPrefix(name, "threatfeed/") || strings.HasPrefix(name, "geo/")
		if managed && !active[name] {
			inactiveStates = append(inactiveStates, name)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for _, name := range inactiveStates {
		if _, err := tx.ExecContext(ctx, `DELETE FROM integration_state WHERE name=?`, name); err != nil {
			return 0, err
		}
	}
	now := time.Now().UTC()
	if removedClaims > 0 {
		if err := markClaimPublicationDirtyTx(ctx, tx, now); err != nil {
			return 0, err
		}
	}
	if len(inactiveSources) > 0 || len(inactiveStates) > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit(created_at,actor,event,detail) VALUES(?,?,?,?)`, now.Format(time.RFC3339Nano), "system", "inactive_integrations_retired", fmt.Sprintf("claim_sources=%d states=%d claims=%d", len(inactiveSources), len(inactiveStates), removedClaims)); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return removedClaims, nil
}

func (s *Store) IntegrationState(ctx context.Context, name string) (*IntegrationState, error) {
	var item IntegrationState
	var success sql.NullString
	var updated string
	err := s.DB.QueryRowContext(ctx, "SELECT name,status,entry_count,last_success,updated_at FROM integration_state WHERE name=?", name).Scan(&item.Name, &item.Status, &item.EntryCount, &success, &updated)
	if err != nil {
		return nil, err
	}
	item.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	if success.Valid {
		t, parseErr := time.Parse(time.RFC3339Nano, success.String)
		if parseErr == nil {
			item.LastSuccess = &t
		}
	}
	return &item, nil
}

func (s *Store) SourceClaimCount(ctx context.Context, source string) (int, error) {
	var count int
	err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM claims WHERE source=?", source).Scan(&count)
	return count, err
}

// QuickCheck performs SQLite's bounded structural integrity check.
func (s *Store) QuickCheck(ctx context.Context) error {
	var result string
	if err := s.DB.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("SQLite quick_check: %s", result)
	}
	return nil
}

// Backup writes a consistent SQLite snapshot and atomically publishes it.
func (s *Store) Backup(ctx context.Context, destination string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	abs, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	parent := filepath.Dir(abs)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return errors.New("backup directory path is unsafe")
	}
	info, statErr := os.Stat(parent)
	if statErr != nil || info.Mode().Perm()&0o022 != 0 {
		return errors.New("backup directory is group/other writable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("backup directory has unsafe ownership")
	}
	if _, err := os.Lstat(abs); err == nil {
		return errors.New("backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".nftfw-backup-*.db")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	if _, err := s.DB.ExecContext(ctx, "VACUUM INTO ?", tmpPath); err != nil {
		return fmt.Errorf("create SQLite backup: %w", err)
	}
	if err := restrictRegularFile(tmpPath, 0o600); err != nil {
		return err
	}
	f, err := os.Open(tmpPath)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, abs); err != nil {
		return err
	}
	return syncDirectory(parent)
}

// ReadGenerationScript is an explicit alias used by reconciliation callers.
func (s *Store) ReadGenerationScript(g *Generation) (string, error) { return s.ReadScript(g) }
