// Package state persists generations, safe-apply leases, dynamic claims, and audit records.
package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	DB  *sql.DB
	Dir string
	mu  sync.Mutex
}

type Generation struct {
	ID               uint64
	Checksum         string
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

func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("state database path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err == nil && fi.Mode().Perm()&0o002 != 0 {
		return nil, errors.New("state directory is world-writable")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	for _, stmt := range []string{"PRAGMA foreign_keys=ON", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA busy_timeout=5000"} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("sqlite %s: %w", stmt, err)
		}
	}
	s := &Store{DB: db, Dir: filepath.Dir(path)}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
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
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	now := time.Now().UTC()
	var deadlineText any
	if deadline != nil {
		deadlineText = deadline.UTC().Format(time.RFC3339Nano)
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO generations(id,checksum,script_path,status,created_at,rollback_deadline,previous_id) VALUES(?,?,?,?,?,?,?)`, id, checksum, path, "pending", now.Format(time.RFC3339Nano), deadlineText, previous)
	if err != nil {
		return err
	}
	return nil
}

func (s *Store) MarkApplied(ctx context.Context, id uint64) error {
	_, err := s.DB.ExecContext(ctx, "UPDATE generations SET status='applied' WHERE id=?", id)
	return err
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
	row := s.DB.QueryRowContext(ctx, `SELECT id,checksum,script_path,status,created_at,rollback_deadline,previous_id FROM generations WHERE status IN ('pending','applied') ORDER BY id DESC LIMIT 1`)
	return scanGeneration(row)
}

func (s *Store) LastKnownGood(ctx context.Context) (*Generation, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT id,checksum,script_path,status,created_at,rollback_deadline,previous_id FROM generations WHERE status='committed' ORDER BY id DESC LIMIT 1`)
	return scanGeneration(row)
}

func scanGeneration(row interface{ Scan(...any) error }) (*Generation, error) {
	var g Generation
	var created string
	var previous sql.NullInt64
	var deadlineVal sql.NullString
	if err := row.Scan(&g.ID, &g.Checksum, &g.ScriptPath, &g.Status, &created, &deadlineVal, &previous); err != nil {
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
		v := uint64(previous.Int64)
		g.PreviousID = &v
	}
	return &g, nil
}

func (s *Store) ReadScript(g *Generation) (string, error) {
	if g == nil {
		return "", errors.New("nil generation")
	}
	b, err := os.ReadFile(g.ScriptPath)
	return string(b), err
}

func (s *Store) AddClaim(ctx context.Context, c Claim) (int64, error) {
	if err := ValidateClaim(c.Address, c.Family); err != nil {
		return 0, err
	}
	if c.Source == "" || c.Actor == "" {
		return 0, errors.New("claim source and actor are required")
	}
	if len(c.Source) > 129 || len(c.Actor) > 128 || len(c.Reason) > 1024 {
		return 0, errors.New("claim source, actor, or reason exceeds its size limit")
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
	res, err := s.DB.ExecContext(ctx, `INSERT INTO claims(address,family,source,reason,actor,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`, c.Address, c.Family, c.Source, c.Reason, c.Actor, c.CreatedAt.UTC().Format(time.RFC3339Nano), expires)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err == nil {
		_ = s.Audit(ctx, c.Actor, "claim_added", fmt.Sprintf("id=%d address=%s source=%s", id, c.Address, c.Source))
	}
	return id, err
}

func (s *Store) RemoveClaim(ctx context.Context, id int64, actor string) error {
	if id <= 0 {
		return errors.New("claim id must be positive")
	}
	res, err := s.DB.ExecContext(ctx, "DELETE FROM claims WHERE id=?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return s.Audit(ctx, actor, "claim_removed", fmt.Sprintf("id=%d", id))
}

// ReplaceSourceClaims atomically replaces exactly one integration's claims.
// Validation completes before the old claims are touched.
func (s *Store) ReplaceSourceClaims(ctx context.Context, source, reason, actor string, addresses []string) (int, error) {
	if source == "" || actor == "" {
		return 0, errors.New("claim source and actor are required")
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
	result := []Claim{}
	for rows.Next() {
		var c Claim
		var created string
		var expires sql.NullString
		if err := rows.Scan(&c.ID, &c.Address, &c.Family, &c.Source, &c.Reason, &c.Actor, &created, &expires); err != nil {
			return nil, err
		}
		c.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if expires.Valid {
			t, e := time.Parse(time.RFC3339Nano, expires.String)
			if e == nil {
				c.ExpiresAt = &t
			}
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
		if c.Family == family && !strings.HasPrefix(c.Source, "allow") {
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
		if c.Family == family && (sourcePrefix == "" || strings.HasPrefix(c.Source, sourcePrefix)) {
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

func (s *Store) Audit(ctx context.Context, actor, event, detail string) error {
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

// ReadGenerationScript is an explicit alias used by reconciliation callers.
func (s *Store) ReadGenerationScript(g *Generation) (string, error) { return s.ReadScript(g) }
