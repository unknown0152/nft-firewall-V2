// Package provenance owns the permanent ingress-interface to conntrack-mark
// registry.  The registry deliberately has a lifecycle independent from the
// replaceable firewall generation database: identities are never deleted or
// reassigned, and retirement is monotonic.
package provenance

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const (
	// Mask reserves the high byte of the conntrack mark for NFTFW ingress
	// provenance. KeepMask preserves every bit NFTFW does not own.
	Mask     uint32 = 0xff000000
	KeepMask uint32 = 0x00ffffff

	MinID     = 1
	MaxID     = 254
	MaxActive = 64

	SchemaVersion = 1
)

var (
	identityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	databasePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

// Assignment is a permanent identity allocation. Retired allocations remain
// authoritative tombstones and may still be referenced by historical
// generation snapshots, but they can never become active again.
type Assignment struct {
	Name      string     `json:"name"`
	ID        uint8      `json:"id"`
	Retired   bool       `json:"retired"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}

func (a Assignment) Encoded() uint32 { return uint32(a.ID) << 24 }

// ValidateActive applies the source-level allocation contract without opening
// the ledger. It is shared by configuration validation and ledger mutation.
func ValidateActive(assignments []Assignment) error {
	if len(assignments) == 0 {
		return errors.New("at least one ingress provenance assignment is required")
	}
	if len(assignments) > MaxActive {
		return fmt.Errorf("active ingress provenance assignments exceed %d", MaxActive)
	}
	names := make(map[string]bool, len(assignments))
	ids := make(map[uint8]string, len(assignments))
	for _, assignment := range assignments {
		if assignment.Retired {
			return fmt.Errorf("active assignment %q is marked retired", assignment.Name)
		}
		if !identityPattern.MatchString(assignment.Name) {
			return fmt.Errorf("invalid provenance identity %q", assignment.Name)
		}
		if assignment.ID < MinID || assignment.ID > MaxID {
			return fmt.Errorf("provenance id for %q must be %d..%d", assignment.Name, MinID, MaxID)
		}
		if names[assignment.Name] {
			return fmt.Errorf("duplicate provenance identity %q", assignment.Name)
		}
		names[assignment.Name] = true
		if prior, exists := ids[assignment.ID]; exists {
			return fmt.Errorf("provenance id %d is assigned to both %q and %q", assignment.ID, prior, assignment.Name)
		}
		ids[assignment.ID] = assignment.Name
	}
	return nil
}

type Ledger struct {
	DB       *sql.DB
	Path     string
	readOnly bool
}

// Open opens or creates the root-protected monotonic ledger. It uses SQLite's
// rollback journal rather than WAL so strict read-only verification never has
// to create shared-memory sidecars.
func Open(ctx context.Context, path string) (*Ledger, error) {
	path, err := preparePath(path, true)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open provenance ledger: %w", err)
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
		"PRAGMA journal_mode=DELETE",
		"PRAGMA synchronous=FULL",
	} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("provenance ledger %s: %w", pragma, err)
		}
	}
	ledger := &Ledger{DB: db, Path: path}
	if err := ledger.initialize(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := secureSidecars(path); err != nil {
		db.Close()
		return nil, err
	}
	return ledger, nil
}

// OpenReadOnly opens an existing ledger without migrations, journal creation,
// or other writes. The path is validated before it becomes a SQLite URI.
func OpenReadOnly(ctx context.Context, path string) (*Ledger, error) {
	path, err := preparePath(path, false)
	if err != nil {
		return nil, err
	}
	// preparePath constrains the absolute path to characters that cannot alter
	// the URI query, so concatenating mode=ro is safe here.
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open read-only provenance ledger: %w", err)
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA query_only=ON"} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("read-only provenance ledger %s: %w", pragma, err)
		}
	}
	ledger := &Ledger{DB: db, Path: path, readOnly: true}
	if err := ledger.verifySchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return ledger, nil
}

func (l *Ledger) Close() error {
	if l == nil || l.DB == nil {
		return nil
	}
	return l.DB.Close()
}

func (l *Ledger) initialize(ctx context.Context) error {
	tx, err := l.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS ledger_metadata (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 schema_version INTEGER NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS allocations (
 interface_name TEXT PRIMARY KEY,
 provenance_id INTEGER NOT NULL UNIQUE CHECK(provenance_id BETWEEN 1 AND 254),
 retired INTEGER NOT NULL DEFAULT 0 CHECK(retired IN (0,1)),
 created_at TEXT NOT NULL,
 retired_at TEXT
);
CREATE TRIGGER IF NOT EXISTS allocations_identity_immutable
BEFORE UPDATE OF interface_name, provenance_id ON allocations
BEGIN SELECT RAISE(ABORT, 'provenance identity is immutable'); END;
CREATE TRIGGER IF NOT EXISTS allocations_no_delete
BEFORE DELETE ON allocations
BEGIN SELECT RAISE(ABORT, 'provenance allocation deletion is forbidden'); END;
CREATE TRIGGER IF NOT EXISTS allocations_retirement_monotonic
BEFORE UPDATE OF retired ON allocations
WHEN OLD.retired=1 AND NEW.retired<>1
BEGIN SELECT RAISE(ABORT, 'provenance retirement is permanent'); END;
INSERT INTO ledger_metadata(singleton,schema_version,created_at)
VALUES(1,1,strftime('%Y-%m-%dT%H:%M:%fZ','now'))
ON CONFLICT(singleton) DO NOTHING;
`); err != nil {
		return fmt.Errorf("initialize provenance ledger: %w", err)
	}
	var version int
	if err := tx.QueryRowContext(ctx, "SELECT schema_version FROM ledger_metadata WHERE singleton=1").Scan(&version); err != nil {
		return fmt.Errorf("read provenance ledger schema: %w", err)
	}
	if version != SchemaVersion {
		return fmt.Errorf("provenance ledger schema %d is unsupported", version)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit provenance ledger schema: %w", err)
	}
	return syncLedger(l.Path)
}

func (l *Ledger) verifySchema(ctx context.Context) error {
	var version int
	if err := l.DB.QueryRowContext(ctx, "SELECT schema_version FROM ledger_metadata WHERE singleton=1").Scan(&version); err != nil {
		return fmt.Errorf("read provenance ledger schema: %w", err)
	}
	if version != SchemaVersion {
		return fmt.Errorf("provenance ledger schema %d is unsupported", version)
	}
	var result string
	if err := l.DB.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil {
		return fmt.Errorf("check provenance ledger: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("provenance ledger quick_check: %s", result)
	}
	return nil
}

// Reserve durably inserts new assignments, verifies every existing identity,
// and permanently tombstones allocations omitted by the new active set. No
// caller may compile or apply a candidate until Reserve returns successfully.
func (l *Ledger) Reserve(ctx context.Context, active []Assignment) error {
	if l == nil || l.DB == nil || l.readOnly {
		return errors.New("writable provenance ledger is required")
	}
	if err := ValidateActive(active); err != nil {
		return err
	}
	tx, err := l.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	existing, err := assignmentsFrom(ctx, tx)
	if err != nil {
		return err
	}
	byName := make(map[string]Assignment, len(existing))
	byID := make(map[uint8]Assignment, len(existing))
	for _, assignment := range existing {
		byName[assignment.Name] = assignment
		byID[assignment.ID] = assignment
	}
	activeNames := make(map[string]bool, len(active))
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, assignment := range active {
		activeNames[assignment.Name] = true
		if prior, exists := byName[assignment.Name]; exists {
			if prior.ID != assignment.ID {
				return fmt.Errorf("provenance identity %q is permanently id %d, not %d", assignment.Name, prior.ID, assignment.ID)
			}
			if prior.Retired {
				return fmt.Errorf("provenance identity %q was permanently retired", assignment.Name)
			}
			continue
		}
		if prior, exists := byID[assignment.ID]; exists {
			return fmt.Errorf("provenance id %d is permanently allocated to %q", assignment.ID, prior.Name)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO allocations(interface_name,provenance_id,retired,created_at,retired_at) VALUES(?,?,0,?,NULL)`, assignment.Name, assignment.ID, now); err != nil {
			return fmt.Errorf("reserve provenance id %d for %s: %w", assignment.ID, assignment.Name, err)
		}
	}
	for _, assignment := range existing {
		if assignment.Retired || activeNames[assignment.Name] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE allocations SET retired=1,retired_at=? WHERE interface_name=? AND retired=0`, now, assignment.Name); err != nil {
			return fmt.Errorf("retire provenance identity %s: %w", assignment.Name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit provenance reservation: %w", err)
	}
	return syncLedger(l.Path)
}

// ValidateRequired proves that every generation-referenced identity has the
// same permanent mapping. Historical snapshots may reference tombstones.
func (l *Ledger) ValidateRequired(ctx context.Context, required []Assignment) error {
	if l == nil || l.DB == nil {
		return errors.New("provenance ledger is required")
	}
	seenNames := map[string]bool{}
	seenIDs := map[uint8]string{}
	for _, assignment := range required {
		if !identityPattern.MatchString(assignment.Name) || assignment.ID < MinID || assignment.ID > MaxID {
			return fmt.Errorf("invalid required provenance assignment %q/%d", assignment.Name, assignment.ID)
		}
		if seenNames[assignment.Name] {
			return fmt.Errorf("duplicate required provenance identity %q", assignment.Name)
		}
		seenNames[assignment.Name] = true
		if prior, ok := seenIDs[assignment.ID]; ok {
			return fmt.Errorf("required provenance id %d is ambiguous between %q and %q", assignment.ID, prior, assignment.Name)
		}
		seenIDs[assignment.ID] = assignment.Name
		var id uint8
		if err := l.DB.QueryRowContext(ctx, "SELECT provenance_id FROM allocations WHERE interface_name=?", assignment.Name).Scan(&id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("provenance identity %q is absent from the monotonic ledger", assignment.Name)
			}
			return err
		}
		if id != assignment.ID {
			return fmt.Errorf("provenance identity %q is ledger id %d, generation requires %d", assignment.Name, id, assignment.ID)
		}
	}
	return nil
}

func (l *Ledger) Assignments(ctx context.Context) ([]Assignment, error) {
	if l == nil || l.DB == nil {
		return nil, errors.New("provenance ledger is required")
	}
	return assignmentsFrom(ctx, l.DB)
}

// Digest is a deterministic evidence identifier for the complete permanent
// registry, including tombstones. It is not a cryptographic signature.
func (l *Ledger) Digest(ctx context.Context) (string, error) {
	assignments, err := l.Assignments(ctx)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, assignment := range assignments {
		fmt.Fprintf(&b, "%s\x00%d\x00%t\n", assignment.Name, assignment.ID, assignment.Retired)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:]), nil
}

// MergeFrom performs a monotonic, merge-only restore. An older saved ledger is
// compatible only when allocations missing from it are already tombstoned in
// the live ledger; live identities are never removed, changed, or resurrected.
func (l *Ledger) MergeFrom(ctx context.Context, savedPath string) error {
	if l == nil || l.DB == nil || l.readOnly {
		return errors.New("writable provenance ledger is required")
	}
	saved, err := OpenReadOnly(ctx, savedPath)
	if err != nil {
		return fmt.Errorf("open saved provenance ledger: %w", err)
	}
	defer saved.Close()
	savedAssignments, err := saved.Assignments(ctx)
	if err != nil {
		return err
	}
	tx, err := l.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	liveAssignments, err := assignmentsFrom(ctx, tx)
	if err != nil {
		return err
	}
	liveByName := make(map[string]Assignment, len(liveAssignments))
	liveByID := make(map[uint8]Assignment, len(liveAssignments))
	savedNames := make(map[string]bool, len(savedAssignments))
	for _, assignment := range liveAssignments {
		liveByName[assignment.Name] = assignment
		liveByID[assignment.ID] = assignment
	}
	for _, assignment := range savedAssignments {
		savedNames[assignment.Name] = true
		if live, exists := liveByName[assignment.Name]; exists {
			if live.ID != assignment.ID {
				return fmt.Errorf("saved ledger changes %q from id %d to %d", assignment.Name, live.ID, assignment.ID)
			}
			if !live.Retired && assignment.Retired {
				return fmt.Errorf("saved ledger retires currently active identity %q", assignment.Name)
			}
			// A newer live tombstone dominates an older active saved row.
			continue
		}
		if live, exists := liveByID[assignment.ID]; exists {
			return fmt.Errorf("saved ledger reuses id %d from %q for %q", assignment.ID, live.Name, assignment.Name)
		}
	}
	for _, live := range liveAssignments {
		if !savedNames[live.Name] && !live.Retired {
			return fmt.Errorf("saved ledger regresses active live identity %q", live.Name)
		}
	}
	for _, assignment := range savedAssignments {
		if _, exists := liveByName[assignment.Name]; exists {
			continue
		}
		var retiredAt any
		if assignment.RetiredAt != nil {
			retiredAt = assignment.RetiredAt.UTC().Format(time.RFC3339Nano)
		}
		created := assignment.CreatedAt.UTC().Format(time.RFC3339Nano)
		if assignment.CreatedAt.IsZero() {
			created = time.Now().UTC().Format(time.RFC3339Nano)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO allocations(interface_name,provenance_id,retired,created_at,retired_at) VALUES(?,?,?,?,?)`, assignment.Name, assignment.ID, boolInt(assignment.Retired), created, retiredAt); err != nil {
			return fmt.Errorf("merge saved provenance identity %s: %w", assignment.Name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit provenance ledger merge: %w", err)
	}
	return syncLedger(l.Path)
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func assignmentsFrom(ctx context.Context, q queryer) ([]Assignment, error) {
	rows, err := q.QueryContext(ctx, `SELECT interface_name,provenance_id,retired,created_at,retired_at FROM allocations ORDER BY provenance_id,interface_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Assignment
	for rows.Next() {
		var assignment Assignment
		var retired int
		var created string
		var retiredAt sql.NullString
		if err := rows.Scan(&assignment.Name, &assignment.ID, &retired, &created, &retiredAt); err != nil {
			return nil, err
		}
		assignment.Retired = retired == 1
		var err error
		assignment.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, fmt.Errorf("invalid provenance creation time: %w", err)
		}
		if retiredAt.Valid {
			t, err := time.Parse(time.RFC3339Nano, retiredAt.String)
			if err != nil {
				return nil, fmt.Errorf("invalid provenance retirement time: %w", err)
			}
			assignment.RetiredAt = &t
		}
		result = append(result, assignment)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ID != result[j].ID {
			return result[i].ID < result[j].ID
		}
		return result[i].Name < result[j].Name
	})
	return result, nil
}

func preparePath(path string, create bool) (string, error) {
	if path == "" {
		return "", errors.New("provenance ledger path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil || abs != path {
		return "", errors.New("provenance ledger path must be absolute and clean")
	}
	if !databasePattern.MatchString(filepath.Base(abs)) || strings.ContainsAny(abs, "?#%") {
		return "", errors.New("provenance ledger path contains unsupported characters")
	}
	parent := filepath.Dir(abs)
	if create {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return "", fmt.Errorf("create provenance ledger directory: %w", err)
		}
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return "", errors.New("provenance ledger directory is absent or contains a symlink")
	}
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 {
		return "", errors.New("provenance ledger directory has unsafe permissions")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || int64(parentStat.Uid) != int64(os.Geteuid()) {
		return "", errors.New("provenance ledger directory has unsafe ownership")
	}
	flags := os.O_RDONLY | syscall.O_NOFOLLOW
	if create {
		flags = os.O_CREATE | os.O_RDWR | syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(abs, flags, 0o600)
	if err != nil {
		return "", fmt.Errorf("open provenance ledger path: %w", err)
	}
	info, statErr := f.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		f.Close()
		return "", errors.New("provenance ledger file has unsafe type or permissions")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		f.Close()
		return "", errors.New("provenance ledger file has unsafe ownership")
	}
	if create {
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			return "", err
		}
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return abs, nil
}

func secureSidecars(path string) error {
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		info, err := os.Lstat(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("unsafe provenance ledger sidecar %s", filepath.Base(path+suffix))
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
			return fmt.Errorf("unsafe provenance ledger sidecar ownership %s", filepath.Base(path+suffix))
		}
		if err := os.Chmod(path+suffix, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func syncLedger(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
