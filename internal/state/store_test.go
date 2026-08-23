package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testChecksum(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func TestClaimProvenanceUnion(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(secureTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.AddClaim(ctx, Claim{Address: "203.0.113.20/32", Family: "ipv4", Source: "manual", Reason: "scanner", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	threat, err := s.AddClaim(ctx, Claim{Address: "203.0.113.20/32", Family: "ipv4", Source: "threatfeed/example", Reason: "feed", Actor: "feed"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.Claims(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := EffectiveAddresses(claims, "ipv4"); len(got) != 1 {
		t.Fatalf("expected one effective address: %v", got)
	}
	if err := s.RemoveClaim(ctx, threat, "feed"); err != nil {
		t.Fatal(err)
	}
	claims, _ = s.Claims(ctx, time.Now())
	if got := EffectiveAddresses(claims, "ipv4"); len(got) != 1 {
		t.Fatalf("manual claim was removed: %v", got)
	}
	claims, _ = s.Claims(ctx, time.Now())
	for _, claim := range claims {
		if claim.Source == "manual" {
			if err := s.RemoveClaim(ctx, claim.ID, "admin"); err != nil {
				t.Fatal(err)
			}
		}
	}
	claims, _ = s.Claims(ctx, time.Now())
	if got := EffectiveAddresses(claims, "ipv4"); len(got) != 0 {
		t.Fatalf("address remained after its final claim was removed: %v", got)
	}
}

func TestClaimPaginationAndInvalidRecordHandling(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(secureTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, address := range []string{"192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32"} {
		if _, err := s.AddClaim(ctx, Claim{Address: address, Family: "ipv4", Source: "manual", Actor: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ClaimsPage(ctx, time.Now().UTC(), 1, 1)
	if err != nil || len(page) != 1 || page[0].Address != "192.0.2.2/32" {
		t.Fatalf("unexpected claim page: %#v %v", page, err)
	}
	if total, err := s.ActiveClaimCount(ctx, time.Now().UTC()); err != nil || total != 3 {
		t.Fatalf("unexpected active claim count: %d %v", total, err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO claims(address,family,source,reason,actor,created_at) VALUES('invalid','ipv4','manual','bad','test','not-a-time')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claims(ctx, time.Now().UTC()); err == nil {
		t.Fatal("invalid persisted claim was silently accepted")
	}
}

func FuzzValidateClaim(f *testing.F) {
	f.Add("203.0.113.1/32", "ipv4")
	f.Add("::/0", "ipv6")
	f.Fuzz(func(t *testing.T, address, family string) {
		_ = ValidateClaim(address, family)
	})
}

func TestReplaceSourceClaimsIsAtomicAndPreservesOtherSources(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(secureTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.AddClaim(ctx, Claim{Address: "203.0.113.5/32", Family: "ipv4", Source: "manual", Reason: "operator", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceSourceClaims(ctx, "geo/XX", "country", "geo", []string{"203.0.113.5/32", "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceSourceClaims(ctx, "geo/XX", "country", "geo", []string{"not-a-prefix"}); err == nil {
		t.Fatal("malformed replacement accepted")
	}
	claims, err := s.Claims(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := EffectiveAddresses(claims, "ipv4"); len(got) != 2 {
		t.Fatalf("failed replacement changed known-good claims: %v", got)
	}
}

func TestBoundedSourceReplacementRollsBackOnTotalLimit(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(secureTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.AddClaim(ctx, Claim{Address: "203.0.113.1/32", Family: "ipv4", Source: "manual", Reason: "operator", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceSourceClaimsBounded(ctx, "threatfeed/test", "feed", "integration", []string{"198.51.100.1/32"}, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceSourceClaimsBounded(ctx, "threatfeed/test", "feed", "integration", []string{"198.51.100.2/32", "198.51.100.3/32"}, 2); err == nil {
		t.Fatal("replacement exceeding the global claim limit succeeded")
	}
	claims, err := s.Claims(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := EffectiveAddresses(claims, "ipv4"); len(got) != 2 || got[0] != "198.51.100.1/32" || got[1] != "203.0.113.1/32" {
		t.Fatalf("failed bounded replacement changed known-good claims: %v", got)
	}
}
func TestMigrationAndCorruptDatabase(t *testing.T) {
	path := filepath.Join(secureTestDir(t), "state.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	var version int
	if err := func() error {
		db, err := sql.Open("sqlite", path)
		if err != nil {
			return err
		}
		defer db.Close()
		return db.QueryRow("select max(version) from schema_migrations").Scan(&version)
	}(); err != nil {
		t.Fatal(err)
	}
	if version != currentSchemaVersion {
		t.Fatalf("migration version %d", version)
	}
	bad := filepath.Join(secureTestDir(t), "bad.db")
	if err := os.WriteFile(bad, []byte("not sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(context.Background(), bad); err == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("corrupt db accepted")
	}
}

func TestAuditRowsArePrunedDuringMigrationAndOnInsert(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(secureTestDir(t), "state.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	// Model a v3 database whose audit table grew before the bound existed.
	if _, err := store.DB.ExecContext(ctx, `DROP TRIGGER audit_prune_after_insert; DROP TABLE runtime_claim_publication; DELETE FROM integration_state WHERE name='runtime/claims'; DELETE FROM schema_migrations WHERE version>=4`); err != nil {
		store.Close()
		t.Fatal(err)
	}
	insertAuditRows := func(count int) {
		t.Helper()
		tx, beginErr := store.DB.BeginTx(ctx, nil)
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		stmt, prepareErr := tx.PrepareContext(ctx, `INSERT INTO audit(created_at,actor,event,detail) VALUES(?,?,?,?)`)
		if prepareErr != nil {
			tx.Rollback()
			t.Fatal(prepareErr)
		}
		defer stmt.Close()
		for i := range count {
			if _, execErr := stmt.ExecContext(ctx, time.Now().UTC().Format(time.RFC3339Nano), "test", "bounded", fmt.Sprintf("row=%d", i)); execErr != nil {
				tx.Rollback()
				t.Fatal(execErr)
			}
		}
		if commitErr := tx.Commit(); commitErr != nil {
			t.Fatal(commitErr)
		}
	}
	insertAuditRows(MaxAuditRows + 7)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assertAuditBound := func() {
		t.Helper()
		var count int
		if queryErr := store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit`).Scan(&count); queryErr != nil {
			t.Fatal(queryErr)
		}
		if count != MaxAuditRows {
			t.Fatalf("audit bound mismatch: got=%d want=%d", count, MaxAuditRows)
		}
	}
	assertAuditBound()
	insertAuditRows(25)
	assertAuditBound()
	var firstID, lastID int64
	if err := store.DB.QueryRowContext(ctx, `SELECT MIN(id),MAX(id) FROM audit`).Scan(&firstID, &lastID); err != nil {
		t.Fatal(err)
	}
	if lastID-firstID+1 != MaxAuditRows {
		t.Fatalf("audit pruning retained the wrong ID window: first=%d last=%d", firstID, lastID)
	}
}

func TestClaimPublicationRevisionTracksEveryDurableMutation(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(secureTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	publication, err := store.ClaimPublicationState(ctx)
	if err != nil || publication.DesiredRevision != 1 || publication.AppliedRevision != 0 {
		t.Fatalf("fresh migration was not conservatively dirty: %#v err=%v", publication, err)
	}
	if err := store.MarkClaimsPublished(ctx, publication.DesiredRevision, 0); err != nil {
		t.Fatal(err)
	}
	id, err := store.AddClaim(ctx, Claim{Address: "203.0.113.8/32", Family: "ipv4", Source: "manual", Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	afterAdd, err := store.ClaimPublicationState(ctx)
	if err != nil || afterAdd.DesiredRevision != 2 || afterAdd.AppliedRevision != 1 {
		t.Fatalf("add did not dirty the next revision: %#v err=%v", afterAdd, err)
	}
	if err := store.MarkClaimsPublished(ctx, 1, 1); err == nil {
		t.Fatal("stale publication revision was accepted")
	}
	if err := store.MarkClaimsPublished(ctx, afterAdd.DesiredRevision, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveClaim(ctx, id, "test"); err != nil {
		t.Fatal(err)
	}
	afterRemove, err := store.ClaimPublicationState(ctx)
	if err != nil || afterRemove.DesiredRevision != 3 || afterRemove.AppliedRevision != 2 {
		t.Fatalf("remove did not dirty the next revision: %#v err=%v", afterRemove, err)
	}
	if _, err := store.ReplaceSourceClaims(ctx, "threatfeed/test", "feed", "test", []string{"8.8.8.8/32"}); err != nil {
		t.Fatal(err)
	}
	afterReplace, err := store.ClaimPublicationState(ctx)
	if err != nil || afterReplace.DesiredRevision != 4 || afterReplace.AppliedRevision != 2 {
		t.Fatalf("source replacement did not dirty the next revision: %#v err=%v", afterReplace, err)
	}
	expires := time.Now().UTC().Add(-time.Minute)
	if _, err := store.AddClaim(ctx, Claim{Address: "203.0.113.9/32", Family: "ipv4", Source: "manual", Actor: "test", ExpiresAt: &expires}); err != nil {
		t.Fatal(err)
	}
	beforePurge, err := store.ClaimPublicationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := store.PurgeExpiredClaims(ctx, time.Now().UTC()); err != nil || count != 1 {
		t.Fatalf("expired claim purge failed: count=%d err=%v", count, err)
	}
	afterPurge, err := store.ClaimPublicationState(ctx)
	if err != nil || afterPurge.DesiredRevision != beforePurge.DesiredRevision+1 {
		t.Fatalf("purge did not dirty the next revision: before=%#v after=%#v err=%v", beforePurge, afterPurge, err)
	}
	state, err := store.IntegrationState(ctx, "runtime/claims")
	if err != nil || state.Status != "degraded" {
		t.Fatalf("dirty claim revision was not exposed as degraded: %#v err=%v", state, err)
	}
}

func TestMigrationFiveInitializesExistingClaimsAsUnpublished(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(secureTestDir(t), "state.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddClaim(ctx, Claim{Address: "203.0.113.10/32", Family: "ipv4", Source: "manual", Actor: "test"}); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if _, err := store.DB.ExecContext(ctx, `DROP TABLE runtime_claim_publication; DELETE FROM integration_state WHERE name='runtime/claims'; DELETE FROM schema_migrations WHERE version=5`); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	publication, err := store.ClaimPublicationState(ctx)
	if err != nil || publication.DesiredRevision != 1 || publication.AppliedRevision != 0 {
		t.Fatalf("v4 migration trusted unknown live runtime state: %#v err=%v", publication, err)
	}
	integration, err := store.IntegrationState(ctx, "runtime/claims")
	if err != nil || integration.Status != "degraded" || integration.EntryCount != 1 {
		t.Fatalf("v4 migration did not expose existing claims as degraded: %#v err=%v", integration, err)
	}
}

func TestRetireInactiveIntegrationsRemovesClaimsAndStaleHealthRows(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(secureTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ReplaceSourceClaims(ctx, "threatfeed/old", "feed", "test", []string{"8.8.8.8/32"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntegrationState(ctx, "threatfeed/old", "degraded", 1, false); err != nil {
		t.Fatal(err)
	}
	removed, err := store.RetireInactiveIntegrations(ctx, map[string]bool{"runtime/claims": true})
	if err != nil || removed != 1 {
		t.Fatalf("inactive source retirement failed: removed=%d err=%v", removed, err)
	}
	if count, err := store.SourceClaimCount(ctx, "threatfeed/old"); err != nil || count != 0 {
		t.Fatalf("inactive integration claims remain: count=%d err=%v", count, err)
	}
	if _, err := store.IntegrationState(ctx, "threatfeed/old"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("inactive degraded state remains: %v", err)
	}
}

func TestPermanentAllowAndReservedIntegrationSourceFailClosed(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(secureTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	claim := Claim{Address: "203.0.113.8/32", Family: "ipv4", Source: "allow", Reason: "lease", Actor: "admin"}
	if _, err := s.AddClaim(ctx, claim); err == nil {
		t.Fatal("permanent allow claim accepted")
	}
	if _, err := s.ReplaceSourceClaims(ctx, "allow", "forged", "integration", []string{"203.0.113.8/32"}); err == nil {
		t.Fatal("integration replaced reserved allow provenance")
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO claims(address,family,source,reason,actor,created_at,expires_at) VALUES(?,?,?,?,?,?,NULL)`, "203.0.113.8/32", "ipv4", "allow", "corrupt", "unknown", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claims(ctx, time.Now().UTC()); err == nil {
		t.Fatal("persisted permanent allow claim was trusted")
	}
}

func TestOpenRejectsNewerSchemaAndDSNFilename(t *testing.T) {
	dir := secureTestDir(t)
	if store, err := Open(context.Background(), filepath.Join(dir, "state.db?mode=memory")); err == nil {
		store.Close()
		t.Fatal("SQLite DSN characters in state filename accepted")
	}
	path := filepath.Join(dir, "future.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL); INSERT INTO schema_migrations VALUES(99, 'now')`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(context.Background(), path); err == nil {
		store.Close()
		t.Fatal("newer state schema accepted")
	}
}

func TestNegativeGenerationReferenceFailsClosed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(secureTestDir(t), "state.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	script := "table inet nftfw_filter { }\n"
	if err := s.SaveGeneration(ctx, 1, testChecksum(script), script, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys=OFF; UPDATE generations SET previous_id=-1 WHERE id=1`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Pending(ctx); err == nil {
		t.Fatal("negative previous generation reference was accepted")
	}
}

func TestGenerationIntegrityAndSQLiteBackup(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t)
	path := filepath.Join(dir, "state.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state database mode is not 0600: info=%v err=%v", info, err)
	}
	script := "table inet nftfw_filter { }\n"
	if err := s.SaveGeneration(ctx, 0, testChecksum(script), script, nil, nil); err == nil {
		t.Fatal("zero generation id accepted")
	}
	if err := s.SaveGeneration(ctx, 1, strings.Repeat("0", 64), script, nil, nil); err == nil {
		t.Fatal("generation with mismatched checksum accepted")
	}
	if err := s.SaveGeneration(ctx, 1, testChecksum(script), script, nil, nil); err != nil {
		t.Fatal(err)
	}
	g, err := s.Pending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.ReadScript(g); err != nil || got != script {
		t.Fatalf("valid generation rejected: got=%q err=%v", got, err)
	}
	if err := os.Chmod(g.ScriptPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadScript(g); err == nil {
		t.Fatal("group-readable generation script accepted")
	}
	if err := os.Chmod(g.ScriptPath, 0o600); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "backups", "state.db")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(backup); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode is not 0600: info=%v err=%v", info, err)
	}
	backupStore, err := Open(ctx, backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := backupStore.QuickCheck(ctx); err != nil {
		backupStore.Close()
		t.Fatal(err)
	}
	backupStore.Close()
	if err := os.WriteFile(g.ScriptPath, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadScript(g); err == nil {
		t.Fatal("tampered generation script accepted")
	}
}

func TestOpenRejectsSymlinkedStatePaths(t *testing.T) {
	dir := secureTestDir(t)
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(context.Background(), filepath.Join(linkDir, "state.db")); err == nil {
		store.Close()
		t.Fatal("symlinked state directory accepted")
	}
	target := filepath.Join(realDir, "target.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dbLink := filepath.Join(realDir, "state.db")
	if err := os.Symlink(target, dbLink); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(context.Background(), dbLink); err == nil {
		store.Close()
		t.Fatal("symlinked state database accepted")
	}
}

func TestConcurrentDatabaseOpenWaitsForWALLock(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(secureTestDir(t), "state.db")
	initial, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			store, openErr := Open(ctx, path)
			if openErr != nil {
				errorsSeen <- openErr
				return
			}
			_ = store.Close()
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for openErr := range errorsSeen {
		t.Errorf("concurrent state open failed: %v", openErr)
	}
}
