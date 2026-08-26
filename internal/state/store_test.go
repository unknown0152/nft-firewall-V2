package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
)

func testChecksum(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func testGenerationMetadata(t *testing.T) GenerationMetadata {
	t.Helper()
	bootID, err := CurrentBootID()
	if err != nil {
		t.Fatal(err)
	}
	return GenerationMetadata{BootID: bootID, Provenance: []provenance.Assignment{{Name: "eth0", ID: 1}}}
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

func TestAuditRowsArePrunedOnInsert(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(secureTestDir(t), "state.db")
	store, err := Open(ctx, path)
	if err != nil {
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

func TestWritableOpenRejectsLegacySchemaWithoutMigration(t *testing.T) {
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
	if _, err := store.DB.ExecContext(ctx, `DROP TABLE runtime_claim_publication; DELETE FROM integration_state WHERE name='runtime/claims'; DELETE FROM schema_migrations WHERE version>=5`); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err == nil {
		store.Close()
		t.Fatal("legacy schema was silently migrated")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("legacy database main image changed during rejected open")
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
	percentPath := filepath.Join(dir, "state%66.db")
	if err := os.WriteFile(percentPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(context.Background(), percentPath); err == nil {
		store.Close()
		t.Fatal("percent-encoded writable state path accepted")
	}
	if store, err := OpenReadOnly(context.Background(), percentPath); err == nil {
		store.Close()
		t.Fatal("percent-encoded read-only state path accepted")
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
	unversionedPath := filepath.Join(dir, "unversioned.db")
	unversioned, err := sql.Open("sqlite", unversionedPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unversioned.Exec(`CREATE TABLE legacy_state(value TEXT)`); err != nil {
		unversioned.Close()
		t.Fatal(err)
	}
	if err := unversioned.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(unversionedPath)
	if err != nil {
		t.Fatal(err)
	}
	if store, err := Open(context.Background(), unversionedPath); err == nil {
		store.Close()
		t.Fatal("nonempty unversioned database was treated as fresh")
	}
	after, err := os.ReadFile(unversionedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected unversioned database main image changed")
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
	if err := s.SaveGenerationWithMetadata(ctx, 1, testChecksum(script), script, nil, nil, testGenerationMetadata(t)); err != nil {
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
	emptyMetadata := testGenerationMetadata(t)
	emptyMetadata.Provenance = nil
	if err := s.SaveGenerationWithMetadata(ctx, 1, testChecksum(script), script, nil, nil, emptyMetadata); err == nil || !strings.Contains(err.Error(), "provenance manifest is required") {
		t.Fatalf("empty production provenance manifest accepted: %v", err)
	}
	if err := s.SaveGenerationWithMetadata(ctx, 0, testChecksum(script), script, nil, nil, testGenerationMetadata(t)); err == nil {
		t.Fatal("zero generation id accepted")
	}
	if err := s.SaveGenerationWithMetadata(ctx, 1, strings.Repeat("0", 64), script, nil, nil, testGenerationMetadata(t)); err == nil {
		t.Fatal("generation with mismatched checksum accepted")
	}
	if err := s.SaveGenerationWithMetadata(ctx, 1, testChecksum(script), script, nil, nil, testGenerationMetadata(t)); err != nil {
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

func TestStatePublicLifecycleAndViews(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(secureTestDir(t), "state.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if got, err := s.NextGeneration(ctx); err != nil || got != 1 {
		t.Fatalf("unexpected next generation: %d %v", got, err)
	}
	script1 := "table inet nftfw_filter { comment \"one\"; }\n"
	if err := s.SaveGenerationWithMetadata(
		ctx, 1, testChecksum(script1), script1, nil, nil, testGenerationMetadata(t),
	); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkApplied(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.SetObservedHash(ctx, 1, testChecksum("observed")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetObservedHash(ctx, 1, "invalid"); err == nil {
		t.Fatal("malformed observed hash accepted")
	}
	if expected, err := s.ExpectedGeneration(ctx); err != nil || expected.ID != 1 {
		t.Fatalf("applied generation was not expected: %#v %v", expected, err)
	}
	if err := s.Commit(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if committed, err := s.LastKnownGood(ctx); err != nil || committed.ID != 1 {
		t.Fatalf("committed generation missing: %#v %v", committed, err)
	}
	generation1, err := s.Generation(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.ReadGenerationScript(generation1); err != nil || got != script1 {
		t.Fatalf("generation alias read failed: %q %v", got, err)
	}

	if got, err := s.NextGeneration(ctx); err != nil || got != 2 {
		t.Fatalf("unexpected second generation: %d %v", got, err)
	}
	previous := uint64(1)
	deadline := time.Now().UTC().Add(time.Hour)
	script2 := "table inet nftfw_filter { comment \"two\"; }\n"
	if err := s.SaveGenerationWithMetadata(
		ctx, 2, testChecksum(script2), script2, &previous, &deadline, testGenerationMetadata(t),
	); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkApplied(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareCommit(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if stored, err := s.PreparedDeadline(ctx, 2); err != nil || stored == nil ||
		!stored.Equal(deadline) {
		t.Fatalf("prepared deadline mismatch: %v %v", stored, err)
	}
	if expected, err := s.ExpectedGeneration(ctx); err != nil || expected.ID != 1 {
		t.Fatalf("unpublished prepared generation became expected: %#v %v", expected, err)
	}
	if err := s.MarkRolledBack(ctx, 2); err != nil {
		t.Fatal(err)
	}

	script3 := "table inet nftfw_filter { comment \"three\"; }\n"
	if err := s.SaveGenerationWithMetadata(
		ctx, 3, testChecksum(script3), script3, &previous, nil, testGenerationMetadata(t),
	); err != nil {
		t.Fatal(err)
	}
	if err := s.FinalizeRecoveryRollback(ctx, 3, "test recovery"); err != nil {
		t.Fatal(err)
	}
	if generation3, err := s.Generation(ctx, 3); err != nil || generation3.Status != "rolled_back" {
		t.Fatalf("recovery rollback was not durable: %#v %v", generation3, err)
	}

	now := time.Now().UTC()
	manualID, err := s.AddClaim(ctx, Claim{
		Address: "192.0.2.10/32", Family: "ipv4", Source: "manual",
		Reason: "operator", Actor: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	expiry := now.Add(time.Hour)
	allowID, err := s.AddClaim(ctx, Claim{
		Address: "192.0.2.20/32", Family: "ipv4", Source: "allow",
		Reason: "temporary", Actor: "admin", ExpiresAt: &expiry,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddClaim(ctx, Claim{
		Address: "192.0.2.30/32", Family: "ipv4", Source: "threatfeed/example",
		Reason: "feed", Actor: "integration",
	}); err != nil {
		t.Fatal(err)
	}
	claims, publication, err := s.ClaimsWithPublication(ctx, now)
	if err != nil || len(claims) != 3 || publication.DesiredRevision <= publication.AppliedRevision {
		t.Fatalf("unexpected claims/publication: %#v %#v %v", claims, publication, err)
	}
	revision, err := s.PrepareClaimPublication(ctx)
	if err != nil || revision != publication.DesiredRevision {
		t.Fatalf("publication preparation changed the pending revision: %d %v", revision, err)
	}
	if err := s.MarkClaimsPublished(ctx, revision, len(claims)); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveOperatorClaim(ctx, allowID, "admin", "block"); err == nil {
		t.Fatal("temporary allow removed through block API")
	}
	if err := s.RemoveOperatorClaim(ctx, allowID, "admin", "allow"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveOperatorClaim(ctx, manualID, "admin", "block"); err != nil {
		t.Fatal(err)
	}
	restored := Claim{
		ID: manualID, Address: "192.0.2.10/32", Family: "ipv4", Source: "manual",
		Reason: "operator", Actor: "admin", CreatedAt: now,
	}
	if err := s.RestoreClaim(ctx, restored, "recovery"); err != nil {
		t.Fatal(err)
	}
	if count, err := s.ClaimCountExcludingSource(ctx, "manual"); err != nil || count != 1 {
		t.Fatalf("unexpected non-manual claim count: %d %v", count, err)
	}
	claims, err = s.Claims(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := EffectiveAddressesFrom(claims, "ipv4", "threatfeed"); !reflect.DeepEqual(
		got, []string{"192.0.2.30/32"},
	) {
		t.Fatalf("unexpected source projection: %v", got)
	}
	if got := EffectiveAddressesFrom(claims, "ipv4", ""); !reflect.DeepEqual(
		got, []string{"192.0.2.10/32", "192.0.2.30/32"},
	) {
		t.Fatalf("unexpected all-source projection: %v", got)
	}

	if err := s.Audit(ctx, "operator", "view_test", "complete"); err != nil {
		t.Fatal(err)
	}
	if recent, err := s.RecentAudit(ctx, 0); err != nil || len(recent) == 0 {
		t.Fatalf("recent audit unavailable: %#v %v", recent, err)
	}
	if err := s.SetIntegrationState(ctx, "wireguard/nftfw0", "healthy", 1, true); err != nil {
		t.Fatal(err)
	}
	if states, err := s.IntegrationStates(ctx); err != nil || len(states) < 2 {
		t.Fatalf("integration states unavailable: %#v %v", states, err)
	}
	if root := StateRootForDatabasePath(path); root != filepath.Dir(path) {
		t.Fatalf("unexpected state root: %s", root)
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

func TestGenerationReadsAndWritesRejectSymlinkedParent(t *testing.T) {
	ctx := context.Background()
	root := secureTestDir(t)
	store, err := Open(ctx, filepath.Join(root, "generation-state", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	external := secureTestDir(t)
	if err := os.Symlink(external, filepath.Join(root, "generations")); err != nil {
		t.Fatal(err)
	}
	script := "table inet nftfw_filter { }\n"
	if err := store.SaveGenerationWithMetadata(ctx, 1, testChecksum(script), script, nil, nil, testGenerationMetadata(t)); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("generation write accepted symlinked parent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(external, fmt.Sprintf("%020d.snapshot.json", 1)), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGenerationSnapshot(root, 1); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("snapshot load accepted symlinked parent: %v", err)
	}
	generation := &Generation{ID: 1, Checksum: testChecksum(script), ScriptPath: filepath.Join(root, "generations", fmt.Sprintf("%020d.nft", 1))}
	if _, err := store.ReadScript(generation); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("script read accepted symlinked parent: %v", err)
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

func BenchmarkSQLiteGenerationStatus(b *testing.B) {
	root := b.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		b.Fatal(err)
	}
	store, err := Open(context.Background(), filepath.Join(root, "state.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := store.NextGeneration(context.Background()); err != nil {
			b.Fatal(err)
		}
		if _, err := store.ClaimPublicationState(context.Background()); err != nil {
			b.Fatal(err)
		}
		if err := store.QuickCheck(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSQLiteBackup(b *testing.B) {
	root := b.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		b.Fatal(err)
	}
	store, err := Open(context.Background(), filepath.Join(root, "state.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	backupRoot := filepath.Join(root, "backups")
	if err := os.Mkdir(backupRoot, 0o700); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for index := 0; b.Loop(); index++ {
		destination := filepath.Join(backupRoot, fmt.Sprintf("state-%d.db", index))
		if err := store.Backup(context.Background(), destination); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		if err := os.Remove(destination); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}
