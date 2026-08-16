package state

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClaimProvenanceUnion(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"))
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

func TestReplaceSourceClaimsIsAtomicAndPreservesOtherSources(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"))
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
func TestMigrationAndCorruptDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
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
	if version != 2 {
		t.Fatalf("migration version %d", version)
	}
	bad := filepath.Join(t.TempDir(), "bad.db")
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
