package provenance

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
)

func ledgerPath(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, name)
}

func active(name string, id uint8) Assignment { return Assignment{Name: name, ID: id} }

func TestValidateActiveContract(t *testing.T) {
	valid := []Assignment{active("enp88s0", 1), active("ovpn0", 2), active("br-media", 3)}
	if err := ValidateActive(valid); err != nil {
		t.Fatalf("valid assignments rejected: %v", err)
	}
	cases := [][]Assignment{
		nil,
		{active("ovpn0", 0)},
		{active("ovpn0", 255)},
		{active("ovpn0", 1), active("ovpn0", 2)},
		{active("ovpn0", 1), active("enp88s0", 1)},
		{{Name: "ovpn0", ID: 1, Retired: true}},
		{{Name: "bad name", ID: 1}},
	}
	tooMany := make([]Assignment, MaxActive+1)
	for i := range tooMany {
		tooMany[i] = active("if"+string(rune('A'+i)), uint8(i+1))
	}
	cases = append(cases, tooMany)
	for i, assignments := range cases {
		if err := ValidateActive(assignments); err == nil {
			t.Errorf("invalid assignment case %d accepted: %#v", i, assignments)
		}
	}
}

func TestLedgerReservationIsImmutableAndRetirementPermanent(t *testing.T) {
	ctx := context.Background()
	path := ledgerPath(t, "provenance-ledger.db")
	ledger, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve(ctx, []Assignment{active("enp88s0", 1), active("ovpn0", 2)}); err != nil {
		t.Fatal(err)
	}
	firstDigest, err := ledger.Digest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening after a process exit represents the crash-after-reservation
	// boundary: the identity must already be permanently visible.
	ledger, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if digest, err := ledger.Digest(ctx); err != nil || digest != firstDigest {
		t.Fatalf("durable reservation changed across reopen: %q %v", digest, err)
	}
	if err := ledger.Reserve(ctx, []Assignment{active("ovpn0", 2)}); err != nil {
		t.Fatal(err)
	}
	assignments, err := ledger.Assignments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 2 || !assignments[0].Retired || assignments[1].Retired {
		t.Fatalf("unexpected retirement inventory: %#v", assignments)
	}
	if err := ledger.ValidateRequired(ctx, []Assignment{active("enp88s0", 1), active("ovpn0", 2)}); err != nil {
		t.Fatalf("historical generation cannot validate tombstone: %v", err)
	}
	if err := ledger.Reserve(ctx, []Assignment{active("enp88s0", 1), active("ovpn0", 2)}); err == nil {
		t.Fatal("retired identity was reactivated")
	}
	if err := ledger.Reserve(ctx, []Assignment{active("replacement", 1), active("ovpn0", 2)}); err == nil {
		t.Fatal("retired id was reused")
	}
	if err := ledger.Reserve(ctx, []Assignment{active("ovpn0", 3)}); err == nil {
		t.Fatal("existing identity changed id")
	}
	if _, err := ledger.DB.ExecContext(ctx, `DELETE FROM allocations WHERE interface_name='enp88s0'`); err == nil {
		t.Fatal("direct allocation deletion bypassed ledger trigger")
	}
	if _, err := ledger.DB.ExecContext(ctx, `UPDATE allocations SET provenance_id=4 WHERE interface_name='ovpn0'`); err == nil {
		t.Fatal("direct identity rewrite bypassed ledger trigger")
	}
}

func TestConcurrentIdenticalReservationIsIdempotent(t *testing.T) {
	ctx := context.Background()
	ledger, err := Open(ctx, ledgerPath(t, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	assignments := []Assignment{active("lan0", 10), active("vpn0", 11)}
	const workers = 12
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- ledger.Reserve(ctx, assignments)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent idempotent reservation failed: %v", err)
		}
	}
	got, err := ledger.Assignments(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("unexpected inventory after concurrency: %#v err=%v", got, err)
	}
}

func TestMergeOnlyRestoreRejectsRegressionAndPreservesTombstones(t *testing.T) {
	ctx := context.Background()
	savedPath := ledgerPath(t, "saved.db")
	saved, err := Open(ctx, savedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := saved.Reserve(ctx, []Assignment{active("lan0", 1)}); err != nil {
		t.Fatal(err)
	}
	if err := saved.Close(); err != nil {
		t.Fatal(err)
	}

	livePath := ledgerPath(t, "live.db")
	live, err := Open(ctx, livePath)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if err := live.Reserve(ctx, []Assignment{active("lan0", 1), active("vpn0", 2)}); err != nil {
		t.Fatal(err)
	}
	if err := live.MergeFrom(ctx, savedPath); err == nil {
		t.Fatal("regressed saved ledger replaced a live allocation")
	}
	if err := live.Reserve(ctx, []Assignment{active("lan0", 1)}); err != nil {
		t.Fatal(err)
	}
	if err := live.MergeFrom(ctx, savedPath); err != nil {
		t.Fatalf("older compatible ledger could not merge over a newer tombstone: %v", err)
	}
	got, err := live.Assignments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "lan0" || got[0].Retired || got[1].Name != "vpn0" || !got[1].Retired {
		t.Fatalf("merge rewound live inventory: %#v", got)
	}
	if err := live.Reserve(ctx, []Assignment{active("lan0", 1), active("new-vpn", 2)}); err == nil {
		t.Fatal("merge permitted tombstoned id reuse")
	}
}

func TestMergeImportsCompatibleMissingHistory(t *testing.T) {
	ctx := context.Background()
	savedPath := ledgerPath(t, "saved.db")
	saved, err := Open(ctx, savedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := saved.Reserve(ctx, []Assignment{active("old-lan", 7), active("vpn", 8)}); err != nil {
		t.Fatal(err)
	}
	if err := saved.Reserve(ctx, []Assignment{active("vpn", 8)}); err != nil {
		t.Fatal(err)
	}
	saved.Close()

	live, err := Open(ctx, ledgerPath(t, "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if err := live.MergeFrom(ctx, savedPath); err != nil {
		t.Fatal(err)
	}
	got, err := live.Assignments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].Retired || got[1].Retired {
		t.Fatalf("saved history was not imported exactly: %#v", got)
	}
}

func TestReadOnlyValidationDoesNotCreateSidecars(t *testing.T) {
	ctx := context.Background()
	path := ledgerPath(t, "ledger.db")
	ledger, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve(ctx, []Assignment{active("lan0", 1)}); err != nil {
		t.Fatal(err)
	}
	ledger.Close()
	before, err := directoryNames(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	readOnly, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := readOnly.ValidateRequired(ctx, []Assignment{active("lan0", 1)}); err != nil {
		t.Fatal(err)
	}
	if _, err := readOnly.DB.ExecContext(ctx, `UPDATE allocations SET retired=1`); err == nil {
		t.Fatal("read-only ledger accepted mutation")
	}
	if err := readOnly.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := directoryNames(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("read-only validation changed directory entries: before=%v after=%v", before, after)
	}
}

func TestBackupCreatesVerifiedNoOverwriteCopy(t *testing.T) {
	ctx := context.Background()
	path := ledgerPath(t, "ledger.db")
	ledger, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err := ledger.Reserve(ctx, []Assignment{active("lan0", 1), active("vpn0", 2)}); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(filepath.Dir(path), "backup", "ledger.db")
	if err := ledger.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	backup, err := OpenReadOnly(ctx, backupPath)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	sourceDigest, err := ledger.Digest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backupDigest, err := backup.Digest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sourceDigest != backupDigest {
		t.Fatal("provenance backup digest differs")
	}
	if info, err := os.Stat(backupPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unsafe backup: info=%v err=%v", info, err)
	}
	if err := ledger.Backup(ctx, backupPath); err == nil {
		t.Fatal("provenance backup overwrote an existing destination")
	}
}

func TestUnsafeLedgerPathRejected(t *testing.T) {
	ctx := context.Background()
	if _, err := Open(ctx, ledgerPath(t, "ledger%66.db")); err == nil {
		t.Fatal("percent-encoded writable ledger path accepted")
	}
	realPath := ledgerPath(t, "real.db")
	ledger, err := Open(ctx, realPath)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Close()
	linkPath := filepath.Join(filepath.Dir(realPath), "link.db")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, linkPath); err == nil {
		t.Fatal("symlinked writable ledger accepted")
	}
	if _, err := OpenReadOnly(ctx, linkPath); err == nil {
		t.Fatal("symlinked read-only ledger accepted")
	}
}

func directoryNames(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}
