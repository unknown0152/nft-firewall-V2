package setup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func terminalJournalForTest(transaction string, generation uint64) Journal {
	started := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	return Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: transaction,
		Phase: PhaseFailed, Status: "rolled_back", StartedAt: started,
		UpdatedAt: started.Add(2 * time.Minute), Deadline: started.Add(time.Minute),
		Generation: generation, Summary: Summary{Schema: "nftfw.setup-plan.v1"},
		ErrorCode: "SETUP_TEST_FAILURE",
	}
}

func runningJournalForTest(transaction string) Journal {
	value := terminalJournalForTest(transaction, 0)
	value.Phase, value.Status, value.ErrorCode = PhaseInspect, "running", ""
	value.UpdatedAt = value.StartedAt
	return value
}

func testFileJournal(t testing.TB) FileJournal {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return FileJournal{Path: filepath.Join(root, "journal.json")}
}

func TestFileJournalBeginArchivesExactTerminalLineage(t *testing.T) {
	store := testFileJournal(t)
	root := filepath.Dir(store.Path)
	prior := terminalJournalForTest("prior", 7)
	if err := store.Write(prior); err != nil {
		t.Fatal(err)
	}
	_, raw, digest, err := readJournalFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Begin(runningJournalForTest("next"), digest); err != nil {
		t.Fatal(err)
	}
	historyPath := filepath.Join(root, "history", "prior."+digest+".json")
	archived, archivedRaw, archivedDigest, err := readJournalFile(historyPath)
	if err != nil || archived.Transaction != "prior" || archivedDigest != digest || string(archivedRaw) != string(raw) {
		t.Fatalf("terminal journal was not archived exactly: %#v %s %v", archived, archivedDigest, err)
	}
	current, err := store.Read()
	if err != nil || current.Transaction != "next" || current.Status != "running" {
		t.Fatalf("new journal was not published: %#v %v", current, err)
	}
}

func TestFileJournalBeginRetriesExistingExactArchive(t *testing.T) {
	store := testFileJournal(t)
	root := filepath.Dir(store.Path)
	prior := terminalJournalForTest("prior", 7)
	if err := store.Write(prior); err != nil {
		t.Fatal(err)
	}
	_, raw, digest, err := readJournalFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := archiveTerminalJournal(root, prior, raw, digest); err != nil {
		t.Fatal(err)
	}
	if err := store.Begin(runningJournalForTest("next"), digest); err != nil {
		t.Fatalf("exact crash-resume archive was rejected: %v", err)
	}
}

func TestFileJournalBeginIgnoresPreRenameCrashResidueOutsideHistory(t *testing.T) {
	store := testFileJournal(t)
	root := filepath.Dir(store.Path)
	prior := terminalJournalForTest("prior", 7)
	if err := store.Write(prior); err != nil {
		t.Fatal(err)
	}
	_, _, digest, err := readJournalFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	residue := filepath.Join(root, ".journal-history-interrupted.tmp")
	if err := os.WriteFile(residue, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Begin(runningJournalForTest("next"), digest); err != nil {
		t.Fatalf("pre-rename crash residue blocked exact retry: %v", err)
	}
	if _, err := os.Lstat(residue); err != nil {
		t.Fatalf("classifier silently removed crash residue: %v", err)
	}
}

func TestFileJournalBeginRefusesChangedOrAmbiguousLineage(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, root string, store FileJournal, digest string)
	}{
		{"wrong-hash", func(_ *testing.T, _ string, _ FileJournal, digest string) {
			_ = digest
		}},
		{"same-transaction", func(t *testing.T, _ string, store FileJournal, digest string) {
			if err := store.Begin(runningJournalForTest("prior"), digest); err == nil {
				t.Fatal("same transaction identity accepted")
			}
		}},
		{"history-symlink", func(t *testing.T, root string, store FileJournal, digest string) {
			target := filepath.Join(root, "target")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(root, "history")); err != nil {
				t.Fatal(err)
			}
			if err := store.Begin(runningJournalForTest("next"), digest); err == nil {
				t.Fatal("symlinked history accepted")
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := testFileJournal(t)
			root := filepath.Dir(store.Path)
			if err := store.Write(terminalJournalForTest("prior", 7)); err != nil {
				t.Fatal(err)
			}
			_, _, digest, err := readJournalFile(store.Path)
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "wrong-hash" {
				wrong := strings.Repeat("0", 64)
				if wrong == digest {
					wrong = strings.Repeat("1", 64)
				}
				if err := store.Begin(runningJournalForTest("next"), wrong); err == nil {
					t.Fatal("changed terminal checksum accepted")
				}
				return
			}
			test.mutate(t, root, store, digest)
		})
	}
}

func TestFileJournalBeginRefusesHistoryCollisionAndUnsafeMode(t *testing.T) {
	for _, mode := range []string{"collision", "mode"} {
		t.Run(mode, func(t *testing.T) {
			store := testFileJournal(t)
			root := filepath.Dir(store.Path)
			prior := terminalJournalForTest("prior", 7)
			if err := store.Write(prior); err != nil {
				t.Fatal(err)
			}
			_, _, digest, err := readJournalFile(store.Path)
			if err != nil {
				t.Fatal(err)
			}
			history := filepath.Join(root, "history")
			if err := os.Mkdir(history, 0o700); err != nil {
				t.Fatal(err)
			}
			if mode == "mode" {
				if err := os.Chmod(history, 0o755); err != nil {
					t.Fatal(err)
				}
			} else {
				path := filepath.Join(history, "prior."+digest+".json")
				if err := os.WriteFile(path, []byte("not the prior journal\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.Begin(runningJournalForTest("next"), digest); err == nil {
				t.Fatal("unsafe or colliding history accepted")
			}
		})
	}
}

func TestReadJournalRejectsDuplicateAndNonCanonicalJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	for _, data := range [][]byte{
		[]byte(`{"schema":"nftfw.setup-journal.v1","schema":"nftfw.setup-journal.v1"}`),
		[]byte(` {"schema":"nftfw.setup-journal.v1"}`),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := readJournalFile(path); err == nil {
			t.Fatal("ambiguous journal JSON accepted")
		}
	}
}

func TestFileJournalBeginBoundaryRefusals(t *testing.T) {
	initial := runningJournalForTest("next")
	if err := (FileJournal{Path: "relative/journal.json"}).Begin(initial, ""); err == nil ||
		err.Error() != "SETUP_JOURNAL_PATH_INVALID" {
		t.Fatalf("relative journal path was accepted: %v", err)
	}
	store := testFileJournal(t)
	root := filepath.Dir(store.Path)
	invalid := initial
	invalid.Status = "rolled_back"
	if err := store.Begin(invalid, ""); err == nil || err.Error() != "SETUP_JOURNAL_INITIAL_INVALID" {
		t.Fatalf("invalid initial journal was accepted: %v", err)
	}
	if err := store.Begin(initial, strings.Repeat("A", 64)); err == nil ||
		err.Error() != "SETUP_JOURNAL_LINEAGE_INVALID" {
		t.Fatalf("noncanonical lineage digest was accepted: %v", err)
	}
	if err := store.Begin(initial, strings.Repeat("0", 64)); err == nil ||
		err.Error() != "SETUP_JOURNAL_LINEAGE_CHANGED" {
		t.Fatalf("missing prior journal was accepted: %v", err)
	}
	if err := store.Begin(initial, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Begin(runningJournalForTest("other"), ""); err == nil ||
		err.Error() != "SETUP_JOURNAL_LINEAGE_UNEXPECTED" {
		t.Fatalf("existing clean journal was overwritten: %v", err)
	}
	if err := (FileJournal{Path: "relative/journal.json"}).Write(initial); err == nil ||
		err.Error() != "SETUP_JOURNAL_PATH_INVALID" {
		t.Fatalf("relative write path was accepted: %v", err)
	}
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (FileJournal{Path: filepath.Join(blocker, "journal.json")}).Write(initial); err == nil ||
		err.Error() != "SETUP_JOURNAL_DIRECTORY_FAILED" {
		t.Fatalf("journal under non-directory parent was accepted: %v", err)
	}
}

func TestFileJournalWriteRefusesUnsafeSetupParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	store := FileJournal{Path: filepath.Join(root, "journal.json")}
	if err := store.Write(runningJournalForTest("unsafe-parent")); err == nil ||
		err.Error() != "SETUP_JOURNAL_DIRECTORY_FAILED" {
		t.Fatalf("unsafe setup journal parent was accepted: %v", err)
	}
	if err := archiveTerminalJournal(root, terminalJournalForTest("unsafe", 0), nil, strings.Repeat("0", 64)); err == nil ||
		err.Error() != "SETUP_JOURNAL_HISTORY_UNSAFE" {
		t.Fatalf("unsafe archive parent was accepted: %v", err)
	}
}

func TestSecureSetupDirectoryRejectsInvalidAndAliasedPaths(t *testing.T) {
	if err := secureSetupDirectory("relative"); err == nil {
		t.Fatal("relative setup directory was accepted")
	}
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	realChild := filepath.Join(realParent, "child")
	if err := os.MkdirAll(realChild, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realParent, alias); err != nil {
		t.Fatal(err)
	}
	if err := secureSetupDirectory(filepath.Join(alias, "child")); err == nil {
		t.Fatal("setup directory beneath symlinked ancestor was accepted")
	}
}

func TestJournalFileAndHistorySecurityBoundaries(t *testing.T) {
	if _, _, _, err := readJournalFile("relative/journal.json"); err == nil ||
		err.Error() != "SETUP_JOURNAL_PATH_INVALID" {
		t.Fatalf("relative read path was accepted: %v", err)
	}
	root := t.TempDir()
	missing := filepath.Join(root, "missing.json")
	if _, _, _, err := readJournalFile(missing); err == nil || err.Error() != "SETUP_JOURNAL_READ_FAILED" {
		t.Fatalf("missing journal was accepted: %v", err)
	}
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := readJournalFile(link); err == nil || err.Error() != "SETUP_JOURNAL_READ_FAILED" {
		t.Fatalf("symlinked journal was accepted: %v", err)
	}
	for _, test := range []struct {
		name string
		data []byte
		mode os.FileMode
		want string
	}{
		{"empty", nil, 0o600, "SETUP_JOURNAL_FILE_UNSAFE"},
		{"unsafe-mode", []byte("data"), 0o644, "SETUP_JOURNAL_FILE_UNSAFE"},
		{"oversized", make([]byte, (1<<20)+1), 0o600, "SETUP_JOURNAL_FILE_UNSAFE"},
		{"malformed", []byte("not-json\n"), 0o600, "SETUP_JOURNAL_INVALID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(root, test.name+".json")
			if err := os.WriteFile(path, test.data, test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := readJournalFile(path); err == nil || err.Error() != test.want {
				t.Fatalf("unsafe journal result=%v want=%s", err, test.want)
			}
		})
	}
	if err := secureHistoryDirectory("relative/history"); err == nil ||
		err.Error() != "SETUP_JOURNAL_HISTORY_UNSAFE" {
		t.Fatalf("relative history was accepted: %v", err)
	}
	if err := secureHistoryDirectory(filepath.Join(root, "missing-parent", "history")); err == nil ||
		err.Error() != "SETUP_JOURNAL_HISTORY_CREATE_FAILED" {
		t.Fatalf("history below missing parent was accepted: %v", err)
	}
	regularHistory := filepath.Join(root, "regular-history")
	if err := os.WriteFile(regularHistory, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secureHistoryDirectory(regularHistory); err == nil ||
		err.Error() != "SETUP_JOURNAL_HISTORY_UNSAFE" {
		t.Fatalf("regular history path was accepted: %v", err)
	}
	if err := syncSetupDirectory(missing); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing directory sync result=%v", err)
	}
	if err := syncRegularSetupFile(missing); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file sync result=%v", err)
	}
}

func TestTerminalJournalClassificationIsStrict(t *testing.T) {
	valid := terminalJournalForTest("terminal", 1)
	if !terminalRolledBackJournal(valid) {
		t.Fatal("valid terminal journal rejected")
	}
	for _, mutate := range []func(*Journal){
		func(value *Journal) { value.Status = "running" },
		func(value *Journal) { value.Phase = PhaseInspect },
		func(value *Journal) { value.Committed = true },
		func(value *Journal) { value.Transaction = "unsafe identity" },
		func(value *Journal) { value.BackupDir = "relative" },
		func(value *Journal) { value.ErrorCode = "lowercase" },
		func(value *Journal) { value.ErrorCode = strings.Repeat("A", 97) },
	} {
		journal := valid
		mutate(&journal)
		if terminalRolledBackJournal(journal) {
			t.Fatalf("ambiguous terminal journal accepted: %#v", journal)
		}
	}
}
