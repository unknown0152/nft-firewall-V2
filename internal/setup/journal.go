package setup

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var journalIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func (f FileJournal) Begin(journal Journal, priorSHA256 string) error {
	if !validJournalPath(f.Path) {
		return errors.New("SETUP_JOURNAL_PATH_INVALID")
	}
	if !initialSetupJournal(journal) {
		return errors.New("SETUP_JOURNAL_INITIAL_INVALID")
	}
	if priorSHA256 == "" {
		if _, err := os.Lstat(f.Path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("SETUP_JOURNAL_LINEAGE_UNEXPECTED")
		}
		return f.Write(journal)
	}
	if !validSHA256(priorSHA256) {
		return errors.New("SETUP_JOURNAL_LINEAGE_INVALID")
	}
	prior, raw, digest, err := readJournalFile(f.Path)
	if err != nil || digest != priorSHA256 || !terminalRolledBackJournal(prior) ||
		prior.Transaction == journal.Transaction {
		return errors.New("SETUP_JOURNAL_LINEAGE_CHANGED")
	}
	if err := archiveTerminalJournal(filepath.Dir(f.Path), prior, raw, digest); err != nil {
		return err
	}
	return f.Write(journal)
}

type FileJournal struct {
	Path string
}

func (f FileJournal) Write(journal Journal) error {
	if !validJournalPath(f.Path) {
		return errors.New("SETUP_JOURNAL_PATH_INVALID")
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return errors.New("SETUP_JOURNAL_DIRECTORY_FAILED")
	}
	if err := secureSetupDirectory(filepath.Dir(f.Path)); err != nil {
		return errors.New("SETUP_JOURNAL_DIRECTORY_FAILED")
	}
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return errors.New("SETUP_JOURNAL_ENCODE_FAILED")
	}
	data = append(data, '\n')
	return writeAtomic(f.Path, data, 0o600)
}

func (f FileJournal) Read() (Journal, error) {
	journal, _, _, err := readJournalFile(f.Path)
	return journal, err
}

func validJournalPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func readJournalFile(path string) (Journal, []byte, string, error) {
	if !validJournalPath(path) {
		return Journal{}, nil, "", errors.New("SETUP_JOURNAL_PATH_INVALID")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Journal{}, nil, "", errors.New("SETUP_JOURNAL_READ_FAILED")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > 1<<20 ||
		before.Mode().Perm()&0o077 != 0 {
		return Journal{}, nil, "", errors.New("SETUP_JOURNAL_FILE_UNSAFE")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return Journal{}, nil, "", errors.New("SETUP_JOURNAL_FILE_UNSAFE")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return Journal{}, nil, "", errors.New("SETUP_JOURNAL_READ_FAILED")
	}
	after, err := file.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return Journal{}, nil, "", errors.New("SETUP_JOURNAL_CHANGED")
	}
	var journal Journal
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		journal.Schema != "nftfw.setup-journal.v1" ||
		!journalIdentityPattern.MatchString(journal.Transaction) ||
		journal.StartedAt.IsZero() || journal.UpdatedAt.IsZero() || journal.Deadline.IsZero() ||
		journal.UpdatedAt.Before(journal.StartedAt) || journal.Deadline.Before(journal.StartedAt) {
		return Journal{}, nil, "", errors.New("SETUP_JOURNAL_INVALID")
	}
	canonical, err := json.MarshalIndent(journal, "", "  ")
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return Journal{}, nil, "", errors.New("SETUP_JOURNAL_INVALID")
	}
	sum := sha256.Sum256(raw)
	return journal, raw, fmt.Sprintf("%x", sum[:]), nil
}

func terminalRolledBackJournal(journal Journal) bool {
	if journal.Status != "rolled_back" || journal.Phase != PhaseFailed || journal.Committed ||
		!journalIdentityPattern.MatchString(journal.Transaction) {
		return false
	}
	if journal.BackupDir != "" && (!filepath.IsAbs(journal.BackupDir) ||
		filepath.Clean(journal.BackupDir) != journal.BackupDir) {
		return false
	}
	if journal.ErrorCode != "" && (len(journal.ErrorCode) > 96 ||
		strings.Trim(journal.ErrorCode, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "") {
		return false
	}
	return true
}

func initialSetupJournal(journal Journal) bool {
	return journal.Schema == "nftfw.setup-journal.v1" &&
		journalIdentityPattern.MatchString(journal.Transaction) && journal.Phase == PhaseInspect &&
		journal.Status == "running" && !journal.Committed && journal.Generation == 0 &&
		journal.BackupDir == "" && journal.ErrorCode == "" &&
		journal.Summary.Schema == "nftfw.setup-plan.v1" &&
		!journal.StartedAt.IsZero() && !journal.UpdatedAt.IsZero() && !journal.Deadline.IsZero() &&
		!journal.UpdatedAt.Before(journal.StartedAt) && !journal.Deadline.Before(journal.StartedAt)
}

func archiveTerminalJournal(parent string, journal Journal, raw []byte, digest string) error {
	if err := secureSetupDirectory(parent); err != nil {
		return errors.New("SETUP_JOURNAL_HISTORY_UNSAFE")
	}
	history := filepath.Join(parent, "history")
	if err := secureHistoryDirectory(history); err != nil {
		return err
	}
	if err := syncSetupDirectory(parent); err != nil {
		return errors.New("SETUP_JOURNAL_HISTORY_SYNC_FAILED")
	}
	destination := filepath.Join(history, journal.Transaction+"."+digest+".json")
	if _, statErr := os.Lstat(destination); statErr == nil {
		existing, existingRaw, existingDigest, err := readJournalFile(destination)
		if err != nil || existingDigest != digest || !bytes.Equal(existingRaw, raw) ||
			!terminalRolledBackJournal(existing) {
			return errors.New("SETUP_JOURNAL_HISTORY_COLLISION")
		}
		if syncRegularSetupFile(destination) != nil || syncSetupDirectory(history) != nil ||
			syncSetupDirectory(parent) != nil {
			return errors.New("SETUP_JOURNAL_HISTORY_SYNC_FAILED")
		}
		return nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errors.New("SETUP_JOURNAL_HISTORY_COLLISION")
	}
	// Keep the unpublished temporary beside history, not inside it. A process
	// death before rename may leave this setup-owned residue, but it cannot be
	// mistaken for an archived lineage entry on the next read. Parent and
	// history are on the same filesystem, so the final no-replace rename stays
	// atomic.
	temporary, err := os.CreateTemp(parent, ".journal-history-*.tmp")
	if err != nil {
		return errors.New("SETUP_JOURNAL_HISTORY_CREATE_FAILED")
	}
	temporaryPath := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.New("SETUP_JOURNAL_HISTORY_CREATE_FAILED")
	}
	if _, err := temporary.Write(raw); err != nil {
		return errors.New("SETUP_JOURNAL_HISTORY_SYNC_FAILED")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("SETUP_JOURNAL_HISTORY_SYNC_FAILED")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("SETUP_JOURNAL_HISTORY_SYNC_FAILED")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, temporaryPath, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, syscall.EEXIST) || func() bool {
			_, statErr := os.Lstat(destination)
			return statErr == nil
		}() {
			return errors.New("SETUP_JOURNAL_HISTORY_COLLISION")
		}
		return errors.New("SETUP_JOURNAL_HISTORY_PUBLISH_FAILED")
	}
	if err := syncSetupDirectory(history); err != nil || syncSetupDirectory(parent) != nil {
		return errors.New("SETUP_JOURNAL_HISTORY_SYNC_FAILED")
	}
	ok = true
	archived, archivedRaw, archivedDigest, err := readJournalFile(destination)
	if err != nil || archivedDigest != digest || !bytes.Equal(archivedRaw, raw) ||
		!terminalRolledBackJournal(archived) {
		return errors.New("SETUP_JOURNAL_HISTORY_VERIFY_FAILED")
	}
	return nil
}

func secureSetupDirectory(path string) error {
	if !validJournalPath(path) {
		return errors.New("setup journal directory is unsafe")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("setup journal directory is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("setup journal directory is unsafe")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("setup journal directory is unsafe")
	}
	return nil
}

func secureHistoryDirectory(path string) error {
	if !validJournalPath(path) {
		return errors.New("SETUP_JOURNAL_HISTORY_UNSAFE")
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("SETUP_JOURNAL_HISTORY_CREATE_FAILED")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("SETUP_JOURNAL_HISTORY_UNSAFE")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("SETUP_JOURNAL_HISTORY_UNSAFE")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("SETUP_JOURNAL_HISTORY_UNSAFE")
	}
	return syncSetupDirectory(path)
}

func syncSetupDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func syncRegularSetupFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func validSHA256(value string) bool {
	return len(value) == sha256.Size*2 && strings.Trim(value, "0123456789abcdef") == ""
}
