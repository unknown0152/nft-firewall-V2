package setup

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

type FileJournal struct {
	Path string
}

func (f FileJournal) Write(journal Journal) error {
	if !filepath.IsAbs(f.Path) || filepath.Clean(f.Path) != f.Path {
		return errors.New("SETUP_JOURNAL_PATH_INVALID")
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
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
	file, err := os.OpenFile(f.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Journal{}, errors.New("SETUP_JOURNAL_READ_FAILED")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 ||
		info.Mode().Perm()&0o077 != 0 {
		return Journal{}, errors.New("SETUP_JOURNAL_FILE_UNSAFE")
	}
	var journal Journal
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil || journal.Schema != "nftfw.setup-journal.v1" ||
		journal.Transaction == "" || journal.StartedAt.IsZero() || journal.Deadline.IsZero() {
		return Journal{}, errors.New("SETUP_JOURNAL_INVALID")
	}
	return journal, nil
}
