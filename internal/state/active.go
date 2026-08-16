package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const (
	activeSnapshotName = "active.snapshot.json"
	activeMarkerName   = "enforcement-enabled"
	maxActiveSnapshot  = 32 << 20
)

type activeSnapshot struct {
	Checksum string `json:"checksum"`
	Script   string `json:"script"`
}

// PublishActive persists the exact committed transaction independently from
// SQLite so early boot can restore known-good enforcement after DB failure.
func (s *Store) PublishActive(script, checksum string) error {
	if s == nil || s.Dir == "" {
		return errors.New("state store is unavailable")
	}
	dir, err := secureActiveDirectory(s.Dir)
	if err != nil {
		return err
	}
	if !validScriptChecksum(script, checksum) {
		return errors.New("active snapshot checksum is invalid")
	}
	encoded, err := json.Marshal(activeSnapshot{Checksum: checksum, Script: script})
	if err != nil {
		return err
	}
	if len(encoded) > maxActiveSnapshot {
		return errors.New("active snapshot exceeds 32 MiB")
	}
	if err := writeAtomic(filepath.Join(dir, activeSnapshotName), append(encoded, '\n')); err != nil {
		return fmt.Errorf("publish active snapshot: %w", err)
	}
	// The marker is written last on first activation. A crash can therefore
	// never advertise enforcement before a complete snapshot is durable.
	if err := writeAtomic(filepath.Join(dir, activeMarkerName), []byte("enabled\n")); err != nil {
		return fmt.Errorf("publish enforcement marker: %w", err)
	}
	return nil
}

func (s *Store) ClearActive() error {
	if s == nil || s.Dir == "" {
		return errors.New("state store is unavailable")
	}
	dir, err := secureActiveDirectory(s.Dir)
	if err != nil {
		return err
	}
	for _, name := range []string{activeMarkerName, activeSnapshotName} {
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return syncDirectory(dir)
}

// LoadActiveSnapshot does not open SQLite. enabled is true whenever a prior
// commit marker exists, including when the snapshot itself is damaged.
func LoadActiveSnapshot(directory string) (script string, enabled bool, err error) {
	dir, err := secureActiveDirectory(directory)
	if err != nil {
		return "", false, err
	}
	marker := filepath.Join(dir, activeMarkerName)
	if _, err := secureActiveFile(marker, 64); errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	} else if err != nil {
		return "", true, fmt.Errorf("enforcement marker: %w", err)
	}
	snapshotPath := filepath.Join(dir, activeSnapshotName)
	data, err := secureActiveFile(snapshotPath, maxActiveSnapshot)
	if err != nil {
		return "", true, fmt.Errorf("active snapshot: %w", err)
	}
	var snapshot activeSnapshot
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return "", true, fmt.Errorf("decode active snapshot: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return "", true, errors.New("active snapshot contains multiple JSON values")
		}
		return "", true, fmt.Errorf("decode active snapshot trailer: %w", err)
	}
	if !validScriptChecksum(snapshot.Script, snapshot.Checksum) {
		return "", true, errors.New("active snapshot checksum mismatch")
	}
	return snapshot.Script, true, nil
}

func secureActiveDirectory(directory string) (string, error) {
	abs, err := filepath.Abs(directory)
	if err != nil || abs != directory || abs == "/" {
		return "", errors.New("active state directory must be absolute and non-root")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved != abs {
		return "", errors.New("active state directory is absent or contains a symlink")
	}
	info, err := os.Stat(abs)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return "", errors.New("active state directory has unsafe permissions")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return "", errors.New("active state directory has unsafe ownership")
	}
	return abs, nil
}

func secureActiveFile(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > max {
		return nil, errors.New("file type, permissions, or size is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("file ownership is unsafe")
	}
	return os.ReadFile(path)
}

func validScriptChecksum(script, checksum string) bool {
	want, err := hex.DecodeString(checksum)
	if err != nil || len(want) != sha256.Size {
		return false
	}
	got := sha256.Sum256([]byte(script))
	return equalBytes(got[:], want)
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return errors.New("active state target is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".active-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	return syncDirectory(dir)
}
