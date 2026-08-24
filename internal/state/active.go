package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
)

const (
	// activeMarkerName is retained for compatibility with the 2.0.1 safety
	// check. In 2.0.2 it contains a canonical JSON pointer, not "enabled".
	activeMarkerName   = "enforcement-enabled"
	activeSnapshotName = "active.snapshot.json" // legacy; never published by 2.0.2
	maxActiveSnapshot  = 32 << 20
	pointerSchema      = "nftfw.enforcement-pointer.v1"
	snapshotSchema     = "nftfw.generation-snapshot.v1"
)

type EnforcementPointer struct {
	Schema           string `json:"schema"`
	Generation       uint64 `json:"generation"`
	SnapshotChecksum string `json:"snapshot_checksum"`
	PolicyChecksum   string `json:"policy_checksum"`
}

func (p EnforcementPointer) valid() bool {
	return p.Schema == pointerSchema && p.Generation > 0 && validChecksum(p.SnapshotChecksum) && validChecksum(p.PolicyChecksum)
}

func (p EnforcementPointer) Equal(other *EnforcementPointer) bool {
	return other != nil && p.Schema == other.Schema && p.Generation == other.Generation && p.SnapshotChecksum == other.SnapshotChecksum && p.PolicyChecksum == other.PolicyChecksum
}

// GenerationSnapshot is immutable after publication. Provenance is the exact
// permanent mapping needed to interpret surviving conntrack marks. Previous
// is the only pointer state from which this generation may be committed.
type GenerationSnapshot struct {
	Schema     string                  `json:"schema"`
	Generation uint64                  `json:"generation"`
	Checksum   string                  `json:"checksum"`
	Script     string                  `json:"script"`
	Provenance []provenance.Assignment `json:"provenance"`
	Previous   *EnforcementPointer     `json:"previous,omitempty"`
	BootID     string                  `json:"boot_id"`
}

func (s GenerationSnapshot) Pointer() EnforcementPointer {
	encoded, _ := encodeGenerationSnapshot(s)
	digest := sha256.Sum256(encoded)
	return EnforcementPointer{
		Schema: pointerSchema, Generation: s.Generation,
		SnapshotChecksum: hex.EncodeToString(digest[:]), PolicyChecksum: s.Checksum,
	}
}

// PreparedPointer is fully written and fsynced. PublishPreparedPointer starts
// with the atomic rename so callers can make their final persisted-deadline
// read immediately before that linearization point without hidden I/O.
type PreparedPointer struct {
	Root     string
	TempPath string
	Pointer  EnforcementPointer
}

func generationSnapshotPath(root string, id uint64) string {
	return filepath.Join(root, "generations", fmt.Sprintf("%020d.snapshot.json", id))
}

func secureGenerationsDirectory(root string, create bool) (string, error) {
	directory := filepath.Join(root, "generations")
	if create {
		if err := os.Mkdir(directory, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("create generations directory: %w", err)
		}
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("generations directory must be a non-symlink directory")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return "", errors.New("generations directory contains a symlink")
	}
	if err := validateOwnedDirectory(directory); err != nil {
		return "", err
	}
	return directory, nil
}

func (s *Store) WriteGenerationSnapshot(snapshot GenerationSnapshot) (string, error) {
	if s == nil || s.Dir == "" {
		return "", errors.New("state store is unavailable")
	}
	root, err := secureActiveDirectory(s.Dir)
	if err != nil {
		return "", err
	}
	if err := validateSnapshot(snapshot); err != nil {
		return "", err
	}
	encoded, err := encodeGenerationSnapshot(snapshot)
	if err != nil {
		return "", err
	}
	if len(encoded) > maxActiveSnapshot {
		return "", errors.New("generation snapshot exceeds 32 MiB")
	}
	if _, err := secureGenerationsDirectory(root, true); err != nil {
		return "", err
	}
	path := generationSnapshotPath(root, snapshot.Generation)
	if existing, readErr := secureActiveFile(path, maxActiveSnapshot); readErr == nil {
		if bytes.Equal(existing, encoded) {
			return path, nil
		}
		return "", fmt.Errorf("immutable generation snapshot %d already exists with different content", snapshot.Generation)
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", readErr
	}
	if err := writeImmutable(path, encoded); err != nil {
		return "", fmt.Errorf("publish immutable generation snapshot: %w", err)
	}
	return path, nil
}

func encodeGenerationSnapshot(snapshot GenerationSnapshot) ([]byte, error) {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func LoadGenerationSnapshot(root string, id uint64) (GenerationSnapshot, error) {
	root, err := secureActiveDirectory(root)
	if err != nil {
		return GenerationSnapshot{}, err
	}
	if id == 0 {
		return GenerationSnapshot{}, errors.New("generation snapshot id must be positive")
	}
	if _, err := secureGenerationsDirectory(root, false); err != nil {
		return GenerationSnapshot{}, err
	}
	data, err := secureActiveFile(generationSnapshotPath(root, id), maxActiveSnapshot)
	if err != nil {
		return GenerationSnapshot{}, err
	}
	var snapshot GenerationSnapshot
	if err := decodeOneJSON(data, &snapshot); err != nil {
		return GenerationSnapshot{}, fmt.Errorf("decode generation snapshot: %w", err)
	}
	if err := validateSnapshot(snapshot); err != nil {
		return GenerationSnapshot{}, err
	}
	if snapshot.Generation != id {
		return GenerationSnapshot{}, errors.New("generation snapshot filename/id mismatch")
	}
	return snapshot, nil
}

// LoadVerifiedGenerationSnapshot also proves that every provenance assignment
// embedded in the immutable snapshot is still present with the same permanent
// meaning in the monotonic ledger. The ledger is opened strictly read-only.
func LoadVerifiedGenerationSnapshot(root string, id uint64) (GenerationSnapshot, error) {
	snapshot, err := LoadGenerationSnapshot(root, id)
	if err != nil {
		return GenerationSnapshot{}, err
	}
	if err := validateSnapshotProvenance(root, snapshot); err != nil {
		return GenerationSnapshot{}, err
	}
	return snapshot, nil
}

func validateSnapshotProvenance(root string, snapshot GenerationSnapshot) error {
	ledger, err := provenance.OpenReadOnly(context.Background(), filepath.Join(root, "provenance-ledger.db"))
	if err != nil {
		return fmt.Errorf("open monotonic provenance ledger: %w", err)
	}
	defer ledger.Close()
	if err := ledger.ValidateRequired(context.Background(), snapshot.Provenance); err != nil {
		return fmt.Errorf("validate generation provenance: %w", err)
	}
	return nil
}

// EnsurePublishedGenerationDurable revalidates the exact authoritative
// pointer and immutable snapshot, then repeats every required fsync boundary.
// Recovery calls this before finalizing a commit whose pointer rename won.
func EnsurePublishedGenerationDurable(root string, expected EnforcementPointer) (GenerationSnapshot, error) {
	pointer, exists, err := ReadEnforcementPointer(root)
	if err != nil {
		return GenerationSnapshot{}, err
	}
	if !exists || !expected.Equal(pointer) {
		return GenerationSnapshot{}, errors.New("published enforcement pointer changed during recovery")
	}
	snapshot, err := LoadVerifiedGenerationSnapshot(root, expected.Generation)
	if err != nil {
		return GenerationSnapshot{}, err
	}
	if !snapshot.Pointer().Equal(pointer) {
		return GenerationSnapshot{}, errors.New("published enforcement pointer does not match immutable snapshot")
	}
	snapshotPath := generationSnapshotPath(root, expected.Generation)
	if err := syncRegularFile(snapshotPath); err != nil {
		return GenerationSnapshot{}, fmt.Errorf("sync immutable generation snapshot: %w", err)
	}
	if err := syncDirectory(filepath.Dir(snapshotPath)); err != nil {
		return GenerationSnapshot{}, fmt.Errorf("sync generation snapshot directory: %w", err)
	}
	pointerPath := filepath.Join(root, activeMarkerName)
	if err := syncRegularFile(pointerPath); err != nil {
		return GenerationSnapshot{}, fmt.Errorf("sync enforcement pointer: %w", err)
	}
	if err := syncDirectory(root); err != nil {
		return GenerationSnapshot{}, fmt.Errorf("sync enforcement pointer directory: %w", err)
	}
	return snapshot, nil
}

func PrepareEnforcementPointer(root string, pointer EnforcementPointer) (*PreparedPointer, error) {
	root, err := secureActiveDirectory(root)
	if err != nil {
		return nil, err
	}
	if !pointer.valid() {
		return nil, errors.New("enforcement pointer is invalid")
	}
	encoded, err := json.Marshal(pointer)
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	tmp, err := os.CreateTemp(root, ".enforcement-pointer-*.tmp")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	cleanup := func(cause error) (*PreparedPointer, error) {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return nil, cause
	}
	if err := tmp.Chmod(0o600); err != nil {
		return cleanup(err)
	}
	if _, err := tmp.Write(encoded); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := syncDirectory(root); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	return &PreparedPointer{Root: root, TempPath: tmpPath, Pointer: pointer}, nil
}

func CancelPreparedPointer(prepared *PreparedPointer) error {
	if prepared == nil || prepared.TempPath == "" {
		return nil
	}
	err := os.Remove(prepared.TempPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDirectory(prepared.Root)
}

func PublishPreparedPointer(prepared *PreparedPointer) error {
	if prepared == nil || prepared.Root == "" || prepared.TempPath == "" || !prepared.Pointer.valid() {
		return errors.New("prepared enforcement pointer is invalid")
	}
	finalPath := filepath.Join(prepared.Root, activeMarkerName)
	// The rename must remain the first filesystem operation in this function.
	if err := os.Rename(prepared.TempPath, finalPath); err != nil {
		return err
	}
	prepared.TempPath = ""
	if err := syncRegularFile(finalPath); err != nil {
		return err
	}
	return syncDirectory(prepared.Root)
}

func ReadEnforcementPointer(root string) (*EnforcementPointer, bool, error) {
	root, err := secureActiveDirectory(root)
	if err != nil {
		return nil, false, err
	}
	data, err := secureActiveFile(filepath.Join(root, activeMarkerName), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, fmt.Errorf("enforcement pointer: %w", err)
	}
	var pointer EnforcementPointer
	if err := decodeOneJSON(data, &pointer); err != nil {
		return nil, true, fmt.Errorf("decode enforcement pointer: %w", err)
	}
	if !pointer.valid() {
		return nil, true, errors.New("enforcement pointer is invalid")
	}
	return &pointer, true, nil
}

// LoadActiveSnapshot validates the pointer, immutable snapshot, checksum, and
// permanent provenance mapping without migrations, journals, or writes.
func LoadActiveSnapshot(directory string) (script string, enabled bool, err error) {
	pointer, enabled, err := ReadEnforcementPointer(directory)
	if err != nil || !enabled {
		return "", enabled, err
	}
	snapshot, err := LoadVerifiedGenerationSnapshot(directory, pointer.Generation)
	if err != nil {
		return "", true, fmt.Errorf("active generation snapshot: %w", err)
	}
	if !snapshot.Pointer().Equal(pointer) {
		return "", true, errors.New("enforcement pointer does not match generation snapshot")
	}
	return snapshot.Script, true, nil
}

func (s *Store) ClearActive() error {
	if s == nil || s.Dir == "" {
		return errors.New("state store is unavailable")
	}
	root, err := secureActiveDirectory(s.Dir)
	if err != nil {
		return err
	}
	for _, name := range []string{activeMarkerName, activeSnapshotName} {
		if err := os.Remove(filepath.Join(root, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return syncDirectory(root)
}

func validateSnapshot(snapshot GenerationSnapshot) error {
	if snapshot.Schema != snapshotSchema || snapshot.Generation == 0 {
		return errors.New("generation snapshot schema or id is invalid")
	}
	if !validScriptChecksum(snapshot.Script, snapshot.Checksum) {
		return errors.New("generation snapshot script checksum is invalid")
	}
	if snapshot.Previous != nil && (!snapshot.Previous.valid() || snapshot.Previous.Generation == snapshot.Generation) {
		return errors.New("generation snapshot prior pointer is invalid")
	}
	if snapshot.BootID == "" {
		return errors.New("generation snapshot boot id is empty")
	}
	if len(snapshot.Provenance) == 0 {
		return errors.New("generation snapshot provenance manifest is empty")
	}
	seenNames := map[string]bool{}
	seenIDs := map[uint8]bool{}
	for _, assignment := range snapshot.Provenance {
		if assignment.Name == "" || assignment.ID < provenance.MinID || assignment.ID > provenance.MaxID || seenNames[assignment.Name] || seenIDs[assignment.ID] {
			return errors.New("generation snapshot provenance manifest is invalid")
		}
		seenNames[assignment.Name], seenIDs[assignment.ID] = true, true
	}
	return nil
}

func validChecksum(checksum string) bool {
	decoded, err := hex.DecodeString(checksum)
	return err == nil && len(decoded) == sha256.Size
}

func validScriptChecksum(script, checksum string) bool {
	if !validChecksum(checksum) {
		return false
	}
	want, _ := hex.DecodeString(checksum)
	got := sha256.Sum256([]byte(script))
	return equalBytes(got[:], want)
}

func decodeOneJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
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
	if err := validateOwnedDirectory(abs); err != nil {
		return "", err
	}
	return abs, nil
}

func validateOwnedDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return errors.New("state directory has unsafe permissions")
	}
	return validateOwnedDirectoryInfo(info, os.Geteuid())
}

func validateOwnedDirectoryInfo(info os.FileInfo, effectiveUID int) error {
	if info == nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("state directory has unsafe permissions")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(effectiveUID) {
		return errors.New("state directory has unsafe ownership")
	}
	return nil
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
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return nil, errors.New("file ownership is unsafe")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, max+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > max {
		return nil, errors.New("state file bounded read failed")
	}
	return data, nil
}

func writeImmutable(path string, data []byte) error {
	directory := filepath.Dir(path)
	tmp, err := os.CreateTemp(directory, ".generation-snapshot-*.tmp")
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
	if err := os.Link(tmpPath, path); err != nil {
		return err
	}
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func syncRegularFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
