// Package operatorbackup creates and verifies complete managed-mode backup
// bundles without embedding live secrets in the manifest.
package operatorbackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/intent"
	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/wgconfig"
)

const (
	Schema       = "nftfw.operator-backup.v1"
	maxFileBytes = 64 << 20
	maxFiles     = 2048
)

type Paths struct {
	Config      string
	Intent      string
	VPN         string
	Sysctl      string
	StateDB     string
	Ledger      string
	Generations string
	Enforcement string
}

type Record struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
}

type Manifest struct {
	Schema    string    `json:"schema"`
	CreatedAt time.Time `json:"created_at"`
	Managed   bool      `json:"managed"`
	Files     []Record  `json:"files"`
}

type Creator struct {
	Paths   Paths
	LockDir string
	Now     func() time.Time
}

func (c Creator) Create(ctx context.Context, destination string) (Manifest, error) {
	if err := validateDestination(destination); err != nil {
		return Manifest{}, err
	}
	parent := filepath.Dir(destination)
	if err := ensureProtectedDirectory(parent, 0o750); err != nil {
		return Manifest{}, err
	}
	if _, err := os.Lstat(destination); err == nil {
		return Manifest{}, errors.New("BACKUP_DESTINATION_EXISTS")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, errors.New("BACKUP_DESTINATION_UNSAFE")
	}
	temporary, err := os.MkdirTemp(parent, ".nftfw-managed-backup-*")
	if err != nil {
		return Manifest{}, errors.New("BACKUP_TEMPORARY_CREATE_FAILED")
	}
	if err := os.Chmod(temporary, 0o700); err != nil {
		_ = os.RemoveAll(temporary)
		return Manifest{}, errors.New("BACKUP_TEMPORARY_CREATE_FAILED")
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(temporary)
		}
	}()

	lockDir := c.LockDir
	if lockDir == "" {
		lockDir = state.DefaultMutationLockDir
	}
	release, err := state.AcquireMutationLock(ctx, lockDir)
	if err != nil {
		return Manifest{}, errors.New("BACKUP_LOCK_FAILED")
	}
	defer release()

	required := []struct {
		source string
		target string
	}{
		{c.Paths.Config, "nftfw.toml"},
		{c.Paths.Intent, "intent.toml"},
		{c.Paths.VPN, "nftfw0.conf"},
	}
	for _, item := range required {
		if err := copyProtected(item.source, filepath.Join(temporary, item.target)); err != nil {
			return Manifest{}, err
		}
	}
	for _, item := range []struct {
		source string
		target string
	}{
		{c.Paths.Sysctl, "90-nftfw-managed.conf"},
		{c.Paths.Enforcement, "enforcement-enabled"},
	} {
		if err := copyOptional(item.source, filepath.Join(temporary, item.target)); err != nil {
			return Manifest{}, err
		}
	}
	if err := copyGenerationArtifacts(c.Paths.Generations, filepath.Join(temporary, "generations")); err != nil {
		return Manifest{}, err
	}

	store, err := state.OpenRecovery(ctx, c.Paths.StateDB)
	if err != nil {
		return Manifest{}, errors.New("BACKUP_STATE_OPEN_FAILED")
	}
	stateDestination := filepath.Join(temporary, "generation-state", "state.db")
	if err := store.Backup(ctx, stateDestination); err != nil {
		store.Close()
		return Manifest{}, errors.New("BACKUP_STATE_CREATE_FAILED")
	}
	if err := store.Close(); err != nil {
		return Manifest{}, errors.New("BACKUP_STATE_CLOSE_FAILED")
	}

	ledger, err := provenance.Open(ctx, c.Paths.Ledger)
	if err != nil {
		return Manifest{}, errors.New("BACKUP_LEDGER_OPEN_FAILED")
	}
	if err := ledger.Backup(ctx, filepath.Join(temporary, "provenance-ledger.db")); err != nil {
		ledger.Close()
		return Manifest{}, errors.New("BACKUP_LEDGER_CREATE_FAILED")
	}
	if err := ledger.Close(); err != nil {
		return Manifest{}, errors.New("BACKUP_LEDGER_CLOSE_FAILED")
	}

	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	manifest := Manifest{
		Schema: Schema, CreatedAt: now().UTC(), Managed: true,
	}
	manifest.Files, err = inventory(temporary, "manifest.json")
	if err != nil {
		return Manifest{}, err
	}
	if err := writeManifest(filepath.Join(temporary, "manifest.json"), manifest); err != nil {
		return Manifest{}, err
	}
	if _, err := Verify(ctx, temporary); err != nil {
		return Manifest{}, err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return Manifest{}, errors.New("BACKUP_PUBLISH_FAILED")
	}
	if err := syncDirectory(parent); err != nil {
		return Manifest{}, err
	}
	published = true
	return manifest, nil
}

func Verify(ctx context.Context, directory string) (Manifest, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return Manifest{}, errors.New("BACKUP_PATH_INVALID")
	}
	if err := verifyProtectedDirectory(directory); err != nil {
		return Manifest{}, err
	}
	manifestPath := filepath.Join(directory, "manifest.json")
	file, err := os.OpenFile(manifestPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Manifest{}, errors.New("BACKUP_MANIFEST_READ_FAILED")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 ||
		info.Mode().Perm()&0o077 != 0 {
		return Manifest{}, errors.New("BACKUP_MANIFEST_UNSAFE")
	}
	var manifest Manifest
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || manifest.Schema != Schema || !manifest.Managed ||
		manifest.CreatedAt.IsZero() {
		return Manifest{}, errors.New("BACKUP_MANIFEST_INVALID")
	}
	actual, err := inventory(directory, "manifest.json")
	if err != nil {
		return Manifest{}, err
	}
	if !recordsEqual(manifest.Files, actual) {
		return Manifest{}, errors.New("BACKUP_CONTENT_MISMATCH")
	}
	if _, err := config.Load(filepath.Join(directory, "nftfw.toml")); err != nil {
		return Manifest{}, errors.New("BACKUP_CONFIG_INVALID")
	}
	if _, err := intent.Load(filepath.Join(directory, "intent.toml")); err != nil {
		return Manifest{}, errors.New("BACKUP_INTENT_INVALID")
	}
	if _, _, err := wgconfig.ReadManaged(filepath.Join(directory, "nftfw0.conf")); err != nil {
		return Manifest{}, errors.New("BACKUP_VPN_INVALID")
	}
	store, err := state.OpenReadOnly(ctx, filepath.Join(directory, "generation-state", "state.db"))
	if err != nil {
		return Manifest{}, errors.New("BACKUP_STATE_INVALID")
	}
	if err := store.Close(); err != nil {
		return Manifest{}, errors.New("BACKUP_STATE_INVALID")
	}
	ledger, err := provenance.OpenReadOnly(ctx, filepath.Join(directory, "provenance-ledger.db"))
	if err != nil {
		return Manifest{}, errors.New("BACKUP_LEDGER_INVALID")
	}
	if err := ledger.QuickCheck(ctx); err != nil {
		ledger.Close()
		return Manifest{}, errors.New("BACKUP_LEDGER_INVALID")
	}
	if err := ledger.Close(); err != nil {
		return Manifest{}, errors.New("BACKUP_LEDGER_INVALID")
	}
	return manifest, nil
}

func validateDestination(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" ||
		strings.ContainsAny(path, "\x00\n\r") {
		return errors.New("BACKUP_PATH_INVALID")
	}
	return nil
}

func ensureProtectedDirectory(path string, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("BACKUP_DIRECTORY_INVALID")
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return errors.New("BACKUP_DIRECTORY_CREATE_FAILED")
	}
	return verifyProtectedDirectory(path)
}

func verifyProtectedDirectory(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("BACKUP_DIRECTORY_UNSAFE")
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("BACKUP_DIRECTORY_UNSAFE")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("BACKUP_DIRECTORY_UNSAFE")
	}
	return nil
}

func copyOptional(source, destination string) error {
	if _, err := os.Lstat(source); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("BACKUP_SOURCE_UNSAFE")
	}
	return copyProtected(source, destination)
}

func copyProtected(source, destination string) error {
	input, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("BACKUP_SOURCE_READ_FAILED")
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 ||
		info.Size() > maxFileBytes || info.Mode().Perm()&0o022 != 0 {
		return errors.New("BACKUP_SOURCE_UNSAFE")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return errors.New("BACKUP_TARGET_CREATE_FAILED")
	}
	output, err := os.OpenFile(
		destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600,
	)
	if err != nil {
		return errors.New("BACKUP_TARGET_CREATE_FAILED")
	}
	ok := false
	defer func() {
		_ = output.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	written, err := io.Copy(output, io.LimitReader(input, maxFileBytes+1))
	if err != nil || written != info.Size() || written > maxFileBytes {
		return errors.New("BACKUP_SOURCE_CHANGED")
	}
	if err := output.Sync(); err != nil {
		return errors.New("BACKUP_TARGET_SYNC_FAILED")
	}
	if err := output.Close(); err != nil {
		return errors.New("BACKUP_TARGET_SYNC_FAILED")
	}
	ok = true
	return nil
}

func copyGenerationArtifacts(source, destination string) error {
	resolved, err := filepath.EvalSymlinks(source)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || resolved != source {
		return errors.New("BACKUP_GENERATIONS_UNSAFE")
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return errors.New("BACKUP_GENERATIONS_READ_FAILED")
	}
	if len(entries) > maxFiles {
		return errors.New("BACKUP_GENERATIONS_TOO_MANY")
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 ||
			(!strings.HasSuffix(entry.Name(), ".nft") &&
				!strings.HasSuffix(entry.Name(), ".snapshot.json")) {
			return errors.New("BACKUP_GENERATIONS_UNSAFE")
		}
		if err := copyProtected(
			filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name()),
		); err != nil {
			return err
		}
	}
	return nil
}

func inventory(root, excluded string) ([]Record, error) {
	var records []Record
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == excluded {
			return nil
		}
		if len(records) >= maxFiles {
			return errors.New("BACKUP_FILE_COUNT_EXCEEDED")
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Size() < 0 || info.Size() > maxFileBytes || info.Mode().Perm()&0o077 != 0 {
			return errors.New("BACKUP_FILE_UNSAFE")
		}
		digest, err := fileDigest(path, info.Size())
		if err != nil {
			return err
		}
		records = append(records, Record{
			Path: relative, SHA256: digest, Size: info.Size(),
			Mode: fmt.Sprintf("%04o", info.Mode().Perm()),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return records, nil
}

func fileDigest(path string, size int64) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", errors.New("BACKUP_FILE_READ_FAILED")
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maxFileBytes+1))
	if err != nil || written != size || written > maxFileBytes {
		return "", errors.New("BACKUP_FILE_CHANGED")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func recordsEqual(left, right []Record) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func writeManifest(path string, manifest Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return errors.New("BACKUP_MANIFEST_ENCODE_FAILED")
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("BACKUP_MANIFEST_WRITE_FAILED")
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return errors.New("BACKUP_MANIFEST_WRITE_FAILED")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return errors.New("BACKUP_MANIFEST_WRITE_FAILED")
	}
	if err := file.Close(); err != nil {
		return errors.New("BACKUP_MANIFEST_WRITE_FAILED")
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return errors.New("BACKUP_DIRECTORY_SYNC_FAILED")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("BACKUP_DIRECTORY_SYNC_FAILED")
	}
	return nil
}
