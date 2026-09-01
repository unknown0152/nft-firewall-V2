package setup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/routing"
)

type backupManifest struct {
	Schema         string               `json:"schema"`
	Path           string               `json:"path"`
	Files          []backupFile         `json:"files"`
	Units          map[string]unitState `json:"units"`
	Sysctls        map[string]string    `json:"sysctls"`
	PreparedSHA256 string               `json:"prepared_sha256,omitempty"`
	Boot           *bootBackup          `json:"boot,omitempty"`
}

type backupFile struct {
	Path   string      `json:"path"`
	Backup string      `json:"backup,omitempty"`
	SHA256 string      `json:"sha256,omitempty"`
	Exists bool        `json:"exists"`
	Mode   os.FileMode `json:"mode,omitempty"`
	UID    int         `json:"uid,omitempty"`
	GID    int         `json:"gid,omitempty"`
}

type unitState struct {
	Enabled bool `json:"enabled"`
	Active  bool `json:"active"`
}

func createBackup(ctx context.Context, runner routing.Runner, directory string, files, units, sysctls []string) (backupManifest, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return backupManifest{}, errors.New("SETUP_BACKUP_PATH_INVALID")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil || os.Chmod(directory, 0o700) != nil {
		return backupManifest{}, errors.New("SETUP_BACKUP_DIRECTORY_FAILED")
	}
	manifest := backupManifest{
		Schema: "nftfw.setup-backup.v1", Path: directory,
		Units: map[string]unitState{}, Sysctls: map[string]string{},
	}
	for index, path := range files {
		item := backupFile{Path: path}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			manifest.Files = append(manifest.Files, item)
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return backupManifest{}, errors.New("SETUP_BACKUP_SOURCE_UNSAFE")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return backupManifest{}, errors.New("SETUP_BACKUP_SOURCE_UNSAFE")
		}
		name := fmt.Sprintf("file-%03d", index)
		if err := copyRegular(path, filepath.Join(directory, name), info.Mode().Perm()); err != nil {
			return backupManifest{}, err
		}
		digest, err := digestRegular(filepath.Join(directory, name))
		if err != nil {
			return backupManifest{}, err
		}
		item.Exists, item.Backup, item.Mode = true, name, info.Mode().Perm()
		item.SHA256 = digest
		item.UID, item.GID = int(stat.Uid), int(stat.Gid)
		manifest.Files = append(manifest.Files, item)
	}
	for _, unit := range units {
		_, enabledErr := runner.Run(ctx, nil, "systemctl", "is-enabled", "--quiet", unit)
		_, activeErr := runner.Run(ctx, nil, "systemctl", "is-active", "--quiet", unit)
		manifest.Units[unit] = unitState{Enabled: enabledErr == nil, Active: activeErr == nil}
	}
	for _, key := range sysctls {
		value, err := runner.Run(ctx, nil, "sysctl", "-n", key)
		if err != nil || len(value) > 128 {
			return backupManifest{}, errors.New("SETUP_BACKUP_SYSCTL_FAILED")
		}
		manifest.Sysctls[key] = strings.TrimSpace(string(value))
	}
	if err := writeBackupManifest(manifest); err != nil {
		return backupManifest{}, err
	}
	return manifest, nil
}

func writeBackupManifest(manifest backupManifest) error {
	if !filepath.IsAbs(manifest.Path) || filepath.Clean(manifest.Path) != manifest.Path ||
		manifest.Schema != "nftfw.setup-backup.v1" {
		return errors.New("SETUP_BACKUP_MANIFEST_FAILED")
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return errors.New("SETUP_BACKUP_MANIFEST_FAILED")
	}
	if err := writeAtomic(filepath.Join(manifest.Path, "manifest.json"), append(data, '\n'), 0o600); err != nil {
		return err
	}
	return nil
}

func restoreBackup(ctx context.Context, runner routing.Runner, directory string) error {
	return restoreBackupDeferring(ctx, runner, directory, nil)
}

// restoreBackupDeferring restores every protected object while deliberately
// leaving selected sysctls for a later, explicit recovery boundary. A kernel
// booted with ipv6.disable=1 does not expose /proc/sys/net/ipv6, so the exact
// pre-boot IPv6 values can only be restored after the rollback reboot.
func restoreBackupDeferring(
	ctx context.Context, runner routing.Runner, directory string, deferSysctl func(string) bool,
) error {
	manifest, err := readBackup(directory)
	if err != nil {
		return err
	}
	for _, item := range manifest.Files {
		if item.Exists {
			source := filepath.Join(directory, item.Backup)
			data, err := os.ReadFile(source)
			if err != nil || len(data) > 4<<20 {
				return errors.New("SETUP_BACKUP_RESTORE_READ_FAILED")
			}
			if item.SHA256 != "" {
				sum := sha256.Sum256(data)
				if fmt.Sprintf("%x", sum[:]) != item.SHA256 {
					return errors.New("SETUP_BACKUP_RESTORE_CHECKSUM_FAILED")
				}
			}
			if err := writeAtomic(item.Path, data, item.Mode); err != nil {
				return err
			}
			if os.Geteuid() == 0 {
				if err := os.Chown(item.Path, item.UID, item.GID); err != nil {
					return errors.New("SETUP_BACKUP_RESTORE_OWNER_FAILED")
				}
			}
		} else {
			info, err := os.Lstat(item.Path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || !info.Mode().IsRegular() {
				return errors.New("SETUP_BACKUP_RESTORE_TARGET_UNSAFE")
			}
			if err := os.Remove(item.Path); err != nil {
				return errors.New("SETUP_BACKUP_RESTORE_REMOVE_FAILED")
			}
		}
	}
	keys := make([]string, 0, len(manifest.Sysctls))
	for key := range manifest.Sysctls {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if deferSysctl != nil && deferSysctl(key) {
			continue
		}
		value := manifest.Sysctls[key]
		if _, err := runner.Run(ctx, nil, "sysctl", "-w", key+"="+value); err != nil {
			return errors.New("SETUP_BACKUP_RESTORE_SYSCTL_FAILED")
		}
	}
	if _, err := runner.Run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return errors.New("SETUP_BACKUP_RESTORE_UNIT_FAILED")
	}
	units := make([]string, 0, len(manifest.Units))
	for unit := range manifest.Units {
		units = append(units, unit)
	}
	sort.Strings(units)
	for _, unit := range units {
		state := manifest.Units[unit]
		enable := "disable"
		if state.Enabled {
			enable = "enable"
		}
		if _, err := runner.Run(ctx, nil, "systemctl", enable, unit); err != nil {
			return errors.New("SETUP_BACKUP_RESTORE_UNIT_FAILED")
		}
	}
	for _, unit := range restoreUnitOrder(units) {
		state := manifest.Units[unit]
		action := "stop"
		if state.Active {
			action = "start"
			if unit == "docker.service" {
				resetUnits := []string{"reset-failed", "docker.service"}
				if _, socketPresent := manifest.Units["docker.socket"]; socketPresent {
					resetUnits = append(resetUnits, "docker.socket")
				}
				if _, err := runner.Run(ctx, nil, "systemctl", resetUnits...); err != nil {
					return errors.New("SETUP_BACKUP_RESTORE_DOCKER_RESET_FAILED")
				}
				action = "restart"
			}
		}
		if _, err := runner.Run(ctx, nil, "systemctl", action, unit); err != nil {
			if unit == "docker.service" && action == "restart" {
				return errors.New("SETUP_BACKUP_RESTORE_DOCKER_RESTART_FAILED")
			}
			return errors.New("SETUP_BACKUP_RESTORE_UNIT_FAILED")
		}
	}
	return nil
}

func restoreDeferredSysctls(
	ctx context.Context, runner routing.Runner, directory string, match func(string) bool,
) error {
	if match == nil {
		return errors.New("SETUP_BACKUP_RESTORE_SYSCTL_FAILED")
	}
	manifest, err := readBackup(directory)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(manifest.Sysctls))
	for key := range manifest.Sysctls {
		if match(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return errors.New("SETUP_BACKUP_RESTORE_SYSCTL_FAILED")
	}
	for _, key := range keys {
		if _, err := runner.Run(ctx, nil, "sysctl", "-w", key+"="+manifest.Sysctls[key]); err != nil {
			return errors.New("SETUP_BACKUP_RESTORE_SYSCTL_FAILED")
		}
	}
	return nil
}

func restoreBackupFiles(directory string, required []string) error {
	manifest, err := readBackup(directory)
	if err != nil {
		return err
	}
	wanted := make(map[string]bool, len(required))
	for _, path := range required {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || wanted[path] {
			return errors.New("SETUP_BACKUP_SELECTION_INVALID")
		}
		wanted[path] = true
	}
	for _, item := range manifest.Files {
		if !wanted[item.Path] {
			continue
		}
		delete(wanted, item.Path)
		if item.Exists {
			source := filepath.Join(directory, item.Backup)
			data, readErr := os.ReadFile(source)
			if readErr != nil || len(data) > 4<<20 {
				return errors.New("SETUP_BACKUP_RESTORE_READ_FAILED")
			}
			sum := sha256.Sum256(data)
			if item.SHA256 == "" || fmt.Sprintf("%x", sum[:]) != item.SHA256 {
				return errors.New("SETUP_BACKUP_RESTORE_CHECKSUM_FAILED")
			}
			if err := writeAtomic(item.Path, data, item.Mode); err != nil {
				return err
			}
			if os.Geteuid() == 0 && os.Chown(item.Path, item.UID, item.GID) != nil {
				return errors.New("SETUP_BACKUP_RESTORE_OWNER_FAILED")
			}
			if err := validateRestoredTarget(item); err != nil {
				return err
			}
			continue
		}
		info, statErr := os.Lstat(item.Path)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("SETUP_BACKUP_RESTORE_TARGET_UNSAFE")
		}
		if err := os.Remove(item.Path); err != nil || syncSetupDirectory(filepath.Dir(item.Path)) != nil {
			return errors.New("SETUP_BACKUP_RESTORE_REMOVE_FAILED")
		}
	}
	if len(wanted) != 0 {
		return errors.New("SETUP_BACKUP_SELECTION_INVALID")
	}
	return nil
}

func restoreUnitOrder(units []string) []string {
	rank := map[string]int{
		"docker.service":                  5,
		"docker.socket":                   6,
		"nftfw-early.service":             10,
		"nftfw-enforcement-ready.service": 20,
		"nftfwd.service":                  30,
		"nftfw-rollback.service":          40,
		"nftfw-rollback.timer":            50,
		"nftfw-vpn.service":               60,
		"nftfw-web.service":               70,
		"nftfw-setup-rollback.service":    80,
		"nftfw-setup-rollback.timer":      90,
	}
	result := append([]string(nil), units...)
	sort.SliceStable(result, func(i, j int) bool {
		left, leftOK := rank[result[i]]
		right, rightOK := rank[result[j]]
		if leftOK != rightOK {
			return leftOK
		}
		if left != right {
			return left < right
		}
		return result[i] < result[j]
	})
	return result
}

func readBackup(directory string) (backupManifest, error) {
	path := filepath.Join(directory, "manifest.json")
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return backupManifest{}, errors.New("SETUP_BACKUP_MANIFEST_READ_FAILED")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 ||
		info.Mode().Perm()&0o077 != 0 {
		return backupManifest{}, errors.New("SETUP_BACKUP_MANIFEST_UNSAFE")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return backupManifest{}, errors.New("SETUP_BACKUP_MANIFEST_UNSAFE")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) == 0 || len(data) > 1<<20 {
		return backupManifest{}, errors.New("SETUP_BACKUP_MANIFEST_READ_FAILED")
	}
	var manifest backupManifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		manifest.Schema != "nftfw.setup-backup.v1" ||
		manifest.Path != directory {
		return backupManifest{}, errors.New("SETUP_BACKUP_MANIFEST_INVALID")
	}
	if manifest.PreparedSHA256 != "" && !validSHA256(manifest.PreparedSHA256) {
		return backupManifest{}, errors.New("SETUP_BACKUP_MANIFEST_INVALID")
	}
	if manifest.Boot != nil && !validBootBackup(*manifest.Boot) {
		return backupManifest{}, errors.New("SETUP_BACKUP_MANIFEST_INVALID")
	}
	canonical, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil || !bytes.Equal(data, append(canonical, '\n')) {
		return backupManifest{}, errors.New("SETUP_BACKUP_MANIFEST_INVALID")
	}
	for _, item := range manifest.Files {
		if item.Exists && item.SHA256 != "" &&
			(len(item.SHA256) != sha256.Size*2 || strings.Trim(item.SHA256, "0123456789abcdef") != "") {
			return backupManifest{}, errors.New("SETUP_BACKUP_MANIFEST_INVALID")
		}
	}
	return manifest, nil
}

func verifyRestoredBackup(ctx context.Context, runner routing.Runner, directory string) (backupManifest, error) {
	return verifyRestoredBackupDeferring(ctx, runner, directory, nil)
}

func verifyRestoredBackupDeferring(
	ctx context.Context, runner routing.Runner, directory string, deferSysctl func(string) bool,
) (backupManifest, error) {
	if err := validateBackupDirectory(directory); err != nil {
		return backupManifest{}, err
	}
	manifest, err := readBackup(directory)
	if err != nil {
		return backupManifest{}, err
	}
	allowed := map[string]bool{"manifest.json": true}
	if manifest.Boot != nil && manifest.Boot.ResumeGuardSHA256 != "" {
		allowed["resume-guard.nft"] = true
		if err := validateBackupPayload(
			filepath.Join(directory, "resume-guard.nft"), manifest.Boot.ResumeGuardSHA256,
		); err != nil {
			return backupManifest{}, err
		}
	}
	seenTargets := map[string]bool{}
	for index, item := range manifest.Files {
		if !filepath.IsAbs(item.Path) || filepath.Clean(item.Path) != item.Path || seenTargets[item.Path] {
			return backupManifest{}, errors.New("SETUP_BACKUP_MANIFEST_INVALID")
		}
		seenTargets[item.Path] = true
		if item.Exists {
			expectedName := fmt.Sprintf("file-%03d", index)
			if item.Backup != expectedName || !validSHA256(item.SHA256) || item.Mode&^os.ModePerm != 0 {
				return backupManifest{}, errors.New("SETUP_BACKUP_MANIFEST_INVALID")
			}
			allowed[item.Backup] = true
			backupPath := filepath.Join(directory, item.Backup)
			if err := validateBackupPayload(backupPath, item.SHA256); err != nil {
				return backupManifest{}, err
			}
			if err := validateRestoredTarget(item); err != nil {
				return backupManifest{}, err
			}
		} else {
			if item.Backup != "" || item.SHA256 != "" || item.Mode != 0 || item.UID != 0 || item.GID != 0 {
				return backupManifest{}, errors.New("SETUP_BACKUP_MANIFEST_INVALID")
			}
			if _, err := os.Lstat(item.Path); !errors.Is(err, os.ErrNotExist) {
				return backupManifest{}, errors.New("SETUP_BACKUP_RESTORE_MISMATCH")
			}
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return backupManifest{}, errors.New("SETUP_BACKUP_DIRECTORY_FAILED")
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return backupManifest{}, errors.New("SETUP_BACKUP_DIRECTORY_UNEXPECTED")
		}
	}
	for key, expected := range manifest.Sysctls {
		if deferSysctl != nil && deferSysctl(key) {
			continue
		}
		value, err := runner.Run(ctx, nil, "sysctl", "-n", key)
		if err != nil || len(value) > 128 || strings.TrimSpace(string(value)) != expected {
			return backupManifest{}, errors.New("SETUP_BACKUP_SYSCTL_MISMATCH")
		}
	}
	for unit, expected := range manifest.Units {
		if err := verifyRestoredUnit(ctx, runner, unit, expected); err != nil {
			return backupManifest{}, err
		}
	}
	return manifest, nil
}

func validateBackupDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("SETUP_BACKUP_PATH_INVALID")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("SETUP_BACKUP_DIRECTORY_UNSAFE")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("SETUP_BACKUP_DIRECTORY_UNSAFE")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return errors.New("SETUP_BACKUP_DIRECTORY_UNSAFE")
	}
	return nil
}

func validateBackupPayload(path, expected string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || info.Size() > 4<<20 {
		return errors.New("SETUP_BACKUP_PAYLOAD_UNSAFE")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("SETUP_BACKUP_PAYLOAD_UNSAFE")
	}
	digest, err := digestRegular(path)
	if err != nil || digest != expected {
		return errors.New("SETUP_BACKUP_RESTORE_CHECKSUM_FAILED")
	}
	return nil
}

func validateRestoredTarget(item backupFile) error {
	info, err := os.Lstat(item.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != item.Mode {
		return errors.New("SETUP_BACKUP_RESTORE_MISMATCH")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != item.UID || int(stat.Gid) != item.GID {
		return errors.New("SETUP_BACKUP_RESTORE_MISMATCH")
	}
	digest, err := digestRegular(item.Path)
	if err != nil || digest != item.SHA256 {
		return errors.New("SETUP_BACKUP_RESTORE_MISMATCH")
	}
	return nil
}

func verifyRestoredUnit(ctx context.Context, runner routing.Runner, unit string, expected unitState) error {
	data, err := runner.Run(ctx, nil, "systemctl", "show", "--property=LoadState,ActiveState", unit)
	if err != nil || len(data) == 0 || len(data) > 512 {
		return errors.New("SETUP_BACKUP_UNIT_MISMATCH")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || (key != "LoadState" && key != "ActiveState") || value == "" || values[key] != "" {
			return errors.New("SETUP_BACKUP_UNIT_MISMATCH")
		}
		values[key] = value
	}
	if values["LoadState"] != "loaded" ||
		(values["ActiveState"] != "active" && values["ActiveState"] != "inactive") ||
		(values["ActiveState"] == "active") != expected.Active {
		return errors.New("SETUP_BACKUP_UNIT_MISMATCH")
	}
	_, enabledErr := runner.Run(ctx, nil, "systemctl", "is-enabled", "--quiet", unit)
	if (enabledErr == nil) != expected.Enabled {
		return errors.New("SETUP_BACKUP_UNIT_MISMATCH")
	}
	return nil
}

func digestRegular(path string) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", errors.New("SETUP_BACKUP_DIGEST_FAILED")
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, (4<<20)+1))
	if err != nil || written > 4<<20 {
		return "", errors.New("SETUP_BACKUP_DIGEST_FAILED")
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func copyRegular(source, destination string, mode os.FileMode) error {
	input, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("SETUP_BACKUP_READ_FAILED")
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return errors.New("SETUP_BACKUP_CREATE_FAILED")
	}
	ok := false
	defer func() {
		_ = output.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(output, io.LimitReader(input, (4<<20)+1)); err != nil {
		return errors.New("SETUP_BACKUP_COPY_FAILED")
	}
	if position, err := output.Seek(0, io.SeekCurrent); err != nil || position > 4<<20 {
		return errors.New("SETUP_BACKUP_FILE_TOO_LARGE")
	}
	if err := output.Sync(); err != nil {
		return errors.New("SETUP_BACKUP_SYNC_FAILED")
	}
	if err := output.Close(); err != nil {
		return errors.New("SETUP_BACKUP_SYNC_FAILED")
	}
	ok = true
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(data) > 4<<20 {
		return errors.New("SETUP_FILE_TARGET_INVALID")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return errors.New("SETUP_FILE_DIRECTORY_FAILED")
	}
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("SETUP_FILE_TARGET_UNSAFE")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("SETUP_FILE_TARGET_UNSAFE")
	}
	temporary := filepath.Join(parent, "."+filepath.Base(path)+".nftfw-"+strconv.FormatInt(timeNowUnixNano(), 10))
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return errors.New("SETUP_FILE_CREATE_FAILED")
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return errors.New("SETUP_FILE_WRITE_FAILED")
	}
	if err := file.Sync(); err != nil {
		return errors.New("SETUP_FILE_SYNC_FAILED")
	}
	if err := file.Chmod(mode); err != nil {
		return errors.New("SETUP_FILE_MODE_FAILED")
	}
	if err := file.Close(); err != nil {
		return errors.New("SETUP_FILE_SYNC_FAILED")
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("SETUP_FILE_PUBLISH_FAILED")
	}
	directory, err := os.Open(parent)
	if err != nil {
		return errors.New("SETUP_FILE_DIRECTORY_FAILED")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("SETUP_FILE_SYNC_FAILED")
	}
	ok = true
	return nil
}

// WriteAtomicFile exposes the setup transaction's no-follow, fsynced file
// publication primitive to the managed CLI commands.
func WriteAtomicFile(path string, data []byte, mode os.FileMode) error {
	return writeAtomic(path, data, mode)
}

var timeNowUnixNano = func() int64 {
	return time.Now().UnixNano()
}
