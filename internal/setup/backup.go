package setup

import (
	"context"
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
	Schema  string               `json:"schema"`
	Path    string               `json:"path"`
	Files   []backupFile         `json:"files"`
	Units   map[string]unitState `json:"units"`
	Sysctls map[string]string    `json:"sysctls"`
}

type backupFile struct {
	Path   string      `json:"path"`
	Backup string      `json:"backup,omitempty"`
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
		item.Exists, item.Backup, item.Mode = true, name, info.Mode().Perm()
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
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return backupManifest{}, errors.New("SETUP_BACKUP_MANIFEST_FAILED")
	}
	if err := writeAtomic(filepath.Join(directory, "manifest.json"), append(data, '\n'), 0o600); err != nil {
		return backupManifest{}, err
	}
	return manifest, nil
}

func restoreBackup(ctx context.Context, runner routing.Runner, directory string) error {
	manifest, err := readBackup(directory)
	if err != nil {
		return err
	}
	for _, item := range manifest.Files {
		if item.Exists {
			source := filepath.Join(directory, item.Backup)
			data, err := os.ReadFile(source)
			if err != nil {
				return errors.New("SETUP_BACKUP_RESTORE_READ_FAILED")
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
	for key, value := range manifest.Sysctls {
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
		}
		if _, err := runner.Run(ctx, nil, "systemctl", action, unit); err != nil {
			return errors.New("SETUP_BACKUP_RESTORE_UNIT_FAILED")
		}
	}
	return nil
}

func restoreUnitOrder(units []string) []string {
	rank := map[string]int{
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
	var manifest backupManifest
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || manifest.Schema != "nftfw.setup-backup.v1" ||
		manifest.Path != directory {
		return backupManifest{}, errors.New("SETUP_BACKUP_MANIFEST_INVALID")
	}
	return manifest, nil
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
