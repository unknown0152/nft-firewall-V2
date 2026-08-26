package main

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
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	managedsetup "github.com/unknown0152/nft-firewall-v2/internal/setup"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

const managedChangeJournalSchema = "nftfw.managed-change-journal.v1"

var (
	managedChangeDir       = "/var/lib/nftfw/managed-change"
	managedChangeJournal   = "/var/lib/nftfw/managed-change/journal.json"
	managedChangeOldIntent = "/var/lib/nftfw/managed-change/old-intent.toml"
	managedChangeOldConfig = "/var/lib/nftfw/managed-change/old-nftfw.toml"
	managedChangeNow       = time.Now
	managedChangeTimeout   = 2 * time.Minute
)

type managedChangeRecord struct {
	Schema          string    `json:"schema"`
	Status          string    `json:"status"`
	Phase           string    `json:"phase"`
	Action          string    `json:"action"`
	Generation      uint64    `json:"generation,omitempty"`
	OldIntentSHA256 string    `json:"old_intent_sha256"`
	OldConfigSHA256 string    `json:"old_config_sha256"`
	NewIntentSHA256 string    `json:"new_intent_sha256"`
	NewConfigSHA256 string    `json:"new_config_sha256"`
	StartedAt       time.Time `json:"started_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Deadline        time.Time `json:"deadline"`
}

func managedRecoverCommand(args []string) error {
	expiredOnly := false
	if len(args) == 1 && args[0] == "--expired" {
		expiredOnly = true
	} else if len(args) != 0 {
		return errors.New("usage: nftfw managed-recover [--expired]")
	}
	if managedEUID() != 0 {
		return errors.New("MANAGED_RECOVERY_REQUIRES_ROOT")
	}
	release, err := acquireSetupLock()
	if err != nil {
		return err
	}
	defer release()
	return recoverManagedChange(context.Background(), expiredOnly)
}

func prepareManagedChange(
	action string,
	oldIntent, oldConfig, newIntent, newConfig []byte,
) (managedChangeRecord, error) {
	if err := ensureManagedChangeDirectory(); err != nil {
		return managedChangeRecord{}, err
	}
	if _, err := readManagedChangeRecord(); err == nil {
		return managedChangeRecord{}, errors.New("MANAGED_CHANGE_ALREADY_RUNNING")
	} else if !errors.Is(err, os.ErrNotExist) {
		return managedChangeRecord{}, err
	}
	if err := managedsetup.WriteAtomicFile(managedChangeOldIntent, oldIntent, 0o600); err != nil {
		return managedChangeRecord{}, errors.New("MANAGED_CHANGE_BACKUP_FAILED")
	}
	if err := managedsetup.WriteAtomicFile(managedChangeOldConfig, oldConfig, 0o600); err != nil {
		return managedChangeRecord{}, errors.New("MANAGED_CHANGE_BACKUP_FAILED")
	}
	now := managedChangeNow().UTC()
	record := managedChangeRecord{
		Schema: managedChangeJournalSchema, Status: "running", Phase: "prepared",
		Action: action, OldIntentSHA256: managedDigest(oldIntent),
		OldConfigSHA256: managedDigest(oldConfig),
		NewIntentSHA256: managedDigest(newIntent),
		NewConfigSHA256: managedDigest(newConfig),
		StartedAt:       now, UpdatedAt: now, Deadline: now.Add(managedChangeTimeout),
	}
	if err := writeManagedChangeRecord(record); err != nil {
		return managedChangeRecord{}, err
	}
	return record, nil
}

func updateManagedChange(record *managedChangeRecord, phase string, generation uint64) error {
	record.Phase = phase
	record.Generation = generation
	record.UpdatedAt = managedChangeNow().UTC()
	return writeManagedChangeRecord(*record)
}

func finishManagedChange(record *managedChangeRecord) error {
	record.Status = "complete"
	record.Phase = "complete"
	record.UpdatedAt = managedChangeNow().UTC()
	if err := writeManagedChangeRecord(*record); err != nil {
		return err
	}
	return cleanupManagedChange()
}

func rollbackKnownManagedChange(ctx context.Context, record *managedChangeRecord) error {
	var failures []error
	if record.Generation != 0 {
		if _, err := managedAPICall(ctx, managedControlSock, api.Request{
			Op: "rollback", Generation: record.Generation,
		}); err != nil {
			failures = append(failures, fmt.Errorf("rollback generation %d: %w", record.Generation, err))
		}
	}
	if err := restoreManagedChangeFiles(*record); err != nil {
		failures = append(failures, err)
	}
	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	record.Status = "rolled_back"
	record.Phase = "rolled_back"
	record.UpdatedAt = managedChangeNow().UTC()
	if err := writeManagedChangeRecord(*record); err != nil {
		return err
	}
	return cleanupManagedChange()
}

func recoverManagedChange(ctx context.Context, expiredOnly bool) error {
	record, err := readManagedChangeRecord()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if record.Status == "complete" || record.Status == "rolled_back" {
		return cleanupManagedChange()
	}
	if expiredOnly && managedChangeNow().UTC().Before(record.Deadline) {
		return nil
	}
	if record.Generation == 0 {
		return rollbackKnownManagedChange(ctx, &record)
	}
	response, err := managedAPICall(ctx, managedControlSock, api.Request{
		Op: "generation", Generation: record.Generation,
	})
	if err != nil {
		return fmt.Errorf("MANAGED_RECOVERY_GENERATION_STATUS_UNAVAILABLE: %w", err)
	}
	encoded, err := json.Marshal(response.Data)
	if err != nil {
		return errors.New("MANAGED_RECOVERY_GENERATION_STATUS_INVALID")
	}
	var generation state.Generation
	if json.Unmarshal(encoded, &generation) != nil || generation.ID != record.Generation {
		return errors.New("MANAGED_RECOVERY_GENERATION_STATUS_INVALID")
	}
	switch generation.Status {
	case "committed":
		if err := verifyManagedChangeFiles(record, true); err != nil {
			return err
		}
		record.Status = "complete"
		record.Phase = "complete"
		record.UpdatedAt = managedChangeNow().UTC()
		if err := writeManagedChangeRecord(record); err != nil {
			return err
		}
		return cleanupManagedChange()
	case "pending", "applied", "commit_prepared", "rolled_back":
		return rollbackKnownManagedChange(ctx, &record)
	default:
		return fmt.Errorf("MANAGED_RECOVERY_GENERATION_STATUS_UNSUPPORTED: %s", generation.Status)
	}
}

func restoreManagedChangeFiles(record managedChangeRecord) error {
	oldIntent, err := readProtectedFile(managedChangeOldIntent, 1<<20)
	if err != nil || managedDigest(oldIntent) != record.OldIntentSHA256 {
		return errors.New("MANAGED_RECOVERY_INTENT_BACKUP_INVALID")
	}
	oldConfig, err := readProtectedFile(managedChangeOldConfig, 4<<20)
	if err != nil || managedDigest(oldConfig) != record.OldConfigSHA256 {
		return errors.New("MANAGED_RECOVERY_CONFIG_BACKUP_INVALID")
	}
	if err := managedsetup.WriteAtomicFile(managedIntentPath, oldIntent, 0o640); err != nil {
		return errors.New("MANAGED_RECOVERY_INTENT_RESTORE_FAILED")
	}
	if err := managedsetup.WriteAtomicFile(managedConfigPath, oldConfig, 0o640); err != nil {
		return errors.New("MANAGED_RECOVERY_CONFIG_RESTORE_FAILED")
	}
	return verifyManagedChangeFiles(record, false)
}

func verifyManagedChangeFiles(record managedChangeRecord, committed bool) error {
	intentData, err := readProtectedFile(managedIntentPath, 1<<20)
	if err != nil {
		return errors.New("MANAGED_RECOVERY_INTENT_VERIFY_FAILED")
	}
	configData, err := readProtectedFile(managedConfigPath, 4<<20)
	if err != nil {
		return errors.New("MANAGED_RECOVERY_CONFIG_VERIFY_FAILED")
	}
	wantIntent, wantConfig := record.OldIntentSHA256, record.OldConfigSHA256
	if committed {
		wantIntent, wantConfig = record.NewIntentSHA256, record.NewConfigSHA256
	}
	if managedDigest(intentData) != wantIntent || managedDigest(configData) != wantConfig {
		return errors.New("MANAGED_RECOVERY_FILE_IDENTITY_MISMATCH")
	}
	return nil
}

func ensureManagedChangeDirectory() error {
	if err := os.MkdirAll(managedChangeDir, 0o700); err != nil {
		return errors.New("MANAGED_CHANGE_DIRECTORY_FAILED")
	}
	if err := os.Chmod(managedChangeDir, 0o700); err != nil {
		return errors.New("MANAGED_CHANGE_DIRECTORY_FAILED")
	}
	resolved, err := filepath.EvalSymlinks(managedChangeDir)
	if err != nil || resolved != managedChangeDir {
		return errors.New("MANAGED_CHANGE_DIRECTORY_UNSAFE")
	}
	info, err := os.Stat(managedChangeDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("MANAGED_CHANGE_DIRECTORY_UNSAFE")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("MANAGED_CHANGE_DIRECTORY_UNSAFE")
	}
	return nil
}

func readManagedChangeRecord() (managedChangeRecord, error) {
	data, err := readProtectedFile(managedChangeJournal, 1<<20)
	if err != nil {
		return managedChangeRecord{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record managedChangeRecord
	if decoder.Decode(&record) != nil {
		return managedChangeRecord{}, errors.New("MANAGED_CHANGE_JOURNAL_INVALID")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return managedChangeRecord{}, errors.New("MANAGED_CHANGE_JOURNAL_INVALID")
	}
	if record.Schema != managedChangeJournalSchema || record.Status == "" ||
		record.Phase == "" || record.Action == "" || record.StartedAt.IsZero() ||
		record.UpdatedAt.IsZero() || record.Deadline.IsZero() ||
		record.UpdatedAt.Before(record.StartedAt) ||
		!record.Deadline.After(record.StartedAt) ||
		!validManagedDigest(record.OldIntentSHA256) ||
		!validManagedDigest(record.OldConfigSHA256) ||
		!validManagedDigest(record.NewIntentSHA256) ||
		!validManagedDigest(record.NewConfigSHA256) ||
		!validManagedChangeState(record.Status, record.Phase) {
		return managedChangeRecord{}, errors.New("MANAGED_CHANGE_JOURNAL_INVALID")
	}
	return record, nil
}

func validManagedChangeState(status, phase string) bool {
	switch status {
	case "running":
		return phase == "prepared" || phase == "files_published" || phase == "applied"
	case "complete":
		return phase == "complete"
	case "rolled_back":
		return phase == "rolled_back"
	default:
		return false
	}
}

func writeManagedChangeRecord(record managedChangeRecord) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return errors.New("MANAGED_CHANGE_JOURNAL_ENCODE_FAILED")
	}
	data = append(data, '\n')
	if err := managedsetup.WriteAtomicFile(managedChangeJournal, data, 0o600); err != nil {
		return errors.New("MANAGED_CHANGE_JOURNAL_WRITE_FAILED")
	}
	return nil
}

func cleanupManagedChange() error {
	for _, path := range []string{
		managedChangeOldIntent, managedChangeOldConfig, managedChangeJournal,
	} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("MANAGED_CHANGE_CLEANUP_FAILED")
		}
	}
	if err := os.Remove(managedChangeDir); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return errors.New("MANAGED_CHANGE_CLEANUP_FAILED")
	}
	return nil
}

func managedDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validManagedDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == string(bytes.ToLower([]byte(value)))
}
