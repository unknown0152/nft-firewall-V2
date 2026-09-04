package setup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/unknown0152/nft-firewall-v2/internal/discovery"
	"github.com/unknown0152/nft-firewall-v2/internal/netgate"
	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
	"github.com/unknown0152/nft-firewall-v2/internal/routing"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/wireguard"
)

const maxRetiredSetupEntries = 1024

type retiredFirstSetup struct {
	PriorJournalSHA256 string
	LatestGeneration   uint64
	Provenance         []provenance.Assignment
	Summary            Summary
}

// inspectRetiredFirstSetup is the sole exception to clean-host refusal. It is
// deliberately all-or-nothing: callers expose only the established adoption
// refusal when any predicate below is absent, malformed, racing, or unsafe.
func inspectRetiredFirstSetup(
	ctx context.Context, runner routing.Runner, paths Paths, snapshot discovery.Snapshot,
) (retiredFirstSetup, error) {
	if !snapshot.ExistingNFTFWState || snapshot.OwnedNFTables || snapshot.ForeignNFTables ||
		len(snapshot.CompetingFirewallUnits) != 0 {
		return retiredFirstSetup{}, errors.New("retired setup firewall state is ambiguous")
	}
	if _, err := os.Lstat(filepath.Join(paths.StateDir, "enforcement-enabled")); !errors.Is(err, os.ErrNotExist) {
		return retiredFirstSetup{}, errors.New("retired setup enforcement pointer is present or unreadable")
	}
	journalPath := filepath.Join(paths.StateDir, "setup", "journal.json")
	current, currentRaw, currentSHA, err := readJournalFile(journalPath)
	if err != nil || !terminalRolledBackJournal(current) ||
		current.Summary.Schema != "nftfw.setup-plan.v1" ||
		netgate.ValidateUnits(current.Summary.NetworkProducers) != nil {
		return retiredFirstSetup{}, errors.New("retired setup journal is not terminal")
	}
	journals, err := readTerminalJournalLineage(
		filepath.Dir(journalPath), current, currentRaw, currentSHA,
	)
	if err != nil {
		return retiredFirstSetup{}, err
	}

	backupSeen := false
	backupPaths := map[string]bool{}
	for _, journal := range journals {
		if !reflect.DeepEqual(journal.Summary, current.Summary) {
			return retiredFirstSetup{}, errors.New("retired setup summaries disagree")
		}
		if journal.BackupDir == "" {
			if journal.Generation != 0 {
				return retiredFirstSetup{}, errors.New("retired generation has no protected backup")
			}
			continue
		}
		if err := validateRetiredBackupPath(paths.StateDir, journal.BackupDir); err != nil {
			return retiredFirstSetup{}, err
		}
		if backupPaths[journal.BackupDir] {
			return retiredFirstSetup{}, errors.New("retired setup backup lineage is ambiguous")
		}
		backupPaths[journal.BackupDir] = true
		manifest, err := verifyRestoredBackup(ctx, runner, journal.BackupDir)
		if err != nil || !backupMatchesRetiredPlan(paths, journal.Summary, manifest) {
			return retiredFirstSetup{}, errors.New("retired setup backup does not prove exact restoration")
		}
		backupSeen = true
	}

	result := retiredFirstSetup{PriorJournalSHA256: currentSHA, Summary: current.Summary}
	database := filepath.Join(paths.StateDir, "generation-state", "state.db")
	ledgerPath := filepath.Join(paths.StateDir, "provenance-ledger.db")
	databaseExists, err := regularPathExists(database)
	if err != nil {
		return retiredFirstSetup{}, err
	}
	ledgerExists, err := regularPathExists(ledgerPath)
	if err != nil {
		return retiredFirstSetup{}, err
	}
	if databaseExists != ledgerExists {
		return retiredFirstSetup{}, errors.New("retired setup database and ledger are incomplete")
	}
	if !databaseExists {
		if hasGenerationJournal(journals) || retainedGenerationArtifacts(paths.StateDir) {
			return retiredFirstSetup{}, errors.New("retired setup generation evidence is incomplete")
		}
		return result, nil
	}
	if !backupSeen {
		return retiredFirstSetup{}, errors.New("retired setup has no verified backup")
	}

	store, err := state.OpenReadOnly(ctx, database)
	if err != nil {
		return retiredFirstSetup{}, err
	}
	defer store.Close()
	generationIDs, err := retiredGenerationIDs(ctx, store)
	if err != nil || len(generationIDs) == 0 {
		return retiredFirstSetup{}, errors.New("retired setup generation history is invalid")
	}
	for index, id := range generationIDs {
		if id != uint64(index+1) {
			return retiredFirstSetup{}, errors.New("retired setup generation history is not monotonic")
		}
	}
	if current.Generation != generationIDs[len(generationIDs)-1] {
		return retiredFirstSetup{}, errors.New("retired setup current journal is not the latest generation")
	}
	if err := verifyRetiredGenerationInventory(paths.StateDir, generationIDs); err != nil {
		return retiredFirstSetup{}, err
	}
	journalGenerations := map[uint64]bool{}
	for _, journal := range journals {
		if journal.Generation != 0 {
			if journalGenerations[journal.Generation] {
				return retiredFirstSetup{}, errors.New("retired setup journal generation is ambiguous")
			}
			journalGenerations[journal.Generation] = true
		}
	}
	var required []provenance.Assignment
	for _, id := range generationIDs {
		if !journalGenerations[id] {
			return retiredFirstSetup{}, errors.New("retired generation has no terminal journal")
		}
		generation, err := store.Generation(ctx, id)
		if err != nil || generation.Status != "rolled_back" || generation.PreviousID != nil ||
			generation.PreparedAt != nil || generation.PreparedPriorID != nil ||
			generation.PreparedPriorSum != "" || generation.PreparedPriorSnapshotSum != "" {
			return retiredFirstSetup{}, errors.New("retired generation is not a first-setup rollback")
		}
		script, err := store.ReadScript(generation)
		if err != nil {
			return retiredFirstSetup{}, err
		}
		expectedScript := filepath.Join(paths.StateDir, "generations", fmt.Sprintf("%020d.nft", id))
		expectedSnapshot := filepath.Join(paths.StateDir, "generations", fmt.Sprintf("%020d.snapshot.json", id))
		if generation.ScriptPath != expectedScript || generation.SnapshotPath != expectedSnapshot {
			return retiredFirstSetup{}, errors.New("retired generation snapshot path is invalid")
		}
		snapshotDigest, err := digestRetainedFile(expectedSnapshot, 32<<20)
		if err != nil || snapshotDigest != generation.SnapshotChecksum {
			return retiredFirstSetup{}, errors.New("retired immutable generation checksum is invalid")
		}
		generationSnapshot, err := state.LoadVerifiedGenerationSnapshot(paths.StateDir, id)
		if err != nil || generationSnapshot.Generation != id || generationSnapshot.Script != script ||
			generationSnapshot.Checksum != generation.Checksum || generationSnapshot.Previous != nil ||
			generationSnapshot.BootID != generation.BootID ||
			generationSnapshot.Pointer().SnapshotChecksum != generation.SnapshotChecksum {
			return retiredFirstSetup{}, errors.New("retired immutable generation evidence is invalid")
		}
		if required == nil {
			required = append([]provenance.Assignment(nil), generationSnapshot.Provenance...)
		} else if !sameProvenanceIdentity(required, generationSnapshot.Provenance) {
			return retiredFirstSetup{}, errors.New("retired generation provenance changed")
		}
		result.LatestGeneration = id
	}
	if len(journalGenerations) != len(generationIDs) {
		return retiredFirstSetup{}, errors.New("retired journal references an unknown generation")
	}
	ledger, err := provenance.OpenReadOnly(ctx, ledgerPath)
	if err != nil {
		return retiredFirstSetup{}, err
	}
	defer ledger.Close()
	if err := ledger.QuickCheck(ctx); err != nil {
		return retiredFirstSetup{}, err
	}
	assignments, err := ledger.Assignments(ctx)
	if err != nil || !sameProvenanceIdentity(required, assignments) {
		return retiredFirstSetup{}, errors.New("retired monotonic provenance ledger is ambiguous")
	}
	for _, assignment := range assignments {
		if assignment.Retired {
			return retiredFirstSetup{}, errors.New("retired monotonic provenance ledger contains tombstones")
		}
	}
	cache := filepath.Join(paths.StateDir, "wg-endpoints.json")
	if exists, err := regularPathExists(cache); err != nil {
		return retiredFirstSetup{}, err
	} else if exists {
		if _, err := wireguard.ValidateRetainedCache(cache); err != nil {
			return retiredFirstSetup{}, err
		}
	}
	result.Provenance = required
	return result, nil
}

func verifyRetiredGenerationInventory(stateDir string, generationIDs []uint64) error {
	directory := filepath.Join(stateDir, "generations")
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("retired generation directory is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("retired generation directory is unsafe")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return errors.New("retired generation directory is unsafe")
	}
	expected := make(map[string]bool, len(generationIDs)*2)
	for _, id := range generationIDs {
		expected[fmt.Sprintf("%020d.nft", id)] = true
		expected[fmt.Sprintf("%020d.snapshot.json", id)] = true
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(expected) {
		return errors.New("retired generation inventory is ambiguous")
	}
	for _, entry := range entries {
		if !expected[entry.Name()] || !entry.Type().IsRegular() {
			return errors.New("retired generation inventory is ambiguous")
		}
	}
	return nil
}

func readTerminalJournalLineage(
	parent string, current Journal, currentRaw []byte, currentSHA string,
) ([]Journal, error) {
	result := []Journal{current}
	seenTransactions := map[string]bool{current.Transaction: true}
	history := filepath.Join(parent, "history")
	info, err := os.Lstat(history)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("retired setup journal history is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return nil, errors.New("retired setup journal history is unsafe")
	}
	resolved, err := filepath.EvalSymlinks(history)
	if err != nil || resolved != history {
		return nil, errors.New("retired setup journal history is unsafe")
	}
	entries, err := os.ReadDir(history)
	if err != nil || len(entries) > maxRetiredSetupEntries {
		return nil, errors.New("retired setup journal history is unreadable")
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, errors.New("retired setup journal history is ambiguous")
		}
		path := filepath.Join(history, entry.Name())
		journal, raw, digest, err := readJournalFile(path)
		if err != nil || !terminalRolledBackJournal(journal) ||
			entry.Name() != journal.Transaction+"."+digest+".json" {
			return nil, errors.New("retired setup journal history is invalid")
		}
		if journal.Transaction == current.Transaction {
			// A crash may occur after the old terminal journal is durably
			// archived but before the new current journal is published. Accept
			// only that exact byte/checksum-identical archive as idempotent
			// lineage residue; every changed duplicate remains ambiguous.
			if digest != currentSHA || !bytes.Equal(raw, currentRaw) {
				return nil, errors.New("retired setup journal history is invalid")
			}
			continue
		}
		if seenTransactions[journal.Transaction] {
			return nil, errors.New("retired setup journal history is invalid")
		}
		seenTransactions[journal.Transaction] = true
		result = append(result, journal)
	}
	return result, nil
}

func validateRetiredBackupPath(stateDir, backup string) error {
	root := filepath.Join(stateDir, "setup", "backups")
	if !filepath.IsAbs(backup) || filepath.Clean(backup) != backup ||
		filepath.Dir(backup) != root || filepath.Base(backup) == "." {
		return errors.New("retired setup backup path is invalid")
	}
	return nil
}

func backupMatchesRetiredPlan(paths Paths, summary Summary, manifest backupManifest) bool {
	if netgate.ValidateUnits(summary.NetworkProducers) != nil {
		return false
	}
	expectedFiles := (&System{Paths: paths}).touchedFiles(Plan{Summary: summary})
	if len(manifest.Files) != len(expectedFiles) {
		return false
	}
	for index, path := range expectedFiles {
		if manifest.Files[index].Path != path {
			return false
		}
	}
	expectedUnits := managedUnits(summary.DockerMode == "enabled")
	for _, unit := range expectedUnits {
		unitState, ok := manifest.Units[unit]
		if !ok || strings.HasPrefix(unit, "nftfw-") && unitState.Active {
			return false
		}
	}
	_, socketPresent := manifest.Units["docker.socket"]
	if len(manifest.Units) != len(expectedUnits) &&
		!(summary.DockerMode == "enabled" && len(manifest.Units) == len(expectedUnits)+1 && socketPresent) {
		return false
	}
	for unit := range manifest.Units {
		if unit == "docker.socket" && summary.DockerMode == "enabled" {
			continue
		}
		if !slices.Contains(expectedUnits, unit) {
			return false
		}
	}
	expectedSysctls := managedSysctls(summary.IPv6Interfaces, summary.DockerMode == "enabled")
	if len(manifest.Sysctls) != len(expectedSysctls) {
		return false
	}
	for _, key := range expectedSysctls {
		if _, ok := manifest.Sysctls[key]; !ok {
			return false
		}
	}
	return true
}

func retiredGenerationIDs(ctx context.Context, store *state.Store) ([]uint64, error) {
	rows, err := store.DB.QueryContext(ctx, "SELECT id FROM generations ORDER BY id LIMIT ?", maxRetiredSetupEntries+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []uint64
	for rows.Next() {
		var id uint64
		if rows.Scan(&id) != nil || id == 0 {
			return nil, errors.New("retired generation id is invalid")
		}
		result = append(result, id)
	}
	if err := rows.Err(); err != nil || len(result) > maxRetiredSetupEntries {
		return nil, errors.New("retired generation history is too large or unreadable")
	}
	return result, nil
}

func regularPathExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return false, errors.New("retained state path is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return false, errors.New("retained state path is unsafe")
	}
	return true, nil
}

func digestRetainedFile(path string, limit int64) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", errors.New("retained immutable file is unreadable")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 ||
		before.Size() <= 0 || before.Size() > limit {
		return "", errors.New("retained immutable file is unsafe")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return "", errors.New("retained immutable file is unsafe")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil || written != before.Size() || written > limit {
		return "", errors.New("retained immutable file is unreadable")
	}
	after, err := file.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return "", errors.New("retained immutable file changed while being read")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func retainedGenerationArtifacts(stateDir string) bool {
	for _, path := range []string{
		filepath.Join(stateDir, "generation-state"),
		filepath.Join(stateDir, "generations"),
		filepath.Join(stateDir, "provenance-ledger.db"),
		filepath.Join(stateDir, "wg-endpoints.json"),
	} {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	return false
}

func hasGenerationJournal(journals []Journal) bool {
	for _, journal := range journals {
		if journal.Generation != 0 {
			return true
		}
	}
	return false
}

func sameProvenanceIdentity(left, right []provenance.Assignment) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]provenance.Assignment(nil), left...)
	right = append([]provenance.Assignment(nil), right...)
	sort.Slice(left, func(i, j int) bool { return left[i].ID < left[j].ID })
	sort.Slice(right, func(i, j int) bool { return right[i].ID < right[j].ID })
	for index := range left {
		if left[index].Name != right[index].Name || left[index].ID != right[index].ID ||
			left[index].Retired != right[index].Retired {
			return false
		}
	}
	return true
}

func retiredSetupRefusal(_ error) error {
	return errors.New("DISCOVERY_EXISTING_NFTFW_REQUIRES_ADOPT")
}
