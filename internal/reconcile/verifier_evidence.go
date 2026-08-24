package reconcile

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

type enforcementEvidence struct {
	databaseDigest string
	pointerDigest  string
	snapshotDigest string
	scriptDigest   string
	ledgerDigest   string
	pointer        state.EnforcementPointer
	generation     uint64
	observedHash   string
}

// captureEnforcementEvidence opens a fresh immutable view of the main state
// database and revalidates every durable input that authorizes the live
// firewall. It deliberately does not trust the verifier's earlier SQLite
// connection or an earlier filesystem read.
func captureEnforcementEvidence(ctx context.Context, original *state.Store) (enforcementEvidence, error) {
	if original == nil || original.Path == "" || original.Dir == "" {
		return enforcementEvidence{}, errors.New("read-only enforcement store is unavailable")
	}
	databaseBefore, err := digestSecureEvidenceFile(original.Path)
	if err != nil {
		return enforcementEvidence{}, fmt.Errorf("fingerprint state database main file: %w", err)
	}
	fresh, err := state.OpenReadOnly(ctx, original.Path)
	if err != nil {
		return enforcementEvidence{}, fmt.Errorf("reopen state database main file: %w", err)
	}
	defer fresh.Close()
	if fresh.Dir != original.Dir || fresh.Path != original.Path {
		return enforcementEvidence{}, errors.New("reopened state database resolved to a different path")
	}
	if pending, err := fresh.Pending(ctx); err == nil {
		return enforcementEvidence{}, fmt.Errorf("generation %d remains %s", pending.ID, pending.Status)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return enforcementEvidence{}, err
	}
	pointer, exists, err := state.ReadEnforcementPointer(fresh.Dir)
	if err != nil || !exists {
		if err != nil {
			return enforcementEvidence{}, err
		}
		return enforcementEvidence{}, errors.New("no committed enforcement pointer exists")
	}
	generation, err := fresh.Generation(ctx, pointer.Generation)
	if err != nil || generation.Status != "committed" || generation.Checksum != pointer.PolicyChecksum || generation.SnapshotChecksum != pointer.SnapshotChecksum {
		if err != nil {
			return enforcementEvidence{}, err
		}
		return enforcementEvidence{}, errors.New("enforcement pointer does not identify an exact committed generation")
	}
	latest, err := fresh.LastKnownGood(ctx)
	if err != nil || latest.ID != generation.ID {
		if err != nil {
			return enforcementEvidence{}, err
		}
		return enforcementEvidence{}, errors.New("enforcement pointer is not the latest committed generation")
	}
	snapshot, err := state.LoadVerifiedGenerationSnapshot(fresh.Dir, generation.ID)
	if err != nil || !snapshot.Pointer().Equal(pointer) {
		if err != nil {
			return enforcementEvidence{}, err
		}
		return enforcementEvidence{}, errors.New("enforcement pointer and immutable snapshot disagree")
	}
	manager := &Manager{Store: fresh}
	if err := manager.validateGenerationSnapshot(ctx, generation, snapshot, false); err != nil {
		return enforcementEvidence{}, err
	}
	script, err := fresh.ReadScript(generation)
	if err != nil {
		return enforcementEvidence{}, err
	}
	if script != snapshot.Script {
		return enforcementEvidence{}, errors.New("generation script and immutable snapshot disagree")
	}
	ledgerDigest, err := captureProvenanceLedgerEvidence(ctx, fresh.Dir, snapshot.Provenance)
	if err != nil {
		return enforcementEvidence{}, err
	}
	pointerDigest, err := digestSecureEvidenceFile(filepath.Join(fresh.Dir, "enforcement-enabled"))
	if err != nil {
		return enforcementEvidence{}, fmt.Errorf("fingerprint enforcement pointer: %w", err)
	}
	snapshotDigest, err := digestSecureEvidenceFile(generation.SnapshotPath)
	if err != nil {
		return enforcementEvidence{}, fmt.Errorf("fingerprint immutable generation snapshot: %w", err)
	}
	scriptDigest, err := digestSecureEvidenceFile(generation.ScriptPath)
	if err != nil {
		return enforcementEvidence{}, fmt.Errorf("fingerprint immutable generation script: %w", err)
	}
	databaseAfter, err := digestSecureEvidenceFile(original.Path)
	if err != nil {
		return enforcementEvidence{}, fmt.Errorf("re-fingerprint state database main file: %w", err)
	}
	if databaseAfter != databaseBefore {
		return enforcementEvidence{}, errors.New("state database main file changed while evidence was captured")
	}
	finalPointer, finalExists, err := state.ReadEnforcementPointer(fresh.Dir)
	if err != nil || !finalExists || !pointer.Equal(finalPointer) {
		if err != nil {
			return enforcementEvidence{}, err
		}
		return enforcementEvidence{}, errors.New("enforcement pointer changed while evidence was captured")
	}
	finalPointerDigest, err := digestSecureEvidenceFile(filepath.Join(fresh.Dir, "enforcement-enabled"))
	if err != nil {
		return enforcementEvidence{}, fmt.Errorf("re-fingerprint enforcement pointer: %w", err)
	}
	if finalPointerDigest != pointerDigest {
		return enforcementEvidence{}, errors.New("enforcement pointer bytes changed while evidence was captured")
	}
	finalSnapshot, err := state.LoadVerifiedGenerationSnapshot(fresh.Dir, generation.ID)
	if err != nil || !finalSnapshot.Pointer().Equal(pointer) {
		if err != nil {
			return enforcementEvidence{}, err
		}
		return enforcementEvidence{}, errors.New("immutable generation snapshot changed while evidence was captured")
	}
	if err := manager.validateGenerationSnapshot(ctx, generation, finalSnapshot, false); err != nil {
		return enforcementEvidence{}, err
	}
	finalScript, err := fresh.ReadScript(generation)
	if err != nil {
		return enforcementEvidence{}, err
	}
	if finalScript != finalSnapshot.Script {
		return enforcementEvidence{}, errors.New("generation script changed while evidence was captured")
	}
	finalSnapshotDigest, err := digestSecureEvidenceFile(generation.SnapshotPath)
	if err != nil {
		return enforcementEvidence{}, fmt.Errorf("re-fingerprint immutable generation snapshot: %w", err)
	}
	if finalSnapshotDigest != snapshotDigest {
		return enforcementEvidence{}, errors.New("immutable generation snapshot bytes changed while evidence was captured")
	}
	finalScriptDigest, err := digestSecureEvidenceFile(generation.ScriptPath)
	if err != nil {
		return enforcementEvidence{}, fmt.Errorf("re-fingerprint immutable generation script: %w", err)
	}
	if finalScriptDigest != scriptDigest {
		return enforcementEvidence{}, errors.New("immutable generation script bytes changed while evidence was captured")
	}
	finalLedgerDigest, err := captureProvenanceLedgerEvidence(ctx, fresh.Dir, finalSnapshot.Provenance)
	if err != nil {
		return enforcementEvidence{}, err
	}
	if finalLedgerDigest != ledgerDigest {
		return enforcementEvidence{}, errors.New("provenance ledger changed while evidence was captured")
	}
	return enforcementEvidence{
		databaseDigest: databaseBefore,
		pointerDigest:  pointerDigest,
		snapshotDigest: snapshotDigest,
		scriptDigest:   scriptDigest,
		ledgerDigest:   ledgerDigest,
		pointer:        *pointer,
		generation:     generation.ID,
		observedHash:   generation.ObservedHash,
	}, nil
}

func compareEnforcementEvidence(expected, observed enforcementEvidence) error {
	switch {
	case observed.databaseDigest != expected.databaseDigest:
		return errors.New("state database main file changed during verification")
	case observed.pointerDigest != expected.pointerDigest || !expected.pointer.Equal(&observed.pointer):
		return errors.New("enforcement pointer changed during verification")
	case observed.snapshotDigest != expected.snapshotDigest:
		return errors.New("immutable generation snapshot changed during verification")
	case observed.scriptDigest != expected.scriptDigest:
		return errors.New("immutable generation script changed during verification")
	case observed.ledgerDigest != expected.ledgerDigest:
		return errors.New("provenance ledger changed during verification")
	case observed.generation != expected.generation || observed.observedHash != expected.observedHash:
		return errors.New("committed generation identity changed during verification")
	default:
		return nil
	}
}

func captureProvenanceLedgerEvidence(ctx context.Context, root string, required []provenance.Assignment) (string, error) {
	path := filepath.Join(root, "provenance-ledger.db")
	ledger, err := provenance.OpenReadOnly(ctx, path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && len(required) == 0 {
			return "ABSENT", nil
		}
		return "", fmt.Errorf("open read-only provenance ledger evidence: %w", err)
	}
	defer ledger.Close()
	if err := ledger.ValidateRequired(ctx, required); err != nil {
		return "", fmt.Errorf("validate provenance ledger evidence: %w", err)
	}
	logicalDigest, err := ledger.Digest(ctx)
	if err != nil {
		return "", fmt.Errorf("digest provenance ledger assignments: %w", err)
	}
	fileDigest, err := digestSecureEvidenceFile(path)
	if err != nil {
		return "", fmt.Errorf("fingerprint provenance ledger file: %w", err)
	}
	return logicalDigest + ":" + fileDigest, nil
}

func digestSecureEvidenceFile(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil || abs != path || abs != filepath.Clean(path) {
		return "", errors.New("evidence path is not absolute and canonical")
	}
	parent := filepath.Dir(abs)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return "", errors.New("evidence directory is absent or contains a symlink")
	}
	file, err := os.OpenFile(abs, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 {
		return "", errors.New("evidence file has unsafe type or permissions")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return "", errors.New("evidence file has unsafe ownership")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	after, err := file.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return "", errors.New("evidence file changed while it was read")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
