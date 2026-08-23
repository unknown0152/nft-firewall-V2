package reconcile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReconcileControllerLockWaitHonorsContext(t *testing.T) {
	m, store, runner := newManager(t)
	defer store.Close()

	lockPath := filepath.Join(store.Dir, ".controller.lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("hold controller lock: %v", err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = m.Reconcile(ctx, false)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "wait for controller lock") {
		t.Fatalf("controller lock wait did not return the context error: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("controller lock cancellation took too long: %v", elapsed)
	}
	if runner.ownedListCalls != 0 || runner.tableListCalls != 0 || runner.applyCalls != 0 {
		t.Fatalf("canceled reconcile reached nftables: owned=%d tables=%d apply=%d", runner.ownedListCalls, runner.tableListCalls, runner.applyCalls)
	}
}

func TestAcquireProcessLockRejectsCanceledContextBeforeAcquisition(t *testing.T) {
	m, store, _ := newManager(t)
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	release, err := m.acquireProcessLock(ctx)
	if release != nil {
		release()
		t.Fatal("canceled lock acquisition returned a release function")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lock acquisition returned %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(store.Dir, ".controller.lock")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("canceled acquisition touched the lock path: %v", statErr)
	}
}

func TestGenerationByIDHonorsCanceledContext(t *testing.T) {
	_, store, _ := newManager(t)
	defer store.Close()
	item := artifact(1)
	if err := store.SaveGeneration(context.Background(), item.Generation, item.Checksum, item.Script, nil, nil); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := generationByID(ctx, store, item.Generation); !errors.Is(err, context.Canceled) {
		t.Fatalf("generation query ignored cancellation: %v", err)
	}
}
