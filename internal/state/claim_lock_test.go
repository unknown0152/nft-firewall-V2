package state

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClaimPublicationLockHonorsContextAndRejectsSymlink(t *testing.T) {
	directory := secureTestDir(t)
	lockPath := filepath.Join(directory, "mutation.lock")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if release, err := AcquireClaimPublicationLock(canceled, directory); release != nil || !errors.Is(err, context.Canceled) {
		if release != nil {
			release()
		}
		t.Fatalf("pre-canceled lock acquisition returned release=%t err=%v", release != nil, err)
	}
	if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pre-canceled lock acquisition touched the lock path: %v", err)
	}
	if err := os.Symlink(filepath.Join(directory, "target"), lockPath); err != nil {
		t.Fatal(err)
	}
	if release, err := AcquireClaimPublicationLock(context.Background(), directory); release != nil || err == nil || !strings.Contains(err.Error(), "not a regular file") {
		if release != nil {
			release()
		}
		t.Fatalf("symlinked lock was accepted: release=%t err=%v", release != nil, err)
	}
}

func TestClaimPublicationLockSerializesIndependentHandles(t *testing.T) {
	directory := secureTestDir(t)
	releaseFirst, err := AcquireClaimPublicationLock(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseFirst()
	waitCtx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	releaseSecond, err := AcquireClaimPublicationLock(waitCtx, directory)
	if releaseSecond != nil {
		releaseSecond()
		t.Fatal("contended lock returned a release function")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended lock ignored context deadline: %v", err)
	}
}
