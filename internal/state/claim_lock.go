package state

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type mutationLockContextKey struct{}

const DefaultMutationLockDir = "/run/nftfw"

func WithMutationLock(ctx context.Context) context.Context {
	return context.WithValue(ctx, mutationLockContextKey{}, true)
}

func MutationLockHeld(ctx context.Context) bool {
	held, _ := ctx.Value(mutationLockContextKey{}).(bool)
	return held
}

// AcquireMutationLock serializes every generation, pointer, ledger-adjacent,
// and durable-claim/kernel-set transition across daemon, CLI, early recovery,
// and rollback processes.
func AcquireMutationLock(ctx context.Context, runtimeDirectory string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("wait for cross-process mutation lock: %w", err)
	}
	directory, err := secureActiveDirectory(runtimeDirectory)
	if err != nil {
		return nil, fmt.Errorf("secure mutation lock directory: %w", err)
	}
	path := filepath.Join(directory, "mutation.lock")
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, errors.New("mutation lock path is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open mutation lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("mutation lock is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		_ = file.Close()
		return nil, errors.New("mutation lock has unsafe ownership")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	retry := time.NewTicker(10 * time.Millisecond)
	defer retry.Stop()
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
				return nil, fmt.Errorf("wait for cross-process mutation lock: %w", ctxErr)
			}
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("lock mutation state: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, fmt.Errorf("wait for cross-process mutation lock: %w", ctx.Err())
		case <-retry.C:
		}
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

// AcquireClaimPublicationLock is a compatibility name for the one global
// mutation lock. There is deliberately no separate claims lock in 2.0.2.
func AcquireClaimPublicationLock(ctx context.Context, runtimeDirectory string) (func(), error) {
	return AcquireMutationLock(ctx, runtimeDirectory)
}
