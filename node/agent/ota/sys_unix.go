//go:build unix

package ota

import (
	"errors"
	"os"
	"syscall"
)

// freeBytes reports the space available to an unprivileged writer in dir.
func freeBytes(dir string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return 0, err
	}
	return uint64(stat.Bavail) * uint64(stat.Bsize), nil
}

// lockFile takes an exclusive, non-blocking advisory lock. The lock is held
// for as long as the returned file stays open, and the kernel releases it when
// the process exits, however it exits.
func lockFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errLockHeld
		}
		return nil, err
	}
	return file, nil
}

// execReplace replaces this process with another program.
func execReplace(path string, arguments, environment []string) error {
	return syscall.Exec(path, arguments, environment)
}
