//go:build !unix

package ota

import (
	"errors"
	"os"
)

// On a platform with no installer these are never reached with a real
// installation; they exist so the package builds everywhere the protocol does.

func freeBytes(string) (uint64, error) { return 0, errors.New("free space is not measurable here") }

func lockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
}

func execReplace(string, []string, []string) error {
	return errors.New("replacing the running process is not supported on this platform")
}
