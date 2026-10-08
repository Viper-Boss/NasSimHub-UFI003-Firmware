//go:build linux

package systemstats

import (
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func platformSource() (Source, string) { return osSource{}, "" }

type osSource struct{}

func (osSource) ReadFile(name string, limit int) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, int64(limit)))
}

func (osSource) ReadDir(name string, limit int) ([]string, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(limit)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return names, err
}

func (osSource) Statfs(path string) (FSStat, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return FSStat{}, err
	}
	return FSStat{BlockSize: uint64(stat.Bsize), Blocks: uint64(stat.Blocks), Free: uint64(stat.Bfree), Available: uint64(stat.Bavail)}, nil
}

func (osSource) ModTime(name string) (time.Time, error) {
	info, err := os.Stat(name)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}
