package systemstats

import "time"

// Source is everything the collector may ask the operating system.
//
// It exists for two reasons. Every read is bounded by the caller, so a file
// that is unexpectedly large - or a /proc with thousands of entries - costs a
// fixed amount on a device with 512 MB of memory. And the collector itself
// then contains no operating-system call, so it is tested against fixture text
// on any host and a platform without procfs simply has no Source.
type Source interface {
	// ReadFile returns at most limit bytes of the file.
	ReadFile(name string, limit int) ([]byte, error)
	// ReadDir returns at most limit entry names, in directory order.
	ReadDir(name string, limit int) ([]string, error)
	Statfs(path string) (FSStat, error)
	ModTime(name string) (time.Time, error)
}

// FSStat is the part of statfs(2) the collector uses, in blocks.
type FSStat struct {
	BlockSize uint64
	Blocks    uint64
	Free      uint64
	Available uint64
}
