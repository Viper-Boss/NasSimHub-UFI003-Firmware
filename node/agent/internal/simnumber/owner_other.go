//go:build !linux

package simnumber

import "os"

func rootOwned(os.FileInfo) bool { return false }
