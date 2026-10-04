//go:build !linux

package imsprobe

import "os"

func rootOwned(os.FileInfo) bool { return false }
