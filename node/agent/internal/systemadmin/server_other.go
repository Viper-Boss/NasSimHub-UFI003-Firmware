//go:build !linux

package systemadmin

import "errors"

func Serve() error { return errors.New("system administration requires Linux") }
