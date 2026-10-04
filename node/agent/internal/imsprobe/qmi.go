// Package imsprobe performs only the QMI IMS registration status query.
package imsprobe

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"
)

func Query(ctx context.Context) (string, error) {
	// A narrowly scoped root service performs the read-only QMI query. The
	// unprivileged Agent reads its fresh result without opening the modem.
	if _, err := os.Lstat("/run/nassimhub-ims/registration"); !errors.Is(err, os.ErrNotExist) {
		return readCache("/run/nassimhub-ims/registration", time.Now())
	}
	query, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(query, "qmicli", "-p", "-d", "/dev/wwan0qmi0", "--imsa-get-ims-registration-status").Output()
	if err != nil {
		return "", err
	}
	services, err := exec.CommandContext(query, "qmicli", "-p", "-d", "/dev/wwan0qmi0", "--imsa-get-ims-services-status").Output()
	if err != nil {
		return "", err
	}
	out = append(append(out, '\n'), services...)
	if len(out) > 2048 {
		return "", errors.New("IMS status response exceeds limit")
	}
	return string(out), nil
}

func readCache(path string, now time.Time) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	link, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !link.Mode().IsRegular() || !os.SameFile(link, info) || !rootOwned(info) || info.Mode().Perm()&0022 != 0 {
		return "", errors.New("IMS cache is not a protected root-owned regular file")
	}
	age := now.Sub(info.ModTime())
	if age < -time.Second || age > 30*time.Second {
		return "", errors.New("IMS cache is stale")
	}
	out, err := io.ReadAll(io.LimitReader(f, 2049))
	if err != nil {
		return "", err
	}
	if len(out) > 2048 {
		return "", errors.New("IMS cache exceeds limit")
	}
	return string(out), nil
}
