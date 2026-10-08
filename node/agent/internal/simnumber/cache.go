package simnumber

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

const CachePath = "/run/nassimhub-sim-number/status.json"

type cacheEntry struct {
	ICCID     string    `json:"iccid"`
	Number    string    `json:"number"`
	QueriedAt time.Time `json:"queried_at"`
}

// Read only accepts a protected root-owned, fresh result for the SIM which
// ModemManager has just reported. The Agent never opens a raw modem port.
func Read(iccid string) (string, error) {
	entry, err := readCache(CachePath, time.Now())
	if err != nil {
		return "", err
	}
	if iccid == "" || entry.ICCID != iccid || !ValidNumber(entry.Number) {
		return "", errors.New("subscriber number unavailable for current SIM")
	}
	return entry.Number, nil
}

func readCache(path string, now time.Time) (cacheEntry, error) {
	var entry cacheEntry
	f, err := os.Open(path)
	if err != nil {
		return entry, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return entry, err
	}
	link, err := os.Lstat(path)
	if err != nil {
		return entry, err
	}
	if !link.Mode().IsRegular() || !os.SameFile(link, info) || !rootOwned(info) || info.Mode().Perm()&0022 != 0 {
		return entry, errors.New("untrusted subscriber number cache")
	}
	age := now.Sub(info.ModTime())
	if age < -time.Second || age > 90*time.Second {
		return entry, errors.New("stale subscriber number cache")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil || len(b) > 1024 {
		return entry, errors.New("invalid subscriber number cache")
	}
	if err = json.Unmarshal(b, &entry); err != nil {
		return cacheEntry{}, errors.New("invalid subscriber number cache")
	}
	return entry, nil
}

func writeCache(path string, entry cacheEntry) error {
	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".number-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0640); err == nil {
		_, err = f.Write(b)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
