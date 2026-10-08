package simnumber

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type runner func(context.Context, string, ...string) (string, error)

func run(ctx context.Context, command string, args ...string) (string, error) {
	query, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	b, err := exec.CommandContext(query, command, args...).Output()
	if err != nil || len(b) > 8192 {
		return "", errors.New("subscriber number query unavailable")
	}
	return string(b), nil
}

func field(output, key string) string {
	for _, line := range strings.Split(output, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func currentICCID(ctx context.Context, query runner) (string, error) {
	if _, err := query(ctx, "systemctl", "is-active", "--quiet", "ModemManager.service"); err != nil {
		return "", err
	}
	modem, err := query(ctx, "mmcli", "-m", "any", "-K")
	if err != nil {
		return "", err
	}
	state := field(modem, "modem.generic.state")
	if state != "registered" && state != "connected" && state != "enabled" {
		return "", errors.New("SIM not ready")
	}
	path := field(modem, "modem.generic.sim")
	const prefix = "/org/freedesktop/ModemManager1/SIM/"
	if !strings.HasPrefix(path, prefix) {
		return "", errors.New("SIM unavailable")
	}
	if _, err := strconv.ParseUint(strings.TrimPrefix(path, prefix), 10, 32); err != nil {
		return "", errors.New("invalid SIM path")
	}
	sim, err := query(ctx, "mmcli", "-i", path, "-K")
	if err != nil {
		return "", err
	}
	iccid := field(sim, "sim.properties.iccid")
	if len(iccid) < 10 || len(iccid) > 32 {
		return "", errors.New("SIM identity unavailable")
	}
	for _, c := range iccid {
		if c < '0' || c > '9' {
			return "", errors.New("invalid SIM identity")
		}
	}
	return iccid, nil
}

func queryNumber(ctx context.Context, query runner) (string, error) {
	// Read the active USIM application first, then the legacy SIM directory.
	// Only EF_MSISDN is allowed. No SELECT/provisioning/PIN/write operation.
	for _, path := range []string{"0x3f00,0x7fff,0x6f40", "0x3f00,0x7f10,0x6f40"} {
		attrs, err := query(ctx, "qmicli", "-p", "-d", "/dev/wwan0qmi0", "--uim-get-file-attributes="+path)
		if err != nil {
			continue
		}
		if field(attrs, "File type") != "linear-fixed" || field(attrs, "File ID") != "28480" {
			continue
		}
		size, err := strconv.Atoi(field(attrs, "Record size"))
		if err != nil || size < 14 || size > 255 {
			continue
		}
		count, err := strconv.Atoi(field(attrs, "Record count"))
		if err != nil || count < 1 || count > 10 {
			continue
		}
		for index := 1; index <= count; index++ {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			args := "file=" + strings.ReplaceAll(path, ",", "-") + ",record-number=" + strconv.Itoa(index) + ",record-length=" + strconv.Itoa(size)
			output, err := query(ctx, "qmicli", "-p", "-d", "/dev/wwan0qmi0", "--uim-read-record="+args)
			if err != nil {
				continue
			}
			record, err := parseRecordOutput(output)
			if err != nil || len(record) != size {
				continue
			}
			number, err := DecodeRecord(record)
			if err == nil && number != "" {
				return number, nil
			}
		}
	}
	return "", errors.New("SIM subscriber number unavailable")
}

// Refresh is called only by the root oneshot service. Error logs never include
// SIM content. Its cache resides on tmpfs and is readable only by the Agent group.
func Refresh(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("subscriber number probe requires root")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	entry, err := sample(ctx, run, CachePath, time.Now())
	if err != nil {
		entry = cacheEntry{}
	}
	return writeCache(CachePath, entry)
}

func sample(ctx context.Context, query runner, path string, now time.Time) (cacheEntry, error) {
	iccid, err := currentICCID(ctx, query)
	if err != nil {
		return cacheEntry{}, err
	}
	old, err := readCache(path, now)
	if err == nil && old.ICCID == iccid && ValidNumber(old.Number) && now.Sub(old.QueriedAt) >= 0 && now.Sub(old.QueriedAt) < 30*time.Minute {
		return old, nil
	}
	// Keep modem queries out of an ongoing call. Missing/stale data stays unknown.
	calls, err := query(ctx, "mmcli", "-m", "any", "--voice-list-calls")
	if err != nil {
		return cacheEntry{}, err
	}
	for _, phase := range []string{"dialing", "ringing", "active", "held", "waiting"} {
		if strings.Contains(calls, "("+phase) {
			return cacheEntry{}, errors.New("number probe deferred during call")
		}
	}
	number, err := queryNumber(ctx, query)
	if err != nil {
		return cacheEntry{}, err
	}
	after, err := currentICCID(ctx, query)
	if err != nil || after != iccid {
		return cacheEntry{}, errors.New("SIM changed during number read")
	}
	return cacheEntry{ICCID: iccid, Number: number, QueriedAt: now}, nil
}
