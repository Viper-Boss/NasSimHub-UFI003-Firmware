package simnumber

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureRecord() []byte {
	b := bytes.Repeat([]byte{0xff}, 28)
	tail := b[14:]
	tail[0] = 8
	tail[1] = 0x91
	copy(tail[2:], []byte{0x68, 0x31, 0x08, 0x10, 0x83, 0x00, 0xf0})
	return b
}

func TestDecodeMSISDN(t *testing.T) {
	valid := fixtureRecord()
	for _, tc := range []struct {
		name   string
		record []byte
		want   string
		fail   bool
	}{
		{"international", valid, "+8613800138000", false},
		{"empty", bytes.Repeat([]byte{0xff}, 28), "", false},
		{"short", []byte{1}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeRecord(tc.record)
			if got != tc.want || (err != nil) != tc.fail {
				t.Fatalf("decode result mismatch: present=%v error=%v", got != "", err)
			}
		})
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[14] = 12 }, func(b []byte) { b[15] = 0x81; b[16] = 0xfa; b[17] = 0x12 },
		func(b []byte) { b[27] = 1 }, func(b []byte) { b[15] = 0x90 }, func(b []byte) {
			for i := 16; i <= 22; i++ {
				b[i] = 0
			}
		},
	} {
		b := append([]byte(nil), valid...)
		mutate(b)
		if _, err := DecodeRecord(b); err == nil {
			t.Fatal("malformed record accepted")
		}
	}
	for _, text := range []string{"Read result: XX", "Read result: " + strings.Repeat("FF:", 256), "no record"} {
		if _, err := parseRecordOutput(text); err == nil {
			t.Fatal("invalid read output accepted")
		}
	}
}

func TestUSIMReadIsBoundedAndNeverWrites(t *testing.T) {
	var commands []string
	query := func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		if strings.Contains(command, "--uim-get-file-attributes=0x3f00,0x7fff,0x6f40") {
			return "File ID: 28480\nFile type: linear-fixed\nRecord size: 28\nRecord count: 2", nil
		}
		if strings.Contains(command, "--uim-read-record=file=0x3f00-0x7fff-0x6f40,record-number=1,record-length=28") {
			return "Read result: " + hex.EncodeToString(fixtureRecord()), nil
		}
		return "", errors.New("unexpected query")
	}
	got, err := queryNumber(context.Background(), query)
	if err != nil || got != "+8613800138000" || len(commands) != 2 {
		t.Fatal("USIM fallback failed", err)
	}
	for _, command := range commands {
		if !strings.Contains(command, "--uim-get-file-attributes=") && !strings.Contains(command, "--uim-read-record=") {
			t.Fatal("unexpected modem command")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := queryNumber(ctx, query); err == nil {
		t.Fatal("canceled record read succeeded")
	}
}

func TestCacheRejectsUntrustedAndStaleFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	entry := cacheEntry{ICCID: "8900000000000000001", Number: "+8613800138000", QueriedAt: time.Now()}
	if err := writeCache(path, entry); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readCache(path, time.Now())
	if rootOwned(info) {
		if err != nil || got.ICCID != entry.ICCID || got.Number != entry.Number {
			t.Fatal("valid cache rejected", err)
		}
	} else if err == nil {
		t.Fatal("non-root cache accepted")
	}
	if _, err := readCache(path, time.Now().Add(2*time.Minute)); err == nil {
		t.Fatal("stale cache accepted")
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err == nil {
		if _, err := readCache(link, time.Now()); err == nil {
			t.Fatal("symlink accepted")
		}
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := readCache(path, time.Now()); err == nil {
		t.Fatal("writable cache accepted")
	}
}

func TestSIMSwapDuringReadDiscardsNumber(t *testing.T) {
	queries := 0
	query := func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		switch {
		case strings.HasPrefix(command, "systemctl "):
			return "", nil
		case strings.Contains(command, "--voice-list-calls"):
			return "No calls were found", nil
		case strings.Contains(command, "mmcli -m any -K"):
			return "modem.generic.state: registered\nmodem.generic.sim: /org/freedesktop/ModemManager1/SIM/0", nil
		case strings.Contains(command, "mmcli -i "):
			queries++
			if queries == 1 {
				return "sim.properties.iccid: 8900000000000000001", nil
			}
			return "sim.properties.iccid: 8900000000000000002", nil
		case strings.Contains(command, "--uim-get-file-attributes="):
			return "File ID: 28480\nFile type: linear-fixed\nRecord size: 28\nRecord count: 1", nil
		case strings.Contains(command, "--uim-read-record="):
			return "Read result: " + hex.EncodeToString(fixtureRecord()), nil
		}
		return "", errors.New("unexpected query")
	}
	entry, err := sample(context.Background(), query, filepath.Join(t.TempDir(), "missing"), time.Now())
	if err == nil || entry.Number != "" {
		t.Fatal("SIM swap exposed an old number")
	}
}
