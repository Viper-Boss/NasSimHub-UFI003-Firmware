package logbuf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

func TestRedactionRemovesEverySensitiveShape(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{"phone international", "incoming call from +8610000000001", "8610000000001"},
		{"phone national", "dialing 10000000001 now", "10000000001"},
		{"iccid", "sim iccid 89860412345678901234 ready", "89860412345678901234"},
		{"imsi", "attached with imsi 460001234567890", "460001234567890"},
		{"bearer", "auth header Bearer aGVsbG8td29ybGQtdG9rZW4", "aGVsbG8td29ybGQtdG9rZW4"},
		{"wifi psk", `connecting ssid=home psk=SuperSecret123`, "SuperSecret123"},
		{"password kv", `login password: hunter2xyz`, "hunter2xyz"},
		{"sim pin", "unlocking with pin=8419", "8419"},
		{"token json", `{"token":"abcdef123456","ok":true}`, "abcdef123456"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Redact(c.input)
			if strings.Contains(got, c.leak) {
				t.Fatalf("redaction leaked %q: %q", c.leak, got)
			}
			if !strings.Contains(got, Redacted) {
				t.Fatalf("redaction produced no marker: %q", got)
			}
		})
	}
}

func TestRedactionLeavesOrdinaryTextAlone(t *testing.T) {
	message := "modem entered state ready on interface wwan0 after 3 retries"
	if got := Redact(message); got != message {
		t.Fatalf("redaction damaged a benign message: %q", got)
	}
}

func TestSMSBodyIsNeverPartiallyLogged(t *testing.T) {
	body := "your verification code is 482913, valid for 5 minutes"
	got := RedactSMSText(body)
	if strings.Contains(got, "482913") {
		t.Fatalf("sms redaction leaked the code: %q", got)
	}
	if strings.Contains(got, "verification") {
		t.Fatalf("sms redaction leaked body text: %q", got)
	}
}

func TestLogAppliesRedactionAtWriteTime(t *testing.T) {
	buffer := New(Options{Capacity: 10})
	buffer.Infof("sim", "card ready iccid 89860412345678901234")
	page := buffer.Page(10, proto.LogDebug)
	if len(page.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(page.Records))
	}
	if strings.Contains(page.Records[0].Message, "89860412345678901234") {
		t.Fatal("a stored record contains an unredacted ICCID")
	}
}

func TestRingDropsOldestAndReportsCount(t *testing.T) {
	buffer := New(Options{Capacity: 3})
	for i := 0; i < 6; i++ {
		buffer.Infof("test", "record %d", i)
	}
	page := buffer.Page(10, proto.LogDebug)
	if len(page.Records) != 3 {
		t.Fatalf("ring held %d records, want 3", len(page.Records))
	}
	if page.Dropped != 3 {
		t.Fatalf("dropped count is %d, want 3", page.Dropped)
	}
	if !strings.Contains(page.Records[0].Message, "record 3") {
		t.Fatalf("oldest surviving record is %q", page.Records[0].Message)
	}
	if !strings.Contains(page.Records[2].Message, "record 5") {
		t.Fatalf("newest record is %q", page.Records[2].Message)
	}
}

func TestPageFiltersByLevel(t *testing.T) {
	buffer := New(Options{Capacity: 10})
	buffer.Debugf("test", "noise")
	buffer.Infof("test", "ordinary")
	buffer.Warnf("test", "attention")
	buffer.Errorf("test", "failure")

	page := buffer.Page(10, proto.LogWarn)
	if len(page.Records) != 2 {
		t.Fatalf("level filter returned %d records, want 2", len(page.Records))
	}
	for _, record := range page.Records {
		if record.Level == proto.LogDebug || record.Level == proto.LogInfo {
			t.Fatalf("level filter admitted %s", record.Level)
		}
	}
}

func TestPageIsChronological(t *testing.T) {
	buffer := New(Options{Capacity: 10})
	for i := 0; i < 4; i++ {
		buffer.Infof("test", "record %d", i)
	}
	page := buffer.Page(3, proto.LogDebug)
	if len(page.Records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(page.Records))
	}
	if !strings.Contains(page.Records[0].Message, "record 1") ||
		!strings.Contains(page.Records[2].Message, "record 3") {
		t.Fatalf("records are out of order: %+v", page.Records)
	}
}

func TestFileMirrorRotatesAndStaysBounded(t *testing.T) {
	dir := t.TempDir()
	buffer := New(Options{Capacity: 10000, Dir: dir, FileBytes: 1024, FileCount: 2})
	defer buffer.Close()

	for i := 0; i < 500; i++ {
		buffer.Infof("test", "a reasonably long diagnostic line number %d padded out to force rotation", i)
	}
	if err := buffer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) > 2 {
		t.Fatalf("rotation kept %d files, want at most 2", len(entries))
	}
	var total int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		total += info.Size()
	}
	// Two files of at most 1 KiB, with one line of slack for the record that
	// triggers rotation.
	if total > 2*1024+512 {
		t.Fatalf("log files total %d bytes, rotation is not bounding growth", total)
	}
}

func TestFileMirrorIsAlsoRedacted(t *testing.T) {
	dir := t.TempDir()
	buffer := New(Options{Capacity: 100, Dir: dir})
	buffer.Infof("wifi", "connect ssid=home psk=TopSecretValue")
	if err := buffer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "agent.log"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(raw), "TopSecretValue") {
		t.Fatal("the file mirror contains an unredacted Wi-Fi password")
	}
}

func TestConcurrentLoggingIsSafe(t *testing.T) {
	buffer := New(Options{Capacity: 500, Now: func() time.Time { return time.Unix(0, 0) }})
	done := make(chan struct{})
	for writer := 0; writer < 8; writer++ {
		go func(id int) {
			for i := 0; i < 100; i++ {
				buffer.Infof("test", "writer %d record %d", id, i)
			}
			done <- struct{}{}
		}(writer)
	}
	for writer := 0; writer < 8; writer++ {
		<-done
	}
	page := buffer.Page(0, proto.LogDebug)
	if len(page.Records) != 500 {
		t.Fatalf("ring holds %d records, want its capacity of 500", len(page.Records))
	}
}
