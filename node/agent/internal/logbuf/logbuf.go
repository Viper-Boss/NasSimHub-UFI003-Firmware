// Package logbuf is the Node's diagnostic log: a bounded in-memory ring with
// redaction applied on the way in, and an optional size-capped file mirror.
//
// Two constraints shape it. First, a SIM Node handles phone numbers,
// verification codes, bearer tokens and Wi-Fi passwords; none of those may ever
// reach a log line, so redaction happens at write time and there is no code
// path that stores an unredacted record. Second, the target hardware has a tiny
// rootfs that has already been filled to 100% once by unbounded logging, so the
// ring has a hard record cap and the file mirror has a hard byte cap with
// rotation rather than growth.
package logbuf

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// DefaultCapacity is how many records the ring holds. At roughly 200 bytes a
// record this is well under a megabyte resident.
const DefaultCapacity = 2000

// DefaultFileBytes caps one log file before rotation.
const DefaultFileBytes = 256 << 10

// DefaultFileCount is how many rotated files are kept, current file included.
const DefaultFileCount = 2

// Redacted is what replaces a sensitive value. It is a fixed marker rather than
// a length-preserving mask so a reader cannot infer the original length.
const Redacted = "[redacted]"

var redactions = []struct {
	name    string
	pattern *regexp.Regexp
	replace string
}{
	// Bearer tokens and Authorization headers in any casing.
	{"bearer", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-+/=]{8,}`), "Bearer " + Redacted},
	// Explicit key=value shapes for the credentials we know we carry.
	// The optional quote after the key lets one rule cover both `psk=value`
	// and JSON's `"token":"value"`.
	{"credential-kv", regexp.MustCompile(`(?i)\b(psk|password|passphrase|token|secret|pin|puk|private_seed|api[_-]?key)\b"?(\s*[:=]\s*)("?)([^\s",;}]+)("?)`), "${1}${2}${3}" + Redacted + "${5}"},
	// ICCID: 18-22 digits, frequently prefixed 89.
	{"iccid", regexp.MustCompile(`\b\d{18,22}\b`), Redacted},
	// IMSI: exactly 15 digits.
	{"imsi", regexp.MustCompile(`\b\d{15}\b`), Redacted},
	// Phone numbers, international or long national form.
	{"phone", regexp.MustCompile(`\+?\d[\d\-\s]{6,17}\d`), Redacted},
	// One-time codes quoted in prose. This exists because message bodies are
	// never supposed to reach the log at all - the rule is enforced at the call
	// sites, and RedactSMSText below is how a body is represented when one has
	// to be mentioned - but "never" is a rule people break under deadline, and
	// the single most damaging thing a leaked body can contain is the code
	// itself. Free-form prose cannot be sanitised in general; this catches the
	// case that actually costs someone their account.
	//
	// The digits are required to follow a code-ish word so that ordinary
	// numbers - a port, a year, a byte count - are left alone.
	{"otp", regexp.MustCompile(`(?i)\b(code|otp|passcode|one[\s-]?time|verification|验证码|校验码)\b?[^0-9\n]{0,16}(\d{4,8})\b`), "${1}" + " " + Redacted},
}

// Redact removes sensitive values from a message.
//
// The order matters: credential key/value shapes are handled before the numeric
// patterns so that "pin=1234" is redacted as a credential rather than being
// missed for being too short to look like a phone number.
func Redact(message string) string {
	for _, rule := range redactions {
		message = rule.pattern.ReplaceAllString(message, rule.replace)
	}
	return message
}

// RedactSMSText replaces message bodies wholesale.
//
// SMS content is never summarised, truncated or sampled into the log. A
// verification code is short and a partial body would still leak it, so the
// only safe representation is the length.
func RedactSMSText(text string) string {
	return fmt.Sprintf("[sms body %d chars]", len([]rune(text)))
}

// Options configures a Buffer.
type Options struct {
	Capacity  int
	Dir       string
	FileBytes int64
	FileCount int
	Now       func() time.Time
}

// Buffer is a concurrent-safe bounded log.
type Buffer struct {
	capacity  int
	dir       string
	fileBytes int64
	fileCount int
	now       func() time.Time

	mu      sync.Mutex
	records []proto.LogRecord
	dropped int
	file    *os.File
	written int64
}

// New builds a Buffer. A zero Dir disables the file mirror entirely, which is
// what the mock Node and the unit tests use.
func New(options Options) *Buffer {
	capacity := options.Capacity
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	fileBytes := options.FileBytes
	if fileBytes <= 0 {
		fileBytes = DefaultFileBytes
	}
	fileCount := options.FileCount
	if fileCount <= 0 {
		fileCount = DefaultFileCount
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Buffer{
		capacity:  capacity,
		dir:       options.Dir,
		fileBytes: fileBytes,
		fileCount: fileCount,
		now:       now,
		records:   make([]proto.LogRecord, 0, capacity),
	}
}

// Log appends one redacted record.
func (b *Buffer) Log(level proto.LogLevel, source, format string, arguments ...any) {
	message := Redact(fmt.Sprintf(format, arguments...))
	record := proto.LogRecord{
		Time:    b.now().UTC(),
		Level:   level,
		Source:  source,
		Message: message,
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.records) == b.capacity {
		copy(b.records, b.records[1:])
		b.records = b.records[:b.capacity-1]
		b.dropped++
	}
	b.records = append(b.records, record)
	b.mirrorLocked(record)
}

func (b *Buffer) Debugf(source, format string, arguments ...any) {
	b.Log(proto.LogDebug, source, format, arguments...)
}

func (b *Buffer) Infof(source, format string, arguments ...any) {
	b.Log(proto.LogInfo, source, format, arguments...)
}

func (b *Buffer) Warnf(source, format string, arguments ...any) {
	b.Log(proto.LogWarn, source, format, arguments...)
}

func (b *Buffer) Errorf(source, format string, arguments ...any) {
	b.Log(proto.LogError, source, format, arguments...)
}

// Page returns the most recent records, newest last, capped at limit.
func (b *Buffer) Page(limit int, minimum proto.LogLevel) proto.LogPage {
	b.mu.Lock()
	defer b.mu.Unlock()
	if limit <= 0 || limit > len(b.records) {
		limit = len(b.records)
	}
	threshold := severity(minimum)
	selected := make([]proto.LogRecord, 0, limit)
	for i := len(b.records) - 1; i >= 0 && len(selected) < limit; i-- {
		if severity(b.records[i].Level) < threshold {
			continue
		}
		selected = append(selected, b.records[i])
	}
	// Reverse into chronological order.
	for left, right := 0, len(selected)-1; left < right; left, right = left+1, right-1 {
		selected[left], selected[right] = selected[right], selected[left]
	}
	return proto.LogPage{Records: selected, Dropped: b.dropped, Capacity: b.capacity}
}

func severity(level proto.LogLevel) int {
	switch level {
	case proto.LogDebug:
		return 0
	case proto.LogInfo:
		return 1
	case proto.LogWarn:
		return 2
	case proto.LogError:
		return 3
	default:
		return 1
	}
}

// Close releases the file mirror.
func (b *Buffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.file == nil {
		return nil
	}
	err := b.file.Close()
	b.file = nil
	return err
}

func (b *Buffer) mirrorLocked(record proto.LogRecord) {
	if b.dir == "" {
		return
	}
	line := fmt.Sprintf("%s %-5s %s %s\n",
		record.Time.Format(time.RFC3339),
		strings.ToUpper(string(record.Level)),
		record.Source,
		record.Message,
	)
	if b.file == nil {
		if err := b.openLocked(); err != nil {
			// Losing the file mirror must never take the Node down; the ring is
			// still authoritative for GET /v1/logs.
			b.dir = ""
			return
		}
	}
	if b.written+int64(len(line)) > b.fileBytes {
		if err := b.rotateLocked(); err != nil {
			b.dir = ""
			return
		}
	}
	written, err := b.file.WriteString(line)
	if err != nil {
		b.dir = ""
		return
	}
	b.written += int64(written)
}

func (b *Buffer) path(index int) string {
	if index == 0 {
		return filepath.Join(b.dir, "agent.log")
	}
	return filepath.Join(b.dir, fmt.Sprintf("agent.log.%d", index))
}

func (b *Buffer) openLocked() error {
	if err := os.MkdirAll(b.dir, 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(b.path(0), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	b.file = file
	b.written = info.Size()
	return nil
}

func (b *Buffer) rotateLocked() error {
	if b.file != nil {
		if err := b.file.Close(); err != nil {
			return err
		}
		b.file = nil
	}
	// Drop the oldest, then shift every remaining file one slot older. The
	// total on disk is therefore bounded by fileBytes*fileCount at all times.
	oldest := b.fileCount - 1
	_ = os.Remove(b.path(oldest))
	for index := oldest - 1; index >= 0; index-- {
		source := b.path(index)
		if _, err := os.Stat(source); err != nil {
			continue
		}
		if err := os.Rename(source, b.path(index+1)); err != nil {
			return err
		}
	}
	return b.openLocked()
}
