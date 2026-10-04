package identity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/human-agent65535/nassimhub-node/proto"
)

func TestIdentitySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	options := Options{Dir: dir, Platform: proto.PlatformMSM8916, Model: "UFI003"}

	first, err := LoadOrCreate(options)
	if err != nil {
		t.Fatalf("first boot: %v", err)
	}
	// Simulate as many restarts as a device might see in a day.
	for i := 0; i < 5; i++ {
		again, err := LoadOrCreate(options)
		if err != nil {
			t.Fatalf("restart %d: %v", i, err)
		}
		if again.DeviceID != first.DeviceID {
			t.Fatalf("restart %d changed device id: %q then %q", i, first.DeviceID, again.DeviceID)
		}
		if !again.PublicKey.Equal(first.PublicKey) {
			t.Fatalf("restart %d regenerated the key", i)
		}
	}
}

func TestIdentityIsCreatedOnceOnly(t *testing.T) {
	dir := t.TempDir()
	options := Options{Dir: dir, Platform: proto.PlatformMock}
	first, err := LoadOrCreate(options)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := LoadOrCreate(options); err != nil {
		t.Fatalf("reload: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("identity file was rewritten on reload")
	}
	if first.DeviceID == "" {
		t.Fatal("device id was not derived")
	}
}

func TestDeviceIDMatchesDerivation(t *testing.T) {
	dir := t.TempDir()
	loaded, err := LoadOrCreate(Options{Dir: dir, Platform: proto.PlatformMSM8916})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !proto.ValidateDeviceID(loaded.DeviceID, proto.PlatformMSM8916, loaded.PublicKey) {
		t.Fatalf("device id %q does not derive from the stored key", loaded.DeviceID)
	}
}

func TestForgedDeviceIDIsRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreate(Options{Dir: dir, Platform: proto.PlatformMSM8916}); err != nil {
		t.Fatalf("create: %v", err)
	}
	path := filepath.Join(dir, FileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var stored map[string]any
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("decode: %v", err)
	}
	stored["device_id"] = "NSH-410-DEADBE"
	tampered, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadOrCreate(Options{Dir: dir, Platform: proto.PlatformMSM8916}); err == nil {
		t.Fatal("a hand-edited device id was accepted")
	}
}

func TestPlatformMismatchIsRefusedRatherThanRewritten(t *testing.T) {
	dir := t.TempDir()
	original, err := LoadOrCreate(Options{Dir: dir, Platform: proto.PlatformMSM8916})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = LoadOrCreate(Options{Dir: dir, Platform: proto.PlatformMock})
	if !errors.Is(err, ErrPlatformMismatch) {
		t.Fatalf("expected ErrPlatformMismatch, got %v", err)
	}
	// The stored identity must be untouched after the refusal.
	again, err := LoadOrCreate(Options{Dir: dir, Platform: proto.PlatformMSM8916})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if again.DeviceID != original.DeviceID {
		t.Fatal("a rejected platform change damaged the stored identity")
	}
}

func TestIdentityFileIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreate(Options{Dir: dir, Platform: proto.PlatformMock}); err != nil {
		t.Fatalf("create: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("identity file mode %v is readable by other users", mode)
	}
}

func TestBootIDChangesBetweenProcessesButIsStableWithin(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreate(Options{Dir: dir, Platform: proto.PlatformMock})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if first.BootID() != first.BootID() {
		t.Fatal("boot id changed within one process")
	}
	second, err := LoadOrCreate(Options{Dir: dir, Platform: proto.PlatformMock})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if second.BootID() == first.BootID() {
		t.Fatal("boot id did not change across a simulated restart")
	}
	if second.DeviceID != first.DeviceID {
		t.Fatal("a new boot id must not imply a new device id")
	}
}

func TestCorruptIdentityIsAnErrorNotARegeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("{ not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadOrCreate(Options{Dir: dir, Platform: proto.PlatformMock}); err == nil {
		t.Fatal("a corrupt identity file was silently replaced with a new device")
	}
}
