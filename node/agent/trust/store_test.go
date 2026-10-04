package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignedRecordRoundTripAndTamperRejection(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := New("NSH-410-123456")
	if err := engine.Bind(strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := Save(path, engine.Snapshot(), private); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path, "NSH-410-123456", public)
	if err != nil || loaded.State != Observation || loaded.BindingHash != strings.Repeat("a", 64) {
		t.Fatalf("loaded = %#v, %v", loaded, err)
	}
	if _, err := Load(path, "NSH-410-OTHER", public); err == nil {
		t.Fatal("cross-device record was accepted")
	}
	restored, err := LoadEngine(path, "NSH-410-123456", public)
	if err != nil || restored.Allow(SendSMS) || !restored.Allow(ReceiveSMS) {
		t.Fatalf("restored policy = %#v, %v", restored, err)
	}
	content, _ := os.ReadFile(path)
	content = []byte(strings.Replace(string(content), "OBSERVATION", "TRUSTED", 1))
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "NSH-410-123456", public); err == nil {
		t.Fatal("tampered trust record was accepted")
	}
}

func TestUnsignedOrPublicRecordIsRejected(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(path, []byte(`{"record":{"device_id":"x","generation":1}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "x", public); err == nil {
		t.Fatal("public unsigned record was accepted")
	}
}
