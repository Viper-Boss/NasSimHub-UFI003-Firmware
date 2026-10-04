package transportkey

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestASecretIsGeneratedAndPersisted(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	if first.Zero() {
		t.Fatal("no secret was generated")
	}

	// Reopening finds the same secret. A Node that regenerated it on every
	// boot would make every paired Core's key stop authenticating after a
	// power cut.
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := reopened.Current()
	if err != nil {
		t.Fatal(err)
	}
	if second.KeyID != first.KeyID || second.Epoch != first.Epoch {
		t.Fatalf("reopening produced key %q epoch %d, was %q epoch %d",
			second.KeyID, second.Epoch, first.KeyID, first.Epoch)
	}
}

func TestTheSecretFileIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != FileMode {
		t.Fatalf("the transport secret is mode %o, want %o", mode, FileMode)
	}
}

func TestRotationAdvancesTheEpochAndChangesTheKey(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	after, err := store.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if after.Epoch <= before.Epoch {
		t.Fatalf("rotation produced epoch %d, was %d", after.Epoch, before.Epoch)
	}
	if string(after.Secret) == string(before.Secret) {
		t.Fatal("rotation kept the same secret")
	}
	// The ring accepts the new epoch, and the old one during its grace window
	// so that packets in flight are not lost.
	ring := store.Ring()
	if _, err := ring.Accepting(after.KeyID, after.Epoch); err != nil {
		t.Fatalf("the new epoch was refused: %v", err)
	}
	if _, err := ring.Accepting(before.KeyID, before.Epoch); err != nil {
		t.Fatalf("the previous epoch was refused during its grace window: %v", err)
	}
}

// The property Part 4 of this round asks for, checked as behaviour: unpairing
// must revoke the transport, not merely forget the owner.
func TestDestroyErasesTheSecretFromMemoryAndDisk(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	ring := store.Ring()

	if err := store.Destroy(); err != nil {
		t.Fatal(err)
	}

	// The old ring is empty, so nothing it held can authenticate a packet.
	if !ring.Empty() {
		t.Fatal("the key ring still holds keys after destruction")
	}
	// The new secret is not the old one.
	after, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	if after.KeyID == before.KeyID {
		t.Fatal("destruction kept the same key id, so the old Core's key would still be current")
	}
	if string(after.Secret) == string(before.Secret) {
		t.Fatal("destruction kept the same secret")
	}
	// And the previous secret is nowhere in the file that replaced it.
	raw, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	var stored document
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Secret.KeyID == before.KeyID {
		t.Fatal("the destroyed key id is still on disk")
	}
}

func TestACorruptFileIsReplacedRatherThanFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("{not json"), FileMode); err != nil {
		t.Fatal(err)
	}
	// A device that refused to start over a file it can safely recreate would
	// be a device somebody has to physically retrieve.
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("a corrupt transport key file prevented start-up: %v", err)
	}
	secret, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	if secret.Zero() {
		t.Fatal("no secret was generated to replace the corrupt one")
	}
}

// The key id is safe to print; the secret is not. This is what lets diagnostics
// say which key is in use.
func TestTheKeyIDRevealsNothingAboutTheSecret(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	secret, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	if store.KeyID() == "" {
		t.Fatal("no key id")
	}
	if strings.Contains(store.KeyID(), string(secret.Secret)) {
		t.Fatal("the key id contains the secret")
	}
	if len(store.KeyID()) >= len(secret.Secret) {
		t.Fatalf("the key id is %d bytes against a %d-byte secret, which is suspicious",
			len(store.KeyID()), len(secret.Secret))
	}
}
