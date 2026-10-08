package pqidentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/human-agent65535/nassimhub-node/proto"
)

func deviceKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return proto.DeviceID(proto.PlatformMSM8916, public), private
}

func TestDisabledAndUnsupportedBuildsHoldNoKeyAndWriteNothing(t *testing.T) {
	dir := t.TempDir()
	id, key := deviceKey(t)
	store, err := LoadOrCreate(Options{Dir: dir, DeviceID: id, DeviceKey: key, Disabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if store.Status() != StatusDisabled || store.Identity().Present() || store.Signer() != nil {
		t.Fatalf("disabled store: %s", store.Status())
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); !os.IsNotExist(err) {
		t.Fatal("a disabled identity wrote a key file")
	}
	if !proto.StandardPQSupported() {
		store, err := LoadOrCreate(Options{Dir: dir, DeviceID: id, DeviceKey: key})
		if err != nil {
			t.Fatal(err)
		}
		if store.Status() != StatusUnavailable || store.Identity().Present() || store.Signer() != nil {
			t.Fatalf("unsupported build: %s", store.Status())
		}
		if _, err := os.Stat(filepath.Join(dir, FileName)); !os.IsNotExist(err) {
			t.Fatal("a build without ML-DSA wrote a key file")
		}
	}
	var missing *Store
	if missing.Status() != StatusUnavailable || missing.Identity().Present() || missing.Signer() != nil {
		t.Fatal("a nil store must read as no identity")
	}
}

func TestKeyIsGeneratedOnceAndSurvivesRestartsAndLevelChanges(t *testing.T) {
	if !proto.StandardPQSupported() {
		t.Skip("this toolchain has no crypto/mldsa")
	}
	dir := t.TempDir()
	id, key := deviceKey(t)
	first, err := LoadOrCreate(Options{Dir: dir, DeviceID: id, DeviceKey: key, Algorithm: proto.PQSigMLDSA65})
	if err != nil {
		t.Fatal(err)
	}
	if first.Status() != StatusActive || first.Identity().Algorithm != proto.PQSigMLDSA65 {
		t.Fatalf("first start: %s %q", first.Status(), first.Detail())
	}
	info, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode is %v", info.Mode().Perm())
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(leftovers) != 0 {
		t.Fatalf("temporary key files were left behind: %d", len(leftovers))
	}

	// A restart, and a restart after the level asks for another parameter set:
	// the stored key is kept. Rotation is the owner's decision, not a side
	// effect of editing a configuration line.
	for _, algorithm := range []proto.PQSignatureAlgorithm{proto.PQSigMLDSA65, proto.PQSigMLDSA87} {
		again, err := LoadOrCreate(Options{Dir: dir, DeviceID: id, DeviceKey: key, Algorithm: algorithm})
		if err != nil {
			t.Fatal(err)
		}
		if !proto.SamePQIdentity(again.Identity(), first.Identity()) {
			t.Fatalf("restart with %s produced a different key", algorithm)
		}
	}

	// The signer really signs for the published key.
	proto.EnableStandardPQ()
	t.Cleanup(func() { proto.RegisterPQProvider(nil); proto.SetPQBackendName("none") })
	signature, err := first.Signer().Sign([]byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := proto.PQVerifierFor(proto.PQSigMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(first.Signer().PublicKey(), []byte("message"), signature); err != nil {
		t.Fatal(err)
	}
}

func TestDamagedOrForeignKeyFilesAreNeverReplaced(t *testing.T) {
	if !proto.StandardPQSupported() {
		t.Skip("this toolchain has no crypto/mldsa")
	}
	id, key := deviceKey(t)
	otherID, otherKey := deviceKey(t)

	valid := func(t *testing.T) (string, []byte) {
		dir := t.TempDir()
		if _, err := LoadOrCreate(Options{Dir: dir, DeviceID: id, DeviceKey: key}); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, FileName))
		if err != nil {
			t.Fatal(err)
		}
		return dir, raw
	}
	edit := func(raw []byte, change func(map[string]any)) []byte {
		var fields map[string]any
		_ = json.Unmarshal(raw, &fields)
		change(fields)
		out, _ := json.Marshal(fields)
		return out
	}

	_, foreignRaw := func() (string, []byte) {
		dir := t.TempDir()
		_, _ = LoadOrCreate(Options{Dir: dir, DeviceID: otherID, DeviceKey: otherKey})
		raw, _ := os.ReadFile(filepath.Join(dir, FileName))
		return dir, raw
	}()

	cases := map[string]func(raw []byte) []byte{
		"truncated":         func(raw []byte) []byte { return raw[:len(raw)/2] },
		"empty":             func([]byte) []byte { return nil },
		"another device":    func([]byte) []byte { return foreignRaw },
		"relabelled device": func([]byte) []byte { return edit(foreignRaw, func(f map[string]any) { f["device_id"] = id }) },
		"public key swapped": func(raw []byte) []byte {
			return edit(raw, func(f map[string]any) { f["public_key"] = "QUJD" })
		},
		"unknown algorithm": func(raw []byte) []byte {
			return edit(raw, func(f map[string]any) { f["algorithm"] = "ml-dsa-44" })
		},
		"algorithm relabelled": func(raw []byte) []byte {
			return edit(raw, func(f map[string]any) { f["algorithm"] = "ml-dsa-87" })
		},
		"short seed": func(raw []byte) []byte {
			return edit(raw, func(f map[string]any) { f["private_seed"] = "QUJD" })
		},
		"binding removed": func(raw []byte) []byte {
			return edit(raw, func(f map[string]any) { f["binding"] = "" })
		},
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			dir, raw := valid(t)
			path := filepath.Join(dir, FileName)
			damaged := corrupt(raw)
			if err := os.WriteFile(path, damaged, 0o600); err != nil {
				t.Fatal(err)
			}
			store, err := LoadOrCreate(Options{Dir: dir, DeviceID: id, DeviceKey: key})
			if err != nil {
				t.Fatal(err)
			}
			if store.Status() != StatusDamaged || store.Identity().Present() || store.Signer() != nil {
				t.Fatalf("status %s, identity present %v", store.Status(), store.Identity().Present())
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(damaged) {
				t.Fatal("the damaged key file was rewritten")
			}
		})
	}
}

func TestDeliberateRotationProducesANewKey(t *testing.T) {
	if !proto.StandardPQSupported() {
		t.Skip("this toolchain has no crypto/mldsa")
	}
	dir := t.TempDir()
	id, key := deviceKey(t)
	first, _ := LoadOrCreate(Options{Dir: dir, DeviceID: id, DeviceKey: key})
	if err := os.Remove(filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(Options{Dir: dir, DeviceID: id, DeviceKey: key, Algorithm: proto.PQSigMLDSA87})
	if err != nil {
		t.Fatal(err)
	}
	if second.Status() != StatusActive || proto.SamePQIdentity(first.Identity(), second.Identity()) {
		t.Fatal("removing the key file did not rotate the key")
	}
	if second.Identity().Algorithm != proto.PQSigMLDSA87 {
		t.Fatalf("rotated key is %s", second.Identity().Algorithm)
	}
}

func TestConcurrentFirstStartsAgreeOnOneKey(t *testing.T) {
	if !proto.StandardPQSupported() {
		t.Skip("this toolchain has no crypto/mldsa")
	}
	dir := t.TempDir()
	id, key := deviceKey(t)
	const starts = 8
	results := make(chan proto.PQIdentity, starts)
	for i := 0; i < starts; i++ {
		go func() {
			store, err := LoadOrCreate(Options{Dir: dir, DeviceID: id, DeviceKey: key})
			if err != nil || store.Status() != StatusActive {
				results <- proto.PQIdentity{}
				return
			}
			results <- store.Identity()
		}()
	}
	onDisk := func() proto.PQIdentity {
		store, _ := LoadOrCreate(Options{Dir: dir, DeviceID: id, DeviceKey: key})
		return store.Identity()
	}
	seen := map[string]bool{}
	for i := 0; i < starts; i++ {
		identity := <-results
		if identity.Present() {
			seen[identity.PublicKey] = true
		}
	}
	final := onDisk()
	if !final.Present() {
		t.Fatal("no key on disk after concurrent first starts")
	}
	for public := range seen {
		if public != final.PublicKey {
			t.Fatal("a concurrent start is using a key that is not the one on disk")
		}
	}
}
