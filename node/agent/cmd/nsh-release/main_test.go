package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/human-agent65535/nassimhub-node/agent/ota"
	"github.com/human-agent65535/nassimhub-node/proto"
)

func mustRun(t *testing.T, arguments ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := run(arguments, &out); err != nil {
		t.Fatalf("nsh-release %s: %v", strings.Join(arguments, " "), err)
	}
	return out.String()
}

func mustFail(t *testing.T, arguments ...string) error {
	t.Helper()
	var out bytes.Buffer
	err := run(arguments, &out)
	if err == nil {
		t.Fatalf("nsh-release %s succeeded: %s", strings.Join(arguments, " "), out.String())
	}
	return err
}

func TestAReleaseIsDescribedSignedAndVerifiedTheWayADeviceWould(t *testing.T) {
	work := t.TempDir()
	keys := filepath.Join(work, "keys")
	binary := filepath.Join(work, "nassimhub-agent")
	content := []byte("nassimhub-agent 1.16.0 (test build)\n")
	if err := os.WriteFile(binary, content, 0o755); err != nil {
		t.Fatal(err)
	}
	pq := "none"
	if proto.StandardPQSupported() {
		pq = "ml-dsa-87"
	}

	output := mustRun(t, "keygen", "-dir", keys, "-key-id", "release-2026", "-pq", pq, "-allow-inside-repository")
	// The private key is never printed.
	private, err := os.ReadFile(filepath.Join(keys, "release-2026.ed25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Seed string `json:"seed"`
	}
	_ = json.Unmarshal(private, &stored)
	if stored.Seed == "" || strings.Contains(output, stored.Seed) {
		t.Fatal("keygen printed the private seed, or wrote none")
	}
	if info, _ := os.Stat(filepath.Join(keys, "release-2026.ed25519.key")); info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode is %v", info.Mode().Perm())
	}
	// A key is never overwritten.
	if err := mustFail(t, "keygen", "-dir", keys, "-key-id", "release-2026", "-pq", "none", "-allow-inside-repository"); !strings.Contains(err.Error(), "never overwritten") {
		t.Fatalf("overwriting a key: %v", err)
	}

	keyring := filepath.Join(work, "ota-keys.json")
	mustRun(t, "keyring", "-dir", keys, "-out", keyring)
	public, _ := os.ReadFile(keyring)
	if strings.Contains(string(public), stored.Seed) || strings.Contains(string(public), "seed") {
		t.Fatal("the public keyring carries private material")
	}
	classical, postQuantum, err := ota.LoadKeyring(keyring)
	if err != nil || len(classical) != 1 {
		t.Fatalf("the keyring does not load on a device: %v", err)
	}
	if proto.StandardPQSupported() && len(postQuantum) != 1 {
		t.Fatal("the keyring has no post-quantum key")
	}

	manifestPath := filepath.Join(work, "manifest.json")
	mustRun(t, "manifest", "-binary", binary, "-version", "1.16.0", "-out", manifestPath,
		"-released-at", "2026-10-04T00:00:00Z")
	// Deterministic for the same inputs.
	first, _ := os.ReadFile(manifestPath)
	mustRun(t, "manifest", "-binary", binary, "-version", "1.16.0", "-out", manifestPath,
		"-released-at", "2026-10-04T00:00:00Z")
	second, _ := os.ReadFile(manifestPath)
	if !bytes.Equal(first, second) {
		t.Fatal("the same inputs produced a different manifest")
	}

	signedPath := filepath.Join(work, "signed.json")
	arguments := []string{"sign", "-manifest", manifestPath, "-dir", keys, "-key-id", "release-2026", "-out", signedPath}
	if proto.StandardPQSupported() {
		arguments = append(arguments, "-pq-key-id", "release-2026")
	}
	mustRun(t, arguments...)

	verified := mustRun(t, "verify", "-signed", signedPath, "-keys", keyring, "-binary", binary)
	if proto.StandardPQSupported() {
		if !strings.Contains(verified, "dual_signed") || !strings.Contains(verified, "ml-dsa-87") {
			t.Fatalf("verify output: %s", verified)
		}
		mustRun(t, "verify", "-signed", signedPath, "-keys", keyring, "-require-pq")
	} else if !strings.Contains(verified, "classical_only") {
		t.Fatalf("verify output: %s", verified)
	}

	// A device accepts exactly this document.
	raw, _ := os.ReadFile(signedPath)
	var signed proto.OTASignedManifest
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	if _, _, err := proto.VerifyManifestHybrid(signed, classical, postQuantum, proto.OTASignaturePreferred); err != nil {
		t.Fatal(err)
	}

	// Another binary under the same manifest fails verification.
	other := filepath.Join(work, "other")
	_ = os.WriteFile(other, []byte("nassimhub-agent 1.16.0 (another build)\n"), 0o755)
	mustFail(t, "verify", "-signed", signedPath, "-keys", keyring, "-binary", other)

	// A keyring from another publisher refuses it.
	otherKeys := filepath.Join(work, "other-keys")
	mustRun(t, "keygen", "-dir", otherKeys, "-key-id", "release-2026", "-pq", "none", "-allow-inside-repository")
	otherRing := filepath.Join(work, "other-ring.json")
	mustRun(t, "keyring", "-dir", otherKeys, "-out", otherRing)
	mustFail(t, "verify", "-signed", signedPath, "-keys", otherRing)

	// Reformatting the signed document invalidates it. This is by design and
	// is the reason the tool writes it compact.
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		t.Fatal(err)
	}
	reformatted := filepath.Join(work, "reformatted.json")
	_ = os.WriteFile(reformatted, pretty.Bytes(), 0o644)
	mustFail(t, "verify", "-signed", reformatted, "-keys", keyring)

	// A classical-only signature is refused where a post-quantum one is
	// demanded.
	classicalOnly := filepath.Join(work, "classical.json")
	mustRun(t, "sign", "-manifest", manifestPath, "-dir", keys, "-key-id", "release-2026", "-out", classicalOnly)
	mustFail(t, "verify", "-signed", classicalOnly, "-keys", keyring, "-require-pq")
}

func TestKeysAreNotCreatedInsideARepositoryAndBadInputsAreRefused(t *testing.T) {
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(work, "deploy", "keys")
	if err := mustFail(t, "keygen", "-dir", inside, "-key-id", "release-1", "-pq", "none"); !strings.Contains(err.Error(), "inside the repository") {
		t.Fatalf("keygen inside a repository: %v", err)
	}
	if _, err := os.Stat(inside); !os.IsNotExist(err) {
		t.Fatal("a refused keygen created the directory")
	}

	outside := t.TempDir()
	mustFail(t, "keygen", "-dir", filepath.Join(outside, "k"), "-key-id", "../escape", "-pq", "none")
	mustFail(t, "keygen", "-dir", filepath.Join(outside, "k"), "-key-id", "release-1", "-pq", "ml-dsa-44")

	binary := filepath.Join(outside, "agent")
	_ = os.WriteFile(binary, []byte("x"), 0o755)
	out := filepath.Join(outside, "m.json")
	mustFail(t, "manifest", "-binary", binary, "-version", "not-a-version", "-out", out)
	mustFail(t, "manifest", "-binary", binary, "-version", "1.0.0", "-release-id", "../x", "-out", out)
	mustFail(t, "manifest", "-binary", binary, "-version", "1.0.0", "-release-id", "current", "-out", out)
	mustFail(t, "manifest", "-binary", filepath.Join(outside, "missing"), "-version", "1.0.0", "-out", out)
	empty := filepath.Join(outside, "empty")
	_ = os.WriteFile(empty, nil, 0o755)
	mustFail(t, "manifest", "-binary", empty, "-version", "1.0.0", "-out", out)
	mustFail(t, "verify", "-signed", out, "-keys", filepath.Join(outside, "no-keys.json"))
	mustFail(t, "nonsense")
	mustFail(t)
}
