// Command nsh-release is the publisher's side of agent updates: it creates
// release keys, describes a built agent in a manifest, signs the manifest, and
// verifies the result the way a device will.
//
//	nsh-release keygen   -dir KEYDIR -key-id ID [-pq ml-dsa-87|ml-dsa-65|none]
//	nsh-release keyring  -dir KEYDIR [-out ota-keys.json]
//	nsh-release manifest -binary FILE -version V -platform msm8916 -arch arm64 [-channel stable] -out manifest.json
//	nsh-release sign     -manifest manifest.json -dir KEYDIR -key-id ID [-pq-key-id ID] -out signed.json
//	nsh-release verify   -signed signed.json -keys ota-keys.json [-binary FILE] [-require-pq]
//
// # Where the private keys are
//
// In KEYDIR, which the publisher chooses, and nowhere else. This tool refuses
// to create a private key inside a version-controlled tree, never prints one,
// and never writes one anywhere but the file it was asked for. The only thing
// that leaves KEYDIR is the public keyring, which is what gets installed on a
// device as /etc/nassimhub/ota-keys.json.
//
// # What is signed
//
// The exact bytes of the manifest as they appear inside the signed document.
// Both signatures - Ed25519 and, when a post-quantum key is used, ML-DSA -
// cover those same bytes. A device verifies the bytes it received before it
// decodes them, so the signed document must reach the device unmodified:
// reformatting it (re-indenting, re-ordering) invalidates both signatures by
// design. Ship signed.json as a file; do not paste it through a formatter.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/ota"
	"github.com/human-agent65535/nassimhub-node/proto"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "nsh-release: %v\n", err)
		os.Exit(1)
	}
}

func run(arguments []string, out io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("usage: nsh-release keygen|keyring|manifest|sign|verify [flags]")
	}
	// The real provider on a toolchain that has it. Without it the
	// post-quantum subcommands say so instead of producing something weaker.
	proto.EnableStandardPQ()
	switch arguments[0] {
	case "keygen":
		return keygen(arguments[1:], out)
	case "keyring":
		return keyring(arguments[1:], out)
	case "manifest":
		return manifest(arguments[1:], out)
	case "sign":
		return sign(arguments[1:], out)
	case "verify":
		return verify(arguments[1:], out)
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

// keyFile is a private release key on disk.
type keyFile struct {
	Version   int    `json:"version"`
	Kind      string `json:"kind"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Seed      string `json:"seed"`
	PublicKey string `json:"public_key"`
	CreatedAt string `json:"created_at"`
}

const (
	kindClassical   = "nassimhub-release-ed25519"
	kindPostQuantum = "nassimhub-release-mldsa"
)

func classicalPath(dir, id string) string   { return filepath.Join(dir, id+".ed25519.key") }
func postQuantumPath(dir, id string) string { return filepath.Join(dir, id+".mldsa.key") }

// insideRepository reports whether dir is inside a version-controlled tree.
func insideRepository(dir string) (string, bool) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return "", false
	}
	for current := absolute; ; current = filepath.Dir(current) {
		for _, marker := range []string{".git", ".hg", ".svn"} {
			if _, err := os.Stat(filepath.Join(current, marker)); err == nil {
				return current, true
			}
		}
		if current == filepath.Dir(current) {
			return "", false
		}
	}
}

func writePrivate(path string, value keyFile) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	// O_EXCL: an existing key is never overwritten. Losing a release key is
	// recoverable (rotate); silently replacing one is not.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists; release keys are never overwritten", filepath.Base(path))
		}
		return err
	}
	_, writeErr := file.Write(append(encoded, '\n'))
	return errors.Join(writeErr, file.Sync(), file.Close())
}

func readPrivate(path, kind string) (keyFile, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return keyFile{}, nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	var value keyFile
	if err := json.Unmarshal(raw, &value); err != nil || value.Version != 1 || value.Kind != kind {
		return keyFile{}, nil, fmt.Errorf("%s is not a %s key file", filepath.Base(path), kind)
	}
	seed, err := base64.StdEncoding.DecodeString(value.Seed)
	if err != nil {
		return keyFile{}, nil, fmt.Errorf("%s has an unreadable seed", filepath.Base(path))
	}
	return value, seed, nil
}

func keygen(arguments []string, out io.Writer) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	dir := flags.String("dir", "", "directory to create the private keys in; must be outside any repository")
	id := flags.String("key-id", "", "key id recorded in manifests and in the device keyring")
	pq := flags.String("pq", "ml-dsa-87", "post-quantum algorithm: ml-dsa-87, ml-dsa-65 or none")
	allowRepo := flags.Bool("allow-inside-repository", false, "create keys inside a version-controlled tree (tests only)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *dir == "" || *id == "" {
		return errors.New("keygen needs -dir and -key-id")
	}
	if _, _, err := ota.ParseKeyring([]byte(`{"version":1,"ed25519":{"` + *id + `":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}}`)); err != nil {
		return fmt.Errorf("key id %q is not usable", *id)
	}
	if root, inside := insideRepository(*dir); inside && !*allowRepo {
		return fmt.Errorf("%s is inside the repository at %s; release private keys must not be created where they can be committed", *dir, root)
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(*dir, 0o700); err != nil {
		return err
	}
	created := time.Now().UTC().Format(time.RFC3339)

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if err := writePrivate(classicalPath(*dir, *id), keyFile{
		Version: 1, Kind: kindClassical, KeyID: *id, Algorithm: "ed25519",
		Seed: base64.StdEncoding.EncodeToString(seed), PublicKey: base64.StdEncoding.EncodeToString(public), CreatedAt: created,
	}); err != nil {
		return err
	}
	fmt.Fprintf(out, "created ed25519 release key %s\n", *id)

	if *pq != "none" {
		algorithm := proto.PQSignatureAlgorithm(*pq)
		if err := proto.ValidatePQSignatureAlgorithm(algorithm); err != nil {
			return err
		}
		pqSeed, err := proto.NewMLDSASeed()
		if err != nil {
			return fmt.Errorf("a post-quantum key cannot be created by this build: %w", err)
		}
		signer, err := proto.NewMLDSASigner(algorithm, pqSeed)
		if err != nil {
			return err
		}
		if err := writePrivate(postQuantumPath(*dir, *id), keyFile{
			Version: 1, Kind: kindPostQuantum, KeyID: *id, Algorithm: string(algorithm),
			Seed: base64.StdEncoding.EncodeToString(pqSeed), PublicKey: signer.Identity().PublicKey, CreatedAt: created,
		}); err != nil {
			return err
		}
		fmt.Fprintf(out, "created %s release key %s\n", algorithm, *id)
	}
	fmt.Fprintf(out, "private keys are in %s; keep that directory off-line and out of every repository and image\n", *dir)
	return nil
}

// loadKeyDir reads every release key in a directory and returns the PUBLIC
// keyrings.
func loadKeyDir(dir string) (proto.OTAKeyring, proto.OTAPQKeyring, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	classical, postQuantum := proto.OTAKeyring{}, proto.OTAPQKeyring{}
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case strings.HasSuffix(name, ".ed25519.key"):
			value, seed, err := readPrivate(filepath.Join(dir, name), kindClassical)
			if err != nil {
				return nil, nil, err
			}
			if len(seed) != ed25519.SeedSize {
				return nil, nil, fmt.Errorf("%s has a seed of the wrong size", name)
			}
			classical[value.KeyID] = ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		case strings.HasSuffix(name, ".mldsa.key"):
			value, seed, err := readPrivate(filepath.Join(dir, name), kindPostQuantum)
			if err != nil {
				return nil, nil, err
			}
			signer, err := proto.NewMLDSASigner(proto.PQSignatureAlgorithm(value.Algorithm), seed)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			postQuantum[value.KeyID] = signer.Identity()
		}
	}
	if len(classical) == 0 {
		return nil, nil, fmt.Errorf("no release keys in %s", dir)
	}
	return classical, postQuantum, nil
}

func keyring(arguments []string, out io.Writer) error {
	flags := flag.NewFlagSet("keyring", flag.ContinueOnError)
	dir := flags.String("dir", "", "directory holding the private keys")
	output := flags.String("out", "", "file to write the public keyring to; default prints it")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("keyring needs -dir")
	}
	classical, postQuantum, err := loadKeyDir(*dir)
	if err != nil {
		return err
	}
	encoded, err := ota.EncodeKeyring(classical, postQuantum)
	if err != nil {
		return err
	}
	// The round trip is the check that what is about to be shipped is what a
	// device will accept.
	if _, _, err := ota.ParseKeyring(encoded); err != nil {
		return fmt.Errorf("the keyring does not load: %w", err)
	}
	if *output == "" {
		_, err := out.Write(append(encoded, '\n'))
		return err
	}
	if err := os.WriteFile(*output, append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote the public keyring (%d ed25519, %d post-quantum) to %s\n", len(classical), len(postQuantum), *output)
	return nil
}

func manifest(arguments []string, out io.Writer) error {
	flags := flag.NewFlagSet("manifest", flag.ContinueOnError)
	binary := flags.String("binary", "", "the built agent")
	version := flags.String("version", "", "the version the binary reports with -version")
	releaseID := flags.String("release-id", "", "release id; default agent-<version>")
	platform := flags.String("platform", "msm8916", "target platform")
	arch := flags.String("arch", "arm64", "target architecture")
	channel := flags.String("channel", "stable", "stable or beta")
	url := flags.String("url", "", "where the artifact can be fetched; informational, the hash decides")
	minCore := flags.String("min-core", proto.MinCoreVersion, "oldest NAS version the new agent accepts")
	notes := flags.String("notes", "", "release notes")
	output := flags.String("out", "", "file to write the unsigned manifest to")
	released := flags.String("released-at", "", "RFC3339 release time; default now (set it for reproducible output)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *binary == "" || *version == "" || *output == "" {
		return errors.New("manifest needs -binary, -version and -out")
	}
	if _, err := proto.ParseVersion(*version); err != nil {
		return fmt.Errorf("version %q is not a version a device can compare", *version)
	}
	id := *releaseID
	if id == "" {
		id = "agent-" + *version
	}
	if err := proto.ValidateOTAReleaseID(id); err != nil {
		return err
	}
	content, err := os.ReadFile(*binary)
	if err != nil {
		return err
	}
	if len(content) == 0 || len(content) > proto.OTAMaxArtifactBytes {
		return fmt.Errorf("the binary is %d bytes; a device accepts 1 to %d", len(content), proto.OTAMaxArtifactBytes)
	}
	at := time.Now().UTC().Truncate(time.Second)
	if *released != "" {
		if at, err = time.Parse(time.RFC3339, *released); err != nil {
			return fmt.Errorf("released-at: %w", err)
		}
	}
	digest := sha256.Sum256(content)
	described := proto.OTAManifest{
		SchemaVersion:  proto.OTASchemaVersion,
		ReleaseID:      id,
		Version:        *version,
		Channel:        proto.OTAChannel(*channel),
		Platform:       proto.Platform(*platform),
		ReleasedAt:     at.UTC(),
		ProtocolMajor:  proto.ProtocolMajor,
		ProtocolMinor:  proto.ProtocolMinor,
		MinCoreVersion: *minCore,
		Artifacts: []proto.OTAArtifact{{
			Kind: proto.OTAArtifactAgent, Name: ota.BinaryName,
			SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content)), URL: *url, Arch: *arch,
		}},
		Notes: *notes,
	}
	// The same policy check a device of this platform would run, against a
	// version older than this one, so a manifest that no device would accept
	// is caught here rather than in the field.
	if err := proto.CheckManifest(described, proto.OTAPolicy{
		Platform: described.Platform, Arch: *arch, Channel: described.Channel, AllowDowngrade: true,
	}); err != nil {
		return err
	}
	encoded, err := json.Marshal(described)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*output, append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "manifest for %s (%s, %s/%s, %d bytes, sha256 %s) written to %s\n",
		id, *version, *platform, *arch, len(content), hex.EncodeToString(digest[:]), *output)
	return nil
}

func sign(arguments []string, out io.Writer) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	input := flags.String("manifest", "", "the unsigned manifest")
	dir := flags.String("dir", "", "directory holding the private keys")
	id := flags.String("key-id", "", "ed25519 key id to sign with")
	pqID := flags.String("pq-key-id", "", "post-quantum key id to also sign with; empty signs classically only")
	output := flags.String("out", "", "file to write the signed manifest to")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || *dir == "" || *id == "" || *output == "" {
		return errors.New("sign needs -manifest, -dir, -key-id and -out")
	}
	raw, err := os.ReadFile(*input)
	if err != nil {
		return err
	}
	var described proto.OTAManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&described); err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	_, seed, err := readPrivate(classicalPath(*dir, *id), kindClassical)
	if err != nil {
		return err
	}
	if len(seed) != ed25519.SeedSize {
		return errors.New("the ed25519 key file has a seed of the wrong size")
	}
	var (
		pqSigner proto.PQSigner
		label    = "classical-only"
	)
	if *pqID != "" {
		value, pqSeed, err := readPrivate(postQuantumPath(*dir, *pqID), kindPostQuantum)
		if err != nil {
			return err
		}
		signer, err := proto.NewMLDSASigner(proto.PQSignatureAlgorithm(value.Algorithm), pqSeed)
		if err != nil {
			return fmt.Errorf("the post-quantum key cannot be used by this build: %w", err)
		}
		pqSigner, label = signer, "dual-signed (ed25519 + "+value.Algorithm+")"
	}
	signed, err := proto.SignManifestHybrid(described, *id, ed25519.NewKeyFromSeed(seed), *pqID, pqSigner)
	if err != nil {
		return err
	}
	// Verify what was just produced, with the public halves, before writing
	// it. A signing step that can emit something that does not verify is how
	// a release goes out that no device will install.
	classical, postQuantum, err := loadKeyDir(*dir)
	if err != nil {
		return err
	}
	policy := proto.OTASignaturePreferred
	if pqSigner != nil {
		policy = proto.OTASignatureRequired
	}
	if _, _, err := proto.VerifyManifestHybrid(signed, classical, postQuantum, policy); err != nil {
		return fmt.Errorf("the signed manifest does not verify: %w", err)
	}
	// Compact, exactly as produced. See the package comment: these bytes are
	// what the signatures cover.
	encoded, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*output, encoded, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s: %s, written to %s\n", described.ReleaseID, label, *output)
	return nil
}

func verify(arguments []string, out io.Writer) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	input := flags.String("signed", "", "the signed manifest")
	keys := flags.String("keys", "", "the public keyring, as installed on a device")
	binary := flags.String("binary", "", "the artifact, to check against the manifest")
	requirePQ := flags.Bool("require-pq", false, "refuse a manifest without a valid post-quantum signature")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || *keys == "" {
		return errors.New("verify needs -signed and -keys")
	}
	raw, err := os.ReadFile(*input)
	if err != nil {
		return err
	}
	var signed proto.OTASignedManifest
	if err := json.Unmarshal(raw, &signed); err != nil {
		return fmt.Errorf("signed manifest: %w", err)
	}
	classical, postQuantum, err := ota.LoadKeyring(*keys)
	if err != nil {
		return err
	}
	if len(classical) == 0 {
		return fmt.Errorf("%s holds no release keys", *keys)
	}
	policy := proto.OTASignaturePreferred
	if *requirePQ {
		policy = proto.OTASignatureRequired
	}
	described, outcome, err := proto.VerifyManifestHybrid(signed, classical, postQuantum, policy)
	if err != nil {
		return err
	}
	if *binary != "" {
		content, err := os.ReadFile(*binary)
		if err != nil {
			return err
		}
		if len(described.Artifacts) != 1 {
			return errors.New("the manifest does not describe exactly one artifact")
		}
		if err := proto.VerifyArtifact(described.Artifacts[0], content); err != nil {
			return err
		}
	}
	ids := make([]string, 0, 2)
	ids = append(ids, signed.KeyID)
	if signed.PQKeyID != "" {
		ids = append(ids, signed.PQKeyID+" ("+string(signed.PQAlgorithm)+")")
	}
	sort.Strings(ids[1:])
	fmt.Fprintf(out, "%s %s for %s: %s, signed by %s\n",
		described.ReleaseID, described.Version, described.Platform, outcome, strings.Join(ids, " and "))
	if outcome == proto.OTAClassicalOnly && !proto.PQIdentityAvailable() {
		fmt.Fprintf(out, "note: this build cannot check post-quantum signatures (%s or newer is required)\n", proto.GoVersionForMLDSA)
	}
	return nil
}
