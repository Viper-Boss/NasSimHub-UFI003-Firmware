// Package identity owns the Node's permanent cryptographic identity.
//
// The single invariant this package exists to protect: a Node generates its
// keypair exactly once, on first boot, and never again. Everything downstream
// depends on that - device_id is derived from the key, pairing binds a Core to
// the key, and Core deduplicates Nodes by device_id. A regenerated key is
// indistinguishable from a brand new device, so a bug that regenerates on every
// start would silently multiply one physical stick into a fresh row in the NAS
// on every reboot.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// DefaultDir is where a real Node keeps its identity. It is chosen to be on
// persistent storage and outside any path an OTA payload would replace.
const DefaultDir = "/var/lib/nassimhub"

// FileName is the identity document inside the directory.
const FileName = "device.json"

// filePerm keeps the private key unreadable by other users on the device.
const (
	filePerm fs.FileMode = 0o600
	dirPerm  fs.FileMode = 0o700
)

// document is the on-disk form. The private key is stored as the 32-byte seed
// rather than the expanded 64-byte form so the file stays small and a truncated
// write is detectable instead of silently producing a usable but wrong key.
type document struct {
	Version     int            `json:"version"`
	DeviceID    string         `json:"device_id"`
	Platform    proto.Platform `json:"platform"`
	Model       string         `json:"model"`
	PrivateSeed string         `json:"private_seed"`
	PublicKey   string         `json:"public_key"`
	CreatedAt   time.Time      `json:"created_at"`
}

// Identity is the loaded, validated identity of this Node.
type Identity struct {
	DeviceID   string
	Platform   proto.Platform
	Model      string
	PublicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	CreatedAt  time.Time

	bootID string
	once   sync.Once
}

// PrivateKey exposes the signing key to the small number of callers that need
// it. It is a method rather than a field so the key does not appear in a
// struct dump or a %+v log line.
func (i *Identity) PrivateKey() ed25519.PrivateKey { return i.privateKey }

// BootID is a value that changes on every process start. Core uses it to notice
// that a Node restarted without ever confusing that with a change of identity.
func (i *Identity) BootID() string {
	i.once.Do(func() {
		raw := make([]byte, 8)
		if _, err := rand.Read(raw); err != nil {
			i.bootID = fmt.Sprintf("%d", time.Now().UnixNano())
			return
		}
		i.bootID = hex.EncodeToString(raw)
	})
	return i.bootID
}

// Options configures identity loading.
type Options struct {
	// Dir is the directory holding device.json. Empty means DefaultDir.
	Dir string
	// Platform is used only when creating a new identity. An existing file's
	// platform always wins, because changing it would change device_id.
	Platform proto.Platform
	// Model is a human-facing hardware label and may change between releases.
	Model string
}

// ErrPlatformMismatch reports that the caller asked for a platform the stored
// identity was not created with. We refuse rather than rewrite, because
// rewriting would change device_id and orphan the pairing.
var ErrPlatformMismatch = errors.New("stored identity was created for a different platform")

// LoadOrCreate returns the Node's identity, generating it only when no identity
// exists yet. Calling it repeatedly is safe and always yields the same device.
func LoadOrCreate(options Options) (*Identity, error) {
	dir := options.Dir
	if dir == "" {
		dir = DefaultDir
	}
	platform := options.Platform
	if platform == "" {
		platform = proto.PlatformMock
	}
	path := filepath.Join(dir, FileName)

	existing, err := load(path)
	switch {
	case err == nil:
		if existing.Platform != platform {
			return nil, fmt.Errorf("%w: stored %q, requested %q", ErrPlatformMismatch, existing.Platform, platform)
		}
		if options.Model != "" {
			existing.Model = options.Model
		}
		return existing, nil
	case errors.Is(err, fs.ErrNotExist):
		// Fall through to creation.
	default:
		return nil, err
	}

	return create(dir, path, platform, options.Model)
}

func load(path string) (*Identity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var stored document
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("identity file %s is corrupt: %w", path, err)
	}
	seed, err := base64.StdEncoding.DecodeString(stored.PrivateSeed)
	if err != nil {
		return nil, fmt.Errorf("identity file %s has an unreadable key: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity file %s has a %d-byte seed, want %d", path, len(seed), ed25519.SeedSize)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)

	// The stored device_id is not trusted; it is recomputed. A file that was
	// hand-edited to claim another device's identifier is rejected here rather
	// than becoming a duplicate on the NAS.
	expected := proto.DeviceID(stored.Platform, public)
	if stored.DeviceID != expected {
		return nil, fmt.Errorf("identity file %s claims %q but its key derives %q", path, stored.DeviceID, expected)
	}
	return &Identity{
		DeviceID:   expected,
		Platform:   stored.Platform,
		Model:      stored.Model,
		PublicKey:  public,
		privateKey: private,
		CreatedAt:  stored.CreatedAt,
	}, nil
}

func create(dir, path string, platform proto.Platform, model string) (*Identity, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("create identity directory %s: %w", dir, err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate identity key: %w", err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	created := time.Now().UTC()

	stored := document{
		Version:     1,
		DeviceID:    proto.DeviceID(platform, public),
		Platform:    platform,
		Model:       model,
		PrivateSeed: base64.StdEncoding.EncodeToString(seed),
		PublicKey:   proto.EncodeKey(public),
		CreatedAt:   created,
	}
	if err := writeAtomic(path, stored); err != nil {
		return nil, err
	}
	return &Identity{
		DeviceID:   stored.DeviceID,
		Platform:   platform,
		Model:      model,
		PublicKey:  public,
		privateKey: private,
		CreatedAt:  created,
	}, nil
}

// writeAtomic writes through a temporary file and a rename so a power cut
// during first boot leaves either no identity or a complete one, never a
// half-written key that would fail to load and trigger regeneration.
func writeAtomic(path string, stored document) error {
	encoded, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("encode identity: %w", err)
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, encoded, filePerm); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("install identity: %w", err)
	}
	return nil
}
