// Package transportkey holds the Node's KCP transport secret: its lifecycle,
// its file, and its destruction.
//
// # Why this is a separate thing from the device identity
//
// The device's Ed25519 key IS the device - it derives device_id, it signs the
// TLS certificate, it cannot be rotated and must never be reused for anything
// else. The transport secret is the opposite in every respect: it is a plain
// random string, it exists only to authenticate UDP packets, it rotates
// whenever anyone wants, and it is destroyed when the pairing ends.
//
// Keeping them in different files with different lifecycles is what makes that
// difference enforceable rather than merely intended. A single "keys" store
// would eventually have something reach for the wrong one.
//
// # How it reaches the Core
//
// Over the pairing-authenticated TLS channel, and only there. The Core asks for
// it with an authenticated request; the Node answers with the current secret or
// a fresh one. It never travels over UDP, never appears in a diagnostics
// bundle, and never appears in a log - there are tests for the last two.
package transportkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/human-agent65535/nassimhub-node/xport/kcp"
)

// FileName is where the secret lives, beside the pairing state.
const FileName = "transport-key.json"

// FileMode is owner-read-write only. The same mode the device key uses: this
// secret authenticates every packet on the UDP path, and a world-readable copy
// would make the mode of the device key beside it pointless.
const FileMode = 0o600

// ErrNoSecret reports that no secret exists, which is the correct state for a
// Node that has never been paired or that has just been reset.
var ErrNoSecret = errors.New("transportkey: no transport secret")

// Store owns the secret on disk and in memory.
type Store struct {
	mu     sync.Mutex
	dir    string
	secret kcp.TransportSecret
	ring   *kcp.KeyRing
}

type document struct {
	Version int               `json:"version"`
	Secret  kcp.EncodedSecret `json:"secret"`
}

// Open loads the secret, generating one if there is none.
//
// Generating at start-up rather than at pairing time is deliberate: the KCP
// listener needs a key ring the moment it opens, and a Node that could only
// authenticate packets after someone paired with it would have to restart its
// listener mid-life. An unpaired Node's secret is simply a secret nobody has
// been given, which protects exactly as well as not having one.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("transportkey: a state directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	store := &Store{dir: dir}
	path := store.path()

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var stored document
		if err := json.Unmarshal(raw, &stored); err != nil {
			// A half-written file reads as "no secret", and a new one is
			// generated. The alternative - refusing to start - would brick a
			// device over a file that can be safely recreated, since the Core
			// re-fetches it whenever authentication fails.
			break
		}
		secret, err := stored.Secret.Decode()
		if err != nil {
			break
		}
		store.secret = secret
	case errors.Is(err, os.ErrNotExist):
		// Nothing yet.
	default:
		return nil, err
	}

	if store.secret.Zero() {
		if err := store.regenerateLocked(1); err != nil {
			return nil, err
		}
	}
	ring, err := kcp.NewKeyRing(store.secret, kcp.RoleNode)
	if err != nil {
		return nil, err
	}
	store.ring = ring
	return store, nil
}

func (s *Store) path() string { return filepath.Join(s.dir, FileName) }

func (s *Store) regenerateLocked(epoch uint32) error {
	secret, err := kcp.NewTransportSecret(epoch)
	if err != nil {
		return err
	}
	s.secret = secret
	return s.persistLocked()
}

func (s *Store) persistLocked() error {
	raw, err := json.MarshalIndent(document{Version: 1, Secret: s.secret.Encode()}, "", "  ")
	if err != nil {
		return err
	}
	temporary := s.path() + ".tmp"
	if err := os.WriteFile(temporary, raw, FileMode); err != nil {
		return err
	}
	// Rename rather than write in place, so a power cut during the write
	// leaves the previous secret rather than a truncated file.
	return os.Rename(temporary, s.path())
}

// Ring is the key ring the transport authenticates with.
func (s *Store) Ring() *kcp.KeyRing {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ring
}

// Current returns the secret to hand to the Core over TLS.
func (s *Store) Current() (kcp.TransportSecret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secret.Zero() {
		return kcp.TransportSecret{}, ErrNoSecret
	}
	return s.secret, nil
}

// Rotate issues a new secret at the next epoch and installs it in the ring.
//
// The previous epoch stays acceptable for the ring's grace window, so packets
// in flight at the moment of rotation are not lost. The Core is expected to
// fetch the new secret over TLS; until it does, its packets authenticate under
// the old epoch, which is exactly what the grace window is for.
func (s *Store) Rotate() (kcp.TransportSecret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secret.Zero() {
		if err := s.regenerateLocked(1); err != nil {
			return kcp.TransportSecret{}, err
		}
	} else {
		epoch := s.secret.Epoch + 1
		if err := s.regenerateLocked(epoch); err != nil {
			return kcp.TransportSecret{}, err
		}
	}
	if s.ring == nil {
		ring, err := kcp.NewKeyRing(s.secret, kcp.RoleNode)
		if err != nil {
			return kcp.TransportSecret{}, err
		}
		s.ring = ring
		return s.secret, nil
	}
	if err := s.ring.Rotate(s.secret); err != nil {
		return kcp.TransportSecret{}, err
	}
	return s.secret, nil
}

// Destroy erases the secret, in memory and on disk.
//
// Called on unpair and on factory reset. After this the Node cannot
// authenticate a single KCP packet from the Core that was paired with it, which
// is the point: unpairing must revoke the transport, not merely forget who the
// owner was.
//
// A fresh secret is generated afterwards so the listener keeps working for
// whoever pairs next. That is not a weakening: the new secret has never been
// given to anybody.
func (s *Store) Destroy() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.secret.Destroy()
	if s.ring != nil {
		s.ring.Destroy()
	}
	if err := os.Remove(s.path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("transportkey: could not remove %s: %w", s.path(), err)
	}
	if err := s.regenerateLocked(1); err != nil {
		return err
	}
	ring, err := kcp.NewKeyRing(s.secret, kcp.RoleNode)
	if err != nil {
		return err
	}
	s.ring = ring
	return nil
}

// KeyID and Epoch report what is current, for diagnostics.
//
// The key ID is an opaque random label, not key material: it names which secret
// is in use without revealing any of it, which is what lets a support bundle
// say "the Node is on key abc123 epoch 4 and the NAS is on epoch 3" - the most
// useful sentence there is when a link stops authenticating.
func (s *Store) KeyID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secret.KeyID
}

// Epoch reports the current epoch.
func (s *Store) Epoch() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secret.Epoch
}
