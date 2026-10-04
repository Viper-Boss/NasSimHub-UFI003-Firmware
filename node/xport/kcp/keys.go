package kcp

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// The transport authentication key: where it comes from, what it is derived
// into, and how it is rotated and destroyed.
//
// # Why this key is not the device key
//
// The obvious shortcut - use the Ed25519 identity key as the HMAC key - is
// wrong in a way that is easy to miss, because it "works". Three separate
// problems:
//
//   - The identity key signs device_id itself and every authenticated API
//     request. Using the same secret as a MAC key in a second protocol means a
//     flaw in either one costs both, and cross-protocol attacks between a
//     signature scheme and a MAC are exactly the kind of thing that is found
//     years later.
//   - Ed25519 private keys are not uniformly random strings; they are seeds
//     with structure. HMAC does not care, but the habit of feeding key material
//     from one scheme into another is how real failures get built.
//   - An identity key cannot be rotated. It IS the device. A transport key that
//     cannot rotate means a compromised NAS backup is a permanent authenticator
//     for that device's UDP path, with no remedy short of a new device.
//
// So: a fresh random secret, generated per pairing, delivered over the already
// authenticated TLS channel, and HKDF-expanded into two directional MAC keys.
// It can be rotated whenever, and it is destroyed on unpair.
//
// # Directional keys
//
// kcp_mac_tx and kcp_mac_rx are different keys, derived with different HKDF
// info strings. With one shared key an attacker could reflect a captured packet
// back to its sender, and the sender's own MAC would verify it. Directional
// keys make a reflected packet fail authentication at the first check.
//
// Every primitive here is from the standard library: crypto/hkdf, crypto/hmac,
// crypto/sha256, crypto/rand. Nothing in this file implements cryptography.

// SecretSize is the length of a transport secret. 32 bytes is the natural size
// for an HMAC-SHA-256 key and leaves no question about entropy.
const SecretSize = 32

// MACKeySize is the length of a derived directional key.
const MACKeySize = 32

// hkdfSalt is a fixed, non-secret salt. HKDF's salt need not be secret; its
// purpose here is domain separation from any other HKDF use in the product.
var hkdfSalt = []byte("nassimhub-node/kcp-transport/v1")

// The two info strings. They differ, which is what makes the two keys differ.
const (
	infoCoreToNode = "kcp mac core-to-node"
	infoNodeToCore = "kcp mac node-to-core"
)

// Role says which end of the link a key schedule belongs to.
type Role string

const (
	// RoleNode is the device. It receives core-to-node and sends node-to-core.
	RoleNode Role = "node"
	// RoleCore is the NAS.
	RoleCore Role = "core"
)

// Errors this file produces.
var (
	// ErrNoSecret reports a missing or destroyed transport secret.
	ErrNoSecret = errors.New("kcp: no transport secret")
	// ErrSecretSize reports a secret of the wrong length.
	ErrSecretSize = errors.New("kcp: transport secret must be 32 bytes")
	// ErrUnknownKeyID reports a packet naming a key this end does not hold.
	ErrUnknownKeyID = errors.New("kcp: unknown transport key id")
	// ErrEpoch reports a packet from an epoch that is no longer accepted.
	ErrEpoch = errors.New("kcp: packet epoch is not accepted")
)

// TransportSecret is the shared secret for one pairing, at one epoch.
//
// Epoch and KeyID are both present and they are not redundant. KeyID names WHICH
// secret; Epoch says which generation of that pairing's keys it belongs to, and
// it is carried in every packet so that a peer holding an old key learns
// immediately rather than failing MAC checks silently.
type TransportSecret struct {
	KeyID    string    `json:"key_id"`
	Epoch    uint32    `json:"epoch"`
	Secret   []byte    `json:"-"`
	IssuedAt time.Time `json:"issued_at"`
}

// EncodedSecret is the wire form, for the one hop where the secret travels: the
// authenticated TLS channel, right after pairing.
type EncodedSecret struct {
	KeyID    string    `json:"key_id"`
	Epoch    uint32    `json:"epoch"`
	Secret   string    `json:"secret"`
	IssuedAt time.Time `json:"issued_at"`
}

// NewTransportSecret generates one.
func NewTransportSecret(epoch uint32) (TransportSecret, error) {
	secret := make([]byte, SecretSize)
	if _, err := rand.Read(secret); err != nil {
		return TransportSecret{}, err
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return TransportSecret{}, err
	}
	return TransportSecret{
		KeyID:    base64.RawURLEncoding.EncodeToString(id),
		Epoch:    epoch,
		Secret:   secret,
		IssuedAt: time.Now().UTC(),
	}, nil
}

// Encode prepares a secret for its single trip over TLS.
func (s TransportSecret) Encode() EncodedSecret {
	return EncodedSecret{
		KeyID:    s.KeyID,
		Epoch:    s.Epoch,
		Secret:   base64.StdEncoding.EncodeToString(s.Secret),
		IssuedAt: s.IssuedAt,
	}
}

// Decode parses one.
func (e EncodedSecret) Decode() (TransportSecret, error) {
	secret, err := base64.StdEncoding.DecodeString(e.Secret)
	if err != nil {
		return TransportSecret{}, fmt.Errorf("%w: not base64", ErrSecretSize)
	}
	if len(secret) != SecretSize {
		return TransportSecret{}, fmt.Errorf("%w: got %d", ErrSecretSize, len(secret))
	}
	if e.KeyID == "" {
		return TransportSecret{}, errors.New("kcp: a transport secret needs a key id")
	}
	return TransportSecret{
		KeyID: e.KeyID, Epoch: e.Epoch, Secret: secret, IssuedAt: e.IssuedAt,
	}, nil
}

// Destroy overwrites the secret in place.
//
// Go's garbage collector can copy memory, so this is not a guarantee that no
// byte of the secret survives anywhere. It is still worth doing: it bounds the
// window in which the live object holds it, and it makes "unpair destroys the
// secret" something a test can check rather than something the code merely
// intends.
func (s *TransportSecret) Destroy() {
	for i := range s.Secret {
		s.Secret[i] = 0
	}
	s.Secret = nil
	s.KeyID = ""
	s.Epoch = 0
}

// Zero reports whether this secret has been destroyed or never set.
func (s TransportSecret) Zero() bool { return len(s.Secret) == 0 }

// MACKeys is one end's pair of directional keys.
type MACKeys struct {
	KeyID string
	Epoch uint32
	TX    []byte
	RX    []byte
}

// Derive expands a transport secret into the directional keys for one role.
//
// The epoch is mixed into the HKDF info, so rotating the epoch produces
// unrelated keys from the same secret. That is what makes a rekey cheap: no new
// secret has to travel, and a captured packet from an old epoch cannot be
// replayed into a new one because the key that would authenticate it no longer
// derives.
func Derive(secret TransportSecret, role Role) (MACKeys, error) {
	if len(secret.Secret) != SecretSize {
		return MACKeys{}, ErrSecretSize
	}
	var epoch [4]byte
	binary.BigEndian.PutUint32(epoch[:], secret.Epoch)
	suffix := " epoch=" + base64.RawURLEncoding.EncodeToString(epoch[:])

	coreToNode, err := hkdf.Key(sha256.New, secret.Secret, hkdfSalt, infoCoreToNode+suffix, MACKeySize)
	if err != nil {
		return MACKeys{}, err
	}
	nodeToCore, err := hkdf.Key(sha256.New, secret.Secret, hkdfSalt, infoNodeToCore+suffix, MACKeySize)
	if err != nil {
		return MACKeys{}, err
	}
	keys := MACKeys{KeyID: secret.KeyID, Epoch: secret.Epoch}
	switch role {
	case RoleCore:
		keys.TX, keys.RX = coreToNode, nodeToCore
	default:
		keys.TX, keys.RX = nodeToCore, coreToNode
	}
	return keys, nil
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

// DefaultGrace is how long an old epoch keeps being accepted after a rekey.
//
// Long enough that packets already on the wire when the rotation happened are
// not lost, short enough that a stolen old key is useless almost immediately.
// Thirty seconds comfortably exceeds any plausible one-way delay on a link this
// product is used over, including a bad cellular one.
const DefaultGrace = 30 * time.Second

// KeyRing holds the keys one end will accept, which is the current epoch and,
// briefly, the one before it.
//
// Exactly two. A ring that kept every epoch would mean a key compromised at any
// point in the device's life remains an authenticator forever, which defeats
// the purpose of rotating at all.
type KeyRing struct {
	mu      sync.RWMutex
	role    Role
	current MACKeys
	// previous is retained until previousUntil, then dropped.
	previous      MACKeys
	previousUntil time.Time
	grace         time.Duration
	now           func() time.Time
}

// NewKeyRing builds a ring holding one secret.
func NewKeyRing(secret TransportSecret, role Role) (*KeyRing, error) {
	keys, err := Derive(secret, role)
	if err != nil {
		return nil, err
	}
	return &KeyRing{role: role, current: keys, grace: DefaultGrace, now: time.Now}, nil
}

// SetGrace changes the grace window, for tests.
func (r *KeyRing) SetGrace(grace time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.grace = grace
}

// SetClock injects a clock, for tests.
func (r *KeyRing) SetClock(now func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
}

// Rotate installs a new secret and keeps the old one for the grace window.
func (r *KeyRing) Rotate(secret TransportSecret) error {
	keys, err := Derive(secret, r.role)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.previous = r.current
	r.previousUntil = r.now().Add(r.grace)
	r.current = keys
	return nil
}

// Sending reports the keys to send with, which are always the current ones. A
// rotation takes effect immediately for sending; the grace window is about what
// is ACCEPTED, not what is produced.
func (r *KeyRing) Sending() (MACKeys, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.current.TX) == 0 {
		return MACKeys{}, ErrNoSecret
	}
	return r.current, nil
}

// Accepting returns the receive key for a packet naming a key id and epoch.
//
// The lookup is by BOTH, and a packet that names the current key id with an old
// epoch is checked against the old key rather than the current one - which is
// what makes an expired epoch fail authentication instead of being tried
// against a key that would never verify it anyway.
func (r *KeyRing) Accepting(keyID string, epoch uint32) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.current.RX) == 0 {
		return nil, ErrNoSecret
	}
	if r.current.KeyID == keyID && r.current.Epoch == epoch {
		return r.current.RX, nil
	}
	if len(r.previous.RX) > 0 && r.previous.KeyID == keyID && r.previous.Epoch == epoch {
		if r.now().Before(r.previousUntil) {
			return r.previous.RX, nil
		}
		return nil, fmt.Errorf("%w: epoch %d expired", ErrEpoch, epoch)
	}
	if r.current.KeyID != keyID {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKeyID, keyID)
	}
	return nil, fmt.Errorf("%w: epoch %d, current is %d", ErrEpoch, epoch, r.current.Epoch)
}

// Destroy drops every key. Called on unpair and on Node removal.
func (r *KeyRing) Destroy() {
	r.mu.Lock()
	defer r.mu.Unlock()
	zero(r.current.TX)
	zero(r.current.RX)
	zero(r.previous.TX)
	zero(r.previous.RX)
	r.current = MACKeys{}
	r.previous = MACKeys{}
	r.previousUntil = time.Time{}
}

// Empty reports whether the ring holds nothing, which is what a destroyed ring
// looks like and what a test asserts after unpair.
func (r *KeyRing) Empty() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.current.TX) == 0 && len(r.current.RX) == 0
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
