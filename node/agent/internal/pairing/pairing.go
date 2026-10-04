// Package pairing owns the Node's trust relationship with exactly one
// NasSimHub Core, plus the short-lived sessions derived from it.
//
// The rule the whole package exists to enforce: once a Node is paired, every
// other Core is refused. A SIM Node carries a real phone number; a second NAS
// on the same LAN quietly adopting it would be able to read verification codes.
// So the second Core gets a conflict, and the user must unpair deliberately.
package pairing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
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

// FileName is the trust document inside the identity directory.
const FileName = "pairing.json"

const (
	filePerm fs.FileMode = 0o600
	dirPerm  fs.FileMode = 0o700
)

// DefaultSessionTTL bounds how long a bearer token stays usable. Short enough
// that a token captured off a plaintext USB link expires quickly, long enough
// that a Node under heavy polling is not re-signing constantly.
const DefaultSessionTTL = 30 * time.Minute

// nonceWindow is how long a signed request's nonce is remembered for replay
// rejection. It matches the clock-skew allowance, because a nonce cannot be
// replayed once its timestamp falls outside that window anyway.
const nonceWindow = proto.MaxClockSkew

// maxNonces caps the replay cache.
//
// Age-based pruning alone is not a bound: an attacker - or a buggy Core in a
// retry loop - can present thousands of distinct nonces inside one window, and
// on a device with 256 MB of RAM an unbounded map is a denial-of-service
// primitive rather than a leak that eventually resolves. When the cap is
// reached the oldest entries are discarded first, which cannot open a replay
// hole: a discarded nonce is only reusable while its own timestamp is still
// inside the skew window, and refilling the cache that fast requires already
// holding the Core's private key.
const maxNonces = 4096

// maxSessions caps outstanding bearer tokens for one Node.
//
// Only one Core ever owns a Node, so a healthy system holds one or two. A
// larger number means something is minting and discarding tokens, and the cap
// stops that from growing without limit.
const maxSessions = 64

var (
	// ErrAlreadyPaired is returned when a second Core attempts to pair.
	ErrAlreadyPaired = errors.New("node is already paired with another core")
	// ErrNotPaired is returned when a privileged operation is attempted on an
	// unpaired Node.
	ErrNotPaired = errors.New("node is not paired")
	// ErrUnknownCore is returned when a signature names a Core this Node does
	// not trust.
	ErrUnknownCore = errors.New("core is not the paired owner")
	// ErrBadSignature is returned when verification fails.
	ErrBadSignature = errors.New("request signature is not valid")
	// ErrStaleRequest is returned for clock skew beyond the allowance.
	ErrStaleRequest = errors.New("request timestamp is outside the accepted window")
	// ErrReplay is returned when a nonce is presented twice.
	ErrReplay = errors.New("request nonce was already used")
	// ErrBadSession is returned for an unknown or expired bearer token.
	ErrBadSession = errors.New("session token is not valid")
)

type document struct {
	Version       int                `json:"version"`
	State         proto.PairingState `json:"state"`
	CoreID        string             `json:"core_id,omitempty"`
	CoreName      string             `json:"core_name,omitempty"`
	CorePublicKey string             `json:"core_public_key,omitempty"`
	PairedAt      time.Time          `json:"paired_at,omitempty"`
}

type session struct {
	expiresAt time.Time
}

// Store is the Node's pairing state. It is safe for concurrent use.
type Store struct {
	path     string
	deviceID string
	ttl      time.Duration
	now      func() time.Time

	mu       sync.Mutex
	state    proto.PairingState
	coreID   string
	coreName string
	coreKey  ed25519.PublicKey
	pairedAt time.Time
	sessions map[string]session
	nonces   map[string]time.Time
}

// Options configures a Store.
type Options struct {
	Dir        string
	DeviceID   string
	SessionTTL time.Duration
	// Now is injectable so tests can exercise expiry and skew without sleeping.
	Now func() time.Time
}

// Open loads the Node's pairing state, creating an unpaired one if none exists.
func Open(options Options) (*Store, error) {
	if options.DeviceID == "" {
		return nil, errors.New("pairing store requires the device id")
	}
	ttl := options.SessionTTL
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	store := &Store{
		path:     filepath.Join(options.Dir, FileName),
		deviceID: options.DeviceID,
		ttl:      ttl,
		now:      now,
		state:    proto.PairingUnpaired,
		sessions: map[string]session{},
		nonces:   map[string]time.Time{},
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read pairing state: %w", err)
	}
	var stored document
	if err := json.Unmarshal(raw, &stored); err != nil {
		return fmt.Errorf("pairing state %s is corrupt: %w", s.path, err)
	}
	if stored.State != proto.PairingPaired {
		return nil
	}
	key, err := proto.DecodePublicKey(stored.CorePublicKey)
	if err != nil {
		return fmt.Errorf("pairing state %s has an unreadable core key: %w", s.path, err)
	}
	s.state = proto.PairingPaired
	s.coreID = stored.CoreID
	s.coreName = stored.CoreName
	s.coreKey = key
	s.pairedAt = stored.PairedAt
	return nil
}

func (s *Store) persistLocked() error {
	stored := document{Version: 1, State: s.state}
	if s.state == proto.PairingPaired {
		stored.CoreID = s.coreID
		stored.CoreName = s.coreName
		stored.CorePublicKey = proto.EncodeKey(s.coreKey)
		stored.PairedAt = s.pairedAt
	}
	encoded, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("encode pairing state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), dirPerm); err != nil {
		return fmt.Errorf("create pairing directory: %w", err)
	}
	temporary := s.path + ".tmp"
	if err := os.WriteFile(temporary, encoded, filePerm); err != nil {
		return fmt.Errorf("write pairing state: %w", err)
	}
	if err := os.Rename(temporary, s.path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("install pairing state: %w", err)
	}
	return nil
}

// State reports the current pairing state.
func (s *Store) State() proto.PairingState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// OwnerID reports the paired Core's identifier, or the empty string.
func (s *Store) OwnerID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.coreID
}

// OwnerFingerprint reports a short form of the owner's key for display.
func (s *Store) OwnerFingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != proto.PairingPaired {
		return ""
	}
	return proto.CoreFingerprint(s.coreKey)
}

// SignedRequest is everything needed to authenticate a signed call.
type SignedRequest struct {
	CoreID    string
	Timestamp string
	Nonce     string
	Signature string
	Method    string
	Path      string
	Body      []byte
}

// Pair binds this Node to a Core. The request must be signed with the private
// half of the key it carries, which is what proves the caller is the Core it
// claims to be rather than a bystander replaying a discovery document.
func (s *Store) Pair(request proto.PairRequest, signed SignedRequest) (proto.Session, error) {
	key, err := proto.DecodePublicKey(request.CorePublicKey)
	if err != nil {
		return proto.Session{}, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if request.CoreID == "" {
		return proto.Session{}, errors.New("pair request must carry a core id")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.verifyFreshnessLocked(signed); err != nil {
		return proto.Session{}, err
	}
	if !verifySignature(key, signed) {
		return proto.Session{}, ErrBadSignature
	}

	if s.state == proto.PairingPaired {
		// Re-pairing with the same owner is idempotent: a Core that lost its
		// local record but kept its key may recover without a user unpair.
		if s.coreID == request.CoreID && s.coreKey.Equal(key) {
			return s.issueSessionLocked(), nil
		}
		return proto.Session{}, ErrAlreadyPaired
	}

	s.state = proto.PairingPaired
	s.coreID = request.CoreID
	s.coreName = request.CoreName
	s.coreKey = key
	s.pairedAt = s.now().UTC()
	if err := s.persistLocked(); err != nil {
		// Roll back in memory so a failed write does not leave the Node
		// believing it is paired while the disk says otherwise.
		s.state = proto.PairingUnpaired
		s.coreID, s.coreName, s.coreKey = "", "", nil
		return proto.Session{}, err
	}
	return s.issueSessionLocked(), nil
}

// NewSession mints a bearer token for the already-paired owner. The request
// must be signed, so a leaked bearer token cannot be used to mint more.
func (s *Store) NewSession(coreID string, signed SignedRequest) (proto.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != proto.PairingPaired {
		return proto.Session{}, ErrNotPaired
	}
	if coreID != s.coreID || signed.CoreID != s.coreID {
		return proto.Session{}, ErrUnknownCore
	}
	if err := s.verifyFreshnessLocked(signed); err != nil {
		return proto.Session{}, err
	}
	if !verifySignature(s.coreKey, signed) {
		return proto.Session{}, ErrBadSignature
	}
	return s.issueSessionLocked(), nil
}

// Unpair releases ownership and revokes every outstanding session.
func (s *Store) Unpair() (proto.PairingState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != proto.PairingPaired {
		return s.state, ErrNotPaired
	}
	s.state = proto.PairingUnpaired
	s.coreID, s.coreName, s.coreKey = "", "", nil
	s.pairedAt = time.Time{}
	s.sessions = map[string]session{}
	if err := s.persistLocked(); err != nil {
		return s.state, err
	}
	return s.state, nil
}

// FactoryResetPairing clears the trust relationship without touching the
// device's cryptographic identity, so device_id survives and the Node can be
// re-adopted without appearing as a new device.
//
// confirm must equal this Node's device_id. This is software-only by design;
// no physical gesture is bound to it.
func (s *Store) FactoryResetPairing(confirm string) (proto.PairingState, error) {
	if subtle.ConstantTimeCompare([]byte(confirm), []byte(s.deviceID)) != 1 {
		return s.State(), fmt.Errorf("confirmation must be this node's device id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = proto.PairingUnpaired
	s.coreID, s.coreName, s.coreKey = "", "", nil
	s.pairedAt = time.Time{}
	s.sessions = map[string]session{}
	s.nonces = map[string]time.Time{}
	if err := s.persistLocked(); err != nil {
		return s.state, err
	}
	return s.state, nil
}

// VerifySession authenticates a bearer token.
func (s *Store) VerifySession(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != proto.PairingPaired {
		return ErrNotPaired
	}
	found, ok := s.sessions[token]
	if !ok {
		return ErrBadSession
	}
	if !s.now().Before(found.expiresAt) {
		delete(s.sessions, token)
		return ErrBadSession
	}
	return nil
}

func (s *Store) issueSessionLocked() proto.Session {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		// A token we cannot randomise is worse than no token; returning an
		// already-expired session forces the caller to retry rather than
		// accepting a predictable credential.
		return proto.Session{Token: "", ExpiresAt: s.now().Add(-time.Second)}
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expiry := s.now().Add(s.ttl).UTC()
	s.pruneSessionsLocked()
	s.sessions[token] = session{expiresAt: expiry}
	return proto.Session{Token: token, ExpiresAt: expiry}
}

func (s *Store) pruneSessionsLocked() {
	now := s.now()
	for token, found := range s.sessions {
		if !now.Before(found.expiresAt) {
			delete(s.sessions, token)
		}
	}
	// Expiry alone does not bound the map: tokens minted faster than the TTL
	// are all simultaneously valid. Past the cap the soonest-expiring live
	// tokens are dropped first, so an attacker minting tokens evicts their own
	// rather than the owner's most recently issued one.
	for len(s.sessions) >= maxSessions {
		var earliestToken string
		var earliestExpiry time.Time
		for token, found := range s.sessions {
			if earliestToken == "" || found.expiresAt.Before(earliestExpiry) {
				earliestToken, earliestExpiry = token, found.expiresAt
			}
		}
		if earliestToken == "" {
			return
		}
		delete(s.sessions, earliestToken)
	}
}

func (s *Store) verifyFreshnessLocked(signed SignedRequest) error {
	stamp, err := proto.ParseTimestamp(signed.Timestamp)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStaleRequest, err)
	}
	now := s.now()
	if difference := now.Sub(stamp); difference > proto.MaxClockSkew || difference < -proto.MaxClockSkew {
		return ErrStaleRequest
	}
	if signed.Nonce == "" {
		return fmt.Errorf("%w: nonce is required", ErrBadSignature)
	}
	for nonce, seen := range s.nonces {
		if now.Sub(seen) > nonceWindow {
			delete(s.nonces, nonce)
		}
	}
	if _, used := s.nonces[signed.Nonce]; used {
		return ErrReplay
	}
	s.evictOldestNoncesLocked()
	s.nonces[signed.Nonce] = now
	return nil
}

// evictOldestNoncesLocked enforces maxNonces by dropping the oldest entries.
func (s *Store) evictOldestNoncesLocked() {
	if len(s.nonces) < maxNonces {
		return
	}
	// Drop a batch rather than exactly one, so a Node under sustained pressure
	// is not doing an O(n) scan on every single request.
	target := len(s.nonces) - maxNonces + maxNonces/4 + 1
	for target > 0 {
		var oldestNonce string
		var oldestSeen time.Time
		for nonce, seen := range s.nonces {
			if oldestNonce == "" || seen.Before(oldestSeen) {
				oldestNonce, oldestSeen = nonce, seen
			}
		}
		if oldestNonce == "" {
			return
		}
		delete(s.nonces, oldestNonce)
		target--
	}
}

func verifySignature(key ed25519.PublicKey, signed SignedRequest) bool {
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return false
	}
	canonical := proto.SigningString(signed.Method, signed.Path, signed.Timestamp, signed.Nonce, signed.Body)
	return ed25519.Verify(key, canonical, signature)
}

// NonceCacheSize reports the current replay-cache size. It exists so a test can
// assert the cap holds; nothing in the running system reads it.
func (s *Store) NonceCacheSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.nonces)
}

// SessionCount reports outstanding bearer tokens, for the same reason.
func (s *Store) SessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}
