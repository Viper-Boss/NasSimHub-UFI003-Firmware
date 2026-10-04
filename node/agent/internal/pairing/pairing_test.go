package pairing

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

const testDeviceID = "NSH-410-A83F29"

type core struct {
	id      string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
	counter int
}

func newCore(t *testing.T, id string) *core {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate core key: %v", err)
	}
	return &core{id: id, public: public, private: private}
}

func (c *core) sign(method, path string, body []byte, at time.Time) SignedRequest {
	c.counter++
	stamp := proto.FormatTimestamp(at)
	nonce := fmt.Sprintf("%s-%d", c.id, c.counter)
	canonical := proto.SigningString(method, path, stamp, nonce, body)
	signature := ed25519.Sign(c.private, canonical)
	return SignedRequest{
		CoreID:    c.id,
		Timestamp: stamp,
		Nonce:     nonce,
		Signature: base64.StdEncoding.EncodeToString(signature),
		Method:    method,
		Path:      path,
		Body:      body,
	}
}

func (c *core) pairRequest() proto.PairRequest {
	return proto.PairRequest{CoreID: c.id, CoreName: "test-nas", CorePublicKey: proto.EncodeKey(c.public)}
}

type clock struct{ at time.Time }

func (c *clock) now() time.Time { return c.at }

func newStore(t *testing.T, dir string, at *clock) *Store {
	t.Helper()
	store, err := Open(Options{Dir: dir, DeviceID: testDeviceID, Now: at.now})
	if err != nil {
		t.Fatalf("open pairing store: %v", err)
	}
	return store
}

func TestFirstPairSucceedsAndYieldsSession(t *testing.T) {
	at := &clock{at: time.Now().UTC()}
	store := newStore(t, t.TempDir(), at)
	nas := newCore(t, "core-a")

	if store.State() != proto.PairingUnpaired {
		t.Fatal("a fresh node must start unpaired")
	}
	session, err := store.Pair(nas.pairRequest(), nas.sign("POST", "/v1/pair", nil, at.at))
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if session.Token == "" {
		t.Fatal("pairing did not return a session token")
	}
	if store.State() != proto.PairingPaired {
		t.Fatal("node did not reach PAIRED")
	}
	if err := store.VerifySession(session.Token); err != nil {
		t.Fatalf("issued session was rejected: %v", err)
	}
}

func TestSecondCoreIsRefused(t *testing.T) {
	at := &clock{at: time.Now().UTC()}
	store := newStore(t, t.TempDir(), at)
	owner := newCore(t, "core-a")
	intruder := newCore(t, "core-b")

	if _, err := store.Pair(owner.pairRequest(), owner.sign("POST", "/v1/pair", nil, at.at)); err != nil {
		t.Fatalf("owner pair: %v", err)
	}
	_, err := store.Pair(intruder.pairRequest(), intruder.sign("POST", "/v1/pair", nil, at.at))
	if !errors.Is(err, ErrAlreadyPaired) {
		t.Fatalf("expected ErrAlreadyPaired, got %v", err)
	}
	if store.OwnerID() != "core-a" {
		t.Fatal("a refused pairing changed the owner")
	}
}

func TestRepairWithSameOwnerIsIdempotent(t *testing.T) {
	at := &clock{at: time.Now().UTC()}
	store := newStore(t, t.TempDir(), at)
	owner := newCore(t, "core-a")

	if _, err := store.Pair(owner.pairRequest(), owner.sign("POST", "/v1/pair", nil, at.at)); err != nil {
		t.Fatalf("pair: %v", err)
	}
	second, err := store.Pair(owner.pairRequest(), owner.sign("POST", "/v1/pair", nil, at.at))
	if err != nil {
		t.Fatalf("re-pair with same owner should succeed: %v", err)
	}
	if second.Token == "" {
		t.Fatal("re-pair did not return a session")
	}
}

func TestPairingSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	at := &clock{at: time.Now().UTC()}
	owner := newCore(t, "core-a")

	store := newStore(t, dir, at)
	if _, err := store.Pair(owner.pairRequest(), owner.sign("POST", "/v1/pair", nil, at.at)); err != nil {
		t.Fatalf("pair: %v", err)
	}
	fingerprint := store.OwnerFingerprint()

	reopened := newStore(t, dir, at)
	if reopened.State() != proto.PairingPaired {
		t.Fatal("pairing did not survive restart")
	}
	if reopened.OwnerID() != "core-a" {
		t.Fatal("owner did not survive restart")
	}
	if reopened.OwnerFingerprint() != fingerprint {
		t.Fatal("owner key did not survive restart")
	}
	// Sessions are process-local and must not survive; a restarted Node forces
	// the Core to re-authenticate with its key.
	if err := reopened.VerifySession("anything"); err == nil {
		t.Fatal("a session survived a restart")
	}
}

func TestForgedSignatureIsRejected(t *testing.T) {
	at := &clock{at: time.Now().UTC()}
	store := newStore(t, t.TempDir(), at)
	owner := newCore(t, "core-a")
	impostor := newCore(t, "core-a")

	// The impostor claims the owner's id and public key but signs with its own
	// private key.
	signed := impostor.sign("POST", "/v1/pair", nil, at.at)
	_, err := store.Pair(owner.pairRequest(), signed)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
	if store.State() != proto.PairingUnpaired {
		t.Fatal("a forged request paired the node")
	}
}

func TestReplayedNonceIsRejected(t *testing.T) {
	at := &clock{at: time.Now().UTC()}
	store := newStore(t, t.TempDir(), at)
	owner := newCore(t, "core-a")

	signed := owner.sign("POST", "/v1/pair", nil, at.at)
	if _, err := store.Pair(owner.pairRequest(), signed); err != nil {
		t.Fatalf("pair: %v", err)
	}
	_, err := store.NewSession(owner.id, signed)
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ErrReplay, got %v", err)
	}
}

func TestStaleTimestampIsRejected(t *testing.T) {
	at := &clock{at: time.Now().UTC()}
	store := newStore(t, t.TempDir(), at)
	owner := newCore(t, "core-a")

	old := at.at.Add(-2 * proto.MaxClockSkew)
	_, err := store.Pair(owner.pairRequest(), owner.sign("POST", "/v1/pair", nil, old))
	if !errors.Is(err, ErrStaleRequest) {
		t.Fatalf("expected ErrStaleRequest, got %v", err)
	}
}

func TestSessionExpires(t *testing.T) {
	at := &clock{at: time.Now().UTC()}
	store, err := Open(Options{Dir: t.TempDir(), DeviceID: testDeviceID, SessionTTL: time.Minute, Now: at.now})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	owner := newCore(t, "core-a")
	session, err := store.Pair(owner.pairRequest(), owner.sign("POST", "/v1/pair", nil, at.at))
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if err := store.VerifySession(session.Token); err != nil {
		t.Fatalf("fresh session rejected: %v", err)
	}
	at.at = at.at.Add(90 * time.Second)
	if err := store.VerifySession(session.Token); !errors.Is(err, ErrBadSession) {
		t.Fatalf("expected ErrBadSession after expiry, got %v", err)
	}
}

func TestUnpairRevokesSessions(t *testing.T) {
	at := &clock{at: time.Now().UTC()}
	store := newStore(t, t.TempDir(), at)
	owner := newCore(t, "core-a")
	session, err := store.Pair(owner.pairRequest(), owner.sign("POST", "/v1/pair", nil, at.at))
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if _, err := store.Unpair(); err != nil {
		t.Fatalf("unpair: %v", err)
	}
	if err := store.VerifySession(session.Token); err == nil {
		t.Fatal("a session survived unpairing")
	}
	if store.State() != proto.PairingUnpaired {
		t.Fatal("node did not return to UNPAIRED")
	}
	// A different Core may now adopt the Node.
	other := newCore(t, "core-b")
	if _, err := store.Pair(other.pairRequest(), other.sign("POST", "/v1/pair", nil, at.at)); err != nil {
		t.Fatalf("re-pair after unpair: %v", err)
	}
}

func TestFactoryResetRequiresDeviceIDAndKeepsIdentity(t *testing.T) {
	at := &clock{at: time.Now().UTC()}
	store := newStore(t, t.TempDir(), at)
	owner := newCore(t, "core-a")
	if _, err := store.Pair(owner.pairRequest(), owner.sign("POST", "/v1/pair", nil, at.at)); err != nil {
		t.Fatalf("pair: %v", err)
	}
	if _, err := store.FactoryResetPairing("NSH-410-WRONG"); err == nil {
		t.Fatal("factory reset accepted the wrong device id")
	}
	if store.State() != proto.PairingPaired {
		t.Fatal("a refused factory reset unpaired the node")
	}
	state, err := store.FactoryResetPairing(testDeviceID)
	if err != nil {
		t.Fatalf("factory reset: %v", err)
	}
	if state != proto.PairingUnpaired {
		t.Fatalf("factory reset left state %s", state)
	}
}

func TestSessionMintingRequiresTheOwner(t *testing.T) {
	at := &clock{at: time.Now().UTC()}
	store := newStore(t, t.TempDir(), at)
	owner := newCore(t, "core-a")
	stranger := newCore(t, "core-b")
	if _, err := store.Pair(owner.pairRequest(), owner.sign("POST", "/v1/pair", nil, at.at)); err != nil {
		t.Fatalf("pair: %v", err)
	}
	_, err := store.NewSession(stranger.id, stranger.sign("POST", "/v1/session", nil, at.at))
	if !errors.Is(err, ErrUnknownCore) {
		t.Fatalf("expected ErrUnknownCore, got %v", err)
	}
	if _, err := store.NewSession(owner.id, owner.sign("POST", "/v1/session", nil, at.at)); err != nil {
		t.Fatalf("owner session: %v", err)
	}
}

func TestUnpairedNodeIssuesNoSessions(t *testing.T) {
	at := &clock{at: time.Now().UTC()}
	store := newStore(t, t.TempDir(), at)
	owner := newCore(t, "core-a")
	_, err := store.NewSession(owner.id, owner.sign("POST", "/v1/session", nil, at.at))
	if !errors.Is(err, ErrNotPaired) {
		t.Fatalf("expected ErrNotPaired, got %v", err)
	}
	if err := store.VerifySession("whatever"); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("expected ErrNotPaired, got %v", err)
	}
}

func TestNonceCacheIsBounded(t *testing.T) {
	// Age-based pruning alone does not bound the cache: every nonce here is
	// inside the skew window, so only the hard cap can stop the map growing.
	at := &clock{at: time.Now().UTC()}
	store := newStore(t, t.TempDir(), at)
	owner := newCore(t, "core-a")
	if _, err := store.Pair(owner.pairRequest(), owner.sign("POST", "/v1/pair", nil, at.at)); err != nil {
		t.Fatalf("pair: %v", err)
	}

	for i := 0; i < maxNonces*3; i++ {
		if _, err := store.NewSession(owner.id, owner.sign("POST", "/v1/session", nil, at.at)); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
	}
	if size := store.NonceCacheSize(); size > maxNonces {
		t.Fatalf("nonce cache grew to %d, cap is %d", size, maxNonces)
	}
	if size := store.NonceCacheSize(); size == 0 {
		t.Fatal("nonce cache was emptied entirely; replay protection is gone")
	}
}

func TestRecentNonceStillRejectedAfterEviction(t *testing.T) {
	// Eviction must not open a replay hole for a nonce that is still fresh.
	at := &clock{at: time.Now().UTC()}
	store := newStore(t, t.TempDir(), at)
	owner := newCore(t, "core-a")
	if _, err := store.Pair(owner.pairRequest(), owner.sign("POST", "/v1/pair", nil, at.at)); err != nil {
		t.Fatalf("pair: %v", err)
	}
	recent := owner.sign("POST", "/v1/session", nil, at.at)
	if _, err := store.NewSession(owner.id, recent); err != nil {
		t.Fatalf("session: %v", err)
	}
	// Push the cache well past the cap, then replay the nonce from just before.
	for i := 0; i < maxNonces/2; i++ {
		if _, err := store.NewSession(owner.id, owner.sign("POST", "/v1/session", nil, at.at)); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
	}
	if _, err := store.NewSession(owner.id, recent); !errors.Is(err, ErrReplay) {
		t.Fatalf("a recent nonce was accepted again after eviction pressure: %v", err)
	}
}

func TestSessionCountIsBounded(t *testing.T) {
	at := &clock{at: time.Now().UTC()}
	store := newStore(t, t.TempDir(), at)
	owner := newCore(t, "core-a")
	if _, err := store.Pair(owner.pairRequest(), owner.sign("POST", "/v1/pair", nil, at.at)); err != nil {
		t.Fatalf("pair: %v", err)
	}
	var last proto.Session
	for i := 0; i < maxSessions*3; i++ {
		session, err := store.NewSession(owner.id, owner.sign("POST", "/v1/session", nil, at.at))
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		last = session
	}
	if count := store.SessionCount(); count > maxSessions {
		t.Fatalf("session table grew to %d, cap is %d", count, maxSessions)
	}
	// The most recently issued token must survive the cap, or a Core that keeps
	// renewing would lock itself out.
	if err := store.VerifySession(last.Token); err != nil {
		t.Fatalf("the newest session was evicted: %v", err)
	}
}
