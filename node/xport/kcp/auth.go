package kcp

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

// Wiring the envelope, the keys and the cookie into the session layer.
//
// This file is the join between the three mechanisms and the transport. It is
// separate from session.go so that the ORDER of checks is readable in one
// place, because the order is the security property and not an implementation
// detail:
//
//	1. rate limit        cheapest, stops a flood before anything is parsed
//	2. cookie            proves the sender receives at its claimed address
//	3. MAC               proves the sender holds the transport secret
//	4. anti-replay       proves this exact packet has not been seen
//	5. KCP               only now does the state machine see a byte
//
// Step 5 is the one that matters. Every step above it exists so that the KCP
// parser, the FEC decoder and the reassembly queues are only ever driven by
// packets from the paired peer. Move any check below step 5 and the parser
// starts running on attacker-controlled input again.

// AuthConfig turns on the authenticated envelope.
//
// A nil AuthConfig means the transport runs without authentication, which is
// correct only for the benchmark harness and the tests that measure the
// transport itself. The agent always supplies one; there is a test that fails
// if a Node ever opens an unauthenticated listener.
type AuthConfig struct {
	// Ring holds the directional MAC keys, with rotation and a grace window.
	Ring *KeyRing
	// SessionID identifies this conversation. The client chooses it and the
	// server adopts it from the authenticated hello, so it cannot be set by
	// anyone who does not hold the transport secret.
	SessionID uint64
	// Cookies issues and verifies address-validation cookies. Server side.
	Cookies *CookieAuthority
	// Limiter is the pair of token buckets. Server side.
	Limiter *HandshakeLimiter
	// Stats is shared with the diagnostics layer. Counters only.
	Stats *AuthCounters
}

// AuthCounters is the concurrent-safe form of AuthStats.
//
// Atomics rather than a mutex: these are incremented on the packet path,
// including on the path that is being flooded, and a contended mutex there
// would turn a flood into a self-inflicted stall.
type AuthCounters struct {
	accepted     atomic.Uint64
	macFailures  atomic.Uint64
	replays      atomic.Uint64
	tooOld       atomic.Uint64
	badEpoch     atomic.Uint64
	malformed    atomic.Uint64
	cookieIssued atomic.Uint64
	cookieBad    atomic.Uint64
	rateLimited  atomic.Uint64
}

// NewAuthCounters builds an empty set.
func NewAuthCounters() *AuthCounters { return &AuthCounters{} }

// Snapshot reads them out.
func (c *AuthCounters) Snapshot() AuthStats {
	if c == nil {
		return AuthStats{}
	}
	return AuthStats{
		Accepted:     c.accepted.Load(),
		MACFailures:  c.macFailures.Load(),
		Replays:      c.replays.Load(),
		TooOld:       c.tooOld.Load(),
		BadEpoch:     c.badEpoch.Load(),
		Malformed:    c.malformed.Load(),
		CookieIssued: c.cookieIssued.Load(),
		CookieBad:    c.cookieBad.Load(),
		RateLimited:  c.rateLimited.Load(),
	}
}

func (c *AuthCounters) add(field *atomic.Uint64) {
	if c != nil {
		field.Add(1)
	}
}

// connAuth is one session's authentication state.
type connAuth struct {
	ring      *KeyRing
	sessionID uint64
	counter   MonotonicCounter
	window    *ReplayWindow
	stats     *AuthCounters
}

func newConnAuth(config *AuthConfig) *connAuth {
	if config == nil || config.Ring == nil {
		return nil
	}
	return &connAuth{
		ring:      config.Ring,
		sessionID: config.SessionID,
		window:    NewReplayWindow(),
		stats:     config.Stats,
	}
}

// seal wraps an outgoing KCP datagram.
func (a *connAuth) seal(payload []byte) ([]byte, error) {
	keys, err := a.ring.Sending()
	if err != nil {
		return nil, err
	}
	counter, err := a.counter.Next()
	if err != nil {
		return nil, err
	}
	return SealEnvelope(keys.TX, EnvelopeHeader{
		Type:      PacketData,
		SessionID: a.sessionID,
		Epoch:     keys.Epoch,
		Counter:   counter,
	}, payload)
}

// open authenticates an incoming packet and returns the KCP datagram inside.
//
// Everything it can reject, it rejects here - before the return value reaches
// any parser. The counters are incremented per REASON, so diagnostics can tell
// a duplicated packet (ordinary on a lossy link) from a forged one (not
// ordinary at all) without either being logged with its contents.
func (a *connAuth) open(packet []byte) ([]byte, error) {
	header, err := PeekEnvelope(packet)
	if err != nil {
		a.stats.add(&a.stats.malformed)
		return nil, err
	}
	if header.Type != PacketData {
		a.stats.add(&a.stats.malformed)
		return nil, ErrEnvelopeType
	}
	if header.SessionID != a.sessionID {
		a.stats.add(&a.stats.malformed)
		return nil, ErrSession
	}
	// The key id is not on the data packet: a session already knows which
	// pairing it belongs to, and putting it on every packet would be 12 bytes
	// of attacker-chosen input per datagram for no benefit. The epoch is
	// enough to select between current and previous.
	key, err := a.ring.Accepting(a.ring.CurrentKeyID(), header.Epoch)
	if err != nil {
		a.stats.add(&a.stats.badEpoch)
		return nil, err
	}
	_, payload, err := OpenEnvelope(key, packet)
	if err != nil {
		a.stats.add(&a.stats.macFailures)
		return nil, err
	}
	// Replay is checked AFTER the MAC, deliberately. Checking it first would
	// let an attacker advance the window with a forged counter and lock the
	// real peer out - a denial of service that needs no key at all.
	if err := a.window.Accept(header.Counter); err != nil {
		if errorsIsReplay(err) {
			a.stats.add(&a.stats.replays)
		} else {
			a.stats.add(&a.stats.tooOld)
		}
		return nil, err
	}
	a.stats.add(&a.stats.accepted)
	return payload, nil
}

func errorsIsReplay(err error) bool {
	return errors.Is(err, ErrReplay)
}

// CurrentKeyID reports the key id in use, for the hello and for lookups.
func (r *KeyRing) CurrentKeyID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current.KeyID
}

// ---------------------------------------------------------------------------
// The server side of the hello exchange
// ---------------------------------------------------------------------------

// helloOutcome is what the listener should do with a hello.
type helloOutcome int

const (
	// helloDropped: nothing more happens. No reply, no allocation.
	helloDropped helloOutcome = iota
	// helloChallenged: a challenge was sent. Still no allocation.
	helloChallenged
	// helloAccepted: the sender proved address ownership and key possession.
	helloAccepted
)

// handleHello runs steps 1 to 3 for an incoming hello.
//
// It allocates NOTHING on any path except the last, and the last is reached
// only after both the cookie and the MAC have verified. That is the property
// the DoS tests assert: a session table that does not grow no matter how many
// helloes arrive without a valid cookie.
func handleHello(
	socket net.PacketConn,
	from net.Addr,
	packet []byte,
	config *AuthConfig,
) (helloOutcome, Hello) {
	stats := config.Stats

	// 1. Rate limit. Before parsing, before any HMAC, before a reply. A
	// limiter that ran after the cookie check would still do the attacker's
	// work for them.
	if config.Limiter != nil && !config.Limiter.Allow(from) {
		stats.add(&stats.rateLimited)
		return helloDropped, Hello{}
	}

	header, err := PeekEnvelope(packet)
	if err != nil || header.Type != PacketHello {
		stats.add(&stats.malformed)
		return helloDropped, Hello{}
	}
	body := packet[envelopeHeaderSize : len(packet)-MACSize]
	hello, err := UnmarshalHello(body)
	if err != nil {
		stats.add(&stats.malformed)
		return helloDropped, Hello{}
	}
	hello.SessionID = header.SessionID
	hello.Epoch = header.Epoch

	// 2. Address validation. A hello with no cookie gets a challenge and
	// nothing else - in particular it does NOT get its MAC checked, because a
	// spoofed source address should not be able to make the device do work
	// that scales with its packet rate.
	if len(hello.Cookie) == 0 {
		challenge := MarshalChallenge(hello.Nonce, config.Cookies.Issue(from, hello.Nonce[:]))
		// The challenge is smaller than the hello that provoked it, so this
		// path cannot be used to amplify traffic at a spoofed victim. There is
		// a test that fails if that stops being true.
		_, _ = socket.WriteTo(challenge, from)
		stats.add(&stats.cookieIssued)
		return helloChallenged, Hello{}
	}
	if err := config.Cookies.Verify(from, hello.Nonce[:], hello.Cookie); err != nil {
		stats.add(&stats.cookieBad)
		return helloDropped, Hello{}
	}

	// 3. Key possession. Only now, for a sender that demonstrably receives at
	// its claimed address.
	key, err := config.Ring.Accepting(hello.KeyID, header.Epoch)
	if err != nil {
		stats.add(&stats.badEpoch)
		return helloDropped, Hello{}
	}
	if _, _, err := OpenEnvelope(key, packet); err != nil {
		stats.add(&stats.macFailures)
		return helloDropped, Hello{}
	}
	stats.add(&stats.accepted)
	return helloAccepted, hello
}

// sealHello builds an authenticated hello.
func sealHello(ring *KeyRing, sessionID uint64, hello Hello) ([]byte, error) {
	keys, err := ring.Sending()
	if err != nil {
		return nil, err
	}
	hello.KeyID = keys.KeyID
	return SealEnvelope(keys.TX, EnvelopeHeader{
		Type:      PacketHello,
		SessionID: sessionID,
		Epoch:     keys.Epoch,
		// A hello uses counter zero. It is outside the replay window's
		// numbering, which starts at one, so a replayed hello cannot consume a
		// data counter - and a replayed hello achieves nothing anyway: it
		// re-establishes a session the holder of the key could establish
		// regardless.
		Counter: 0,
	}, MarshalHello(hello))
}

// helloSize is what a hello costs on the wire, for the amplification test.
func helloSize(cookie int) int {
	return envelopeHeaderSize + 1 + 0 + NonceSize + 1 + cookie + MACSize
}

// challengeSize is what a challenge costs.
func challengeSize() int { return 2 + NonceSize + CookieSize }

// sessionKeys guards the listener's session table when authentication is on.
//
// Keyed by session id rather than by address, which is a real improvement and
// not only a convenience: an authenticated packet proves who sent it, so a peer
// whose NAT rebinding changed its source port keeps its session instead of
// silently starting a new one. Without authentication that would be a
// session-hijacking primitive; with it, the MAC is what makes it safe.
type sessionKeys struct {
	mu       sync.Mutex
	byID     map[uint64]*Conn
	maxCount int
}

func newSessionKeys(max int) *sessionKeys {
	return &sessionKeys{byID: map[uint64]*Conn{}, maxCount: max}
}

func (s *sessionKeys) get(id uint64) (*Conn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	conn, ok := s.byID[id]
	return conn, ok
}

func (s *sessionKeys) put(id uint64, conn *Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.byID) >= s.maxCount {
		return false
	}
	s.byID[id] = conn
	return true
}

func (s *sessionKeys) drop(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
}

func (s *sessionKeys) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}

func (s *sessionKeys) all() []*Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Conn, 0, len(s.byID))
	for _, conn := range s.byID {
		out = append(out, conn)
	}
	return out
}
