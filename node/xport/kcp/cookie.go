package kcp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Address validation before anything expensive happens.
//
// # The attack this stops
//
// UDP source addresses are free to forge. Without validation, one packet from a
// spoofed address makes the Node allocate a session, a receive buffer, a replay
// window and a KCP state machine - and then, if the handshake proceeded, run a
// hybrid post-quantum key agreement, which is the single most expensive thing
// the device does. A few thousand such packets from an attacker who never
// receives a reply would take a Cortex-A53 out of service, and none of it would
// appear in any log as an authentication failure, because nothing ever got as
// far as authenticating.
//
// It is also an amplification source: a device that answers a 60-byte packet
// with a 1200-byte handshake flight is a 20x amplifier pointed at whoever the
// attacker claims to be.
//
// # The exchange
//
//	client -> server   Hello       (session id, epoch, nonce)          63 bytes
//	server -> client   Challenge   (nonce, cookie)                     50 bytes
//	client -> server   Hello+Cookie                                    95 bytes
//	                   -> cookie verified, THEN MAC verified,
//	                      THEN a session is allocated
//
// The challenge is SMALLER than the hello that provoked it. That is not an
// accident of the field sizes; it is a requirement, and there is a test that
// fails if a future change makes the reply larger than the request.
//
// # Why stateless
//
// A server that remembered issued cookies would have the memory problem the
// cookie exists to prevent. Instead the cookie is an HMAC over the client's own
// address and a time bucket, keyed by a secret only the server knows: the
// server can verify what it never stored. This is the DTLS HelloVerifyRequest
// construction, and it is used here for the same reason.
//
// All primitives standard library: crypto/hmac, crypto/sha256, crypto/rand.

// Cookie sizing and lifetime.
const (
	// CookieSize is the truncated HMAC carried on the wire. 16 bytes is ample
	// for a value that is only useful within one short time bucket and that an
	// attacker cannot test offline - they must send each guess to the server,
	// where the rate limiter is waiting.
	CookieSize = 16
	// NonceSize is the client's freshness contribution.
	NonceSize = 16
	// CookieBucket is how long one cookie value is valid for.
	CookieBucket = 15 * time.Second
	// cookieSecretSize is the server's rotating secret.
	cookieSecretSize = 32
)

// Errors from address validation.
var (
	// ErrCookieRequired reports a hello with no cookie; the caller answers
	// with a challenge rather than treating it as a failure.
	ErrCookieRequired = errors.New("kcp: address validation required")
	// ErrCookieInvalid reports a cookie that does not verify for this address.
	ErrCookieInvalid = errors.New("kcp: cookie does not verify for this address")
	// ErrCookieExpired reports a cookie from a time bucket no longer accepted.
	ErrCookieExpired = errors.New("kcp: cookie has expired")
	// ErrRateLimited reports a handshake refused by a token bucket.
	ErrRateLimited = errors.New("kcp: handshake rate limit reached")
)

// CookieAuthority issues and verifies stateless address-validation cookies.
type CookieAuthority struct {
	mu       sync.RWMutex
	current  []byte
	previous []byte
	rotateAt time.Time
	rotation time.Duration
	now      func() time.Time
}

// DefaultCookieRotation is how often the server secret changes.
//
// Rotating bounds the value of a leaked secret. Keeping the previous secret for
// one period is what stops a rotation from invalidating cookies that are
// legitimately in flight at that moment.
const DefaultCookieRotation = 5 * time.Minute

// NewCookieAuthority builds one with a fresh secret.
func NewCookieAuthority() (*CookieAuthority, error) {
	secret := make([]byte, cookieSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	authority := &CookieAuthority{
		current:  secret,
		rotation: DefaultCookieRotation,
		now:      time.Now,
	}
	authority.rotateAt = authority.now().Add(authority.rotation)
	return authority, nil
}

// SetClock injects a clock, for tests.
func (a *CookieAuthority) SetClock(now func() time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.now = now
	a.rotateAt = now().Add(a.rotation)
}

// Rotate installs a new secret, keeping the previous one usable.
func (a *CookieAuthority) Rotate() error {
	secret := make([]byte, cookieSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.previous = a.current
	a.current = secret
	a.rotateAt = a.now().Add(a.rotation)
	return nil
}

func (a *CookieAuthority) maybeRotate() {
	a.mu.RLock()
	due := a.now().After(a.rotateAt)
	a.mu.RUnlock()
	if due {
		_ = a.Rotate()
	}
}

// bucket is the coarse time value a cookie is bound to.
func (a *CookieAuthority) bucket(at time.Time) uint64 {
	return uint64(at.UnixNano() / int64(CookieBucket))
}

// compute is the cookie itself:
//
//	HMAC-SHA-256(secret, source_ip || source_port || bucket || client_nonce)
//
// truncated to CookieSize. The address binding is what makes it useless from
// anywhere else, and the nonce binding is what stops a cookie issued for one
// hello being replayed into another from the same address.
func compute(secret []byte, address net.Addr, bucket uint64, nonce []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	ip, port := splitAddress(address)
	mac.Write(ip)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	mac.Write(portBytes[:])
	var bucketBytes [8]byte
	binary.BigEndian.PutUint64(bucketBytes[:], bucket)
	mac.Write(bucketBytes[:])
	mac.Write(nonce)
	return mac.Sum(nil)[:CookieSize]
}

// splitAddress extracts the IP and port from a net.Addr in a form that is
// stable to hash. An address that cannot be split contributes its string form,
// so an exotic address type degrades to "still bound to something" rather than
// to "bound to nothing".
func splitAddress(address net.Addr) ([]byte, uint16) {
	switch value := address.(type) {
	case *net.UDPAddr:
		return value.IP.To16(), uint16(value.Port)
	case *net.TCPAddr:
		return value.IP.To16(), uint16(value.Port)
	default:
		if address == nil {
			return nil, 0
		}
		return []byte(address.String()), 0
	}
}

// Issue produces a cookie for an address and nonce.
func (a *CookieAuthority) Issue(address net.Addr, nonce []byte) []byte {
	a.maybeRotate()
	a.mu.RLock()
	defer a.mu.RUnlock()
	return compute(a.current, address, a.bucket(a.now()), nonce)
}

// Verify checks a cookie.
//
// Three buckets are accepted - the current one and one on each side - because a
// client that receives a challenge at the end of a bucket sends its reply in
// the next one, and a hard boundary would make one exchange in every few fail
// for no reason. Both the current and previous server secrets are tried, for
// the same reason applied to rotation.
//
// That is nine HMACs in the worst case. Each is a few microseconds and the rate
// limiter has already run, so the cost is bounded by design rather than by
// hope.
func (a *CookieAuthority) Verify(address net.Addr, nonce, cookie []byte) error {
	if len(cookie) != CookieSize {
		return fmt.Errorf("%w: wrong length", ErrCookieInvalid)
	}
	a.mu.RLock()
	defer a.mu.RUnlock()

	now := a.bucket(a.now())
	secrets := [][]byte{a.current}
	if len(a.previous) > 0 {
		secrets = append(secrets, a.previous)
	}
	for _, secret := range secrets {
		for _, bucket := range []uint64{now, now - 1, now + 1} {
			if hmac.Equal(compute(secret, address, bucket, nonce), cookie) {
				return nil
			}
		}
	}
	return ErrCookieInvalid
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

// TokenBucket is a simple refilling allowance.
type TokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	refill   float64 // tokens per second
	last     time.Time
	now      func() time.Time
}

// NewTokenBucket builds one that starts full.
func NewTokenBucket(capacity float64, perSecond float64) *TokenBucket {
	return &TokenBucket{
		tokens: capacity, capacity: capacity, refill: perSecond,
		last: time.Now(), now: time.Now,
	}
}

// SetClock injects a clock, for tests.
func (b *TokenBucket) SetClock(now func() time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.now = now
	b.last = now()
}

// Allow takes one token, reporting whether there was one.
func (b *TokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.refill
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Tokens reports the current allowance, for tests.
func (b *TokenBucket) Tokens() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tokens
}

// Handshake rate limits.
//
// Two buckets, because they stop different things. The per-source bucket stops
// one address from consuming the service; the global bucket stops a thousand
// addresses from doing the same thing with one packet each, which the per-source
// bucket alone would happily permit.
//
// The numbers are deliberately generous for a real user and restrictive for a
// flood: a Node is contacted by one NAS, which opens a session and keeps it.
const (
	// GlobalHandshakeRate is handshakes per second across all sources.
	GlobalHandshakeRate = 20
	// GlobalHandshakeBurst absorbs a restart storm without dropping the NAS.
	GlobalHandshakeBurst = 40
	// PerSourceHandshakeRate is handshakes per second from one address.
	PerSourceHandshakeRate = 2
	// PerSourceHandshakeBurst allows a retry or two.
	PerSourceHandshakeBurst = 5
	// MaxTrackedSources bounds the per-source table. Without a bound, the
	// table itself becomes the memory exhaustion primitive the rate limiter
	// was added to prevent - which would be an unusually embarrassing bug.
	MaxTrackedSources = 4096
)

// HandshakeLimiter enforces both buckets.
type HandshakeLimiter struct {
	mu      sync.Mutex
	global  *TokenBucket
	sources map[string]*sourceBucket
	now     func() time.Time
}

type sourceBucket struct {
	bucket *TokenBucket
	seen   time.Time
}

// NewHandshakeLimiter builds one with the default rates.
func NewHandshakeLimiter() *HandshakeLimiter {
	return &HandshakeLimiter{
		global:  NewTokenBucket(GlobalHandshakeBurst, GlobalHandshakeRate),
		sources: map[string]*sourceBucket{},
		now:     time.Now,
	}
}

// SetClock injects a clock, for tests.
func (l *HandshakeLimiter) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
	l.global.SetClock(now)
}

// Allow reports whether a handshake from this address may proceed.
//
// The global bucket is checked FIRST and consumed only if the per-source bucket
// also allows - otherwise one blocked source would drain the global allowance
// and do the attacker's work for them.
func (l *HandshakeLimiter) Allow(address net.Addr) bool {
	l.mu.Lock()
	key := sourceKey(address)
	entry, known := l.sources[key]
	if !known {
		if len(l.sources) >= MaxTrackedSources {
			l.evictLocked()
		}
		entry = &sourceBucket{
			bucket: NewTokenBucket(PerSourceHandshakeBurst, PerSourceHandshakeRate),
		}
		entry.bucket.SetClock(l.now)
		l.sources[key] = entry
	}
	entry.seen = l.now()
	global := l.global
	l.mu.Unlock()

	if !entry.bucket.Allow() {
		return false
	}
	return global.Allow()
}

// evictLocked drops the least recently seen half of the table.
//
// Half rather than one entry: evicting one per insertion turns a full table
// into an O(n) scan per packet, which is itself a denial of service.
func (l *HandshakeLimiter) evictLocked() {
	type aged struct {
		key  string
		seen time.Time
	}
	entries := make([]aged, 0, len(l.sources))
	for key, entry := range l.sources {
		entries = append(entries, aged{key: key, seen: entry.seen})
	}
	cutoff := l.now().Add(-time.Minute)
	dropped := 0
	for _, entry := range entries {
		if entry.seen.Before(cutoff) {
			delete(l.sources, entry.key)
			dropped++
		}
	}
	if dropped > 0 {
		return
	}
	// Nothing was old enough. Drop half anyway, oldest first, so the table
	// cannot pin at its limit and refuse every new source forever.
	for i := 0; i < len(entries)/2; i++ {
		delete(l.sources, entries[i].key)
	}
}

// Tracked reports how many sources are held, for tests and diagnostics.
func (l *HandshakeLimiter) Tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sources)
}

func sourceKey(address net.Addr) string {
	if address == nil {
		return ""
	}
	// Keyed by ADDRESS ONLY, not address and port. A source that gets a new
	// ephemeral port per packet would otherwise get a fresh bucket each time,
	// which is the easiest possible way around a per-source limit.
	switch value := address.(type) {
	case *net.UDPAddr:
		return value.IP.String()
	case *net.TCPAddr:
		return value.IP.String()
	default:
		host, _, err := net.SplitHostPort(address.String())
		if err != nil {
			return address.String()
		}
		return host
	}
}

// ---------------------------------------------------------------------------
// Hello and challenge packets
// ---------------------------------------------------------------------------

// Hello is a client's request to open a session.
//
// It is authenticated with the transport MAC like every other packet, which is
// what proves the sender holds the transport secret. The cookie proves
// something different and cheaper - that the sender receives at the address it
// claims - and is checked first precisely because it is cheaper.
type Hello struct {
	SessionID uint64
	Epoch     uint32
	KeyID     string
	Nonce     [NonceSize]byte
	Cookie    []byte
}

// MarshalHello encodes the body a Hello's MAC covers.
func MarshalHello(hello Hello) []byte {
	out := make([]byte, 0, 1+len(hello.KeyID)+NonceSize+1+len(hello.Cookie))
	out = append(out, byte(len(hello.KeyID)))
	out = append(out, hello.KeyID...)
	out = append(out, hello.Nonce[:]...)
	out = append(out, byte(len(hello.Cookie)))
	out = append(out, hello.Cookie...)
	return out
}

// UnmarshalHello parses a Hello body. It is called only on bytes whose MAC has
// already verified, with one exception documented at the call site: a hello
// with no cookie is parsed to extract the nonce for the challenge, and nothing
// from that parse is trusted or retained beyond building the reply.
func UnmarshalHello(body []byte) (Hello, error) {
	var hello Hello
	if len(body) < 1 {
		return hello, ErrEnvelopeShort
	}
	keyLength := int(body[0])
	offset := 1
	if len(body) < offset+keyLength+NonceSize+1 {
		return hello, ErrEnvelopeShort
	}
	hello.KeyID = string(body[offset : offset+keyLength])
	offset += keyLength
	copy(hello.Nonce[:], body[offset:offset+NonceSize])
	offset += NonceSize
	cookieLength := int(body[offset])
	offset++
	if len(body) < offset+cookieLength {
		return hello, ErrEnvelopeShort
	}
	if cookieLength > 0 {
		hello.Cookie = append([]byte(nil), body[offset:offset+cookieLength]...)
	}
	return hello, nil
}

// MarshalChallenge encodes a cookie challenge.
//
// Nonce then cookie, and nothing else. Every byte here is a byte sent to an
// address that has not been validated, so the format is as small as it can be
// while still letting the client match the reply to its hello.
func MarshalChallenge(nonce [NonceSize]byte, cookie []byte) []byte {
	out := make([]byte, 0, 2+NonceSize+len(cookie))
	out = append(out, EnvelopeVersion, PacketChallenge)
	out = append(out, nonce[:]...)
	out = append(out, cookie...)
	return out
}

// UnmarshalChallenge parses one.
//
// A challenge is NOT authenticated, and it cannot be: it is sent before the
// server knows who the client is, and the client has not yet proven anything
// either. An attacker can therefore forge one. That is harmless, because the
// worst a forged challenge achieves is making the client send a hello carrying
// a cookie the real server will reject - costing the client one packet. The
// client must not act on a challenge in any other way, which is why this
// returns only the nonce and the cookie bytes.
func UnmarshalChallenge(packet []byte) (nonce [NonceSize]byte, cookie []byte, err error) {
	if len(packet) < 2+NonceSize+CookieSize {
		return nonce, nil, ErrEnvelopeShort
	}
	if packet[0] != EnvelopeVersion {
		return nonce, nil, fmt.Errorf("%w: %d", ErrEnvelopeVersion, packet[0])
	}
	if packet[1] != PacketChallenge {
		return nonce, nil, fmt.Errorf("%w: %d", ErrEnvelopeType, packet[1])
	}
	copy(nonce[:], packet[2:2+NonceSize])
	cookie = append([]byte(nil), packet[2+NonceSize:]...)
	return nonce, cookie, nil
}

// NewNonce generates a client nonce.
func NewNonce() ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	_, err := rand.Read(nonce[:])
	return nonce, err
}
