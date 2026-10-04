package kcp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// The authenticated envelope: everything a UDP packet must survive before the
// KCP state machine is allowed to look at it.
//
// # Why this layer exists at all
//
// TLS protects application data. It does not protect the KCP header, because
// the KCP header is OUTSIDE the TLS record - it has to be, since KCP is what
// delivers the record in the first place. So without this layer anyone who can
// send UDP to the port can drive the KCP state machine: acknowledge segments
// that never arrived, claim a receive window of zero to stall the peer, inject
// out-of-order fragments to grow the reassembly queue, or simply spray
// malformed headers at the parser. None of that ever touches TLS, and TLS never
// gets a chance to object, because the connection dies below it.
//
// The layering, with the new rung:
//
//	UDP
//	  Authenticated Envelope   <- this file. MAC checked FIRST.
//	    KCP                    reliability, ARQ, FEC
//	      TLS 1.3 hybrid PQ    the same trust model as every other transport
//	        NasSimHub Protocol
//
// # The rule that makes it worth having
//
// A packet that fails the MAC is dropped before Input is called. Not logged
// with its contents, not parsed to see what it claimed, not counted per packet
// - dropped, with a rate-limited counter. That ordering is the entire security
// property: if a malformed packet could reach the parser and only then be
// rejected, the parser would still have run on attacker-controlled bytes.
//
// Every primitive is standard library: crypto/hmac, crypto/sha256.

// Envelope wire format, version 1:
//
//	offset  size  field
//	0       1     version
//	1       1     packet type
//	2       8     session id
//	10      4     epoch
//	14      8     counter
//	22      n     payload (a KCP datagram, itself possibly FEC-wrapped)
//	22+n    32    MAC over bytes [0, 22+n)
//
// The MAC covers the header as well as the payload, so session id, epoch and
// counter cannot be edited in flight - which matters because the anti-replay
// window trusts the counter, and a counter an attacker could rewrite would let
// them push the window forward and lock the peer out.
const (
	// EnvelopeVersion is the current envelope version.
	EnvelopeVersion = 1
	// envelopeHeaderSize is version + type + session + epoch + counter.
	envelopeHeaderSize = 1 + 1 + 8 + 4 + 8
	// MACSize is the full HMAC-SHA-256 output. Not truncated: the 4.4% of a
	// 1200-byte MTU it costs is not worth the argument, and a truncation
	// choice is one more thing a reviewer would have to check.
	MACSize = sha256.Size
	// EnvelopeOverhead is what every data packet pays.
	EnvelopeOverhead = envelopeHeaderSize + MACSize
)

// Packet types.
const (
	// PacketData carries a KCP datagram.
	PacketData byte = 0x03
	// PacketHello is a client's request to open a session. See cookie.go.
	PacketHello byte = 0x01
	// PacketChallenge is the server's cookie reply.
	PacketChallenge byte = 0x02
)

// Errors from this layer. They are distinct so diagnostics can count them
// separately: a MAC failure is somebody sending garbage, an old counter is
// usually the network duplicating a packet, and conflating them would hide an
// attack inside ordinary noise.
var (
	// ErrEnvelopeShort reports a packet too small to be an envelope.
	ErrEnvelopeShort = errors.New("kcp: packet is shorter than an envelope")
	// ErrEnvelopeVersion reports an envelope version this build does not know.
	ErrEnvelopeVersion = errors.New("kcp: unknown envelope version")
	// ErrEnvelopeType reports an unexpected packet type.
	ErrEnvelopeType = errors.New("kcp: unexpected packet type")
	// ErrMAC reports a packet whose MAC does not verify.
	ErrMAC = errors.New("kcp: packet authentication failed")
	// ErrReplay reports a packet whose counter has been seen.
	ErrReplay = errors.New("kcp: packet is a replay")
	// ErrTooOld reports a counter below the anti-replay window.
	ErrTooOld = errors.New("kcp: packet is older than the replay window")
	// ErrSession reports a packet for a different session.
	ErrSession = errors.New("kcp: packet is for another session")
)

// EnvelopeHeader is the parsed, authenticated header.
type EnvelopeHeader struct {
	Version   byte
	Type      byte
	SessionID uint64
	Epoch     uint32
	Counter   uint64
}

// SealEnvelope builds an authenticated packet.
//
// The buffer is allocated to the exact size needed. A pool would save
// allocations, and is deliberately not used here: a pooled buffer that escapes
// into the receive path while another packet is being sealed is a data race
// that would show up as an occasional authentication failure, which is the
// hardest possible bug to attribute.
func SealEnvelope(key []byte, header EnvelopeHeader, payload []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrNoSecret
	}
	out := make([]byte, envelopeHeaderSize+len(payload)+MACSize)
	out[0] = EnvelopeVersion
	out[1] = header.Type
	binary.BigEndian.PutUint64(out[2:10], header.SessionID)
	binary.BigEndian.PutUint32(out[10:14], header.Epoch)
	binary.BigEndian.PutUint64(out[14:22], header.Counter)
	copy(out[envelopeHeaderSize:], payload)

	mac := hmac.New(sha256.New, key)
	mac.Write(out[:envelopeHeaderSize+len(payload)])
	copy(out[envelopeHeaderSize+len(payload):], mac.Sum(nil))
	return out, nil
}

// PeekEnvelope reads the header WITHOUT authenticating it.
//
// It exists for exactly one purpose: the receiver must know which key id and
// epoch to check against before it can check anything. Nothing else may use
// what this returns. The returned header is attacker-controlled until
// OpenEnvelope has succeeded, and the two are separate functions so that a
// caller cannot accidentally treat the first as the second.
func PeekEnvelope(packet []byte) (EnvelopeHeader, error) {
	if len(packet) < envelopeHeaderSize+MACSize {
		return EnvelopeHeader{}, ErrEnvelopeShort
	}
	if packet[0] != EnvelopeVersion {
		return EnvelopeHeader{}, fmt.Errorf("%w: %d", ErrEnvelopeVersion, packet[0])
	}
	return EnvelopeHeader{
		Version:   packet[0],
		Type:      packet[1],
		SessionID: binary.BigEndian.Uint64(packet[2:10]),
		Epoch:     binary.BigEndian.Uint32(packet[10:14]),
		Counter:   binary.BigEndian.Uint64(packet[14:22]),
	}, nil
}

// OpenEnvelope authenticates a packet and returns its payload.
//
// The payload is a sub-slice of the input, so the caller must not retain it
// past the read buffer's reuse. Every caller in this package copies before
// queueing.
func OpenEnvelope(key []byte, packet []byte) (EnvelopeHeader, []byte, error) {
	header, err := PeekEnvelope(packet)
	if err != nil {
		return EnvelopeHeader{}, nil, err
	}
	if len(key) == 0 {
		return EnvelopeHeader{}, nil, ErrNoSecret
	}
	split := len(packet) - MACSize
	mac := hmac.New(sha256.New, key)
	mac.Write(packet[:split])
	// hmac.Equal is constant time. A byte-by-byte comparison here would leak
	// how many leading bytes of a forged MAC were right, which is enough to
	// forge one a byte at a time over enough attempts.
	if !hmac.Equal(mac.Sum(nil), packet[split:]) {
		return EnvelopeHeader{}, nil, ErrMAC
	}
	return header, packet[envelopeHeaderSize:split], nil
}

// ---------------------------------------------------------------------------
// Anti-replay
// ---------------------------------------------------------------------------

// ReplayWindowSize is how far behind the highest seen counter a packet may be
// and still be considered.
//
// 1024 packets. Wide enough to absorb the reordering a lossy link produces -
// jitter of 50 ms at a few hundred packets per second reorders far less than
// this - and narrow enough that the bitmap is 128 bytes per session.
const ReplayWindowSize = 1024

// ReplayWindow is a sliding window of seen counters.
//
// The classic construction (IPsec, DTLS, WireGuard all use a variant): a
// highest-seen counter and a bitmap of which of the preceding N were seen. It
// is O(1) per packet with a fixed memory cost, which matters because the
// alternative - remembering every counter - is an unbounded structure an
// attacker fills for free.
type ReplayWindow struct {
	mu      sync.Mutex
	highest uint64
	// bitmap[i] is set when counter (highest - i) has been accepted.
	bitmap  [ReplayWindowSize / 64]uint64
	started bool
}

// NewReplayWindow builds an empty window.
func NewReplayWindow() *ReplayWindow { return &ReplayWindow{} }

// Accept records a counter and reports whether the packet may proceed.
//
// A counter equal to one already seen, or below the window, is refused. The
// refusal happens BEFORE the payload goes anywhere, which is what stops a
// replayed packet from reaching the KCP state machine and being processed a
// second time - the specific harm being a duplicate acknowledgement moving the
// sender's window, or a duplicated segment being handed up twice.
func (w *ReplayWindow) Accept(counter uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.started {
		w.started = true
		w.highest = counter
		w.set(0)
		return nil
	}
	if counter > w.highest {
		shift := counter - w.highest
		w.shift(shift)
		w.highest = counter
		w.set(0)
		return nil
	}
	behind := w.highest - counter
	if behind >= ReplayWindowSize {
		return fmt.Errorf("%w: counter %d, window starts at %d",
			ErrTooOld, counter, w.highest-ReplayWindowSize+1)
	}
	if w.isSet(behind) {
		return fmt.Errorf("%w: counter %d", ErrReplay, counter)
	}
	w.set(behind)
	return nil
}

// Highest reports the highest counter accepted, for diagnostics.
func (w *ReplayWindow) Highest() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.highest
}

func (w *ReplayWindow) shift(by uint64) {
	if by >= ReplayWindowSize {
		for i := range w.bitmap {
			w.bitmap[i] = 0
		}
		return
	}
	words := by / 64
	bits := by % 64
	for i := len(w.bitmap) - 1; i >= 0; i-- {
		var value uint64
		source := i - int(words)
		if source >= 0 {
			value = w.bitmap[source] << bits
			if bits > 0 && source > 0 {
				value |= w.bitmap[source-1] >> (64 - bits)
			}
		}
		w.bitmap[i] = value
	}
}

func (w *ReplayWindow) set(offset uint64) {
	w.bitmap[offset/64] |= 1 << (offset % 64)
}

func (w *ReplayWindow) isSet(offset uint64) bool {
	return w.bitmap[offset/64]&(1<<(offset%64)) != 0
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

// MonotonicCounter issues strictly increasing packet counters.
//
// It never wraps: at 64 bits, a link sending a million packets a second exhausts
// it in half a million years. A wrapping counter would silently make the replay
// window meaningless, so the type simply does not wrap - it refuses.
type MonotonicCounter struct {
	mu    sync.Mutex
	value uint64
}

// ErrCounterExhausted reports the counter reaching its limit, which cannot
// happen in practice and is refused rather than wrapped in case it does.
var ErrCounterExhausted = errors.New("kcp: packet counter exhausted; rekey required")

// Next returns the next counter.
func (c *MonotonicCounter) Next() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.value == ^uint64(0) {
		return 0, ErrCounterExhausted
	}
	c.value++
	return c.value, nil
}

// Value reports the last counter issued.
func (c *MonotonicCounter) Value() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value
}

// Reset sets the counter back to zero, which is only correct alongside a new
// epoch: counters restart per epoch, and the epoch is in the MAC, so a replayed
// packet from a previous epoch cannot be mistaken for a fresh one.
func (c *MonotonicCounter) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value = 0
}

// AuthStats counts what this layer rejected, for diagnostics.
//
// Counts only. No payloads, no addresses, no key material - the whole point of
// the counters is to say "something is sending us rubbish" without recording
// what the rubbish was.
type AuthStats struct {
	Accepted     uint64 `json:"accepted"`
	MACFailures  uint64 `json:"mac_failures"`
	Replays      uint64 `json:"replays"`
	TooOld       uint64 `json:"too_old"`
	BadEpoch     uint64 `json:"bad_epoch"`
	Malformed    uint64 `json:"malformed"`
	CookieIssued uint64 `json:"cookie_issued"`
	CookieBad    uint64 `json:"cookie_rejected"`
	RateLimited  uint64 `json:"rate_limited"`
}
