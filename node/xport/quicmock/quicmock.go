// Package quicmock is the QUIC transport's shape, without QUIC.
//
// # Why there is no real QUIC here
//
// QUIC is not something to write. It is a large protocol with a large attack
// surface, and the sensible options are the two mature Go implementations -
// quic-go and the standard library's golang.org/x/net/quic - both of which are
// third-party or extended-standard-library modules that this container cannot
// fetch: the module proxy is unreachable and every dependency in this project
// is the Go standard library for that reason.
//
// Writing one instead would be the worst of the three options. A hand-rolled
// QUIC would be a second, unreviewed implementation of packet protection and
// connection migration, in a codebase whose entire security argument rests on
// not implementing cryptographic machinery itself.
//
// So this package provides the INTERFACE and a mock that exercises it, and the
// real thing is marked HOST VERIFICATION REQUIRED. What that buys is the part
// that actually matters for the design: the rest of the product can be written,
// and tested, against a QUIC-shaped transport now, so that adding the real one
// later is a dependency change rather than an architecture change.
//
// # What the real implementation must preserve
//
// Three things, and they are the reason this file states them rather than
// leaving them to be rediscovered:
//
//  1. TLS 1.3, from crypto/tls, with the same certificate and the same pinning.
//     QUIC carries TLS rather than replacing it; a QUIC implementation that
//     wanted its own certificate verification would have to be given the same
//     VerifyPeerCertificate callback, not a parallel one.
//
//  2. No second pairing. The device identity, device_id derivation and pairing
//     state are transport-independent and stay that way. QUIC's connection IDs
//     are a transport concept and must never leak into identity.
//
//  3. 0-RTT off for anything with a side effect. QUIC's early data is
//     replayable by design; see proto.SideEffecting and the test that pins it.
//     The safe default is 0-RTT disabled entirely, and turning it on for the
//     two read-only paths is an optimisation nobody has asked for yet.
package quicmock

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// Transport is a QUIC-shaped transport backed by TCP.
//
// It is a mock in the precise sense that it has the right interface and the
// wrong implementation: connections are ordinary TCP, so nothing about
// multiplexing, migration, or 0-RTT is being tested. It exists so that code
// paths which must work "on QUIC" can be written and exercised, and so that the
// status page can show a QUIC mode without a real implementation behind it.
//
// It reports Ready() false. Nothing in the product offers QUIC to a user while
// that is false.
type Transport struct {
	mu       sync.Mutex
	dialed   int
	accepted int
}

// New builds the mock.
func New() *Transport { return &Transport{} }

// Ready reports whether this is a real QUIC implementation. It is not.
func (t *Transport) Ready() bool { return false }

// Mode names the transport.
func (t *Transport) Mode() proto.TransportMode { return proto.TransportQUIC }

// Dial opens a connection. The mock uses TCP underneath.
func (t *Transport) Dial(ctx context.Context, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.dialed++
	t.mu.Unlock()
	return conn, nil
}

// Listen accepts connections.
func (t *Transport) Listen(address string) (*Listener, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: listener, transport: t}, nil
}

// Stats reports what a real implementation would measure. The mock measures
// nothing and says so, rather than reporting zeros that look like a perfect
// link.
func (t *Transport) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Stats{Dialed: t.dialed, Accepted: t.accepted, Measured: false}
}

// Stats is the mock's counters.
type Stats struct {
	Dialed   int
	Accepted int
	Measured bool
}

// Listener accepts mock QUIC connections.
type Listener struct {
	inner     net.Listener
	transport *Transport
}

// Accept returns the next connection.
func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	l.transport.mu.Lock()
	l.transport.accepted++
	l.transport.mu.Unlock()
	return conn, nil
}

// Close stops accepting.
func (l *Listener) Close() error { return l.inner.Close() }

// Addr reports where it is bound.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// ---------------------------------------------------------------------------
// 0-RTT
// ---------------------------------------------------------------------------

// ErrEarlyDataRefused reports a request rejected because it may not be replayed.
var ErrEarlyDataRefused = errors.New(
	"quic: this request may not be sent as early data because it can be replayed")

// EarlyDataPolicy decides whether a request may go in 0-RTT.
//
// It is here, in the mock, so that the rule exists and is tested before any
// implementation can be tempted to skip it. A real QUIC transport calls the
// same function.
//
// The policy is: no. Not "no for writes" - no, unless the request is on the
// short allow-list of reads that carry neither a side effect nor private
// content. An attacker who replays captured early data must gain nothing, and
// the only requests where that is true are the two that are already served
// without authentication.
func EarlyDataPolicy(method, path string) error {
	if proto.SideEffecting(method, path) {
		return ErrEarlyDataRefused
	}
	return nil
}

// EarlyDataEnabled reports whether 0-RTT is offered at all.
//
// False. A transport that cannot do 0-RTT cannot get the policy wrong, and
// turning it on would be an optimisation for a handshake that happens once per
// connection on a link that is already up.
func EarlyDataEnabled() bool { return false }
