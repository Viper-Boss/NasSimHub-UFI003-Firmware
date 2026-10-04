package kcp

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// The four-packet session handshake, on both sides.
//
//	1. client -> server   Hello, no cookie, MAC'd
//	2. server -> client   Challenge: a cookie for this address. NOT authenticated,
//	                      and it cannot be - see UnmarshalChallenge for why that
//	                      is harmless.
//	3. client -> server   Hello + cookie, MAC'd. Cookie checked first, then MAC.
//	4. server -> client   Hello, MAC'd. The session exists.
//
// Step 4 is not decoration. Without it a client whose step 3 was lost would
// start sending data packets into a server that has no session for them and
// drops every one, and the failure would look like a dead link rather than a
// lost handshake. It also proves to the client that the peer holds the
// transport secret, which makes the exchange mutual: after step 4 each side has
// authenticated the other, before a single byte of TLS has moved.
//
// Nothing here is a key exchange. The key already exists - it was delivered
// over TLS at pairing time. This is address validation and proof of possession,
// and it is deliberately much cheaper than the TLS handshake that follows it,
// because being cheap is the entire point of doing it first.

// HandshakeTimeout bounds the whole exchange.
const HandshakeTimeout = 10 * time.Second

// handshakeAttempts is how many times a client will retry a lost packet.
const handshakeAttempts = 4

// Errors from the handshake.
var (
	// ErrHandshakeTimeout reports a handshake that did not complete.
	ErrHandshakeTimeout = errors.New("kcp: session handshake timed out")
	// ErrHandshakeRefused reports a peer that answered with something else.
	ErrHandshakeRefused = errors.New("kcp: session handshake was refused")
)

// clientHandshake runs steps 1, 3 and waits for 4.
//
// It uses the socket directly, before the session's read pump starts. Doing it
// inline rather than through the pump keeps the state machine out of the
// handshake: there is no window where a half-open session exists and something
// could write into it.
func clientHandshake(socket net.PacketConn, remote net.Addr, config *AuthConfig, timeout time.Duration) error {
	if config == nil || config.Ring == nil {
		return ErrNoSecret
	}
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}
	deadline := time.Now().Add(timeout)

	nonce, err := NewNonce()
	if err != nil {
		return err
	}
	var cookie []byte
	buffer := make([]byte, 2048)

	for attempt := 0; attempt < handshakeAttempts; attempt++ {
		if time.Now().After(deadline) {
			return ErrHandshakeTimeout
		}
		packet, err := sealHello(config.Ring, config.SessionID, Hello{Nonce: nonce, Cookie: cookie})
		if err != nil {
			return err
		}
		if _, err := socket.WriteTo(packet, remote); err != nil {
			return err
		}

		// One retry budget per attempt, so a lost challenge does not consume
		// the whole deadline on the first pass.
		wait := time.Until(deadline)
		if step := timeout / handshakeAttempts; step < wait {
			wait = step
		}
		_ = socket.SetReadDeadline(time.Now().Add(wait))
		n, from, err := socket.ReadFrom(buffer)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return err
		}
		if n <= 0 || from == nil {
			continue
		}
		reply := make([]byte, n)
		copy(reply, buffer[:n])

		if n >= 2 && reply[1] == PacketChallenge {
			_, issued, err := UnmarshalChallenge(reply)
			if err != nil {
				continue
			}
			// The challenge is unauthenticated, so a forged one costs this
			// client exactly one wasted packet: the cookie will not verify and
			// the real server will drop it. Nothing here is trusted beyond
			// "bytes to echo back".
			cookie = issued
			continue
		}

		header, err := PeekEnvelope(reply)
		if err != nil || header.Type != PacketHello {
			continue
		}
		key, err := config.Ring.Accepting(config.Ring.CurrentKeyID(), header.Epoch)
		if err != nil {
			continue
		}
		if _, _, err := OpenEnvelope(key, reply); err != nil {
			// A hello-shaped packet that does not authenticate is not the
			// peer. Ignored rather than treated as a refusal, so that an
			// attacker cannot end a legitimate handshake by racing one packet.
			continue
		}
		if header.SessionID != config.SessionID {
			continue
		}
		_ = socket.SetReadDeadline(time.Time{})
		return nil
	}
	_ = socket.SetReadDeadline(time.Time{})
	return fmt.Errorf("%w: no authenticated reply after %d attempts",
		ErrHandshakeTimeout, handshakeAttempts)
}

// serverAccept sends step 4.
func serverAccept(socket net.PacketConn, to net.Addr, config *AuthConfig, hello Hello) error {
	packet, err := sealHello(config.Ring, hello.SessionID, Hello{Nonce: hello.Nonce})
	if err != nil {
		return err
	}
	_, err = socket.WriteTo(packet, to)
	return err
}

// AmplificationRatio reports how many bytes the server sends in response to an
// unvalidated client packet, per byte received.
//
// Exposed rather than left implicit because it is a property that must be
// checked, not assumed: a future change that adds a field to the challenge
// could quietly turn the Node into an amplifier, and a number a test can assert
// is the only way that gets noticed.
func AmplificationRatio() float64 {
	return float64(challengeSize()) / float64(helloSize(0))
}
