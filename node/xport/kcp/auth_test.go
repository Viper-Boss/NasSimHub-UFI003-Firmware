package kcp

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// The authenticated envelope, the replay window, the key ring and the cookie -
// tested for the properties they exist to provide, not for their internals.

func mustSecret(t *testing.T, epoch uint32) TransportSecret {
	t.Helper()
	secret, err := NewTransportSecret(epoch)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

// authedPair starts an authenticated listener and dials it, over real UDP.
func authedPair(t *testing.T) (client, server *Conn, serverStats, clientStats *AuthCounters, secret TransportSecret) {
	t.Helper()
	secret = mustSecret(t, 1)

	serverRing, err := NewKeyRing(secret, RoleNode)
	if err != nil {
		t.Fatal(err)
	}
	cookies, err := NewCookieAuthority()
	if err != nil {
		t.Fatal(err)
	}
	serverStats = NewAuthCounters()
	listener, err := Listen("127.0.0.1:0", Options{
		Profile: ProfileAggressive,
		Auth: &AuthConfig{
			Ring:    serverRing,
			Cookies: cookies,
			Limiter: NewHandshakeLimiter(),
			Stats:   serverStats,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan *Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn.(*Conn)
		}
	}()

	clientRing, err := NewKeyRing(secret, RoleCore)
	if err != nil {
		t.Fatal(err)
	}
	clientStats = NewAuthCounters()
	client, err = Dial(listener.Addr().String(), Options{
		Profile: ProfileAggressive,
		Auth: &AuthConfig{
			Ring:      clientRing,
			SessionID: 0x5150,
			Stats:     clientStats,
		},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	select {
	case server = <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("the server never accepted the authenticated session")
	}
	t.Cleanup(func() { _ = server.Close() })
	return client, server, serverStats, clientStats, secret
}

func TestAnAuthenticatedSessionCarriesData(t *testing.T) {
	client, server, _, _, _ := authedPair(t)

	payload := []byte("hello over an authenticated envelope")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = server.SetReadDeadline(time.Now().Add(10 * time.Second))
	buffer := make([]byte, len(payload))
	if _, err := readFullConn(server, buffer); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer, payload) {
		t.Fatalf("received %q", buffer)
	}
}

func readFullConn(conn net.Conn, buffer []byte) (int, error) {
	read := 0
	for read < len(buffer) {
		n, err := conn.Read(buffer[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

// The central claim of the whole layer.
func TestAForgedPacketNeverReachesTheKCPParser(t *testing.T) {
	client, server, serverStats, _, _ := authedPair(t)

	// Establish the session and let it settle, so the baseline is a real one.
	if _, err := client.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 3)
	if _, err := readFullConn(server, buffer); err != nil {
		t.Fatal(err)
	}
	before := server.kcp.Stats().SegmentsReceived

	// Now spray packets with a valid-looking envelope and a wrong MAC.
	attacker, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	target, err := net.ResolveUDPAddr("udp", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := make([]byte, MACKeySize)
	for i := 0; i < 50; i++ {
		forged, err := SealEnvelope(wrongKey, EnvelopeHeader{
			Type:      PacketData,
			SessionID: 0x5150,
			Epoch:     1,
			Counter:   uint64(1000 + i),
		}, bytes.Repeat([]byte{0xAB}, 64))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := attacker.WriteTo(forged, target); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(300 * time.Millisecond)

	if after := server.kcp.Stats().SegmentsReceived; after != before {
		t.Fatalf("the KCP parser saw %d segments after the forgery, %d before",
			after, before)
	}
	if failures := serverStats.Snapshot().MACFailures; failures == 0 {
		t.Fatal("the forged packets were not counted as authentication failures")
	}

	// And the real session still works, which matters: a layer that defended
	// itself by breaking the connection would be its own denial of service.
	if _, err := client.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := readFullConn(server, buffer); err != nil {
		t.Fatalf("the session died after a forgery: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Replay window
// ---------------------------------------------------------------------------

func TestAReplayedCounterIsRejected(t *testing.T) {
	window := NewReplayWindow()
	if err := window.Accept(1); err != nil {
		t.Fatal(err)
	}
	if err := window.Accept(1); !errors.Is(err, ErrReplay) {
		t.Fatalf("a repeated counter returned %v", err)
	}
	if err := window.Accept(2); err != nil {
		t.Fatal(err)
	}
	if err := window.Accept(2); !errors.Is(err, ErrReplay) {
		t.Fatalf("a repeated counter returned %v", err)
	}
}

func TestOutOfOrderWithinTheWindowIsAccepted(t *testing.T) {
	window := NewReplayWindow()
	// A lossy link reorders. Refusing anything out of order would make the
	// window itself the cause of retransmissions.
	for _, counter := range []uint64{10, 8, 9, 12, 11} {
		if err := window.Accept(counter); err != nil {
			t.Fatalf("counter %d was refused: %v", counter, err)
		}
	}
	for _, counter := range []uint64{8, 9, 10, 11, 12} {
		if err := window.Accept(counter); !errors.Is(err, ErrReplay) {
			t.Fatalf("replaying %d returned %v", counter, err)
		}
	}
}

func TestACounterBelowTheWindowIsRejected(t *testing.T) {
	window := NewReplayWindow()
	if err := window.Accept(ReplayWindowSize * 4); err != nil {
		t.Fatal(err)
	}
	if err := window.Accept(1); !errors.Is(err, ErrTooOld) {
		t.Fatalf("an ancient counter returned %v", err)
	}
	// The edge of the window is still usable.
	edge := uint64(ReplayWindowSize*4) - ReplayWindowSize + 1
	if err := window.Accept(edge); err != nil {
		t.Fatalf("the oldest in-window counter was refused: %v", err)
	}
}

func TestTheWindowSlidesWithoutForgettingRecentCounters(t *testing.T) {
	window := NewReplayWindow()
	if err := window.Accept(100); err != nil {
		t.Fatal(err)
	}
	if err := window.Accept(200); err != nil {
		t.Fatal(err)
	}
	// 100 is still inside the window after sliding to 200, so it must still be
	// remembered as seen.
	if err := window.Accept(100); !errors.Is(err, ErrReplay) {
		t.Fatalf("a counter the window should still remember returned %v", err)
	}
}

// ---------------------------------------------------------------------------
// Key ring: rotation, grace, epochs, destruction
// ---------------------------------------------------------------------------

func TestDirectionalKeysDiffer(t *testing.T) {
	secret := mustSecret(t, 1)
	core, err := Derive(secret, RoleCore)
	if err != nil {
		t.Fatal(err)
	}
	node, err := Derive(secret, RoleNode)
	if err != nil {
		t.Fatal(err)
	}
	// The two ends must agree on each direction...
	if !bytes.Equal(core.TX, node.RX) || !bytes.Equal(core.RX, node.TX) {
		t.Fatal("the two ends do not derive matching directional keys")
	}
	// ...and the two directions must not be the same key, or a captured packet
	// could be reflected back at its sender and authenticate.
	if bytes.Equal(core.TX, core.RX) {
		t.Fatal("send and receive keys are identical; reflection would verify")
	}
}

func TestAnEpochChangeChangesTheKeys(t *testing.T) {
	secret := mustSecret(t, 1)
	first, err := Derive(secret, RoleCore)
	if err != nil {
		t.Fatal(err)
	}
	secret.Epoch = 2
	second, err := Derive(secret, RoleCore)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.TX, second.TX) {
		t.Fatal("rotating the epoch produced the same key, so a rekey changes nothing")
	}
}

func TestAnOldEpochIsRejectedOutsideTheGraceWindow(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	secret := mustSecret(t, 1)
	ring, err := NewKeyRing(secret, RoleNode)
	if err != nil {
		t.Fatal(err)
	}
	ring.SetClock(clock)
	ring.SetGrace(30 * time.Second)

	next := secret
	next.Epoch = 2
	if err := ring.Rotate(next); err != nil {
		t.Fatal(err)
	}

	// Inside the grace window the old epoch is still accepted, so packets
	// already in flight are not lost.
	if _, err := ring.Accepting(secret.KeyID, 1); err != nil {
		t.Fatalf("the previous epoch was refused during its grace window: %v", err)
	}
	// Outside it, refused.
	now = now.Add(31 * time.Second)
	if _, err := ring.Accepting(secret.KeyID, 1); !errors.Is(err, ErrEpoch) {
		t.Fatalf("an expired epoch returned %v", err)
	}
	// The new epoch works throughout.
	if _, err := ring.Accepting(secret.KeyID, 2); err != nil {
		t.Fatalf("the current epoch was refused: %v", err)
	}
}

func TestAnUnknownKeyIDIsRejected(t *testing.T) {
	ring, err := NewKeyRing(mustSecret(t, 1), RoleNode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Accepting("not-a-key-id", 1); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("an unknown key id returned %v", err)
	}
}

func TestDestroyingTheRingLeavesNothingUsable(t *testing.T) {
	secret := mustSecret(t, 1)
	ring, err := NewKeyRing(secret, RoleNode)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ring.Sending()
	if err != nil {
		t.Fatal(err)
	}
	retained := keys.TX

	ring.Destroy()
	if !ring.Empty() {
		t.Fatal("the ring still holds keys after Destroy")
	}
	if _, err := ring.Sending(); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("a destroyed ring still produced a send key: %v", err)
	}
	if _, err := ring.Accepting(secret.KeyID, 1); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("a destroyed ring still produced a receive key: %v", err)
	}
	// The bytes the caller was holding are zeroed too, which is what makes
	// "destroyed" mean something rather than merely "dropped".
	if !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("the derived key bytes were not zeroed")
	}
}

func TestDestroyingASecretZeroesIt(t *testing.T) {
	secret := mustSecret(t, 1)
	held := secret.Secret
	secret.Destroy()
	if !secret.Zero() {
		t.Fatal("the secret still reports itself as present")
	}
	if !bytes.Equal(held, make([]byte, SecretSize)) {
		t.Fatal("the secret bytes were not zeroed")
	}
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

func addr(t *testing.T, text string) net.Addr {
	t.Helper()
	resolved, err := net.ResolveUDPAddr("udp", text)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestACookieOnlyVerifiesForTheAddressItWasIssuedTo(t *testing.T) {
	authority, err := NewCookieAuthority()
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("0123456789abcdef")
	client := addr(t, "192.0.2.10:5000")
	cookie := authority.Issue(client, nonce)

	if err := authority.Verify(client, nonce, cookie); err != nil {
		t.Fatalf("a freshly issued cookie did not verify: %v", err)
	}
	// The whole point: an attacker who observes a cookie cannot use it from
	// their own address, and a spoofer never receives one in the first place.
	if err := authority.Verify(addr(t, "198.51.100.7:5000"), nonce, cookie); !errors.Is(err, ErrCookieInvalid) {
		t.Fatalf("a cookie verified for a different address: %v", err)
	}
	if err := authority.Verify(addr(t, "192.0.2.10:5001"), nonce, cookie); !errors.Is(err, ErrCookieInvalid) {
		t.Fatalf("a cookie verified for a different port: %v", err)
	}
	if err := authority.Verify(client, []byte("fedcba9876543210"), cookie); !errors.Is(err, ErrCookieInvalid) {
		t.Fatalf("a cookie verified for a different nonce: %v", err)
	}
}

func TestAnExpiredCookieIsRejected(t *testing.T) {
	authority, err := NewCookieAuthority()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	authority.SetClock(func() time.Time { return now })

	client := addr(t, "192.0.2.10:5000")
	nonce := []byte("0123456789abcdef")
	cookie := authority.Issue(client, nonce)

	// One bucket either side is accepted, so a client that replies across a
	// boundary is not punished for it.
	now = now.Add(CookieBucket)
	if err := authority.Verify(client, nonce, cookie); err != nil {
		t.Fatalf("a cookie one bucket old was refused: %v", err)
	}
	// Well beyond, refused.
	now = now.Add(10 * CookieBucket)
	if err := authority.Verify(client, nonce, cookie); !errors.Is(err, ErrCookieInvalid) {
		t.Fatalf("an expired cookie returned %v", err)
	}
}

func TestAForgedCookieIsRejected(t *testing.T) {
	authority, err := NewCookieAuthority()
	if err != nil {
		t.Fatal(err)
	}
	client := addr(t, "192.0.2.10:5000")
	nonce := []byte("0123456789abcdef")
	for _, forged := range [][]byte{
		make([]byte, CookieSize),
		bytes.Repeat([]byte{0xFF}, CookieSize),
		bytes.Repeat([]byte{0x01}, CookieSize-1),
		nil,
	} {
		if err := authority.Verify(client, nonce, forged); err == nil {
			t.Fatalf("a forged cookie of %d bytes verified", len(forged))
		}
	}
}

// ---------------------------------------------------------------------------
// Denial of service
// ---------------------------------------------------------------------------

// A hello with no cookie must produce a challenge and nothing else. No session,
// no buffer, no TLS, no ML-KEM.
func TestAHelloWithoutACookieAllocatesNoSession(t *testing.T) {
	secret := mustSecret(t, 1)
	ring, err := NewKeyRing(secret, RoleNode)
	if err != nil {
		t.Fatal(err)
	}
	cookies, err := NewCookieAuthority()
	if err != nil {
		t.Fatal(err)
	}
	stats := NewAuthCounters()
	listener, err := Listen("127.0.0.1:0", Options{
		Auth: &AuthConfig{Ring: ring, Cookies: cookies, Limiter: NewHandshakeLimiter(), Stats: stats},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	attacker, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	target := addr(t, listener.Addr().String())

	clientRing, err := NewKeyRing(secret, RoleCore)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		nonce, err := NewNonce()
		if err != nil {
			t.Fatal(err)
		}
		hello, err := sealHello(clientRing, uint64(i+1), Hello{Nonce: nonce})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := attacker.WriteTo(hello, target); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(300 * time.Millisecond)

	if count := listener.authed.count(); count != 0 {
		t.Fatalf("%d sessions were allocated for helloes with no cookie", count)
	}
	if issued := stats.Snapshot().CookieIssued; issued == 0 {
		t.Fatal("no challenges were issued, so the exchange never started")
	}
}

// A hello carrying somebody else's cookie must be dropped, still with no
// allocation.
func TestASpoofedCookieAllocatesNoSession(t *testing.T) {
	secret := mustSecret(t, 1)
	ring, err := NewKeyRing(secret, RoleNode)
	if err != nil {
		t.Fatal(err)
	}
	cookies, err := NewCookieAuthority()
	if err != nil {
		t.Fatal(err)
	}
	stats := NewAuthCounters()
	listener, err := Listen("127.0.0.1:0", Options{
		Auth: &AuthConfig{Ring: ring, Cookies: cookies, Limiter: NewHandshakeLimiter(), Stats: stats},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	attacker, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()

	clientRing, err := NewKeyRing(secret, RoleCore)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	// A cookie issued to somebody else entirely.
	stolen := cookies.Issue(addr(t, "203.0.113.5:9999"), nonce[:])
	hello, err := sealHello(clientRing, 77, Hello{Nonce: nonce, Cookie: stolen})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attacker.WriteTo(hello, addr(t, listener.Addr().String())); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	if count := listener.authed.count(); count != 0 {
		t.Fatalf("%d sessions were allocated for a stolen cookie", count)
	}
	if rejected := stats.Snapshot().CookieBad; rejected == 0 {
		t.Fatal("the stolen cookie was not counted as rejected")
	}
}

// The reply to an unvalidated packet must not be bigger than the packet.
func TestTheChallengeCannotAmplify(t *testing.T) {
	if challengeSize() > helloSize(0) {
		t.Fatalf("a %d-byte challenge answers a %d-byte hello, which is an amplifier",
			challengeSize(), helloSize(0))
	}
	if ratio := AmplificationRatio(); ratio > 1 {
		t.Fatalf("amplification ratio is %.2f", ratio)
	}
}

func TestThePerSourceRateLimitStopsOneAddress(t *testing.T) {
	now := time.Now()
	limiter := NewHandshakeLimiter()
	limiter.SetClock(func() time.Time { return now })

	client := addr(t, "192.0.2.10:5000")
	allowed := 0
	for i := 0; i < 50; i++ {
		if limiter.Allow(client) {
			allowed++
		}
	}
	if allowed > PerSourceHandshakeBurst {
		t.Fatalf("one address got %d handshakes, burst is %d", allowed, PerSourceHandshakeBurst)
	}
	// Another address is unaffected, which matters: a limiter that let one
	// attacker lock out every other client would be the attack.
	if !limiter.Allow(addr(t, "198.51.100.7:5000")) {
		t.Fatal("a different address was refused because of the first one")
	}
}

func TestTheGlobalRateLimitStopsADistributedFlood(t *testing.T) {
	now := time.Now()
	limiter := NewHandshakeLimiter()
	limiter.SetClock(func() time.Time { return now })

	// One packet each from many addresses: every per-source bucket is full, so
	// only the global bucket can stop this.
	allowed := 0
	for i := 0; i < 500; i++ {
		source := addr(t, netIP(i)+":5000")
		if limiter.Allow(source) {
			allowed++
		}
	}
	if allowed > GlobalHandshakeBurst {
		t.Fatalf("a distributed flood got %d handshakes, global burst is %d",
			allowed, GlobalHandshakeBurst)
	}
}

func TestTheSourceTableIsBounded(t *testing.T) {
	now := time.Now()
	limiter := NewHandshakeLimiter()
	limiter.SetClock(func() time.Time { return now })
	for i := 0; i < MaxTrackedSources*2; i++ {
		limiter.Allow(addr(t, netIP(i)+":5000"))
	}
	if tracked := limiter.Tracked(); tracked > MaxTrackedSources {
		t.Fatalf("the limiter tracks %d sources, bound is %d", tracked, MaxTrackedSources)
	}
}

// netIP turns a counter into a distinct address, for flood tests.
func netIP(i int) string {
	return "10." + itoa((i>>16)&0xFF) + "." + itoa((i>>8)&0xFF) + "." + itoa(i&0xFF)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	digits := ""
	for v > 0 {
		digits = string(rune('0'+v%10)) + digits
		v /= 10
	}
	return digits
}

// ---------------------------------------------------------------------------
// Envelope encoding
// ---------------------------------------------------------------------------

func TestSealAndOpenRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x2A}, MACKeySize)
	header := EnvelopeHeader{Type: PacketData, SessionID: 0xDEADBEEF, Epoch: 7, Counter: 99}
	payload := []byte("a kcp datagram")

	packet, err := SealEnvelope(key, header, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, body, err := OpenEnvelope(key, packet)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != header.SessionID || got.Epoch != header.Epoch || got.Counter != header.Counter {
		t.Fatalf("header round trip produced %+v", got)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("payload round trip produced %q", body)
	}
}

// Every field is covered by the MAC, so none of them can be edited in flight.
// The counter matters most: an editable counter would let an attacker push the
// replay window forward and lock the real peer out.
func TestEveryHeaderFieldIsCoveredByTheMAC(t *testing.T) {
	key := bytes.Repeat([]byte{0x2A}, MACKeySize)
	packet, err := SealEnvelope(key, EnvelopeHeader{
		Type: PacketData, SessionID: 1, Epoch: 1, Counter: 1,
	}, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	for offset := 0; offset < envelopeHeaderSize+len("payload"); offset++ {
		tampered := append([]byte(nil), packet...)
		tampered[offset] ^= 0xFF
		if _, _, err := OpenEnvelope(key, tampered); err == nil {
			t.Fatalf("flipping byte %d still authenticated", offset)
		}
	}
}

func TestAShortPacketIsRefusedBeforeAnythingIsRead(t *testing.T) {
	key := bytes.Repeat([]byte{0x2A}, MACKeySize)
	for _, size := range []int{0, 1, envelopeHeaderSize, envelopeHeaderSize + MACSize - 1} {
		if _, _, err := OpenEnvelope(key, make([]byte, size)); !errors.Is(err, ErrEnvelopeShort) &&
			!errors.Is(err, ErrEnvelopeVersion) {
			t.Fatalf("a %d-byte packet returned %v", size, err)
		}
	}
}

func TestTheCounterNeverRepeats(t *testing.T) {
	var counter MonotonicCounter
	seen := map[uint64]bool{}
	for i := 0; i < 1000; i++ {
		value, err := counter.Next()
		if err != nil {
			t.Fatal(err)
		}
		if seen[value] {
			t.Fatalf("counter repeated %d", value)
		}
		seen[value] = true
	}
	// Counters start at one, so zero stays reserved for the handshake.
	if seen[0] {
		t.Fatal("the data counter issued zero, which the hello uses")
	}
}
