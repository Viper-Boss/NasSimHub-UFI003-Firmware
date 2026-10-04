package kcp

import (
	"errors"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"
)

// A net.Conn over KCP, so that crypto/tls can sit on top of it unchanged.
//
// That is the whole reason this file exists in this shape. TLS needs a
// net.Conn; give it one and the entire security model above - the pinned
// certificate, the hybrid post-quantum handshake, the device identity binding -
// works over UDP without knowing anything changed. No part of the trust model
// is reimplemented for this transport, which is the property that makes adding
// a transport safe.

// Options configures a session.
type Options struct {
	Profile Profile
	FEC     FECMode
	Config  Config
	// ReadBuffer bounds the bytes a session holds for a reader that is not
	// reading. Zero uses 1 MiB. It is a cap on memory, not a performance knob:
	// a peer that sends faster than this process consumes must eventually be
	// made to wait, and the alternative is an allocation that grows until the
	// device dies.
	ReadBuffer int
	// MaxSessions bounds how many peers a listener will track. Zero uses
	// defaultMaxSessions. It is part of the options rather than a field poked
	// onto the Listener afterwards because ListenWith starts the reader
	// goroutine before it returns: a later write would be a data race with the
	// dispatch that reads it, and the race detector found exactly that.
	MaxSessions int
	Now         func() time.Time
	// Auth turns on the authenticated envelope: every packet carries an
	// HMAC-SHA-256 over its header and payload, and a packet that does not
	// verify is dropped before the KCP state machine sees it. See auth.go for
	// the order of checks and why that order is the security property.
	//
	// Nil means no authentication, which is correct only for the benchmark
	// harness and for tests that measure the transport itself. A Node always
	// supplies one.
	Auth *AuthConfig
}

const defaultReadBuffer = 1 << 20

func (o Options) resolve() (Options, error) {
	if o.Profile == "" {
		o.Profile = ProfileBalanced
	}
	if !ValidProfile(o.Profile) {
		return o, errors.New("kcp: unknown profile " + string(o.Profile))
	}
	if o.FEC == "" {
		o.FEC = FECOff
	}
	if !ValidFECMode(o.FEC) {
		return o, errors.New("kcp: unknown fec mode " + string(o.FEC))
	}
	if o.Config == (Config{}) {
		config, err := ConfigFor(o.Profile)
		if err != nil {
			return o, err
		}
		o.Config = config
	}
	if o.ReadBuffer <= 0 {
		o.ReadBuffer = defaultReadBuffer
	}
	if o.MaxSessions <= 0 {
		o.MaxSessions = defaultMaxSessions
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o, nil
}

// Conn is a reliable ordered connection. It implements net.Conn.
type Conn struct {
	kcp     *KCP
	encoder *fecEncoder
	decoder *fecDecoder
	options Options

	socket net.PacketConn
	remote net.Addr
	owned  bool // this Conn closes the socket (a dialed client does; a server session does not)

	// auth is nil when the transport runs unauthenticated. When it is set,
	// every outgoing packet is sealed and every incoming one must open before
	// it reaches the decoder or the KCP parser.
	auth *connAuth

	mu       sync.Mutex
	incoming []byte
	readable chan struct{}
	closed   chan struct{}
	closeOne sync.Once
	failure  error

	readDeadline  atomicTime
	writeDeadline atomicTime

	stop chan struct{}
	done sync.WaitGroup
}

type atomicTime struct {
	mu sync.Mutex
	at time.Time
}

func (a *atomicTime) set(t time.Time) {
	a.mu.Lock()
	a.at = t
	a.mu.Unlock()
}

func (a *atomicTime) get() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.at
}

func newConn(socket net.PacketConn, remote net.Addr, conv uint32, options Options, owned bool) (*Conn, error) {
	resolved, err := options.resolve()
	if err != nil {
		return nil, err
	}
	c := &Conn{
		encoder:  newFECEncoder(resolved.FEC),
		decoder:  newFECDecoder(resolved.FEC),
		options:  resolved,
		socket:   socket,
		remote:   remote,
		owned:    owned,
		readable: make(chan struct{}, 1),
		closed:   make(chan struct{}),
		stop:     make(chan struct{}),
	}
	c.auth = newConnAuth(resolved.Auth)
	c.kcp = New(conv, resolved.Config, func(datagram []byte) {
		for _, packet := range c.encoder.encode(datagram) {
			if c.auth != nil {
				sealed, err := c.auth.seal(packet)
				if err != nil {
					// No key, or a counter that cannot advance. Dropping is
					// right: sending the packet unauthenticated would be a
					// silent downgrade of exactly the kind this layer exists
					// to prevent, and it would be invisible on both ends.
					continue
				}
				packet = sealed
			}
			_, _ = c.socket.WriteTo(packet, c.remote)
		}
	})
	c.done.Add(1)
	go c.pump()
	return c, nil
}

// pump drives the ARQ timers. It is the only goroutine a session owns, and it
// exits when the session closes - which is what makes a thousand connect and
// disconnect cycles leak nothing.
func (c *Conn) pump() {
	defer c.done.Done()
	interval := c.options.Config.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.kcp.Update(c.options.Now())
			if c.kcp.Dead() {
				c.fail(ErrDeadLink)
				return
			}
			c.drain()
		}
	}
}

// feed hands a received packet to the session.
// setRemote updates where this session's packets are sent.
//
// Only ever called with an address an authenticated packet arrived from. A
// session whose remote could be changed by an unauthenticated packet would be
// trivially hijackable: one spoofed datagram and the Node starts talking to the
// attacker instead of the NAS.
func (c *Conn) setRemote(remote net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if remote != nil && c.remote.String() != remote.String() {
		c.remote = remote
	}
}

// feedFrom authenticates a packet and, only if it authenticates, adopts the
// address it came from.
func (c *Conn) feedFrom(from net.Addr, packet []byte) {
	if c.auth != nil {
		payload, err := c.auth.open(packet)
		if err != nil {
			return
		}
		c.setRemote(from)
		c.deliver(payload)
		return
	}
	c.feed(packet)
}

// deliver hands an already-authenticated payload to the decoder and the state
// machine. It exists so that feed and feedFrom cannot diverge in what they do
// after authentication.
func (c *Conn) deliver(payload []byte) {
	for _, datagram := range c.decoder.decode(payload) {
		if err := c.kcp.Input(datagram); err != nil {
			continue
		}
	}
	c.drain()
}

func (c *Conn) feed(packet []byte) {
	if c.auth != nil {
		// The whole point of this layer, in three lines: a packet that fails
		// authentication returns here, having touched neither the FEC decoder
		// nor the KCP state machine. Both of those parse attacker-shaped
		// input; neither of them ever sees any.
		payload, err := c.auth.open(packet)
		if err != nil {
			return
		}
		packet = payload
	}
	for _, datagram := range c.decoder.decode(packet) {
		if err := c.kcp.Input(datagram); err != nil {
			// A malformed datagram is dropped, not fatal. On an open UDP port
			// anyone can send anything, and disconnecting on receipt of
			// garbage would hand any passer-by a way to kill the link.
			continue
		}
	}
	c.drain()
}

// drain moves completed messages into the read buffer.
func (c *Conn) drain() {
	for {
		message := c.kcp.Recv()
		if message == nil {
			return
		}
		c.mu.Lock()
		if len(c.incoming)+len(message) > c.options.ReadBuffer {
			// The cap. Dropping here would corrupt a TLS stream, so the
			// session fails instead: a reader that has stopped reading for
			// long enough to overrun a megabyte is not coming back, and a
			// clean failure is better than a stall nobody can diagnose.
			c.mu.Unlock()
			c.fail(errors.New("kcp: read buffer overrun; the application stopped reading"))
			return
		}
		c.incoming = append(c.incoming, message...)
		c.mu.Unlock()
		select {
		case c.readable <- struct{}{}:
		default:
		}
	}
}

// Read implements net.Conn.
func (c *Conn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.incoming) > 0 {
			n := copy(p, c.incoming)
			c.incoming = append(c.incoming[:0], c.incoming[n:]...)
			c.mu.Unlock()
			return n, nil
		}
		failure := c.failure
		c.mu.Unlock()

		select {
		case <-c.closed:
			if failure != nil {
				return 0, failure
			}
			return 0, io.EOF
		default:
		}
		if failure != nil {
			return 0, failure
		}

		var timeout <-chan time.Time
		if deadline := c.readDeadline.get(); !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, timeoutError{}
			}
			timer := time.NewTimer(remaining)
			defer timer.Stop()
			timeout = timer.C
		}
		select {
		case <-c.readable:
		case <-c.closed:
		case <-timeout:
			return 0, timeoutError{}
		case <-time.After(20 * time.Millisecond):
			// A short poll in addition to the signal, so a message that
			// arrived between the buffer check and the select is not waited
			// on until the next packet.
		}
	}
}

// Write implements net.Conn.
func (c *Conn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.mu.Lock()
	failure := c.failure
	c.mu.Unlock()
	if failure != nil {
		return 0, failure
	}

	deadline := c.writeDeadline.get()
	written := 0
	for written < len(p) {
		// Chunked so one enormous Write cannot exceed the queue cap in a
		// single call and fail outright.
		chunk := len(p) - written
		if maximum := c.kcp.MSS() * 32; chunk > maximum {
			chunk = maximum
		}
		err := c.kcp.Send(p[written : written+chunk])
		if errors.Is(err, ErrOverflow) {
			if !deadline.IsZero() && time.Now().After(deadline) {
				return written, timeoutError{}
			}
			select {
			case <-c.closed:
				return written, net.ErrClosed
			case <-time.After(5 * time.Millisecond):
			}
			continue
		}
		if err != nil {
			return written, err
		}
		written += chunk
	}
	c.kcp.Flush(c.options.Now())
	return written, nil
}

// Close implements net.Conn.
func (c *Conn) Close() error {
	c.closeOne.Do(func() {
		close(c.stop)
		close(c.closed)
	})
	c.done.Wait()
	if c.owned {
		return c.socket.Close()
	}
	return nil
}

func (c *Conn) fail(err error) {
	c.mu.Lock()
	if c.failure == nil {
		c.failure = err
	}
	c.mu.Unlock()
	select {
	case c.readable <- struct{}{}:
	default:
	}
}

// LocalAddr implements net.Conn.
func (c *Conn) LocalAddr() net.Addr { return c.socket.LocalAddr() }

// RemoteAddr implements net.Conn.
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline implements net.Conn.
func (c *Conn) SetDeadline(t time.Time) error {
	c.readDeadline.set(t)
	c.writeDeadline.set(t)
	return nil
}

// SetReadDeadline implements net.Conn.
func (c *Conn) SetReadDeadline(t time.Time) error { c.readDeadline.set(t); return nil }

// SetWriteDeadline implements net.Conn.
func (c *Conn) SetWriteDeadline(t time.Time) error { c.writeDeadline.set(t); return nil }

// Stats reports the ARQ and FEC counters for diagnostics.
func (c *Conn) Stats() (Stats, FECStats) {
	return c.kcp.Stats(), c.encoder.Stats()
}

// RecoveredByFEC reports how many datagrams parity reconstructed.
func (c *Conn) RecoveredByFEC() uint64 { return c.decoder.Stats().Recovered }

type timeoutError struct{}

func (timeoutError) Error() string   { return "kcp: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// ---------------------------------------------------------------------------
// Dial and Listen
// ---------------------------------------------------------------------------

// Dial opens a session to a remote address.
func Dial(address string, options Options) (*Conn, error) {
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	socket, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}
	conv := rand.Uint32()
	if conv == 0 {
		conv = 1
	}
	return DialWith(socket, remote, conv, options, true)
}

// DialWith opens a session over a caller-provided packet connection.
//
// The emulator in xport/netem is a net.PacketConn, which is how a deterministic
// loss and latency profile is applied to a real session without a real network.
func DialWith(socket net.PacketConn, remote net.Addr, conv uint32, options Options, owned bool) (*Conn, error) {
	resolved, err := options.resolve()
	if err != nil {
		if owned {
			_ = socket.Close()
		}
		return nil, err
	}
	// The handshake runs BEFORE the session exists, on the bare socket. There
	// is therefore no window in which a half-open session could be written to,
	// and no session is allocated at all if the peer never answers - which is
	// the client-side mirror of the server's rule about not allocating for an
	// unvalidated hello.
	if resolved.Auth != nil {
		if resolved.Auth.SessionID == 0 {
			// Session id zero is reserved so that an uninitialised value
			// cannot silently collide with a real session.
			resolved.Auth.SessionID = uint64(conv)<<32 | uint64(conv)
		}
		// The conversation id is DERIVED from the session id, on both ends,
		// rather than carried in the hello. With the envelope on, the KCP
		// header is inside the MAC, so there is nothing to parse before
		// authenticating - and a conv the peer could choose independently
		// would simply be a second identifier to keep in step for no gain.
		// The first version of this got it wrong: the client kept its random
		// conv while the server derived one, and every segment was discarded
		// on conv mismatch, which presents as a handshake that succeeds
		// followed by a session that carries nothing.
		conv = convForSession(resolved.Auth.SessionID)
		if err := clientHandshake(socket, remote, resolved.Auth, HandshakeTimeout); err != nil {
			if owned {
				_ = socket.Close()
			}
			return nil, err
		}
	}
	conn, err := newConn(socket, remote, conv, resolved, owned)
	if err != nil {
		if owned {
			_ = socket.Close()
		}
		return nil, err
	}
	conn.done.Add(1)
	go func() {
		defer conn.done.Done()
		buffer := make([]byte, 65536)
		for {
			select {
			case <-conn.stop:
				return
			default:
			}
			_ = socket.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, from, err := socket.ReadFrom(buffer)
			if n > 0 && sameAddr(from, remote) {
				packet := make([]byte, n)
				copy(packet, buffer[:n])
				conn.feed(packet)
			}
			if err != nil {
				if isTimeout(err) {
					continue
				}
				select {
				case <-conn.stop:
					return
				default:
				}
				conn.fail(err)
				return
			}
		}
	}()
	return conn, nil
}

// Listener accepts KCP sessions on one packet connection.
type Listener struct {
	socket   net.PacketConn
	options  Options
	sessions map[string]*Conn
	mu       sync.Mutex
	accept   chan *Conn
	stop     chan struct{}
	once     sync.Once
	done     sync.WaitGroup
	// authed is the session table used when the envelope is on. Keyed by
	// session id rather than by remote address: an authenticated packet proves
	// who sent it, so a peer whose NAT rebinding changed its source port keeps
	// its session. Without authentication that same behaviour would be a
	// hijacking primitive, which is why there are two tables and not one.
	authed *sessionKeys
	// MaxSessions bounds how many peers may be tracked at once. An unbounded
	// map keyed on remote address is a memory exhaustion primitive for anyone
	// who can send UDP packets from spoofed sources.
	//
	// Set it through Options.MaxSessions before the listener is created. It is
	// read by the dispatch goroutine that ListenWith starts, so writing it
	// afterwards is a data race.
	MaxSessions int
}

const defaultMaxSessions = 64

// Listen starts accepting sessions.
func Listen(address string, options Options) (*Listener, error) {
	socket, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}
	return ListenWith(socket, options)
}

// ListenWith accepts sessions on a caller-provided packet connection.
func ListenWith(socket net.PacketConn, options Options) (*Listener, error) {
	resolved, err := options.resolve()
	if err != nil {
		return nil, err
	}
	l := &Listener{
		socket:      socket,
		options:     resolved,
		sessions:    map[string]*Conn{},
		accept:      make(chan *Conn, 16),
		stop:        make(chan struct{}),
		MaxSessions: resolved.MaxSessions,
	}
	if resolved.Auth != nil {
		l.authed = newSessionKeys(resolved.MaxSessions)
	}
	l.done.Add(1)
	go l.serve()
	return l, nil
}

func (l *Listener) serve() {
	defer l.done.Done()
	buffer := make([]byte, 65536)
	for {
		select {
		case <-l.stop:
			return
		default:
		}
		_ = l.socket.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, from, err := l.socket.ReadFrom(buffer)
		// >=, not >. A packet carrying nothing but an acknowledgement is
		// exactly one FEC header plus one KCP header, and dropping those on
		// the floor leaves the peer's send window stuck at one segment
		// forever - a stall that looks like a congestion problem and is not.
		//
		// With the envelope on the floor is lower, because a hello carries no
		// KCP at all. The check is a cheap length filter, not a security
		// boundary: everything that matters happens in dispatchAuthenticated.
		floor := fecHeaderSize + HeaderSize
		if l.authed != nil {
			floor = envelopeHeaderSize + MACSize
		}
		if n >= floor {
			packet := make([]byte, n)
			copy(packet, buffer[:n])
			if l.authed != nil {
				l.dispatchAuthenticated(from, packet)
			} else {
				l.dispatch(from, packet)
			}
		}
		if err != nil {
			if isTimeout(err) {
				continue
			}
			select {
			case <-l.stop:
			default:
			}
			return
		}
	}
}

// dispatchAuthenticated is the packet path when the envelope is on.
//
// Two rules, both load-bearing:
//
//   - A DATA packet never allocates. If there is no session for the id it
//     names, it is dropped. An attacker who can forge a session id therefore
//     gains nothing: the table only grows through a completed handshake.
//   - A HELLO allocates only after handleHello has run the rate limiter, the
//     cookie check and the MAC check, in that order.
func (l *Listener) dispatchAuthenticated(from net.Addr, packet []byte) {
	config := l.options.Auth
	header, err := PeekEnvelope(packet)
	if err != nil {
		config.Stats.add(&config.Stats.malformed)
		return
	}

	switch header.Type {
	case PacketHello:
		outcome, hello := handleHello(l.socket, from, packet, config)
		if outcome != helloAccepted {
			return
		}
		if existing, known := l.authed.get(hello.SessionID); known {
			// A repeated hello for a live session. The peer probably lost the
			// acceptance; re-send it and keep the session rather than tearing
			// down a working conversation.
			existing.setRemote(from)
			_ = serverAccept(l.socket, from, config, hello)
			return
		}
		session, err := l.newAuthenticatedSession(from, hello)
		if err != nil {
			return
		}
		if !l.authed.put(hello.SessionID, session) {
			// At the session ceiling. Closing immediately rather than queueing
			// keeps the bound a real bound.
			_ = session.Close()
			return
		}
		if err := serverAccept(l.socket, from, config, hello); err != nil {
			l.authed.drop(hello.SessionID)
			_ = session.Close()
			return
		}
		select {
		case l.accept <- session:
		case <-l.stop:
			l.authed.drop(hello.SessionID)
			_ = session.Close()
		}

	case PacketData:
		session, known := l.authed.get(header.SessionID)
		if !known {
			config.Stats.add(&config.Stats.malformed)
			return
		}
		// The address is updated only after feed() authenticates the packet,
		// so a forged packet cannot redirect a session to an attacker. feed
		// returns nothing, so the update is done by the session itself.
		session.feedFrom(from, packet)

	default:
		config.Stats.add(&config.Stats.malformed)
	}
}

// convForSession maps a session id onto a KCP conversation id, identically on
// both ends.
func convForSession(id uint64) uint32 {
	conv := uint32(id) ^ uint32(id>>32)
	if conv == 0 {
		conv = 1
	}
	return conv
}

// newAuthenticatedSession builds the server side of an accepted handshake.
func (l *Listener) newAuthenticatedSession(from net.Addr, hello Hello) (*Conn, error) {
	options := l.options
	// Each session gets its own replay window and counter, sharing the ring.
	auth := *options.Auth
	auth.SessionID = hello.SessionID
	options.Auth = &auth
	// The conversation id is derived from the session id rather than read from
	// the packet: with the envelope on, the KCP header is inside the MAC and
	// there is no need to parse anything before authenticating it.
	return newConn(l.socket, from, convForSession(hello.SessionID), options, false)
}

func (l *Listener) dispatch(from net.Addr, packet []byte) {
	key := from.String()
	l.mu.Lock()
	session, known := l.sessions[key]
	if !known {
		if len(l.sessions) >= l.MaxSessions {
			l.mu.Unlock()
			return
		}
		// The conversation id is read from the packet, past the FEC header.
		if len(packet) < fecHeaderSize+HeaderSize {
			l.mu.Unlock()
			return
		}
		conv := uint32(packet[fecHeaderSize]) |
			uint32(packet[fecHeaderSize+1])<<8 |
			uint32(packet[fecHeaderSize+2])<<16 |
			uint32(packet[fecHeaderSize+3])<<24
		created, err := newConn(l.socket, from, conv, l.options, false)
		if err != nil {
			l.mu.Unlock()
			return
		}
		l.sessions[key] = created
		session = created
		l.mu.Unlock()
		select {
		case l.accept <- created:
		case <-l.stop:
			_ = created.Close()
			return
		}
	} else {
		l.mu.Unlock()
	}
	session.feed(packet)
}

// Accept returns the next session.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accept:
		return conn, nil
	case <-l.stop:
		return nil, net.ErrClosed
	}
}

// Close stops accepting and closes every session.
func (l *Listener) Close() error {
	l.once.Do(func() { close(l.stop) })
	l.done.Wait()
	l.mu.Lock()
	sessions := make([]*Conn, 0, len(l.sessions))
	for _, session := range l.sessions {
		sessions = append(sessions, session)
	}
	l.sessions = map[string]*Conn{}
	l.mu.Unlock()
	for _, session := range sessions {
		_ = session.Close()
	}
	return l.socket.Close()
}

// Addr reports where the listener is bound.
func (l *Listener) Addr() net.Addr { return l.socket.LocalAddr() }

// Sessions reports how many peers are tracked, for leak checks.
func (l *Listener) Sessions() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sessions)
}

func sameAddr(a, b net.Addr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.String() == b.String()
}

func isTimeout(err error) bool {
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

// bufferedForTest reports the bytes held for a reader that has not read. It
// exists so a test can assert the cap is real rather than inferring it.
func (c *Conn) bufferedForTest() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.incoming)
}
