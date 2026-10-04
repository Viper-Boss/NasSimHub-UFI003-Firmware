// Package netem is a deterministic network emulator.
//
// It exists because the interesting claims about a weak-network transport - it
// recovers faster at 5% loss, forward error correction earns its overhead above
// some threshold - cannot be tested on loopback, which loses nothing, and
// cannot be tested on a real cellular link without a laboratory and a great
// deal of patience.
//
// # What it does and does not model
//
// It models: independent per-packet loss, one-way delay, jitter, duplication,
// and reordering that follows from jitter. Each endpoint is a net.PacketConn,
// so a real KCP session with a real TLS handshake on top runs over it
// unmodified - the code under test cannot tell it apart from a socket.
//
// It does NOT model: bursty loss, which is what cellular links actually do;
// bandwidth limits and the queueing delay that comes with them; competing
// traffic; a radio that stops for 400 ms during a handover; MTU discovery
// failures. Every one of those changes the answer, and several of them would
// change it in the direction that flatters this implementation less.
//
// So numbers from here are a floor on how well something works, useful for
// COMPARING two transports under identical conditions, and not a prediction of
// field performance. The benchmark document says so where the numbers appear.
//
// # Determinism
//
// Loss, jitter and duplication are drawn from a seeded PRNG, so the same seed
// produces the same pattern of dropped packets on every run. That is what makes
// a regression visible: a change that makes recovery worse shows up as a
// different number, not as noise. Delivery timing uses real time, so wall-clock
// results still vary by a millisecond or two - the pattern is deterministic,
// the schedule is not.
package netem

import (
	"errors"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"
)

// Profile describes a link.
type Profile struct {
	// Name is for benchmark tables.
	Name string
	// Loss is the fraction of packets dropped in each direction, 0 to 1.
	Loss float64
	// RTT is the round trip; each direction gets half.
	RTT time.Duration
	// Jitter is the maximum random variation added to each one-way delay. It
	// is uniform rather than the heavy-tailed distribution a real link shows,
	// which is one of the ways this is a floor rather than a prediction.
	Jitter time.Duration
	// Duplicate is the fraction of packets delivered twice.
	Duplicate float64
	// Seed makes the run reproducible.
	Seed int64
}

// Address is an emulated endpoint address.
type Address struct{ name string }

// Network implements net.Addr.
func (a Address) Network() string { return "netem" }

// String implements net.Addr.
func (a Address) String() string { return a.name }

// Stats counts what the emulator did, so a test can assert that loss actually
// happened rather than trusting the configuration.
type Stats struct {
	Sent       int
	Delivered  int
	Dropped    int
	Duplicated int
}

// Conn is one end of an emulated link. It implements net.PacketConn.
type Conn struct {
	address Address
	peer    *Conn

	mu       sync.Mutex
	inbox    [][]byte
	from     []net.Addr
	closed   bool
	deadline time.Time
	signal   chan struct{}

	// outbound is this endpoint's queue of packets in flight towards the peer,
	// ordered by delivery time and drained by one goroutine. See schedule.
	outbound []pending
	sending  bool

	link *link
}

type link struct {
	mu        sync.Mutex
	random    *rand.Rand
	profile   Profile
	stats     Stats
	inFlight  sync.WaitGroup
	closed    bool
	maxInbox  int
	dropQueue int
}

// DefaultMaxInbox bounds the packets an endpoint will hold for a reader that is
// not reading. Without it the emulator becomes the memory leak it is supposed
// to be testing for.
const DefaultMaxInbox = 4096

// Pair builds two connected endpoints.
func Pair(profile Profile) (*Conn, *Conn) {
	if profile.Seed == 0 {
		profile.Seed = 1
	}
	shared := &link{
		random:   rand.New(rand.NewSource(profile.Seed)),
		profile:  profile,
		maxInbox: DefaultMaxInbox,
	}
	left := &Conn{address: Address{name: "netem:left"}, link: shared, signal: make(chan struct{}, 1)}
	right := &Conn{address: Address{name: "netem:right"}, link: shared, signal: make(chan struct{}, 1)}
	left.peer, right.peer = right, left
	return left, right
}

// WriteTo implements net.PacketConn. The destination is ignored: the emulator
// is a two-ended link, and a packet always goes to the other end.
func (c *Conn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}

	c.link.mu.Lock()
	if c.link.closed {
		c.link.mu.Unlock()
		return len(packet), nil
	}
	profile := c.link.profile
	c.link.stats.Sent++
	lost := c.link.random.Float64() < profile.Loss
	duplicated := !lost && profile.Duplicate > 0 && c.link.random.Float64() < profile.Duplicate
	delay := profile.RTT / 2
	if profile.Jitter > 0 {
		delay += time.Duration(c.link.random.Int63n(int64(profile.Jitter)))
	}
	if lost {
		c.link.stats.Dropped++
	}
	if duplicated {
		c.link.stats.Duplicated++
	}
	c.link.mu.Unlock()

	if lost {
		// Reported as written. A real socket does the same: loss is not an
		// error the sender learns about.
		return len(packet), nil
	}

	copies := 1
	if duplicated {
		copies = 2
	}
	for i := 0; i < copies; i++ {
		body := make([]byte, len(packet))
		copy(body, packet)
		c.schedule(body, delay)
	}
	return len(packet), nil
}

// schedule queues a packet for delivery at now+delay.
//
// Delivery is serialised through one goroutine per direction, in time order.
// A goroutine per packet - the obvious implementation - reorders packets that
// share a delivery time, because the runtime is free to run them in any order.
// That made a profile with ZERO jitter reorder packets, which is not a network
// behaviour and quietly changed what the benchmarks were measuring: forward
// error correction appeared to "recover" packets on a link that had lost
// nothing, because parity arrived before a data packet that was never lost.
func (c *Conn) schedule(body []byte, delay time.Duration) {
	at := time.Now().Add(delay)
	c.link.mu.Lock()
	c.outbound = append(c.outbound, pending{body: body, at: at})
	sort.SliceStable(c.outbound, func(i, j int) bool {
		return c.outbound[i].at.Before(c.outbound[j].at)
	})
	if !c.sending {
		c.sending = true
		c.link.inFlight.Add(1)
		go c.deliverLoop()
	}
	c.link.mu.Unlock()
}

type pending struct {
	body []byte
	at   time.Time
}

func (c *Conn) deliverLoop() {
	defer c.link.inFlight.Done()
	for {
		c.link.mu.Lock()
		if len(c.outbound) == 0 {
			c.sending = false
			c.link.mu.Unlock()
			return
		}
		next := c.outbound[0]
		c.link.mu.Unlock()

		if wait := time.Until(next.at); wait > 0 {
			timer := time.NewTimer(wait)
			<-timer.C
			timer.Stop()
		}

		c.link.mu.Lock()
		if len(c.outbound) == 0 {
			c.sending = false
			c.link.mu.Unlock()
			return
		}
		packet := c.outbound[0]
		c.outbound = c.outbound[1:]
		c.link.mu.Unlock()

		c.peer.deliver(packet.body, c.address)
	}
}

func (c *Conn) deliver(packet []byte, from net.Addr) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if len(c.inbox) >= c.link.maxInbox {
		// The bound. A dropped packet here is indistinguishable from one the
		// link lost, which is the correct behaviour for a receiver that has
		// stopped keeping up.
		c.mu.Unlock()
		c.link.mu.Lock()
		c.link.dropQueue++
		c.link.mu.Unlock()
		return
	}
	c.inbox = append(c.inbox, packet)
	c.from = append(c.from, from)
	c.mu.Unlock()

	c.link.mu.Lock()
	c.link.stats.Delivered++
	c.link.mu.Unlock()

	select {
	case c.signal <- struct{}{}:
	default:
	}
}

// ReadFrom implements net.PacketConn.
func (c *Conn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		if len(c.inbox) > 0 {
			packet, from := c.inbox[0], c.from[0]
			c.inbox = c.inbox[1:]
			c.from = c.from[1:]
			c.mu.Unlock()
			return copy(buffer, packet), from, nil
		}
		if c.closed {
			c.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		deadline := c.deadline
		c.mu.Unlock()

		var timeout <-chan time.Time
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, nil, timeoutError{}
			}
			timer := time.NewTimer(remaining)
			defer timer.Stop()
			timeout = timer.C
		}
		select {
		case <-c.signal:
		case <-timeout:
			return 0, nil, timeoutError{}
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// Close implements net.PacketConn.
func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	select {
	case c.signal <- struct{}{}:
	default:
	}
	return nil
}

// LocalAddr implements net.PacketConn.
func (c *Conn) LocalAddr() net.Addr { return c.address }

// SetDeadline implements net.PacketConn.
func (c *Conn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

// SetReadDeadline implements net.PacketConn.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline implements net.PacketConn. Writes never block here.
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }

// Stats reports what the link did.
func (c *Conn) Stats() Stats {
	c.link.mu.Lock()
	defer c.link.mu.Unlock()
	return c.link.stats
}

// ObservedLoss is the fraction actually dropped, which a test should assert
// against the configured rate rather than assuming they match.
func (c *Conn) ObservedLoss() float64 {
	stats := c.Stats()
	if stats.Sent == 0 {
		return 0
	}
	return float64(stats.Dropped) / float64(stats.Sent)
}

// Shutdown stops the link and waits for in-flight packets, so a test can end
// without leaving delivery goroutines behind.
func (c *Conn) Shutdown() {
	c.link.mu.Lock()
	c.link.closed = true
	c.link.mu.Unlock()
	c.link.inFlight.Wait()
	_ = c.Close()
	_ = c.peer.Close()
}

// Remote is the address to dial for the other end.
func (c *Conn) Remote() net.Addr { return c.peer.address }

type timeoutError struct{}

func (timeoutError) Error() string   { return "netem: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// Profiles is the standard grid the benchmarks use.
//
// It is written out here rather than built in the benchmark so that every
// document quoting a number refers to the same conditions.
func Profiles() []Profile {
	var out []Profile
	for _, loss := range []float64{0, 0.01, 0.03, 0.05, 0.10} {
		for _, rtt := range []time.Duration{20 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond} {
			for _, jitter := range []time.Duration{0, 20 * time.Millisecond, 50 * time.Millisecond} {
				out = append(out, Profile{
					Name:   profileName(loss, rtt, jitter),
					Loss:   loss,
					RTT:    rtt,
					Jitter: jitter,
					Seed:   1,
				})
			}
		}
	}
	return out
}

func profileName(loss float64, rtt, jitter time.Duration) string {
	return formatPercent(loss) + " loss / " + rtt.String() + " rtt / " + jitter.String() + " jitter"
}

func formatPercent(value float64) string {
	switch {
	case value == 0:
		return "0%"
	case value < 0.015:
		return "1%"
	case value < 0.04:
		return "3%"
	case value < 0.075:
		return "5%"
	default:
		return "10%"
	}
}

// ErrClosed is returned when an endpoint is used after Close.
var ErrClosed = errors.New("netem: endpoint is closed")
