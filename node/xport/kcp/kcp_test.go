package kcp

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/xport/netem"
)

// pair wires two KCP sessions through the emulator.
func pair(t *testing.T, profile netem.Profile, options Options) (*Conn, *Conn) {
	t.Helper()

	left, right := netem.Pair(profile)
	listener, err := ListenWith(right, options)
	if err != nil {
		t.Fatal(err)
	}
	client, err := DialWith(left, left.Remote(), 0x4e534831, options, false)
	if err != nil {
		t.Fatal(err)
	}

	// The server session does not exist until the client sends something.
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	var server net.Conn
	select {
	case server = <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("no session was accepted")
	}

	// Consume the handshake byte the dial used to create the session.
	buffer := make([]byte, 5)
	if err := readFull(server, buffer); err != nil {
		t.Fatalf("read the opening message: %v", err)
	}
	if string(buffer) != "hello" {
		t.Fatalf("opening message is %q", buffer)
	}
	// Clear the deadline readFull set. A deadline left behind on a net.Conn
	// applies to every later read, including the ones crypto/tls makes during
	// its handshake - which fails twenty seconds later with a timeout that
	// looks like a transport bug and is not.
	_ = server.SetReadDeadline(time.Time{})
	_ = client.SetReadDeadline(time.Time{})

	t.Cleanup(func() {
		_ = client.Close()
		_ = listener.Close()
		left.Shutdown()
	})
	return client, server.(*Conn)
}

func readFull(conn net.Conn, buffer []byte) error {
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	_, err := io.ReadFull(conn, buffer)
	return err
}

func TestAStreamSurvivesACleanLink(t *testing.T) {
	t.Parallel()

	client, server := pair(t, netem.Profile{RTT: 20 * time.Millisecond, Seed: 1}, Options{})

	payload := make([]byte, 200*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = client.Write(payload)
	}()

	received := make([]byte, len(payload))
	if err := readFull(server, received); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(payload, received) {
		t.Fatal("the bytes that arrived are not the bytes that were sent")
	}
}

// The point of the whole exercise: a link that loses one packet in twenty still
// delivers every byte, in order, exactly once.
func TestAStreamSurvivesFivePercentLoss(t *testing.T) {
	t.Parallel()

	link := netem.Profile{Loss: 0.05, RTT: 100 * time.Millisecond, Jitter: 20 * time.Millisecond, Seed: 7}
	client, server := pair(t, link, Options{Profile: ProfileAggressive})

	payload := make([]byte, 64*1024)
	for index := range payload {
		payload[index] = byte(index)
	}
	go func() { _, _ = client.Write(payload) }()

	received := make([]byte, len(payload))
	if err := readFull(server, received); err != nil {
		t.Fatalf("read under loss: %v", err)
	}
	if !bytes.Equal(payload, received) {
		t.Fatal("the stream was corrupted by loss")
	}
	stats, _ := client.Stats()
	if stats.Retransmits == 0 {
		t.Fatal("5% loss produced no retransmissions; the emulator or the ARQ is not doing its job")
	}
	t.Logf("5%% loss: %d segments, %d retransmits (%d fast, %d timeout), srtt %s",
		stats.SegmentsSent, stats.Retransmits, stats.FastRetransmits, stats.TimeoutRetrans, stats.SRTT)
}

// Duplicated packets must not produce duplicated bytes. A reliable stream that
// delivers something twice is worse than one that loses it.
func TestDuplicatesAreNotDelivered(t *testing.T) {
	t.Parallel()

	link := netem.Profile{Loss: 0.02, Duplicate: 0.10, RTT: 50 * time.Millisecond, Seed: 3}
	client, server := pair(t, link, Options{})

	payload := bytes.Repeat([]byte("0123456789"), 2000)
	go func() { _, _ = client.Write(payload) }()

	received := make([]byte, len(payload))
	if err := readFull(server, received); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(payload, received) {
		t.Fatal("duplication corrupted the stream")
	}
}

// The send queue is bounded. A writer that outruns the link must be made to
// wait, not allowed to allocate until the device dies.
func TestTheSendQueueIsBounded(t *testing.T) {
	t.Parallel()

	config, err := ConfigFor(ProfileBalanced)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxBacklog = 16
	sent := 0
	k := New(1, config, func([]byte) { sent++ })

	payload := make([]byte, config.MTU-HeaderSize)
	var overflowed bool
	for i := 0; i < 1000; i++ {
		if err := k.Send(payload); err != nil {
			overflowed = true
			break
		}
	}
	if !overflowed {
		t.Fatal("a thousand segments went into a queue capped at sixteen")
	}
	if queued := k.Stats().SendQueue; queued > config.MaxBacklog {
		t.Fatalf("the queue holds %d segments with a cap of %d", queued, config.MaxBacklog)
	}
}

// The receive buffer is bounded too, and overrunning it fails the session
// rather than silently dropping bytes out of a reliable stream.
func TestTheReadBufferIsBounded(t *testing.T) {
	t.Parallel()

	client, server := pair(t, netem.Profile{RTT: 5 * time.Millisecond, Seed: 11},
		Options{ReadBuffer: 32 * 1024})

	// Write far more than the reader's buffer, and never read it.
	go func() {
		payload := make([]byte, 8*1024)
		for i := 0; i < 64; i++ {
			if _, err := client.Write(payload); err != nil {
				return
			}
		}
	}()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		stats, _ := server.Stats()
		if stats.RecvQueue > 0 || server.bufferedForTest() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Whatever happens, the session must not be holding more than its cap.
	if buffered := server.bufferedForTest(); buffered > 32*1024 {
		t.Fatalf("the read buffer holds %d bytes with a cap of %d", buffered, 32*1024)
	}
}

func TestMemoryBudgetIsFinite(t *testing.T) {
	t.Parallel()

	for _, profile := range []Profile{ProfileBalanced, ProfileAggressive} {
		config, err := ConfigFor(profile)
		if err != nil {
			t.Fatal(err)
		}
		budget := config.MemoryBudget()
		if budget <= 0 {
			t.Fatalf("%s has no memory budget", profile)
		}
		// A device with 256 MB cannot afford a profile whose single session
		// could hold more than a few tens of megabytes.
		if budget > 32<<20 {
			t.Fatalf("%s can hold %d MB in one session", profile, budget>>20)
		}
		t.Logf("%s worst case %d MB per session", profile, budget>>20)
	}
}

func TestUnknownProfileAndFECModeAreRefused(t *testing.T) {
	t.Parallel()

	if _, err := ConfigFor("turbo"); err == nil {
		t.Fatal("an unknown profile was accepted")
	}
	if ValidFECMode("maximum") {
		t.Fatal("an unknown fec mode was accepted")
	}
	if _, err := (Options{Profile: "turbo"}).resolve(); err == nil {
		t.Fatal("options with an unknown profile resolved")
	}
}
