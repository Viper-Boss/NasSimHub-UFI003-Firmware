package kcp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
	"github.com/human-agent65535/nassimhub-node/xport/netem"
)

// TLS over KCP.
//
// This is the test that decides whether the layering claim is true. If
// crypto/tls can complete a handshake over a KCP session and carry data, then
// the entire security model above - pinning, identity binding, the hybrid
// post-quantum key agreement - applies to this transport without a line of it
// being reimplemented. If it cannot, the design is wrong no matter how good the
// ARQ is.

func selfSigned(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "kcp-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"kcp-test.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: parsed}, parsed
}

// tlsOverKCP runs a handshake with the given groups and returns the two ends.
func tlsOverKCP(t *testing.T, link netem.Profile, options Options, groups []uint16) (*tls.Conn, *tls.Conn, error) {
	t.Helper()

	certificate, leaf := selfSigned(t)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	curves := make([]tls.CurveID, 0, len(groups))
	for _, group := range groups {
		curves = append(curves, tls.CurveID(group))
	}

	client, server := pair(t, link, options)

	serverConfig := &tls.Config{
		Certificates:     []tls.Certificate{certificate},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: curves,
	}
	clientConfig := &tls.Config{
		RootCAs:          roots,
		ServerName:       "kcp-test.local",
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: curves,
	}

	serverTLS := tls.Server(server, serverConfig)
	clientTLS := tls.Client(client, clientConfig)

	errs := make(chan error, 2)
	go func() { errs <- serverTLS.Handshake() }()
	go func() { errs <- clientTLS.Handshake() }()

	deadline := time.After(30 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if err != nil {
				return nil, nil, err
			}
		case <-deadline:
			t.Fatal("the TLS handshake over KCP did not finish")
		}
	}
	return clientTLS, serverTLS, nil
}

func TestTLSCompletesOverKCP(t *testing.T) {
	t.Parallel()

	client, server, err := tlsOverKCP(t,
		netem.Profile{RTT: 40 * time.Millisecond, Seed: 21},
		Options{},
		[]uint16{proto.GroupX25519MLKEM768})
	if err != nil {
		t.Fatalf("handshake over KCP: %v", err)
	}
	if state := client.ConnectionState(); state.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated TLS %x over KCP", state.Version)
	}

	go func() { _, _ = client.Write([]byte("over kcp and tls")) }()
	buffer := make([]byte, len("over kcp and tls"))
	_ = server.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(server, buffer); err != nil {
		t.Fatalf("read over TLS/KCP: %v", err)
	}
	if string(buffer) != "over kcp and tls" {
		t.Fatalf("received %q", buffer)
	}
}

// The handshake must survive a lossy link. A handshake is the worst case for
// loss: every message blocks the next, so one dropped packet costs a full
// retransmission timeout before anything else can happen.
func TestTLSHandshakeSurvivesLoss(t *testing.T) {
	t.Parallel()

	client, _, err := tlsOverKCP(t,
		netem.Profile{Loss: 0.05, RTT: 100 * time.Millisecond, Jitter: 20 * time.Millisecond, Seed: 31},
		Options{Profile: ProfileAggressive, FEC: FECBalanced},
		[]uint16{proto.GroupX25519MLKEM768})
	if err != nil {
		t.Fatalf("handshake over a 5%% loss link: %v", err)
	}
	if !client.ConnectionState().HandshakeComplete {
		t.Fatal("the handshake did not complete")
	}
}

// KCP must not be able to see or alter what it carries. This checks the weaker
// but checkable half: the bytes on the wire are not the plaintext.
func TestKCPCarriesOnlyCiphertext(t *testing.T) {
	t.Parallel()

	secret := "the quick brown fox jumps over the lazy dog"

	left, right := netem.Pair(netem.Profile{RTT: 10 * time.Millisecond, Seed: 5})
	captured := &capturingConn{PacketConn: left}

	listener, err := ListenWith(right, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	client, err := DialWith(captured, left.Remote(), 0x99, Options{}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	certificate, leaf := selfSigned(t)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	clientTLS := tls.Client(client, &tls.Config{
		RootCAs: roots, ServerName: "kcp-test.local", MinVersion: tls.VersionTLS13,
	})
	handshake := make(chan error, 1)
	go func() { handshake <- clientTLS.Handshake() }()

	var server net.Conn
	select {
	case server = <-accepted:
	case <-time.After(20 * time.Second):
		t.Fatal("no session accepted")
	}
	serverTLS := tls.Server(server, &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13,
	})
	go func() { _ = serverTLS.Handshake() }()

	select {
	case err := <-handshake:
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("handshake timed out")
	}

	if _, err := clientTLS.Write([]byte(secret)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(secret))
	_ = serverTLS.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(serverTLS, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != secret {
		t.Fatalf("received %q", buffer)
	}

	for _, packet := range captured.packets() {
		if containsSubslice(packet, []byte(secret)) {
			t.Fatal("the plaintext appeared in a KCP datagram; TLS is not actually above KCP")
		}
	}
	left.Shutdown()
}

type capturingConn struct {
	net.PacketConn
	seen [][]byte
}

func (c *capturingConn) WriteTo(packet []byte, addr net.Addr) (int, error) {
	c.seen = append(c.seen, append([]byte(nil), packet...))
	return c.PacketConn.WriteTo(packet, addr)
}

func (c *capturingConn) packets() [][]byte { return c.seen }

func containsSubslice(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
