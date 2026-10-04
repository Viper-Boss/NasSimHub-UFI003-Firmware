// Package xport is the unified transport layer: one interface, several ways of
// moving bytes, and no way for the business layer to tell them apart.
//
// The name avoids a collision. core/transport already exists and does something
// different - it chooses which ENDPOINT of a Node to talk to, USB or Wi-Fi, and
// keeps the device's identity stable across that choice. This package chooses
// how to carry bytes to whichever endpoint that one picked. The two compose:
// core/transport says "the USB address", xport says "over TCP", and neither
// knows what the other decided.
//
// # The contract
//
// Every transport here produces a net.Conn. That is the entire integration
// surface, and it is deliberately the smallest one possible, because it is what
// makes the security model transport-independent: crypto/tls takes a net.Conn,
// so the pinned certificate, the identity binding and the hybrid post-quantum
// handshake all work over any of these without a line of them being changed or
// re-verified per transport.
//
// The layering, top to bottom:
//
//	NasSimHub Node Protocol   /v1/*, identical on every transport
//	  HTTP/1.1                 the same handler
//	    TLS 1.3 hybrid PQ      the same trust model, the same pinning
//	      xport                STANDARD | KCP | QUIC
//	        TCP or UDP
//
// Nothing above the xport line may branch on which transport is in use. A test
// in the integration suite checks that the device identity, the pairing and the
// trust state are unchanged across a transport switch, because "the business
// layer does not know" is a claim that decays unless something enforces it.
package xport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
	"github.com/human-agent65535/nassimhub-node/xport/kcp"
)

// ErrUnsupported reports a transport this build cannot provide.
var ErrUnsupported = errors.New("xport: transport is not available in this build")

// Listener accepts connections, whatever carries them.
type Listener interface {
	Accept() (net.Conn, error)
	Close() error
	Addr() net.Addr
}

// Transport dials and listens.
type Transport interface {
	// Mode names it, for status and diagnostics.
	Mode() proto.TransportMode
	// Dial opens one connection.
	Dial(ctx context.Context, address string) (net.Conn, error)
	// Listen accepts connections.
	Listen(address string) (Listener, error)
	// Stats reports link counters. They are observations about delivery, never
	// key material - by construction, since this layer sits below TLS and
	// cannot see a key even in principle.
	Stats() Stats
}

// Stats is the transport-independent view of link quality.
//
// A transport that cannot measure something leaves it zero rather than
// inventing it. TCP, for instance, does not tell userspace its retransmission
// count on every platform, so the standard transport reports zero there and the
// status page shows a dash - which is honest, where a plausible-looking zero
// would not be.
type Stats struct {
	Mode         proto.TransportMode `json:"mode"`
	RTT          time.Duration       `json:"rtt"`
	Jitter       time.Duration       `json:"jitter"`
	PacketLoss   float64             `json:"packet_loss"`
	Retransmits  uint64              `json:"retransmits"`
	FECRecovered uint64              `json:"fec_recovered"`
	FECOverhead  float64             `json:"fec_overhead"`
	BytesSent    uint64              `json:"bytes_sent"`
	BytesRecv    uint64              `json:"bytes_received"`
	// Measured reports which fields this transport can actually fill in.
	Measured bool `json:"measured"`
}

// Options configures a transport.
type Options struct {
	Mode        proto.TransportMode
	KCPProfile  kcp.Profile
	KCPFEC      kcp.FECMode
	DialTimeout time.Duration
	// QUICReady is whether a real QUIC implementation is linked in. It is
	// false in this stage; see quicmock.
	QUICReady bool
	// MaxSessions bounds how many KCP peers a listener will track. Zero uses
	// the package default.
	//
	// It matters more on a device than the default suggests. The per-session
	// memory ceiling is roughly 5 MB on the balanced profile and 10 MB on the
	// aggressive one, so the default of 64 is a bound against unbounded growth
	// rather than a budget that fits a 256 MB device. A Node has exactly one
	// owner and should set this to a small number; see nodeserver.
	MaxSessions int
	// Auth turns on the authenticated envelope for the KCP transport: every
	// packet carries an HMAC-SHA-256 that must verify before the KCP state
	// machine sees it, plus address validation and anti-replay.
	//
	// Nil means unauthenticated, which is correct only for benchmarks and for
	// tests that measure the transport itself. Production callers always set
	// it; see agent/nodeserver.
	Auth *kcp.AuthConfig
}

// New builds a transport for a mode.
//
// TransportAuto is resolved here rather than deferred, and it resolves
// conservatively: see proto.AutoSelect, which never picks KCP on its own.
func New(options Options) (Transport, error) {
	mode := options.Mode
	if mode == "" {
		mode = proto.TransportStandard
	}
	if err := proto.ValidateTransportMode(mode); err != nil {
		return nil, err
	}
	if mode == proto.TransportAuto {
		mode = proto.AutoSelect(proto.AdviceNormal, options.QUICReady)
	}
	switch mode {
	case proto.TransportStandard:
		return &standardTransport{timeout: options.DialTimeout}, nil
	case proto.TransportKCP:
		profile := options.KCPProfile
		if profile == "" {
			profile = kcp.ProfileBalanced
		}
		if !kcp.ValidProfile(profile) {
			return nil, fmt.Errorf("xport: unknown kcp profile %q", profile)
		}
		fec := options.KCPFEC
		if fec == "" {
			fec = kcp.FECOff
		}
		if !kcp.ValidFECMode(fec) {
			return nil, fmt.Errorf("xport: unknown fec mode %q", fec)
		}
		return &kcpTransport{
			options: kcp.Options{
				Profile: profile,
				FEC:     fec,
				Auth:    options.Auth,
				// Set here rather than on the listener afterwards: the
				// listener starts its reader goroutine before it is returned,
				// so a later write races with it.
				MaxSessions: options.MaxSessions,
			},
		}, nil
	case proto.TransportQUIC:
		if !options.QUICReady {
			return nil, fmt.Errorf("%w: quic", ErrUnsupported)
		}
		return nil, fmt.Errorf("%w: no quic implementation is linked in", ErrUnsupported)
	default:
		return nil, fmt.Errorf("xport: unhandled mode %q", mode)
	}
}

// ---------------------------------------------------------------------------
// Standard: TCP
// ---------------------------------------------------------------------------

type standardTransport struct {
	timeout time.Duration
}

func (t *standardTransport) Mode() proto.TransportMode { return proto.TransportStandard }

func (t *standardTransport) Dial(ctx context.Context, address string) (net.Conn, error) {
	timeout := t.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "tcp", address)
}

func (t *standardTransport) Listen(address string) (Listener, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return tcpListener{listener}, nil
}

// Stats for TCP are deliberately empty. The kernel has the numbers; userspace
// does not, portably. Reporting zeros as if they were measurements would put a
// confident "0% loss" on the status page of a link that is losing packets.
func (t *standardTransport) Stats() Stats {
	return Stats{Mode: proto.TransportStandard, Measured: false}
}

type tcpListener struct{ net.Listener }

func (l tcpListener) Accept() (net.Conn, error) { return l.Listener.Accept() }
func (l tcpListener) Close() error              { return l.Listener.Close() }
func (l tcpListener) Addr() net.Addr            { return l.Listener.Addr() }

// ---------------------------------------------------------------------------
// KCP
// ---------------------------------------------------------------------------

type kcpTransport struct {
	options kcp.Options
	last    *kcp.Conn
}

func (t *kcpTransport) Mode() proto.TransportMode { return proto.TransportKCP }

func (t *kcpTransport) Dial(_ context.Context, address string) (net.Conn, error) {
	conn, err := kcp.Dial(address, t.options)
	if err != nil {
		return nil, err
	}
	t.last = conn
	return conn, nil
}

func (t *kcpTransport) Listen(address string) (Listener, error) {
	listener, err := kcp.Listen(address, t.options)
	if err != nil {
		return nil, err
	}
	return kcpListener{listener}, nil
}

func (t *kcpTransport) Stats() Stats {
	if t.last == nil {
		return Stats{Mode: proto.TransportKCP, Measured: true}
	}
	arq, fec := t.last.Stats()
	stats := Stats{
		Mode:         proto.TransportKCP,
		RTT:          arq.SRTT,
		Jitter:       arq.RTTVar,
		Retransmits:  arq.Retransmits,
		FECRecovered: t.last.RecoveredByFEC(),
		FECOverhead:  fec.OverheadRatio,
		BytesSent:    arq.BytesSent,
		BytesRecv:    arq.BytesReceived,
		Measured:     true,
	}
	if arq.SegmentsSent > 0 {
		// An estimate of loss from the sender's point of view: what fraction
		// of transmissions were repeats. It over-reports on a link with
		// reordering, which is the safe direction for something that drives
		// advice rather than a control loop.
		stats.PacketLoss = float64(arq.Retransmits) / float64(arq.SegmentsSent)
	}
	return stats
}

type kcpListener struct{ *kcp.Listener }

func (l kcpListener) Accept() (net.Conn, error) { return l.Listener.Accept() }
func (l kcpListener) Close() error              { return l.Listener.Close() }
func (l kcpListener) Addr() net.Addr            { return l.Listener.Addr() }
