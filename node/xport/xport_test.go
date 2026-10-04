package xport

import (
	"errors"
	"testing"

	"github.com/human-agent65535/nassimhub-node/proto"
	"github.com/human-agent65535/nassimhub-node/xport/kcp"
)

func TestAnEmptyModeIsTheStandardTransport(t *testing.T) {
	transport, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if transport.Mode() != proto.TransportStandard {
		t.Fatalf("mode is %q", transport.Mode())
	}
}

// AUTO resolves conservatively. The property being defended is that nothing
// moves a working connection onto the weak-network transport without a person
// choosing it.
func TestAutoResolvesToTheStandardTransport(t *testing.T) {
	transport, err := New(Options{Mode: proto.TransportAuto})
	if err != nil {
		t.Fatal(err)
	}
	if transport.Mode() == proto.TransportKCP {
		t.Fatal("auto resolved to kcp on its own")
	}
	if transport.Mode() != proto.TransportStandard {
		t.Fatalf("auto resolved to %q", transport.Mode())
	}
}

// An unavailable transport must fail loudly rather than quietly become another
// one. A silent substitution would put traffic on a transport nobody chose.
func TestQUICIsRefusedRatherThanSubstituted(t *testing.T) {
	if _, err := New(Options{Mode: proto.TransportQUIC}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("quic returned %v, want ErrUnsupported", err)
	}
	// Even with QUICReady set, there is no implementation linked in, and the
	// error says so instead of handing back a TCP transport.
	if _, err := New(Options{Mode: proto.TransportQUIC, QUICReady: true}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("quic with QUICReady returned %v, want ErrUnsupported", err)
	}
}

func TestUnknownModesAndProfilesAreRefused(t *testing.T) {
	if _, err := New(Options{Mode: "carrier-pigeon"}); err == nil {
		t.Fatal("an unknown mode was accepted")
	}
	if _, err := New(Options{Mode: proto.TransportKCP, KCPProfile: "turbo"}); err == nil {
		t.Fatal("an unknown kcp profile was accepted")
	}
	if _, err := New(Options{Mode: proto.TransportKCP, KCPFEC: "maybe"}); err == nil {
		t.Fatal("an unknown fec mode was accepted")
	}
}

// TCP has no counters to report, and reporting zeros as though they were
// measurements would put a confident "0% loss" on the status page of a link
// that is failing.
func TestTheStandardTransportReportsNothingRatherThanZeros(t *testing.T) {
	transport, err := New(Options{Mode: proto.TransportStandard})
	if err != nil {
		t.Fatal(err)
	}
	if stats := transport.Stats(); stats.Measured {
		t.Fatal("the standard transport claims to measure the link")
	}
}

func TestTheKCPTransportReportsThatItMeasures(t *testing.T) {
	transport, err := New(Options{
		Mode:       proto.TransportKCP,
		KCPProfile: kcp.ProfileBalanced,
		KCPFEC:     kcp.FECOff,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !transport.Stats().Measured {
		t.Fatal("the kcp transport reports that it measures nothing")
	}
}

// The session ceiling reaches the listener. It is the bound between "a peer
// that can send UDP" and "a map that grows until the device runs out of
// memory", so a setting that was accepted and then ignored would be worse than
// no setting at all.
func TestTheSessionCeilingReachesTheListener(t *testing.T) {
	transport, err := New(Options{Mode: proto.TransportKCP, MaxSessions: 3})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := transport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	inner, ok := listener.(kcpListener)
	if !ok {
		t.Fatalf("listener is %T", listener)
	}
	if inner.Listener.MaxSessions != 3 {
		t.Fatalf("the listener's session ceiling is %d, want 3", inner.Listener.MaxSessions)
	}
}
