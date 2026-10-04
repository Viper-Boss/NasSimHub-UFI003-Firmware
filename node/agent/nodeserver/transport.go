package nodeserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
	"github.com/human-agent65535/nassimhub-node/xport"
	"github.com/human-agent65535/nassimhub-node/xport/kcp"
)

// The Node's side of the unified transport.
//
// One thing is worth stating plainly, because it is the whole reason this file
// is short: NOTHING about the Node protocol changes when a request arrives over
// KCP instead of TCP. KCP produces a net.Conn and a listener that yields
// net.Conns, so the same tls.Config, the same certificate issued from the same
// device identity, and the same http.Handler sit on top of it unchanged. There
// is no second pairing, no transport-specific authentication, and no key
// material anywhere below the TLS layer.
//
// The layering, top to bottom:
//
//	NasSimHub Node Protocol  /v1/*, byte-identical on every transport
//	  HTTP/1.1               the same handler instance
//	    TLS 1.3 hybrid PQ    the same certificate, the same pinning
//	      KCP                reliability, ARQ, retransmission, FEC
//	        UDP
//
// KCP is responsible for delivery and for nothing else. It holds no secret, it
// authenticates nothing, and it cannot: it sits below the encryption.

// maxNodeSessions bounds concurrent KCP sessions on a Node. See startKCP for
// the arithmetic behind the number.
const maxNodeSessions = 4

// transportState carries the link counters from the transport up to the
// diagnostics handler.
//
// It is a small mutable object rather than a value because the handler is built
// before the listeners are opened, and the numbers change while the process
// runs. The handler holds a function, calls it when a bundle is collected, and
// never learns which transport answered.
type transportState struct {
	mu          sync.Mutex
	mode        proto.TransportMode
	fec         kcp.FECMode
	transport   xport.Transport
	listeners   []xport.Listener
	recommender *proto.Recommender
	// authStats counts what the envelope rejected. Counters only - no
	// payloads, no addresses, no key material - so the whole structure is safe
	// to put in a support bundle.
	authStats *kcp.AuthCounters
}

func newTransportState(mode proto.TransportMode, fec kcp.FECMode) *transportState {
	return &transportState{
		mode:        mode,
		fec:         fec,
		recommender: proto.NewRecommender(),
		authStats:   kcp.NewAuthCounters(),
	}
}

// section is what the diagnostics bundle and the status page render.
//
// Every field is an observation about DELIVERY - round trips, retransmissions,
// recovered packets - measured below the encryption layer, which is why none of
// it can be key material even in principle. A transport that measures nothing
// reports Measured=false and leaves the counters at zero, so the UI can draw a
// dash instead of a confident and false "0% loss".
func (t *transportState) section() proto.TransportSection {
	t.mu.Lock()
	defer t.mu.Unlock()

	section := proto.TransportSection{
		Mode:     t.mode,
		Resolved: t.mode,
		Advice:   t.recommender.Advice(),
	}
	if t.transport == nil {
		return section
	}
	section.Resolved = t.transport.Mode()
	stats := t.transport.Stats()
	section.Measured = stats.Measured
	if !stats.Measured {
		// The link counters mean nothing on this transport, but the
		// authentication counters still do: a device being sprayed with forged
		// packets should say so whether or not it can measure its RTT.
		section.Auth = authSection(t.authStats.Snapshot())
		return section
	}
	if stats.RTT > 0 {
		section.RTT = stats.RTT.Round(time.Millisecond).String()
	}
	if stats.Jitter > 0 {
		section.Jitter = stats.Jitter.Round(time.Millisecond).String()
	}
	section.PacketLoss = stats.PacketLoss
	section.Retransmits = stats.Retransmits
	if t.fec != "" && t.fec != kcp.FECOff {
		section.FECMode = string(t.fec)
		section.FECRecovered = stats.FECRecovered
		section.FECOverhead = stats.FECOverhead
	}
	section.Auth = authSection(t.authStats.Snapshot())
	// Advice is a RECOMMENDATION and never an action. Nothing here switches
	// transport; the Node reports what it sees and the person decides. The
	// Recommender applies hysteresis - consecutive agreement plus dwell time -
	// so a link sitting on a threshold does not produce a flapping suggestion.
	section.Advice = t.recommender.Observe(proto.LinkSample{
		RTT:        stats.RTT,
		Jitter:     stats.Jitter,
		PacketLoss: stats.PacketLoss,
	})
	return section
}

// authSection converts the counters into the diagnostics shape.
func authSection(stats kcp.AuthStats) proto.TransportAuthSection {
	return proto.TransportAuthSection{
		Authenticated: true,
		Accepted:      stats.Accepted,
		MACFailures:   stats.MACFailures,
		Replays:       stats.Replays,
		TooOld:        stats.TooOld,
		BadEpoch:      stats.BadEpoch,
		Malformed:     stats.Malformed,
		CookiesIssued: stats.CookieIssued,
		CookiesBad:    stats.CookieBad,
		RateLimited:   stats.RateLimited,
	}
}

// resolveTransport validates the configured transport and its KCP settings.
func resolveTransport(options Options) (proto.TransportMode, kcp.Profile, kcp.FECMode, error) {
	mode := options.TransportMode
	if mode == "" {
		mode = proto.TransportStandard
	}
	if err := proto.ValidateTransportMode(mode); err != nil {
		return "", "", "", err
	}
	profile := kcp.Profile(options.KCPProfile)
	if profile == "" {
		profile = kcp.ProfileBalanced
	}
	if !kcp.ValidProfile(profile) {
		return "", "", "", fmt.Errorf("unknown kcp profile %q", options.KCPProfile)
	}
	fec := kcp.FECMode(options.KCPFEC)
	if fec == "" {
		fec = kcp.FECOff
	}
	if !kcp.ValidFECMode(fec) {
		return "", "", "", fmt.Errorf("unknown fec mode %q", options.KCPFEC)
	}
	return mode, profile, fec, nil
}

// servesKCP reports whether the weak-network listener should be opened.
//
// Under AUTO as well as under KCP, and deliberately so. A Node that needs the
// weak-network transport is by definition on a link that is failing, which is
// the worst possible moment to require a configuration change on the device:
// the owner would have to reach it over the link that does not work. Opening
// the UDP listener under AUTO costs one socket and makes the path available
// when Core asks for it.
//
// The standard listener stays open in every mode. Nothing here removes the
// ordinary way to reach the device.
func servesKCP(mode proto.TransportMode) bool {
	return mode == proto.TransportKCP || mode == proto.TransportAuto
}

// startKCP opens the weak-network listener on each configured address.
//
// The same handler and, when TLS is enabled, the same certificate and the same
// post-quantum policy. A failure to build the TLS configuration is fatal for
// the same reason it is on the TCP path: a listener that accepts connections
// and rejects every handshake is worse than one that never opened.
func (s *Server) startKCP() error {
	if !servesKCP(s.transport.mode) {
		return nil
	}
	addresses := s.options.KCPListeners
	if len(addresses) == 0 {
		addresses = s.options.Listeners
	}
	transport, err := xport.New(xport.Options{
		Mode:       proto.TransportKCP,
		KCPProfile: s.kcpProfile,
		KCPFEC:     s.transport.fec,
		// Authentication is not optional on a device. Every packet on this
		// listener carries a MAC that must verify before the KCP state machine
		// sees it, every session is preceded by address validation, and both
		// are rate limited. A Node that opened an unauthenticated UDP listener
		// would hand anyone who can send a datagram the ability to drive its
		// transport state machine; there is a test that fails if this is ever
		// nil here.
		Auth: s.auth,
		// A Node has exactly one owner, so the session ceiling is small on
		// purpose. The arithmetic is the reason: each KCP session's bounded
		// queues add up to roughly 5 MB on the balanced profile and 10 MB on
		// the aggressive one, and the library's default ceiling of 64 would
		// therefore permit several hundred megabytes on a device that has 256.
		// Four leaves room for a reconnect that overlaps a session the Node has
		// not yet timed out, and nothing more.
		MaxSessions: maxNodeSessions,
	})
	if err != nil {
		return fmt.Errorf("build kcp transport: %w", err)
	}
	s.transport.mu.Lock()
	s.transport.transport = transport
	s.transport.mu.Unlock()

	for _, address := range addresses {
		listener, err := transport.Listen(address)
		if err != nil {
			return fmt.Errorf("listen for kcp on %s: %w", address, err)
		}
		var served net.Listener = listenerAdapter{listener}
		server := &http.Server{
			Handler:           s.handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		if s.certificate != nil {
			tlsConfig, err := s.serverTLSConfig()
			if err != nil {
				_ = listener.Close()
				return fmt.Errorf("configure tls for kcp on %s: %w", address, err)
			}
			server.TLSConfig = tlsConfig
			served = tls.NewListener(served, tlsConfig)
		}
		s.transport.mu.Lock()
		s.transport.listeners = append(s.transport.listeners, listener)
		s.transport.mu.Unlock()
		s.servers = append(s.servers, server)

		go func(server *http.Server, listener net.Listener) {
			if err := server.Serve(listener); err != nil &&
				!errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				s.Logs.Errorf("server", "kcp listener %s stopped: %v", listener.Addr(), err)
			}
		}(server, served)

		s.Logs.Infof("server", "serving node protocol over kcp on %s (profile %s, fec %s)",
			listener.Addr(), s.kcpProfile, s.transport.fec)
	}
	return nil
}

// stopKCP closes the weak-network listeners.
func (s *Server) stopKCP() {
	s.transport.mu.Lock()
	listeners := s.transport.listeners
	s.transport.listeners = nil
	s.transport.mu.Unlock()
	for _, listener := range listeners {
		_ = listener.Close()
	}
}

// listenerAdapter presents an xport.Listener as a net.Listener, which is all
// http.Server and tls.NewListener need.
type listenerAdapter struct{ inner xport.Listener }

func (l listenerAdapter) Accept() (net.Conn, error) { return l.inner.Accept() }
func (l listenerAdapter) Close() error              { return l.inner.Close() }
func (l listenerAdapter) Addr() net.Addr            { return l.inner.Addr() }

// KCPAddresses reports the weak-network addresses actually in use, which is
// what a caller needs when a listener was configured with port 0.
func (s *Server) KCPAddresses() []string {
	s.transport.mu.Lock()
	defer s.transport.mu.Unlock()
	addresses := make([]string, 0, len(s.transport.listeners))
	for _, listener := range s.transport.listeners {
		addresses = append(addresses, listener.Addr().String())
	}
	return addresses
}

// TransportReport is the link report, for tests and for embedding.
func (s *Server) TransportReport() proto.TransportSection { return s.transport.section() }
