// Package nodeserver assembles a running Node from its parts.
//
// Both binaries - the real agent and the mock Node - build the same object
// here. That is deliberate: if the mock ran through a different assembly path
// it could drift from the real one, and the development experience would stop
// predicting production behaviour.
package nodeserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/internal/httpapi"
	"github.com/human-agent65535/nassimhub-node/agent/internal/identity"
	"github.com/human-agent65535/nassimhub-node/agent/internal/localadmin"
	"github.com/human-agent65535/nassimhub-node/agent/internal/logbuf"
	"github.com/human-agent65535/nassimhub-node/agent/internal/pairing"
	"github.com/human-agent65535/nassimhub-node/agent/internal/transportkey"
	"github.com/human-agent65535/nassimhub-node/agent/internal/voicemedia"
	"github.com/human-agent65535/nassimhub-node/agent/modembackend"
	"github.com/human-agent65535/nassimhub-node/agent/netbackend"
	"github.com/human-agent65535/nassimhub-node/agent/nodetls"
	"github.com/human-agent65535/nassimhub-node/proto"
	"github.com/human-agent65535/nassimhub-node/xport/kcp"
)

// Options configures a Node.
type Options struct {
	// EnableLocalAdmin serves the standalone browser console on an independent TLS listener.
	EnableLocalAdmin bool
	AdminListen      string

	// StateDir holds device.json and pairing.json. It must be on persistent
	// storage; a Node whose state directory is a tmpfs would regenerate its
	// identity on every boot and appear as a new device each time.
	StateDir string
	// LogDir enables the rotating file mirror. Empty keeps logs in memory only.
	LogDir string
	// Platform and Model describe the hardware.
	Platform proto.Platform
	Model    string
	// Listeners are the addresses the Node serves on. Several are expected:
	// one on the USB network interface and one on Wi-Fi. They serve the same
	// handler, which is what makes the two links indistinguishable to Core.
	Listeners []string
	// Modem is the radio backend.
	Modem     modembackend.Backend
	CallMedia voicemedia.Opener
	// Network is the Wi-Fi backend. Leave it nil and set NetworkFactory
	// instead when the backend needs the device id, which is only known once
	// the identity has been loaded.
	Network netbackend.Backend
	// NetworkFactory builds the Wi-Fi backend from the resolved device id. It
	// is used only when Network is nil.
	NetworkFactory func(deviceID string) netbackend.Backend
	// AgentVersion and BuildDate are reported to Core.
	AgentVersion string
	BuildDate    string
	// SessionTTL bounds bearer tokens.
	SessionTTL time.Duration
	// EnableTLS serves the Node protocol over TLS using the device
	// certificate, which is the only way a Node should be reachable in
	// production. It is off by default so that in-process tests can speak
	// plain HTTP to a handler without a certificate; the binaries turn it on.
	//
	// The certificate is not a separate secret to manage: it is issued from
	// the device identity key, so Core pinning the key and Core pinning the
	// TLS identity are the same act. See proto/tlsbind.go.
	EnableTLS bool
	// CertificateAddresses are added to the certificate as IP SANs. They are a
	// convenience for a human with curl; Core connects by the hostname derived
	// from device_id and does not rely on them.
	CertificateAddresses []net.IP
	// PQProfile and PQPolicy set the post-quantum key agreement this Node will
	// offer. Empty means the standard profile, preferred rather than required.
	//
	// Preferred is the right default FOR A DEVICE, and the asymmetry with Core
	// is deliberate: a Node that required post-quantum would become unreachable
	// from an older NAS the moment it was updated, and a device the owner
	// cannot reach is a worse outcome than a session key that is merely as good
	// as last year's.
	PQProfile proto.PQProfile
	PQPolicy  proto.PQPolicy
	// SecurityLevel is the outward-facing setting. When set it DECIDES the
	// profile and policy above: one conversion point, so a level and a profile
	// that disagree cannot both be honoured somewhere.
	SecurityLevel proto.SecurityLevel

	// TransportMode selects how the Node is reachable, in addition to the
	// ordinary TCP listener that is always open. KCP and AUTO also open a
	// weak-network listener on UDP; see servesKCP for why AUTO does too.
	//
	// Nothing above the transport changes with this setting. The Node protocol,
	// the pairing, the certificate and the post-quantum policy are identical on
	// every transport, which is what makes the choice safe to expose at all.
	TransportMode proto.TransportMode
	// KCPProfile is "balanced" or "aggressive"; empty means balanced.
	KCPProfile string
	// KCPFEC is "off", "balanced" or "aggressive"; empty means off.
	KCPFEC string
	// KCPListeners are the UDP addresses for the weak-network transport.
	// Empty uses the same addresses as Listeners, on UDP.
	KCPListeners []string
}

// Server is a running Node.
type Server struct {
	Identity *identity.Identity
	Pairing  *pairing.Store
	Logs     *logbuf.Buffer

	adminHandler     http.Handler
	adminCertificate *tls.Certificate
	adminAddress     string
	handler          http.Handler
	servers          []*http.Server
	listeners        []net.Listener
	options          Options
	certificate      *tls.Certificate

	// transport carries the weak-network listener and the link counters. See
	// transport.go; the standard TCP listeners above do not go through it,
	// because TCP has no counters to report and inventing some would be worse
	// than reporting none.
	transport  *transportState
	kcpProfile kcp.Profile
	// keys is the KCP transport secret store. It is opened at start-up rather
	// than at pairing time so the listener has a key ring the moment it opens;
	// see agent/internal/transportkey for why that is safe.
	keys *transportkey.Store
	// auth is the shared authentication configuration for the weak-network
	// listener: the key ring, the cookie authority and the rate limiter.
	auth *kcp.AuthConfig

	// links gates each listener independently so a caller can take one link
	// down without stopping the Node. It exists for development and testing of
	// USB/Wi-Fi failover: on real hardware a link goes down because a cable was
	// pulled, and without this there would be no way to reproduce that on a
	// machine with one network interface.
	linkMu sync.Mutex
	links  map[string]*link
}

// link is one listener's up/down gate.
type link struct {
	up atomic.Bool
}

// gate refuses traffic the way a severed link does - by closing the connection
// - rather than with a tidy HTTP error, so the client experiences a genuine
// transport failure and its failover path is actually exercised.
func gate(l *link, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if l.up.Load() {
			handler.ServeHTTP(w, r)
			return
		}
		if hijacker, ok := w.(http.Hijacker); ok {
			if connection, _, err := hijacker.Hijack(); err == nil {
				_ = connection.Close()
				return
			}
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
}

// New assembles a Node without starting it.
func New(options Options) (*Server, error) {
	if options.StateDir == "" {
		options.StateDir = identity.DefaultDir
	}
	if options.Modem == nil {
		return nil, errors.New("a modem backend is required")
	}
	if options.Network == nil && options.NetworkFactory == nil {
		return nil, errors.New("a network backend or a network factory is required")
	}

	loaded, err := identity.LoadOrCreate(identity.Options{
		Dir:      options.StateDir,
		Platform: options.Platform,
		Model:    options.Model,
	})
	if err != nil {
		return nil, fmt.Errorf("load device identity: %w", err)
	}
	pairs, err := pairing.Open(pairing.Options{
		Dir:        options.StateDir,
		DeviceID:   loaded.DeviceID,
		SessionTTL: options.SessionTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("load pairing state: %w", err)
	}
	if options.Network == nil {
		options.Network = options.NetworkFactory(loaded.DeviceID)
	}
	logs := logbuf.New(logbuf.Options{Dir: options.LogDir})

	profile := options.PQProfile
	if profile == "" {
		profile = proto.PQStandard
	}
	policy := options.PQPolicy
	if policy == "" {
		policy = proto.PQPreferred
	}
	if options.SecurityLevel != "" {
		if err := proto.ValidateSecurityLevel(options.SecurityLevel); err != nil {
			return nil, err
		}
		// The level wins. A deployment that set both and meant the profile
		// would be surprised here - but the alternative, letting a stale
		// profile silently override a level somebody chose deliberately, is
		// the direction that weakens security rather than strengthens it.
		profile, policy = proto.ProfileAndPolicyFor(options.SecurityLevel)
	}
	if err := proto.ValidatePQProfile(profile); err != nil {
		return nil, err
	}
	if err := proto.ValidatePQPolicy(policy); err != nil {
		return nil, err
	}

	mode, kcpProfile, fec, err := resolveTransport(options)
	if err != nil {
		return nil, err
	}
	state := newTransportState(mode, fec)

	keys, err := transportkey.Open(options.StateDir)
	if err != nil {
		return nil, fmt.Errorf("open the transport key store: %w", err)
	}
	cookies, err := kcp.NewCookieAuthority()
	if err != nil {
		return nil, fmt.Errorf("prepare address validation: %w", err)
	}
	auth := &kcp.AuthConfig{
		Ring:    keys.Ring(),
		Cookies: cookies,
		Limiter: kcp.NewHandshakeLimiter(),
		Stats:   state.authStats,
	}

	var certificate *tls.Certificate
	if options.EnableTLS {
		issued, err := nodetls.EnsureCertificate(nodetls.Options{
			Dir:        options.StateDir,
			DeviceID:   loaded.DeviceID,
			Platform:   loaded.Platform,
			PrivateKey: loaded.PrivateKey(),
			Addresses:  options.CertificateAddresses,
		})
		if err != nil {
			return nil, fmt.Errorf("prepare device certificate: %w", err)
		}
		certificate = &issued
	}

	var adminAccess func() (bool, string, int)
	var adminWrap func(http.Handler)
	var adminHandler http.Handler
	var adminCertificate *tls.Certificate
	if options.EnableLocalAdmin {
		if !options.EnableTLS {
			return nil, errors.New("local administration requires TLS")
		}
		admin, err := localadmin.Open(localadmin.Options{Dir: options.StateDir, DeviceID: loaded.DeviceID, Model: loaded.Model, Version: options.AgentVersion})
		if err != nil {
			return nil, fmt.Errorf("prepare local administration: %w", err)
		}
		issued, err := localadmin.Certificate(options.StateDir, loaded.DeviceID, options.CertificateAddresses)
		if err != nil {
			return nil, fmt.Errorf("prepare admin certificate: %w", err)
		}
		adminCertificate = &issued
		if options.AdminListen == "" {
			options.AdminListen = "127.0.0.1:0"
		}
		adminWrap = func(api http.Handler) { adminHandler = admin.Wrap(api) }
		adminAccess = func() (bool, string, int) {
			configured, proof := admin.OwnerSetup()
			_, rawPort, _ := net.SplitHostPort(options.AdminListen)
			port, _ := strconv.Atoi(rawPort)
			return configured, proof, port
		}
	}
	handler := httpapi.New(httpapi.Options{
		LocalAdmin:       adminWrap,
		LocalAdminAccess: adminAccess,
		Identity:         loaded,
		Pairing:          pairs,
		Modem:            options.Modem,
		CallMedia:        options.CallMedia,
		Network:          options.Network,
		Logs:             logs,
		AgentVersion:     options.AgentVersion,
		BuildDate:        options.BuildDate,
		ListenPorts:      listenPorts(options.Listeners),
		TLS:              options.EnableTLS,
		PQProfile:        profile,
		PQPolicy:         policy,
		TransportKeys:    transportKeyIssuer{store: keys},
		// The device holds no post-quantum identity yet: no build can produce
		// one until crypto/x509 carries ML-DSA. Reporting an empty identity is
		// the honest answer, and the schema is already in place so that the
		// day it exists, nothing above this line changes.
		PQIdentity:    func() proto.PQIdentity { return proto.PQIdentity{} },
		SecurityLevel: proto.LevelFor(profile, policy),
		// A function rather than a value: the counters change while the
		// process runs, and the handler must never hold a snapshot that
		// silently becomes a description of a link that no longer exists.
		TransportReport: state.section,
	})

	options.PQProfile = profile
	options.PQPolicy = policy
	options.TransportMode = mode
	return &Server{
		Identity: loaded, Pairing: pairs, Logs: logs,
		handler: handler, options: options,
		adminHandler: adminHandler, adminCertificate: adminCertificate,
		certificate: certificate,
		links:       map[string]*link{},
		transport:   state,
		kcpProfile:  kcpProfile,
		keys:        keys,
		auth:        auth,
	}, nil
}

// serverTLSConfig builds the listener configuration: the device certificate
// plus the configured post-quantum policy.
//
// One function, used by every transport. That is the mechanical reason a KCP
// connection cannot end up with weaker protection than a TCP one - there is no
// second configuration for it to be weaker than.
func (s *Server) serverTLSConfig() (*tls.Config, error) {
	if s.certificate == nil {
		return nil, errors.New("no device certificate; the node is serving plaintext")
	}
	return nodetls.SecureServerConfig(*s.certificate, s.options.PQProfile, s.options.PQPolicy)
}

// Handler exposes the Node's HTTP handler, for tests and for embedding.
func (s *Server) Handler() http.Handler { return s.handler }

// Certificate reports the device certificate, or nil when the Node is serving
// plaintext. It is what a test or a local tool needs in order to pin.
func (s *Server) Certificate() *tls.Certificate { return s.certificate }

// Scheme is "https" when the Node serves TLS and "http" otherwise, so callers
// can build a base URL without knowing how the Node was configured.
func (s *Server) Scheme() string {
	if s.certificate != nil {
		return "https"
	}
	return "http"
}

// Addresses reports the addresses the Node is actually listening on, which is
// what a caller needs when a listener was configured with port 0.
func (s *Server) Addresses() []string {
	addresses := make([]string, 0, len(s.listeners))
	for _, listener := range s.listeners {
		addresses = append(addresses, listener.Addr().String())
	}
	return addresses
}

// Start opens every configured listener and serves the same handler on all of
// them.
//
// One handler across many listeners is the whole transport story on the Node
// side: the agent does not know or care whether a request arrived over USB or
// Wi-Fi, so there is no code path where the two could diverge.
func (s *Server) Start() error {
	for _, address := range s.options.Listeners {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			_ = s.Stop(context.Background())
			return fmt.Errorf("listen on %s: %w", address, err)
		}
		gateway := &link{}
		gateway.up.Store(true)
		s.linkMu.Lock()
		s.links[address] = gateway
		s.links[listener.Addr().String()] = gateway
		s.linkMu.Unlock()

		server := &http.Server{
			Handler:           gate(gateway, s.handler),
			ReadHeaderTimeout: 10 * time.Second,
		}
		if s.certificate != nil {
			// A failure here is a configuration this build cannot satisfy -
			// most likely PQ_EXTREME on a toolchain without
			// SecP384r1MLKEM1024. Refusing to start says so once, where
			// starting anyway would produce a device that listens and rejects
			// every connection.
			tlsConfig, err := s.serverTLSConfig()
			if err != nil {
				_ = listener.Close()
				_ = s.Stop(context.Background())
				return fmt.Errorf("configure tls on %s: %w", address, err)
			}
			server.TLSConfig = tlsConfig
			listener = tls.NewListener(listener, tlsConfig)
		}
		s.listeners = append(s.listeners, listener)
		s.servers = append(s.servers, server)

		go func(server *http.Server, listener net.Listener) {
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.Logs.Errorf("server", "listener %s stopped: %v", listener.Addr(), err)
			}
		}(server, listener)

		s.Logs.Infof("server", "serving node protocol on %s", listener.Addr())
	}
	// The weak-network listener, when one is configured. It serves the same
	// handler through the same TLS configuration; see transport.go.
	if err := s.startAdmin(); err != nil {
		_ = s.Stop(context.Background())
		return err
	}
	if err := s.startKCP(); err != nil {
		_ = s.Stop(context.Background())
		return err
	}
	s.Logs.Infof("node", "device %s ready, platform %s, pairing %s",
		s.Identity.DeviceID, s.Identity.Platform, s.Pairing.State())
	return nil
}

// SetLinkUp takes one of the Node's listeners up or down.
//
// The address is either the configured listen address or the resolved one. A
// down link closes connections instead of answering, which is what a pulled
// cable looks like to the other side. It reports whether the address is known.
func (s *Server) SetLinkUp(address string, up bool) bool {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	gateway, ok := s.links[address]
	if !ok {
		return false
	}
	gateway.up.Store(up)
	if up {
		s.Logs.Infof("server", "link %s is up", address)
	} else {
		s.Logs.Warnf("server", "link %s is down", address)
	}
	return true
}

// Stop shuts the Node down.
func (s *Server) Stop(ctx context.Context) error {
	var firstError error
	for _, server := range s.servers {
		if err := server.Shutdown(ctx); err != nil && firstError == nil {
			firstError = err
		}
	}
	s.servers = nil
	s.listeners = nil
	// http.Server.Shutdown closes the listeners it was given, but the KCP
	// listener owns a UDP socket and a reader goroutine underneath that, so it
	// is closed explicitly. Without this a restarted agent would find its own
	// port still held.
	s.stopKCP()
	if err := s.options.Modem.Close(); err != nil && firstError == nil {
		firstError = err
	}
	if err := s.options.Network.Close(); err != nil && firstError == nil {
		firstError = err
	}
	if err := s.Logs.Close(); err != nil && firstError == nil {
		firstError = err
	}
	return firstError
}

// listenPorts extracts the port numbers from the configured listen addresses.
//
// Ports, not addresses: they end up in diagnostics, and a bundle should not
// carry a description of the owner's network.
func listenPorts(addresses []string) []int {
	ports := make([]int, 0, len(addresses))
	seen := map[int]bool{}
	for _, address := range addresses {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}
		number, err := strconv.Atoi(port)
		if err != nil || number <= 0 || seen[number] {
			continue
		}
		seen[number] = true
		ports = append(ports, number)
	}
	return ports
}
