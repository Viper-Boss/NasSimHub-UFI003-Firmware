// Package provisioning serves the first-boot Wi-Fi setup API.
//
// The problem it exists to solve: a brand-new Node has no owner, so it has no
// bearer token, so it cannot answer the ordinary /v1/wifi/* endpoints - and
// without Wi-Fi the NAS can never reach it to pair in the first place. The
// tempting fix is to let the normal Node API answer anonymously while
// unpaired. That is the wrong fix: it would make every privileged endpoint -
// SMS, calls, SIM identity, logs - reachable by anyone on the LAN during a
// window that, on a device that fails to join a network, never closes.
//
// So this is a second, deliberately tiny API with its own listener and its own
// handler. It shares no routing, no middleware and no handler code with the
// Node API. Four constraints hold it shut:
//
//  1. It exists only while the Wi-Fi backend is in PROVISIONING_AP. The
//     supervisor opens the listener on entering that state and closes it on
//     leaving, so a Node that joins a network stops serving this within one
//     poll interval.
//  2. It answers only requests whose source address is inside the access
//     point's own subnet. A request arriving over the cellular interface, or
//     over a USB link, or from a routed LAN address, is refused before the
//     handler runs.
//  3. It has exactly three routes: status, scan, connect. There is no route
//     that can reach a message, a call, a SIM identifier or a log record,
//     because no such handler is registered on this mux.
//  4. Its status document is a fixed, hand-written struct. It cannot
//     accidentally grow a sensitive field by reusing a richer type from the
//     Node protocol.
package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/netbackend"
	"github.com/human-agent65535/nassimhub-node/proto"
)

const maxRequestBodyBytes = 8 << 10

// DefaultAPSubnet is the network the provisioning access point hands out.
// Matches the documented 192.168.4.1 gateway.
const DefaultAPSubnet = "192.168.4.0/24"

// DefaultListenAddress is where the provisioning API listens while the access
// point is up.
const DefaultListenAddress = "192.168.4.1:80"

// Status is the entire document this API discloses.
//
// Every field here is already public on the unauthenticated /v1/node
// discovery endpoint, or is Wi-Fi state the user is actively configuring.
// There is deliberately no SIM, operator, number, signal, message, call or log
// field, and no struct from the Node protocol is embedded, so a later change to
// those types cannot widen this document by accident.
type Status struct {
	DeviceID     string             `json:"device_id"`
	Platform     proto.Platform     `json:"platform"`
	Model        string             `json:"model"`
	AgentVersion string             `json:"agent_version"`
	PairingState proto.PairingState `json:"pairing_state"`
	WiFiState    proto.WiFiState    `json:"wifi_state"`
	SSID         string             `json:"ssid,omitempty"`
	APSSID       string             `json:"ap_ssid,omitempty"`
	Failure      string             `json:"failure_reason,omitempty"`
}

// Network is one scan result, reduced to what a setup page needs.
type Network struct {
	SSID      string             `json:"ssid"`
	SignalDBM float64            `json:"signal_dbm"`
	Security  proto.WiFiSecurity `json:"security"`
}

// ScanResult is the envelope for POST /provision/scan.
type ScanResult struct {
	Networks []Network `json:"networks"`
}

// ConnectRequest joins a network. The PSK travels inbound only and is never
// echoed by any endpoint here.
type ConnectRequest struct {
	SSID     string             `json:"ssid"`
	PSK      string             `json:"psk,omitempty"`
	Security proto.WiFiSecurity `json:"security,omitempty"`
}

// Identity is the small slice of device identity the status document needs.
// Taking it as a struct rather than the whole identity object keeps the
// device's private key out of this package entirely.
type Identity struct {
	DeviceID     string
	Platform     proto.Platform
	Model        string
	AgentVersion string
}

// PairingReader is the one thing this package needs from pairing state.
type PairingReader interface {
	State() proto.PairingState
}

// Options configures the provisioning API.
type Options struct {
	Identity Identity
	Network  netbackend.Backend
	Pairing  PairingReader
	// Listen is the address the API binds while the access point is up.
	Listen string
	// AllowedSubnets restricts callers by source address. Empty means
	// DefaultAPSubnet. A caller outside every listed subnet is refused.
	AllowedSubnets []string
	// Logf receives one line per refused request; optional.
	Logf func(format string, arguments ...any)
}

// Handler is the provisioning HTTP handler. Exported for tests; production
// code uses Supervisor, which owns its lifetime.
type Handler struct {
	identity Identity
	network  netbackend.Backend
	pairing  PairingReader
	allowed  []*net.IPNet
	logf     func(string, ...any)
}

// NewHandler builds the provisioning handler.
func NewHandler(options Options) (*Handler, http.Handler, error) {
	if options.Network == nil {
		return nil, nil, errors.New("provisioning requires a network backend")
	}
	subnets := options.AllowedSubnets
	if len(subnets) == 0 {
		subnets = []string{DefaultAPSubnet}
	}
	allowed := make([]*net.IPNet, 0, len(subnets))
	for _, entry := range subnets {
		_, network, err := net.ParseCIDR(strings.TrimSpace(entry))
		if err != nil {
			return nil, nil, fmt.Errorf("provisioning subnet %q: %w", entry, err)
		}
		allowed = append(allowed, network)
	}
	logf := options.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	h := &Handler{
		identity: options.Identity,
		network:  options.Network,
		pairing:  options.Pairing,
		allowed:  allowed,
		logf:     logf,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", h.guard(h.serveUI))
	mux.HandleFunc("GET /provision/status", h.guard(h.status))
	mux.HandleFunc("POST /provision/scan", h.guard(h.scan))
	mux.HandleFunc("POST /provision/connect", h.guard(h.connect))
	// Everything else, including every Node API path, is not found here. The
	// catch-all is registered last and deliberately says nothing about what
	// else might exist on this device.
	mux.HandleFunc("/", h.guard(h.notFound))
	return h, mux, nil
}

// guard enforces the two preconditions before any handler body runs: the
// caller is on the access point's own network, and the device is still in
// PROVISIONING_AP.
func (h *Handler) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.allowedSource(r.RemoteAddr) {
			h.logf("provisioning: refused request from %s", r.RemoteAddr)
			// A refused caller learns nothing about the device, not even that
			// this is a NasSimHub Node.
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !h.provisioningActive(r.Context()) {
			h.logf("provisioning: refused request while not in PROVISIONING_AP")
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		next(w, r)
	}
}

// allowedSource reports whether addr is inside a permitted subnet.
func (h *Handler) allowedSource(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	for _, network := range h.allowed {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// provisioningActive reports whether the device is still in the state that
// justifies an unauthenticated API.
func (h *Handler) provisioningActive(ctx context.Context) bool {
	status, err := h.network.Status(ctx)
	if err != nil {
		return false
	}
	return status.State == proto.WiFiProvisioningAP
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	wifi, err := h.network.Status(r.Context())
	if err != nil {
		writeFailure(w, http.StatusServiceUnavailable, "wifi state is unavailable")
		return
	}
	pairingState := proto.PairingUnpaired
	if h.pairing != nil {
		pairingState = h.pairing.State()
	}
	writeJSON(w, http.StatusOK, Status{
		DeviceID:     h.identity.DeviceID,
		Platform:     h.identity.Platform,
		Model:        h.identity.Model,
		AgentVersion: h.identity.AgentVersion,
		PairingState: pairingState,
		WiFiState:    wifi.State,
		SSID:         wifi.SSID,
		APSSID:       wifi.APSSID,
		Failure:      wifi.FailureReason,
	})
}

func (h *Handler) scan(w http.ResponseWriter, r *http.Request) {
	result, err := h.network.Scan(r.Context())
	if err != nil {
		writeFailure(w, http.StatusServiceUnavailable, "scan failed")
		return
	}
	// Reduced on purpose: channel and BSSID are not needed to pick a network
	// and would only help someone fingerprint the location.
	networks := make([]Network, 0, len(result.Networks))
	for _, network := range result.Networks {
		networks = append(networks, Network{
			SSID:      network.SSID,
			SignalDBM: network.SignalDBM,
			Security:  network.Security,
		})
	}
	writeJSON(w, http.StatusOK, ScanResult{Networks: networks})
}

func (h *Handler) connect(w http.ResponseWriter, r *http.Request) {
	var request ConnectRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeFailure(w, http.StatusBadRequest, err.Error())
		return
	}
	status, err := h.network.Connect(r.Context(), proto.WiFiConnectRequest{
		SSID:     request.SSID,
		PSK:      request.PSK,
		Security: request.Security,
	})
	if err != nil {
		code := proto.CodeOf(err)
		writeFailure(w, code.HTTPStatus(), "could not start the connection")
		return
	}
	// The response carries state, never the credential that was just supplied.
	writeJSON(w, http.StatusAccepted, Status{
		DeviceID:     h.identity.DeviceID,
		Platform:     h.identity.Platform,
		Model:        h.identity.Model,
		AgentVersion: h.identity.AgentVersion,
		PairingState: proto.PairingUnpaired,
		WiFiState:    status.State,
		SSID:         status.SSID,
		APSSID:       status.APSSID,
	})
}

func (h *Handler) notFound(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not found", http.StatusNotFound)
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

// Supervisor opens the provisioning listener while the Node is in
// PROVISIONING_AP and closes it the moment it is not.
//
// Polling rather than subscribing keeps this independent of whether a
// particular network backend can push state changes, and the interval is the
// worst-case window during which a just-connected Node still answers. The
// handler's own guard closes that window immediately for any request that
// arrives inside it, so the listener outliving the state by a few seconds is
// not itself an exposure.
type Supervisor struct {
	options  Options
	interval time.Duration

	mu       sync.Mutex
	server   *http.Server
	listener net.Listener
	address  string
	starts   int
	stops    int
}

// NewSupervisor builds a supervisor. It does not listen until Run.
func NewSupervisor(options Options, interval time.Duration) (*Supervisor, error) {
	if _, _, err := NewHandler(options); err != nil {
		return nil, err
	}
	if options.Listen == "" {
		options.Listen = DefaultListenAddress
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Supervisor{options: options, interval: interval}, nil
}

// Run drives the supervisor until ctx is cancelled. It returns only when the
// listener has been closed, so a caller can rely on the port being free.
func (s *Supervisor) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	s.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			s.stop()
			return
		case <-ticker.C:
			s.reconcile(ctx)
		}
	}
}

func (s *Supervisor) reconcile(ctx context.Context) {
	status, err := s.options.Network.Status(ctx)
	if err != nil {
		s.stop()
		return
	}
	if status.State == proto.WiFiProvisioningAP {
		s.start()
		return
	}
	s.stop()
}

func (s *Supervisor) start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil {
		return
	}
	_, handler, err := NewHandler(s.options)
	if err != nil {
		return
	}
	listener, err := net.Listen("tcp", s.options.Listen)
	if err != nil {
		// A device whose AP interface is not up yet simply retries next tick.
		return
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	s.server = server
	s.listener = listener
	s.address = listener.Addr().String()
	s.starts++
	go func() {
		_ = server.Serve(listener)
	}()
}

func (s *Supervisor) stop() {
	s.mu.Lock()
	server := s.server
	s.server = nil
	s.listener = nil
	if server != nil {
		s.stops++
	}
	s.mu.Unlock()
	if server == nil {
		return
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Shutdown first so an in-flight setup POST completes; Close guarantees the
	// port is released even if a client is holding the connection open.
	_ = server.Shutdown(shutdown)
	_ = server.Close()
}

// Address reports the bound address while serving, or the empty string.
func (s *Supervisor) Address() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.address
}

// Serving reports whether the provisioning listener is currently open.
func (s *Supervisor) Serving() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.server != nil
}

// Counters reports how many times the listener has been opened and closed, so
// a test can assert the lifecycle rather than guess at it.
func (s *Supervisor) Counters() (starts, stops int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.starts, s.stops
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeFailure(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return errors.New("request body could not be read")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid JSON request")
	}
	return nil
}
