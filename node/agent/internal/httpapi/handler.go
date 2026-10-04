// Package httpapi serves the NasSimHub Node Protocol over HTTP.
//
// The handler is transport agnostic by construction. It is mounted on whatever
// listener the agent opens - a USB network interface, a Wi-Fi interface, or a
// loopback socket in a test - and nothing in it inspects the peer address or
// behaves differently depending on which interface a request arrived on. That
// is what makes "USB and Wi-Fi speak the same protocol" a structural property
// rather than a convention someone has to remember.
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/diag"
	"github.com/human-agent65535/nassimhub-node/agent/internal/identity"
	"github.com/human-agent65535/nassimhub-node/agent/internal/logbuf"
	"github.com/human-agent65535/nassimhub-node/agent/internal/pairing"
	"github.com/human-agent65535/nassimhub-node/agent/internal/systemstats"
	"github.com/human-agent65535/nassimhub-node/agent/internal/voicemedia"
	"github.com/human-agent65535/nassimhub-node/agent/modembackend"
	"github.com/human-agent65535/nassimhub-node/agent/netbackend"
	"github.com/human-agent65535/nassimhub-node/agent/nodetls"
	"github.com/human-agent65535/nassimhub-node/proto"
)

const maxRequestBodyBytes = 64 << 10

// Options wires the handler's collaborators.
type Options struct {
	// LocalAdmin wraps only the explicit local device routes with separate browser authentication.
	LocalAdmin       func(http.Handler)
	LocalAdminAccess func() (bool, string, int)

	Identity     *identity.Identity
	Pairing      *pairing.Store
	Modem        modembackend.Backend
	CallMedia    voicemedia.Opener
	Network      netbackend.Backend
	Logs         *logbuf.Buffer
	AgentVersion string
	BuildDate    string
	Now          func() time.Time
	// ListenPorts and TLS describe how this Node is served. They appear only
	// in diagnostics, where "which port, and is it encrypted" is a question
	// support actually has to ask. Addresses are deliberately not carried.
	ListenPorts []int
	TLS         bool
	// PQProfile and PQPolicy are what this Node was configured with. They are
	// reported alongside what a given connection actually negotiated, so a
	// user can see the difference between "asked for" and "got".
	PQProfile proto.PQProfile
	PQPolicy  proto.PQPolicy
	// TransportReport supplies the link counters. It is a function rather than
	// a value because the numbers change while the process runs, and it is
	// optional because a Node reached over TCP has none to report - in which
	// case the section says "not measured" instead of showing zeros.
	TransportReport func() proto.TransportSection
	// TransportKeys issues and destroys the KCP transport secret. Optional: a
	// Node with no weak-network transport answers the endpoint with
	// NotSupported.
	TransportKeys TransportKeys
	// PQIdentity reports the device's post-quantum identity, when it has one.
	PQIdentity func() proto.PQIdentity
	// SecurityLevel is the level this Node was configured with.
	SecurityLevel proto.SecurityLevel
}

type handler struct {
	identity     *identity.Identity
	pairing      *pairing.Store
	modem        modembackend.Backend
	callMedia    voicemedia.Opener
	mediaMu      sync.Mutex
	mediaActive  bool
	network      netbackend.Backend
	logs         *logbuf.Buffer
	events       modembackend.EventSource
	agentVersion string
	buildDate    string
	now          func() time.Time
	startedAt    time.Time
	listenPorts  []int
	tls          bool
	pqProfile    proto.PQProfile
	pqPolicy     proto.PQPolicy
	transport    func() proto.TransportSection
	// transportKeys issues the KCP transport secret over the authenticated
	// TLS channel, and destroys it on unpair. Nil on a Node with no
	// weak-network transport, where the endpoint answers 404 and a Core reads
	// that as "this device cannot do KCP" rather than as a failure.
	transportKeys TransportKeys
	// identityOf reports the device's post-quantum identity, when it has one.
	identityOf func() proto.PQIdentity
	// securityLevel is what this Node was configured with.
	securityLevel proto.SecurityLevel
}

// TransportKeys is the part of the transport key store this handler needs.
//
// An interface rather than the concrete store, so that the handler package does
// not depend on the agent's internal key storage - and so a test can supply one
// that records whether Destroy was called, which is how "unpair destroys the
// secret" is checked as behaviour rather than read as intent.
type TransportKeys interface {
	Current() (proto.TransportKeyResponse, error)
	Rotate() (proto.TransportKeyResponse, error)
	Destroy() error
}

// New builds the Node's HTTP handler.
func New(options Options) http.Handler {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	h := &handler{
		identity:     options.Identity,
		pairing:      options.Pairing,
		modem:        options.Modem,
		callMedia:    options.CallMedia,
		network:      options.Network,
		logs:         options.Logs,
		agentVersion: options.AgentVersion,
		buildDate:    options.BuildDate,
		now:          now,
		startedAt:    now().UTC(),
		listenPorts:  options.ListenPorts,
		tls:          options.TLS,
		pqProfile:    options.PQProfile,
		pqPolicy:     options.PQPolicy,
		transport:    options.TransportReport,

		transportKeys: options.TransportKeys,
		identityOf:    options.PQIdentity,
		securityLevel: options.SecurityLevel,
	}
	if h.securityLevel == "" {
		h.securityLevel = proto.LevelFor(options.PQProfile, options.PQPolicy)
	}
	if h.pqProfile == "" {
		h.pqProfile = proto.PQStandard
	}
	if h.pqPolicy == "" {
		h.pqPolicy = proto.PQPreferred
	}
	// Event streaming is optional. A backend that cannot observe changes simply
	// does not implement the interface and the endpoint answers 501, rather
	// than the handler pretending to stream and delivering nothing.
	h.events, _ = options.Modem.(modembackend.EventSource)

	mux := http.NewServeMux()

	// Unauthenticated. These two exist so an unpaired Node can be discovered
	// and shown to a user. They carry identity and liveness only - never SIM
	// data, never a phone number, never a network address.
	mux.HandleFunc("GET /v1/node", h.getNode)
	mux.HandleFunc("GET /v1/health", h.getHealth)

	// Signed with the Core's long-lived key.
	mux.HandleFunc("POST /v1/pair", h.postPair)
	mux.HandleFunc("POST /v1/session", h.postSession)

	// Bearer-authenticated.
	mux.HandleFunc("DELETE /v1/pair", h.authenticated(h.deletePair))
	mux.HandleFunc("POST /v1/pair/factory-reset", h.authenticated(h.postFactoryReset))
	mux.HandleFunc("POST /v1/admin/access", h.authenticated(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			h.writeAPIError(w, proto.ErrorPermissionDenied, "local_admin_access", "", "TLS is required")
			return
		}
		if options.LocalAdminAccess == nil {
			h.writeAPIError(w, proto.ErrorNotSupported, "local_admin_access", "", "local administration is unavailable")
			return
		}
		configured, proof, port := options.LocalAdminAccess()
		w.Header().Set("Cache-Control", "no-store")
		h.writeJSON(w, http.StatusOK, struct {
			Configured bool   `json:"configured"`
			SetupCode  string `json:"setup_code,omitempty"`
			Port       int    `json:"port"`
		}{configured, proof, port})
	}))
	mux.HandleFunc("GET /v1/capabilities", h.authenticated(h.getCapabilities))
	mux.HandleFunc("GET /v1/version", h.authenticated(h.getVersion))
	mux.HandleFunc("GET /v1/status", h.authenticated(h.getStatus))
	mux.HandleFunc("GET /v1/sim", h.authenticated(h.getSIM))
	mux.HandleFunc("GET /v1/network", h.authenticated(h.getNetwork))
	mux.HandleFunc("GET /v1/signal", h.authenticated(h.getSignal))
	mux.HandleFunc("GET /v1/sms", h.authenticated(h.getSMS))
	mux.HandleFunc("POST /v1/sms/send", h.authenticated(h.postSendSMS))
	mux.HandleFunc("DELETE /v1/sms/{id}", h.authenticated(h.deleteSMS))
	mux.HandleFunc("GET /v1/calls", h.authenticated(h.getCalls))
	mux.HandleFunc("POST /v1/calls/dial", h.authenticated(h.postDial))
	mux.HandleFunc("POST /v1/calls/{id}/answer", h.authenticated(h.postAnswer))
	mux.HandleFunc("POST /v1/calls/{id}/hangup", h.authenticated(h.postHangup))
	mux.HandleFunc("GET /v1/calls/{id}/media", h.authenticated(h.getCallMedia))
	mux.HandleFunc("GET /v1/wifi", h.authenticated(h.getWiFi))
	mux.HandleFunc("POST /v1/wifi/scan", h.authenticated(h.postWiFiScan))
	mux.HandleFunc("POST /v1/wifi/connect", h.authenticated(h.postWiFiConnect))
	mux.HandleFunc("POST /v1/wifi/forget", h.authenticated(h.postWiFiForget))
	mux.HandleFunc("GET /v1/logs", h.authenticated(h.getLogs))
	mux.HandleFunc("POST "+proto.TransportKeyPath, h.authenticated(h.postTransportKey))
	// Diagnostics are authenticated like everything else. The bundle carries no
	// secrets by construction, but "carries no secrets" is not a reason to let
	// a stranger on the network enumerate the device's state.
	mux.HandleFunc("GET /v1/diagnostics", h.authenticated(h.getDiagnostics))
	mux.HandleFunc("GET /v1/diagnostics/archive", h.authenticated(h.getDiagnosticsArchive))
	mux.HandleFunc("GET /v1/events", h.authenticated(h.getEvents))

	if options.LocalAdmin != nil {
		local := http.NewServeMux()
		local.HandleFunc("GET /v1/node", h.getNode)
		local.HandleFunc("GET /v1/version", h.getVersion)
		local.HandleFunc("GET /v1/status", h.getStatus)
		local.HandleFunc("GET /v1/sim", h.getSIM)
		local.HandleFunc("GET /v1/network", h.getNetwork)
		local.HandleFunc("GET /v1/signal", h.getSignal)
		local.HandleFunc("GET /v1/capabilities", h.getCapabilities)
		local.HandleFunc("GET /v1/sms", h.getSMS)
		local.HandleFunc("POST /v1/sms/send", h.postSendSMS)
		local.HandleFunc("DELETE /v1/sms/{id}", h.deleteSMS)
		local.HandleFunc("GET /v1/calls", h.getCalls)
		local.HandleFunc("GET /v1/wifi", h.getWiFi)
		local.HandleFunc("POST /v1/wifi/scan", h.postWiFiScan)
		local.HandleFunc("POST /v1/wifi/connect", h.postWiFiConnect)
		local.HandleFunc("POST /v1/wifi/forget", h.postWiFiForget)
		local.HandleFunc("GET /v1/logs", h.getLogs)
		local.HandleFunc("GET /v1/diagnostics", h.getDiagnostics)
		local.HandleFunc("GET /v1/diagnostics/archive", h.getDiagnosticsArchive)
		options.LocalAdmin(local)
	}
	mux.HandleFunc("/", h.notFound)
	return mux
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

// authenticated wraps a handler in the bearer-token check.
//
// An unpaired Node rejects every one of these endpoints. That is the guarantee
// behind "an unpaired Node cannot send an SMS": the check happens before the
// handler runs, so no operation can be reached by forgetting a guard.
func (h *handler) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			h.writeAPIError(w, proto.ErrorUnauthenticated, "authenticate", "", "a bearer token is required")
			return
		}
		switch err := h.pairing.VerifySession(token); {
		case err == nil:
		case errors.Is(err, pairing.ErrNotPaired):
			h.writeAPIError(w, proto.ErrorPermissionDenied, "authenticate", "", "node is not paired")
			return
		default:
			h.writeAPIError(w, proto.ErrorUnauthenticated, "authenticate", "", "session token is not valid")
			return
		}
		next(w, r)
	}
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

// readSigned reads a body and assembles the signature material from headers.
func (h *handler) readSigned(w http.ResponseWriter, r *http.Request) ([]byte, pairing.SignedRequest, bool) {
	body, err := readBody(w, r)
	if err != nil {
		h.writeAPIError(w, proto.ErrorInvalidArgument, "authenticate", "", err.Error())
		return nil, pairing.SignedRequest{}, false
	}
	signed := pairing.SignedRequest{
		CoreID:    r.Header.Get(proto.HeaderCoreID),
		Timestamp: r.Header.Get(proto.HeaderTimestamp),
		Nonce:     r.Header.Get(proto.HeaderNonce),
		Signature: r.Header.Get(proto.HeaderSignature),
		Method:    r.Method,
		Path:      r.URL.Path,
		Body:      body,
	}
	if signed.CoreID == "" || signed.Signature == "" || signed.Timestamp == "" || signed.Nonce == "" {
		h.writeAPIError(w, proto.ErrorUnauthenticated, "authenticate", "", "request is not signed")
		return nil, pairing.SignedRequest{}, false
	}
	return body, signed, true
}

// ---------------------------------------------------------------------------
// Discovery and liveness
// ---------------------------------------------------------------------------

func (h *handler) getNode(w http.ResponseWriter, _ *http.Request) {
	h.writeJSON(w, http.StatusOK, proto.Node{
		DeviceID:        h.identity.DeviceID,
		Platform:        h.identity.Platform,
		Model:           h.identity.Model,
		AgentVersion:    h.agentVersion,
		Protocol:        proto.ProtocolVersion,
		PublicKey:       proto.EncodeKey(h.identity.PublicKey),
		PairingState:    h.pairing.State(),
		PairedCoreID:    h.pairing.OwnerID(),
		BootID:          h.identity.BootID(),
		StartedAt:       h.startedAt,
		ProtocolVersion: proto.ProtocolMajor,
		ProtocolMinor:   proto.ProtocolMinor,
		MinCoreVersion:  proto.MinCoreVersion,
		// The post-quantum identity is published in the UNAUTHENTICATED
		// document, alongside the Ed25519 key, because Core needs both before
		// it can decide whether to adopt the device. Publishing a public key
		// is not a disclosure - that is what public means - and withholding it
		// until after pairing would mean pairing could not be dual-signed.
		PQIdentity: h.pqIdentity(),
	})
}

// pqIdentity reports the device's post-quantum identity, or an empty one.
func (h *handler) pqIdentity() proto.PQIdentity {
	if h.identityOf == nil {
		return proto.PQIdentity{}
	}
	return h.identityOf()
}

func (h *handler) getHealth(w http.ResponseWriter, r *http.Request) {
	state := proto.ModemUnknown
	if observer, ok := h.modem.(interface {
		HealthState(context.Context) (proto.ModemState, error)
	}); ok {
		if observed, err := observer.HealthState(r.Context()); err == nil {
			state = observed
		}
	} else if status, err := h.modem.GetStatus(r.Context()); err == nil {
		state = status.State
	}
	health := proto.Health{
		Status:       proto.HealthOK,
		APIVersion:   proto.APIVersion,
		AgentVersion: h.agentVersion,
		DeviceID:     h.identity.DeviceID,
		ModemState:   string(state),
		ObservedAt:   h.now().UTC(),
	}
	if state != proto.ModemReady {
		// The agent is alive but cannot do its job. Reporting "degraded" rather
		// than failing the request keeps the Node visible in the NAS while
		// making the reason explicit.
		health.Status = proto.HealthDegraded
	}
	h.writeJSON(w, http.StatusOK, health)
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

func (h *handler) postPair(w http.ResponseWriter, r *http.Request) {
	body, signed, ok := h.readSigned(w, r)
	if !ok {
		return
	}
	var request proto.PairRequest
	if err := json.Unmarshal(body, &request); err != nil {
		h.writeAPIError(w, proto.ErrorInvalidArgument, "pair", "", "invalid JSON request")
		return
	}
	if signed.CoreID != request.CoreID {
		h.writeAPIError(w, proto.ErrorUnauthenticated, "pair", "", "signature core id does not match the request")
		return
	}

	session, err := h.pairing.Pair(request, signed)
	if err != nil {
		h.logs.Warnf("pairing", "pair request from %s refused: %v", request.CoreID, err)
		h.writePairingError(w, "pair", err)
		return
	}
	h.logs.Infof("pairing", "paired with core %s", request.CoreID)
	h.writeJSON(w, http.StatusCreated, proto.PairResponse{
		DeviceID:        h.identity.DeviceID,
		PairingState:    h.pairing.State(),
		CoreFingerprint: h.pairing.OwnerFingerprint(),
		Session:         session,
	})
}

func (h *handler) postSession(w http.ResponseWriter, r *http.Request) {
	body, signed, ok := h.readSigned(w, r)
	if !ok {
		return
	}
	var request proto.SessionRequest
	if err := json.Unmarshal(body, &request); err != nil {
		h.writeAPIError(w, proto.ErrorInvalidArgument, "session", "", "invalid JSON request")
		return
	}
	session, err := h.pairing.NewSession(request.CoreID, signed)
	if err != nil {
		h.writePairingError(w, "session", err)
		return
	}
	h.writeJSON(w, http.StatusCreated, session)
}

func (h *handler) deletePair(w http.ResponseWriter, _ *http.Request) {
	state, err := h.pairing.Unpair()
	if err != nil {
		h.writePairingError(w, "unpair", err)
		return
	}
	// Unpairing must REVOKE the transport, not merely forget who the owner
	// was. Without this the previous Core keeps a key that authenticates every
	// UDP packet to this device - a pairing that was undone on one side only.
	h.destroyTransportKeys("unpair")
	h.logs.Infof("pairing", "unpaired on request")
	h.writeJSON(w, http.StatusOK, proto.UnpairResponse{DeviceID: h.identity.DeviceID, PairingState: state})
}

func (h *handler) postFactoryReset(w http.ResponseWriter, r *http.Request) {
	var request proto.FactoryResetRequest
	if !h.decode(w, r, "factory_reset", &request) {
		return
	}
	state, err := h.pairing.FactoryResetPairing(request.Confirm)
	if err != nil {
		h.writeAPIError(w, proto.ErrorInvalidArgument, "factory_reset", "", err.Error())
		return
	}
	h.destroyTransportKeys("factory_reset")
	h.logs.Warnf("pairing", "pairing factory reset; device identity retained")
	h.writeJSON(w, http.StatusOK, proto.UnpairResponse{DeviceID: h.identity.DeviceID, PairingState: state})
}

// destroyTransportKeys erases the KCP secret and says so in the log.
//
// The log line names no key material - only that a destruction happened, which
// is the one fact support needs when a Core reports that its packets stopped
// authenticating right after somebody pressed unbind.
func (h *handler) destroyTransportKeys(reason string) {
	if h.transportKeys == nil {
		return
	}
	if err := h.transportKeys.Destroy(); err != nil {
		h.logs.Errorf("transport", "could not destroy the transport secret after %s: %v", reason, err)
		return
	}
	h.logs.Infof("transport", "transport secret destroyed after %s", reason)
}

// postTransportKey hands the paired Core the KCP transport secret.
//
// Authenticated, so only the owner can ask. Over TLS, because the response
// carries raw key material - the only response in this protocol that does. It
// is never logged and never reaches a diagnostics bundle; there are tests for
// both.
func (h *handler) postTransportKey(w http.ResponseWriter, r *http.Request) {
	if h.transportKeys == nil {
		h.writeAPIError(w, proto.ErrorNotSupported, "transport_key", "",
			"this node does not provide a weak-network transport")
		return
	}
	var request proto.TransportKeyRequest
	if r.ContentLength > 0 && !h.decode(w, r, "transport_key", &request) {
		return
	}
	var (
		response proto.TransportKeyResponse
		err      error
	)
	if request.Rotate {
		response, err = h.transportKeys.Rotate()
	} else {
		response, err = h.transportKeys.Current()
	}
	if err != nil {
		h.writeError(w, proto.Internal("transport_key", "could not issue a transport secret", err))
		return
	}
	// The log records THAT a key was issued and which epoch, never the key.
	h.logs.Infof("transport", "transport secret issued, epoch %d, rotate=%v",
		response.Epoch, request.Rotate)
	h.writeJSON(w, http.StatusOK, response)
}

func (h *handler) writePairingError(w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, pairing.ErrAlreadyPaired):
		h.writeAPIError(w, proto.ErrorConflict, operation, "", "node is already paired with another core")
	case errors.Is(err, pairing.ErrNotPaired):
		h.writeAPIError(w, proto.ErrorFailedPrecondition, operation, "", "node is not paired")
	case errors.Is(err, pairing.ErrUnknownCore):
		h.writeAPIError(w, proto.ErrorPermissionDenied, operation, "", "core is not the paired owner")
	case errors.Is(err, pairing.ErrReplay):
		h.writeAPIError(w, proto.ErrorUnauthenticated, operation, "", "request nonce was already used")
	case errors.Is(err, pairing.ErrStaleRequest):
		h.writeAPIError(w, proto.ErrorUnauthenticated, operation, "", "request timestamp is outside the accepted window")
	case errors.Is(err, pairing.ErrBadSignature):
		h.writeAPIError(w, proto.ErrorUnauthenticated, operation, "", "request signature is not valid")
	default:
		h.writeAPIError(w, proto.ErrorInternal, operation, "", "pairing failed")
	}
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

func (h *handler) getCapabilities(w http.ResponseWriter, r *http.Request) {
	capabilities, err := h.modem.Capabilities(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	voice, voiceErr := h.modem.GetVoiceCapability(r.Context())
	response := struct {
		proto.Capabilities
		Voice *modembackend.VoiceCapability `json:"voice,omitempty"`
		// Security is per-connection, not per-device: the same Node answers
		// one Core over a post-quantum session and an older one classically.
		// Reporting what THIS request negotiated is the only answer that means
		// anything, which is why it is read from the request rather than from
		// a field set at start-up.
		Security proto.SecurityCapability `json:"security"`
	}{Capabilities: capabilities, Security: h.securityOf(r)}
	if voiceErr == nil {
		response.Voice = &voice
	}
	h.writeJSON(w, http.StatusOK, response)
}

// securityOf reports what the connection carrying this request negotiated.
//
// A plaintext request reports pq_supported truthfully and pq_active "no": there
// is no key agreement at all, which is strictly worse than a classical one, and
// saying "unknown" would let a development build look like an old toolchain.
func (h *handler) securityOf(r *http.Request) proto.SecurityCapability {
	capability := nodetls.Supported()
	capability.PQProfile = h.pqProfile
	capability.PQPolicy = h.pqPolicy
	if r.TLS == nil {
		capability.PQActive = proto.TriNo
		return capability
	}
	return nodetls.ObserveServer(*r.TLS, h.pqProfile, h.pqPolicy)
}

func (h *handler) getVersion(w http.ResponseWriter, _ *http.Request) {
	h.writeJSON(w, http.StatusOK, proto.VersionInfo{
		AgentVersion:    h.agentVersion,
		ProtocolVersion: proto.ProtocolMajor,
		Platform:        h.identity.Platform,
		BuildDate:       h.buildDate,
		// OTA is groundwork only in this stage: the Node reports what it is
		// running and nothing fetches or applies anything.
		OTASupported: false,
	})
}

func (h *handler) getStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.modem.GetStatus(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	if sample := systemstats.Snapshot(); sample != nil {
		resources := *sample
		resources.Metrics = make(map[string]any, len(sample.Metrics)+1)
		for key, value := range sample.Metrics {
			resources.Metrics[key] = value
		}
		cellular := map[string]any{"state": status.Network.Registration, "rat": status.Network.AccessTechnology, "plmn": status.Network.OperatorCode, "rsrp": status.Signal.RSRP, "rsrq": status.Signal.RSRQ, "rssi": status.Signal.DBM, "sinr": status.Signal.SNR}
		if radio, ok := resources.Metrics["cellular_radio"].(map[string]any); ok {
			for key, value := range radio {
				cellular[key] = value
			}
		}
		resources.Metrics["cellular"] = cellular
		status.Resources = &resources
	}
	h.writeJSON(w, http.StatusOK, status)
}

func (h *handler) getSIM(w http.ResponseWriter, r *http.Request) {
	info, err := h.modem.GetSIMInfo(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, info)
}

func (h *handler) getNetwork(w http.ResponseWriter, r *http.Request) {
	network, err := h.modem.GetNetwork(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, network)
}

func (h *handler) getSignal(w http.ResponseWriter, r *http.Request) {
	signal, err := h.modem.GetSignal(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, signal)
}

// ---------------------------------------------------------------------------
// Messaging
// ---------------------------------------------------------------------------

func (h *handler) getSMS(w http.ResponseWriter, r *http.Request) {
	messages, err := h.modem.ListSMS(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.stampNode(messages)
	h.writeJSON(w, http.StatusOK, proto.SMSList{Messages: messages})
}

// stampNode fills in the node_id every message and call carries.
//
// The Node stamps its own identifier rather than leaving it to Core, so a
// message is self-describing from the moment it leaves the device. Combined
// with the SIMID the backend already sets, a message that crosses a
// multi-Node NAS can always be attributed to one device and one card.
func (h *handler) stampNode(messages []proto.SMS) {
	for index := range messages {
		messages[index].NodeID = h.identity.DeviceID
	}
}

func (h *handler) stampNodeCalls(calls []proto.Call) {
	for index := range calls {
		calls[index].NodeID = h.identity.DeviceID
	}
}

func (h *handler) postSendSMS(w http.ResponseWriter, r *http.Request) {
	var request proto.SendSMSRequest
	if !h.decode(w, r, "send_sms", &request) {
		return
	}
	response, err := h.modem.SendSMS(r.Context(), request)
	if err != nil {
		h.writeErrorWithRequest(w, err, request.RequestID)
		return
	}
	// The recipient and the body are deliberately absent from this log line.
	h.logs.Infof("sms", "submitted message %s (%s)", response.MessageID, logbuf.RedactSMSText(request.Text))
	h.writeJSON(w, http.StatusCreated, response)
}

func (h *handler) deleteSMS(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		h.writeAPIError(w, proto.ErrorInvalidArgument, "delete_sms", "", "message id is required")
		return
	}
	if err := h.modem.DeleteSMS(r.Context(), id); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

func (h *handler) getCalls(w http.ResponseWriter, r *http.Request) {
	calls, err := h.modem.ListCalls(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.stampNodeCalls(calls)
	h.writeJSON(w, http.StatusOK, proto.CallList{Calls: calls})
}

func (h *handler) postDial(w http.ResponseWriter, r *http.Request) {
	var request proto.DialRequest
	if !h.decode(w, r, "dial", &request) {
		return
	}
	receipt, err := h.modem.Dial(r.Context(), request)
	if err != nil {
		h.writeErrorWithRequest(w, err, request.RequestID)
		return
	}
	h.logs.Infof("call", "originated call %s", receipt.CallID)
	h.writeJSON(w, http.StatusCreated, receipt)
}

func (h *handler) postAnswer(w http.ResponseWriter, r *http.Request) {
	h.callCommand(w, r, "answer", h.modem.Answer)
}

func (h *handler) postHangup(w http.ResponseWriter, r *http.Request) {
	h.callCommand(w, r, "hangup", h.modem.Hangup)
}

func (h *handler) callCommand(
	w http.ResponseWriter,
	r *http.Request,
	operation string,
	run func(ctx context.Context, id string) (proto.CallReceipt, error),
) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "call id is required")
		return
	}
	receipt, err := run(r.Context(), id)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, receipt)
}

// ---------------------------------------------------------------------------
// Wi-Fi
// ---------------------------------------------------------------------------

func (h *handler) getWiFi(w http.ResponseWriter, r *http.Request) {
	status, err := h.network.Status(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, status)
}

func (h *handler) postWiFiScan(w http.ResponseWriter, r *http.Request) {
	result, err := h.network.Scan(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *handler) postWiFiConnect(w http.ResponseWriter, r *http.Request) {
	var request proto.WiFiConnectRequest
	if !h.decode(w, r, "wifi_connect", &request) {
		return
	}
	status, err := h.network.Connect(r.Context(), request)
	if err != nil {
		h.writeError(w, err)
		return
	}
	// The SSID is logged; the PSK is not passed to the logger at all.
	h.logs.Infof("wifi", "joining network %q", request.SSID)
	h.writeJSON(w, http.StatusAccepted, status)
}

func (h *handler) postWiFiForget(w http.ResponseWriter, r *http.Request) {
	status, err := h.network.Forget(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.logs.Infof("wifi", "forgot the saved network")
	h.writeJSON(w, http.StatusOK, status)
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

func (h *handler) getLogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			h.writeAPIError(w, proto.ErrorInvalidArgument, "logs", "", "limit must be a non-negative integer")
			return
		}
		limit = parsed
	}
	level := proto.LogLevel(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level"))))
	switch level {
	case proto.LogDebug, proto.LogInfo, proto.LogWarn, proto.LogError:
	case "":
		level = proto.LogDebug
	default:
		h.writeAPIError(w, proto.ErrorInvalidArgument, "logs", "", "level must be debug, info, warn or error")
		return
	}
	h.writeJSON(w, http.StatusOK, h.logs.Page(limit, level))
}

func (h *handler) getEvents(w http.ResponseWriter, r *http.Request) {
	if h.events == nil {
		h.writeAPIError(w, proto.ErrorNotSupported, "events", "", "this backend cannot observe changes")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.writeAPIError(w, proto.ErrorNotSupported, "events", "", "streaming is not available")
		return
	}
	stream, err := h.events.Subscribe(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	encoder := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case event, open := <-stream:
			if !open {
				return
			}
			if _, err := io.WriteString(w, "data: "); err != nil {
				return
			}
			if err := encoder.Encode(event); err != nil {
				return
			}
			if _, err := io.WriteString(w, "\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

func (h *handler) notFound(w http.ResponseWriter, _ *http.Request) {
	h.writeAPIError(w, proto.ErrorNotFound, "route", "", "endpoint not found")
}

func (h *handler) decode(w http.ResponseWriter, r *http.Request, operation string, destination any) bool {
	body, err := readBody(w, r)
	if err != nil {
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", err.Error())
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "invalid JSON request")
		return false
	}
	return true
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.ContentLength == 0 && r.Header.Get("Content-Type") == "" {
		return []byte{}, nil
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("content type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, errors.New("request body could not be read")
	}
	return body, nil
}

func (h *handler) writeError(w http.ResponseWriter, err error) {
	h.writeErrorWithRequest(w, err, "")
}

func (h *handler) writeErrorWithRequest(w http.ResponseWriter, err error, requestID string) {
	operationError, ok := proto.AsOperationError(err)
	if !ok {
		h.writeAPIError(w, proto.ErrorInternal, "", requestID, "internal error")
		return
	}
	message := operationError.Message
	if operationError.Cause != nil {
		message = message + ": " + operationError.Cause.Error()
	}
	h.writeAPIError(w, operationError.Code, operationError.Operation, requestID, message)
}

func (h *handler) writeAPIError(w http.ResponseWriter, code proto.ErrorCode, operation, requestID, message string) {
	h.writeJSON(w, code.HTTPStatus(), proto.ErrorBody{Error: proto.APIError{
		Code:      code,
		Operation: operation,
		RequestID: requestID,
		Message:   message,
	}})
}

func (h *handler) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// getDiagnostics returns the bundle as JSON, which is what Core renders.
func (h *handler) getDiagnostics(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, http.StatusOK, h.diagnostics(r))
}

// getDiagnosticsArchive returns the bundle as a downloadable .tar.gz.
//
// The archive is built in memory before a single byte is written, so a failure
// half way through collection becomes an error response rather than a truncated
// file the user would send anyway without knowing it was incomplete.
func (h *handler) getDiagnosticsArchive(w http.ResponseWriter, r *http.Request) {
	bundle := h.diagnostics(r)
	var archive bytes.Buffer
	if err := diag.WriteArchive(&archive, bundle); err != nil {
		h.writeError(w, proto.Internal("diagnostics", "could not build the diagnostics archive", err))
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition",
		`attachment; filename="`+diag.FileName(h.identity.DeviceID, bundle.GeneratedAt)+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(archive.Len()))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(archive.Bytes())
}

func (h *handler) diagnostics(r *http.Request) proto.DiagnosticsBundle {
	return diag.Collect(r.Context(), diag.Options{
		Identity: diag.Identity{
			DeviceID:  h.identity.DeviceID,
			Platform:  h.identity.Platform,
			Model:     h.identity.Model,
			BootID:    h.identity.BootID(),
			StartedAt: h.startedAt,
		},
		AgentVersion: h.agentVersion,
		BuildDate:    h.buildDate,
		Modem:        h.modem,
		Network:      h.network,
		Pairing:      h.pairing,
		Logs:         h.logs,
		ListenPorts:  h.listenPorts,
		TLS:          h.tls,
		Now:          h.now,
		Transport:    h.transportSection(r),
	})
}

// transportSection is the link report for a diagnostics bundle.
//
// The security half is read from the REQUEST rather than from a field set at
// start-up, for the same reason the capability document does it: the same Node
// answers one Core over a post-quantum session and an older one classically, so
// a single stored answer would be wrong for one of them. A bundle collected
// over a connection therefore describes that connection.
//
// When nothing supplies counters the section still carries the security
// capability, because "which encryption did this device negotiate" is a
// question a support bundle must answer even on a transport that measures
// nothing else.
func (h *handler) transportSection(r *http.Request) proto.TransportSection {
	section := proto.TransportSection{Mode: proto.TransportStandard}
	if h.transport != nil {
		section = h.transport()
	}
	section.Security = h.securityOf(r)
	return section
}
