package httpapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	stdio "io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/internal/httpapi"
	"github.com/human-agent65535/nassimhub-node/agent/internal/identity"
	"github.com/human-agent65535/nassimhub-node/agent/internal/logbuf"
	"github.com/human-agent65535/nassimhub-node/agent/internal/pairing"
	"github.com/human-agent65535/nassimhub-node/agent/modembackend"
	"github.com/human-agent65535/nassimhub-node/agent/modembackend/mock"
	netmock "github.com/human-agent65535/nassimhub-node/agent/netbackend/mock"
	"github.com/human-agent65535/nassimhub-node/agent/trust"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// Tests of device-local trust enforcement at the HTTP layer. Offline: a mock
// modem, a mock radio and an in-process handler.

// outgoingRecorder counts the backend calls that are outgoing use. It wraps
// the interface, so every other method is the mock's own.
type outgoingRecorder struct {
	modembackend.Backend
	dials, sends, tones atomic.Int64
}

func (r *outgoingRecorder) Dial(ctx context.Context, request proto.DialRequest) (proto.CallReceipt, error) {
	r.dials.Add(1)
	return r.Backend.Dial(ctx, request)
}

func (r *outgoingRecorder) SendSMS(ctx context.Context, request proto.SendSMSRequest) (proto.SendSMSResponse, error) {
	r.sends.Add(1)
	return r.Backend.SendSMS(ctx, request)
}

func (r *outgoingRecorder) SendDTMF(_ context.Context, id string, request proto.DTMFRequest) (proto.CallReceipt, error) {
	r.tones.Add(1)
	return proto.CallReceipt{RequestID: request.RequestID, CallID: id, State: proto.CallActive}, nil
}

func (r *outgoingRecorder) outgoing() int64 { return r.dials.Load() + r.sends.Load() + r.tones.Load() }

type trustNode struct {
	*node
	gate     *trust.Gate
	backend  *outgoingRecorder
	routes   []httpapi.Route
	local    http.Handler
	dir      string
	clock    *time.Time
	mono     time.Duration
	clockMu  *sync.Mutex
	hardware proto.HardwareIdentity
}

// newTrustNode assembles a handler the way nodeserver does: one gate, given to
// the handler, verifying against the pairing store's owner.
func newTrustNode(t *testing.T, withGate bool) *trustNode {
	t.Helper()
	dir := t.TempDir()
	loaded, err := identity.LoadOrCreate(identity.Options{Dir: dir, Platform: proto.PlatformMock, Model: "mock"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := pairing.Open(pairing.Options{Dir: dir, DeviceID: loaded.DeviceID})
	if err != nil {
		t.Fatal(err)
	}
	scenario := mock.ChinaUnicom
	scenario.VoiceControl, scenario.VoiceAudio = true, true
	modem := mock.New(mock.Options{Scenario: scenario, DeviceID: loaded.DeviceID})
	backend := &outgoingRecorder{Backend: modem}
	wifi := netmock.New(netmock.Options{DeviceID: loaded.DeviceID})
	logs := logbuf.New(logbuf.Options{Capacity: 200})
	now := time.Now()
	tn := &trustNode{backend: backend, dir: dir, clock: &now, clockMu: &sync.Mutex{},
		hardware: proto.HardwareIdentity{Present: false, Reason: "test: no hardware identifier"}}
	options := httpapi.Options{
		Identity: loaded, Pairing: store, Modem: backend, Network: wifi, Logs: logs, AgentVersion: "test", BuildDate: "2026-10-05",
		LocalAdmin: func(local http.Handler) { tn.local = local },
		Hardware:   func() proto.HardwareIdentity { return tn.hardware },
	}
	if withGate {
		tn.gate, err = trust.Open(trust.Options{Dir: dir, DeviceID: loaded.DeviceID, Owner: store.Owner, Now: func() time.Time {
			tn.clockMu.Lock()
			defer tn.clockMu.Unlock()
			return *tn.clock
		}, Monotonic: func() time.Duration {
			tn.clockMu.Lock()
			defer tn.clockMu.Unlock()
			return tn.mono
		}, Logf: func(level proto.LogLevel, format string, arguments ...any) { logs.Infof("trust", format, arguments...) }})
		if err != nil {
			t.Fatal(err)
		}
		options.Trust = tn.gate
	}
	handler, routes := httpapi.NewWithRoutes(options)
	tn.routes = routes
	server := httptest.NewServer(handler)
	t.Cleanup(func() {
		server.Close()
		_ = modem.Close()
		_ = wifi.Close()
		_ = logs.Close()
	})
	tn.node = &node{t: t, server: server, identity: loaded, pairs: store, modem: modem, wifi: wifi, logs: logs}
	return tn
}

func (n *trustNode) policy(core *coreKey, generation uint64, state proto.TrustState, deny ...proto.TrustAction) proto.TrustPolicy {
	now := time.Now()
	return proto.TrustPolicy{Version: 1, DeviceID: n.identity.DeviceID, CoreID: core.id, Generation: generation, State: state,
		Mode: proto.TrustEnforce, Deny: proto.NormalizeTrustDeny(deny), Reason: "test reason",
		IssuedAt: proto.FormatTrustTime(now), ExpiresAt: proto.FormatTrustTime(now.Add(24 * time.Hour))}
}

func signPolicy(t *testing.T, key ed25519.PrivateKey, policy proto.TrustPolicy) proto.SignedTrustPolicy {
	t.Helper()
	signed, err := proto.SignTrustPolicy(policy, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// push sends a policy over the genuine authenticated session.
func (n *trustNode) push(token string, signed proto.SignedTrustPolicy) *http.Response {
	n.t.Helper()
	return n.auth(token, "POST", proto.TrustPolicyPath, signed)
}

func (n *trustNode) mustPush(token string, core *coreKey, policy proto.TrustPolicy) {
	n.t.Helper()
	response := n.push(token, signPolicy(n.t, core.private, policy))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		n.t.Fatalf("push generation %d: %d %+v", policy.Generation, response.StatusCode, errorBodyOf(n.t, response))
	}
}

func (n *trustNode) status(token string) proto.TrustStatus {
	n.t.Helper()
	response := n.auth(token, "GET", proto.TrustStatusPath, nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		n.t.Fatalf("GET /v1/trust: %d", response.StatusCode)
	}
	var status proto.TrustStatus
	decode(n.t, response, &status)
	return status
}

var allActions = proto.TrustActions

func TestTrustPolicyIsInstalledAndTheDeviceItselfRefuses(t *testing.T) {
	n := newTrustNode(t, true)
	core := newCore(t, "core-trust")
	token := n.pair(core)

	// Before any policy: nothing is enforced, and it says so.
	if status := n.status(token); !status.Supported || status.Installed || status.Enforcing || status.Hardware.Present || status.Hardware.Reason == "" {
		t.Fatalf("fresh pairing: %+v", status)
	}

	n.mustPush(token, core, n.policy(core, 1, proto.TrustObservation, proto.TrustActionDial, proto.TrustActionSendSMS, proto.TrustActionDTMF))
	status := n.status(token)
	if !status.Installed || !status.Enforcing || status.Generation != 1 || status.State != proto.TrustObservation || len(status.Deny) != 3 || status.Stale || status.Damaged {
		t.Fatalf("after the push: %+v", status)
	}

	// The genuine session asks for outgoing use; the DEVICE refuses.
	send := proto.SendSMSRequest{RequestID: "trust-req-1", To: "10010", Text: "hello"}
	response := n.auth(token, "POST", "/v1/sms/send", send)
	failure := errorBodyOf(t, response)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || failure.Code != proto.ErrorPermissionDenied || failure.Operation != "send_sms" ||
		!strings.Contains(failure.Message, "OBSERVATION") || !strings.Contains(failure.Message, "test reason") {
		t.Fatalf("send under observation: %d %+v", response.StatusCode, failure)
	}
	if strings.Contains(failure.Message, n.identity.DeviceID) || strings.Contains(failure.Message, core.id) || strings.Contains(failure.Message, "10010") {
		t.Fatalf("a refusal carries no identifier: %s", failure.Message)
	}
	response = n.auth(token, "POST", "/v1/calls/dial", proto.DialRequest{RequestID: "trust-dial-1", To: "10010"})
	failure = errorBodyOf(t, response)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || failure.Code != proto.ErrorPermissionDenied || failure.Operation != "dial" {
		t.Fatalf("dial under observation: %d %+v", response.StatusCode, failure)
	}
	if n.backend.outgoing() != 0 {
		t.Fatalf("a refused request reached the backend %d times", n.backend.outgoing())
	}
	// A refused request is refused before its body is looked at.
	response = n.request("POST", "/v1/sms/send", "x", map[string]string{"Authorization": "Bearer " + token}, []byte("{not json"))
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("the gate comes before the body: %d", response.StatusCode)
	}

	// Receiving, answering, hanging up, status, Wi-Fi, logs and diagnostics
	// are never gated.
	if _, err := n.modem.InjectIncomingSMS("10086", "notice"); err != nil {
		t.Fatal(err)
	}
	call, err := n.modem.InjectIncomingCall("+8610000000010")
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct{ method, path string }{
		{"GET", "/v1/sms"}, {"GET", "/v1/calls"}, {"GET", "/v1/status"}, {"GET", "/v1/sim"}, {"GET", "/v1/capabilities"},
		{"POST", "/v1/calls/" + call.ID + "/answer"}, {"POST", "/v1/calls/" + call.ID + "/hangup"},
		{"GET", "/v1/wifi"}, {"POST", "/v1/wifi/scan"}, {"GET", "/v1/logs"}, {"GET", "/v1/diagnostics"}, {"GET", proto.OTAStatusPath},
	} {
		response := n.auth(token, request.method, request.path, nil)
		response.Body.Close()
		if response.StatusCode == http.StatusForbidden {
			t.Errorf("%s %s must never be gated by the trust policy", request.method, request.path)
		}
	}
	if messages := readMessages(t, n.node, token); len(messages) != 1 {
		t.Fatalf("receiving under observation: %d messages", len(messages))
	}

	// The owner lifts it with a higher generation, and the SAME request id
	// now sends: the refusal recorded nothing for de-duplication.
	n.mustPush(token, core, n.policy(core, 2, proto.TrustTrusted))
	response = n.auth(token, "POST", "/v1/sms/send", send)
	response.Body.Close()
	if response.StatusCode != http.StatusCreated || n.backend.sends.Load() != 1 {
		t.Fatalf("send when trusted: %d, backend sends %d", response.StatusCode, n.backend.sends.Load())
	}
	// Pairing is never gated either: unpair works under a quarantine.
	n.mustPush(token, core, n.policy(core, 3, proto.TrustQuarantine, allActions...))
	response = n.auth(token, "DELETE", "/v1/pair", nil)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unpair under quarantine: %d", response.StatusCode)
	}
}

func TestTrustPolicyAuthorityIsTheSignatureNotTheSession(t *testing.T) {
	n := newTrustNode(t, true)
	core := newCore(t, "core-trust")
	token := n.pair(core)

	expect := func(name string, response *http.Response, status int, code proto.ErrorCode) {
		t.Helper()
		failure := errorBodyOf(t, response)
		response.Body.Close()
		if response.StatusCode != status || failure.Code != code || failure.Operation != "trust_policy" {
			t.Fatalf("%s: %d %+v", name, response.StatusCode, failure)
		}
	}

	// Signed by a different key, sent over the genuine authenticated session.
	stranger := newCore(t, core.id)
	expect("another key", n.push(token, signPolicy(t, stranger.private, n.policy(core, 1, proto.TrustTrusted))), http.StatusForbidden, proto.ErrorPermissionDenied)

	// A genuine policy, signed by the owner, for another device.
	elsewhere := n.policy(core, 1, proto.TrustTrusted)
	elsewhere.DeviceID = "NSH-410-TESTDEVICE02"
	expect("another device", n.push(token, signPolicy(t, core.private, elsewhere)), http.StatusForbidden, proto.ErrorPermissionDenied)

	// From another core id.
	foreign := n.policy(core, 1, proto.TrustTrusted)
	foreign.CoreID = "core-elsewhere"
	expect("another core", n.push(token, signPolicy(t, core.private, foreign)), http.StatusForbidden, proto.ErrorPermissionDenied)

	// A header cannot convey authority: an unsigned body with every signing
	// header the protocol knows is still refused.
	unsigned, _ := json.Marshal(proto.SignedTrustPolicy{TrustPolicy: n.policy(core, 1, proto.TrustTrusted), Signature: "AAAA"})
	response := n.request("POST", proto.TrustPolicyPath, "x", map[string]string{
		"Authorization": "Bearer " + token, proto.HeaderCoreID: core.id, proto.HeaderSignature: "AAAA",
		proto.HeaderTimestamp: proto.FormatTimestamp(time.Now()), proto.HeaderNonce: "n", "X-NSH-Trust": "TRUSTED",
	}, unsigned)
	expect("headers", response, http.StatusForbidden, proto.ErrorPermissionDenied)

	// Malformed, and unknown fields.
	expect("malformed", n.request("POST", proto.TrustPolicyPath, "x", map[string]string{"Authorization": "Bearer " + token}, []byte(`{"state":"TRUSTED"}`)),
		http.StatusBadRequest, proto.ErrorInvalidArgument)
	var loose map[string]any
	raw, _ := json.Marshal(signPolicy(t, core.private, n.policy(core, 1, proto.TrustTrusted)))
	_ = json.Unmarshal(raw, &loose)
	loose["allow"] = []string{"dial"}
	extended, _ := json.Marshal(loose)
	expect("unknown field", n.request("POST", proto.TrustPolicyPath, "x", map[string]string{"Authorization": "Bearer " + token}, extended),
		http.StatusBadRequest, proto.ErrorInvalidArgument)

	if n.status(token).Installed {
		t.Fatal("none of those may install anything")
	}

	// The session is still required: a correctly signed policy without one is
	// not even looked at.
	good := signPolicy(t, core.private, n.policy(core, 4, proto.TrustQuarantine, allActions...))
	response = n.do("POST", proto.TrustPolicyPath, good)
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session: %d", response.StatusCode)
	}
	response = n.do("GET", proto.TrustStatusPath, nil)
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /v1/trust without a session: %d", response.StatusCode)
	}

	// Rollback and replay.
	response = n.push(token, good)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("genuine push: %d", response.StatusCode)
	}
	expect("rollback", n.push(token, signPolicy(t, core.private, n.policy(core, 3, proto.TrustTrusted))), http.StatusConflict, proto.ErrorConflict)
	different := n.policy(core, 4, proto.TrustTrusted)
	expect("same generation, other content", n.push(token, signPolicy(t, core.private, different)), http.StatusConflict, proto.ErrorConflict)
	response = n.push(token, good) // the same document again
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("idempotent re-push: %d", response.StatusCode)
	}
	if status := n.status(token); status.Generation != 4 || status.State != proto.TrustQuarantine {
		t.Fatalf("after the refused rollbacks: %+v", status)
	}

	// The public discovery document gained nothing.
	response = n.do("GET", "/v1/node", nil)
	body, _ := stdio.ReadAll(response.Body)
	response.Body.Close()
	for _, word := range []string{`"trust"`, "QUARANTINE", "generation", "hardware", "deny", "stale"} {
		if bytes.Contains(body, []byte(word)) {
			t.Fatalf("/v1/node mentions %q: %s", word, body)
		}
	}
}

func TestExpiredPolicyOverHTTPDeniesAndGoesStale(t *testing.T) {
	n := newTrustNode(t, true)
	core := newCore(t, "core-trust")
	token := n.pair(core)
	n.mustPush(token, core, n.policy(core, 1, proto.TrustTrusted, proto.TrustActionForwardOTP))
	send := func(id string) *http.Response {
		return n.auth(token, "POST", "/v1/sms/send", proto.SendSMSRequest{RequestID: id, To: "10010", Text: "hello"})
	}
	response := send("fresh-1")
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("fresh policy: %d", response.StatusCode)
	}
	// The gate's clock moves past expiry; the session (wall clock) is fine.
	n.clockMu.Lock()
	*n.clock = n.clock.Add(25 * time.Hour)
	n.mono += 25 * time.Hour
	n.clockMu.Unlock()
	response = send("stale-1")
	failure := errorBodyOf(t, response)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || !strings.Contains(failure.Message, "expired") {
		t.Fatalf("an authenticated session does not refresh an expired policy by itself: %d %+v", response.StatusCode, failure)
	}
	if status := n.status(token); !status.Stale || !status.Enforcing || status.Freshness != proto.TrustStaleExpired {
		t.Fatalf("status: %+v", status)
	}
	// Only a fresh policy from the owner does.
	fresh := n.policy(core, 2, proto.TrustTrusted, proto.TrustActionForwardOTP)
	n.clockMu.Lock()
	fresh.IssuedAt, fresh.ExpiresAt = proto.FormatTrustTime(*n.clock), proto.FormatTrustTime(n.clock.Add(24*time.Hour))
	n.clockMu.Unlock()
	n.mustPush(token, core, fresh)
	response = send("stale-1")
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("after the re-push: %d", response.StatusCode)
	}
}

// A UFI003 boots with no idea of the date. A policy from its owner must be
// installed and usable anyway: POST /v1/trust/policy does not consult the
// device's clock, and GET /v1/trust says the policy is fresh.
func TestPolicyOverHTTPDoesNotNeedTheDeviceClock(t *testing.T) {
	n := newTrustNode(t, true)
	core := newCore(t, "core-trust")
	token := n.pair(core)
	n.clockMu.Lock()
	*n.clock = time.Date(1970, 1, 1, 0, 3, 0, 0, time.UTC) // the gate's wall clock only
	n.clockMu.Unlock()

	n.mustPush(token, core, n.policy(core, 1, proto.TrustTrusted, proto.TrustActionForwardOTP)) // issued at the real "now"
	response := n.auth(token, "GET", proto.TrustStatusPath, nil)
	raw, _ := stdio.ReadAll(response.Body)
	response.Body.Close()
	if !bytes.Contains(raw, []byte(`"freshness":"fresh"`)) || !bytes.Contains(raw, []byte(`"stale":false`)) {
		t.Fatalf("GET /v1/trust with an unset clock: %s", raw)
	}
	send := func(id string) int {
		response := n.auth(token, "POST", "/v1/sms/send", proto.SendSMSRequest{RequestID: id, To: "10010", Text: "hello"})
		defer response.Body.Close()
		return response.StatusCode
	}
	if code := send("unset-clock-1"); code != http.StatusCreated {
		t.Fatalf("a permitted send with an unset clock: %d", code)
	}
	// The same document again is accepted (200, not a conflict) ...
	again := n.push(token, signPolicy(t, core.private, n.gatePolicy(t)))
	again.Body.Close()
	if again.StatusCode != http.StatusOK {
		t.Fatalf("an identical re-push: %d", again.StatusCode)
	}
	// ... an older generation is refused whatever the clock says ...
	n.mustPush(token, core, n.policy(core, 5, proto.TrustTrusted))
	older := n.push(token, signPolicy(t, core.private, n.policy(core, 4, proto.TrustTrusted)))
	failure := errorBodyOf(t, older)
	older.Body.Close()
	if older.StatusCode != http.StatusConflict || failure.Code != proto.ErrorConflict {
		t.Fatalf("rollback with an unset clock: %d %+v", older.StatusCode, failure)
	}
	// ... and a restriction is enforced with the clock unset too.
	n.mustPush(token, core, n.policy(core, 6, proto.TrustRestricted, allActions...))
	if code := send("unset-clock-2"); code != http.StatusForbidden {
		t.Fatalf("a denied send with an unset clock: %d", code)
	}
	if status := n.status(token); status.Freshness != proto.TrustFresh || status.Stale || !status.Enforcing {
		t.Fatalf("status: %+v", status)
	}
}

// gatePolicy is the policy the device holds, as stored.
func (n *trustNode) gatePolicy(t *testing.T) proto.TrustPolicy {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(n.dir, trust.FileName))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := proto.DecodeSignedTrustPolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	return signed.TrustPolicy
}

func TestMonitorPolicyOverHTTPRefusesNothing(t *testing.T) {
	n := newTrustNode(t, true)
	core := newCore(t, "core-trust")
	token := n.pair(core)
	policy := n.policy(core, 1, proto.TrustObservation, proto.TrustActionDial, proto.TrustActionSendSMS, proto.TrustActionDTMF)
	policy.Mode = proto.TrustMonitor
	n.mustPush(token, core, policy)
	response := n.auth(token, "POST", "/v1/sms/send", proto.SendSMSRequest{RequestID: "mon-1", To: "10010", Text: "hello"})
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("monitor mode must not refuse: %d", response.StatusCode)
	}
	status := n.status(token)
	if status.Enforcing || status.Mode != proto.TrustMonitor || status.WouldRefuse[proto.TrustActionSendSMS] != 1 {
		t.Fatalf("monitor status: %+v", status)
	}
}

// An agent without the gate is an agent that predates it: the endpoints are
// not there, and dial and send behave as they always have.
func TestWithoutAGateTheEndpointsAre404AndNothingIsGated(t *testing.T) {
	n := newTrustNode(t, false)
	core := newCore(t, "core-trust")
	token := n.pair(core)
	for _, request := range []struct{ method, path string }{{"GET", proto.TrustStatusPath}, {"POST", proto.TrustPolicyPath}} {
		response := n.auth(token, request.method, request.path, map[string]string{})
		failure := errorBodyOf(t, response)
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound || failure.Code != proto.ErrorNotFound || failure.Operation != "route" {
			t.Fatalf("%s %s on an agent without enforcement: %d %+v", request.method, request.path, response.StatusCode, failure)
		}
	}
	response := n.auth(token, "POST", "/v1/sms/send", proto.SendSMSRequest{RequestID: "old-1", To: "10010", Text: "hello"})
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("send without a gate: %d", response.StatusCode)
	}
}

// With a gate and no policy, dial and send answer byte for byte as an agent
// without the gate does. Both nodes run the same scenario and the same
// request, so the bodies are comparable once the per-run values are masked.
func TestNoPolicyIsByteForByteTheOldBehaviour(t *testing.T) {
	volatile := regexp.MustCompile(`"(timestamp|observed_at|started_at|updated_at|created_at)":"[^"]*"`)
	run := func(withGate bool) []string {
		n := newTrustNode(t, withGate)
		token := n.pair(newCore(t, "core-trust"))
		var out []string
		for _, request := range []struct {
			path string
			body []byte
		}{
			{"/v1/sms/send", []byte(`{"request_id":"compat-1","to":"10010","text":"hello"}`)},
			{"/v1/sms/send", []byte(`{"request_id":"compat-1","to":"10010","text":"hello"}`)}, // repeat: de-duplicated
			{"/v1/sms/send", []byte(`{"request_id":"","to":"10010","text":"hello"}`)},
			{"/v1/sms/send", []byte(`{not json`)},
			{"/v1/sms/send", []byte(`{"request_id":"compat-2","to":"10010","text":"hello","extra":1}`)},
			{"/v1/calls/dial", []byte(`{"request_id":"compat-3","to":"10010"}`)},
			{"/v1/calls/dial", []byte(`{"request_id":"compat-3","to":"10010"}`)},
			{"/v1/calls/dial", []byte(`{"request_id":"compat-4","to":""}`)},
			{"/v1/calls/dial", []byte(`[]`)},
		} {
			response := n.request("POST", request.path, "x", map[string]string{"Authorization": "Bearer " + token}, request.body)
			body, _ := stdio.ReadAll(response.Body)
			response.Body.Close()
			out = append(out, response.Status+" "+response.Header.Get("Content-Type")+" "+volatile.ReplaceAllString(string(body), `"$1":"-"`))
		}
		return out
	}
	without, with := run(false), run(true)
	for index := range without {
		if without[index] != with[index] {
			t.Errorf("request %d differs:\n without gate: %s\n with gate:    %s", index, without[index], with[index])
		}
	}
}

// The gate cannot be skipped by route aliasing. Every registered route and
// method is called with every candidate body; the routes that reach a dial or
// send backend method are found by observation, not by a list someone has to
// keep up to date, and under a policy that denies everything none of them
// reaches the backend.
func TestEveryRouteThatReachesDialOrSendGoesThroughTheGate(t *testing.T) {
	bodies := [][]byte{
		nil,
		[]byte(`{"request_id":"route-table-1","to":"10010","text":"hello"}`),
		[]byte(`{"request_id":"route-table-2","to":"10010"}`),
		[]byte(`{}`),
	}
	type attempt struct {
		route httpapi.Route
		body  int
	}
	// walk calls every route with every body and reports which attempts were
	// followed by a dial or a send.
	walk := func(n *trustNode, token string) (reached map[attempt]bool, statuses map[attempt]int) {
		reached, statuses = map[attempt]bool{}, map[attempt]int{}
		for _, route := range n.routes {
			method, path, ok := strings.Cut(route.Pattern, " ")
			if !ok {
				t.Fatalf("route %q has no method; a method-less route would answer every method", route.Pattern)
			}
			// Streaming and upload routes cannot dial or send and would block.
			if path == "/v1/events" || strings.HasSuffix(path, "/media") || path == proto.OTAArtifactPath {
				continue
			}
			path = regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(path, "x")
			for index, body := range bodies {
				before := n.backend.outgoing()
				var status int
				if route.Local {
					// The standalone console authenticates these itself and
					// then calls the handler directly.
					request := httptest.NewRequest(method, path, bytes.NewReader(body))
					if body != nil {
						request.Header.Set("Content-Type", "application/json")
					}
					recorder := httptest.NewRecorder()
					n.local.ServeHTTP(recorder, request)
					status = recorder.Code
				} else {
					var marker any
					if body != nil {
						marker = "x"
					}
					headers := map[string]string{"Authorization": "Bearer " + token}
					if method == "DELETE" && path == "/v1/pair" || path == "/v1/pair/factory-reset" || path == "/v1/pair" || path == "/v1/session" {
						// Pairing routes would end the session the walk needs;
						// they are signed or destructive and reach no backend.
						continue
					}
					response := n.request(method, path, marker, headers, body)
					response.Body.Close()
					status = response.StatusCode
				}
				key := attempt{route, index}
				statuses[key] = status
				if n.backend.outgoing() != before {
					reached[key] = true
				}
			}
		}
		return reached, statuses
	}

	// Pass 1: no policy. Find what reaches the backend.
	open := newTrustNode(t, true)
	reached, _ := walk(open, open.pair(newCore(t, "core-trust")))
	reachingRoutes := map[string]bool{}
	for key := range reached {
		reachingRoutes[key.route.Pattern+map[bool]string{true: " (local)", false: ""}[key.route.Local]] = true
	}
	for _, want := range []string{"POST /v1/sms/send", "POST /v1/calls/dial", "POST /v1/sms/send (local)", "POST /v1/calls/{id}/dtmf"} {
		if !reachingRoutes[want] {
			t.Fatalf("the walk did not exercise %s; it proves nothing. reached: %v", want, reachingRoutes)
		}
	}
	if len(reachingRoutes) != 4 {
		// A new route that dials or sends appears here. That is allowed - the
		// second pass decides whether it is gated - but the count is pinned so
		// that adding one is a conscious act.
		t.Fatalf("routes reaching dial or send changed: %v", reachingRoutes)
	}

	// Pass 2: a policy that denies everything.
	closed := newTrustNode(t, true)
	core := newCore(t, "core-trust")
	token := closed.pair(core)
	closed.mustPush(token, core, closed.policy(core, 1, proto.TrustQuarantine, allActions...))
	stillReached, statuses := walk(closed, token)
	for key := range stillReached {
		t.Errorf("%s (local=%v) reached a dial or send under a deny-everything policy", key.route.Pattern, key.route.Local)
	}
	if closed.backend.outgoing() != 0 {
		t.Fatalf("the backend was asked for outgoing use %d times under a deny-everything policy", closed.backend.outgoing())
	}
	for key := range reached {
		if statuses[key] != http.StatusForbidden {
			t.Errorf("%s (local=%v): want 403 from the gate, got %d", key.route.Pattern, key.route.Local, statuses[key])
		}
	}
	// The console is handed no route that installs or reads the policy
	// through the Core protocol.
	for _, route := range closed.routes {
		if route.Local && strings.Contains(route.Pattern, "/v1/trust") {
			t.Errorf("the standalone console must not be given %s", route.Pattern)
		}
	}
}

func TestTrustStatusCarriesTheHardwareIdentityAsRead(t *testing.T) {
	n := newTrustNode(t, true)
	token := n.pair(newCore(t, "core-trust"))
	n.hardware = proto.HardwareIdentity{Present: true, Source: proto.HardwareSourceSocinfo, SerialSHA256: strings.Repeat("ab", 32), SocID: "206"}
	response := n.auth(token, "GET", proto.TrustStatusPath, nil)
	raw, _ := stdio.ReadAll(response.Body)
	response.Body.Close()
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	hardware, _ := document["hardware"].(map[string]any)
	if hardware["present"] != true || hardware["source"] != "qcom-socinfo" || hardware["serial_sha256"] != strings.Repeat("ab", 32) || hardware["soc_id"] != "206" {
		t.Fatalf("hardware: %s", raw)
	}
	for _, field := range []string{"supported", "installed", "generation", "deny", "stale", "enforcing", "damaged", "hardware"} {
		if _, present := document[field]; !present {
			t.Errorf("GET /v1/trust lacks %q: %s", field, raw)
		}
	}
	n.hardware = proto.HardwareIdentity{Present: false, Reason: "the SoC serial number is all zeros"}
	if status := n.status(token); status.Hardware.Present || status.Hardware.Reason == "" || status.Hardware.SerialSHA256 != "" {
		t.Fatalf("absent hardware: %+v", status.Hardware)
	}
}

func TestConcurrentPolicyPushesOverHTTP(t *testing.T) {
	n := newTrustNode(t, true)
	core := newCore(t, "core-trust")
	token := n.pair(core)
	const pushes = 24
	var group sync.WaitGroup
	for generation := 1; generation <= pushes; generation++ {
		signed := signPolicy(t, core.private, n.policy(core, uint64(generation), proto.TrustObservation, proto.TrustActionSendSMS))
		group.Add(1)
		go func() {
			defer group.Done()
			response := n.push(token, signed)
			response.Body.Close()
			if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusConflict {
				t.Errorf("push: %d", response.StatusCode)
			}
		}()
	}
	for range 4 {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range 20 {
				response := n.auth(token, "POST", "/v1/sms/send", proto.SendSMSRequest{RequestID: "race", To: "10010", Text: "x"})
				response.Body.Close()
				_ = index
			}
		}()
	}
	group.Wait()
	if status := n.status(token); status.Generation != pushes {
		t.Fatalf("the highest generation wins: %+v", status)
	}
}
