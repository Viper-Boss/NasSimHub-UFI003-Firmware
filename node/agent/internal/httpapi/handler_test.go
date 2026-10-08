package httpapi_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/internal/httpapi"
	"github.com/human-agent65535/nassimhub-node/agent/internal/identity"
	"github.com/human-agent65535/nassimhub-node/agent/internal/logbuf"
	"github.com/human-agent65535/nassimhub-node/agent/internal/pairing"
	"github.com/human-agent65535/nassimhub-node/agent/modembackend/mock"
	"github.com/human-agent65535/nassimhub-node/agent/modembackend/msm8916"
	netmock "github.com/human-agent65535/nassimhub-node/agent/netbackend/mock"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type node struct {
	t        *testing.T
	server   *httptest.Server
	identity *identity.Identity
	pairs    *pairing.Store
	modem    *mock.Backend
	wifi     *netmock.Backend
	logs     *logbuf.Buffer
}

type coreKey struct {
	id      string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
	counter int
}

func newCore(t *testing.T, id string) *coreKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return &coreKey{id: id, public: public, private: private}
}

func newNode(t *testing.T, scenario mock.Scenario) *node {
	t.Helper()
	dir := t.TempDir()
	loaded, err := identity.LoadOrCreate(identity.Options{Dir: dir, Platform: proto.PlatformMock, Model: "mock"})
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	store, err := pairing.Open(pairing.Options{Dir: dir, DeviceID: loaded.DeviceID})
	if err != nil {
		t.Fatalf("pairing: %v", err)
	}
	modem := mock.New(mock.Options{Scenario: scenario, DeviceID: loaded.DeviceID})
	wifi := netmock.New(netmock.Options{DeviceID: loaded.DeviceID})
	logs := logbuf.New(logbuf.Options{Capacity: 200})

	handler := httpapi.New(httpapi.Options{
		Identity: loaded, Pairing: store, Modem: modem, Network: wifi,
		Logs: logs, AgentVersion: "test", BuildDate: "2026-09-13",
	})
	server := httptest.NewServer(handler)
	t.Cleanup(func() {
		server.Close()
		_ = modem.Close()
		_ = wifi.Close()
		_ = logs.Close()
	})
	return &node{t: t, server: server, identity: loaded, pairs: store, modem: modem, wifi: wifi, logs: logs}
}

// do issues an unauthenticated request.
func (n *node) do(method, path string, body any) *http.Response {
	n.t.Helper()
	return n.request(method, path, body, nil, nil)
}

// auth issues a bearer-authenticated request.
func (n *node) auth(token, method, path string, body any) *http.Response {
	n.t.Helper()
	return n.request(method, path, body, map[string]string{"Authorization": "Bearer " + token}, nil)
}

// signed issues a request signed with a Core key.
func (n *node) signed(core *coreKey, method, path string, body any) *http.Response {
	n.t.Helper()
	encoded := encodeBody(n.t, body)
	core.counter++
	stamp := proto.FormatTimestamp(time.Now())
	nonce := fmt.Sprintf("%s-%d", core.id, core.counter)
	signature := ed25519.Sign(core.private, proto.SigningString(method, path, stamp, nonce, encoded))
	headers := map[string]string{
		proto.HeaderCoreID:    core.id,
		proto.HeaderTimestamp: stamp,
		proto.HeaderNonce:     nonce,
		proto.HeaderSignature: base64.StdEncoding.EncodeToString(signature),
	}
	return n.request(method, path, body, headers, encoded)
}

func (n *node) request(method, path string, body any, headers map[string]string, raw []byte) *http.Response {
	n.t.Helper()
	if raw == nil {
		raw = encodeBody(n.t, body)
	}
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequest(method, n.server.URL+path, reader)
	if err != nil {
		n.t.Fatalf("build request: %v", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := n.server.Client().Do(request)
	if err != nil {
		n.t.Fatalf("%s %s: %v", method, path, err)
	}
	return response
}

func encodeBody(t *testing.T, body any) []byte {
	t.Helper()
	if body == nil {
		return []byte{}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}
	return encoded
}

// pair runs the pairing handshake and returns the session token.
func (n *node) pair(core *coreKey) string {
	n.t.Helper()
	response := n.signed(core, "POST", "/v1/pair", proto.PairRequest{
		CoreID: core.id, CoreName: "test-nas", CorePublicKey: proto.EncodeKey(core.public),
	})
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		n.t.Fatalf("pair returned %d", response.StatusCode)
	}
	var decoded proto.PairResponse
	decode(n.t, response, &decoded)
	return decoded.Session.Token
}

func decode(t *testing.T, response *http.Response, destination any) {
	t.Helper()
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func errorBodyOf(t *testing.T, response *http.Response) proto.APIError {
	t.Helper()
	var body proto.ErrorBody
	decode(t, response, &body)
	return body.Error
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

func TestDiscoveryIsUnauthenticatedAndCarriesNoSubscriberData(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)

	response := n.do("GET", "/v1/node", nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("discovery returned %d", response.StatusCode)
	}

	raw := new(strings.Builder)
	var document proto.Node
	if err := json.NewDecoder(io(response, raw)).Decode(&document); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if document.DeviceID != n.identity.DeviceID {
		t.Fatalf("discovery reports %q", document.DeviceID)
	}
	if document.PairingState != proto.PairingUnpaired {
		t.Fatalf("a fresh node reports %s", document.PairingState)
	}
	if document.Protocol != proto.ProtocolVersion {
		t.Fatalf("protocol is %q", document.Protocol)
	}
	// The discovery document must be safe to serve to anyone on the LAN.
	body := raw.String()
	for _, secret := range []string{mock.ChinaMobile.ICCID, mock.ChinaMobile.IMSI, mock.ChinaMobile.PhoneNumber} {
		if strings.Contains(body, secret) {
			t.Fatalf("discovery leaked %q", secret)
		}
	}
}

// io tees the response body so a test can both decode and inspect it.
func io(response *http.Response, sink *strings.Builder) *strings.Reader {
	buffer := new(bytes.Buffer)
	_, _ = buffer.ReadFrom(response.Body)
	sink.WriteString(buffer.String())
	return strings.NewReader(buffer.String())
}

func TestDeviceIDIsVerifiableFromDiscovery(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	response := n.do("GET", "/v1/node", nil)
	defer response.Body.Close()
	var document proto.Node
	decode(t, response, &document)

	key, err := proto.DecodePublicKey(document.PublicKey)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	if !proto.ValidateDeviceID(document.DeviceID, document.Platform, key) {
		t.Fatal("the advertised device id does not derive from the advertised key")
	}
}

func TestHealthReportsDegradedWhenModemIsDown(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	n.modem.SetModemState(proto.ModemOffline)

	response := n.do("GET", "/v1/health", nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health returned %d; it must stay answerable", response.StatusCode)
	}
	var health proto.Health
	decode(t, response, &health)
	if health.Status != proto.HealthDegraded {
		t.Fatalf("health status is %q", health.Status)
	}
	if health.ModemState != string(proto.ModemOffline) {
		t.Fatalf("modem state is %q", health.ModemState)
	}
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

func TestPairingLifecycle(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	core := newCore(t, "core-a")

	token := n.pair(core)
	if token == "" {
		t.Fatal("pairing returned no session")
	}

	response := n.auth(token, "GET", "/v1/sim", nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authenticated read returned %d", response.StatusCode)
	}
}

func TestSecondCoreCannotAdoptAPairedNode(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	owner := newCore(t, "core-a")
	intruder := newCore(t, "core-b")
	n.pair(owner)

	response := n.signed(intruder, "POST", "/v1/pair", proto.PairRequest{
		CoreID: intruder.id, CoreName: "other-nas", CorePublicKey: proto.EncodeKey(intruder.public),
	})
	defer response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("a second core got %d, want 409", response.StatusCode)
	}
	if code := errorBodyOf(t, response).Code; code != proto.ErrorConflict {
		t.Fatalf("error code is %s", code)
	}
}

func TestUnsignedPairRequestIsRejected(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	core := newCore(t, "core-a")

	response := n.do("POST", "/v1/pair", proto.PairRequest{
		CoreID: core.id, CorePublicKey: proto.EncodeKey(core.public),
	})
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unsigned pair request got %d", response.StatusCode)
	}
}

func TestUnpairAndReadopt(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	owner := newCore(t, "core-a")
	token := n.pair(owner)

	response := n.auth(token, "DELETE", "/v1/pair", nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unpair returned %d", response.StatusCode)
	}

	// The old token must be dead immediately.
	after := n.auth(token, "GET", "/v1/sim", nil)
	defer after.Body.Close()
	if after.StatusCode == http.StatusOK {
		t.Fatal("a revoked token still works")
	}

	// A different NAS may now adopt the Node.
	other := newCore(t, "core-b")
	if newToken := n.pair(other); newToken == "" {
		t.Fatal("re-adoption failed")
	}
}

func TestFactoryResetKeepsDeviceIdentity(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	core := newCore(t, "core-a")
	token := n.pair(core)
	before := n.identity.DeviceID

	wrong := n.auth(token, "POST", "/v1/pair/factory-reset", proto.FactoryResetRequest{Confirm: "NSH-MOCK-WRONG"})
	wrong.Body.Close()
	if wrong.StatusCode != http.StatusBadRequest {
		t.Fatalf("a mistyped confirmation returned %d", wrong.StatusCode)
	}

	right := n.auth(token, "POST", "/v1/pair/factory-reset", proto.FactoryResetRequest{Confirm: before})
	defer right.Body.Close()
	if right.StatusCode != http.StatusOK {
		t.Fatalf("factory reset returned %d", right.StatusCode)
	}

	// The identity must be untouched, so the NAS sees the same device rather
	// than a new one after a reset.
	document := n.do("GET", "/v1/node", nil)
	defer document.Body.Close()
	var node proto.Node
	decode(t, document, &node)
	if node.DeviceID != before {
		t.Fatalf("factory reset changed the device id from %q to %q", before, node.DeviceID)
	}
	if node.PairingState != proto.PairingUnpaired {
		t.Fatalf("state after reset is %s", node.PairingState)
	}
}

// ---------------------------------------------------------------------------
// The guarantees
// ---------------------------------------------------------------------------

func TestUnpairedNodeCannotSendSMS(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)

	// No credential at all.
	anonymous := n.do("POST", "/v1/sms/send", proto.SendSMSRequest{RequestID: "r1", To: "+8610000000001", Text: "hi"})
	defer anonymous.Body.Close()
	if anonymous.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an anonymous send returned %d, want 401", anonymous.StatusCode)
	}

	// A plausible-looking but unissued token.
	invented := n.auth("not-a-real-token", "POST", "/v1/sms/send", proto.SendSMSRequest{RequestID: "r2", To: "+8610000000001", Text: "hi"})
	defer invented.Body.Close()
	if invented.StatusCode != http.StatusForbidden && invented.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an invented token returned %d", invented.StatusCode)
	}

	// Nothing was sent.
	core := newCore(t, "core-a")
	token := n.pair(core)
	listed := n.auth(token, "GET", "/v1/sms", nil)
	defer listed.Body.Close()
	var messages proto.SMSList
	decode(t, listed, &messages)
	if len(messages.Messages) != 0 {
		t.Fatalf("an unauthenticated request managed to send %d messages", len(messages.Messages))
	}
}

func TestEveryPrivilegedEndpointRequiresAuthentication(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	cases := []struct {
		method string
		path   string
		body   any
	}{
		{"GET", "/v1/capabilities", nil},
		{"GET", "/v1/sim", nil},
		{"GET", "/v1/network", nil},
		{"GET", "/v1/signal", nil},
		{"GET", "/v1/sms", nil},
		{"POST", "/v1/sms/send", proto.SendSMSRequest{RequestID: "r", To: "1", Text: "x"}},
		{"DELETE", "/v1/sms/abc", nil},
		{"GET", "/v1/calls", nil},
		{"POST", "/v1/calls/dial", proto.DialRequest{RequestID: "r", To: "1"}},
		{"POST", "/v1/calls/abc/answer", nil},
		{"POST", "/v1/calls/abc/hangup", nil},
		{"POST", "/v1/calls/mm-7/dtmf", proto.DTMFRequest{RequestID: "auth-dtmf", Digits: "1"}},
		{"GET", "/v1/calls/abc/media", nil},
		{"GET", "/v1/wifi", nil},
		{"POST", "/v1/wifi/scan", nil},
		{"POST", "/v1/wifi/connect", proto.WiFiConnectRequest{SSID: "x", PSK: "y"}},
		{"POST", "/v1/wifi/forget", nil},
		{"GET", "/v1/logs", nil},
		{"GET", "/v1/events", nil},
		{"DELETE", "/v1/pair", nil},
	}
	for _, c := range cases {
		response := n.do(c.method, c.path, c.body)
		status := response.StatusCode
		response.Body.Close()
		if status != http.StatusUnauthorized && status != http.StatusForbidden {
			t.Fatalf("%s %s is reachable without authentication (%d)", c.method, c.path, status)
		}
	}
}

func TestDialIsRefusedWhenVoiceCapabilityIsFalse(t *testing.T) {
	n := newNode(t, mock.ChinaUnicom) // no voice control
	core := newCore(t, "core-a")
	token := n.pair(core)

	capabilities := n.auth(token, "GET", "/v1/capabilities", nil)
	defer capabilities.Body.Close()
	var advertised struct {
		proto.Capabilities
		Voice *struct {
			Control bool           `json:"control"`
			Audio   bool           `json:"audio"`
			VoLTE   proto.Tristate `json:"volte"`
		} `json:"voice"`
	}
	decode(t, capabilities, &advertised)
	if advertised.VoiceControl {
		t.Fatal("a voiceless node advertised voice control")
	}
	if advertised.Voice == nil || advertised.Voice.Control {
		t.Fatalf("voice detail is %+v", advertised.Voice)
	}

	response := n.auth(token, "POST", "/v1/calls/dial", proto.DialRequest{RequestID: "d1", To: "+8610000000010"})
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotImplemented {
		t.Fatalf("dial on a voiceless node returned %d, want 501", response.StatusCode)
	}
	if code := errorBodyOf(t, response).Code; code != proto.ErrorNotSupported {
		t.Fatalf("error code is %s", code)
	}
}

func TestModemOfflineReturnsServiceUnavailableNotInternalError(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	core := newCore(t, "core-a")
	token := n.pair(core)
	n.modem.SetModemState(proto.ModemOffline)

	for _, c := range []struct {
		method string
		path   string
		body   any
	}{
		{"GET", "/v1/sms", nil},
		{"GET", "/v1/calls", nil},
		{"POST", "/v1/sms/send", proto.SendSMSRequest{RequestID: "r1", To: "+8610000000001", Text: "x"}},
		{"POST", "/v1/calls/dial", proto.DialRequest{RequestID: "d1", To: "+8610000000001"}},
	} {
		response := n.auth(token, c.method, c.path, c.body)
		status := response.StatusCode
		body := errorBodyOf(t, response)
		response.Body.Close()
		if status != http.StatusServiceUnavailable {
			t.Fatalf("%s %s returned %d while the modem is offline, want 503", c.method, c.path, status)
		}
		if body.Code != proto.ErrorUnavailable {
			t.Fatalf("%s %s reported %s", c.method, c.path, body.Code)
		}
	}

	// Status endpoints must keep answering so the NAS can explain the outage.
	status := n.auth(token, "GET", "/v1/status", nil)
	defer status.Body.Close()
	if status.StatusCode != http.StatusOK {
		t.Fatalf("status returned %d while the modem is offline", status.StatusCode)
	}
	var modem proto.ModemStatus
	decode(t, status, &modem)
	if modem.State != proto.ModemOffline || modem.Reason == "" {
		t.Fatalf("status is %+v", modem)
	}
}

func TestMessagesAreAttributedToNodeAndCard(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	core := newCore(t, "core-a")
	token := n.pair(core)

	if _, err := n.modem.InjectIncomingSMS("10086", "hello"); err != nil {
		t.Fatalf("inject: %v", err)
	}
	response := n.auth(token, "GET", "/v1/sms", nil)
	defer response.Body.Close()
	var listed proto.SMSList
	decode(t, response, &listed)
	if len(listed.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(listed.Messages))
	}
	message := listed.Messages[0]
	if message.NodeID != n.identity.DeviceID {
		t.Fatalf("message node id is %q", message.NodeID)
	}
	if message.SIMID != mock.ChinaMobile.ICCID {
		t.Fatalf("message sim id is %q", message.SIMID)
	}
}

func TestTwoNodesReceivingAtOnceDoNotCrossCards(t *testing.T) {
	first := newNode(t, mock.ChinaMobile)
	second := newNode(t, mock.ChinaUnicom)
	coreA := newCore(t, "core-a")
	coreB := newCore(t, "core-b")
	tokenA := first.pair(coreA)
	tokenB := second.pair(coreB)

	if first.identity.DeviceID == second.identity.DeviceID {
		t.Fatal("two nodes generated the same device id")
	}

	// Deliver to both at the same moment.
	done := make(chan error, 2)
	go func() { _, err := first.modem.InjectIncomingSMS("10086", "from mobile"); done <- err }()
	go func() { _, err := second.modem.InjectIncomingSMS("10010", "from unicom"); done <- err }()
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("inject: %v", err)
		}
	}

	listA := readMessages(t, first, tokenA)
	listB := readMessages(t, second, tokenB)
	if len(listA) != 1 || len(listB) != 1 {
		t.Fatalf("message counts are %d and %d", len(listA), len(listB))
	}
	if listA[0].NodeID == listB[0].NodeID {
		t.Fatal("messages from two nodes share a node id")
	}
	if listA[0].SIMID == listB[0].SIMID {
		t.Fatal("messages from two nodes share a sim id")
	}
	if listA[0].SIMID != mock.ChinaMobile.ICCID || listB[0].SIMID != mock.ChinaUnicom.ICCID {
		t.Fatalf("cards were crossed: %q and %q", listA[0].SIMID, listB[0].SIMID)
	}
}

func readMessages(t *testing.T, n *node, token string) []proto.SMS {
	t.Helper()
	response := n.auth(token, "GET", "/v1/sms", nil)
	defer response.Body.Close()
	var listed proto.SMSList
	decode(t, response, &listed)
	return listed.Messages
}

// ---------------------------------------------------------------------------
// Wi-Fi, logs, msm8916 wiring
// ---------------------------------------------------------------------------

func TestWiFiProvisioningThroughTheAPI(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	core := newCore(t, "core-a")
	token := n.pair(core)

	status := n.auth(token, "GET", "/v1/wifi", nil)
	defer status.Body.Close()
	var wifi proto.WiFiStatus
	decode(t, status, &wifi)
	if wifi.State != proto.WiFiProvisioningAP {
		t.Fatalf("a fresh node is in %s", wifi.State)
	}

	scan := n.auth(token, "POST", "/v1/wifi/scan", nil)
	defer scan.Body.Close()
	var result proto.WiFiScanResult
	decode(t, scan, &result)
	if len(result.Networks) == 0 {
		t.Fatal("scan returned nothing")
	}

	connect := n.auth(token, "POST", "/v1/wifi/connect", proto.WiFiConnectRequest{SSID: "HomeNet", PSK: "secret-value"})
	defer connect.Body.Close()
	if connect.StatusCode != http.StatusAccepted {
		t.Fatalf("connect returned %d", connect.StatusCode)
	}
}

func TestWiFiPasswordNeverAppearsInLogs(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	core := newCore(t, "core-a")
	token := n.pair(core)

	const secret = "SuperSecretWifiPassword"
	connect := n.auth(token, "POST", "/v1/wifi/connect", proto.WiFiConnectRequest{SSID: "HomeNet", PSK: secret})
	connect.Body.Close()

	response := n.auth(token, "GET", "/v1/logs", nil)
	defer response.Body.Close()
	var page proto.LogPage
	raw := new(strings.Builder)
	if err := json.NewDecoder(io(response, raw)).Decode(&page); err != nil {
		t.Fatalf("decode logs: %v", err)
	}
	if strings.Contains(raw.String(), secret) {
		t.Fatal("the log endpoint served a Wi-Fi password")
	}
}

func TestSMSBodyAndNumberNeverAppearInLogs(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	core := newCore(t, "core-a")
	token := n.pair(core)

	const code = "482913"
	const recipient = "+8610000000012"
	send := n.auth(token, "POST", "/v1/sms/send", proto.SendSMSRequest{
		RequestID: "r1", To: recipient, Text: "your verification code is " + code,
	})
	send.Body.Close()

	response := n.auth(token, "GET", "/v1/logs", nil)
	defer response.Body.Close()
	raw := new(strings.Builder)
	var page proto.LogPage
	if err := json.NewDecoder(io(response, raw)).Decode(&page); err != nil {
		t.Fatalf("decode logs: %v", err)
	}
	body := raw.String()
	if strings.Contains(body, code) {
		t.Fatal("the log endpoint served a verification code")
	}
	if strings.Contains(body, recipient) {
		t.Fatal("the log endpoint served a recipient number")
	}
}

func TestLogsValidateQueryParameters(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	core := newCore(t, "core-a")
	token := n.pair(core)

	bad := n.auth(token, "GET", "/v1/logs?limit=-5", nil)
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("a negative limit returned %d", bad.StatusCode)
	}
	level := n.auth(token, "GET", "/v1/logs?level=shout", nil)
	level.Body.Close()
	if level.StatusCode != http.StatusBadRequest {
		t.Fatalf("an unknown level returned %d", level.StatusCode)
	}
}

func TestUnknownRouteIsACodedNotFound(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	response := n.do("GET", "/v1/nonexistent", nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown route returned %d", response.StatusCode)
	}
	if code := errorBodyOf(t, response).Code; code != proto.ErrorNotFound {
		t.Fatalf("error code is %s", code)
	}
}

func TestMSM8916StubServesTheSameProtocol(t *testing.T) {
	// The stub must be a drop-in: the same routes, the same auth, the same
	// error shapes. Only the answers differ.
	dir := t.TempDir()
	loaded, err := identity.LoadOrCreate(identity.Options{Dir: dir, Platform: proto.PlatformMSM8916, Model: "UFI003"})
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	store, err := pairing.Open(pairing.Options{Dir: dir, DeviceID: loaded.DeviceID})
	if err != nil {
		t.Fatalf("pairing: %v", err)
	}
	logs := logbuf.New(logbuf.Options{Capacity: 50})
	defer logs.Close()
	handler := httpapi.New(httpapi.Options{
		Identity: loaded, Pairing: store,
		Modem:   msm8916.New(msm8916.Options{}),
		Network: netmock.New(netmock.Options{DeviceID: loaded.DeviceID}),
		Logs:    logs, AgentVersion: "test",
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	n := &node{t: t, server: server, identity: loaded, pairs: store, logs: logs}

	document := n.do("GET", "/v1/node", nil)
	defer document.Body.Close()
	var advertised proto.Node
	decode(t, document, &advertised)
	if !strings.HasPrefix(advertised.DeviceID, "NSH-410-") {
		t.Fatalf("msm8916 node id is %q", advertised.DeviceID)
	}

	core := newCore(t, "core-a")
	token := n.pair(core)

	capabilities := n.auth(token, "GET", "/v1/capabilities", nil)
	defer capabilities.Body.Close()
	var shape proto.Capabilities
	decode(t, capabilities, &shape)
	if shape.SMS || shape.VoiceControl || shape.VoiceAudio || shape.MobileData {
		t.Fatalf("the stub advertises capability: %+v", shape)
	}
	if shape.VoLTE != proto.TriUnknown {
		t.Fatalf("stub VoLTE is %s", shape.VoLTE)
	}

	dial := n.auth(token, "POST", "/v1/calls/dial", proto.DialRequest{RequestID: "d1", To: "+8610000000001"})
	defer dial.Body.Close()
	if dial.StatusCode != http.StatusNotImplemented {
		t.Fatalf("stub dial returned %d, want 501", dial.StatusCode)
	}
}

func TestEventStreamDeliversChanges(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	core := newCore(t, "core-a")
	token := n.pair(core)

	request, err := http.NewRequest("GET", n.server.URL+"/v1/events", nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := n.server.Client().Do(request)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("events returned %d", response.StatusCode)
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = n.modem.InjectIncomingSMS("10086", "hello")
	}()

	buffer := make([]byte, 512)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		count, err := response.Body.Read(buffer)
		if err != nil {
			t.Fatalf("read stream: %v", err)
		}
		if count > 0 && strings.Contains(string(buffer[:count]), "sms") {
			return
		}
	}
	t.Fatal("no sms event arrived on the stream")
}
