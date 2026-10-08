package localadmin_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/internal/httpapi"
	"github.com/human-agent65535/nassimhub-node/agent/internal/pairing"
	"github.com/human-agent65535/nassimhub-node/agent/modembackend/mock"
	netmock "github.com/human-agent65535/nassimhub-node/agent/netbackend/mock"
	"github.com/human-agent65535/nassimhub-node/agent/nodeserver"
	"github.com/human-agent65535/nassimhub-node/agent/ota"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// console is a signed-in browser talking to the assembled agent. Everything
// here is simulated: a mock modem, a mock radio and an in-process handler.
type console struct {
	t      *testing.T
	node   *nodeserver.Server
	dir    string
	cookie *http.Cookie
	csrf   string
	// What the test typed, so a redaction test can look for it afterwards.
	password, proof string
}

func (c *console) do(method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, "https://device.test"+path, reader)
	r.TLS = &tls.ConnectionState{}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if method != "GET" {
		r.Header.Set("Origin", "https://device.test")
		r.Header.Set("X-CSRF-Token", c.csrf)
	}
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	w := httptest.NewRecorder()
	c.node.AdminHandler().ServeHTTP(w, r)
	return w
}

func openConsole(t *testing.T, change func(*nodeserver.Options)) *console {
	t.Helper()
	dir := t.TempDir()
	modem := mock.New(mock.Options{Scenario: mock.ChinaTelecom})
	options := nodeserver.Options{StateDir: dir, Platform: proto.PlatformMock, Model: "test", Modem: modem, EnableTLS: true, EnableLocalAdmin: true, AgentVersion: "0.0.0-test"}
	if change != nil {
		change(&options)
	}
	if options.Network == nil {
		options.Network = netmock.New(netmock.Options{})
	}
	node, err := nodeserver.New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Logs.Close(); _ = modem.Close() })
	proof, _ := os.ReadFile(filepath.Join(dir, "admin-bootstrap.txt"))
	c := &console{t: t, node: node, dir: dir, password: "Fake-Console-Passw0rd-r127", proof: strings.TrimSpace(string(proof))}
	c.csrf = ""
	w := c.do("POST", "/admin/login", map[string]string{"setup_code": c.proof, "password": c.password})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var login map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &login)
	c.cookie, c.csrf = w.Result().Cookies()[0], login["csrf"]
	return c
}

type outcome struct {
	Outcome       string
	Settled       bool
	TargetSSID    string `json:"target_ssid"`
	PreviousSSID  string `json:"previous_ssid"`
	State         string
	SSID          string
	SavedSSID     string `json:"saved_ssid"`
	APSSID        string `json:"ap_ssid"`
	FailureReason string `json:"failure_reason"`
}

func (c *console) outcome() outcome {
	c.t.Helper()
	var view outcome
	w := c.do("GET", "/admin/api/v1/wifi/change", nil)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
		c.t.Fatal(w.Code, w.Body.String())
	}
	return view
}

// A new network that does not come up must not cost the owner the device.
// This drives the real handlers and the mock radio's own state machine through
// the console's API, with the radio's clock injected.
func TestFailedWiFiChangeNeverReplacesTheSavedNetworkAndEndsReachable(t *testing.T) {
	for _, scenario := range []struct {
		name, saved string
	}{{"with a saved network", "FakeHome"}, {"with no saved network", ""}} {
		t.Run(scenario.name, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			radio := netmock.New(netmock.Options{SavedSSID: scenario.saved, Passwords: map[string]string{"FakeNew": "the-right-fake-pass"}, Now: func() time.Time { return now }})
			c := openConsole(t, func(o *nodeserver.Options) { o.Network = radio })

			// Refused by the console before the radio is touched.
			if w := c.do("POST", "/admin/api/v1/wifi/connect", proto.WiFiConnectRequest{SSID: "FakeNew", PSK: "short", Security: proto.WiFiSecurityWPA2}); w.Code != 400 {
				t.Fatal("an invalid passphrase reached the radio", w.Code)
			}
			if got := c.outcome(); got.Outcome != "none" {
				t.Fatal("a refused request was recorded as a change", got)
			}
			w := c.do("POST", "/admin/api/v1/wifi/connect", proto.WiFiConnectRequest{SSID: "FakeNew", PSK: "the-wrong-fake-pass", Security: proto.WiFiSecurityWPA2})
			if w.Code != 202 || strings.Contains(w.Body.String(), "the-wrong-fake-pass") {
				t.Fatal(w.Code, w.Body.String())
			}
			if got := c.outcome(); got.Outcome != "pending" || got.Settled || got.TargetSSID != "FakeNew" || got.PreviousSSID != scenario.saved {
				t.Fatalf("while joining: %+v", got)
			}
			// A second submission while one is in flight is refused, not queued.
			if w = c.do("POST", "/admin/api/v1/wifi/connect", proto.WiFiConnectRequest{SSID: "FakeNew", PSK: "the-right-fake-pass", Security: proto.WiFiSecurityWPA2}); w.Code != 409 {
				t.Fatal("double submit was accepted", w.Code)
			}
			now = now.Add(netmock.ConnectDelay)
			got := c.outcome()
			if got.Outcome != "failed" || got.Settled || got.FailureReason == "" {
				t.Fatalf("after the join failed: %+v", got)
			}
			if got.SavedSSID != scenario.saved {
				t.Fatalf("the failed network replaced the saved one: %+v", got)
			}
			now = now.Add(netmock.RecoveryWindow)
			got = c.outcome()
			// The mock backend's contract: back to the setup access point, with
			// the earlier network still stored. It does not rejoin it by itself.
			if got.Outcome != "provisioning_ap" || !got.Settled || got.APSSID == "" || got.SavedSSID != scenario.saved {
				t.Fatalf("after the recovery window: %+v", got)
			}
			var status proto.WiFiStatus
			_ = json.Unmarshal(c.do("GET", "/admin/api/v1/wifi", nil).Body.Bytes(), &status)
			if status.State != proto.WiFiProvisioningAP || status.SavedSSID != scenario.saved || status.SSID == "FakeNew" {
				t.Fatalf("radio state: %+v", status)
			}
			// And the right passphrase afterwards is reported as connected.
			if w = c.do("POST", "/admin/api/v1/wifi/connect", proto.WiFiConnectRequest{SSID: "FakeNew", PSK: "the-right-fake-pass", Security: proto.WiFiSecurityWPA2}); w.Code != 202 {
				t.Fatal(w.Code, w.Body.String())
			}
			now = now.Add(netmock.ConnectDelay)
			if got = c.outcome(); got.Outcome != "connected" || !got.Settled || got.SSID != "FakeNew" || got.SavedSSID != "FakeNew" {
				t.Fatalf("after a good join: %+v", got)
			}
			for _, w := range []*httptest.ResponseRecorder{c.do("GET", "/admin/api/v1/wifi/change", nil), c.do("GET", "/admin/api/v1/wifi", nil), c.do("GET", "/admin/api/v1/logs?limit=0", nil)} {
				if strings.Contains(w.Body.String(), "fake-pass") {
					t.Fatal("a passphrase was kept or logged")
				}
			}
		})
	}
}

func grouped(key []byte) string {
	digest := sha256.Sum256(key)
	encoded := strings.ToUpper(hex.EncodeToString(digest[:16]))
	var groups []string
	for i := 0; i < len(encoded); i += 4 {
		groups = append(groups, encoded[i:i+4])
	}
	return strings.Join(groups, " ")
}

type securityView struct {
	DeviceID            string                                                          `json:"device_id"`
	IdentityAlgorithm   string                                                          `json:"identity_algorithm"`
	IdentityFingerprint string                                                          `json:"identity_fingerprint"`
	SecurityLevel       string                                                          `json:"security_level"`
	PQIdentity          struct{ Status, Algorithm, Fingerprint, Detail, Policy string } `json:"pq_identity"`
	Owner               struct {
		Paired          string
		CoreID          string `json:"core_id"`
		CoreFingerprint string `json:"core_fingerprint"`
		PQPinned        string `json:"pq_pinned"`
		PQFingerprint   string `json:"pq_fingerprint"`
	}
	AdminTLS struct {
		FingerprintSHA256 string     `json:"fingerprint_sha256"`
		KeyAlgorithm      string     `json:"key_algorithm"`
		NotAfter          *time.Time `json:"not_after"`
	} `json:"admin_tls"`
}

func TestSecurityPageReportsRealStateAndNoKeyMaterial(t *testing.T) {
	c := openConsole(t, func(o *nodeserver.Options) { o.SecurityLevel = proto.LevelPQ })
	read := func() (securityView, string) {
		var view securityView
		w := c.do("GET", "/admin/api/v1/security", nil)
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		return view, w.Body.String()
	}
	view, body := read()
	if view.DeviceID != c.node.Identity.DeviceID || view.IdentityAlgorithm != "Ed25519" || view.IdentityFingerprint != grouped(c.node.Identity.PublicKey) {
		t.Fatalf("device identity: %+v", view)
	}
	if view.SecurityLevel != "PQ" {
		t.Fatal("security level", view.SecurityLevel)
	}
	if view.Owner.Paired != "no" || view.Owner.PQPinned != "no" || view.Owner.CoreID != "" {
		t.Fatalf("an unpaired device reported an owner: %+v", view.Owner)
	}
	// The post-quantum identity: whatever the store says, and nothing nicer.
	store := c.node.PQIdentity
	if view.PQIdentity.Status != string(store.Status()) {
		t.Fatalf("pq status %q, store says %q", view.PQIdentity.Status, store.Status())
	}
	if current := store.Identity(); current.Present() {
		raw, _ := base64.StdEncoding.DecodeString(current.PublicKey)
		if view.PQIdentity.Algorithm != string(current.Algorithm) || view.PQIdentity.Fingerprint != grouped(raw) {
			t.Fatalf("pq identity: %+v", view.PQIdentity)
		}
		if strings.Contains(body, current.PublicKey) {
			t.Fatal("the post-quantum public key itself was served; a fingerprint is enough")
		}
	} else if view.PQIdentity.Fingerprint != "" || view.PQIdentity.Algorithm != "" {
		t.Fatalf("a device with no post-quantum key reported one: %+v", view.PQIdentity)
	}
	// The certificate of this console.
	certificate, _ := os.ReadFile(filepath.Join(c.dir, "admin-tls-cert.pem"))
	block, _ := pem.Decode(certificate)
	digest := sha256.Sum256(block.Bytes)
	var want []string
	for _, b := range digest {
		want = append(want, fmt.Sprintf("%02X", b))
	}
	if view.AdminTLS.FingerprintSHA256 != strings.Join(want, ":") || view.AdminTLS.KeyAlgorithm != "ECDSA" {
		t.Fatalf("certificate: %+v", view.AdminTLS)
	}
	if view.AdminTLS.NotAfter == nil || time.Until(*view.AdminTLS.NotAfter) < 365*24*time.Hour {
		t.Fatal("certificate expiry", view.AdminTLS.NotAfter)
	}

	// Pair, and the owner appears as the device pinned it.
	public, private, _ := ed25519.GenerateKey(nil)
	request := proto.PairRequest{CoreID: "fake-core-1", CoreName: "test", CorePublicKey: proto.EncodeKey(public)}
	raw, _ := json.Marshal(request)
	stamp, nonce := proto.FormatTimestamp(time.Now()), "fake-nonce-security-page"
	signed := pairing.SignedRequest{CoreID: request.CoreID, Method: "POST", Path: "/v1/pair", Body: raw, Timestamp: stamp, Nonce: nonce,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, proto.SigningString("POST", "/v1/pair", stamp, nonce, raw)))}
	session, err := c.node.Pairing.Pair(request, signed)
	if err != nil {
		t.Fatal(err)
	}
	view, body = read()
	if view.Owner.Paired != "yes" || view.Owner.CoreID != "fake-core-1" || view.Owner.CoreFingerprint != proto.CoreFingerprint(public) {
		t.Fatalf("owner: %+v", view.Owner)
	}
	// This Core proved no post-quantum key, so none is pinned - and that is "no", not "unknown".
	if view.Owner.PQPinned != "no" || view.Owner.PQFingerprint != "" {
		t.Fatalf("owner post-quantum pin: %+v", view.Owner)
	}

	// Nothing that could be used as a key, and no bearer token, in either answer.
	secrets := map[string]string{"core public key": proto.EncodeKey(public), "device public key": proto.EncodeKey(c.node.Identity.PublicKey), "core session token": session.Token}
	for _, file := range []string{"device.json", "pq-identity.json", "pairing.json"} {
		var document map[string]any
		content, err := os.ReadFile(filepath.Join(c.dir, file))
		if err != nil {
			continue
		}
		_ = json.Unmarshal(content, &document)
		for key, value := range document {
			if text, ok := value.(string); ok && len(text) >= 32 && (strings.Contains(key, "seed") || strings.Contains(key, "key") || strings.Contains(key, "secret") || strings.Contains(key, "token") || key == "binding") {
				secrets[file+" "+key] = text
			}
		}
	}
	key, _ := os.ReadFile(filepath.Join(c.dir, "admin-tls-key.pem"))
	keyBlock, _ := pem.Decode(key)
	secrets["admin TLS private key"] = base64.StdEncoding.EncodeToString(keyBlock.Bytes)[:48]
	if len(secrets) < 6 {
		t.Fatal("the key files were not found; this test would prove nothing", len(secrets))
	}
	for name, secret := range secrets {
		if strings.Contains(body, secret) {
			t.Errorf("the security page serves the %s", name)
		}
	}
	if regexp.MustCompile(`[A-Za-z0-9+/_-]{44,}`).MatchString(body) {
		t.Error("the security page carries a long encoded value; fingerprints are short")
	}
	// It is behind the same session as everything else.
	c.cookie = nil
	if w := c.do("GET", "/admin/api/v1/security", nil); w.Code != 401 {
		t.Fatal("security page without a session", w.Code)
	}
}

// fakeOTA is an update service that records what it was asked to do.
type fakeOTA struct {
	status      proto.OTADeviceStatus
	rollbackErr error
	rollbacks   int
	other       int
}

func (f *fakeOTA) Status() proto.OTADeviceStatus { return f.status }
func (f *fakeOTA) Offer(context.Context, proto.OTASignedManifest) (proto.OTAOfferResponse, error) {
	f.other++
	return proto.OTAOfferResponse{}, nil
}
func (f *fakeOTA) Receive(context.Context, string, int64, io.Reader) (proto.OTADeviceStatus, error) {
	f.other++
	return f.status, nil
}
func (f *fakeOTA) Apply(context.Context, string) (proto.OTADeviceStatus, error) {
	f.other++
	return f.status, nil
}
func (f *fakeOTA) Confirm(string) (proto.OTADeviceStatus, error) {
	f.other++
	return f.status, nil
}
func (f *fakeOTA) Rollback(context.Context, string) (proto.OTADeviceStatus, error) {
	f.rollbacks++
	if f.rollbackErr != nil {
		return f.status, f.rollbackErr
	}
	f.status.State, f.status.RestartPending = proto.OTARolledBack, true
	return f.status, nil
}

var _ httpapi.Updates = (*fakeOTA)(nil)

func TestUpdatePageThroughTheAssembledAgent(t *testing.T) {
	// No update service: unsupported, said as such, with HTTP 200.
	bare := openConsole(t, nil)
	if w := bare.do("GET", "/admin/api/v1/update", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"available":false`) || !strings.Contains(w.Body.String(), "not supported in this build") {
		t.Fatal(w.Code, w.Body.String())
	}

	service := &fakeOTA{}
	service.status.State, service.status.ReleaseID, service.status.Supported = proto.OTAPendingConfirm, "fake-release-7", true
	service.status.CurrentVersion, service.status.FactoryVersion, service.status.ActiveRelease = "0.0.7-fake", "0.0.1-fake", "fake-release-7"
	service.status.Keys = proto.OTAKeyStatus{Classical: 1}
	c := openConsole(t, func(o *nodeserver.Options) { o.Updates = service })
	w := c.do("GET", "/admin/api/v1/update", nil)
	for _, want := range []string{`"available":true`, `"can_rollback":true`, `"release_id":"fake-release-7"`, `"factory_version":"0.0.1-fake"`, `"classical":1`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("missing %s in %s", want, w.Body.String())
		}
	}
	// The NAS-only operations have no route in the console, whatever the method.
	for _, path := range []string{"/admin/api/v1/ota/manifest", "/admin/api/v1/ota/artifact", "/admin/api/v1/ota/apply", "/admin/api/v1/ota/confirm", "/admin/api/v1/ota/rollback", "/admin/api/v1/ota/status",
		"/admin/api/v1/update/apply", "/admin/api/v1/update/confirm", "/admin/api/v1/update/manifest", "/admin/api/v1/update/artifact", "/admin/api/v1/pair/factory-reset", "/admin/api/v1/pair", "/admin/api/v1/transport/key", "/admin/api/v1/calls/dial"} {
		for _, method := range []string{"POST", "PUT", "DELETE"} {
			if w := c.do(method, path, proto.OTAReleaseRequest{ReleaseID: "fake-release-7"}); w.Code != 404 && w.Code != 405 {
				t.Errorf("%s %s answered %d", method, path, w.Code)
			}
		}
	}
	if service.other != 0 || service.rollbacks != 0 {
		t.Fatal("the console reached an update operation it must not have", service.other, service.rollbacks)
	}
	// The update service's own refusal arrives as a conflict, not a crash.
	service.rollbackErr = fmt.Errorf("%w: state changed", ota.ErrNotReady)
	if w = c.do("POST", "/admin/api/v1/update/rollback", proto.OTAReleaseRequest{ReleaseID: "fake-release-7"}); w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	service.rollbackErr, service.rollbacks = nil, 0
	if w = c.do("POST", "/admin/api/v1/update/rollback", proto.OTAReleaseRequest{ReleaseID: "fake-release-7"}); w.Code != 202 || service.rollbacks != 1 {
		t.Fatal(w.Code, service.rollbacks, w.Body.String())
	}
	// Once rolled back there is nothing left to roll back.
	if w = c.do("POST", "/admin/api/v1/update/rollback", proto.OTAReleaseRequest{ReleaseID: "fake-release-7"}); w.Code != 409 || service.rollbacks != 1 {
		t.Fatal("a second rollback went through", w.Code, service.rollbacks)
	}
	if logs := c.do("GET", "/admin/api/v1/logs?limit=0", nil).Body.String(); !strings.Contains(logs, "fake-release-7 rolled back from the local console") {
		t.Fatal("the rollback is not in the device log")
	}
}

// Every place a log line or a diagnostics bundle can be read from, as text.
func (c *console) everythingReadable(logDir string) map[string]string {
	c.t.Helper()
	out := map[string]string{}
	for name, path := range map[string]string{"logs": "/admin/api/v1/logs?limit=0", "debug logs": "/admin/api/v1/logs?limit=0&level=debug", "diagnostics": "/admin/api/v1/diagnostics"} {
		w := c.do("GET", path, nil)
		if w.Code != 200 {
			c.t.Fatal(name, w.Code)
		}
		out[name] = w.Body.String()
	}
	w := c.do("GET", "/admin/api/v1/diagnostics/archive", nil)
	if w.Code != 200 {
		c.t.Fatal("archive", w.Code)
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		c.t.Error("the diagnostics archive may be cached")
	}
	unzipped, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		c.t.Fatal(err)
	}
	archive := tar.NewReader(unzipped)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			c.t.Fatal(err)
		}
		content, _ := io.ReadAll(archive)
		out["archive "+header.Name] = header.Name + "\n" + string(content)
	}
	if len(out) < 5 {
		c.t.Fatal("the archive was empty", len(out))
	}
	files, _ := filepath.Glob(filepath.Join(logDir, "agent.log*"))
	if len(files) == 0 {
		c.t.Fatal("no log file was written; the file mirror is not being checked")
	}
	for _, file := range files {
		content, _ := os.ReadFile(file)
		out["file "+filepath.Base(file)] = string(content)
	}
	return out
}

// Nothing a person types into the console, and nothing that identifies the
// subscriber, may come back out through the logs or the diagnostics bundle.
// All values below are invented for this test.
func TestLogsAndDiagnosticsNeverCarrySecrets(t *testing.T) {
	logDir := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	radio := netmock.New(netmock.Options{SavedSSID: "FakeHome", Now: func() time.Time { return now }})
	c := openConsole(t, func(o *nodeserver.Options) { o.LogDir, o.Network = logDir, radio })

	const (
		wrongPassword = "Wrong-Fake-Guess-0000"
		newPassword   = "Fake-Rotated-Passw0rd-r127"
		passphrase    = "Fake-WiFi-Passphrase-2468"
		recipient     = "+99900000000123"
		smsBody       = "FAKE BANK: your verification code is 918273, never share it"
	)
	secrets := map[string]string{"setup proof": c.proof, "password": c.password, "wrong password": wrongPassword, "new password": newPassword,
		"wifi passphrase": passphrase, "sms recipient": recipient, "sms body": smsBody, "sms code": "918273", "sms body fragment": "verification code is 9"}

	// What an owner really does, through the real handlers.
	if w := c.do("POST", "/admin/login", map[string]string{"password": wrongPassword}); w.Code != 401 {
		t.Fatal(w.Code)
	}
	secrets["first session cookie"], secrets["first csrf token"] = c.cookie.Value, c.csrf
	w := c.do("POST", "/admin/password", map[string]string{"current_password": c.password, "password": newPassword})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rotated map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &rotated)
	c.cookie, c.csrf = w.Result().Cookies()[0], rotated["csrf"]
	secrets["session cookie"], secrets["csrf token"] = c.cookie.Value, c.csrf
	if w = c.do("POST", "/admin/api/v1/wifi/connect", proto.WiFiConnectRequest{SSID: "FakeNew", PSK: passphrase, Security: proto.WiFiSecurityWPA2}); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	now = now.Add(netmock.ConnectDelay)
	if w = c.do("POST", "/admin/api/v1/sms/send", proto.SendSMSRequest{RequestID: "fake-request-redaction", To: recipient, Text: smsBody}); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = c.do("POST", "/admin/api/v1/sms/send", proto.SendSMSRequest{RequestID: "fake-request-refused", To: "not a number", Text: smsBody}); w.Code != 400 {
		t.Fatal(w.Code)
	}
	// The subscriber identifiers this (mock) SIM and modem report: every long
	// digit string in the status documents.
	identifiers := regexp.MustCompile(`\+?\d{11,}`)
	for _, path := range []string{"/admin/api/v1/status", "/admin/api/v1/sim", "/admin/api/v1/sms"} {
		for i, found := range identifiers.FindAllString(c.do("GET", path, nil).Body.String(), -1) {
			secrets[fmt.Sprintf("identifier %d from %s", i, path)] = found
		}
	}
	if len(secrets) < 15 {
		t.Fatal("the mock SIM reported no identifiers; this test would prove less than it claims", len(secrets))
	}

	// And what careless code might do: the same values written straight into
	// the log, in the shapes the redaction recognises.
	iccid, imei := "89990000000000000017", "990000000000019"
	secrets["planted iccid"], secrets["planted imei"] = iccid, imei
	logs := c.node.Logs
	logs.Warnf("careless", "admin login password=%s", c.password)
	logs.Warnf("careless", `request {"password":"%s","setup_code":"x"}`, newPassword)
	logs.Errorf("careless", "wifi join failed psk=%s", passphrase)
	logs.Warnf("careless", "passphrase: %s", passphrase)
	logs.Warnf("careless", "cookie token=%s", c.cookie.Value)
	logs.Warnf("careless", `{"token":"%s"}`, c.csrf)
	logs.Errorf("careless", "Authorization: Bearer %s", c.cookie.Value)
	logs.Warnf("careless", "setup secret=%s", c.proof)
	logs.Warnf("careless", "sim iccid %s imei %s", iccid, imei)
	logs.Errorf("careless", "send to %s failed", recipient)
	logs.Warnf("careless", "inbound text: verification code is 918273")
	logs.Infof("careless", "psk=%s", passphrase)

	for place, content := range c.everythingReadable(logDir) {
		if !strings.Contains(content, "careless") && strings.HasPrefix(place, "file") {
			t.Errorf("%s: the planted lines never arrived, so their absence proves nothing", place)
		}
		for name, secret := range secrets {
			if strings.Contains(content, secret) {
				t.Errorf("%s contains the %s", place, name)
			}
		}
	}
	// The events themselves are still recorded, without the values.
	all := c.do("GET", "/admin/api/v1/logs?limit=0", nil).Body.String()
	for _, want := range []string{"sign-in refused", "management password changed", "joining network", "submitted message"} {
		if !strings.Contains(all, want) {
			t.Errorf("the log lost the event %q", want)
		}
	}
}

// radioWithSetupAP is the mock radio plus a credential source, standing in
// for the hardware backend, which is the only one that has a setup access
// point passphrase. The values are invented.
type radioWithSetupAP struct {
	*netmock.Backend
	reads int
}

const (
	plantedAPSSID       = "NasSimHub-FAKE00"
	plantedAPPassphrase = "fake-plnt-edap-pass"
)

func (r *radioWithSetupAP) SetupAPCredential() (string, string, error) {
	r.reads++
	return plantedAPSSID, plantedAPPassphrase, nil
}

// The setup access point passphrase through the assembled agent: the node
// server finds the backend's credential source, the console gives it to a
// signed-in owner who re-enters the password, and it then appears in no log,
// no diagnostics document and no file of the diagnostics archive.
func TestSetupAPPassphraseReachesTheOwnerAndNoLogOrDiagnostics(t *testing.T) {
	logDir := t.TempDir()
	radio := &radioWithSetupAP{Backend: netmock.New(netmock.Options{})}
	c := openConsole(t, func(o *nodeserver.Options) { o.LogDir, o.Network = logDir, radio })

	w := c.do("GET", "/admin/api/v1/wifi/setup-ap", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"available":true`) || !strings.Contains(w.Body.String(), plantedAPSSID) || strings.Contains(w.Body.String(), plantedAPPassphrase) {
		t.Fatal("section", w.Code, w.Body.String())
	}
	if w = c.do("POST", "/admin/api/v1/wifi/setup-ap/reveal", map[string]string{"current_password": "Wrong-Fake-Guess-0000"}); w.Code != 401 || strings.Contains(w.Body.String(), plantedAPPassphrase) {
		t.Fatal("wrong password", w.Code, w.Body.String())
	}
	read := radio.reads
	w = c.do("POST", "/admin/api/v1/wifi/setup-ap/reveal", map[string]string{"current_password": c.password})
	var secret struct{ SSID, Passphrase string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &secret) != nil || secret.SSID != plantedAPSSID || secret.Passphrase != plantedAPPassphrase {
		t.Fatal("the owner was refused the passphrase", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", w.Header().Get("Cache-Control"))
	}
	if radio.reads != read+1 {
		t.Fatal("the credential was read", radio.reads-read, "times for one request")
	}
	// Without the session the same request is refused.
	signedIn := c.cookie
	c.cookie = nil
	if w = c.do("POST", "/admin/api/v1/wifi/setup-ap/reveal", map[string]string{"current_password": c.password}); w.Code != 401 {
		t.Fatal("no session", w.Code)
	}
	c.cookie = signedIn

	// Every other document the agent serves to this owner, and the Wi-Fi
	// documents a wider audience can read.
	for _, path := range []string{"/admin/session", "/admin/api/v1/wifi", "/admin/api/v1/status", "/admin/api/v1/node", "/admin/api/v1/capabilities", "/admin/api/v1/security", "/admin/api/v1/wifi/change"} {
		if strings.Contains(c.do("GET", path, nil).Body.String(), plantedAPPassphrase) {
			t.Errorf("%s carries the passphrase", path)
		}
	}
	if w = c.do("POST", "/admin/api/v1/wifi/scan", map[string]string{}); strings.Contains(w.Body.String(), plantedAPPassphrase) {
		t.Error("the scan result carries the passphrase")
	}
	// The hardware backend keeps the passphrase in a file of this name in the
	// state directory. A second invented value stands in for it, so a bundle
	// that one day collected state files would be caught here too.
	const storedAPPassphrase = "fake-stor-edap-file"
	if err := os.WriteFile(filepath.Join(c.dir, "setup-ap-passphrase"), []byte(storedAPPassphrase+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{"setup access point passphrase": plantedAPPassphrase, "stored setup access point passphrase": storedAPPassphrase,
		"management password": c.password, "wrong password": "Wrong-Fake-Guess-0000"}
	for place, content := range c.everythingReadable(logDir) {
		for name, value := range secrets {
			if strings.Contains(content, value) {
				t.Errorf("%s contains the %s", place, name)
			}
		}
	}
	// That it was shown is recorded; what it was is not.
	all := c.do("GET", "/admin/api/v1/logs?limit=0", nil).Body.String()
	for _, want := range []string{"setup access point passphrase request refused", "setup access point passphrase shown in the local console"} {
		if !strings.Contains(all, want) {
			t.Errorf("the log lost the event %q", want)
		}
	}
}

// The mock radio has no setup access point credential, as most backends do
// not. The assembled agent says so instead of showing an empty section.
func TestSetupAPWithoutACredentialSourceIsExplicitlyUnsupported(t *testing.T) {
	c := openConsole(t, nil)
	w := c.do("GET", "/admin/api/v1/wifi/setup-ap", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"available":false`) || !strings.Contains(w.Body.String(), `"no_credential_source"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = c.do("POST", "/admin/api/v1/wifi/setup-ap/reveal", map[string]string{"current_password": c.password}); w.Code != 501 || !strings.Contains(w.Body.String(), `"not_supported"`) {
		t.Fatal(w.Code, w.Body.String())
	}
}
