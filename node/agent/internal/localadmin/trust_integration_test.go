package localadmin_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/internal/pairing"
	"github.com/human-agent65535/nassimhub-node/agent/nodeserver"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// The assembled agent: the standalone console and the Core protocol share one
// trust gate, and the console can read the policy and never change it.
// Simulated end to end (mock modem, mock radio, in-process handlers).

type trustCore struct {
	id  string
	key ed25519.PrivateKey
}

func newTrustCore(id string, fill byte) trustCore {
	return trustCore{id: id, key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))}
}

// pairWith pairs the node with a core through the pairing store, the way the
// signed POST /v1/pair does.
func (c *console) pairWith(core trustCore) {
	c.t.Helper()
	request := proto.PairRequest{CoreID: core.id, CoreName: "test-nas", CorePublicKey: proto.EncodeKey(core.key.Public().(ed25519.PublicKey))}
	body, _ := json.Marshal(request)
	stamp, nonce := proto.FormatTimestamp(time.Now()), "nonce-"+core.id+time.Now().Format("150405.000000000")
	signature := ed25519.Sign(core.key, proto.SigningString("POST", "/v1/pair", stamp, nonce, body))
	if _, err := c.node.Pairing.Pair(request, pairing.SignedRequest{CoreID: core.id, Timestamp: stamp, Nonce: nonce,
		Signature: base64.StdEncoding.EncodeToString(signature), Method: "POST", Path: "/v1/pair", Body: body}); err != nil {
		c.t.Fatal(err)
	}
}

func (c *console) signedPolicy(core trustCore, generation uint64, state proto.TrustState, issued time.Time, deny ...proto.TrustAction) []byte {
	c.t.Helper()
	signed, err := proto.SignTrustPolicy(proto.TrustPolicy{Version: 1, DeviceID: c.node.Identity.DeviceID, CoreID: core.id, Generation: generation,
		State: state, Mode: proto.TrustEnforce, Deny: proto.NormalizeTrustDeny(deny), Reason: "test reason",
		IssuedAt: proto.FormatTrustTime(issued), ExpiresAt: proto.FormatTrustTime(issued.Add(time.Hour))}, core.key, nil)
	if err != nil {
		c.t.Fatal(err)
	}
	raw, _ := json.Marshal(signed)
	return raw
}

func (c *console) sendSMS(id string) (int, map[string]string) {
	w := c.do("POST", "/admin/api/v1/sms/send", proto.SendSMSRequest{RequestID: id, To: "10000", Text: "simulated text"})
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

func (c *console) trustPage() map[string]any {
	c.t.Helper()
	w := c.do("GET", "/admin/api/v1/trust", nil)
	var view map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
		c.t.Fatal(w.Code, w.Body.String())
	}
	return view
}

func TestConsoleSharesTheDeviceTrustGateAndCannotChangeIt(t *testing.T) {
	c := openConsole(t, nil)
	core := newTrustCore("core-console-test", 0x51)
	outgoing := []proto.TrustAction{proto.TrustActionDial, proto.TrustActionSendSMS, proto.TrustActionDTMF}

	// Not paired, no policy: the console sends as it always has.
	if view := c.trustPage(); view["supported"] != true || view["installed"] != false || view["send_sms_allowed"] != true {
		t.Fatalf("no policy: %v", view)
	}
	if code, body := c.sendSMS("fake-request-open"); code != 201 {
		t.Fatalf("send without a policy: %d %v", code, body)
	}

	c.pairWith(core)
	if err := c.node.Trust.Install(c.signedPolicy(core, 1, proto.TrustObservation, time.Now(), outgoing...)); err != nil {
		t.Fatal(err)
	}
	// The policy the paired NAS signed stops the console's own send.
	code, body := c.sendSMS("fake-request-denied")
	if code != 403 || body["code"] != "trust_denied" || !strings.Contains(body["error"], "本页不能解除") {
		t.Fatalf("send under observation: %d %v", code, body)
	}
	view := c.trustPage()
	if view["installed"] != true || view["state"] != "OBSERVATION" || view["enforcing"] != true || view["send_sms_allowed"] != false || view["reason"] != "test reason" {
		t.Fatalf("trust page: %v", view)
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), c.node.Identity.DeviceID) || strings.Contains(string(raw), core.id) {
		t.Fatalf("the trust page carries an identifier: %s", raw)
	}
	// Nothing was sent: the device holds only the one message from before.
	listing := c.do("GET", "/admin/api/v1/sms", nil)
	if strings.Count(listing.Body.String(), `"direction":"outgoing"`) > 1 || strings.Contains(listing.Body.String(), "fake-request-denied") {
		t.Fatalf("a refused message reached the modem: %s", listing.Body.String())
	}

	// The console cannot install, edit or clear a policy - not with a body the
	// owner really signed, not through any path under its API.
	lift := c.signedPolicy(core, 2, proto.TrustTrusted, time.Now())
	for _, attempt := range []struct{ method, path string }{
		{"POST", "/admin/api/v1/trust/policy"}, {"POST", "/admin/api/v1/trust"}, {"PUT", "/admin/api/v1/trust"},
		{"DELETE", "/admin/api/v1/trust"}, {"DELETE", "/admin/api/v1/trust/policy"}, {"POST", "/admin/api" + proto.TrustPolicyPath},
	} {
		w := c.do(attempt.method, attempt.path, json.RawMessage(lift))
		if w.Code < 400 {
			t.Errorf("%s %s was accepted by the console: %d %s", attempt.method, attempt.path, w.Code, w.Body.String())
		}
	}
	if w := c.do("GET", "/admin/api"+proto.TrustStatusPath, nil); w.Code != 200 {
		// /admin/api/v1/trust is the console's own page (above); the Core
		// protocol's GET /v1/trust is not among the routes handed to it.
		t.Fatalf("the console's own page: %d", w.Code)
	}
	if status := c.node.Trust.Status(); status.Generation != 1 || status.State != proto.TrustObservation {
		t.Fatalf("the policy changed through the console: %+v", status)
	}

	// Under the restriction the rest of the console works.
	for _, path := range []string{"/admin/api/v1/security", "/admin/api/v1/update", "/admin/api/v1/wifi", "/admin/api/v1/logs", "/admin/api/v1/diagnostics", "/admin/api/v1/status"} {
		if w := c.do("GET", path, nil); w.Code != 200 {
			t.Errorf("%s under a restriction: %d", path, w.Code)
		}
	}
	if w := c.do("POST", "/admin/api/v1/wifi/scan", nil); w.Code != 200 {
		t.Errorf("wifi scan under a restriction: %d", w.Code)
	}

	// Expired: nothing is denied by this policy, and the console's send is
	// still refused, with the instruction to connect the NAS.
	rawPermit := c.signedPolicy(core, 2, proto.TrustTrusted, time.Now())
	permit, err := proto.DecodeSignedTrustPolicy(rawPermit)
	if err != nil {
		t.Fatal(err)
	}
	issued, _, err := permit.Times()
	if err != nil {
		t.Fatal(err)
	}
	permit.ExpiresAt = proto.FormatTrustTime(issued.Add(time.Second))
	signedPermit, err := proto.SignTrustPolicy(permit.TrustPolicy, core.key, nil)
	if err != nil {
		t.Fatal(err)
	}
	rawPermit, err = json.Marshal(signedPermit)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.node.Trust.Install(rawPermit); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // Real monotonic validity, not a wall-clock jump.
	code, body = c.sendSMS("fake-request-stale")
	if code != 403 || body["code"] != "trust_stale" || !strings.Contains(body["error"], "策略已过期") || !strings.Contains(body["error"], "NAS") {
		t.Fatalf("send on an expired policy: %d %v", code, body)
	}
	if view := c.trustPage(); view["stale"] != true || view["send_sms_allowed"] != false {
		t.Fatalf("stale page: %v", view)
	}

	// A fresh policy from the owner allows it again.
	if err := c.node.Trust.Install(c.signedPolicy(core, 3, proto.TrustTrusted, time.Now())); err != nil {
		t.Fatal(err)
	}
	if code, body := c.sendSMS("fake-request-trusted"); code != 201 {
		t.Fatalf("send when trusted: %d %v", code, body)
	}
	if view := c.trustPage(); view["send_sms_allowed"] != true || view["stale"] != false {
		t.Fatalf("trusted page: %v", view)
	}
}

// A build with enforcement left out says "not supported"; it does not present
// an unrestricted device as a checked one.
func TestConsoleReportsEnforcementAsUnsupportedWhenLeftOut(t *testing.T) {
	c := openConsole(t, func(o *nodeserver.Options) { o.DisableTrustEnforcement = true })
	if view := c.trustPage(); view["supported"] != false || view["installed"] != false {
		t.Fatalf("without enforcement: %v", view)
	}
	if code, body := c.sendSMS("fake-request-plain"); code != 201 {
		t.Fatalf("send: %d %v", code, body)
	}
}
