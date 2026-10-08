package localadmin_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/modembackend/mock"
	netmock "github.com/human-agent65535/nassimhub-node/agent/netbackend/mock"
	"github.com/human-agent65535/nassimhub-node/agent/nodeserver"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// The console's SMS refusal reasons against the REAL trust gate of an
// assembled agent (mock modem, mock radio, in-process handlers; not a device).
// The policies are really signed by the paired Core key and really verified.

// restart builds a new agent over the same state directory and signs in again
// with the password, the way a device comes back after a power cycle.
func (c *console) restart() *console {
	c.t.Helper()
	modem := mock.New(mock.Options{Scenario: mock.ChinaTelecom})
	node, err := nodeserver.New(nodeserver.Options{StateDir: c.dir, Platform: proto.PlatformMock, Model: "test", Modem: modem,
		EnableTLS: true, EnableLocalAdmin: true, AgentVersion: "0.0.0-test", Network: netmock.New(netmock.Options{})})
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { _ = node.Logs.Close(); _ = modem.Close() })
	next := &console{t: c.t, node: node, dir: c.dir, password: c.password}
	w := next.do("POST", "/admin/login", map[string]string{"password": c.password})
	if w.Code != 200 {
		c.t.Fatal(w.Code, w.Body.String())
	}
	var login map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &login)
	next.cookie, next.csrf = w.Result().Cookies()[0], login["csrf"]
	return next
}

func (c *console) expectBlocked(what, code, state string) {
	c.t.Helper()
	status, body := c.sendSMS("fake-request-" + what)
	if status != 403 || body["code"] != code || body["state"] != state {
		c.t.Fatalf("%s: send answered %d %v, want 403 %s (%s)", what, status, body, code, state)
	}
	view := c.trustPage()
	if view["send_sms_allowed"] != false || view["send_sms_block"] != code || view["state"] != state {
		c.t.Fatalf("%s: trust page %v, want block %s state %s", what, view, code, state)
	}
}

func (c *console) expectAllowed(what string) {
	c.t.Helper()
	if status, body := c.sendSMS("fake-request-" + what); status != 201 {
		c.t.Fatalf("%s: send answered %d %v, want 201", what, status, body)
	}
	view := c.trustPage()
	if _, named := view["send_sms_block"]; view["send_sms_allowed"] != true || named {
		c.t.Fatalf("%s: trust page still names a block: %v", what, view)
	}
}

func TestConsoleSMSRefusalReasonsWithTheRealGateAndRecovery(t *testing.T) {
	c := openConsole(t, nil)
	core := newTrustCore("core-sms-block-test", 0x52)
	outgoing := []proto.TrustAction{proto.TrustActionDial, proto.TrustActionSendSMS, proto.TrustActionDTMF}
	c.pairWith(core)
	install := func(raw []byte) {
		t.Helper()
		if err := c.node.Trust.Install(raw); err != nil {
			t.Fatal(err)
		}
	}

	// Trusted and fresh: the console sends.
	trusted := c.signedPolicy(core, 1, proto.TrustTrusted, time.Now())
	install(trusted)
	c.expectAllowed("trusted")

	// 1. The device restarts. Nothing expired and nothing is denied, but the
	//    NAS has not confirmed the policy since: "waiting for the NAS".
	c = c.restart()
	c.expectBlocked("after-restart", "trust_stale_restart", "TRUSTED")
	// Asking again changes nothing by itself - no number of attempts confirms it.
	c.expectBlocked("after-restart-again", "trust_stale_restart", "TRUSTED")
	//    Recovery is the NAS sending the same signed policy again (what it
	//    does when it reconnects). No new generation, nothing done on the page.
	install(trusted)
	c.expectAllowed("confirmed-after-restart")

	// 2. Observation: outgoing use denied by the policy itself.
	install(c.signedPolicy(core, 2, proto.TrustObservation, time.Now(), outgoing...))
	c.expectBlocked("observation", "trust_denied", "OBSERVATION")
	//    A restart during observation is still "observation", not "waiting for
	//    the NAS": reconnecting the NAS would not make sending possible.
	c = c.restart()
	c.expectBlocked("observation-after-restart", "trust_denied", "OBSERVATION")
	//    Recovery: the NAS issues the policy that follows the observation period.
	install(c.signedPolicy(core, 3, proto.TrustTrusted, time.Now()))
	c.expectAllowed("after-observation")

	// 3. Restricted by an administrator on the NAS, then quarantined.
	install(c.signedPolicy(core, 4, proto.TrustRestricted, time.Now(), outgoing...))
	c.expectBlocked("restricted", "trust_denied", "RESTRICTED")
	install(c.signedPolicy(core, 5, proto.TrustQuarantine, time.Now(), append(outgoing, proto.TrustActionForwardOTP)...))
	c.expectBlocked("quarantine", "trust_denied", "QUARANTINE")
	//    Recovery passes through observation (still blocked), then trusted.
	install(c.signedPolicy(core, 6, proto.TrustObservation, time.Now(), outgoing...))
	c.expectBlocked("restored-into-observation", "trust_denied", "OBSERVATION")
	install(c.signedPolicy(core, 7, proto.TrustTrusted, time.Now()))
	c.expectAllowed("after-restore")

	// 4. Expired: a policy valid for one second, measured on the real
	//    monotonic clock.
	short, err := proto.DecodeSignedTrustPolicy(c.signedPolicy(core, 8, proto.TrustTrusted, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	issued, _, err := short.Times()
	if err != nil {
		t.Fatal(err)
	}
	short.ExpiresAt = proto.FormatTrustTime(issued.Add(time.Second))
	signed, err := proto.SignTrustPolicy(short.TrustPolicy, core.key, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(signed)
	install(raw)
	time.Sleep(1100 * time.Millisecond)
	c.expectBlocked("expired", "trust_stale", "TRUSTED")
	//    Recovery: a new policy from the NAS.
	install(c.signedPolicy(core, 9, proto.TrustTrusted, time.Now()))
	c.expectAllowed("after-expiry")

	// Throughout, nothing refused reached the modem: only the allowed sends did.
	listing := c.do("GET", "/admin/api/v1/sms", nil).Body.String()
	for _, refused := range []string{"after-restart", "observation", "restricted", "quarantine", "expired"} {
		if strings.Contains(listing, "fake-request-"+refused) {
			t.Fatalf("a refused message (%s) reached the modem", refused)
		}
	}
}
