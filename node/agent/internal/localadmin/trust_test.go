package localadmin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A fake trust source: the console's own behaviour, without the gate.
type fakeTrust struct {
	report  TrustReport
	refusal *TrustRefusal
	asked   int
}

func (f *fakeTrust) sources() Sources {
	return Sources{Trust: func() TrustReport { return f.report }, RequireSendSMS: func() *TrustRefusal { f.asked++; return f.refusal }}
}

func TestTrustPageIsReadOnlyAndSaysWhoDecides(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	api := &spy{}
	a, h, cookie, csrf := configured(t, c, api)

	read := func() (TrustReport, int) {
		var view TrustReport
		w := get(h, "/admin/api/v1/trust", cookie, false)
		_ = json.Unmarshal(w.Body.Bytes(), &view)
		return view, w.Code
	}
	// No source attached: unsupported, not "unrestricted and fine".
	if view, code := read(); code != 200 || view.Supported || view.Installed || view.Deny == nil {
		t.Fatalf("no source: %d %+v", code, view)
	}
	trust := &fakeTrust{report: TrustReport{Supported: true}}
	a.Attach(trust.sources())
	if view, _ := read(); !view.Supported || view.Installed || !view.SendSMSAllowed {
		t.Fatalf("no policy: %+v", view)
	}
	trust.report = TrustReport{Supported: true, Installed: true, State: "QUARANTINE", Mode: "enforce", Deny: []string{"dial", "dtmf", "forward_otp", "send_sms"},
		Reason: "restricted by an administrator", Generation: 7, ExpiresAt: "2026-10-06T08:00:00Z", Enforcing: true}
	view, _ := read()
	if view.State != "QUARANTINE" || view.Generation != 7 || len(view.Deny) != 4 || view.Reason == "" || view.SendSMSAllowed || !view.Enforcing {
		t.Fatalf("quarantine: %+v", view)
	}
	if trust.asked != 0 {
		t.Fatal("reading the page must not count as an attempt to send")
	}
	// Stale: what is not denied is not available either.
	trust.report = TrustReport{Supported: true, Installed: true, State: "TRUSTED", Mode: "enforce", Deny: []string{}, Stale: true, Enforcing: true}
	if view, _ := read(); view.SendSMSAllowed || !view.Stale {
		t.Fatalf("stale: %+v", view)
	}
	// The reason for staleness is passed through as the gate gave it.
	trust.report.Freshness = "stale_restart"
	w := get(h, "/admin/api/v1/trust", cookie, false)
	if !strings.Contains(w.Body.String(), `"freshness":"stale_restart"`) || !strings.Contains(w.Body.String(), `"send_sms_allowed":false`) {
		t.Fatalf("stale after a restart: %s", w.Body.String())
	}
	// Monitor: shown as it is, and nothing is refused.
	trust.report = TrustReport{Supported: true, Installed: true, State: "OBSERVATION", Mode: "monitor", Deny: []string{"send_sms"}}
	if view, _ := read(); !view.SendSMSAllowed || view.Enforcing {
		t.Fatalf("monitor: %+v", view)
	}

	// The page is a read: every other method on it is refused, and the route
	// table holds nothing else under /trust.
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if w := call(t, h, "/admin/api/v1/trust", method, map[string]any{"state": "TRUSTED", "deny": []string{}}, cookie, csrf, origin); w.Code != 405 {
			t.Errorf("%s /admin/api/v1/trust: %d", method, w.Code)
		}
	}
	for _, candidate := range routes {
		if strings.Contains(candidate.path, "trust") && (candidate.method != "GET" || candidate.path != "/admin/api/v1/trust") {
			t.Errorf("the console has a trust route that is not the read-only page: %s %s", candidate.method, candidate.path)
		}
	}
	if api.calls != 0 {
		t.Fatalf("the trust page reached the device API %d times", api.calls)
	}
	// It needs a session like every other page.
	if w := get(h, "/admin/api/v1/trust", nil, false); w.Code != 401 {
		t.Fatalf("without a session: %d", w.Code)
	}
}

func TestConsoleSMSGoesThroughTheTrustGate(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	api := &spy{status: 201}
	a, h, cookie, csrf := configured(t, c, api)
	trust := &fakeTrust{}
	a.Attach(trust.sources())
	message := map[string]string{"request_id": "fake-request-1", "to": "10000", "text": "simulated text"}

	cases := []struct {
		name            string
		refusal         *TrustRefusal
		code            string
		messageContains []string
	}{
		{"denied", &TrustRefusal{State: "OBSERVATION", Denied: true}, "trust_denied", []string{"NAS", "本页不能解除"}},
		{"stale", &TrustRefusal{State: "TRUSTED", Stale: true}, "trust_stale", []string{"策略已过期", "NAS", "刷新"}},
		{"stale, expired named", &TrustRefusal{State: "TRUSTED", Stale: true, Freshness: "stale_expired"}, "trust_stale", []string{"策略已过期", "NAS", "刷新"}},
		// After a restart nothing has expired, and the page must not say so.
		{"stale after a restart", &TrustRefusal{State: "TRUSTED", Stale: true, Freshness: "stale_restart"}, "trust_stale_restart",
			[]string{"设备重启后需由 NAS 重新确认策略；连接 NAS 后自动恢复", "本页不能解除"}},
		// A denied action is reported as denied whatever the freshness.
		{"denied after a restart", &TrustRefusal{State: "RESTRICTED", Denied: true, Stale: true, Freshness: "stale_restart"}, "trust_denied", []string{"NAS", "本页不能解除"}},
		{"damaged", &TrustRefusal{Damaged: true, Stale: true}, "trust_damaged", []string{"校验失败", "NAS"}},
	}
	for _, tc := range cases {
		trust.refusal = tc.refusal
		w := call(t, h, "/admin/api/v1/sms/send", "POST", message, cookie, csrf, origin)
		var body map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != 403 || body["code"] != tc.code || api.calls != 0 {
			t.Fatalf("%s: %d %v, device calls %d", tc.name, w.Code, body, api.calls)
		}
		for _, want := range tc.messageContains {
			if !strings.Contains(body["error"], want) {
				t.Errorf("%s: the message must contain %q: %s", tc.name, want, body["error"])
			}
		}
		// The gate comes before validation: an invalid body is refused the
		// same way and says nothing about the body.
		if w := call(t, h, "/admin/api/v1/sms/send", "POST", map[string]string{"to": "not a number"}, cookie, csrf, origin); w.Code != 403 {
			t.Errorf("%s: an invalid body got past the gate: %d", tc.name, w.Code)
		}
	}
	// Allowed: forwarded exactly once.
	trust.refusal = nil
	if w := call(t, h, "/admin/api/v1/sms/send", "POST", message, cookie, csrf, origin); w.Code != 201 || api.calls != 1 {
		t.Fatalf("allowed: %d, device calls %d", w.Code, api.calls)
	}

	// Everything else the console does works under a deny-everything policy.
	trust.refusal = &TrustRefusal{State: "QUARANTINE", Denied: true}
	for _, path := range []string{"/admin/api/v1/security", "/admin/api/v1/update", "/admin/api/v1/wifi/change", "/admin/api/v1/trust", "/admin/api/v1/logs", "/admin/api/v1/diagnostics"} {
		if w := get(h, path, cookie, false); w.Code >= 400 {
			t.Errorf("%s under a deny-everything policy: %d", path, w.Code)
		}
	}
	if w := call(t, h, "/admin/api/v1/wifi/connect", "POST", map[string]string{"ssid": "FakeHome", "psk": "a-fake-passphrase", "security": "wpa2"}, cookie, csrf, origin); w.Code >= 400 {
		t.Errorf("wifi under a deny-everything policy: %d %s", w.Code, w.Body.String())
	}
	w := call(t, h, "/admin/password", "POST", map[string]string{"current_password": "a-fake-management-password", "password": "another-fake-password"}, cookie, csrf, origin)
	if w.Code != 200 {
		t.Fatalf("password change under a deny-everything policy: %d %s", w.Code, w.Body.String())
	}
	cookie = w.Result().Cookies()[0]
	var rotated map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &rotated)
	if w := call(t, h, "/admin/logout", "POST", map[string]string{}, cookie, rotated["csrf"], origin); w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	}
	if w := call(t, h, "/admin/login", "POST", map[string]string{"password": "another-fake-password"}, nil, "", origin); w.Code != 200 {
		t.Fatalf("login under a deny-everything policy: %d %s", w.Code, w.Body.String())
	}
}

// The page's strings for the trust section exist and say that the decision is
// the paired NAS's.
func TestTrustSectionStringsArePresent(t *testing.T) {
	script, err := assets.ReadFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"信任 / 使用限制", "由已配对的 NAS 决定；本页不能解除", "api('trust')", "UNBOUND", "OBSERVATION", "TRUSTED", "RESTRICTED", "QUARANTINE", "forward_otp", "send_sms_allowed"} {
		if !strings.Contains(string(script), want) {
			t.Errorf("app.js lacks %q", want)
		}
	}
}
