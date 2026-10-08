package localadmin

import (
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Why this console's own SMS is refused, as the person is told it.
//
// These are tests of the console against a fake trust source (the real gate is
// exercised in sms_block_integration_test.go) and of the page script against a
// stub DOM. Nothing here ran in a browser or on a device.

func TestSMSBlockClassificationFollowsTheGateOrder(t *testing.T) {
	for _, c := range []struct {
		name                   string
		denied, stale, damaged bool
		freshness, want        string
	}{
		{"allowed", false, false, false, "fresh", ""},
		{"restart", false, true, false, "stale_restart", "trust_stale_restart"},
		{"expired", false, true, false, "stale_expired", "trust_stale"},
		{"stale without a reason is not called a restart", false, true, false, "", "trust_stale"},
		{"denied", true, false, false, "fresh", "trust_denied"},
		// A restriction is the reason even while the policy also waits for the
		// NAS: reconnecting would not lift it, so "wait for the NAS" would be
		// the wrong thing to tell the person.
		{"denied and waiting", true, true, false, "stale_restart", "trust_denied"},
		{"denied and expired", true, true, false, "stale_expired", "trust_denied"},
		{"damaged wins", true, true, true, "stale_restart", "trust_damaged"},
	} {
		if got := smsBlock(c.denied, c.stale, c.damaged, c.freshness); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRefusedSMSSaysWhichSituationAndThePageAgreesInAdvance(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	api := &spy{status: 201}
	a, h, cookie, csrf := configured(t, c, api)
	trust := &fakeTrust{}
	a.Attach(trust.sources())

	send := func() (int, map[string]string) {
		w := call(t, h, "/admin/api/v1/sms/send", "POST", map[string]string{"request_id": "fake-request-0001", "to": "10000", "text": "simulated"}, cookie, csrf, origin)
		var body map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body
	}
	page := func() TrustReport {
		var view TrustReport
		_ = json.Unmarshal(get(h, "/admin/api/v1/trust", cookie, false).Body.Bytes(), &view)
		return view
	}
	outgoing := []string{"dial", "dtmf", "send_sms"}
	for _, situation := range []struct {
		name     string
		report   TrustReport
		refusal  TrustRefusal
		code     string
		state    string
		contains string
	}{
		{"restart, waiting for the NAS",
			TrustReport{Supported: true, Installed: true, Enforcing: true, State: "TRUSTED", Stale: true, Freshness: "stale_restart"},
			TrustRefusal{State: "TRUSTED", Stale: true, Freshness: "stale_restart"}, "trust_stale_restart", "TRUSTED", "重启后需由 NAS 重新确认"},
		{"expired",
			TrustReport{Supported: true, Installed: true, Enforcing: true, State: "TRUSTED", Stale: true, Freshness: "stale_expired"},
			TrustRefusal{State: "TRUSTED", Stale: true, Freshness: "stale_expired"}, "trust_stale", "TRUSTED", "策略已过期"},
		{"observation",
			TrustReport{Supported: true, Installed: true, Enforcing: true, State: "OBSERVATION", Deny: outgoing},
			TrustRefusal{State: "OBSERVATION", Denied: true, Freshness: "fresh"}, "trust_denied", "OBSERVATION", "限制了此设备的外发"},
		{"restricted",
			TrustReport{Supported: true, Installed: true, Enforcing: true, State: "RESTRICTED", Deny: outgoing},
			TrustRefusal{State: "RESTRICTED", Denied: true, Freshness: "fresh"}, "trust_denied", "RESTRICTED", "限制了此设备的外发"},
		{"restricted, and the device restarted",
			TrustReport{Supported: true, Installed: true, Enforcing: true, State: "RESTRICTED", Deny: outgoing, Stale: true, Freshness: "stale_restart"},
			TrustRefusal{State: "RESTRICTED", Denied: true, Stale: true, Freshness: "stale_restart"}, "trust_denied", "RESTRICTED", "限制了此设备的外发"},
		{"quarantine",
			TrustReport{Supported: true, Installed: true, Enforcing: true, State: "QUARANTINE", Deny: append([]string{"forward_otp"}, outgoing...)},
			TrustRefusal{State: "QUARANTINE", Denied: true, Freshness: "fresh"}, "trust_denied", "QUARANTINE", "限制了此设备的外发"},
		{"damaged",
			TrustReport{Supported: true, Installed: true, Enforcing: true, Damaged: true, Stale: true},
			TrustRefusal{Damaged: true, Stale: true}, "trust_damaged", "", "校验失败"},
	} {
		trust.report, trust.refusal = situation.report, &situation.refusal
		before := api.calls
		code, body := send()
		if code != 403 || body["code"] != situation.code || body["state"] != situation.state || !strings.Contains(body["error"], situation.contains) || !strings.Contains(body["error"], "本页不能解除") {
			t.Errorf("%s: refused send answered %d %v", situation.name, code, body)
		}
		if api.calls != before {
			t.Errorf("%s: a refused message reached the device API", situation.name)
		}
		// The page, read in advance, names the same situation - from the
		// device's report, without asking the gate (reading is not an attempt).
		asked := trust.asked
		view := page()
		if view.SendSMSAllowed || view.SendSMSBlock != situation.code || view.State != situation.state {
			t.Errorf("%s: trust page says allowed=%v block=%q state=%q", situation.name, view.SendSMSAllowed, view.SendSMSBlock, view.State)
		}
		if trust.asked != asked {
			t.Errorf("%s: reading the page counted as an attempt to send", situation.name)
		}
	}

	// Recovery: the same request goes through once the gate allows it, and the
	// page stops naming a block. Monitor mode and "no policy" never name one.
	for name, report := range map[string]TrustReport{
		"fresh again":  {Supported: true, Installed: true, Enforcing: true, State: "TRUSTED", Freshness: "fresh"},
		"no policy":    {Supported: true},
		"monitor only": {Supported: true, Installed: true, Enforcing: false, Mode: "monitor", State: "OBSERVATION", Deny: outgoing},
		"unsupported":  {},
	} {
		trust.report, trust.refusal = report, nil
		before := api.calls
		if code, body := send(); code >= 400 || api.calls != before+1 {
			t.Errorf("%s: send after recovery answered %d %v (forwarded %d)", name, code, body, api.calls-before)
		}
		if view := page(); !view.SendSMSAllowed || view.SendSMSBlock != "" {
			t.Errorf("%s: trust page still names a block: %+v", name, view)
		}
	}
	raw := get(h, "/admin/api/v1/trust", cookie, false).Body.String()
	if strings.Contains(raw, "send_sms_block") {
		t.Errorf("an allowed send carries no block field at all: %s", raw)
	}
}

// The page explains every code the console can answer with, and every trust
// state a denial can carry; a new one without an explanation fails here
// instead of showing the fallback to a person.
func TestPageExplainsEverySMSBlock(t *testing.T) {
	scriptBytes, _ := assets.ReadFile("app.js")
	pageBytes, _ := assets.ReadFile("index.html")
	script := string(scriptBytes)
	start := strings.Index(script, "    block: {")
	if start < 0 {
		t.Fatal("app.js has no sms.block strings")
	}
	section := script[start : start+strings.Index(script[start:], "    uncertain:")]
	for _, key := range []string{smsBlockStaleRestart, smsBlockStale, smsBlockDamaged, smsBlockDenied, "OBSERVATION", "RESTRICTED", "QUARANTINE"} {
		entry := regexp.MustCompile(`(?s)\n      ` + key + `: \{\s*title: '[^']+',\s*text: '[^']+',\s*recover: '恢复方法：[^']+',\s*\}`)
		if !entry.MatchString(section) {
			t.Errorf("sms.block.%s needs a title, a text and a recovery sentence", key)
		}
	}
	for _, want := range []string{"draftKept: '草稿已保留", "不会自动重试"} {
		if !strings.Contains(section, want) {
			t.Errorf("sms.block lacks %q", want)
		}
	}
	// Recovery never promises what this page cannot do, and never tells the
	// person to use a password or entrance that belongs somewhere else.
	for _, banned := range []string{"本页可以解除", "输入 NAS 密码", "自动重发", "自动发送"} {
		if strings.Contains(section, banned) {
			t.Errorf("sms.block must not say %q", banned)
		}
	}
	for _, id := range []string{"sms-block", "sms-block-title", "sms-block-text", "sms-block-recover", "sms-block-draft", "sms-block-recheck"} {
		if !strings.Contains(string(pageBytes), `id="`+id+`"`) {
			t.Errorf("index.html lacks #%s", id)
		}
	}
	// The explanation is filled with textContent only and cleared on sign-out.
	if strings.Contains(script, "sms-block').innerHTML") || !regexp.MustCompile(`(?s)function wipe\(\) \{.*?hideSMSBlock\(\);`).MatchString(script) {
		t.Error("the SMS block must be text-only and wiped with the session")
	}
}

// The page script, run for real against a stub DOM and a scripted device:
// each refusal shows its own explanation and recovery, the draft stays, there
// is exactly one request per press, re-checking never sends, and after the NAS
// confirmed the person's own next press sends once.
func TestPageKeepsTheDraftAndNeverRetriesARefusedSMS(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; the page behaviour test (testdata/sms_block_harness.js) was NOT run")
	}
	appJS, _ := assets.ReadFile("app.js")
	script := t.TempDir() + "/app.js"
	if err := os.WriteFile(script, appJS, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(node, "--check", script).CombinedOutput(); err != nil {
		t.Fatalf("app.js does not parse: %v\n%s", err, out)
	}
	out, err := exec.Command(node, "testdata/sms_block_harness.js", script).CombinedOutput()
	if err != nil {
		t.Fatalf("page behaviour: %v\n%s", err, out)
	}
	t.Log(strings.TrimSpace(string(out)))
}
