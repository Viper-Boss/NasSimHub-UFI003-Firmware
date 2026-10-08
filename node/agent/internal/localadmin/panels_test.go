package localadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

type fakeUpdates struct {
	status    proto.OTADeviceStatus
	err       error
	rollbacks int
	asked     string
}

func (f *fakeUpdates) Status() proto.OTADeviceStatus { return f.status }
func (f *fakeUpdates) Rollback(_ context.Context, releaseID string) (proto.OTADeviceStatus, error) {
	f.rollbacks++
	f.asked = releaseID
	if f.err != nil {
		return f.status, f.err
	}
	f.status.State = proto.OTARolledBack
	f.status.RestartPending = true
	return f.status, nil
}

func pendingStatus() proto.OTADeviceStatus {
	status := proto.OTADeviceStatus{
		UnsupportedReason: "",
		Keys:              proto.OTAKeyStatus{Classical: 2, PostQuantum: 1},
		ReceivedBytes:     1000, ExpectedBytes: 1000,
		ActiveRelease: "fake-release-1", FactoryVersion: "0.0.1-fake",
	}
	status.State = proto.OTAPendingConfirm
	status.CurrentVersion, status.TargetVersion, status.PreviousVersion = "0.0.2-fake", "0.0.2-fake", "0.0.1-fake"
	status.ReleaseID = "fake-release-1"
	status.Supported = true
	status.ConfirmDeadline = time.Unix(1_800_000_600, 0).UTC()
	return status
}

func TestUpdatePageWithoutAnUpdateServiceIsUnsupportedNotAnError(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	_, h, cookie, csrf := configured(t, c, &spy{})
	w := get(h, "/admin/api/v1/update", cookie, false)
	var view struct {
		Available   bool
		Reason      string
		Status      *json.RawMessage
		CanRollback bool `json:"can_rollback"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	if view.Available || view.Status != nil || view.CanRollback || view.Reason != "not supported in this build" {
		t.Fatal("a build without updates must say so plainly", w.Body.String())
	}
	if w = call(t, h, "/admin/api/v1/update/rollback", "POST", map[string]string{"release_id": "fake-release-1"}, cookie, csrf, origin); w.Code != 501 {
		t.Fatal("rollback without an update service", w.Code)
	}
}

func TestUpdatePageReportsTheServiceAndOnlyRollsBackAnUnconfirmedUpdate(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	a, h, cookie, csrf := configured(t, c, &spy{})
	updates := &fakeUpdates{status: pendingStatus()}
	var logged []string
	a.Attach(Sources{Updates: updates, Logf: func(format string, arguments ...any) { logged = append(logged, fmt.Sprintf(format, arguments...)) }})

	body := get(h, "/admin/api/v1/update", cookie, false).Body.String()
	for _, want := range []string{`"available":true`, `"can_rollback":true`, `"state":"PENDING_CONFIRM"`, `"current_version":"0.0.2-fake"`, `"factory_version":"0.0.1-fake"`,
		`"active_release":"fake-release-1"`, `"target_version":"0.0.2-fake"`, `"received_bytes":1000`, `"expected_bytes":1000`, `"confirm_deadline":"2027-`, `"supported":true`, `"keys":{"classical":2,"post_quantum":1}`, `"signatures":{`} {
		if !strings.Contains(body, want) {
			t.Errorf("update status lacks %s in %s", want, body)
		}
	}
	rollback := func(release string) int {
		return call(t, h, "/admin/api/v1/update/rollback", "POST", map[string]string{"release_id": release}, cookie, csrf, origin).Code
	}
	// Not the release that was shown, or not a release id at all: nothing happens.
	for release, want := range map[string]int{"fake-release-2": 409, "": 400, "../../etc": 400, "current": 400} {
		if got := rollback(release); got != want {
			t.Errorf("rollback of %q: %d, want %d", release, got, want)
		}
	}
	// Any state other than applied-and-unconfirmed: nothing happens.
	for _, state := range []proto.OTAState{proto.OTAIdle, proto.OTAReady, proto.OTADownloading, proto.OTAApplying, proto.OTAFailed, proto.OTARolledBack} {
		updates.status.State = state
		if got := rollback("fake-release-1"); got != 409 {
			t.Errorf("rollback in %s: %d", state, got)
		}
		if strings.Contains(get(h, "/admin/api/v1/update", cookie, false).Body.String(), `"can_rollback":true`) {
			t.Errorf("rollback offered in %s", state)
		}
	}
	updates.status.State = proto.OTAPendingConfirm
	updates.status.Supported = false
	if got := rollback("fake-release-1"); got != 501 {
		t.Error("rollback on an unsupported device", got)
	}
	updates.status.Supported = true
	if updates.rollbacks != 0 {
		t.Fatal("a refused rollback reached the update service", updates.rollbacks)
	}
	// The service's own refusals become specific answers.
	for cause, want := range map[error]int{ErrUpdateBusy: 409, ErrUpdateNotPending: 409, ErrUpdateNoRelease: 409, ErrUpdateUnsupported: 501, errors.New("installer exploded at /fake/path"): 500} {
		updates.err = fmt.Errorf("wrapped: %w", cause)
		w := call(t, h, "/admin/api/v1/update/rollback", "POST", map[string]string{"release_id": "fake-release-1"}, cookie, csrf, origin)
		if w.Code != want {
			t.Errorf("%v: %d, want %d", cause, w.Code, want)
		}
		if strings.Contains(w.Body.String(), "/fake/path") {
			t.Error("an internal error text reached the page")
		}
	}
	updates.err, updates.rollbacks = nil, 0
	w := call(t, h, "/admin/api/v1/update/rollback", "POST", map[string]string{"release_id": "fake-release-1"}, cookie, csrf, origin)
	if w.Code != 202 || updates.rollbacks != 1 || updates.asked != "fake-release-1" {
		t.Fatal("rollback of the unconfirmed update", w.Code, updates.rollbacks, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"restart_pending":true`) || strings.Contains(w.Body.String(), `"can_rollback":true`) {
		t.Fatal("the answer after a rollback still offers one", w.Body.String())
	}
	if len(logged) == 0 || !strings.Contains(logged[len(logged)-1], "fake-release-1") {
		t.Fatal("a rollback was not recorded in the device log", logged)
	}
	// There is no upload, apply or confirm here, under any method.
	for _, path := range []string{"update/apply", "update/confirm", "update/manifest", "update/artifact", "ota/apply", "ota/confirm", "ota/manifest", "ota/artifact"} {
		for _, method := range []string{"POST", "PUT"} {
			inner := http.NewServeMux() // a device API with no such route, as in the agent
			if got := call(t, a.Wrap(inner), "/admin/api/v1/"+path, method, map[string]string{"release_id": "fake-release-1"}, cookie, csrf, origin).Code; got != 404 && got != 405 {
				t.Errorf("%s %s answered %d", method, path, got)
			}
		}
	}
}

func TestSecurityPageWithoutASourceSaysUnknownNotFine(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	a, h, cookie, _ := configured(t, c, &spy{})
	var report SecurityReport
	w := get(h, "/admin/api/v1/security", cookie, false)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &report) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	for name, value := range map[string]string{"fingerprint": report.IdentityFingerprint, "level": report.SecurityLevel, "pq": report.PQIdentity.Status, "paired": report.Owner.Paired, "pinned": report.Owner.PQPinned, "certificate": report.AdminTLS.FingerprintSHA256} {
		if value != Unknown {
			t.Errorf("%s = %q without any evidence", name, value)
		}
	}
	if report.AdminTLS.NotAfter != nil || report.Owner.CoreID != "" {
		t.Error("invented a certificate expiry or an owner")
	}
	// Partial evidence stays partial.
	a.Attach(Sources{Security: func() SecurityReport {
		return SecurityReport{DeviceID: "test-device", SecurityLevel: "PQ", PQIdentity: PQIdentityReport{Status: "active"}, Owner: OwnerReport{Paired: "yes", PQPinned: "yes"}}
	}})
	_ = json.Unmarshal(get(h, "/admin/api/v1/security", cookie, false).Body.Bytes(), &report)
	if report.SecurityLevel != "PQ" || report.PQIdentity.Algorithm != Unknown || report.PQIdentity.Fingerprint != Unknown || report.Owner.CoreID != Unknown || report.Owner.CoreFingerprint != Unknown || report.Owner.PQFingerprint != Unknown {
		t.Fatalf("missing facts were not reported as unknown: %+v", report)
	}
}

func TestWiFiAndSMSInputIsValidatedBeforeTheDeviceSeesIt(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	api := &spy{status: 202}
	_, h, cookie, csrf := configured(t, c, api)
	hex64 := strings.Repeat("0123456789abcdef", 4)
	wifi := []struct {
		name               string
		ssid, psk, mode    string
		ok                 bool
		messageMustContain string
	}{
		{"plain wpa2", "FakeNet", "fake-pass-1234", "wpa2", true, ""},
		{"eight characters", "FakeNet", "12345678", "wpa2", true, ""},
		{"sixty-three characters", "FakeNet", strings.Repeat("a", 63), "wpa3", true, ""},
		{"sixty-four hex", "FakeNet", hex64, "wpa2", true, ""},
		{"open", "FakeNet", "", "open", true, ""},
		{"32-byte ssid", strings.Repeat("s", 32), "fake-pass-1234", "wpa2", true, ""},
		{"empty ssid", "  ", "fake-pass-1234", "wpa2", false, "SSID"},
		{"33-byte ssid", strings.Repeat("s", 33), "fake-pass-1234", "wpa2", false, "32 字节"},
		{"11 CJK characters are 33 bytes", strings.Repeat("网", 11), "fake-pass-1234", "wpa2", false, "32 字节"},
		{"control character in ssid", "Fake\nNet", "fake-pass-1234", "wpa2", false, "控制字符"},
		{"no passphrase", "FakeNet", "", "wpa2", false, "密码"},
		{"seven characters", "FakeNet", "1234567", "wpa2", false, "至少 8 位"},
		{"sixty-four not hex", "FakeNet", strings.Repeat("z", 64), "wpa2", false, "十六进制"},
		{"sixty-four hex for wpa3", "FakeNet", hex64, "wpa3", false, "WPA2"},
		{"sixty-five characters", "FakeNet", strings.Repeat("a", 65), "wpa2", false, "最多 63 位"},
		{"control character in passphrase", "FakeNet", "fake\tpass-1234", "wpa2", false, "控制字符"},
		{"passphrase on an open network", "FakeNet", "fake-pass-1234", "open", false, "开放网络"},
		{"no security chosen", "FakeNet", "fake-pass-1234", "", false, "加密方式"},
		{"unknown security", "FakeNet", "fake-pass-1234", "wep", false, "加密方式"},
	}
	for _, tc := range wifi {
		before := api.calls
		w := call(t, h, "/admin/api/v1/wifi/connect", "POST", map[string]string{"ssid": tc.ssid, "psk": tc.psk, "security": tc.mode}, cookie, csrf, origin)
		switch {
		case tc.ok && (w.Code != 202 || api.calls != before+1):
			t.Errorf("wifi %s: refused (%d %s)", tc.name, w.Code, w.Body.String())
		case !tc.ok && (w.Code != 400 || api.calls != before || !strings.Contains(w.Body.String(), tc.messageMustContain)):
			t.Errorf("wifi %s: %d, device calls %d, body %s", tc.name, w.Code, api.calls-before, w.Body.String())
		}
		if tc.psk != "" && strings.Contains(w.Body.String(), tc.psk) {
			t.Errorf("wifi %s: the passphrase was echoed", tc.name)
		}
	}
	sms := []struct {
		name, id, to, text string
		ok                 bool
		messageMustContain string
	}{
		{"plain", "fake-request-1", "10000", "simulated text", true, ""},
		{"international", "fake-request-2", "+99900000000123", "模拟短信", true, ""},
		{"largest body", "fake-request-3", "10000", strings.Repeat("a", maxSMSBytes), true, ""},
		{"no request id", "", "10000", "simulated text", false, "请求编号"},
		{"request id with a space", "fake request", "10000", "simulated text", false, "请求编号"},
		{"no recipient", "fake-request-4", "", "simulated text", false, "收件号码"},
		{"recipient with a space", "fake-request-4", "100 00", "simulated text", false, "3 至 20 位"},
		{"recipient with letters", "fake-request-4", "FAKEBANK", "simulated text", false, "3 至 20 位"},
		{"recipient too long", "fake-request-4", strings.Repeat("9", 21), "simulated text", false, "3 至 20 位"},
		{"blank body", "fake-request-4", "10000", " \n ", false, "短信内容"},
		{"body one byte too long", "fake-request-4", "10000", strings.Repeat("a", maxSMSBytes+1), false, "4096 字节"},
		{"CJK body over the byte limit", "fake-request-4", "10000", strings.Repeat("字", maxSMSBytes/3+1), false, "4096 字节"},
	}
	for _, tc := range sms {
		before := api.calls
		w := call(t, h, "/admin/api/v1/sms/send", "POST", map[string]string{"request_id": tc.id, "to": tc.to, "text": tc.text}, cookie, csrf, origin)
		switch {
		case tc.ok && api.calls != before+1:
			t.Errorf("sms %s: refused (%d %s)", tc.name, w.Code, w.Body.String())
		case !tc.ok && (w.Code != 400 || api.calls != before || !strings.Contains(w.Body.String(), tc.messageMustContain)):
			t.Errorf("sms %s: %d, device calls %d, body %.120s", tc.name, w.Code, api.calls-before, w.Body.String())
		case tc.ok:
			// Forwarded exactly once, with the request id the page chose.
			last := api.bodies[len(api.bodies)-1]
			if !strings.HasPrefix(last, "POST /v1/sms/send ") || !strings.Contains(last, `"request_id":"`+tc.id+`"`) {
				t.Errorf("sms %s: forwarded as %.120s", tc.name, last)
			}
		}
	}
	// An unknown field is refused rather than silently dropped.
	if w := call(t, h, "/admin/api/v1/sms/send", "POST", map[string]string{"request_id": "fake-request-5", "to": "10000", "text": "x", "retry": "3"}, cookie, csrf, origin); w.Code != 400 {
		t.Error("unknown field accepted", w.Code)
	}
}

// fakeRadio is a Wi-Fi backend reduced to the state it reports.
type fakeRadio struct {
	status proto.WiFiStatus
	err    error
}

func (f *fakeRadio) Status(context.Context) (proto.WiFiStatus, error) { return f.status, f.err }

func TestWiFiOutcomeIsReadFromTheRadioAndNeverAssumed(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	api := &spy{status: 202}
	a, h, cookie, csrf := configured(t, c, api)
	radio := &fakeRadio{status: proto.WiFiStatus{State: proto.WiFiConnected, SSID: "FakeOld", SavedSSID: "FakeOld"}}
	a.Attach(Sources{WiFi: radio})
	outcome := func() wifiOutcomeView {
		var view wifiOutcomeView
		w := get(h, "/admin/api/v1/wifi/change", cookie, true)
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		return view
	}
	if view := outcome(); view.Outcome != "none" || !view.Settled {
		t.Fatal("an outcome before any change", view)
	}
	connect := func() {
		if w := call(t, h, "/admin/api/v1/wifi/connect", "POST", map[string]string{"ssid": "FakeNew", "psk": "fake-pass-1234", "security": "wpa2"}, cookie, csrf, origin); w.Code != 202 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	connect()
	steps := []struct {
		name    string
		status  proto.WiFiStatus
		err     error
		advance time.Duration
		outcome string
		settled bool
	}{
		{"joining", proto.WiFiStatus{State: proto.WiFiConnecting, SSID: "FakeNew"}, nil, time.Second, "pending", false},
		{"failed, recovering", proto.WiFiStatus{State: proto.WiFiFailed, FailureReason: "authentication failed"}, nil, 10 * time.Second, "failed", false},
		{"radio unreadable", proto.WiFiStatus{}, errors.New("backend down"), time.Second, "unknown", false},
		{"wifi down, saved profile kept", proto.WiFiStatus{State: proto.WiFiNoConfig, SavedSSID: "FakeOld"}, nil, time.Second, "not_connected", false},
		{"back on the old network", proto.WiFiStatus{State: proto.WiFiConnected, SSID: "FakeOld", SavedSSID: "FakeOld"}, nil, time.Second, "restored", true},
		{"setup access point", proto.WiFiStatus{State: proto.WiFiProvisioningAP, APSSID: "NasSimHub-0000", SavedSSID: "FakeOld"}, nil, time.Second, "provisioning_ap", true},
		{"on the new network", proto.WiFiStatus{State: proto.WiFiConnected, SSID: "FakeNew", SavedSSID: "FakeNew"}, nil, time.Second, "connected", true},
		{"on some third network", proto.WiFiStatus{State: proto.WiFiConnected, SSID: "FakeOther"}, nil, time.Second, "unknown", true},
		{"still down when the window closes", proto.WiFiStatus{State: proto.WiFiNoConfig, SavedSSID: "FakeOld"}, nil, wifiSettleWindow, "not_connected", true},
		{"still joining when the window closes", proto.WiFiStatus{State: proto.WiFiConnecting, SSID: "FakeNew"}, nil, time.Second, "unknown", true},
		// Recomputed on every read: a late recovery is still reported.
		{"recovered after the window", proto.WiFiStatus{State: proto.WiFiConnected, SSID: "FakeOld", SavedSSID: "FakeOld"}, nil, time.Minute, "restored", true},
	}
	for _, step := range steps {
		c.advance(step.advance)
		radio.status, radio.err = step.status, step.err
		view := outcome()
		if view.Outcome != step.outcome || view.Settled != step.settled {
			t.Errorf("%s: outcome %q settled %t, want %q %t", step.name, view.Outcome, view.Settled, step.outcome, step.settled)
		}
		if view.TargetSSID != "FakeNew" || view.PreviousSSID != "FakeOld" {
			t.Errorf("%s: lost track of the change: %+v", step.name, view)
		}
	}
	if strings.Contains(get(h, "/admin/api/v1/wifi/change", cookie, true).Body.String(), "fake-pass-1234") {
		t.Fatal("the passphrase was kept")
	}
	// A change the device refused is not remembered as a change.
	radio.status = proto.WiFiStatus{State: proto.WiFiConnected, SSID: "FakeOld", SavedSSID: "FakeOld"}
	api.status = 409
	if w := call(t, h, "/admin/api/v1/wifi/connect", "POST", map[string]string{"ssid": "FakeRefused", "psk": "fake-pass-1234", "security": "wpa2"}, cookie, csrf, origin); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if view := outcome(); view.TargetSSID != "FakeNew" {
		t.Fatal("a refused change replaced the record", view)
	}
	// Forgetting: the device says where it ended up.
	api.status = 200
	if w := call(t, h, "/admin/api/v1/wifi/forget", "POST", map[string]string{}, cookie, csrf, origin); w.Code != 200 {
		t.Fatal(w.Code)
	}
	radio.status = proto.WiFiStatus{State: proto.WiFiNoConfig}
	if view := outcome(); view.Outcome != "forgotten" || !view.Settled {
		t.Fatal(view)
	}
	radio.status = proto.WiFiStatus{State: proto.WiFiProvisioningAP, APSSID: "NasSimHub-0000"}
	if view := outcome(); view.Outcome != "provisioning_ap" {
		t.Fatal(view)
	}
}
