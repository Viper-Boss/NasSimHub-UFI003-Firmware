package localadmin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/netbackend"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// All values in this file are invented. Nothing here ran on a device.
const (
	fakeAPSSID       = "NasSimHub-FAKE00"
	fakeAPPassphrase = "fake-plnt-edap-pass"
	rightPassword    = "a-fake-management-password"
	revealPath       = "/admin/api/v1/wifi/setup-ap/reveal"
	setupAPPath      = "/admin/api/v1/wifi/setup-ap"
)

// fakeSetupAP is a credential source that counts how often it was asked.
type fakeSetupAP struct {
	calls int
	err   error
}

func (f *fakeSetupAP) SetupAPCredential() (string, string, error) {
	f.calls++
	if f.err != nil {
		return "", "", f.err
	}
	return fakeAPSSID, fakeAPPassphrase, nil
}

type logSink struct{ lines []string }

func (l *logSink) logf(format string, arguments ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, arguments...))
}
func (l *logSink) all() string { return strings.Join(l.lines, "\n") }

func TestSetupAPPassphraseNeedsSessionCSRFAndThePasswordAgain(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	api := &spy{}
	a, h, cookie, csrf := configured(t, c, api)
	source, logs := &fakeSetupAP{}, &logSink{}
	radio := &fakeRadio{status: proto.WiFiStatus{State: proto.WiFiProvisioningAP, ProvisioningState: proto.WiFiProvisioningAPReady}}
	a.Attach(Sources{SetupAP: source, WiFi: radio, Logf: logs.logf})
	right := map[string]string{"current_password": rightPassword}
	wrong := map[string]string{"current_password": "a-wrong-fake-password"}

	// Without a session, without the token, from elsewhere: refused before
	// the source is asked, even with the right password in the body.
	for name, attempt := range map[string]struct {
		cookie *http.Cookie
		csrf   string
		origin string
		want   int
	}{
		"no session":   {nil, csrf, origin, 401},
		"no token":     {cookie, "", origin, 403},
		"wrong token":  {cookie, strings.Repeat("A", len(csrf)), origin, 403},
		"cross origin": {cookie, csrf, "https://elsewhere.test", 403},
	} {
		w := call(t, h, revealPath, "POST", right, attempt.cookie, attempt.csrf, attempt.origin)
		if w.Code != attempt.want || strings.Contains(w.Body.String(), fakeAPPassphrase) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	if w := get(h, setupAPPath, nil, false); w.Code != 401 {
		t.Error("the access point section answered without a session", w.Code)
	}
	if w := get(h, revealPath, cookie, false); w.Code != 405 || strings.Contains(w.Body.String(), fakeAPPassphrase) {
		t.Error("the passphrase route answered a GET", w.Code)
	}
	if source.calls != 0 {
		t.Fatal("a refused request reached the credential source", source.calls)
	}

	// The section itself names the access point and never carries the passphrase.
	var view setupAPView
	w := get(h, setupAPPath, cookie, false)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	if !view.Available || view.SSID != fakeAPSSID || view.ProvisioningState != proto.WiFiProvisioningAPReady {
		t.Fatal("section", view)
	}
	if strings.Contains(w.Body.String(), fakeAPPassphrase) || strings.Contains(w.Body.String(), "passphrase") {
		t.Fatal("the section carries the passphrase", w.Body.String())
	}
	for _, path := range []string{"/admin/session", "/", "/admin/app.js", "/admin/api/v1/security", "/admin/api/v1/wifi/change"} {
		if strings.Contains(get(h, path, cookie, false).Body.String(), fakeAPPassphrase) {
			t.Errorf("%s carries the passphrase", path)
		}
	}
	asked := source.calls

	// A session is not enough: the password is checked, on the device.
	for _, body := range []map[string]string{wrong, {"current_password": ""}, {}, {"current_password": strings.Repeat("x", 300)}} {
		if w = call(t, h, revealPath, "POST", body, cookie, csrf, origin); w.Code != 401 || strings.Contains(w.Body.String(), fakeAPPassphrase) {
			t.Fatal("wrong password", w.Code, w.Body.String())
		}
	}
	// The setup proof is not a way in, nor is any field but the password.
	if w = call(t, h, revealPath, "POST", map[string]string{"setup_code": "x", "current_password": rightPassword}, cookie, csrf, origin); w.Code != 400 {
		t.Fatal("an unknown field was accepted", w.Code)
	}
	if source.calls != asked {
		t.Fatal("a wrong password reached the credential source")
	}
	// Four wrong passwords so far; the fifth locks, exactly as at sign-in.
	if a.failures != lockoutThreshold-1 {
		t.Fatal("wrong passwords were not counted", a.failures)
	}
	if w = call(t, h, revealPath, "POST", wrong, cookie, csrf, origin); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w = call(t, h, revealPath, "POST", right, cookie, csrf, origin); w.Code != 429 || w.Header().Get("Retry-After") == "" || strings.Contains(w.Body.String(), fakeAPPassphrase) {
		t.Fatal("the right password was looked at while locked", w.Code, w.Body.String())
	}
	if w = call(t, h, "/admin/login", "POST", map[string]string{"password": rightPassword}, nil, "", origin); w.Code != 429 {
		t.Fatal("guessing through the passphrase form did not lock sign-in", w.Code)
	}
	if source.calls != asked {
		t.Fatal("a locked request reached the credential source")
	}
	// A wrong password does not end the session.
	if w = get(h, "/admin/api/v1/status", cookie, false); w.Code != 204 {
		t.Fatal(w.Code)
	}

	c.advance(lockoutBase)
	w = call(t, h, revealPath, "POST", right, cookie, csrf, origin)
	var secret setupAPSecret
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &secret) != nil || secret.SSID != fakeAPSSID || secret.Passphrase != fakeAPPassphrase {
		t.Fatal("the owner was refused the passphrase", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", w.Header().Get("Cache-Control"))
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("revealing the passphrase changed the session")
	}
	if source.calls != asked+1 {
		t.Fatal("the passphrase was read more than once for one request", source.calls-asked)
	}
	// A success clears the count, as a sign-in does.
	if a.failures != 0 {
		t.Error("the failure count survived a correct password", a.failures)
	}
	// It is recorded that it happened, and not what it was.
	recorded := logs.all()
	for _, want := range []string{"passphrase request refused", "locked for", "passphrase shown in the local console"} {
		if !strings.Contains(recorded, want) {
			t.Errorf("the log lost the event %q:\n%s", want, recorded)
		}
	}
	for name, secret := range map[string]string{"passphrase": fakeAPPassphrase, "password": rightPassword, "wrong password": "a-wrong-fake-password", "csrf": csrf, "cookie": cookie.Value} {
		if strings.Contains(recorded, secret) {
			t.Errorf("the log contains the %s", name)
		}
	}
	// Nothing was kept: the next reader of anything else still gets nothing.
	if stored := fmt.Sprintf("%+v", a.sources.WiFi) + fmt.Sprintf("%+v", a.change) + fmt.Sprintf("%+v", a.sessions); strings.Contains(stored, fakeAPPassphrase) {
		t.Error("the passphrase was kept in the console's state")
	}
	if api.calls != 1 {
		t.Error("the device API saw a passphrase request", api.bodies)
	}
}

// First-time setup must stay exactly as it was: there is no session before a
// password exists, and the setup proof opens nothing here.
func TestSetupAPPassphraseIsNotReachableDuringFirstTimeSetup(t *testing.T) {
	a, err := Open(Options{Dir: t.TempDir(), DeviceID: "test-device"})
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeSetupAP{}
	a.Attach(Sources{SetupAP: source})
	h := a.Wrap(&spy{})
	proof := a.bootstrap
	for _, body := range []map[string]string{{"current_password": proof}, {"current_password": ""}, {"setup_code": proof}} {
		if w := call(t, h, revealPath, "POST", body, nil, proof, origin); w.Code != 401 || strings.Contains(w.Body.String(), fakeAPPassphrase) {
			t.Fatal(body, w.Code, w.Body.String())
		}
	}
	if w := get(h, setupAPPath, nil, false); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if source.calls != 0 {
		t.Fatal("the credential source was asked before anyone owned the device")
	}
	if configured, kept := a.OwnerSetup(); configured || kept != proof || a.failures != 0 {
		t.Fatal("first-time setup was disturbed", configured, a.failures)
	}
}

func TestSetupAPWithoutASourceOrSwitchedOffSaysSo(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	a, h, cookie, csrf := configured(t, c, &spy{})
	status := func() setupAPView {
		var view setupAPView
		w := get(h, setupAPPath, cookie, false)
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		return view
	}
	reveal := func(password string) (int, string) {
		w := call(t, h, revealPath, "POST", map[string]string{"current_password": password}, cookie, csrf, origin)
		return w.Code, w.Body.String()
	}

	// No credential source at all: explicitly unsupported, never an empty answer.
	a.Attach(Sources{})
	if view := status(); view.Available || view.Reason != setupAPNoSource || view.SSID != "" {
		t.Fatal("no source", view)
	}
	for i := 0; i < lockoutThreshold+1; i++ {
		if code, body := reveal("a-wrong-fake-password"); code != 501 || !strings.Contains(body, `"not_supported"`) {
			t.Fatal("no source", code, body)
		}
	}
	// Asking a device that has nothing to show is not password guessing.
	if a.failures != 0 || a.locked() != 0 {
		t.Fatal("an unsupported request counted towards the lock", a.failures)
	}

	// Switched off in the configuration: said so, and the source is not asked,
	// because asking is what would create a passphrase for it.
	source := &fakeSetupAP{}
	radio := &fakeRadio{status: proto.WiFiStatus{State: proto.WiFiNoConfig, ProvisioningState: proto.WiFiProvisioningDisabled}}
	a.Attach(Sources{SetupAP: source, WiFi: radio})
	if view := status(); view.Available || view.Reason != setupAPOff || view.SSID != "" || view.ProvisioningState != proto.WiFiProvisioningDisabled {
		t.Fatal("off", view)
	}
	if code, body := reveal(rightPassword); code != 409 || !strings.Contains(body, setupAPOff) || strings.Contains(body, fakeAPPassphrase) {
		t.Fatal("off", code, body)
	}
	if source.calls != 0 {
		t.Fatal("a switched-off access point was asked for its credential", source.calls)
	}

	// AP_FAILED is not "off": the credential exists and the reason travels.
	radio.status = proto.WiFiStatus{State: proto.WiFiNoConfig, ProvisioningState: proto.WiFiProvisioningAPFailed, ProvisioningReason: "fake driver refused"}
	if view := status(); !view.Available || view.SSID != fakeAPSSID || view.ProvisioningReason != "fake driver refused" {
		t.Fatal("failed access point", view)
	}
	// A radio that cannot be read leaves the state unknown, and is not "off".
	radio.err = errors.New("backend down")
	if view := status(); !view.Available || view.ProvisioningState != "" {
		t.Fatal("unreadable radio", view)
	}
	if code, body := reveal(rightPassword); code != 200 || !strings.Contains(body, fakeAPPassphrase) {
		t.Fatal("unreadable radio", code)
	}

	// A source that fails: unavailable, with nothing of the backend's error
	// passed on or logged.
	logs := &logSink{}
	a.Attach(Sources{SetupAP: &fakeSetupAP{err: errors.New("fake-backend-detail-" + fakeAPPassphrase)}, Logf: logs.logf})
	if view := status(); view.Available || view.Reason != setupAPUnavailable {
		t.Fatal("failing source", view)
	}
	code, body := reveal(rightPassword)
	if code != 503 || strings.Contains(body, "fake-backend-detail") || strings.Contains(logs.all(), "fake-backend-detail") {
		t.Fatal("failing source", code, body, logs.all())
	}
	if !strings.Contains(logs.all(), "could not be read") {
		t.Error("the failure is not in the log")
	}
}

func script(t *testing.T) string {
	t.Helper()
	b, err := assets.ReadFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The page has words for every provisioning state the backend can report. The
// names are read from netbackend, so a state added there without a label here
// fails this test instead of showing its raw name to the owner.
func TestEveryProvisioningStateHasALabel(t *testing.T) {
	js := script(t)
	table := regexp.MustCompile(`(?s)provisioningStates: \{(.*?)\n\s*\},`).FindStringSubmatch(js)
	if table == nil {
		t.Fatal("app.js has no provisioningStates table")
	}
	if len(netbackend.States) < 10 {
		t.Fatal("the state table was not read", len(netbackend.States))
	}
	labels := map[string]string{}
	for _, entry := range regexp.MustCompile(`(?m)^\s*([A-Z_]+): '([^']+)',$`).FindAllStringSubmatch(table[1], -1) {
		labels[entry[1]] = entry[2]
	}
	for state := range netbackend.States {
		if strings.TrimSpace(labels[string(state)]) == "" {
			t.Errorf("app.js has no label for provisioning state %s", state)
		}
	}
	for name := range labels {
		if _, ok := netbackend.States[proto.WiFiProvisioningState(name)]; !ok {
			t.Errorf("app.js labels %s, which is not a state of the backend", name)
		}
	}
	// The two states whose wording the owner acts on.
	if labels[string(proto.WiFiProvisioningDisabled)] != "配网热点已关闭：通过 USB 配置 Wi-Fi" {
		t.Errorf("DISABLED reads %q", labels[string(proto.WiFiProvisioningDisabled)])
	}
	if !strings.Contains(labels[string(proto.WiFiProvisioningAPFailed)], "USB") {
		t.Error("AP_FAILED does not say that USB still works")
	}
	// The state and its reason are read from the status document, and an
	// absent state has its own words rather than one of the labels.
	for _, want := range []string{"provisioning_state", "provisioning_reason", "provisioningUnknown", "provisioningOther"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js does not use %s", want)
		}
	}
}

// Scan results are marked, not hidden, and a cached list says it is cached.
func TestScanSupportMarksAndCacheNoticeAreRendered(t *testing.T) {
	js := script(t)
	table := regexp.MustCompile(`(?s)\n\s*support: \{(.*?)\n\s*\},`).FindStringSubmatch(js)
	if table == nil {
		t.Fatal("app.js has no support table")
	}
	for _, support := range []proto.WiFiSupport{proto.WiFiSupportVerified, proto.WiFiSupportUnverified, proto.WiFiSupportUnsupported} {
		if !regexp.MustCompile(`\b` + string(support) + `: '[^']+'`).MatchString(table[1]) {
			t.Errorf("no label for support %q", support)
		}
	}
	for _, want := range []string{"unknown: '", "band5: '5 GHz'", "wpa3: '纯 WPA3'", "enterprise: '企业级"} {
		if !strings.Contains(table[1], want) {
			t.Errorf("support table lacks %s", want)
		}
	}
	for _, want := range []string{"n.support_reason", "d.from_cache", "d.scanned_at", "'scan-note'"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js does not use %s", want)
		}
	}
	// No promise that a network of any kind will work.
	for _, claim := range []string{"一定可用", "保证可用", "可以正常连接", "完全支持"} {
		if strings.Contains(js, claim) {
			t.Errorf("app.js promises %q", claim)
		}
	}
	// Nothing filters the list by support: the only use of the mark is to label.
	if regexp.MustCompile(`networks[^;\n]*\.filter\(`).MatchString(js) {
		t.Error("scan results are filtered")
	}
}

// jsonNames collects the JSON field names of a type and of everything it holds.
func jsonNames(kind reflect.Type, into map[string]bool) {
	for kind.Kind() == reflect.Pointer || kind.Kind() == reflect.Slice {
		kind = kind.Elem()
	}
	if kind.Kind() != reflect.Struct || kind == reflect.TypeOf(time.Time{}) {
		return
	}
	for i := 0; i < kind.NumField(); i++ {
		field := kind.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		into[name] = true
		jsonNames(field.Type, into)
	}
}

// The overview claims to render the device's telemetry. Every field of the
// telemetry types is looked for in the script by its JSON name, taken from
// proto by reflection: a field added to the protocol and not to the page
// fails here.
func TestOverviewReferencesEveryTelemetryField(t *testing.T) {
	js := script(t)
	resources := reflect.TypeOf(proto.SystemResources{})
	names := map[string]bool{}
	for _, field := range []string{"ProcessScanTruncated", "ThreadCount", "CPU", "ThermalZones", "Memory", "Storage", "EMMC", "Interfaces", "Agent", "BootID", "Cell"} {
		found, ok := resources.FieldByName(field)
		if !ok {
			t.Fatalf("proto.SystemResources has no field %s", field)
		}
		names[strings.Split(found.Tag.Get("json"), ",")[0]] = true
		jsonNames(found.Type, names)
	}
	if len(names) < 50 {
		t.Fatal("the telemetry types were not walked", len(names))
	}
	for name := range names {
		if !regexp.MustCompile(`\.` + name + `\b`).MatchString(js) {
			t.Errorf("app.js does not read the telemetry field %q", name)
		}
	}
	// Absent is "unknown": the telemetry renderer has no fallback to a number.
	body := regexp.MustCompile(`(?s)function renderTelemetry\(.*?\n\}`).FindString(js)
	if body == "" {
		t.Fatal("app.js has no renderTelemetry")
	}
	if regexp.MustCompile(`\|\|\s*0\b|\?\?\s*0\b`).MatchString(body) {
		t.Error("renderTelemetry substitutes 0 for a missing value")
	}
	if strings.Count(body, "T.unknown")+strings.Count(body, "orUnknown(")+strings.Count(body, "size(")+strings.Count(body, "rate(") < 30 {
		t.Error("renderTelemetry does not route its values through the unknown-aware formatters")
	}
	// The eMMC codes carry their meaning, and a zone is not called the CPU's.
	for _, want := range []string{"(n - 1) * 10", "to: n * 10", "1: '{code}：正常'", "2: '{code}：警告", "3: '{code}：紧急'", "z.type ?", "zoneUntyped"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
	if strings.Contains(body, "CPU 温度") || strings.Contains(body, "cpuTemp") {
		t.Error("renderTelemetry names a thermal zone itself")
	}
	// One timer drives the overview; telemetry added none.
	if n := strings.Count(js, "setInterval("); n != 1 {
		t.Errorf("app.js has %d intervals, want the session check alone", n)
	}
	if n := len(regexp.MustCompile(`api\('status'`).FindAllString(js, -1)); n != 1 {
		t.Errorf("the status document is requested from %d places", n)
	}
}

// What the page does with the passphrase, as far as a reading of the script
// can show it. Behaviour in a browser is not tested here.
func TestPageNeverKeepsTheSetupAPPassphrase(t *testing.T) {
	js := script(t)
	page, err := assets.ReadFile("index.html")
	if err != nil {
		t.Fatal(err)
	}
	// It is read from the response once, straight into its element.
	uses := regexp.MustCompile(`[^\n]*\.passphrase\b[^\n]*`).FindAllString(js, -1)
	if len(uses) != 1 || !strings.Contains(uses[0], "$('setup-ap-passphrase').textContent = d.passphrase;") {
		t.Fatal("the passphrase is read somewhere other than its one element", uses)
	}
	hide := regexp.MustCompile(`(?s)function hideSetupAP\(.*?\n\}`).FindString(js)
	for _, want := range []string{"$('setup-ap-passphrase').textContent = ''", "$('setup-ap-form').reset()", "clearTimeout(apTimer)", "apRequest++"} {
		if !strings.Contains(hide, want) {
			t.Errorf("hideSetupAP lacks %s", want)
		}
	}
	// Closed on logout and expiry (wipe), on leaving the page, and by a timer.
	for name, pattern := range map[string]string{
		"wipe":      `(?s)function wipe\(\) \{.*?hideSetupAP\(\);.*?\n\}`,
		"switchTab": `(?s)async function switchTab\(.*?hideSetupAP\(\);.*?\n\}`,
		"timer":     `apTimer = setTimeout\(\(\) => hideSetupAP\(`,
		"button":    `\$\('setup-ap-hide'\)\.addEventListener\('click', \(\) => \{\s*hideSetupAP\(`,
	} {
		if !regexp.MustCompile(pattern).MatchString(js) {
			t.Errorf("the passphrase is not cleared by %s", name)
		}
	}
	// The password typed to see it is sent in the body of a POST and dropped.
	if !strings.Contains(js, "api('wifi/setup-ap/reveal', { body: { current_password: password } })") {
		t.Error("the reveal request is not the expected POST")
	}
	html := string(page)
	if !strings.Contains(html, `<span class="mono" id="setup-ap-passphrase"></span>`) {
		t.Error("the passphrase element is missing or not empty in the page")
	}
	if !regexp.MustCompile(`<div id="setup-ap-secret" hidden>`).MatchString(html) || !regexp.MustCompile(`<form id="setup-ap-form" novalidate hidden>`).MatchString(html) {
		t.Error("the passphrase section is not closed to begin with")
	}
	// The saved-network promise the backend now keeps is stated before submit.
	for _, want := range []string{"切换失败后设备回到已保存的网络，而不是回到配网热点", "https://10.55.0.2:7581 不受 Wi-Fi 变更影响"} {
		if !strings.Contains(js, want) {
			t.Errorf("the Wi-Fi safety text lacks %q", want)
		}
	}
}
