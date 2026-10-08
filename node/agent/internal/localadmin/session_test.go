package localadmin

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// clock is an injected time source; tests move it instead of sleeping.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

// spy is a device API that only counts what reached it.
type spy struct {
	calls  int
	bodies []string
	status int
}

func (s *spy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.calls++
	b := make([]byte, 1<<16)
	n, _ := r.Body.Read(b)
	s.bodies = append(s.bodies, r.Method+" "+r.URL.Path+" "+string(b[:n]))
	status := s.status
	if status == 0 {
		status = 204
	}
	w.WriteHeader(status)
}

const origin = "https://device.test"

var tlsState = &tls.ConnectionState{}

func configured(t *testing.T, c *clock, api http.Handler) (*Admin, http.Handler, *http.Cookie, string) {
	t.Helper()
	a, err := Open(Options{Dir: t.TempDir(), DeviceID: "test-device", Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Wrap(api)
	w := call(t, h, "/admin/login", "POST", map[string]string{"password": "a-fake-management-password", "setup_code": a.bootstrap}, nil, "", origin)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	return a, h, w.Result().Cookies()[0], result["csrf"]
}

// get is an authenticated read; passive marks it as the page's own polling.
func get(h http.Handler, path string, cookie *http.Cookie, passive bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "https://device.test"+path, nil)
	r.TLS = tlsState
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if passive {
		r.Header.Set(passiveHeader, "1")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestSessionExpiresWhenIdle(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	_, h, cookie, _ := configured(t, c, &spy{})
	// Activity slides the idle limit.
	for i := 0; i < 3; i++ {
		c.advance(idleLifetime - time.Minute)
		if w := get(h, "/admin/api/v1/status", cookie, false); w.Code != 204 {
			t.Fatalf("active session refused after %d periods: %d", i+1, w.Code)
		}
	}
	// The page's own polling is answered but is not activity.
	c.advance(idleLifetime - time.Minute)
	if w := get(h, "/admin/api/v1/status", cookie, true); w.Code != 204 {
		t.Fatal("passive request refused inside the idle limit", w.Code)
	}
	c.advance(2 * time.Minute)
	w := get(h, "/admin/api/v1/status", cookie, true)
	if w.Code != 401 || !strings.Contains(w.Body.String(), `"session_expired"`) {
		t.Fatal("polling kept an idle session alive", w.Code, w.Body.String())
	}
	if w = get(h, "/admin/api/v1/status", cookie, false); w.Code != 401 {
		t.Fatal("an expired session came back", w.Code)
	}
	var state struct{ Authenticated bool }
	_ = json.Unmarshal(get(h, "/admin/session", cookie, false).Body.Bytes(), &state)
	if state.Authenticated {
		t.Fatal("session probe reports an expired session as signed in")
	}
}

func TestSessionProbeIsNotActivity(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	_, h, cookie, _ := configured(t, c, &spy{})
	for i := 0; i < 4; i++ {
		c.advance(idleLifetime / 3)
		if i < 2 {
			if w := get(h, "/admin/session", cookie, false); !strings.Contains(w.Body.String(), `"authenticated":true`) {
				t.Fatal("probe inside the idle limit", w.Body.String())
			}
		}
	}
	if w := get(h, "/admin/api/v1/status", cookie, false); w.Code != 401 {
		t.Fatal("asking whether a session exists extended it", w.Code)
	}
}

func TestSessionExpiresAbsolutelyHoweverBusy(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	_, h, cookie, csrf := configured(t, c, &spy{})
	step := idleLifetime / 2
	for elapsed := step; elapsed < absoluteLifetime; elapsed += step {
		c.advance(step)
		if w := get(h, "/admin/api/v1/status", cookie, false); w.Code != 204 {
			t.Fatalf("busy session refused at %s: %d", elapsed, w.Code)
		}
	}
	c.advance(step)
	if w := get(h, "/admin/api/v1/status", cookie, false); w.Code != 401 {
		t.Fatal("session outlived the absolute limit", w.Code)
	}
	if w := call(t, h, "/admin/api/v1/wifi/scan", "POST", nil, cookie, csrf, origin); w.Code != 401 {
		t.Fatal("expired session could still change state", w.Code)
	}
	if cookie.MaxAge != int(absoluteLifetime.Seconds()) {
		t.Fatal("cookie outlives or undercuts the server-side limit", cookie.MaxAge)
	}
}

func TestSessionTableIsBoundedAndEvictsTheLeastRecentlyUsed(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	a, h, first, _ := configured(t, c, &spy{})
	var last *http.Cookie
	for i := 0; i < maxSessions+8; i++ {
		c.advance(time.Second)
		w := call(t, h, "/admin/login", "POST", map[string]string{"password": "a-fake-management-password"}, nil, "", origin)
		if w.Code != 200 {
			t.Fatal(i, w.Code)
		}
		last = w.Result().Cookies()[0]
	}
	if len(a.sessions) != maxSessions {
		t.Fatal("session table not bounded", len(a.sessions))
	}
	if w := get(h, "/admin/api/v1/status", last, false); w.Code != 204 {
		t.Fatal("newest session was dropped", w.Code)
	}
	if w := get(h, "/admin/api/v1/status", first, false); w.Code != 401 {
		t.Fatal("oldest session survived eviction", w.Code)
	}
}

func TestLockoutBacksOffAndIgnoresTheCredentialWhileLocked(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	_, h, cookie, csrf := configured(t, c, &spy{})
	attempt := func(password string) *httptest.ResponseRecorder {
		return call(t, h, "/admin/login", "POST", map[string]string{"password": password}, nil, "", origin)
	}
	for i := 0; i < lockoutThreshold; i++ {
		if w := attempt("a-wrong-fake-password"); w.Code != 401 {
			t.Fatal(i, w.Code)
		}
	}
	// Locked: even the right password is refused, and the answer says for how long.
	for _, wait := range []time.Duration{lockoutBase, 2 * lockoutBase, 4 * lockoutBase, 8 * lockoutBase, lockoutMax, lockoutMax} {
		w := attempt("a-fake-management-password")
		if w.Code != 429 || w.Header().Get("Retry-After") != strconv.Itoa(int(wait.Seconds())) {
			t.Fatalf("want a %s lock, got %d Retry-After=%q", wait, w.Code, w.Header().Get("Retry-After"))
		}
		if len(w.Result().Cookies()) != 0 {
			t.Fatal("a locked sign-in issued a session")
		}
		// Changing the password shares the limiter.
		if p := call(t, h, "/admin/password", "POST", map[string]string{"current_password": "a-fake-management-password", "password": "another-fake-password"}, cookie, csrf, origin); p.Code != 429 {
			t.Fatal("password change bypassed the lock", p.Code)
		}
		c.advance(wait - time.Second)
		if w = attempt("a-fake-management-password"); w.Code != 429 {
			t.Fatal("lock ended early", w.Code)
		}
		c.advance(time.Second)
		// One more wrong attempt after the lock ends doubles the next one.
		if w = attempt("a-wrong-fake-password"); w.Code != 401 {
			t.Fatal("attempt after the lock", w.Code)
		}
	}
	c.advance(lockoutMax)
	if w := attempt("a-fake-management-password"); w.Code != 200 {
		t.Fatal("correct password refused after the lock ended", w.Code)
	}
	// A success clears the count: one mistake afterwards does not lock.
	if w := attempt("a-wrong-fake-password"); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := attempt("a-fake-management-password"); w.Code != 200 {
		t.Fatal("one mistake after a success locked the device", w.Code)
	}
}

func TestWrongCurrentPasswordCountsTowardsTheLock(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	_, h, cookie, csrf := configured(t, c, &spy{})
	for i := 0; i < lockoutThreshold; i++ {
		w := call(t, h, "/admin/password", "POST", map[string]string{"current_password": "a-wrong-fake-password", "password": "another-fake-password"}, cookie, csrf, origin)
		if w.Code != 401 {
			t.Fatal(i, w.Code)
		}
	}
	if w := call(t, h, "/admin/login", "POST", map[string]string{"password": "a-fake-management-password"}, nil, "", origin); w.Code != 429 {
		t.Fatal("guessing through the password form was not limited", w.Code)
	}
	// A wrong current password is not a session failure: the session stands.
	if w := get(h, "/admin/api/v1/status", cookie, false); w.Code != 204 {
		t.Fatal(w.Code)
	}
}

// Every state-changing route is refused without the CSRF token, before any
// handler runs. The route table is enumerated, so a route added to it later is
// covered here without anyone writing a new case.
func TestEveryStateChangingRouteRequiresSessionAndCSRF(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	api := &spy{}
	a, h, cookie, csrf := configured(t, c, api)
	updates := &fakeUpdates{status: pendingStatus()}
	credential := &fakeSetupAP{}
	a.Attach(Sources{Updates: updates, SetupAP: credential})

	if len(unauthenticatedWrites) != 1 || !unauthenticatedWrites["/admin/login"] {
		t.Fatal("a state-changing route other than sign-in is reachable without a session", unauthenticatedWrites)
	}
	type target struct{ method, path string }
	var targets []target
	for _, r := range routes {
		if r.method != "GET" {
			targets = append(targets, target{r.method, r.path})
		}
	}
	if len(targets) < 7 {
		t.Fatal("route table was not enumerated", len(targets))
	}
	// The route that answers with a credential is in the table, and so is
	// behind the one guard like every other.
	if last := (target{"POST", "/admin/api/v1/wifi/setup-ap/reveal"}); !slices.Contains(targets, last) {
		t.Fatal("the setup access point passphrase route is not in the route table")
	}
	// The device API's own writes, and paths nobody has defined yet.
	for _, path := range []string{"/admin/api/v1/wifi/scan", "/admin/api/v1/sms/any-id", "/admin/api/v1/anything/new", "/admin/api/v2/x", "/admin/unknown", "/unknown", "/"} {
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			targets = append(targets, target{method, path})
		}
	}
	body := map[string]string{"release_id": "fake-release-1", "current_password": "a-fake-management-password", "password": "another-fake-password"}
	for _, tc := range targets {
		for name, attempt := range map[string]struct {
			cookie *http.Cookie
			csrf   string
			want   int
		}{
			"no session":     {nil, csrf, 401},
			"no token":       {cookie, "", 403},
			"wrong token":    {cookie, strings.Repeat("A", len(csrf)), 403},
			"token as query": {cookie, "", 403},
		} {
			path := tc.path
			if name == "token as query" {
				path += "?csrf=" + csrf + "&X-CSRF-Token=" + csrf
			}
			w := call(t, h, path, tc.method, body, attempt.cookie, attempt.csrf, origin)
			if w.Code != attempt.want {
				t.Errorf("%s %s with %s: got %d, want %d", tc.method, tc.path, name, w.Code, attempt.want)
			}
		}
		// And never from another origin, token or not.
		if w := call(t, h, tc.path, tc.method, body, cookie, csrf, "https://elsewhere.test"); w.Code != 403 {
			t.Errorf("%s %s cross-origin: %d", tc.method, tc.path, w.Code)
		}
	}
	if api.calls != 0 || updates.rollbacks != 0 || credential.calls != 0 {
		t.Fatal("a refused request reached a handler", api.calls, updates.rollbacks, credential.calls)
	}
	if w := get(h, "/admin/api/v1/status", cookie, false); w.Code != 204 {
		t.Fatal("refused requests ended the session or the password changed", w.Code)
	}
	// A write route does not answer a read, so a link or an image tag cannot trigger it.
	for _, r := range routes {
		if r.method == "GET" {
			continue
		}
		if w := get(h, r.path, cookie, false); w.Code != 405 && w.Code != 404 {
			t.Errorf("GET %s: %d", r.path, w.Code)
		}
	}
	if api.calls != 1 || updates.rollbacks != 0 || credential.calls != 0 {
		t.Fatal("a GET changed state", api.calls, updates.rollbacks, credential.calls)
	}
}

func TestSecurityHeadersOnEveryKindOfResponse(t *testing.T) {
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	_, h, cookie, csrf := configured(t, c, &spy{})
	responses := map[string]*httptest.ResponseRecorder{
		"page":          get(h, "/", nil, false),
		"script":        get(h, "/admin/app.js", nil, false),
		"style":         get(h, "/admin/style.css", nil, false),
		"session":       get(h, "/admin/session", nil, false),
		"api":           get(h, "/admin/api/v1/status", cookie, false),
		"own api":       get(h, "/admin/api/v1/security", cookie, false),
		"unauthorized":  get(h, "/admin/api/v1/status", nil, false),
		"not found":     get(h, "/nothing", nil, false),
		"refused write": call(t, h, "/admin/api/v1/wifi/scan", "POST", nil, cookie, "", origin),
		"failed login":  call(t, h, "/admin/login", "POST", map[string]string{"password": "a-wrong-fake-password"}, nil, "", origin),
		"write":         call(t, h, "/admin/api/v1/wifi/scan", "POST", nil, cookie, csrf, origin),
	}
	for name, w := range responses {
		header := w.Header()
		for key, want := range map[string]string{
			"Cache-Control":                "no-store",
			"X-Content-Type-Options":       "nosniff",
			"Referrer-Policy":              "no-referrer",
			"X-Frame-Options":              "DENY",
			"Cross-Origin-Resource-Policy": "same-origin",
		} {
			if header.Get(key) != want {
				t.Errorf("%s: %s = %q, want %q", name, key, header.Get(key), want)
			}
		}
		policy := header.Get("Content-Security-Policy")
		directives := map[string]string{}
		for _, part := range strings.Split(policy, ";") {
			fields := strings.Fields(part)
			if len(fields) > 0 {
				directives[fields[0]] = strings.Join(fields[1:], " ")
			}
		}
		// default-src is 'none', which is stricter than 'self'; what the page
		// needs is then allowed for this origin only.
		if d := directives["default-src"]; d != "'none'" && d != "'self'" {
			t.Errorf("%s: default-src %q", name, d)
		}
		for _, key := range []string{"script-src", "style-src", "connect-src"} {
			if directives[key] != "'self'" {
				t.Errorf("%s: %s %q", name, key, directives[key])
			}
		}
		if directives["frame-ancestors"] != "'none'" || directives["base-uri"] != "'none'" {
			t.Errorf("%s: framing or base not closed: %q", name, policy)
		}
		for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "unsafe-hashes", "*", "http:", "https:", "blob:"} {
			if strings.Contains(policy, forbidden) {
				t.Errorf("%s: policy allows %s", name, forbidden)
			}
		}
	}
}

// The page must work under that policy and must never talk to another host.
func TestAssetsAreSelfContainedAndUseNoDynamicCode(t *testing.T) {
	files := map[string]string{}
	for _, name := range []string{"index.html", "app.js", "style.css"} {
		b, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(b)
	}
	// The SVG namespace is an identifier, not a request; the other is the
	// device's own USB address, quoted in help text.
	allowed := map[string]bool{"http://www.w3.org/2000/svg": true, "https://10.55.0.2:7581": true}
	absolute := regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s'"<>)（）。，]+`)
	relative := regexp.MustCompile(`["'(=]\s*//[A-Za-z0-9]`)
	for name, content := range files {
		for _, found := range absolute.FindAllString(content, -1) {
			if !allowed[found] {
				t.Errorf("%s refers to %s", name, found)
			}
		}
		if relative.MatchString(content) {
			t.Errorf("%s has a protocol-relative reference", name)
		}
		for _, forbidden := range []string{"eval(", "new Function", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "javascript:", "@import", "@font-face", "url(", "localStorage", "sessionStorage", "indexedDB", "document.cookie", "importScripts", "XMLHttpRequest", "WebSocket", "sendBeacon"} {
			if strings.Contains(content, forbidden) {
				t.Errorf("%s contains %q", name, forbidden)
			}
		}
	}
	if regexp.MustCompile(`setTimeout\(\s*['"\x60]|setInterval\(\s*['"\x60]`).MatchString(files["app.js"]) {
		t.Error("a timer is given a string to evaluate")
	}
	page := files["index.html"]
	if regexp.MustCompile(`(?i)<script[^>]*>[^<]+</script>`).MatchString(page) || regexp.MustCompile(`(?i)<style`).MatchString(page) {
		t.Error("inline script or style, which the content security policy forbids")
	}
	if regexp.MustCompile(`(?i)\son[a-z]+\s*=|\sstyle\s*=`).MatchString(page) {
		t.Error("inline event handler or style attribute")
	}
	for _, reference := range regexp.MustCompile(`(?i)\s(?:src|href|action)="([^"]*)"`).FindAllStringSubmatch(page, -1) {
		if r := reference[1]; r != "/" && r != "#main" && !strings.HasPrefix(r, "/admin/") {
			t.Errorf("index.html loads or links %q", r)
		}
	}
	// Every element the script looks up exists, and every labelled control has its error slot.
	for _, use := range regexp.MustCompile(`\$\('([A-Za-z0-9-]+)'\)`).FindAllStringSubmatch(files["app.js"], -1) {
		if !strings.Contains(page, `id="`+use[1]+`"`) {
			t.Errorf("app.js uses #%s, which index.html does not define", use[1])
		}
	}
	for _, input := range regexp.MustCompile(`<(?:input|textarea|select)[^>]*\sid="([^"]+)"`).FindAllStringSubmatch(page, -1) {
		if !regexp.MustCompile(`<label[^>]*>(?:[^<]|<span[^>]*>[^<]*</span>)*<(?:input|textarea|select)[^>]*\sid="` + regexp.QuoteMeta(input[1]) + `"`).MatchString(page) {
			t.Errorf("#%s has no label", input[1])
		}
	}
	// No destructive function has a control or a string.
	for _, word := range []string{"factory-reset", "factory_reset", "恢复出厂设置", "刷写", "格式化存储", "nv-write", "edl-enter"} {
		if strings.Contains(page+files["app.js"], word) {
			t.Errorf("the console mentions a destructive action: %s", word)
		}
	}
	if strings.Contains(page+files["app.js"], "通话许可证") {
		t.Error("wording about a call licence")
	}
}
