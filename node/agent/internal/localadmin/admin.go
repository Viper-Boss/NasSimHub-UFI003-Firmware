// Package localadmin owns browser authentication independently of NAS pairing.
package localadmin

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed index.html app.js style.css
var assets embed.FS

// The numbers that decide how long a browser stays signed in and how fast a
// password can be guessed. They are constants rather than configuration: a
// device whose lockout depended on a file somebody edited is a device nobody
// can reason about afterwards. README-local-admin.md quotes them.
const (
	// PBKDF2-HMAC-SHA256 iteration count for the stored password hash.
	rounds     = 210000
	cookieName = "__Host-nsh-admin"
	// idleLifetime ends a session nobody is using. Only requests a person
	// caused extend it; the page's own polling does not (see passiveHeader).
	idleLifetime = 30 * time.Minute
	// absoluteLifetime ends a session however busy it is.
	absoluteLifetime = 12 * time.Hour
	// maxSessions bounds the table. The least recently used session is
	// dropped when a new sign-in would exceed it.
	maxSessions = 32
	// After lockoutThreshold consecutive wrong passwords (or setup proofs)
	// further attempts are refused for lockoutBase, doubling with every
	// additional failure up to lockoutMax. A success clears the count; so does
	// lockoutMax of quiet after the last lock ended.
	lockoutThreshold = 5
	lockoutBase      = time.Minute
	lockoutMax       = 15 * time.Minute
	// passiveHeader marks a request the page sent on a timer. It is honoured
	// only in the direction that shortens a session: a passive request is
	// authenticated like any other but does not count as activity, so an
	// unattended tab cannot keep itself signed in.
	passiveHeader = "X-NSH-Passive"
	// wifiSettleWindow is how long a Wi-Fi change is watched before its
	// outcome is reported as unknown: the backend's 90 s join limit plus its
	// 75 s recovery window, with a little slack.
	wifiSettleWindow = 3 * time.Minute
)

type credentials struct {
	Salt string `json:"salt"`
	Hash string `json:"hash"`
}
type session struct {
	CSRF    string
	Created time.Time
	Seen    time.Time
}
type Options struct {
	Dir, DeviceID, Model, Version string
	Now                           func() time.Time
}
type Admin struct {
	mu        sync.Mutex
	options   Options
	cred      credentials
	bootstrap string
	sessions  map[string]session
	// failures counts consecutive refused credentials; lockedUntil is when the
	// next attempt will be looked at.
	failures    int
	lastFailure time.Time
	lockedUntil time.Time
	sources     Sources
	change      *wifiChange
}

// Open creates a per-device, one-use setup code. Neither this code nor the
// password hash belongs in a factory image. Restarting preserves credentials.
func Open(options Options) (*Admin, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	if err := os.MkdirAll(options.Dir, 0700); err != nil {
		return nil, err
	}
	a := &Admin{options: options, sessions: make(map[string]session)}
	b, err := os.ReadFile(filepath.Join(options.Dir, "admin.json"))
	if err == nil {
		if json.Unmarshal(b, &a.cred) != nil || !validCredentials(a.cred) {
			return nil, errors.New("invalid local administrator credentials")
		}
		// A crash between saving credentials and deleting the code must not reopen setup.
		_ = os.Remove(filepath.Join(options.Dir, "admin-bootstrap.txt"))
		return a, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	b, err = os.ReadFile(filepath.Join(options.Dir, "admin-bootstrap.txt"))
	if os.IsNotExist(err) {
		a.bootstrap = randomToken()
		if err = writePrivate(options.Dir, "admin-bootstrap.txt", []byte(a.bootstrap+"\n")); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		a.bootstrap = strings.TrimSpace(string(b))
	}
	if len(a.bootstrap) != 43 {
		return nil, errors.New("invalid local administrator setup code")
	}
	return a, nil
}

// OwnerSetup is consumed only by the paired Core's authenticated management
// route. The public browser session and diagnostics never expose this proof.
func (a *Admin) OwnerSetup() (configured bool, proof string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cred.Hash != "" {
		return true, ""
	}
	return false, a.bootstrap
}

func validCredentials(c credentials) bool {
	s, e := base64.RawURLEncoding.DecodeString(c.Salt)
	h, f := base64.RawURLEncoding.DecodeString(c.Hash)
	return e == nil && f == nil && len(s) == 24 && len(h) == 32
}
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func hash(password, salt string) string {
	b, err := pbkdf2.Key(sha256.New, password, []byte(salt), rounds, 32)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func writePrivate(dir, name string, b []byte) error {
	f, err := os.CreateTemp(dir, ".admin-*")
	if err != nil {
		return err
	}
	p := f.Name()
	defer os.Remove(p)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(p, filepath.Join(dir, name))
}
func (a *Admin) save(password string) error {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	c := credentials{Salt: base64.RawURLEncoding.EncodeToString(b)}
	c.Hash = hash(password, c.Salt)
	data, _ := json.Marshal(c)
	if err := writePrivate(a.options.Dir, "admin.json", data); err != nil {
		return err
	}
	a.cred = c
	a.bootstrap = ""
	a.sessions = make(map[string]session)
	_ = os.Remove(filepath.Join(a.options.Dir, "admin-bootstrap.txt"))
	return nil
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}

// failCode adds a stable word the page can act on without parsing the text.
func failCode(w http.ResponseWriter, status int, code, message string) {
	respond(w, status, map[string]string{"error": message, "code": code})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeLimit(w, r, v, 4096)
}
func decodeLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(w, 415, "需要 JSON 请求")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		fail(w, 400, "请求格式无效")
		return false
	}
	return true
}
func sameOrigin(r *http.Request) bool {
	u, err := url.Parse(r.Header.Get("Origin"))
	return err == nil && u.Scheme == "https" && u.Host == r.Host && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Path == ""
}
func (a *Admin) logf(format string, arguments ...any) {
	if a.sources.Logf != nil {
		a.sources.Logf(format, arguments...)
	}
}

// expired applies both limits. A session is judged by the server's clock
// alone; the cookie's own Max-Age is a courtesy to the browser.
func (a *Admin) expired(s session, now time.Time) bool {
	return now.Sub(s.Created) >= absoluteLifetime || now.Sub(s.Seen) >= idleLifetime
}
func (a *Admin) current(r *http.Request) (string, session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", session{}, false
	}
	s, ok := a.sessions[c.Value]
	if !ok || a.expired(s, a.options.Now()) {
		delete(a.sessions, c.Value)
		return "", session{}, false
	}
	return c.Value, s, true
}

// authenticate is current plus the idle clock: activity a person caused
// extends the session, the page's background polling does not.
func (a *Admin) authenticate(r *http.Request) (string, session, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id, s, ok := a.current(r)
	if ok && r.Header.Get(passiveHeader) == "" {
		s.Seen = a.options.Now()
		a.sessions[id] = s
	}
	return id, s, ok
}
func (a *Admin) createSession(w http.ResponseWriter) session {
	now := a.options.Now()
	for id, s := range a.sessions {
		if a.expired(s, now) {
			delete(a.sessions, id)
		}
	}
	// Dropping the least recently used session keeps the table bounded
	// without signing everybody else out because one more browser arrived.
	for len(a.sessions) >= maxSessions {
		oldest, seen := "", time.Time{}
		for id, s := range a.sessions {
			if oldest == "" || s.Seen.Before(seen) {
				oldest, seen = id, s.Seen
			}
		}
		delete(a.sessions, oldest)
	}
	id := randomToken()
	s := session{CSRF: randomToken(), Created: now, Seen: now}
	a.sessions[id] = s
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(absoluteLifetime.Seconds())})
	return s
}

// contentSecurityPolicy allows this origin's own script, style and requests
// and nothing else: no inline script, no eval, no framing, no third party.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

func secure(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	h.Set("Content-Security-Policy", contentSecurityPolicy)
}

// route is one request this package answers itself, after the session and
// CSRF checks in Wrap. Everything else under /admin/api/ belongs to the
// device handlers the caller supplied.
type route struct {
	method, path string
	handle       func(a *Admin, w http.ResponseWriter, r *http.Request, id string, api http.Handler)
}

// routes is a table rather than a chain of ifs so that a test can enumerate
// it: a state-changing route added here is checked for its CSRF guard without
// anyone remembering to write that test.
var routes = []route{
	{"GET", "/admin/api/v1/system", (*Admin).systemStatus},
	{"POST", "/admin/api/v1/system/change", (*Admin).systemChange},
	{"POST", "/admin/password", (*Admin).password},
	{"POST", "/admin/logout", (*Admin).logout},
	{"GET", "/admin/api/v1/security", (*Admin).security},
	{"GET", "/admin/api/v1/trust", (*Admin).trust},
	{"GET", "/admin/api/v1/update", (*Admin).update},
	{"POST", "/admin/api/v1/update/rollback", (*Admin).updateRollback},
	{"GET", "/admin/api/v1/wifi/change", (*Admin).wifiOutcome},
	{"POST", "/admin/api/v1/wifi/connect", (*Admin).wifiConnect},
	{"POST", "/admin/api/v1/wifi/forget", (*Admin).wifiForget},
	{"GET", "/admin/api/v1/wifi/setup-ap", (*Admin).setupAPStatus},
	{"POST", "/admin/api/v1/wifi/setup-ap/reveal", (*Admin).setupAPReveal},
	{"POST", "/admin/api/v1/sms/send", (*Admin).smsSend},
}

// unauthenticatedWrites are the state-changing routes reachable without a
// session, and therefore without a CSRF token. Signing in is the only one: it
// is what creates the token, and it is covered by the same-origin check, the
// SameSite=Strict cookie and the lockout instead.
var unauthenticatedWrites = map[string]bool{"/admin/login": true}

// Wrap accepts a deliberately limited management API. Its caller supplies
// device handlers directly; no NAS bearer token is minted or forwarded.
func (a *Admin) Wrap(api http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secure(w)
		if r.TLS == nil {
			fail(w, 403, "独立管理后台仅通过 HTTPS 提供")
			return
		}
		write := r.Method != "GET" && r.Method != "HEAD"
		if write && !sameOrigin(r) {
			fail(w, 403, "请求来源无效")
			return
		}
		if r.URL.Path == "/admin/session" && r.Method == "GET" {
			a.mu.Lock()
			defer a.mu.Unlock()
			// Asking whether a session exists is not activity.
			_, s, ok := a.current(r)
			respond(w, 200, map[string]any{"configured": a.cred.Hash != "", "authenticated": ok, "csrf": s.CSRF, "device_id": a.options.DeviceID, "model": a.options.Model, "version": a.options.Version,
				"idle_timeout_seconds": int(idleLifetime.Seconds()), "absolute_timeout_seconds": int(absoluteLifetime.Seconds()), "locked_seconds": int(a.locked().Round(time.Second).Seconds())})
			return
		}
		if write && unauthenticatedWrites[r.URL.Path] {
			if r.Method != "POST" {
				http.NotFound(w, r)
				return
			}
			a.login(w, r)
			return
		}
		// One guard for every other request that changes state and for the
		// whole device API, placed before any dispatch: a route cannot be
		// reached by forgetting to check it.
		if write || strings.HasPrefix(r.URL.Path, "/admin/api/") {
			id, s, ok := a.authenticate(r)
			if !ok {
				failCode(w, 401, "session_expired", "登录已失效，请重新登录")
				return
			}
			if write && !equal(r.Header.Get("X-CSRF-Token"), s.CSRF) {
				failCode(w, 403, "csrf", "请求校验失败")
				return
			}
			for _, candidate := range routes {
				if candidate.path == r.URL.Path {
					if candidate.method != r.Method {
						w.Header().Set("Allow", candidate.method)
						failCode(w, 405, "method_not_allowed", "不支持的请求方法")
						return
					}
					candidate.handle(a, w, r, id, api)
					return
				}
			}
			if strings.HasPrefix(r.URL.Path, "/admin/api/") && api != nil {
				http.StripPrefix("/admin/api", api).ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}
		name := ""
		switch r.URL.Path {
		case "/", "/admin", "/admin/":
			name = "index.html"
		case "/admin/app.js":
			name = "app.js"
		case "/admin/style.css":
			name = "style.css"
		}
		if name != "" {
			b, _ := assets.ReadFile(name)
			types := map[string]string{"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8"}
			w.Header().Set("Content-Type", types[name])
			if r.Method != "HEAD" {
				_, _ = w.Write(b)
			}
			return
		}
		http.NotFound(w, r)
	})
}
func (a *Admin) logout(w http.ResponseWriter, _ *http.Request, id string, _ http.Handler) {
	a.mu.Lock()
	delete(a.sessions, id)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	respond(w, 200, map[string]bool{"ok": true})
}

// locked reports how long attempts are still refused.
func (a *Admin) locked() time.Duration {
	if remaining := a.lockedUntil.Sub(a.options.Now()); remaining > 0 {
		return remaining
	}
	return 0
}

// refused records one wrong credential and returns the lock it caused, if any.
func (a *Admin) refused() time.Duration {
	now := a.options.Now()
	// A count from long ago is not evidence of guessing now.
	if a.failures > 0 && now.Sub(a.lastFailure) >= lockoutMax && now.Sub(a.lockedUntil) >= lockoutMax {
		a.failures = 0
	}
	a.failures++
	a.lastFailure = now
	if a.failures < lockoutThreshold {
		return 0
	}
	lock := lockoutMax
	if shift := a.failures - lockoutThreshold; shift < 8 && lockoutBase<<shift < lockoutMax {
		lock = lockoutBase << shift
	}
	a.lockedUntil = now.Add(lock)
	return lock
}

// refuseLocked answers 429 while a lock is running. The credential in the
// request is not examined at all, so a locked device gives a guesser nothing.
func (a *Admin) refuseLocked(w http.ResponseWriter) bool {
	remaining := a.locked()
	if remaining <= 0 {
		return false
	}
	seconds := int((remaining + time.Second - 1) / time.Second)
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	respond(w, 429, map[string]any{"error": fmt.Sprintf("尝试过于频繁，请在 %d 秒后重试", seconds), "code": "locked", "retry_after_seconds": seconds})
	return true
}
func (a *Admin) login(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Password  string `json:"password"`
		SetupCode string `json:"setup_code"`
	}
	if !decode(w, r, &v) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.refuseLocked(w) {
		return
	}
	if len(v.Password) > 256 {
		fail(w, 400, "密码过长")
		return
	}
	if a.cred.Hash == "" {
		if !equal(v.SetupCode, a.bootstrap) {
			if lock := a.refused(); lock > 0 {
				a.logf("first-time setup locked for %s after %d refused proofs", lock, a.failures)
			}
			fail(w, 401, "初始化码无效")
			return
		}
		if len(v.Password) < 12 {
			fail(w, 400, "请设置至少 12 位管理密码")
			return
		}
		if err := a.save(v.Password); err != nil {
			fail(w, 500, "保存管理密码失败")
			return
		}
		a.logf("management password created; first-time setup is closed")
	} else if !equal(hash(v.Password, a.cred.Salt), a.cred.Hash) {
		if lock := a.refused(); lock > 0 {
			a.logf("sign-in locked for %s after %d refused attempts", lock, a.failures)
		} else {
			a.logf("sign-in refused (%d consecutive)", a.failures)
		}
		fail(w, 401, "管理密码错误")
		return
	}
	a.failures = 0
	a.lockedUntil = time.Time{}
	s := a.createSession(w)
	respond(w, 200, map[string]string{"csrf": s.CSRF})
}
func (a *Admin) password(w http.ResponseWriter, r *http.Request, _ string, _ http.Handler) {
	var v struct {
		Current  string `json:"current_password"`
		Password string `json:"password"`
	}
	if !decode(w, r, &v) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.refuseLocked(w) {
		return
	}
	if len(v.Current) > 256 || !equal(hash(v.Current, a.cred.Salt), a.cred.Hash) {
		a.refused()
		fail(w, 401, "原密码错误")
		return
	}
	if len(v.Password) < 12 || len(v.Password) > 256 {
		fail(w, 400, "新密码需为 12 至 256 位")
		return
	}
	if err := a.save(v.Password); err != nil {
		fail(w, 500, "保存失败")
		return
	}
	// save dropped every session, this one included; the caller gets a new one.
	a.failures = 0
	a.logf("management password changed; every other session was signed out")
	s := a.createSession(w)
	respond(w, 200, map[string]string{"csrf": s.CSRF})
}
