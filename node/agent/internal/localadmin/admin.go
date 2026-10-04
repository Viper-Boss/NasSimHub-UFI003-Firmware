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
	"strings"
	"sync"
	"time"
)

//go:embed index.html app.js style.css
var assets embed.FS

const rounds = 210000
const cookieName = "__Host-nsh-admin"
const lifetime = 30 * time.Minute

type credentials struct {
	Salt string `json:"salt"`
	Hash string `json:"hash"`
}
type session struct {
	CSRF    string
	Expires time.Time
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
	attempts  int
	window    time.Time
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
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(w, 415, "需要 JSON 请求")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
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
func (a *Admin) current(r *http.Request) (string, session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", session{}, false
	}
	s, ok := a.sessions[c.Value]
	if !ok || !a.options.Now().Before(s.Expires) {
		delete(a.sessions, c.Value)
		return "", session{}, false
	}
	return c.Value, s, true
}
func (a *Admin) createSession(w http.ResponseWriter) session {
	now := a.options.Now()
	for id, s := range a.sessions {
		if !now.Before(s.Expires) {
			delete(a.sessions, id)
		}
	}
	if len(a.sessions) >= 32 {
		a.sessions = make(map[string]session)
	}
	id := randomToken()
	s := session{CSRF: randomToken(), Expires: now.Add(lifetime)}
	a.sessions[id] = s
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(lifetime.Seconds())})
	return s
}

// Wrap accepts a deliberately limited management API. Its caller supplies
// device handlers directly; no NAS bearer token is minted or forwarded.
func (a *Admin) Wrap(api http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.TLS == nil {
			fail(w, 403, "独立管理后台仅通过 HTTPS 提供")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && !sameOrigin(r) {
			fail(w, 403, "请求来源无效")
			return
		}
		if r.URL.Path == "/admin/session" && r.Method == "GET" {
			a.mu.Lock()
			defer a.mu.Unlock()
			_, s, ok := a.current(r)
			respond(w, 200, map[string]any{"configured": a.cred.Hash != "", "authenticated": ok, "csrf": s.CSRF, "device_id": a.options.DeviceID, "model": a.options.Model, "version": a.options.Version})
			return
		}
		if r.URL.Path == "/admin/login" && r.Method == "POST" {
			a.login(w, r)
			return
		}
		if r.URL.Path == "/admin/password" && r.Method == "POST" {
			a.password(w, r)
			return
		}
		if r.URL.Path == "/admin/logout" && r.Method == "POST" {
			a.mu.Lock()
			defer a.mu.Unlock()
			id, s, ok := a.current(r)
			if !ok || !equal(r.Header.Get("X-CSRF-Token"), s.CSRF) {
				fail(w, 403, "登录已失效")
				return
			}
			delete(a.sessions, id)
			http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
			respond(w, 200, map[string]bool{"ok": true})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/admin/api/") {
			a.mu.Lock()
			_, s, ok := a.current(r)
			a.mu.Unlock()
			if !ok {
				fail(w, 401, "请先登录")
				return
			}
			if r.Method != "GET" && r.Method != "HEAD" && !equal(r.Header.Get("X-CSRF-Token"), s.CSRF) {
				fail(w, 403, "请求校验失败")
				return
			}
			http.StripPrefix("/admin/api", api).ServeHTTP(w, r)
			return
		}
		if r.Method == "GET" || r.Method == "HEAD" {
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
		}
		http.NotFound(w, r)
	})
}
func (a *Admin) allow() bool {
	now := a.options.Now()
	if now.Sub(a.window) >= time.Minute {
		a.window = now
		a.attempts = 0
	}
	a.attempts++
	return a.attempts <= 5
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
	if !a.allow() {
		fail(w, 429, "尝试过于频繁，请一分钟后重试")
		return
	}
	if len(v.Password) > 256 {
		fail(w, 400, "密码过长")
		return
	}
	if a.cred.Hash == "" {
		if !equal(v.SetupCode, a.bootstrap) {
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
	} else if !equal(hash(v.Password, a.cred.Salt), a.cred.Hash) {
		fail(w, 401, "管理密码错误")
		return
	}
	a.attempts = 0
	s := a.createSession(w)
	respond(w, 200, map[string]string{"csrf": s.CSRF})
}
func (a *Admin) password(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Current  string `json:"current_password"`
		Password string `json:"password"`
	}
	if !decode(w, r, &v) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, s, ok := a.current(r)
	if !ok || !equal(r.Header.Get("X-CSRF-Token"), s.CSRF) {
		fail(w, 403, "登录已失效")
		return
	}
	if !a.allow() {
		fail(w, 429, "尝试过于频繁，请稍后重试")
		return
	}
	if len(v.Current) > 256 || !equal(hash(v.Current, a.cred.Salt), a.cred.Hash) {
		fail(w, 401, "原密码错误")
		return
	}
	if len(v.Password) < 12 || len(v.Password) > 256 {
		fail(w, 400, "新密码需为 12 至 256 位")
		return
	}
	if err := a.save(v.Password); err != nil {
		fail(w, 500, fmt.Sprint("保存失败"))
		return
	}
	s = a.createSession(w)
	respond(w, 200, map[string]string{"csrf": s.CSRF})
}
