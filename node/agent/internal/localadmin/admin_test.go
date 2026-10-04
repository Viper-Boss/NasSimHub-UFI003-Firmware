package localadmin

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func call(t *testing.T, h http.Handler, path, method string, body any, cookie *http.Cookie, csrf, origin string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(method, "https://device.test"+path, bytes.NewReader(b))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func login(t *testing.T, a *Admin, password string) (http.Handler, *http.Cookie, string) {
	t.Helper()
	h := a.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	w := call(t, h, "/admin/login", "POST", map[string]string{"password": password, "setup_code": a.bootstrap}, nil, "", "https://device.test")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	c := w.Result().Cookies()[0]
	return h, c, result["csrf"]
}
func TestLocalLoginPersistsAndNeverPersistsPlainPassword(t *testing.T) {
	dir := t.TempDir()
	a, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	setup := a.bootstrap
	password := "independent-test-password"
	h, c, csrf := login(t, a, password)
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatal("unsafe session cookie", c)
	}
	if w := call(t, h, "/admin/api/v1/status", "GET", nil, c, "", ""); w.Code != 204 {
		t.Fatal(w.Code)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "admin.json"))
	if strings.Contains(string(data), password) || strings.Contains(string(data), setup) {
		t.Fatal("plaintext credential was stored")
	}
	if _, err = os.Stat(filepath.Join(dir, "admin-bootstrap.txt")); !os.IsNotExist(err) {
		t.Fatal("setup code not consumed")
	}
	info, _ := os.Stat(filepath.Join(dir, "admin.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("credential permissions", info.Mode())
	}
	b, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if b.bootstrap != "" {
		t.Fatal("setup was reopened")
	}
	wh := b.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	if w := call(t, wh, "/admin/api/v1/status", "GET", nil, c, "", ""); w.Code != 401 {
		t.Fatal("restart retained session")
	}
	w := call(t, wh, "/admin/login", "POST", map[string]string{"password": password}, nil, "", "https://device.test")
	if w.Code != 200 {
		t.Fatal("password did not survive restart", w.Code)
	}
	if w = call(t, h, "/admin/logout", "POST", nil, c, csrf, "https://device.test"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = call(t, h, "/admin/api/v1/status", "GET", nil, c, "", ""); w.Code != 401 {
		t.Fatal("logout did not revoke session")
	}
}
func TestManagementAuthenticationOriginAndCSRF(t *testing.T) {
	a, _ := Open(Options{Dir: t.TempDir()})
	h, c, csrf := login(t, a, "a-strong-test-password")
	for _, tc := range []struct {
		cookie       *http.Cookie
		csrf, origin string
		want         int
	}{{nil, "", "https://device.test", 401}, {c, "", "https://device.test", 403}, {c, csrf, "https://evil.test", 403}, {c, csrf, "", 403}, {c, csrf, "https://device.test.evil", 403}, {c, csrf, "https://device.test", 204}} {
		w := call(t, h, "/admin/api/v1/wifi/connect", "POST", nil, tc.cookie, tc.csrf, tc.origin)
		if w.Code != tc.want {
			t.Fatalf("got %d want %d", w.Code, tc.want)
		}
	}
	r := httptest.NewRequest("GET", "http://device.test/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("plaintext admin allowed")
	}
}
func TestPasswordChangeRevokesOtherSessionsAndOldPassword(t *testing.T) {
	a, _ := Open(Options{Dir: t.TempDir()})
	h, c, csrf := login(t, a, "the-old-test-password")
	_, other, _ := login(t, a, "the-old-test-password")
	w := call(t, h, "/admin/password", "POST", map[string]string{"current_password": "the-old-test-password", "password": "the-new-test-password"}, c, csrf, "https://device.test")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = call(t, h, "/admin/api/v1/status", "GET", nil, other, "", ""); w.Code != 401 {
		t.Fatal("other session survived password change")
	}
	if w = call(t, h, "/admin/login", "POST", map[string]string{"password": "the-old-test-password"}, nil, "", "https://device.test"); w.Code != 401 {
		t.Fatal("old password still works")
	}
}
func TestSetupRateLimitExpiryAndCorruptState(t *testing.T) {
	now := time.Now()
	a, _ := Open(Options{Dir: t.TempDir(), Now: func() time.Time { return now }})
	h := a.Wrap(http.NotFoundHandler())
	for i := 0; i < 6; i++ {
		w := call(t, h, "/admin/login", "POST", map[string]string{"setup_code": "wrong", "password": "long-enough-password"}, nil, "", "https://device.test")
		want := 401
		if i == 5 {
			want = 429
		}
		if w.Code != want {
			t.Fatal(i, w.Code)
		}
	}
	now = now.Add(time.Minute)
	h, c, _ := login(t, a, "long-enough-password")
	now = now.Add(lifetime)
	if w := call(t, h, "/admin/api/v1/status", "GET", nil, c, "", ""); w.Code != 401 {
		t.Fatal("expired session accepted")
	}
	if err := os.WriteFile(filepath.Join(a.options.Dir, "admin.json"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Dir: a.options.Dir}); err == nil {
		t.Fatal("corrupt credential state reopened setup")
	}
}
func TestAssetsDoNotExposeDeviceDataOrExternalResources(t *testing.T) {
	a, _ := Open(Options{Dir: t.TempDir(), DeviceID: "test-device"})
	h := a.Wrap(http.NotFoundHandler())
	for _, p := range []string{"/", "/admin/app.js", "/admin/style.css"} {
		w := call(t, h, p, "GET", nil, nil, "", "")
		if w.Code != 200 {
			t.Fatal(p, w.Code)
		}
		if strings.Contains(w.Body.String(), a.bootstrap) {
			t.Fatal("setup code leaked")
		}
		if w.Header().Get("Content-Security-Policy") == "" {
			t.Fatal("CSP missing")
		}
	}
	if w := call(t, h, "/admin-bootstrap.txt", "GET", nil, nil, "", ""); w.Code != 404 {
		t.Fatal("credential file accessible")
	}
}
