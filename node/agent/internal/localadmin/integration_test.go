package localadmin_test

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

	"github.com/human-agent65535/nassimhub-node/agent/modembackend/mock"
	netmock "github.com/human-agent65535/nassimhub-node/agent/netbackend/mock"
	"github.com/human-agent65535/nassimhub-node/agent/nodeserver"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// Exercise the actual assembled agent, not a separate imitation of its routes.
func TestUnpairedDeviceLocalManagementDoesNotAuthorizeNASProtocol(t *testing.T) {
	dir := t.TempDir()
	modem := mock.New(mock.Options{Scenario: mock.ChinaTelecom})
	defer modem.Close()
	network := netmock.New(netmock.Options{SavedSSID: "existing", Passwords: map[string]string{"existing": "correct-password", "new": "new-password"}})
	defer network.Close()
	options := nodeserver.Options{StateDir: dir, Platform: proto.PlatformMock, Model: "test", Modem: modem, Network: network, EnableTLS: true, EnableLocalAdmin: true}
	node, err := nodeserver.New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer node.Logs.Close()
	request := func(path, method string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "https://device.test"+path, bytes.NewReader(b))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://device.test")
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		if strings.HasPrefix(path, "/admin") || path == "/" {
			node.AdminHandler().ServeHTTP(w, r)
		} else {
			node.Handler().ServeHTTP(w, r)
		}
		return w
	}
	if w := request("/admin/api/v1/status", "GET", nil, nil, ""); w.Code != 401 {
		t.Fatal("local status unguarded", w.Code)
	}
	code, _ := os.ReadFile(filepath.Join(dir, "admin-bootstrap.txt"))
	w := request("/admin/login", "POST", map[string]string{"setup_code": strings.TrimSpace(string(code)), "password": "device-management-password"}, nil, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	var login map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &login)
	csrf := login["csrf"]
	for _, path := range []string{"status", "sim", "signal", "wifi", "node", "capabilities", "logs", "diagnostics"} {
		w = request("/admin/api/v1/"+path, "GET", nil, cookie, "")
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	// A browser session cannot become a Core session, even on the same listener.
	if w = request("/v1/status", "GET", nil, cookie, ""); w.Code != 401 {
		t.Fatal("local cookie authorized Core protocol", w.Code)
	}
	if w = request("/v1/sms/send", "POST", proto.SendSMSRequest{RequestID: "bypass", To: "10000", Text: "test"}, cookie, csrf); w.Code != 401 {
		t.Fatal("local cookie authorized Core SMS", w.Code)
	}
	for _, path := range []string{"calls/dial", "pair/factory-reset", "transport/key"} {
		w = request("/admin/api/v1/"+path, "POST", map[string]string{}, cookie, csrf)
		if w.Code != 404 && w.Code != 405 {
			t.Fatal("local privilege escaped whitelist", path, w.Code)
		}
	}
	msg := proto.SendSMSRequest{RequestID: "local-admin-sms-1", To: "10000", Text: "simulated test"}
	for i := 0; i < 2; i++ {
		w = request("/admin/api/v1/sms/send", "POST", msg, cookie, csrf)
		if w.Code != 201 {
			t.Fatal("send SMS", w.Code, w.Body.String())
		}
	}
	w = request("/admin/api/v1/sms", "GET", nil, cookie, "")
	var list proto.SMSList
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	count := 0
	for _, sms := range list.Messages {
		if sms.Text == msg.Text {
			count++
		}
	}
	if count != 1 {
		t.Fatal("SMS retry duplicated message", count)
	}
	w = request("/admin/api/v1/wifi/connect", "POST", proto.WiFiConnectRequest{SSID: "new", PSK: "new-password", Security: proto.WiFiSecurityWPA2}, cookie, csrf)
	if w.Code != 202 {
		t.Fatal("Wi-Fi connect", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "new-password") {
		t.Fatal("Wi-Fi credential echoed")
	}
	w = request("/admin/api/v1/diagnostics/archive", "GET", nil, cookie, "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/gzip" {
		t.Fatal("diagnostic download failed", w.Code)
	}
	options.EnableTLS = false
	if _, err := nodeserver.New(options); err == nil {
		t.Fatal("local console allowed without TLS")
	}
}
