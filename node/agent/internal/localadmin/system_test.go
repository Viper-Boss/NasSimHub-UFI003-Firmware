package localadmin

import (
	"context"
	"github.com/human-agent65535/nassimhub-node/agent/internal/systemadmin"
	"net/http"
	"testing"
	"time"
)

type systemSpy struct{ calls int }

func (s *systemSpy) Execute(_ context.Context, r systemadmin.Request) (systemadmin.Status, error) {
	s.calls++
	return systemadmin.Status{Accounts: []systemadmin.Account{}, SSH: systemadmin.SSHSettings{Port: 2222}}, nil
}
func TestSystemMutationsRequireSessionCSRFAndReauthentication(t *testing.T) {
	a, h, cookie, csrf := configured(t, &clock{now: time.Now()}, &spy{})
	s := &systemSpy{}
	a.sources.System = s
	body := map[string]any{"action": "sudo", "user": "alice", "enabled": true, "current_password": "a-fake-management-password"}
	for _, v := range []struct {
		cookie bool
		csrf   string
		origin string
	}{{false, csrf, origin}, {true, "", origin}, {true, csrf, "https://evil.test"}} {
		var c *http.Cookie
		if v.cookie {
			c = cookie
		}
		w := call(t, h, "/admin/api/v1/system/change", "POST", body, c, v.csrf, v.origin)
		if w.Code < 400 {
			t.Fatal(w.Code)
		}
	}
	body["current_password"] = "wrong"
	if w := call(t, h, "/admin/api/v1/system/change", "POST", body, cookie, csrf, origin); w.Code != 401 {
		t.Fatal(w.Code, w.Body.String())
	}
	if s.calls != 0 {
		t.Fatal("unauthorized operation reached helper")
	}
	body["current_password"] = "a-fake-management-password"
	if w := call(t, h, "/admin/api/v1/system/change", "POST", body, cookie, csrf, origin); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if s.calls != 1 {
		t.Fatal(s.calls)
	}
	body["user"] = "root"
	if w := call(t, h, "/admin/api/v1/system/change", "POST", body, cookie, csrf, origin); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if s.calls != 1 {
		t.Fatal("protected action reached helper")
	}
}
