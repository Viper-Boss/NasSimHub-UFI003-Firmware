package localadmin

import (
	"context"
	"github.com/human-agent65535/nassimhub-node/agent/internal/systemadmin"
	"net/http"
)

type SystemAdministrator interface {
	Execute(context.Context, systemadmin.Request) (systemadmin.Status, error)
}

func (a *Admin) systemStatus(w http.ResponseWriter, r *http.Request, _ string, _ http.Handler) {
	a.mu.Lock()
	source := a.sources.System
	a.mu.Unlock()
	if source == nil {
		failCode(w, 501, "not_supported", "此设备未安装系统管理服务")
		return
	}
	result, err := source.Execute(r.Context(), systemadmin.Request{Action: "status"})
	if err != nil {
		failCode(w, 503, "unavailable", err.Error())
		return
	}
	respond(w, 200, result)
}
func (a *Admin) systemChange(w http.ResponseWriter, r *http.Request, _ string, _ http.Handler) {
	var v struct {
		systemadmin.Request
		Current string `json:"current_password"`
	}
	if !decode(w, r, &v) {
		return
	}
	if v.Action == "status" {
		fail(w, 400, "请使用状态查询接口")
		return
	}
	if err := systemadmin.Validate(v.Request); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.mu.Lock()
	if a.refuseLocked(w) {
		a.mu.Unlock()
		return
	}
	if a.cred.Hash == "" || len(v.Current) > 256 || !equal(hash(v.Current, a.cred.Salt), a.cred.Hash) {
		a.refused()
		a.mu.Unlock()
		failCode(w, 401, "wrong_password", "管理密码错误")
		return
	}
	a.failures = 0
	source := a.sources.System
	a.mu.Unlock()
	if source == nil {
		failCode(w, 501, "not_supported", "此设备未安装系统管理服务")
		return
	}
	result, err := source.Execute(r.Context(), v.Request)
	// Log only the finite operation name, never the password, key or request.
	if err != nil {
		a.logf("system administration %s failed", v.Action)
		failCode(w, 409, "system_operation_failed", err.Error())
		return
	}
	a.logf("system administration %s completed", v.Action)
	respond(w, 200, result)
}
