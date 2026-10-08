package localadmin

import (
	"net/http"
	"strings"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// SetupAPCredentials is the Wi-Fi backend's setup access point credential, as
// netbackend.SetupAPCredentialSource declares it. It is repeated here so this
// package depends on the method and not on the backend.
//
// The passphrase lets a person standing near the device reach its setup page.
// This package hands it to exactly one caller: a signed-in owner who has just
// typed the management password again. It is never written to a log, kept in
// a field, or added to any other document this package serves.
type SetupAPCredentials interface {
	SetupAPCredential() (ssid, passphrase string, err error)
}

// Why the setup access point credential cannot be shown.
const (
	// The Wi-Fi backend of this device runs no password-protected access
	// point, so there is no credential to show.
	setupAPNoSource = "no_credential_source"
	// The access point is switched off in the device configuration
	// (provisioning_ap = off). Its credential opens nothing.
	setupAPOff = "access_point_off"
	// The backend has a credential source and it failed to answer.
	setupAPUnavailable = "unavailable"
)

// setupAPView is GET /admin/api/v1/wifi/setup-ap. It has no field a
// passphrase could travel in; that is the reveal route's answer alone.
type setupAPView struct {
	// Available is true when a credential exists and may be revealed.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// SSID is the access point's name, which the radio broadcasts anyway.
	SSID string `json:"ssid,omitempty"`
	// ProvisioningState is the backend's own state, absent when it gave none.
	// It is what says whether the access point is up right now.
	ProvisioningState  proto.WiFiProvisioningState `json:"provisioning_state,omitempty"`
	ProvisioningReason string                      `json:"provisioning_reason,omitempty"`
}

// setupAPSecret is the reveal route's answer.
type setupAPSecret struct {
	SSID       string `json:"ssid"`
	Passphrase string `json:"passphrase"`
}

// setupAP decides whether there is a credential to talk about, without
// touching it. A device whose access point is switched off is not asked for
// one: the backend creates the passphrase on first use, and a page view must
// not be what creates a credential for an access point that is off.
func (a *Admin) setupAP(r *http.Request) (SetupAPCredentials, setupAPView) {
	a.mu.Lock()
	source, reader := a.sources.SetupAP, a.sources.WiFi
	a.mu.Unlock()
	view := setupAPView{}
	if reader != nil {
		// A radio that cannot be read leaves the state absent: unknown, and
		// not a reason to refuse an owner the credential.
		if status, err := reader.Status(r.Context()); err == nil {
			view.ProvisioningState, view.ProvisioningReason = status.ProvisioningState, status.ProvisioningReason
		}
	}
	switch {
	case source == nil:
		view.Reason = setupAPNoSource
	case view.ProvisioningState == proto.WiFiProvisioningDisabled:
		view.Reason = setupAPOff
	default:
		view.Available = true
	}
	return source, view
}

func (a *Admin) setupAPStatus(w http.ResponseWriter, r *http.Request, _ string, _ http.Handler) {
	source, view := a.setupAP(r)
	if view.Available {
		// The name only. The passphrase returned beside it is dropped here.
		ssid, _, err := source.SetupAPCredential()
		if err != nil || strings.TrimSpace(ssid) == "" {
			view.Available, view.Reason = false, setupAPUnavailable
		} else {
			view.SSID = ssid
		}
	}
	respond(w, 200, view)
}

// setupAPReveal answers with the passphrase once, to a signed-in owner who
// has typed the management password again.
//
// Wrap has already required the session and the CSRF token. The password is
// asked for on top of that because a session is a browser left open, and this
// is the one answer in the console that is itself a credential. A wrong
// password counts towards the same lockout as a wrong sign-in, so this route
// is no faster a way to guess the password than the sign-in form is.
//
// First-time setup cannot reach this: there is no session before a password
// exists, and the setup proof is not accepted here in its place.
func (a *Admin) setupAPReveal(w http.ResponseWriter, r *http.Request, _ string, _ http.Handler) {
	var v struct {
		Current string `json:"current_password"`
	}
	if !decode(w, r, &v) {
		return
	}
	source, view := a.setupAP(r)
	switch view.Reason {
	case setupAPNoSource:
		failCode(w, 501, "not_supported", "此设备的 Wi-Fi 后端没有带口令的配网热点，没有可显示的口令")
		return
	case setupAPOff:
		failCode(w, 409, setupAPOff, "配网热点已在设备配置中关闭，没有可显示的口令")
		return
	}
	a.mu.Lock()
	if a.refuseLocked(w) {
		a.mu.Unlock()
		return
	}
	if a.cred.Hash == "" || len(v.Current) > 256 || !equal(hash(v.Current, a.cred.Salt), a.cred.Hash) {
		if lock := a.refused(); lock > 0 {
			a.logf("setup access point passphrase request locked for %s after %d refused attempts", lock, a.failures)
		} else {
			a.logf("setup access point passphrase request refused: wrong management password (%d consecutive)", a.failures)
		}
		a.mu.Unlock()
		failCode(w, 401, "wrong_password", "管理密码错误")
		return
	}
	a.failures = 0
	a.mu.Unlock()
	ssid, passphrase, err := source.SetupAPCredential()
	if err != nil || passphrase == "" {
		// The backend's error is not passed on or logged: the only thing this
		// route may say about the credential is the credential, to its owner.
		a.logf("setup access point passphrase could not be read for the local console")
		failCode(w, 503, setupAPUnavailable, "设备暂时无法读取配网热点口令")
		return
	}
	a.logf("setup access point passphrase shown in the local console")
	// secure() set this for every response already. It is repeated because
	// this is the answer it matters most for.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	respond(w, 200, setupAPSecret{SSID: ssid, Passphrase: passphrase})
}
