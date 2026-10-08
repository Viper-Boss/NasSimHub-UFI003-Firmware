package localadmin

import "net/http"

// The console's view of device-local trust enforcement (agent/trust).
//
// Two things, and deliberately no third:
//
//   - a read-only page saying how far the paired NAS allows this device to be
//     used, what is refused and why;
//   - the same gate in front of the one outgoing action this console has,
//     sending an SMS.
//
// There is no route here that installs, edits or clears a policy, and the
// Sources below give this package no function that could. The decision is the
// paired NAS's; a restriction that the device's own page could lift would not
// be a restriction. Signing in, the password, Wi-Fi, diagnostics and the
// update view do not consult the policy and work under any of them.

// TrustReport is GET /admin/api/v1/trust. States and a reason only: it carries
// no identifier.
type TrustReport struct {
	// Supported is false on a build or configuration with no device-local
	// enforcement. That is reported as such, never as "unrestricted".
	Supported bool `json:"supported"`
	// Installed is false when the paired NAS has not sent a policy (or the
	// device is not paired): nothing is restricted by this device then.
	Installed  bool     `json:"installed"`
	State      string   `json:"state,omitempty"`
	Mode       string   `json:"mode,omitempty"`
	Deny       []string `json:"deny"`
	Reason     string   `json:"reason,omitempty"`
	Generation uint64   `json:"generation"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	Stale      bool     `json:"stale"`
	// Freshness says why a policy is stale: "fresh", "stale_restart" (the
	// device restarted and the NAS has not confirmed the policy since) or
	// "stale_expired". Empty when nothing is installed or it is damaged.
	Freshness string `json:"freshness,omitempty"`
	Damaged   bool   `json:"damaged"`
	Enforcing bool   `json:"enforcing"`
	// SendSMSAllowed is whether this console's own send would be accepted now.
	SendSMSAllowed bool `json:"send_sms_allowed"`
	// SendSMSBlock says why not, in the same words a refused send uses (see
	// smsBlock): empty when allowed. The page shows its explanation from this
	// and from State; it never works a permission out for itself.
	SendSMSBlock string `json:"send_sms_block,omitempty"`
}

// The reasons this console's own send can be refused. They are the "code" of a
// refused POST sms/send and the send_sms_block of the trust page.
const (
	smsBlockDamaged      = "trust_damaged"
	smsBlockStaleRestart = "trust_stale_restart"
	smsBlockStale        = "trust_stale"
	smsBlockDenied       = "trust_denied"
)

// smsBlock classifies a refusal. One function decides for both the refused
// request and the page's advance notice, so the two cannot disagree.
//
// The order is the gate's: a damaged policy first; then what the policy
// denies, which holds whatever its freshness (a restriction does not lapse and
// is not lifted by reconnecting); only a send the policy would allow can be
// "waiting for the NAS" or "expired".
func smsBlock(denied, stale, damaged bool, freshness string) string {
	switch {
	case damaged:
		return smsBlockDamaged
	case denied:
		return smsBlockDenied
	case stale && freshness == "stale_restart":
		return smsBlockStaleRestart
	case stale:
		return smsBlockStale
	}
	return ""
}

// TrustRefusal is why an outgoing action was refused.
type TrustRefusal struct {
	State, Reason          string
	Denied, Stale, Damaged bool
	// Freshness is the gate's reason for Stale; see TrustReport.Freshness.
	Freshness string
}

func (a *Admin) trustSources() (func() TrustReport, func() *TrustRefusal) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sources.Trust, a.sources.RequireSendSMS
}

func (a *Admin) trust(w http.ResponseWriter, _ *http.Request, _ string, _ http.Handler) {
	report, _ := a.trustSources()
	view := TrustReport{Deny: []string{}}
	if report != nil {
		view = report()
		if view.Deny == nil {
			view.Deny = []string{}
		}
	}
	// Worked out from the policy as reported, not by asking the gate: reading
	// this page must not count as an attempt to send.
	view.SendSMSAllowed = !view.Supported || !view.Installed || !view.Enforcing || (!view.Stale && !view.Damaged && !contains(view.Deny, "send_sms"))
	view.SendSMSBlock = ""
	if !view.SendSMSAllowed {
		view.SendSMSBlock = smsBlock(contains(view.Deny, "send_sms"), view.Stale, view.Damaged, view.Freshness)
	}
	respond(w, 200, view)
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// refuseSMS answers a send the trust policy does not allow. It reports whether
// it did. The wording says who decides and that this page cannot change it.
func (a *Admin) refuseSMS(w http.ResponseWriter) bool {
	_, require := a.trustSources()
	if require == nil {
		return false
	}
	refusal := require()
	if refusal == nil {
		return false
	}
	// "state" is the trust state the NAS gave, as the gate reported it with
	// this refusal. It lets the page tell an observation period from a
	// restriction without reading anything into the wording.
	code := smsBlock(refusal.Denied, true, refusal.Damaged, refusal.Freshness)
	message := ""
	switch code {
	case smsBlockDamaged:
		message = "设备上保存的使用策略校验失败，暂时不能发送短信。请连接已配对的 NAS 恢复策略；本页不能解除。"
	case smsBlockStaleRestart:
		// Not "expired": nothing ran out. The device cannot tell how long it
		// was off, so the NAS has to say again that the policy stands, and it
		// does so by itself when it connects.
		message = "设备重启后需由 NAS 重新确认策略；连接 NAS 后自动恢复。在此之前不能发送短信；本页不能解除。"
	case smsBlockStale:
		message = "策略已过期，请连接 NAS 刷新后再发送短信。本页不能解除。"
	default:
		message = "已配对的 NAS 限制了此设备的外发使用，当前不能发送短信。此限制由 NAS 决定；本页不能解除。"
	}
	respond(w, 403, map[string]string{"error": message, "code": code, "state": refusal.State})
	return true
}
