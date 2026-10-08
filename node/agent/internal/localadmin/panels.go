package localadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// Sources is what the console reads from the rest of the agent.
//
// Small interfaces defined here, filled in by nodeserver: this package never
// reaches into the identity, pairing or update packages, so nothing it serves
// can be closer to a private key than the adapter chose to hand over. Every
// field is optional; a missing one is reported as unsupported or unknown, not
// as an error and never as a default "fine".
type Sources struct {
 System SystemAdministrator
	// Security describes the device's identity and trust state. Public
	// fingerprints only.
	Security func() SecurityReport
	// Updates is the agent update service, or nil on a build without one.
	Updates Updates
	// WiFi reads the radio state, for reporting what a Wi-Fi change led to.
	WiFi WiFiReader
	// SetupAP is the setup access point's credential source, or nil when the
	// Wi-Fi backend has none. See setupap.go for who may be shown it.
	SetupAP SetupAPCredentials
	// Logf records administrative events in the device log. Arguments are
	// never credentials.
	Logf func(format string, arguments ...any)
	// Trust reports the device-local trust policy for the read-only page, and
	// RequireSendSMS asks the same gate the Core protocol uses whether an SMS
	// may be sent now (nil: yes). Neither can change a policy. See trust.go.
	Trust          func() TrustReport
	RequireSendSMS func() *TrustRefusal
}

// Attach supplies the sources. It is called once, while the agent is being
// assembled and before the console serves a request.
func (a *Admin) Attach(sources Sources) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sources = sources
}

// Unknown is what a fact with no evidence behind it is reported as.
const Unknown = "unknown"

// SecurityReport is the read-only security page. Every field is a public
// fingerprint, a name or a state. There is no field a key could travel in.
type SecurityReport struct {
	DeviceID            string `json:"device_id"`
	IdentityAlgorithm   string `json:"identity_algorithm"`
	IdentityFingerprint string `json:"identity_fingerprint"`
	// SecurityLevel is STANDARD, PQ or PQ_EXTREME.
	SecurityLevel string            `json:"security_level"`
	PQIdentity    PQIdentityReport  `json:"pq_identity"`
	Owner         OwnerReport       `json:"owner"`
	AdminTLS      CertificateReport `json:"admin_tls"`
}

// PQIdentityReport is the device's additional post-quantum identity.
type PQIdentityReport struct {
	// Status is active, unavailable (this build has no ML-DSA), disabled or
	// damaged.
	Status      string `json:"status"`
	Algorithm   string `json:"algorithm,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// Detail is the store's own reason for a status that is not active.
	Detail string `json:"detail,omitempty"`
	// Policy is how much post-quantum identity this device demands of a Core.
	Policy string `json:"policy,omitempty"`
}

// OwnerReport is the Core this device is paired with, as the device pinned it.
type OwnerReport struct {
	// Paired and PQPinned are yes, no or unknown.
	Paired          string `json:"paired"`
	CoreID          string `json:"core_id,omitempty"`
	CoreFingerprint string `json:"core_fingerprint,omitempty"`
	PQPinned        string `json:"pq_pinned"`
	PQAlgorithm     string `json:"pq_algorithm,omitempty"`
	PQFingerprint   string `json:"pq_fingerprint,omitempty"`
}

// CertificateReport is the certificate this console itself is served with.
type CertificateReport struct {
	// FingerprintSHA256 is the digest a browser shows for the certificate.
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	KeyAlgorithm      string     `json:"key_algorithm,omitempty"`
	NotBefore         *time.Time `json:"not_before,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
}

func orUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return Unknown
	}
	return value
}

// normalize turns every missing answer into "unknown". A blank on a security
// page reads as "nothing to worry about"; that is not what a blank means.
func (s SecurityReport) normalize() SecurityReport {
	s.DeviceID = orUnknown(s.DeviceID)
	s.IdentityAlgorithm = orUnknown(s.IdentityAlgorithm)
	s.IdentityFingerprint = orUnknown(s.IdentityFingerprint)
	s.SecurityLevel = orUnknown(s.SecurityLevel)
	s.PQIdentity.Status = orUnknown(s.PQIdentity.Status)
	if s.PQIdentity.Status == "active" {
		s.PQIdentity.Algorithm = orUnknown(s.PQIdentity.Algorithm)
		s.PQIdentity.Fingerprint = orUnknown(s.PQIdentity.Fingerprint)
	}
	s.PQIdentity.Policy = orUnknown(s.PQIdentity.Policy)
	s.Owner.Paired = orUnknown(s.Owner.Paired)
	s.Owner.PQPinned = orUnknown(s.Owner.PQPinned)
	if s.Owner.Paired == "yes" {
		s.Owner.CoreID = orUnknown(s.Owner.CoreID)
		s.Owner.CoreFingerprint = orUnknown(s.Owner.CoreFingerprint)
	}
	if s.Owner.PQPinned == "yes" {
		s.Owner.PQAlgorithm = orUnknown(s.Owner.PQAlgorithm)
		s.Owner.PQFingerprint = orUnknown(s.Owner.PQFingerprint)
	}
	s.AdminTLS.FingerprintSHA256 = orUnknown(s.AdminTLS.FingerprintSHA256)
	s.AdminTLS.KeyAlgorithm = orUnknown(s.AdminTLS.KeyAlgorithm)
	return s
}

func (a *Admin) security(w http.ResponseWriter, _ *http.Request, _ string, _ http.Handler) {
	a.mu.Lock()
	source := a.sources.Security
	a.mu.Unlock()
	report := SecurityReport{DeviceID: a.options.DeviceID}
	if source != nil {
		report = source()
	}
	respond(w, 200, report.normalize())
}

// ---------------------------------------------------------------------------
// Updates
// ---------------------------------------------------------------------------

// Updates is the part of the agent update service this console uses: reading
// where the update machine is, and undoing an update that has been applied
// and not yet confirmed. Offering, uploading, applying and confirming a
// release are the paired Core's job and have no route here.
type Updates interface {
	Status() proto.OTADeviceStatus
	Rollback(ctx context.Context, releaseID string) (proto.OTADeviceStatus, error)
}

// The reasons a rollback is refused, for the adapter to translate the update
// service's own errors into. Anything else is reported as a plain failure.
var (
	ErrUpdateUnsupported = errors.New("updates are not supported on this device")
	ErrUpdateNoRelease   = errors.New("that release is not the one applied")
	ErrUpdateNotPending  = errors.New("no applied update is awaiting confirmation")
	ErrUpdateBusy        = errors.New("an update operation is already in progress")
)

// updateView is GET /admin/api/v1/update.
type updateView struct {
	// Available is false on a build with no update service at all. That is a
	// property of the build, reported as such, and not an error.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// Status is the update service's own document. It carries versions,
	// states and key COUNTS; no key and no path.
	Status *proto.OTADeviceStatus `json:"status,omitempty"`
	// CanRollback is true only for an applied update that nobody has
	// confirmed yet, which is the one thing this console may undo.
	CanRollback bool `json:"can_rollback"`
}

func canRollback(status proto.OTADeviceStatus) bool {
	return status.Supported && status.State == proto.OTAPendingConfirm && status.ReleaseID != "" && !status.RestartPending
}
func (a *Admin) updates() Updates {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sources.Updates
}
func (a *Admin) update(w http.ResponseWriter, _ *http.Request, _ string, _ http.Handler) {
	service := a.updates()
	if service == nil {
		respond(w, 200, updateView{Reason: "not supported in this build"})
		return
	}
	status := service.Status()
	respond(w, 200, updateView{Available: true, Status: &status, CanRollback: canRollback(status)})
}
func (a *Admin) updateRollback(w http.ResponseWriter, r *http.Request, _ string, _ http.Handler) {
	var v struct {
		ReleaseID string `json:"release_id"`
	}
	if !decode(w, r, &v) {
		return
	}
	service := a.updates()
	if service == nil {
		failCode(w, 501, "not_supported", "此版本没有更新服务，无法回滚")
		return
	}
	// The page sends back the release it showed, so "roll back" always means
	// "roll back what I was looking at" and never whatever is applied by now.
	if proto.ValidateOTAReleaseID(v.ReleaseID) != nil {
		failCode(w, 400, "invalid_argument", "缺少有效的发布编号")
		return
	}
	status := service.Status()
	if !status.Supported {
		failCode(w, 501, "not_supported", "此设备不支持更新，无法回滚")
		return
	}
	if !canRollback(status) || status.ReleaseID != v.ReleaseID {
		failCode(w, 409, "not_pending", "当前没有等待确认的更新，无法回滚")
		return
	}
	status, err := service.Rollback(r.Context(), v.ReleaseID)
	switch {
	case err == nil:
	case errors.Is(err, ErrUpdateUnsupported):
		failCode(w, 501, "not_supported", "此设备不支持更新，无法回滚")
		return
	case errors.Is(err, ErrUpdateNoRelease), errors.Is(err, ErrUpdateNotPending):
		failCode(w, 409, "not_pending", "当前没有等待确认的更新，无法回滚")
		return
	case errors.Is(err, ErrUpdateBusy):
		failCode(w, 409, "busy", "另一项更新操作正在进行，请稍后再试")
		return
	default:
		// The cause goes to the log, which redacts; the page gets a sentence.
		a.logf("rollback of update %s requested from the local console failed: %v", v.ReleaseID, err)
		failCode(w, 500, "rollback_failed", "回滚未完成，请查看诊断日志")
		return
	}
	a.logf("update %s rolled back from the local console; the agent will restart", v.ReleaseID)
	respond(w, 202, updateView{Available: true, Status: &status, CanRollback: canRollback(status)})
}

// ---------------------------------------------------------------------------
// Wi-Fi
// ---------------------------------------------------------------------------

// WiFiReader is the one thing this package needs from the Wi-Fi backend.
type WiFiReader interface {
	Status(ctx context.Context) (proto.WiFiStatus, error)
}

// wifiChange remembers the last change submitted from this console, so the
// page can be told what it led to. It holds SSIDs and states. The passphrase
// is never kept: which is also why this package cannot put the previous
// network back by itself, and only reports whether the backend did.
type wifiChange struct {
	target        string
	previous      proto.WiFiStatus
	previousKnown bool
	started       time.Time
	forgotten     bool
}

// wifiOutcomeView is GET /admin/api/v1/wifi/change.
type wifiOutcomeView struct {
	// Outcome is one of:
	//   none             nothing was changed from this console since start-up
	//   pending          the join is still being attempted
	//   connected        the device is on the requested network
	//   restored         the join failed and the device is back on the
	//                    network it was using before
	//   provisioning_ap  the device is serving its setup access point
	//   failed           the join failed; the backend is in its recovery
	//                    window and has not settled yet
	//   not_connected    Wi-Fi is down; SavedSSID says whether the earlier
	//                    configuration is still stored
	//   forgotten        the saved network was removed on request
	//   unknown          the radio state could not be read, or nothing
	//                    settled within the window
	Outcome string `json:"outcome"`
	// Settled is false while the outcome may still change.
	Settled       bool            `json:"settled"`
	TargetSSID    string          `json:"target_ssid,omitempty"`
	PreviousSSID  string          `json:"previous_ssid,omitempty"`
	PreviousState proto.WiFiState `json:"previous_state,omitempty"`
	State         proto.WiFiState `json:"state,omitempty"`
	SSID          string          `json:"ssid,omitempty"`
	SavedSSID     string          `json:"saved_ssid,omitempty"`
	APSSID        string          `json:"ap_ssid,omitempty"`
	APAddress     string          `json:"ap_address,omitempty"`
	FailureReason string          `json:"failure_reason,omitempty"`
	// ProvisioningState and ProvisioningReason are the backend's own finer
	// state, passed through; absent when the backend gave none.
	ProvisioningState  proto.WiFiProvisioningState `json:"provisioning_state,omitempty"`
	ProvisioningReason string                      `json:"provisioning_reason,omitempty"`
	ElapsedSeconds     int                         `json:"elapsed_seconds"`
	WindowSeconds      int                         `json:"window_seconds"`
}

// validWiFi returns a message for the first thing wrong with a request, or "".
//
// The limits are the standard's: an SSID is at most 32 bytes; a WPA passphrase
// is 8 to 63 characters, or exactly 64 hexadecimal digits when it is the
// pre-computed key, which WPA3 (SAE) does not have.
func validWiFi(request proto.WiFiConnectRequest) string {
	ssid := request.SSID
	switch {
	case strings.TrimSpace(ssid) == "":
		return "请填写网络名称（SSID）"
	case !utf8.ValidString(ssid):
		return "网络名称不是有效的 UTF-8 文本"
	case len(ssid) > 32:
		return "网络名称过长：SSID 最多 32 字节（一个汉字占 3 字节）"
	case hasControl(ssid):
		return "网络名称不能包含控制字符"
	}
	psk := request.PSK
	switch request.Security {
	case proto.WiFiSecurityOpen:
		if psk != "" {
			return "开放网络不需要密码，请清空密码或改选加密方式"
		}
		return ""
	case proto.WiFiSecurityWPA2, proto.WiFiSecurityWPA3:
	default:
		return "请选择加密方式：WPA2、WPA3 或开放网络"
	}
	switch {
	case psk == "":
		return "请填写 Wi-Fi 密码"
	case !utf8.ValidString(psk) || hasControl(psk):
		return "Wi-Fi 密码不能包含控制字符"
	case len(psk) == 64:
		if request.Security != proto.WiFiSecurityWPA2 {
			return "64 位十六进制密钥仅适用于 WPA2；WPA3 请填写 8 至 63 位密码"
		}
		if !hexKey.MatchString(psk) {
			return "64 位的 Wi-Fi 密钥必须全部是十六进制字符（0-9、a-f）"
		}
	case len(psk) < 8:
		return "Wi-Fi 密码至少 8 位"
	case len(psk) > 63:
		return "Wi-Fi 密码最多 63 位（或 64 位十六进制密钥）"
	}
	return ""
}

var hexKey = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)

func hasControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

// recorder notes the status the device handler answered with.
type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	return r.ResponseWriter.Write(b)
}

// forward hands a validated request to the device handler exactly once. The
// body is re-encoded from what was validated, so the handler acts on the bytes
// that were checked and not on a second reading of the original.
func forward(api http.Handler, w http.ResponseWriter, r *http.Request, body any) int {
	if api == nil {
		http.NotFound(w, r)
		return 404
	}
	encoded, _ := json.Marshal(body)
	next := r.Clone(r.Context())
	next.Body = io.NopCloser(bytes.NewReader(encoded))
	next.ContentLength = int64(len(encoded))
	next.Header.Set("Content-Type", "application/json")
	recorded := &recorder{ResponseWriter: w}
	http.StripPrefix("/admin/api", api).ServeHTTP(recorded, next)
	return recorded.status
}
func (a *Admin) wifiReader() WiFiReader {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sources.WiFi
}
func (a *Admin) wifiConnect(w http.ResponseWriter, r *http.Request, _ string, api http.Handler) {
	var request proto.WiFiConnectRequest
	if !decode(w, r, &request) {
		return
	}
	if message := validWiFi(request); message != "" {
		failCode(w, 400, "invalid_argument", message)
		return
	}
	// What the radio was doing before, read before anything is changed. It
	// is the only way to say afterwards "back on the old network" rather
	// than merely "connected to something".
	change := &wifiChange{target: strings.TrimSpace(request.SSID), started: a.options.Now()}
	if reader := a.wifiReader(); reader != nil {
		if previous, err := reader.Status(r.Context()); err == nil {
			change.previous, change.previousKnown = previous, true
		}
	}
	if status := forward(api, w, r, request); status >= 200 && status < 300 {
		a.mu.Lock()
		a.change = change
		a.mu.Unlock()
	}
}
func (a *Admin) wifiForget(w http.ResponseWriter, r *http.Request, _ string, api http.Handler) {
	change := &wifiChange{forgotten: true, started: a.options.Now()}
	if reader := a.wifiReader(); reader != nil {
		if previous, err := reader.Status(r.Context()); err == nil {
			change.previous, change.previousKnown = previous, true
		}
	}
	if status := forward(api, w, r, struct{}{}); status >= 200 && status < 300 {
		a.mu.Lock()
		a.change = change
		a.mu.Unlock()
	}
}

// wifiOutcome reports what the last change led to, from the radio's state as
// it is NOW. Nothing is cached: an outcome is recomputed on every read, so a
// device that recovered a minute after the page gave up is reported as
// recovered the next time anyone looks.
func (a *Admin) wifiOutcome(w http.ResponseWriter, r *http.Request, _ string, _ http.Handler) {
	a.mu.Lock()
	change := a.change
	reader := a.sources.WiFi
	a.mu.Unlock()
	view := wifiOutcomeView{Outcome: "none", Settled: true, WindowSeconds: int(wifiSettleWindow.Seconds())}
	if change == nil {
		respond(w, 200, view)
		return
	}
	elapsed := a.options.Now().Sub(change.started)
	late := elapsed >= wifiSettleWindow
	view.TargetSSID = change.target
	view.ElapsedSeconds = int(elapsed.Seconds())
	if change.previousKnown {
		view.PreviousSSID = change.previous.SSID
		if view.PreviousSSID == "" {
			view.PreviousSSID = change.previous.SavedSSID
		}
		view.PreviousState = change.previous.State
	}
	var status proto.WiFiStatus
	err := errors.New("no Wi-Fi backend")
	if reader != nil {
		status, err = reader.Status(r.Context())
	}
	if err != nil {
		view.Outcome, view.Settled = Unknown, late
		respond(w, 200, view)
		return
	}
	view.State, view.SSID, view.SavedSSID = status.State, status.SSID, status.SavedSSID
	view.APSSID, view.APAddress, view.FailureReason = status.APSSID, status.APAddress, status.FailureReason
	view.ProvisioningState, view.ProvisioningReason = status.ProvisioningState, status.ProvisioningReason
	switch {
	case change.forgotten:
		switch status.State {
		case proto.WiFiProvisioningAP:
			view.Outcome = "provisioning_ap"
		case proto.WiFiConnected, proto.WiFiConnecting:
			// Asked to forget and still on a network: not what was asked
			// for, and not something to describe as done.
			view.Outcome = Unknown
		default:
			view.Outcome = "forgotten"
		}
	case status.State == proto.WiFiConnecting:
		view.Outcome, view.Settled = "pending", false
	case status.State == proto.WiFiConnected && status.SSID == change.target:
		view.Outcome = "connected"
	case status.State == proto.WiFiConnected && change.previousKnown && status.SSID != "" && status.SSID == change.previous.SSID:
		view.Outcome = "restored"
	case status.State == proto.WiFiConnected:
		// On some network that is neither the one asked for nor the one
		// before. Say so rather than guess which.
		view.Outcome = Unknown
	case status.State == proto.WiFiProvisioningAP:
		view.Outcome = "provisioning_ap"
	case status.State == proto.WiFiFailed:
		view.Outcome, view.Settled = "failed", false
	case status.State == proto.WiFiNoConfig:
		// The backend may still be bringing the saved network back.
		view.Outcome, view.Settled = "not_connected", false
	default:
		view.Outcome = Unknown
	}
	if late && !view.Settled {
		// Past the window nothing more is expected to happen by itself.
		view.Settled = true
		if view.Outcome == "pending" {
			view.Outcome = Unknown
		}
	}
	respond(w, 200, view)
}

// ---------------------------------------------------------------------------
// SMS
// ---------------------------------------------------------------------------

// The limits below are the modem backend's own (modembackend/msm8916). They
// are repeated here so a mistake gets a sentence the user can act on instead
// of the backend's terse refusal; the backend still has the last word.
const maxSMSBytes = 4096

var (
	smsRecipient = regexp.MustCompile(`^\+?[0-9]{3,20}$`)
	smsRequestID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

func validSMS(request proto.SendSMSRequest) string {
	switch {
	case !smsRequestID.MatchString(request.RequestID):
		return "请求编号无效，请刷新页面后重试"
	case request.To == "":
		return "请填写收件号码"
	case !smsRecipient.MatchString(request.To):
		return "收件号码只能包含 3 至 20 位数字，可以 + 开头，不能有空格或横线"
	case strings.TrimSpace(request.Text) == "":
		return "请填写短信内容"
	case !utf8.ValidString(request.Text):
		return "短信内容不是有效的 UTF-8 文本"
	case len(request.Text) > maxSMSBytes:
		return "短信内容过长：最多 4096 字节（一个汉字占 3 字节）"
	}
	return ""
}

// smsSend validates and forwards once. The request id travels through
// untouched: it is what makes a repeat of the SAME request return the first
// receipt instead of sending again, and nothing here ever repeats a request.
func (a *Admin) smsSend(w http.ResponseWriter, r *http.Request, _ string, api http.Handler) {
	// The trust gate comes first, before the body is read. The device handler
	// this forwards to checks it again; asking here is what lets the refusal
	// say, in the page's language, who decides and what to do.
	if a.refuseSMS(w) {
		return
	}
	var request proto.SendSMSRequest
	if !decodeLimit(w, r, &request, 32<<10) {
		return
	}
	if message := validSMS(request); message != "" {
		failCode(w, 400, "invalid_argument", message)
		return
	}
	forward(api, w, r, request)
}
