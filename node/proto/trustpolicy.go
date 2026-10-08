package proto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Device-local trust enforcement (protocol 1.4, additive).
//
// The gateway's trust engine DECIDES how far a device may be used. Until 1.4
// it was also the only thing that enforced the decision: a restricted device
// still did whatever an authenticated session asked of it. That leaves three
// ways around a restriction which have nothing to do with breaking a key - a
// bug in the gateway process, a request replayed at the device, and the
// device's own standalone administration page, which never goes through the
// gateway at all.
//
// So the gateway now SIGNS its decision and the device enforces the signed
// document:
//
//	POST /v1/trust/policy   authenticated session AND a signed body. The
//	                        device installs it when the signature is the
//	                        pinned owner's and the generation is not older
//	                        than the one it holds.
//	GET  /v1/trust          authenticated. What the device holds and whether
//	                        it is enforcing it.
//
// An older Core never calls either. An older Node answers 404, which the Core
// reports as "this device does not enforce" - one informational fact, not an
// error.
//
// # Why the signature and not the session
//
// A bearer session proves "the owner opened this session". It says nothing
// about which bytes the owner meant to send over it, and it cannot be told
// apart from a recording played back while the session is alive. The policy
// therefore carries its own Ed25519 signature (and, when the Core has a
// post-quantum key, an ML-DSA signature over the same bytes), verified against
// the key the device pinned at pairing. Nothing in an HTTP header conveys
// authority.
//
// # Why not json.Marshal
//
// For the reasons the release manifest and the pairing transcript give: field
// order, whitespace and number formatting in JSON are not canonical, so a
// signature made by one encoder need not verify against another's bytes, and a
// signature has to survive a Go release and a reimplementation. The signed
// bytes are a fixed-order, line-based encoding that begins with a domain line.
// The JSON envelope is only the carrier.

// Trust endpoints.
const (
	TrustPolicyPath = "/v1/trust/policy"
	TrustStatusPath = "/v1/trust"
)

// TrustPolicyVersion is the only policy document version.
const TrustPolicyVersion = 1

// TrustPolicyDomain is the first line of the signed bytes.
//
// It is what makes it safe for the Core's one identity key to sign policies as
// well as requests and (on the device side of the same protocol) pairing
// transcripts: a request's canonical string starts with an upper-case HTTP
// method, a pairing transcript with a four-byte big-endian length, an update
// manifest with its own domain - none can begin with this line, and these
// bytes can begin with nothing else. TestTrustPolicyDomainSeparation holds
// both directions. If the encoding ever changes meaning, this string changes
// with it.
const TrustPolicyDomain = "nsh-domain=trust-policy-v1"

// Bounds on a policy document. They are internal to the document: a device
// never compares a policy's times with its own wall clock to decide whether to
// accept it, because a device with no battery-backed clock boots with a wrong
// one (agent/trust explains what it does instead).
const (
	// TrustPolicyMaxValidity bounds expires_at - issued_at.
	TrustPolicyMaxValidity = 7 * 24 * time.Hour
	// TrustPolicyReasonMaxBytes bounds the reason text.
	TrustPolicyReasonMaxBytes = 160
	// trustIDMaxBytes bounds device_id and core_id.
	trustIDMaxBytes = 128
)

// TrustState is the gateway's trust state for the device. The names are the
// engine's.
type TrustState string

const (
	TrustUnbound     TrustState = "UNBOUND"
	TrustObservation TrustState = "OBSERVATION"
	TrustTrusted     TrustState = "TRUSTED"
	TrustRestricted  TrustState = "RESTRICTED"
	TrustQuarantine  TrustState = "QUARANTINE"
)

// TrustMode says whether the deny list is enforced or only counted.
type TrustMode string

const (
	TrustEnforce TrustMode = "enforce"
	// TrustMonitor refuses nothing and counts what would have been refused. It
	// mirrors the gateway's monitor mode, which exists for bringing up
	// hardware.
	TrustMonitor TrustMode = "monitor"
)

// TrustAction is something the device can be told to refuse. Only outgoing
// use is ever gated: answering, hanging up, receiving, status, diagnostics,
// Wi-Fi, updates and pairing are not in this list and cannot be denied.
type TrustAction string

const (
	TrustActionDial       TrustAction = "dial"
	TrustActionSendSMS    TrustAction = "send_sms"
	TrustActionDTMF       TrustAction = "dtmf"
	TrustActionForwardOTP TrustAction = "forward_otp"
)

// TrustActions lists every action a policy may deny, sorted as a deny list is.
var TrustActions = []TrustAction{TrustActionDial, TrustActionDTMF, TrustActionForwardOTP, TrustActionSendSMS}

func knownTrustAction(action TrustAction) bool {
	for _, known := range TrustActions {
		if action == known {
			return true
		}
	}
	return false
}

// TrustPolicy is what the gateway decided for one device.
type TrustPolicy struct {
	Version  int    `json:"version"`
	DeviceID string `json:"device_id"`
	CoreID   string `json:"core_id"`
	// Generation increases strictly per device and Core. It is the whole
	// anti-rollback mechanism: a device never installs a lower one.
	Generation uint64     `json:"generation"`
	State      TrustState `json:"state"`
	Mode       TrustMode  `json:"mode"`
	// Deny is sorted and without duplicates. An empty list is "nothing is
	// refused", and is encoded as [] rather than omitted.
	Deny []TrustAction `json:"deny"`
	// Reason is a short explanation for a person. It carries no identifier.
	Reason string `json:"reason"`
	// IssuedAt and ExpiresAt are RFC 3339 UTC to the second ("...Z"). They are
	// strings so that the text that was signed is the text that is carried.
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

// SignedTrustPolicy is the JSON envelope: the policy and its signatures.
type SignedTrustPolicy struct {
	TrustPolicy
	// Signature is Ed25519 over Canonical(), base64.
	Signature string `json:"signature"`
	// PQSignature is the Core's post-quantum signature over the same bytes.
	PQSignature string               `json:"pq_signature,omitempty"`
	PQAlgorithm PQSignatureAlgorithm `json:"pq_algorithm,omitempty"`
}

// Errors of the policy path. Distinct values, because "this is not a policy",
// "this policy is not the owner's" and "this policy is for another device" are
// different facts and are reported differently.
var (
	// ErrTrustPolicyInvalid means the document is malformed.
	ErrTrustPolicyInvalid = errors.New("trust policy is not valid")
	// ErrTrustPolicySignature means the Ed25519 signature is not the owner's.
	ErrTrustPolicySignature = errors.New("trust policy is not signed by the paired owner")
	// ErrTrustPolicyWrongDevice means the policy names another device.
	ErrTrustPolicyWrongDevice = errors.New("trust policy is for another device")
	// ErrTrustPolicyWrongCore means the policy names a Core other than the
	// pinned owner.
	ErrTrustPolicyWrongCore = errors.New("trust policy is from a core that is not the paired owner")
)

// FormatTrustTime renders a policy time.
func FormatTrustTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

// ParseTrustTime reads a policy time, accepting only the exact form
// FormatTrustTime writes.
func ParseTrustTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || !strings.HasSuffix(value, "Z") || FormatTrustTime(parsed) != value {
		return time.Time{}, fmt.Errorf("%w: %q is not an RFC 3339 UTC time to the second", ErrTrustPolicyInvalid, value)
	}
	return parsed, nil
}

// Times returns the parsed issue and expiry times.
func (p TrustPolicy) Times() (issued, expires time.Time, err error) {
	if issued, err = ParseTrustTime(p.IssuedAt); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if expires, err = ParseTrustTime(p.ExpiresAt); err != nil {
		return time.Time{}, time.Time{}, err
	}
	return issued, expires, nil
}

// cleanTrustText reports whether a value can sit on one line of the canonical
// encoding and be shown to a person: valid UTF-8, no control character.
func cleanTrustText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == ' ' || character == ' ' {
			return false
		}
	}
	return true
}

func cleanTrustID(value string) bool {
	if value == "" || len(value) > trustIDMaxBytes {
		return false
	}
	for _, character := range value {
		// Printable ASCII without space: an identifier is never free text.
		if character <= ' ' || character > '~' {
			return false
		}
	}
	return true
}

// Validate checks everything about a policy that needs no key and no clock.
func (p TrustPolicy) Validate() error {
	fail := func(format string, arguments ...any) error {
		return fmt.Errorf("%w: %s", ErrTrustPolicyInvalid, fmt.Sprintf(format, arguments...))
	}
	if p.Version != TrustPolicyVersion {
		return fail("version %d is not supported", p.Version)
	}
	if !cleanTrustID(p.DeviceID) {
		return fail("device_id is missing or malformed")
	}
	if !cleanTrustID(p.CoreID) {
		return fail("core_id is missing or malformed")
	}
	if p.Generation == 0 {
		return fail("generation must be positive")
	}
	switch p.State {
	case TrustUnbound, TrustObservation, TrustTrusted, TrustRestricted, TrustQuarantine:
	default:
		return fail("unknown state")
	}
	switch p.Mode {
	case TrustEnforce, TrustMonitor:
	default:
		return fail("unknown mode")
	}
	for index, action := range p.Deny {
		if !knownTrustAction(action) {
			return fail("unknown action in deny")
		}
		if index > 0 && p.Deny[index-1] >= action {
			return fail("deny must be sorted and without duplicates")
		}
	}
	if len(p.Reason) > TrustPolicyReasonMaxBytes || !cleanTrustText(p.Reason) {
		return fail("reason is too long or contains control characters")
	}
	issued, expires, err := p.Times()
	if err != nil {
		return err
	}
	if !expires.After(issued) {
		return fail("expires_at is not after issued_at")
	}
	if expires.Sub(issued) > TrustPolicyMaxValidity {
		return fail("validity exceeds %s", TrustPolicyMaxValidity)
	}
	return nil
}

// Denies reports whether the policy lists an action.
func (p TrustPolicy) Denies(action TrustAction) bool {
	for _, denied := range p.Deny {
		if denied == action {
			return true
		}
	}
	return false
}

// Canonical renders the exact bytes that are signed.
//
// Every field appears, in this order, whether or not it is empty, one per
// line, after the domain line. Validate has refused any value containing a
// line break or a control character, and the deny list's members are fixed
// words, so no value can run into the next line or the next list entry.
func (p TrustPolicy) Canonical() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	deny := make([]string, len(p.Deny))
	for index, action := range p.Deny {
		deny[index] = string(action)
	}
	var builder strings.Builder
	write := func(key, value string) {
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(value)
		builder.WriteByte('\n')
	}
	// Written whole: the domain line carries its own '='.
	builder.WriteString(TrustPolicyDomain)
	builder.WriteByte('\n')
	write("version", strconv.Itoa(p.Version))
	write("device_id", p.DeviceID)
	write("core_id", p.CoreID)
	write("generation", strconv.FormatUint(p.Generation, 10))
	write("state", string(p.State))
	write("mode", string(p.Mode))
	write("deny", strings.Join(deny, ","))
	write("reason", p.Reason)
	write("issued_at", p.IssuedAt)
	write("expires_at", p.ExpiresAt)
	return []byte(builder.String()), nil
}

// NormalizeTrustDeny sorts a deny list and removes duplicates, for the signer.
func NormalizeTrustDeny(actions []TrustAction) []TrustAction {
	sorted := append([]TrustAction{}, actions...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	out := sorted[:0]
	for index, action := range sorted {
		if index == 0 || sorted[index-1] != action {
			out = append(out, action)
		}
	}
	return out
}

// SignTrustPolicy signs a policy with the Core's identity key and, when the
// Core has one, its post-quantum key. A post-quantum signer that fails is an
// error and never a quietly classical policy: a device that requires the
// second signature would refuse it anyway, with a less useful message.
func SignTrustPolicy(policy TrustPolicy, key ed25519.PrivateKey, pq PQSigner) (SignedTrustPolicy, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedTrustPolicy{}, errors.New("a trust policy is signed with the core identity key")
	}
	if policy.Deny == nil {
		policy.Deny = []TrustAction{}
	}
	canonical, err := policy.Canonical()
	if err != nil {
		return SignedTrustPolicy{}, err
	}
	signed := SignedTrustPolicy{TrustPolicy: policy, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, canonical))}
	if pq != nil {
		signature, err := pq.Sign(canonical)
		if err != nil {
			return SignedTrustPolicy{}, fmt.Errorf("post-quantum policy signing failed: %w", err)
		}
		signed.PQSignature = base64.StdEncoding.EncodeToString(signature)
		signed.PQAlgorithm = pq.Algorithm()
	}
	return signed, nil
}

// DecodeSignedTrustPolicy reads an envelope strictly: an unknown field, a
// second JSON value or a missing deny list is a refusal. A document this
// device does not fully understand is not one it should enforce a part of.
func DecodeSignedTrustPolicy(raw []byte) (SignedTrustPolicy, error) {
	var signed SignedTrustPolicy
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		return SignedTrustPolicy{}, fmt.Errorf("%w: %v", ErrTrustPolicyInvalid, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return SignedTrustPolicy{}, fmt.Errorf("%w: trailing data", ErrTrustPolicyInvalid)
	}
	if signed.Deny == nil {
		return SignedTrustPolicy{}, fmt.Errorf("%w: deny is required", ErrTrustPolicyInvalid)
	}
	if err := signed.Validate(); err != nil {
		return SignedTrustPolicy{}, err
	}
	if signed.Signature == "" {
		return SignedTrustPolicy{}, fmt.Errorf("%w: signature is required", ErrTrustPolicyInvalid)
	}
	if (signed.PQSignature == "") != (signed.PQAlgorithm == "") {
		return SignedTrustPolicy{}, fmt.Errorf("%w: pq_signature and pq_algorithm go together", ErrTrustPolicyInvalid)
	}
	return signed, nil
}

// SameSignedTrustPolicy reports whether two envelopes are the same signed
// document: the same signed bytes under the same signatures. It is what makes
// re-pushing a policy idempotent without depending on JSON whitespace.
func SameSignedTrustPolicy(a, b SignedTrustPolicy) bool {
	left, errLeft := a.Canonical()
	right, errRight := b.Canonical()
	return errLeft == nil && errRight == nil && bytes.Equal(left, right) &&
		a.Signature == b.Signature && a.PQSignature == b.PQSignature && a.PQAlgorithm == b.PQAlgorithm
}

// TrustPolicyExpectation is what a device knows before it reads a policy: who
// it is and who owns it. All of it comes from the device's own pairing state.
type TrustPolicyExpectation struct {
	DeviceID string
	CoreID   string
	CoreKey  ed25519.PublicKey
	// CorePQ is the owner's pinned post-quantum key, or empty.
	CorePQ PQIdentity
	// PQPolicy is the device's post-quantum identity policy.
	PQPolicy PQIdentityPolicy
}

// VerifyTrustPolicy decides whether a policy is the paired owner's decision
// about this device. It consults no clock and no stored generation; those are
// the installer's rules.
//
// In order, and every failure returns:
//
//  1. the document is well formed;
//  2. it names this device and the pinned owner;
//  3. the Ed25519 signature verifies against the pinned owner key;
//  4. the post-quantum half: under a required policy the signature must be
//     present and verify against the pinned key; otherwise a signature that is
//     present and can be checked against a pinned key must verify, and an
//     absent one is accepted.
//
// The classical check comes first for the reason VerifyPairingTranscript
// gives: a second signature over bytes the owner's classical key did not sign
// proves nothing about the owner.
func VerifyTrustPolicy(signed SignedTrustPolicy, expect TrustPolicyExpectation) (IdentityOutcome, error) {
	if err := ValidatePQIdentityPolicy(expect.PQPolicy); err != nil {
		return "", err
	}
	canonical, err := signed.Canonical()
	if err != nil {
		return "", err
	}
	if expect.DeviceID == "" || signed.DeviceID != expect.DeviceID {
		return "", ErrTrustPolicyWrongDevice
	}
	if expect.CoreID == "" || signed.CoreID != expect.CoreID {
		return "", ErrTrustPolicyWrongCore
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || len(expect.CoreKey) != ed25519.PublicKeySize || !ed25519.Verify(expect.CoreKey, canonical, signature) {
		return "", ErrTrustPolicySignature
	}

	hasPQ := signed.PQSignature != "" && signed.PQAlgorithm != ""
	required := expect.PQPolicy == PQIdentityRequired
	switch {
	case !hasPQ && required:
		return "", fmt.Errorf("%w: %w", ErrPQIdentityRequired, ErrPQIdentityMissing)
	case !hasPQ:
		return IdentityClassicalOnly, nil
	case !expect.CorePQ.Present() && required:
		// Required, and no key was ever pinned to check against.
		return "", fmt.Errorf("%w: %w", ErrPQIdentityRequired, ErrPQIdentityMissing)
	case !expect.CorePQ.Present():
		// A Core that gained a post-quantum key after this pairing was made.
		// There is no pinned key, so the signature can establish nothing; the
		// policy stands on its verified Ed25519 signature, as its requests do.
		return IdentityClassicalOnly, nil
	}
	if err := expect.CorePQ.Validate(); err != nil {
		return "", fmt.Errorf("%w: %s", ErrPQIdentityInvalid, err)
	}
	if signed.PQAlgorithm != expect.CorePQ.Algorithm {
		return "", fmt.Errorf("%w: signature claims %s, the pinned key is %s", ErrPQIdentityInvalid, signed.PQAlgorithm, expect.CorePQ.Algorithm)
	}
	verifier, err := PQVerifierFor(signed.PQAlgorithm)
	if err != nil {
		// A signature is present and this build cannot check it. "Present must
		// verify" has no honest reading under which that is acceptable.
		return "", fmt.Errorf("%w: %w", ErrPQIdentityRequired, err)
	}
	publicKey, err := base64.StdEncoding.DecodeString(expect.CorePQ.PublicKey)
	if err != nil {
		return "", fmt.Errorf("%w: pinned public key is not base64", ErrPQIdentityInvalid)
	}
	raw, err := base64.StdEncoding.DecodeString(signed.PQSignature)
	if err != nil {
		return "", fmt.Errorf("%w: signature is not base64", ErrPQIdentityInvalid)
	}
	if err := verifier.Verify(publicKey, canonical, raw); err != nil {
		return "", fmt.Errorf("%w: %s", ErrPQIdentityInvalid, err)
	}
	return IdentityDual, nil
}

// ---------------------------------------------------------------------------
// What the device reports
// ---------------------------------------------------------------------------

// HardwareIdentity is the device's credible hardware identifier, when it has
// one, for "the module was replaced" detection.
//
// On an MSM8916 the modem is part of the SoC, so the identifier is the SoC
// serial the kernel's Qualcomm socinfo driver exposes. The raw serial never
// leaves the device: SerialSHA256 is a domain-separated digest of it. When no
// such identifier can be read Present is false and Reason says why. Nothing
// else is ever substituted - not an IMEI, not a MAC address, not an interface
// name, not the eMMC's identity (storage is replaceable and is not the
// module), and nothing generated.
type HardwareIdentity struct {
	Present bool `json:"present"`
	// Source names where the identifier came from: "qcom-socinfo".
	Source       string `json:"source,omitempty"`
	SerialSHA256 string `json:"serial_sha256,omitempty"`
	// SocID and Machine are context, not identity: every device of a model
	// shares them.
	SocID   string `json:"soc_id,omitempty"`
	Machine string `json:"machine,omitempty"`
	// Reason says why Present is false.
	Reason string `json:"reason,omitempty"`
}

// HardwareSourceSocinfo is the only hardware identity source.
const HardwareSourceSocinfo = "qcom-socinfo"

// HardwareHashDomain prefixes the serial before it is hashed, so the digest is
// useless as a lookup key for any other purpose.
const HardwareHashDomain = "nsh-hw-v1\x00"

// TrustFreshness is whether an installed policy's permissions hold, and if
// not, why not.
type TrustFreshness string

const (
	TrustFresh TrustFreshness = "fresh"
	// TrustStaleRestart: the device restarted and its owner has not sent the
	// policy since. The device cannot know how long it was off, so it does not
	// guess; the gateway sends the policy again on its next session.
	TrustStaleRestart TrustFreshness = "stale_restart"
	// TrustStaleExpired: the validity the owner signed has run out.
	TrustStaleExpired TrustFreshness = "stale_expired"
)

// TrustStatus is GET /v1/trust.
type TrustStatus struct {
	// Supported is always true in an answer; a device that does not enforce
	// has no such endpoint.
	Supported bool `json:"supported"`
	// Installed is true when a policy from the CURRENT owner is held, valid or
	// damaged.
	Installed  bool          `json:"installed"`
	Generation uint64        `json:"generation"`
	State      TrustState    `json:"state,omitempty"`
	Mode       TrustMode     `json:"mode,omitempty"`
	Deny       []TrustAction `json:"deny"`
	ExpiresAt  string        `json:"expires_at,omitempty"`
	// Stale is true when the policy's permissions no longer hold: the device
	// restarted and the owner has not sent the policy again, its validity ran
	// out, or it is damaged. The deny list stays in force; what is not denied
	// is refused too until the owner sends the policy again or a newer one.
	Stale bool `json:"stale"`
	// Freshness says why (protocol 1.4, additive). It is empty when no policy
	// is installed and when the stored one is damaged - Damaged says that.
	Freshness TrustFreshness `json:"freshness,omitempty"`
	// Enforcing is true when the device would refuse something now.
	Enforcing bool   `json:"enforcing"`
	Reason    string `json:"reason,omitempty"`
	// Damaged is true when the stored policy does not verify against the
	// pinned owner key. Its restrictions are kept; nothing it permits is.
	Damaged bool `json:"damaged"`
	// WouldRefuse counts, since the agent started, requests that monitor mode
	// let through and enforcement would have refused.
	WouldRefuse map[TrustAction]uint64 `json:"would_refuse,omitempty"`
	// Refused counts requests refused since the agent started.
	Refused  map[TrustAction]uint64 `json:"refused,omitempty"`
	Hardware HardwareIdentity       `json:"hardware"`
}
