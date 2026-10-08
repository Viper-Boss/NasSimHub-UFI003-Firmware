package proto

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// Signing headers. Core signs a small number of privileged requests with its
// long-lived key; everything else runs on a short-lived bearer token obtained
// with one of those signed requests. Signing every call would be wasteful on an
// MSM8916, and a bearer-only design would have no way to bootstrap trust.
const (
	HeaderCoreID    = "X-NSH-Core-Id"
	HeaderTimestamp = "X-NSH-Timestamp"
	HeaderNonce     = "X-NSH-Nonce"
	HeaderSignature = "X-NSH-Signature"
	HeaderDeviceID  = "X-NSH-Device-Id"
)

// MaxClockSkew bounds how far a signed request's timestamp may be from the
// Node's clock. It is generous because an MSM8916 with no RTC battery can boot
// with a badly wrong clock until NTP lands.
const MaxClockSkew = 5 * time.Minute

// SigningString builds the canonical bytes a Core signs.
//
// Binding the method, the path and a digest of the body means a captured
// signature cannot be replayed against a different endpoint or with altered
// content. The nonce and timestamp bound replay against the same endpoint.
func SigningString(method, path, timestamp, nonce string, body []byte) []byte {
	digest := sha256.Sum256(body)
	canonical := strings.Join([]string{
		strings.ToUpper(method),
		path,
		timestamp,
		nonce,
		base64.StdEncoding.EncodeToString(digest[:]),
	}, "\n")
	return []byte(canonical)
}

// FormatTimestamp renders a signing timestamp.
func FormatTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// ParseTimestamp reads a signing timestamp.
func ParseTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp must be RFC3339: %w", err)
	}
	return parsed, nil
}

// PairRequest is the body of POST /v1/pair. It is signed with the Core key it
// carries, which proves the sender holds the private half.
type PairRequest struct {
	CoreID        string `json:"core_id"`
	CoreName      string `json:"core_name"`
	CorePublicKey string `json:"core_public_key"`
	// CorePQ is the Core's ADDITIONAL post-quantum public key, when it has one
	// (protocol 1.3). The request then also carries HeaderPQSignature over the
	// same canonical bytes. An older Node ignores the field and the header; an
	// older Core sends neither. See pqattest.go.
	CorePQ *PQIdentity `json:"core_pq,omitempty"`
}

// OfferedPQ returns the post-quantum identity a pair request carries, or an
// empty one.
func (r PairRequest) OfferedPQ() PQIdentity {
	if r.CorePQ == nil {
		return PQIdentity{}
	}
	return *r.CorePQ
}

// PairResponse confirms ownership and hands back the first session.
type PairResponse struct {
	DeviceID        string       `json:"device_id"`
	PairingState    PairingState `json:"pairing_state"`
	CoreFingerprint string       `json:"core_fingerprint"`
	Session         Session      `json:"session"`
}

// Session is a short-lived bearer credential for the ordinary endpoints.
type Session struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionRequest is the body of POST /v1/session. It is signed, like pairing,
// so a leaked bearer token cannot be used to mint fresh ones.
type SessionRequest struct {
	CoreID string `json:"core_id"`
}

// UnpairResponse reports the state after ownership is released.
type UnpairResponse struct {
	DeviceID     string       `json:"device_id"`
	PairingState PairingState `json:"pairing_state"`
}

// FactoryResetRequest releases pairing without touching device identity.
//
// Confirm must equal the Node's own device_id. Requiring the caller to name the
// device makes an accidental reset of the wrong Node in a multi-Node install
// impossible rather than merely unlikely.
//
// This is a software operation only. It is deliberately not bound to any
// physical gesture on UFI003 hardware, because the long-press-at-power-on
// gesture on that device enters Qualcomm 9008/EDL and must stay reserved.
type FactoryResetRequest struct {
	Confirm string `json:"confirm"`
}
