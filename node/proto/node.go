// Package proto defines the NasSimHub Node Protocol: the wire types, the
// capability model, the error taxonomy and the request-signing rules shared by
// NasSimHub Core and nassimhub-agent.
//
// The protocol is transport independent on purpose. A Node reached over a USB
// network interface and the same Node reached over Wi-Fi speak exactly the same
// API on exactly the same paths. Nothing in this package may depend on how the
// peer was reached, and in particular nothing may treat an IP address as an
// identity.
package proto

import "time"

const (
	// APIVersion is the URL path segment every Node endpoint lives under.
	APIVersion = "v1"

	// ProtocolVersion identifies the semantics of the payloads below. Core
	// refuses to pair with a Node whose major version it does not understand.
	ProtocolVersion = "nassimhub-node/1"
)

// Platform names the hardware family a Node runs on. It is part of the stable
// device identity and is baked into device_id, so it must never be derived from
// anything mutable at runtime.
type Platform string

const (
	// PlatformMSM8916 is Qualcomm MSM8916 / Snapdragon 410 (UFI003 class).
	PlatformMSM8916 Platform = "msm8916"
	// PlatformMock is the software-only development Node.
	PlatformMock Platform = "mock"
)

// ShortCode is the platform fragment embedded in a device_id. Keeping it short
// and numeric-ish keeps identifiers readable on a device label.
func (p Platform) ShortCode() string {
	switch p {
	case PlatformMSM8916:
		return "410"
	case PlatformMock:
		return "MOCK"
	default:
		return "GEN"
	}
}

// Tristate models a fact that may be genuinely unknown. VoLTE support is the
// motivating case: on an unflashed MSM8916 the honest answer is neither true
// nor false, and the UI must be able to tell the difference.
type Tristate string

const (
	TriYes     Tristate = "yes"
	TriNo      Tristate = "no"
	TriUnknown Tristate = "unknown"
)

// Capabilities is the Node's self-description. Core must gate every optional
// operation on this structure rather than assuming a Node can do anything
// beyond report its own status. A Node that cannot place calls advertises
// VoiceControl=false, and Core must then not offer a dial affordance at all.
type Capabilities struct {
	SMS              bool     `json:"sms"`
	MobileData       bool     `json:"mobile_data"`
	VoiceControl     bool     `json:"voice_control"`
	VoiceAudio       bool     `json:"voice_audio"`
	DTMF             bool     `json:"dtmf,omitempty"`
	VoLTE            Tristate `json:"volte"`
	WiFiProvisioning bool     `json:"wifi_provisioning"`
	Logs             bool     `json:"logs"`
	OTA              bool     `json:"ota"`
}

// PairingState is the Node's trust relationship with a NasSimHub Core.
type PairingState string

const (
	// PairingUnpaired means the Node trusts nobody and will accept exactly one
	// pairing request.
	PairingUnpaired PairingState = "UNPAIRED"
	// PairingPairing means a pairing request is in flight and awaiting
	// confirmation. It is a transient state with a deadline.
	PairingPairing PairingState = "PAIRING"
	// PairingPaired means the Node has an owner and rejects every other Core.
	PairingPaired PairingState = "PAIRED"
)

// ConnectionType records how Core is currently reaching a Node. It is a
// property of the link, never of the device: the same device_id may move
// between values without ever becoming a second device.
type ConnectionType string

const (
	ConnectionUSB  ConnectionType = "usb"
	ConnectionWiFi ConnectionType = "wifi"
	ConnectionNone ConnectionType = "none"
)

// Node is the public identity document served by GET /v1/node. It is
// deliberately readable without authentication so that an unpaired device can
// be discovered and shown to the user, and it deliberately contains no SIM
// data, no phone numbers and no network addresses.
type Node struct {
	DeviceID        string       `json:"device_id"`
	Platform        Platform     `json:"platform"`
	Model           string       `json:"model"`
	AgentVersion    string       `json:"agent_version"`
	Protocol        string       `json:"protocol"`
	PublicKey       string       `json:"public_key"`
	PairingState    PairingState `json:"pairing_state"`
	PairedCoreID    string       `json:"paired_core_id,omitempty"`
	BootID          string       `json:"boot_id"`
	StartedAt       time.Time    `json:"started_at"`
	ProtocolVersion int          `json:"protocol_version"`

	// ProtocolMinor and MinCoreVersion let Core decide, from this
	// unauthenticated document alone, whether the two can work together -
	// before the user is offered the chance to adopt the device. See
	// compat.go for why the min_core_version direction matters.
	ProtocolMinor  int    `json:"protocol_minor"`
	MinCoreVersion string `json:"min_core_version,omitempty"`

	// PQIdentity is the device's ADDITIONAL post-quantum public key, when it
	// has one. It is omitted entirely by a device that does not.
	//
	// device_id does not derive from it and never will - that derivation is
	// frozen on the Ed25519 key, so that enabling post-quantum identity does
	// not give every deployed device a new identity. This key is a second key
	// the same device also holds; see proto/pqidentity.go.
	PQIdentity PQIdentity `json:"pq_identity,omitempty"`
}

// HasPQIdentity reports whether this device published a post-quantum identity.
//
// Deliberately a method rather than a field comparison at each call site: the
// question "does this device have a post-quantum identity" is asked in several
// places and must mean the same thing in all of them.
func (n Node) HasPQIdentity() bool { return n.PQIdentity.Present() }

// Compatibility extracts the version contract from an identity document.
//
// A document from an agent that predates these fields reports minor 0 and no
// minimum Core, which is the correct reading of its silence: it is a 1.0 Node
// that never expressed a requirement.
func (n Node) Compatibility() Compatibility {
	major := n.ProtocolVersion
	if major == 0 {
		major = ProtocolMajor
	}
	return Compatibility{
		ProtocolMajor:  major,
		ProtocolMinor:  n.ProtocolMinor,
		AgentVersion:   n.AgentVersion,
		MinCoreVersion: n.MinCoreVersion,
	}
}

// Health is the liveness document served by GET /v1/health. Like Node it is
// unauthenticated, so it carries availability and nothing else.
type Health struct {
	Status       string    `json:"status"`
	APIVersion   string    `json:"api_version"`
	AgentVersion string    `json:"agent_version"`
	DeviceID     string    `json:"device_id"`
	ModemState   string    `json:"modem_state"`
	ObservedAt   time.Time `json:"observed_at"`
}

const (
	HealthOK       = "ok"
	HealthDegraded = "degraded"
)
