package proto

import "time"

// ModemState is the lifecycle of the radio itself, independent of the SIM.
type ModemState string

const (
	ModemOffline    ModemState = "offline"
	ModemRestarting ModemState = "restarting"
	ModemReady      ModemState = "ready"
	ModemFailed     ModemState = "failed"
	ModemUnknown    ModemState = "unknown"
)

// SIMState describes the card, not the subscription and not the network.
type SIMState string

const (
	SIMReady     SIMState = "ready"
	SIMMissing   SIMState = "missing"
	SIMPINLocked SIMState = "pin_locked"
	SIMPUKLocked SIMState = "puk_locked"
	SIMError     SIMState = "error"
	SIMUnknown   SIMState = "unknown"
)

// SIMInfo is the Node's view of the installed card.
//
// ICCID and IMSI are carried here because Core needs them to bind messages and
// calls to a specific card across Node restarts and SIM swaps. They are
// sensitive identifiers: they must never reach a diagnostic log unmasked. See
// the logbuf package for the redaction that enforces this.
type SIMInfo struct {
	State        SIMState  `json:"state"`
	ICCID        string    `json:"iccid,omitempty"`
	IMSI         string    `json:"imsi,omitempty"`
	OperatorName string    `json:"operator_name,omitempty"`
	OperatorCode string    `json:"operator_code,omitempty"`
	PhoneNumber  string    `json:"phone_number,omitempty"`
	PINRetries   *int      `json:"pin_retries,omitempty"`
	ObservedAt   time.Time `json:"observed_at"`
}

// SIMID is the stable identifier Core uses to attribute traffic to a card. It
// is the ICCID when the card reports one, and empty otherwise. Core must never
// fall back to the device_id here: two cards moved between two Nodes must not
// collapse into one conversation history.
func (s SIMInfo) SIMID() string { return s.ICCID }

// RegistrationState is the modem's attachment to a network.
type RegistrationState string

const (
	RegRegistered   RegistrationState = "registered"
	RegSearching    RegistrationState = "searching"
	RegDenied       RegistrationState = "denied"
	RegRoaming      RegistrationState = "roaming"
	RegUnregistered RegistrationState = "unregistered"
	RegUnknown      RegistrationState = "unknown"
)

// AccessTechnology is the radio bearer currently serving the Node.
type AccessTechnology string

const (
	AccessLTE     AccessTechnology = "lte"
	AccessUMTS    AccessTechnology = "umts"
	AccessGSM     AccessTechnology = "gsm"
	AccessUnknown AccessTechnology = "unknown"
)

// NetworkStatus is cellular network state. Wi-Fi state is a separate document;
// the two must not be conflated because a Node can be reachable over Wi-Fi
// while its cellular side is completely unregistered, and vice versa.
type NetworkStatus struct {
	Registration     RegistrationState `json:"registration"`
	AccessTechnology AccessTechnology  `json:"access_technology"`
	OperatorName     string            `json:"operator_name,omitempty"`
	OperatorCode     string            `json:"operator_code,omitempty"`
	Roaming          bool              `json:"roaming"`
	DataConnected    bool              `json:"data_connected"`
	APN              string            `json:"apn,omitempty"`
	IPv4             string            `json:"ipv4,omitempty"`
	ObservedAt       time.Time         `json:"observed_at"`
}

// Signal is sampled radio quality. Every field is optional because a modem that
// is offline or unregistered genuinely has nothing to report, and reporting a
// zero would be a lie the UI cannot distinguish from a real -0 dBm.
type Signal struct {
	DBM        *float64  `json:"dbm,omitempty"`
	RSRP       *float64  `json:"rsrp,omitempty"`
	RSRQ       *float64  `json:"rsrq,omitempty"`
	SNR        *float64  `json:"snr,omitempty"`
	Bars       int       `json:"bars"`
	Known      bool      `json:"known"`
	ObservedAt time.Time `json:"observed_at"`
}

// BarsFromDBM maps an RSSI in dBm onto the five-bar scale the web UI draws.
// The thresholds match the existing NasSimHub SignalBars component so a Node
// and a QDC507 line never disagree about what "three bars" means.
func BarsFromDBM(dbm float64) int {
	switch {
	case dbm >= -65:
		return 5
	case dbm >= -75:
		return 4
	case dbm >= -85:
		return 3
	case dbm >= -95:
		return 2
	case dbm >= -105:
		return 1
	default:
		return 0
	}
}

// ModemStatus is the single document that answers "what is this Node's radio
// doing right now".
type ModemStatus struct {
	Resources  *SystemResources `json:"resources,omitempty"`
	State      ModemState       `json:"state"`
	Reason     string           `json:"reason,omitempty"`
	SIM        SIMInfo          `json:"sim"`
	Network    NetworkStatus    `json:"network"`
	Signal     Signal           `json:"signal"`
	ObservedAt time.Time        `json:"observed_at"`
}
