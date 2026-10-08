package proto

import "time"

// WiFiState is the Node's station/AP state machine.
//
// The provisioning loop matters more than it looks: a Node that loses its
// saved network must return to an access point the user can reach, or the
// device becomes unrecoverable without physical access. On UFI003 hardware
// physical access is exactly what we must not rely on, because holding the
// button for about five seconds at power-on enters Qualcomm 9008/EDL. That
// hardware behaviour is reserved and NasSimHub never binds a recovery gesture
// to it; PROVISIONING_AP is the recovery path instead.
type WiFiState string

const (
	WiFiNoConfig       WiFiState = "NO_WIFI_CONFIG"
	WiFiConnecting     WiFiState = "CONNECTING"
	WiFiConnected      WiFiState = "CONNECTED"
	WiFiFailed         WiFiState = "FAILED"
	WiFiProvisioningAP WiFiState = "PROVISIONING_AP"
)

// WiFiProvisioningState is where the device stands in first-time setup and
// link recovery. It is finer than WiFiState and reported beside it: WiFiState
// says what the radio is doing now, this says why, and what happens next.
//
// The transitions between these states are a table in the agent
// (agent/netbackend/statemachine.go). An absent value means the backend has not
// observed the radio yet, or does not track this - it is "unknown", not a state.
type WiFiProvisioningState string

const (
	// No saved network and no access point yet.
	WiFiProvisioningUnconfigured WiFiProvisioningState = "UNCONFIGURED"
	// The setup access point is being brought up.
	WiFiProvisioningAPStarting WiFiProvisioningState = "AP_STARTING"
	// The setup access point is up and the setup page is reachable through it.
	WiFiProvisioningAPReady WiFiProvisioningState = "AP_READY"
	// The setup access point could not be started; ProvisioningReason says
	// why. USB management is unaffected and the start is retried.
	WiFiProvisioningAPFailed WiFiProvisioningState = "AP_FAILED"
	// Credentials were submitted and a join is in progress.
	WiFiProvisioningJoining WiFiProvisioningState = "JOINING"
	// The device is on a network as a client.
	WiFiProvisioningJoined WiFiProvisioningState = "JOINED"
	// The last join failed and the device is going back to where it was.
	WiFiProvisioningJoinFailed WiFiProvisioningState = "JOIN_FAILED"
	// A saved network exists and the device is waiting for it to come back.
	WiFiProvisioningSavedNetworkSearching WiFiProvisioningState = "SAVED_NETWORK_SEARCHING"
	// The saved network stayed unreachable; the setup access point is offered
	// again while the saved network is kept.
	WiFiProvisioningSavedNetworkLost WiFiProvisioningState = "SAVED_NETWORK_LOST"
	// The setup access point is switched off in the device configuration.
	WiFiProvisioningDisabled WiFiProvisioningState = "DISABLED"
)

// WiFiStatus is the document served by GET /v1/wifi.
//
// PSKs never appear here in any state. The field does not exist on purpose:
// a value that is never carried cannot be leaked by a future logging change.
type WiFiStatus struct {
	State         WiFiState `json:"state"`
	SSID          string    `json:"ssid,omitempty"`
	IPv4          string    `json:"ipv4,omitempty"`
	SignalDBM     *float64  `json:"signal_dbm,omitempty"`
	APSSID        string    `json:"ap_ssid,omitempty"`
	APAddress     string    `json:"ap_address,omitempty"`
	FailureReason string    `json:"failure_reason,omitempty"`
	SavedSSID     string    `json:"saved_ssid,omitempty"`
	// ProvisioningState is absent when the backend has no evidence for one.
	ProvisioningState WiFiProvisioningState `json:"provisioning_state,omitempty"`
	// ProvisioningReason explains AP_FAILED. It never contains a credential.
	ProvisioningReason string    `json:"provisioning_reason,omitempty"`
	ObservedAt         time.Time `json:"observed_at"`
}

// WiFiSecurity is a coarse classification; it exists so the UI can warn about
// open networks, not so anything can be configured from it.
type WiFiSecurity string

const (
	WiFiSecurityOpen    WiFiSecurity = "open"
	WiFiSecurityWPA2    WiFiSecurity = "wpa2"
	WiFiSecurityWPA3    WiFiSecurity = "wpa3"
	WiFiSecurityUnknown WiFiSecurity = "unknown"
)

// WiFiSupport says how much evidence there is that this hardware can join a
// network of that kind. It is a statement about testing, not a prediction: an
// unverified network may well work, and a verified one can still be refused by
// its router. An absent value means the backend gave no hint - unknown.
type WiFiSupport string

const (
	// Joined successfully on the real hardware: 2.4 GHz with WPA2-PSK, or
	// WPA2/WPA3 mixed mode (which is joined as WPA2).
	WiFiSupportVerified WiFiSupport = "verified"
	// Not tested on the real hardware: 5 GHz, WPA3-only (SAE), open networks.
	WiFiSupportUnverified WiFiSupport = "unverified"
	// Cannot be joined by this agent at all: 802.1X (enterprise).
	WiFiSupportUnsupported WiFiSupport = "unsupported"
)

// WiFiNetwork is one scan result.
type WiFiNetwork struct {
	SSID      string       `json:"ssid"`
	SignalDBM float64      `json:"signal_dbm"`
	Security  WiFiSecurity `json:"security"`
	Channel   int          `json:"channel,omitempty"`
	// Support and SupportReason mark what is and is not known to work. A
	// network is listed whatever its support: hiding it would look like the
	// device cannot see it.
	Support       WiFiSupport `json:"support,omitempty"`
	SupportReason string      `json:"support_reason,omitempty"`
}

// WiFiScanResult is the envelope for POST /v1/wifi/scan.
type WiFiScanResult struct {
	Networks  []WiFiNetwork `json:"networks"`
	ScannedAt time.Time     `json:"scanned_at"`
	// FromCache is set when the radio could not scan at the time of the
	// request (it is serving the setup access point) and the list is the last
	// one taken before that. ScannedAt is then the time of that older scan.
	FromCache bool `json:"from_cache,omitempty"`
}

// WiFiConnectRequest carries a credential inbound only. The Node stores the
// PSK outside the API surface and never echoes it back on any endpoint.
type WiFiConnectRequest struct {
	SSID     string       `json:"ssid"`
	PSK      string       `json:"psk,omitempty"`
	Security WiFiSecurity `json:"security,omitempty"`
}

// LogLevel is the severity of a diagnostic record.
type LogLevel string

const (
	LogDebug LogLevel = "debug"
	LogInfo  LogLevel = "info"
	LogWarn  LogLevel = "warn"
	LogError LogLevel = "error"
)

// LogRecord is one line of Node diagnostics. Records are already redacted when
// they enter the buffer, not when they leave it, so there is no code path that
// can serve an unredacted record.
type LogRecord struct {
	Time    time.Time `json:"time"`
	Level   LogLevel  `json:"level"`
	Source  string    `json:"source"`
	Message string    `json:"message"`
}

// LogPage is the envelope for GET /v1/logs.
type LogPage struct {
	Records  []LogRecord `json:"records"`
	Dropped  int         `json:"dropped"`
	Capacity int         `json:"capacity"`
}

// VersionInfo is the OTA groundwork. This stage only reports; it never fetches
// or applies anything.
type VersionInfo struct {
	AgentVersion    string   `json:"agent_version"`
	ProtocolVersion int      `json:"protocol_version"`
	Platform        Platform `json:"platform"`
	BuildDate       string   `json:"build_date,omitempty"`
	OTASupported    bool     `json:"ota_supported"`
	OTAChannel      string   `json:"ota_channel,omitempty"`
}
