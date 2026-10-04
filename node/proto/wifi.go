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
	ObservedAt    time.Time `json:"observed_at"`
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

// WiFiNetwork is one scan result.
type WiFiNetwork struct {
	SSID      string       `json:"ssid"`
	SignalDBM float64      `json:"signal_dbm"`
	Security  WiFiSecurity `json:"security"`
	Channel   int          `json:"channel,omitempty"`
}

// WiFiScanResult is the envelope for POST /v1/wifi/scan.
type WiFiScanResult struct {
	Networks  []WiFiNetwork `json:"networks"`
	ScannedAt time.Time     `json:"scanned_at"`
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
