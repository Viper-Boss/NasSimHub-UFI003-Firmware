package proto

import "time"

// The diagnostics bundle is a wire type, not an agent type.
//
// It lives here because both halves of the product need it: the agent builds
// one, Core stores and renders it, and the Windows client displays it. Putting
// it in the agent package would have made Core depend on the agent module,
// which is backwards - Core does not run on the device and must never need the
// device's code to read what the device sent.
//
// The rules about what may and may not appear in one are documented, and
// enforced by tests, in agent/diag - the package that fills it in. Nothing here
// should be populated by hand.

// DiagnosticsFormatVersion identifies the bundle layout, so a future reader can tell what
// it is looking at without guessing.
const DiagnosticsFormatVersion = 1

// DiagnosticsMaxLogLines bounds the log section. A bundle has to be small enough to
// attach to a message; a device that has been failing for a week would
// otherwise produce one nobody can send.
const DiagnosticsMaxLogLines = 500

// DiagnosticsBundle is the whole diagnostics document.
//
// Every field here was decided on deliberately. Adding one is a decision to
// publish it, and should be made with the package doc's rule in mind.
type DiagnosticsBundle struct {
	FormatVersion int       `json:"format_version"`
	GeneratedAt   time.Time `json:"generated_at"`

	Device   DeviceSection   `json:"device"`
	Software SoftwareSection `json:"software"`
	Link     LinkSection     `json:"link"`
	Modem    ModemSection    `json:"modem"`
	Network  NetworkSection  `json:"network"`
	WiFi     WiFiSection     `json:"wifi"`
	Runtime  RuntimeSection  `json:"runtime"`
	Errors   []ErrorRecord   `json:"recent_errors"`
	Notes    []string        `json:"notes,omitempty"`

	// Transport is how bytes are moving and how well. Every field is an
	// observation about DELIVERY - round trips, retransmissions, recovered
	// packets - measured below the encryption layer, which is why none of it
	// can be key material even in principle.
	Transport TransportSection `json:"transport"`
}

// TransportSection reports the link, for the status page and for a support
// bundle.
//
// There is no address here and no port beyond what LinkSection already carries.
// A bundle describing the owner's network topology would be a bundle they
// should think twice about sending, and the counters are what actually
// diagnose a weak link.
type TransportSection struct {
	Mode     TransportMode `json:"mode"`
	Resolved TransportMode `json:"resolved_mode"`
	Advice   LinkAdvice    `json:"advice"`

	RTT         string  `json:"rtt,omitempty"`
	Jitter      string  `json:"jitter,omitempty"`
	PacketLoss  float64 `json:"packet_loss"`
	Retransmits uint64  `json:"retransmits"`

	FECMode      string  `json:"fec_mode,omitempty"`
	FECRecovered uint64  `json:"fec_recovered"`
	FECOverhead  float64 `json:"fec_overhead"`

	// Measured says whether the numbers above mean anything. TCP does not
	// report its retransmission count to userspace portably, so a standard
	// transport leaves them zero - and a zero that looks like a measurement
	// would put a confident "0% loss" on the page of a link that is failing.
	Measured bool `json:"measured"`

	Security SecurityCapability `json:"security"`

	// Auth is what the packet authentication layer rejected.
	//
	// Counters only, and deliberately so: "12 MAC failures in the last hour"
	// is the single most useful line in a support bundle when a link is
	// failing, and it says nothing about what was in the packets. Recording
	// the payloads would be recording somebody's traffic.
	Auth TransportAuthSection `json:"auth"`

	// Identity is the post-quantum identity picture: present, available,
	// which policy. Separate from Security because key AGREEMENT and
	// AUTHENTICATION are different questions with different answers, and a
	// bundle that merged them would let a reader conclude a device has
	// post-quantum identity when it has post-quantum confidentiality.
	Identity IdentityCapability `json:"identity"`

	// Level is the security level in force.
	Level SecurityLevel `json:"level,omitempty"`
}

// TransportAuthSection reports the authenticated-envelope counters.
//
// Authenticated is false on a transport with no envelope - the standard TCP
// one, where TLS covers everything and there is no header outside it. A zero
// count next to Authenticated=false means "not applicable"; next to
// Authenticated=true it means "nothing was rejected", and those are different
// facts that a single number could not distinguish.
type TransportAuthSection struct {
	Authenticated bool   `json:"authenticated"`
	Accepted      uint64 `json:"accepted"`
	MACFailures   uint64 `json:"mac_failures"`
	Replays       uint64 `json:"replays"`
	TooOld        uint64 `json:"too_old"`
	BadEpoch      uint64 `json:"bad_epoch"`
	Malformed     uint64 `json:"malformed"`
	CookiesIssued uint64 `json:"cookies_issued"`
	CookiesBad    uint64 `json:"cookies_rejected"`
	RateLimited   uint64 `json:"rate_limited"`
}

// UnderAttack is a deliberately conservative reading of the counters.
//
// A handful of MAC failures is ordinary: a stale peer, a middlebox rewriting a
// packet, a rotation that raced. A large number alongside almost no accepted
// packets is not ordinary, and a status page that never said so would leave the
// owner staring at a device that "looks fine" while something hammers it.
func (t TransportAuthSection) UnderAttack() bool {
	if !t.Authenticated {
		return false
	}
	const floor = 100
	rejected := t.MACFailures + t.CookiesBad + t.RateLimited
	return rejected > floor && rejected > t.Accepted
}

// DeviceSection identifies the hardware without identifying its owner.
type DeviceSection struct {
	DeviceID     string       `json:"device_id"`
	Platform     Platform     `json:"platform"`
	Model        string       `json:"model"`
	BootID       string       `json:"boot_id"`
	StartedAt    time.Time    `json:"started_at"`
	PairingState PairingState `json:"pairing_state"`
	// Paired is a boolean rather than the owner's Core id. Whether the device
	// has an owner is a diagnostic fact; WHO owns it is not, and a Core id in
	// a bundle would let anyone holding the bundle recognise that NAS
	// elsewhere.
	Paired bool `json:"paired"`
}

// SoftwareSection is what is running.
type SoftwareSection struct {
	AgentVersion   string `json:"agent_version"`
	BuildDate      string `json:"build_date,omitempty"`
	ProtocolMajor  int    `json:"protocol_major"`
	ProtocolMinor  int    `json:"protocol_minor"`
	MinCoreVersion string `json:"min_core_version"`
	GoVersion      string `json:"go_version"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
}

// LinkSection is how the Node is reachable.
type LinkSection struct {
	Connection ConnectionType `json:"connection_type"`
	// Listeners are ports, never addresses. An address in a bundle is a small
	// piece of the owner's network topology and is not needed to diagnose
	// anything: "listening on 7580" is the useful half.
	ListenPorts []int `json:"listen_ports,omitempty"`
	TLS         bool  `json:"tls"`
}

// ModemSection is the radio's state and the reason for it.
type ModemSection struct {
	Backend      string       `json:"backend"`
	State        ModemState   `json:"state"`
	Reason       string       `json:"reason,omitempty"`
	SIMState     SIMState     `json:"sim_state"`
	SIMPresent   bool         `json:"sim_present"`
	Capabilities Capabilities `json:"capabilities"`
	VoiceControl Tristate     `json:"voice_control"`
	VoiceAudio   Tristate     `json:"voice_audio"`
	VoLTE        Tristate     `json:"volte"`
	VoiceReason  string       `json:"voice_reason,omitempty"`
	ObservedAt   time.Time    `json:"observed_at"`
}

// NetworkSection is the cellular attachment.
//
// The operator NAME is here and the operator CODE is not, for a reason worth
// stating: the name is what a human needs to read ("China Mobile"), and the
// code combined with the roaming flag and a timestamp narrows down where the
// device is. The name alone does not.
type NetworkSection struct {
	Registration     RegistrationState `json:"registration"`
	AccessTechnology AccessTechnology  `json:"access_technology"`
	OperatorName     string            `json:"operator_name,omitempty"`
	Roaming          bool              `json:"roaming"`
	DataConnected    bool              `json:"data_connected"`
	SignalBars       int               `json:"signal_bars"`
	SignalKnown      bool              `json:"signal_known"`
	SignalDBM        *float64          `json:"signal_dbm,omitempty"`
	ObservedAt       time.Time         `json:"observed_at"`
}

// WiFiSection is the Wi-Fi state machine, with no credentials and no SSID.
//
// The SSID is omitted deliberately. It is not a secret in the cryptographic
// sense, but it names the user's home network and is enough to locate a
// household through public wardriving databases. "CONNECTED" is the diagnostic
// fact; which network is not.
type WiFiSection struct {
	State        WiFiState `json:"state"`
	HasSSID      bool      `json:"has_ssid"`
	APActive     bool      `json:"ap_active"`
	Failure      string    `json:"failure_reason,omitempty"`
	RetryCount   int       `json:"retry_count,omitempty"`
	LastChangeAt time.Time `json:"last_change_at,omitempty"`
}

// RuntimeSection is resource usage, which is what most "it got slow" reports
// actually need.
type RuntimeSection struct {
	Uptime           string `json:"uptime"`
	UptimeSeconds    int64  `json:"uptime_seconds"`
	Goroutines       int    `json:"goroutines"`
	HeapAllocBytes   uint64 `json:"heap_alloc_bytes"`
	HeapObjects      uint64 `json:"heap_objects"`
	SysBytes         uint64 `json:"sys_bytes"`
	NumGC            uint32 `json:"num_gc"`
	OpenFileHandles  int    `json:"open_file_handles,omitempty"`
	NonceCacheSize   int    `json:"nonce_cache_size"`
	ActiveSessions   int    `json:"active_sessions"`
	LogRecordsBuffed int    `json:"log_records_buffered"`
}

// ErrorRecord is one sanitised log line.
type ErrorRecord struct {
	At      time.Time `json:"at"`
	Level   LogLevel  `json:"level"`
	Source  string    `json:"source"`
	Message string    `json:"message"`
}
