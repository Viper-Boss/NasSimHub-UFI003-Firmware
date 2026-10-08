// Package networkmanager implements Wi-Fi control for the UFI003 with nmcli.
// The agent remains unprivileged; firmware polkit rules grant only the three
// NetworkManager actions required by this package.
package networkmanager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/human-agent65535/nassimhub-node/agent/netbackend"
	"github.com/human-agent65535/nassimhub-node/proto"
)

const (
	defaultDevice  = "wlan0"
	defaultProfile = "nassimhub-wifi"
	// previousProfile holds the saved network aside while a new one takes its
	// name, so there is never a moment with no saved network at all.
	previousProfile = "nassimhub-wifi-previous"
	recoveryWindow  = 75 * time.Second
)

type runner func(context.Context, ...string) (string, error)

// Options contains the platform wiring used by the backend.
type Options struct {
	Device   string
	StateDir string
	Run      func(context.Context, ...string) (string, error)
	Now      func() time.Time
	// DeviceID names the setup access point (its last group becomes the SSID
	// suffix), so two sticks in one room can be told apart.
	DeviceID string
	// ProvisioningAP is the configuration key of the same name: "auto" offers
	// the setup access point when there is no saved network or the saved one
	// has stayed unreachable; "off" never issues an access point command.
	// Empty means off, so that the diagnostic commands built on this package
	// never start an access point as a side effect of being run.
	ProvisioningAP string
	// Logf receives state transitions and access point failures. Nothing
	// passed to it contains a credential.
	Logf func(format string, arguments ...any)
}

// Backend drives the single Wi-Fi radio through NetworkManager.
type Backend struct {
	device   string
	stateDir string
	run      runner
	now      func() time.Time

	mu       sync.Mutex
	state    proto.WiFiState
	target   string
	failure  string
	failedAt time.Time

	// The setup access point and the provisioning state machine; see
	// setupap.go. opMu serialises every sequence of nmcli commands that only
	// makes sense as a whole - a join, an access point start, a forget - so
	// two of them can never interleave on the one radio.
	opMu     sync.Mutex
	deviceID string
	apMode   string
	logf     func(string, ...any)
	machine  *netbackend.Machine
	ap       apState
}

// New returns a backend. Individual operations check runtime availability so
// a NetworkManager restart does not require an agent restart.
func New(options Options) *Backend {
	device := strings.TrimSpace(options.Device)
	if device == "" {
		device = defaultDevice
	}
	stateDir := strings.TrimSpace(options.StateDir)
	if stateDir == "" {
		stateDir = "/var/lib/nassimhub"
	}
	run := runner(options.Run)
	if run == nil {
		run = runNMCLI
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	logf := options.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	mode := strings.ToLower(strings.TrimSpace(options.ProvisioningAP))
	if mode != ProvisioningAPAuto {
		mode = ProvisioningAPOff
	}
	backend := &Backend{device: device, stateDir: stateDir, run: run, now: now,
		deviceID: strings.TrimSpace(options.DeviceID), apMode: mode, logf: logf}
	backend.machine = netbackend.NewMachine(now, logf)
	if mode == ProvisioningAPOff {
		backend.machine.Start(proto.WiFiProvisioningDisabled, "the setup access point is switched off")
	}
	return backend
}

func (*Backend) Name() string { return "networkmanager" }
func (*Backend) Close() error { return nil }

func runNMCLI(ctx context.Context, arguments ...string) (string, error) {
	output, err := exec.CommandContext(ctx, "/usr/bin/nmcli", arguments...).Output()
	return string(output), err
}

// Status reports the live radio state and the one profile owned by NasSimHub.
func (b *Backend) Status(ctx context.Context) (proto.WiFiStatus, error) {
	provisioning, _ := b.machine.State()
	b.mu.Lock()
	provisioningReason := ""
	if provisioning == proto.WiFiProvisioningAPFailed {
		provisioningReason = b.ap.failure
	}
	if b.state == proto.WiFiConnecting {
		status := proto.WiFiStatus{State: b.state, SSID: b.target, ProvisioningState: provisioning, ObservedAt: b.now().UTC()}
		b.mu.Unlock()
		return status, nil
	}
	// A failed join stays visible for the recovery window so the user sees why
	// it failed. Once the access point is back the radio's state is the access
	// point - the setup page is only served in that state - and the reason
	// travels with it instead of hiding it.
	lastFailure := ""
	if b.state == proto.WiFiFailed && b.now().Sub(b.failedAt) < recoveryWindow {
		if provisioning != proto.WiFiProvisioningAPReady {
			status := proto.WiFiStatus{State: b.state, FailureReason: b.failure, ProvisioningState: provisioning,
				ProvisioningReason: provisioningReason, ObservedAt: b.now().UTC()}
			b.mu.Unlock()
			return status, nil
		}
		lastFailure = b.failure
	} else {
		b.state, b.target, b.failure, b.failedAt = "", "", "", time.Time{}
	}
	b.mu.Unlock()

	rows, err := b.run(ctx, "-t", "--escape", "yes", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device")
	if err != nil {
		return proto.WiFiStatus{}, proto.Unavailable("wifi.status", "NetworkManager status is unavailable", err)
	}
	var deviceState, connection string
	for _, line := range nonemptyLines(rows) {
		fields := splitEscaped(line, ':')
		if len(fields) >= 4 && fields[0] == b.device {
			deviceState, connection = fields[2], fields[3]
			break
		}
	}
	if deviceState == "" {
		return proto.WiFiStatus{}, proto.Unavailable("wifi.status", "Wi-Fi device is not managed by NetworkManager", nil)
	}

	status := proto.WiFiStatus{State: proto.WiFiNoConfig, ProvisioningState: provisioning,
		ProvisioningReason: provisioningReason, ObservedAt: b.now().UTC()}
	savedSSID, _ := b.connectionSSID(ctx, defaultProfile)
	status.SavedSSID = savedSSID
	if deviceState != "connected" || connection == "" || connection == "--" {
		return status, nil
	}
	if connection == apProfile {
		// NetworkManager calls an active access point "connected" too. It is
		// not a client connection and must never be reported as one.
		status.State = proto.WiFiProvisioningAP
		status.APSSID, status.APAddress = b.apSSID(), apAddress
		status.FailureReason = lastFailure
		return status, nil
	}
	ssid, err := b.connectionSSID(ctx, connection)
	if err != nil || ssid == "" {
		ssid = savedSSID
	}
	status.State, status.SSID = proto.WiFiConnected, ssid
	if address, err := b.run(ctx, "-g", "IP4.ADDRESS", "device", "show", b.device); err == nil {
		if first := firstLine(address); first != "" {
			status.IPv4 = strings.SplitN(first, "/", 2)[0]
		}
	}
	if signal, ok := b.signalFor(ctx, ssid); ok {
		status.SignalDBM = &signal
	}
	return status, nil
}

// Scan returns visible non-hidden SSIDs, deduplicated by strongest signal.
//
// While the radio serves the setup access point it may be unable to scan. The
// list taken just before the access point started is returned then, marked
// FromCache and carrying the time it was taken, rather than an empty list that
// would read as "there are no networks here".
func (b *Backend) Scan(ctx context.Context) (proto.WiFiScanResult, error) {
	b.NoteSetupActivity()
	result, err := b.scan(ctx)
	if state, _ := b.machine.State(); state == proto.WiFiProvisioningAPReady && (err != nil || len(result.Networks) == 0) {
		b.mu.Lock()
		cached := b.ap.scanCache
		b.mu.Unlock()
		if cached != nil {
			copied := *cached
			copied.Networks = append([]proto.WiFiNetwork(nil), cached.Networks...)
			copied.FromCache = true
			return copied, nil
		}
	}
	return result, err
}

func (b *Backend) scan(ctx context.Context) (proto.WiFiScanResult, error) {
	output, err := b.run(ctx, "-t", "--escape", "yes", "-f", "SSID,SIGNAL,SECURITY,CHAN", "device", "wifi", "list", "ifname", b.device, "--rescan", "yes")
	if err != nil {
		return proto.WiFiScanResult{}, proto.Unavailable("wifi.scan", "Wi-Fi scan failed", err)
	}
	bySSID := make(map[string]proto.WiFiNetwork)
	// A network name is often broadcast on both bands. When any of its radios
	// is of a kind already verified, that one is listed: the name is joinable
	// on evidence, and the note says the other band was seen too.
	alsoUnverified := make(map[string]bool)
	for _, line := range nonemptyLines(output) {
		fields := splitEscaped(line, ':')
		if len(fields) < 4 || strings.TrimSpace(fields[0]) == "" {
			continue
		}
		signal, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		channel, _ := strconv.Atoi(fields[3])
		network := proto.WiFiNetwork{SSID: fields[0], SignalDBM: percentToDBM(signal), Security: classifySecurity(fields[2]), Channel: channel}
		network.Support, network.SupportReason = netbackend.SupportFor(network.Security, channel, isEnterprise(fields[2]))
		if network.Support == proto.WiFiSupportVerified && !strings.Contains(strings.ToUpper(fields[2]), "WPA2") {
			// First-generation WPA is classified with WPA2 because it is
			// joined the same way, but it is not what was tested.
			network.Support, network.SupportReason = proto.WiFiSupportUnverified, "WPA without WPA2 has not been verified on this hardware"
		}
		old, exists := bySSID[network.SSID]
		if exists && (old.Support == proto.WiFiSupportVerified) != (network.Support == proto.WiFiSupportVerified) {
			alsoUnverified[network.SSID] = true
		}
		switch {
		case !exists:
			bySSID[network.SSID] = network
		case network.Support == proto.WiFiSupportVerified && old.Support != proto.WiFiSupportVerified:
			bySSID[network.SSID] = network
		case old.Support == proto.WiFiSupportVerified && network.Support != proto.WiFiSupportVerified:
		case network.SignalDBM > old.SignalDBM:
			bySSID[network.SSID] = network
		}
	}
	networks := make([]proto.WiFiNetwork, 0, len(bySSID))
	for _, network := range bySSID {
		if alsoUnverified[network.SSID] {
			network.SupportReason += "; the same name was also seen on a band or security type that is not verified, and the radio chooses which one it joins"
		}
		networks = append(networks, network)
	}
	sort.Slice(networks, func(i, j int) bool {
		if networks[i].SignalDBM == networks[j].SignalDBM {
			return networks[i].SSID < networks[j].SSID
		}
		return networks[i].SignalDBM > networks[j].SignalDBM
	})
	return proto.WiFiScanResult{Networks: networks, ScannedAt: b.now().UTC()}, nil
}

// Connect starts a bounded NetworkManager join in the background.
func (b *Backend) Connect(_ context.Context, request proto.WiFiConnectRequest) (proto.WiFiStatus, error) {
	ssid := strings.TrimSpace(request.SSID)
	if err := validateSSID(ssid); err != nil {
		return proto.WiFiStatus{}, proto.InvalidArgument("wifi.connect", err.Error())
	}
	if request.Security != proto.WiFiSecurityOpen && strings.TrimSpace(request.PSK) == "" {
		return proto.WiFiStatus{}, proto.InvalidArgument("wifi.connect", "psk is required for a protected network")
	}
	if request.Security != proto.WiFiSecurityOpen && !validPSK(request.PSK, request.Security) {
		return proto.WiFiStatus{}, proto.InvalidArgument("wifi.connect", "psk must contain 8 to 63 characters, or 64 hexadecimal digits for WPA2")
	}
	for _, character := range request.PSK {
		if unicode.IsControl(character) {
			return proto.WiFiStatus{}, proto.InvalidArgument("wifi.connect", "psk contains a control character")
		}
	}

	b.mu.Lock()
	if b.state == proto.WiFiConnecting {
		b.mu.Unlock()
		return proto.WiFiStatus{}, proto.Conflict("wifi.connect", "a connection attempt is already in progress")
	}
	b.state, b.target, b.failure = proto.WiFiConnecting, ssid, ""
	b.mu.Unlock()
	b.NoteSetupActivity()

	go b.connect(context.Background(), ssid, request.PSK, request.Security)
	return proto.WiFiStatus{State: proto.WiFiConnecting, SSID: ssid, ObservedAt: b.now().UTC()}, nil
}

func (b *Backend) connect(ctx context.Context, ssid, psk string, security proto.WiFiSecurity) {
	// One radio, one sequence at a time: a join waits for an access point
	// start or a rejoin of the saved network to finish, and they wait for it.
	b.opMu.Lock()
	defer b.opMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, netbackend.JoinTimeout)
	defer cancel()
	// The radio cannot be an access point and a client at once, so joining
	// stops the access point. A failed join brings it back; see joinFailed.
	apWasUp := b.beginJoin(ctx, ssid)
	profile := fmt.Sprintf("nsh-agent-%d", time.Now().UnixNano())
	if _, err := b.run(ctx, "connection", "add", "type", "wifi", "ifname", b.device, "con-name", profile, "ssid", ssid, "connection.autoconnect", "no"); err != nil {
		b.joinFailed("could not create the saved network", false, apWasUp)
		return
	}
	cleanup := func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = b.run(cleanupContext, "connection", "delete", "id", profile)
	}
	if security != proto.WiFiSecurityOpen {
		keyMgmt := "wpa-psk"
		if security == proto.WiFiSecurityWPA3 {
			keyMgmt = "sae"
		}
		if _, err := b.run(ctx, "connection", "modify", "id", profile, "802-11-wireless-security.key-mgmt", keyMgmt); err != nil {
			cleanup()
			b.joinFailed("could not configure network security", false, apWasUp)
			return
		}
	}

	passwordFile := ""
	if security != proto.WiFiSecurityOpen {
		var err error
		passwordFile, err = b.writePasswordFile(psk)
		if err != nil {
			cleanup()
			b.joinFailed("could not prepare the network credential", false, apWasUp)
			return
		}
		defer os.Remove(passwordFile)
	}
	arguments := []string{"--wait", "75"}
	arguments = append(arguments, "connection", "up", "id", profile, "ifname", b.device)
	if passwordFile != "" {
		arguments = append(arguments, "passwd-file", passwordFile)
	}
	if _, err := b.run(ctx, arguments...); err != nil {
		cleanup()
		b.joinFailed("authentication or association failed", true, apWasUp)
		return
	}
	// The new network is up. Give it the saved name without ever being in a
	// state where neither the old nor the new profile exists: the old one is
	// moved aside first and deleted only after the new one is in place.
	hadPrevious := false
	if _, err := b.run(ctx, "connection", "modify", "id", defaultProfile, "connection.id", previousProfile); err == nil {
		hadPrevious = true
	}
	if _, err := b.run(ctx, "connection", "modify", "id", profile, "connection.id", defaultProfile); err != nil {
		cleanup()
		if hadPrevious {
			recoverContext, cancelRecover := context.WithTimeout(context.Background(), netbackend.SaveRecoveryTimeout)
			_, _ = b.run(recoverContext, "connection", "modify", "id", previousProfile, "connection.id", defaultProfile)
			cancelRecover()
		}
		b.joinFailed("could not save the connected network", hadPrevious, apWasUp)
		return
	}
	if hadPrevious {
		_, _ = b.run(ctx, "connection", "delete", "id", previousProfile)
	}
	if _, err := b.run(ctx, "connection", "modify", "id", defaultProfile, "connection.autoconnect", "yes"); err != nil {
		// The network is joined and saved under its name; only the automatic
		// reconnection flag is missing. The radio is a client, so the machine
		// records a join - the failure is reported, and nothing is torn down.
		b.fire(netbackend.EventJoinOK, "joined, but automatic reconnection could not be enabled")
		b.fail("could not enable automatic reconnection")
		return
	}
	b.fire(netbackend.EventJoinOK, "")
	b.mu.Lock()
	b.state, b.target, b.failure, b.failedAt = "", "", "", time.Time{}
	b.mu.Unlock()
}

// restorePrevious asks NetworkManager to rejoin the saved network after a
// failed attempt at a new one. Without it the radio stays idle until
// NetworkManager's own autoconnect decides to try, which after a failed
// activation on the same device can be minutes. It is best effort: there may
// be no saved network, and the old network may be out of range - neither is an
// error of the attempt that just failed, and USB access does not depend on it.
func (b *Backend) restorePrevious(profile string) bool {
	restoreContext, cancel := context.WithTimeout(context.Background(), netbackend.RestoreTimeout)
	defer cancel()
	_, err := b.run(restoreContext, "--wait", "30", "connection", "up", "id", profile, "ifname", b.device)
	return err == nil
}

// validPSK accepts a WPA passphrase (8 to 63 characters) or, for WPA2 only, the
// 64-hexadecimal-digit form of the key itself. SAE has no raw-key form.
func validPSK(psk string, security proto.WiFiSecurity) bool {
	if len(psk) >= 8 && len(psk) <= 63 {
		return true
	}
	if len(psk) != 64 || security != proto.WiFiSecurityWPA2 {
		return false
	}
	for _, character := range psk {
		if !strings.ContainsRune("0123456789abcdefABCDEF", character) {
			return false
		}
	}
	return true
}

func (b *Backend) fail(reason string) {
	b.mu.Lock()
	b.state, b.target, b.failure, b.failedAt = proto.WiFiFailed, "", reason, b.now()
	b.mu.Unlock()
}

// Forget deletes only the profile owned by NasSimHub.
//
// It is the one operation allowed to remove the saved network, and it is
// refused while a join or an access point start is running: deleting a profile
// in the middle of a sequence that renames profiles would leave whichever one
// happened to hold the name at that instant deleted.
func (b *Backend) Forget(ctx context.Context) (proto.WiFiStatus, error) {
	b.mu.Lock()
	joining := b.state == proto.WiFiConnecting
	b.mu.Unlock()
	if joining || !b.lockOperation(ctx) {
		return proto.WiFiStatus{}, proto.Conflict("wifi.forget", "the radio is busy with another Wi-Fi operation; try again shortly")
	}
	defer b.opMu.Unlock()
	if state, _ := b.machine.State(); state != "" && state != proto.WiFiProvisioningDisabled {
		transition, fireErr := b.machine.Fire(netbackend.EventForget, "")
		if fireErr != nil || !transition.DeletesSavedProfile {
			return proto.WiFiStatus{}, proto.Conflict("wifi.forget", "the saved network cannot be removed in the current state")
		}
	}
	_, err := b.run(ctx, "connection", "delete", "id", defaultProfile)
	if err != nil && !isMissingProfile(err) {
		return proto.WiFiStatus{}, proto.Unavailable("wifi.forget", "could not remove the saved network", err)
	}
	b.mu.Lock()
	b.state, b.target, b.failure, b.failedAt = "", "", "", time.Time{}
	b.mu.Unlock()
	// With the setup access point enabled it comes up on the next supervision
	// step, not here: the answer reports what is true now.
	provisioning, _ := b.machine.State()
	status := proto.WiFiStatus{State: proto.WiFiNoConfig, ProvisioningState: provisioning, ObservedAt: b.now().UTC()}
	if provisioning == proto.WiFiProvisioningAPReady {
		status.State, status.APSSID, status.APAddress = proto.WiFiProvisioningAP, b.apSSID(), apAddress
	}
	return status, nil
}

// forgetLockWait is how long Forget waits for a supervision step to finish
// before answering "busy". A step is normally a few status commands; only an
// access point start takes longer, and a caller is better told than held.
const forgetLockWait = 3 * time.Second

// lockOperation takes opMu, waiting a short bounded time for it.
func (b *Backend) lockOperation(ctx context.Context) bool {
	deadline := time.Now().Add(forgetLockWait)
	for !b.opMu.TryLock() {
		if ctx.Err() != nil || time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

func (b *Backend) writePasswordFile(psk string) (string, error) {
	if err := os.MkdirAll(b.stateDir, 0700); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(b.stateDir, ".wifi-secret-*")
	if err != nil {
		return "", err
	}
	name := file.Name()
	if err := file.Chmod(0600); err == nil {
		_, err = fmt.Fprintf(file, "802-11-wireless-security.psk:%s\n", psk)
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(name)
		return "", errors.Join(err, closeErr)
	}
	return filepath.Clean(name), nil
}

func (b *Backend) connectionSSID(ctx context.Context, connection string) (string, error) {
	output, err := b.run(ctx, "-g", "802-11-wireless.ssid", "connection", "show", connection)
	return firstLine(output), err
}

func (b *Backend) signalFor(ctx context.Context, ssid string) (float64, bool) {
	if ssid == "" {
		return 0, false
	}
	output, err := b.run(ctx, "-t", "--escape", "yes", "-f", "SSID,SIGNAL", "device", "wifi", "list", "ifname", b.device, "--rescan", "no")
	if err != nil {
		return 0, false
	}
	for _, line := range nonemptyLines(output) {
		fields := splitEscaped(line, ':')
		if len(fields) != 2 || fields[0] != ssid {
			continue
		}
		value, err := strconv.Atoi(fields[1])
		if err == nil {
			return percentToDBM(value), true
		}
	}
	return 0, false
}

func validateSSID(ssid string) error {
	if ssid == "" {
		return errors.New("ssid is required")
	}
	if len([]byte(ssid)) > 32 {
		return errors.New("ssid is longer than 32 bytes")
	}
	for _, character := range ssid {
		if unicode.IsControl(character) {
			return errors.New("ssid contains a control character")
		}
	}
	return nil
}

// isEnterprise reports whether a scan row's security column names 802.1X.
func isEnterprise(value string) bool {
	return strings.Contains(strings.ToUpper(value), "802.1X")
}

func classifySecurity(value string) proto.WiFiSecurity {
	upper := strings.ToUpper(strings.TrimSpace(value))
	switch {
	case upper == "" || upper == "--":
		return proto.WiFiSecurityOpen
	// A transition-mode AP also offers WPA2. Do not infer that this
	// device supports SAE merely because the AP advertises WPA3.
	case strings.Contains(upper, "WPA2"):
		return proto.WiFiSecurityWPA2
	case strings.Contains(upper, "WPA3") || strings.Contains(upper, "SAE"):
		return proto.WiFiSecurityWPA3
	case strings.Contains(upper, "WPA"):
		return proto.WiFiSecurityWPA2
	default:
		return proto.WiFiSecurityUnknown
	}
}

func percentToDBM(percent int) float64 {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	return float64(percent)/2 - 100
}

func splitEscaped(value string, separator byte) []string {
	var fields []string
	var current strings.Builder
	escaped := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if escaped {
			current.WriteByte(character)
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == separator {
			fields = append(fields, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(character)
	}
	if escaped {
		current.WriteByte('\\')
	}
	return append(fields, current.String())
}

func nonemptyLines(value string) []string {
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func firstLine(value string) string {
	lines := nonemptyLines(value)
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[0])
}

func isMissingProfile(err error) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == 10
}
