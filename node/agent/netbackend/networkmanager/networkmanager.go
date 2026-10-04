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

	"github.com/human-agent65535/nassimhub-node/proto"
)

const (
	defaultDevice  = "wlan0"
	defaultProfile = "nassimhub-wifi"
	recoveryWindow = 75 * time.Second
)

type runner func(context.Context, ...string) (string, error)

// Options contains the platform wiring used by the backend.
type Options struct {
	Device   string
	StateDir string
	Run      func(context.Context, ...string) (string, error)
	Now      func() time.Time
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
	return &Backend{device: device, stateDir: stateDir, run: run, now: now}
}

func (*Backend) Name() string { return "networkmanager" }
func (*Backend) Close() error { return nil }

func runNMCLI(ctx context.Context, arguments ...string) (string, error) {
	output, err := exec.CommandContext(ctx, "/usr/bin/nmcli", arguments...).Output()
	return string(output), err
}

// Status reports the live radio state and the one profile owned by NasSimHub.
func (b *Backend) Status(ctx context.Context) (proto.WiFiStatus, error) {
	b.mu.Lock()
	if b.state == proto.WiFiConnecting {
		status := proto.WiFiStatus{State: b.state, SSID: b.target, ObservedAt: b.now().UTC()}
		b.mu.Unlock()
		return status, nil
	}
	if b.state == proto.WiFiFailed && b.now().Sub(b.failedAt) < recoveryWindow {
		status := proto.WiFiStatus{State: b.state, FailureReason: b.failure, ObservedAt: b.now().UTC()}
		b.mu.Unlock()
		return status, nil
	}
	b.state, b.target, b.failure, b.failedAt = "", "", "", time.Time{}
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

	status := proto.WiFiStatus{State: proto.WiFiNoConfig, ObservedAt: b.now().UTC()}
	savedSSID, _ := b.connectionSSID(ctx, defaultProfile)
	status.SavedSSID = savedSSID
	if deviceState != "connected" || connection == "" || connection == "--" {
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
func (b *Backend) Scan(ctx context.Context) (proto.WiFiScanResult, error) {
	output, err := b.run(ctx, "-t", "--escape", "yes", "-f", "SSID,SIGNAL,SECURITY,CHAN", "device", "wifi", "list", "ifname", b.device, "--rescan", "yes")
	if err != nil {
		return proto.WiFiScanResult{}, proto.Unavailable("wifi.scan", "Wi-Fi scan failed", err)
	}
	bySSID := make(map[string]proto.WiFiNetwork)
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
		if old, exists := bySSID[network.SSID]; !exists || network.SignalDBM > old.SignalDBM {
			bySSID[network.SSID] = network
		}
	}
	networks := make([]proto.WiFiNetwork, 0, len(bySSID))
	for _, network := range bySSID {
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
	if request.Security != proto.WiFiSecurityOpen && (len(request.PSK) < 8 || len(request.PSK) > 63) {
		return proto.WiFiStatus{}, proto.InvalidArgument("wifi.connect", "psk must contain 8 to 63 characters")
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

	go b.connect(context.Background(), ssid, request.PSK, request.Security)
	return proto.WiFiStatus{State: proto.WiFiConnecting, SSID: ssid, ObservedAt: b.now().UTC()}, nil
}

func (b *Backend) connect(ctx context.Context, ssid, psk string, security proto.WiFiSecurity) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	profile := fmt.Sprintf("nsh-agent-%d", time.Now().UnixNano())
	if _, err := b.run(ctx, "connection", "add", "type", "wifi", "ifname", b.device, "con-name", profile, "ssid", ssid, "connection.autoconnect", "no"); err != nil {
		b.fail("could not create the saved network")
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
			b.fail("could not configure network security")
			return
		}
	}

	passwordFile := ""
	if security != proto.WiFiSecurityOpen {
		var err error
		passwordFile, err = b.writePasswordFile(psk)
		if err != nil {
			cleanup()
			b.fail("could not prepare the network credential")
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
		b.fail("authentication or association failed")
		return
	}
	_, _ = b.run(ctx, "connection", "delete", "id", defaultProfile)
	if _, err := b.run(ctx, "connection", "modify", "id", profile, "connection.id", defaultProfile); err != nil {
		cleanup()
		b.fail("could not save the connected network")
		return
	}
	if _, err := b.run(ctx, "connection", "modify", "id", defaultProfile, "connection.autoconnect", "yes"); err != nil {
		b.fail("could not enable automatic reconnection")
		return
	}
	b.mu.Lock()
	b.state, b.target, b.failure, b.failedAt = "", "", "", time.Time{}
	b.mu.Unlock()
}

func (b *Backend) fail(reason string) {
	b.mu.Lock()
	b.state, b.target, b.failure, b.failedAt = proto.WiFiFailed, "", reason, b.now()
	b.mu.Unlock()
}

// Forget deletes only the profile owned by NasSimHub.
func (b *Backend) Forget(ctx context.Context) (proto.WiFiStatus, error) {
	_, err := b.run(ctx, "connection", "delete", "id", defaultProfile)
	if err != nil && !isMissingProfile(err) {
		return proto.WiFiStatus{}, proto.Unavailable("wifi.forget", "could not remove the saved network", err)
	}
	b.mu.Lock()
	b.state, b.target, b.failure, b.failedAt = "", "", "", time.Time{}
	b.mu.Unlock()
	return proto.WiFiStatus{State: proto.WiFiNoConfig, ObservedAt: b.now().UTC()}, nil
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
