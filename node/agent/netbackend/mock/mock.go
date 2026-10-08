// Package mock implements the Wi-Fi state machine in software.
//
// It is a full implementation of the provisioning lifecycle - including the
// timed recovery back to an access point after a failed join - so the entire
// flow can be driven, demonstrated and regression-tested with no radio. A real
// device backend replaces only the three verbs (scan, associate, tear down the
// AP); the state machine and its recovery guarantee live here and are shared.
package mock

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/netbackend"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// RecoveryWindow is how long a failed join stays visible before the Node
// returns to provisioning. It sits inside the 60-90 second band the design
// calls for: long enough that the user sees why the join failed, short enough
// that an unattended device is never stranded.
const RecoveryWindow = 75 * time.Second

// ConnectDelay is how long CONNECTING lasts before it resolves.
const ConnectDelay = 3 * time.Second

// Backend is a software Wi-Fi radio.
type Backend struct {
	mu sync.Mutex

	deviceID  string
	now       func() time.Time
	visible   []proto.WiFiNetwork
	passwords map[string]string

	state      proto.WiFiState
	savedSSID  string
	activeSSID string
	failure    string
	// offered holds the PSK supplied by the in-flight Connect. It lives only
	// for the duration of the join attempt and is cleared the moment the
	// attempt resolves, so a credential is never retained after its use and
	// never becomes reachable from any read path.
	offered string
	// deadline is when the current transient state resolves: the end of
	// CONNECTING, or the end of the FAILED recovery window.
	deadline time.Time
}

// Options configures the mock Wi-Fi backend.
type Options struct {
	// DeviceID seeds the provisioning SSID so several mock Nodes on one
	// machine are distinguishable.
	DeviceID string
	// Visible is the fake neighbourhood returned by Scan.
	Visible []proto.WiFiNetwork
	// Passwords maps SSID to the PSK that will be accepted. An SSID absent
	// from the map accepts any non-empty PSK, which keeps demos frictionless;
	// an SSID present in the map rejects anything else, which is what the
	// failure-path tests need.
	Passwords map[string]string
	// SavedSSID pre-seeds a previously configured network, for starting a mock
	// Node directly in CONNECTED.
	SavedSSID string
	Now       func() time.Time
}

// DefaultVisible is a plausible neighbourhood.
func DefaultVisible() []proto.WiFiNetwork {
	return []proto.WiFiNetwork{
		{SSID: "HomeNet-5G", SignalDBM: -48, Security: proto.WiFiSecurityWPA2, Channel: 36},
		{SSID: "HomeNet", SignalDBM: -55, Security: proto.WiFiSecurityWPA2, Channel: 6},
		{SSID: "Neighbour-2.4", SignalDBM: -79, Security: proto.WiFiSecurityWPA3, Channel: 11},
		{SSID: "FreeWiFi", SignalDBM: -88, Security: proto.WiFiSecurityOpen, Channel: 1},
	}
}

// New builds a mock Wi-Fi backend.
//
// With no saved network it starts in PROVISIONING_AP rather than idle, because
// a Node that is not reachable is a Node that has to be recovered by hand.
func New(options Options) *Backend {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	visible := options.Visible
	if visible == nil {
		visible = DefaultVisible()
	}
	backend := &Backend{
		deviceID:  options.DeviceID,
		now:       now,
		visible:   visible,
		passwords: options.Passwords,
		state:     proto.WiFiProvisioningAP,
		savedSSID: options.SavedSSID,
	}
	if options.SavedSSID != "" {
		backend.state = proto.WiFiConnected
		backend.activeSSID = options.SavedSSID
	}
	return backend
}

func (b *Backend) Name() string { return "mock-wifi" }

func (b *Backend) Close() error { return nil }

// apSSID is the provisioning network name. The device_id suffix makes several
// Nodes distinguishable in a list, which matters as soon as a household has
// more than one stick.
func (b *Backend) apSSID() string {
	suffix := "0000"
	if parts := strings.Split(b.deviceID, "-"); len(parts) > 0 {
		last := parts[len(parts)-1]
		if len(last) >= 4 {
			suffix = last[len(last)-4:]
		}
	}
	return "NasSimHub-" + suffix
}

// advanceLocked resolves whichever transient state has reached its deadline.
//
// Doing this on read rather than on a timer means the state machine has no
// background goroutine, no timer to leak, and behaves identically whether time
// is real or injected by a test.
func (b *Backend) advanceLocked() {
	if b.deadline.IsZero() || b.now().Before(b.deadline) {
		return
	}
	switch b.state {
	case proto.WiFiConnecting:
		accepted := b.acceptsLocked(b.activeSSID)
		b.offered = ""
		if accepted {
			b.state = proto.WiFiConnected
			b.savedSSID = b.activeSSID
			b.failure = ""
			b.deadline = time.Time{}
			return
		}
		b.state = proto.WiFiFailed
		b.failure = "authentication failed"
		b.activeSSID = ""
		// The recovery window starts the moment the join fails.
		b.deadline = b.now().Add(RecoveryWindow)
	case proto.WiFiFailed:
		// Never leave the device unreachable: go back to serving the AP.
		b.state = proto.WiFiProvisioningAP
		b.deadline = time.Time{}
	}
}

// acceptsLocked decides whether the offered credential joins ssid.
func (b *Backend) acceptsLocked(ssid string) bool {
	expected, known := b.passwords[ssid]
	if !known {
		return b.offered != ""
	}
	return b.offered == expected
}

func (b *Backend) Status(context.Context) (proto.WiFiStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.advanceLocked()
	return b.statusLocked(), nil
}

func (b *Backend) statusLocked() proto.WiFiStatus {
	status := proto.WiFiStatus{
		State:      b.state,
		SavedSSID:  b.savedSSID,
		ObservedAt: b.now().UTC(),
	}
	switch b.state {
	case proto.WiFiConnected:
		status.SSID = b.activeSSID
		status.IPv4 = "192.168.1.64"
		if signal, ok := b.signalFor(b.activeSSID); ok {
			status.SignalDBM = &signal
		}
	case proto.WiFiConnecting:
		status.SSID = b.activeSSID
	case proto.WiFiFailed:
		status.FailureReason = b.failure
	case proto.WiFiProvisioningAP:
		status.APSSID = b.apSSID()
		status.APAddress = "192.168.4.1"
	}
	return status
}

func (b *Backend) signalFor(ssid string) (float64, bool) {
	for _, network := range b.visible {
		if network.SSID == ssid {
			return network.SignalDBM, true
		}
	}
	return 0, false
}

func (b *Backend) Scan(context.Context) (proto.WiFiScanResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.advanceLocked()
	networks := make([]proto.WiFiNetwork, len(b.visible))
	copy(networks, b.visible)
	for index := range networks {
		// The same evidence-based hint the hardware backend gives, so the
		// pages built against the mock show the marks they will show for real.
		if networks[index].Support == "" {
			networks[index].Support, networks[index].SupportReason = netbackend.SupportFor(networks[index].Security, networks[index].Channel, false)
		}
	}
	return proto.WiFiScanResult{Networks: networks, ScannedAt: b.now().UTC()}, nil
}

func (b *Backend) Connect(_ context.Context, request proto.WiFiConnectRequest) (proto.WiFiStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.advanceLocked()

	ssid := strings.TrimSpace(request.SSID)
	if ssid == "" {
		return proto.WiFiStatus{}, proto.InvalidArgument("wifi_connect", "ssid is required")
	}
	if request.Security != proto.WiFiSecurityOpen && strings.TrimSpace(request.PSK) == "" {
		return proto.WiFiStatus{}, proto.InvalidArgument("wifi_connect", "psk is required for a protected network")
	}
	if b.state == proto.WiFiConnecting {
		return proto.WiFiStatus{}, proto.Conflict("wifi_connect", "a connection attempt is already in progress")
	}

	b.activeSSID = ssid
	b.offered = request.PSK
	b.state = proto.WiFiConnecting
	b.failure = ""
	b.deadline = b.now().Add(ConnectDelay)
	return b.statusLocked(), nil
}

func (b *Backend) Forget(context.Context) (proto.WiFiStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.savedSSID = ""
	b.activeSSID = ""
	b.offered = ""
	b.failure = ""
	b.deadline = time.Time{}
	// Forgetting always lands on the access point rather than on an idle
	// state, so the device stays reachable.
	b.state = proto.WiFiProvisioningAP
	return b.statusLocked(), nil
}

// ---------------------------------------------------------------------------
// Scenario control for the mock Node CLI.
// ---------------------------------------------------------------------------

// SetVisible replaces the fake neighbourhood.
func (b *Backend) SetVisible(networks []proto.WiFiNetwork) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.visible = networks
}

// Drop simulates losing the associated network, which is what a router reboot
// looks like from the Node's side.
func (b *Backend) Drop(reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if reason == "" {
		reason = "association lost"
	}
	b.state = proto.WiFiFailed
	b.failure = reason
	b.activeSSID = ""
	b.deadline = b.now().Add(RecoveryWindow)
}

// Describe renders the state machine for a CLI status line.
func (b *Backend) Describe() string {
	status, _ := b.Status(context.Background())
	switch status.State {
	case proto.WiFiConnected:
		return fmt.Sprintf("connected to %s", status.SSID)
	case proto.WiFiProvisioningAP:
		return fmt.Sprintf("provisioning ap %s at %s", status.APSSID, status.APAddress)
	default:
		return string(status.State)
	}
}
