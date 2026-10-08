package provisioning

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// hintBackend is a backend in its access point that reports what the hardware
// backend reports: a provisioning state, support hints and a cached scan.
type hintBackend struct {
	activity int
	scan     proto.WiFiScanResult
}

func (*hintBackend) Name() string { return "hint" }
func (*hintBackend) Close() error { return nil }
func (*hintBackend) Status(context.Context) (proto.WiFiStatus, error) {
	return proto.WiFiStatus{State: proto.WiFiProvisioningAP, APSSID: "NasSimHub-A83F29", APAddress: "192.168.4.1",
		ProvisioningState: proto.WiFiProvisioningAPReady, ObservedAt: time.Unix(1_700_000_000, 0)}, nil
}
func (b *hintBackend) Scan(context.Context) (proto.WiFiScanResult, error) { return b.scan, nil }
func (*hintBackend) Connect(context.Context, proto.WiFiConnectRequest) (proto.WiFiStatus, error) {
	return proto.WiFiStatus{State: proto.WiFiConnecting}, nil
}
func (*hintBackend) Forget(context.Context) (proto.WiFiStatus, error) {
	return proto.WiFiStatus{State: proto.WiFiNoConfig}, nil
}
func (b *hintBackend) NoteSetupActivity() { b.activity++ }

func TestScanPassesTheSupportHintThroughAndHidesNoNetwork(t *testing.T) {
	backend := &hintBackend{scan: proto.WiFiScanResult{FromCache: true, Networks: []proto.WiFiNetwork{
		{SSID: "Example-24", SignalDBM: -50, Security: proto.WiFiSecurityWPA2, Channel: 6, Support: proto.WiFiSupportVerified, SupportReason: "verified kind"},
		{SSID: "Example-5", SignalDBM: -50, Security: proto.WiFiSecurityWPA2, Channel: 36, Support: proto.WiFiSupportUnverified, SupportReason: "5 GHz has not been verified on this hardware"},
		{SSID: "Example-SAE", SignalDBM: -50, Security: proto.WiFiSecurityWPA3, Channel: 1, Support: proto.WiFiSupportUnverified, SupportReason: "WPA3-only (SAE) has not been verified on this hardware"},
		{SSID: "Example-Corp", SignalDBM: -50, Security: proto.WiFiSecurityWPA2, Channel: 1, Support: proto.WiFiSupportUnsupported, SupportReason: "802.1X"},
		{SSID: "Example-NoHint", SignalDBM: -50, Security: proto.WiFiSecurityWPA2},
	}}}
	_, handler, err := NewHandler(Options{Identity: Identity{DeviceID: deviceID}, Network: backend})
	if err != nil {
		t.Fatal(err)
	}
	response := call(t, handler, http.MethodPost, "/provision/scan", "192.168.4.23:40000", map[string]string{})
	if response.Code != http.StatusOK {
		t.Fatalf("scan: %d %s", response.Code, response.Body)
	}
	var result ScanResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Networks) != 5 || !result.FromCache {
		t.Fatalf("every network must be listed and a cached list marked: %#v", result)
	}
	for index, want := range []proto.WiFiSupport{proto.WiFiSupportVerified, proto.WiFiSupportUnverified, proto.WiFiSupportUnverified, proto.WiFiSupportUnsupported, ""} {
		if got := result.Networks[index]; got.Support != want || (want != "" && got.SupportReason == "") {
			t.Fatalf("%s: support %q (%q), want %q", got.SSID, got.Support, got.SupportReason, want)
		}
	}
	// No hint from the backend is "unknown": the field is absent, not "verified".
	if strings.Count(response.Body.String(), `"support":`) != 4 {
		t.Fatalf("a network without a hint was given one: %s", response.Body)
	}
	// Channel stays out of this reduced document.
	if strings.Contains(response.Body.String(), "channel") {
		t.Fatalf("the reduced scan document grew a channel: %s", response.Body)
	}
}

func TestStatusCarriesTheProvisioningStateAndThePageUseIsNoted(t *testing.T) {
	backend := &hintBackend{}
	_, handler, err := NewHandler(Options{Identity: Identity{DeviceID: deviceID}, Network: backend})
	if err != nil {
		t.Fatal(err)
	}
	response := call(t, handler, http.MethodGet, "/provision/status", "192.168.4.23:40000", nil)
	var status Status
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil || status.ProvisioningState != proto.WiFiProvisioningAPReady {
		t.Fatalf("status: %s %v", response.Body, err)
	}
	if backend.activity != 1 {
		t.Fatalf("a request from the setup page was noted %d times", backend.activity)
	}
	// A caller outside the access point's network is not someone using the
	// setup page and must not be able to hold the access point up.
	call(t, handler, http.MethodGet, "/provision/status", "10.55.0.1:40000", nil)
	if backend.activity != 1 {
		t.Fatal("a refused caller was counted as setup page activity")
	}
}

func TestTheSetupPageMarksUnverifiedNetworksAndClaimsNoSupportForThem(t *testing.T) {
	page := string(setupPage)
	for _, want := range []string{"network.support", "未在本设备上验证", "不支持", "from_cache"} {
		if !strings.Contains(page, want) {
			t.Fatalf("the setup page does not handle %q", want)
		}
	}
	for _, claim := range []string{"支持 5G", "支持 WPA3", "支持5G", "支持WPA3"} {
		if strings.Contains(page, claim) {
			t.Fatalf("the setup page claims %q, which is not verified on this hardware", claim)
		}
	}
}

// An access point whose setup page cannot be served must not be silent: the
// reason is logged, once, and the supervisor keeps trying.
func TestSupervisorSaysOnceWhyTheSetupPageCannotListen(t *testing.T) {
	var lines []string
	supervisor, err := NewSupervisor(Options{
		Identity: Identity{DeviceID: deviceID}, Network: &hintBackend{},
		// TEST-NET-3: never an address of this machine, so the bind fails.
		Listen: "203.0.113.7:8080",
		Logf:   func(format string, arguments ...any) { lines = append(lines, fmt.Sprintf(format, arguments...)) },
	}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		supervisor.reconcile(context.Background())
	}
	if supervisor.Serving() {
		t.Fatal("the supervisor claims to serve on an address it cannot bind")
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "203.0.113.7:8080") {
		t.Fatalf("the listen failure was logged %d time(s): %v", len(lines), lines)
	}
}
