package mock

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

type clock struct{ at time.Time }

func (c *clock) now() time.Time { return c.at }

func newBackend(t *testing.T, options Options) (*Backend, *clock, context.Context) {
	t.Helper()
	at := &clock{at: time.Now().UTC()}
	options.Now = at.now
	if options.DeviceID == "" {
		options.DeviceID = "NSH-410-A83F29"
	}
	backend := New(options)
	t.Cleanup(func() { _ = backend.Close() })
	return backend, at, context.Background()
}

func TestFirstBootServesProvisioningAP(t *testing.T) {
	backend, _, ctx := newBackend(t, Options{})
	status, err := backend.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.State != proto.WiFiProvisioningAP {
		t.Fatalf("a node with no saved network is in %s, want PROVISIONING_AP", status.State)
	}
	if status.APSSID != "NasSimHub-3F29" {
		t.Fatalf("ap ssid is %q", status.APSSID)
	}
	if status.APAddress != "192.168.4.1" {
		t.Fatalf("ap address is %q", status.APAddress)
	}
}

func TestProvisioningSSIDDistinguishesNodes(t *testing.T) {
	first, _, ctx := newBackend(t, Options{DeviceID: "NSH-410-A83F29"})
	second, _, _ := newBackend(t, Options{DeviceID: "NSH-410-B14C07"})
	a, _ := first.Status(ctx)
	b, _ := second.Status(ctx)
	if a.APSSID == b.APSSID {
		t.Fatalf("two nodes advertise the same provisioning ssid %q", a.APSSID)
	}
}

func TestSuccessfulJoinLifecycle(t *testing.T) {
	backend, at, ctx := newBackend(t, Options{Passwords: map[string]string{"HomeNet": "correct-horse"}})

	status, err := backend.Connect(ctx, proto.WiFiConnectRequest{SSID: "HomeNet", PSK: "correct-horse"})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if status.State != proto.WiFiConnecting {
		t.Fatalf("state after connect is %s", status.State)
	}

	at.at = at.at.Add(ConnectDelay + time.Second)
	status, err = backend.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.State != proto.WiFiConnected {
		t.Fatalf("state after the join window is %s", status.State)
	}
	if status.SSID != "HomeNet" || status.SavedSSID != "HomeNet" {
		t.Fatalf("status is %+v", status)
	}
	if status.IPv4 == "" {
		t.Fatal("a connected node reported no address")
	}
	if status.APSSID != "" {
		t.Fatal("the provisioning AP is still advertised after a successful join")
	}
}

func TestFailedJoinRecoversToProvisioning(t *testing.T) {
	backend, at, ctx := newBackend(t, Options{Passwords: map[string]string{"HomeNet": "correct-horse"}})

	if _, err := backend.Connect(ctx, proto.WiFiConnectRequest{SSID: "HomeNet", PSK: "wrong"}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	at.at = at.at.Add(ConnectDelay + time.Second)
	status, err := backend.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.State != proto.WiFiFailed {
		t.Fatalf("a bad credential produced %s", status.State)
	}
	if status.FailureReason == "" {
		t.Fatal("a failed join must explain itself")
	}

	// Still failed part-way through the recovery window.
	at.at = at.at.Add(RecoveryWindow / 2)
	status, _ = backend.Status(ctx)
	if status.State != proto.WiFiFailed {
		t.Fatalf("recovery fired early, state is %s", status.State)
	}

	// Recovered once the window elapses. This is the property that keeps a
	// headless device reachable without touching the power button.
	at.at = at.at.Add(RecoveryWindow)
	status, _ = backend.Status(ctx)
	if status.State != proto.WiFiProvisioningAP {
		t.Fatalf("node did not recover to the provisioning AP, state is %s", status.State)
	}
	if status.APAddress != "192.168.4.1" {
		t.Fatalf("recovered node serves %q", status.APAddress)
	}
}

func TestRecoveryWindowIsInTheDesignBand(t *testing.T) {
	if RecoveryWindow < 60*time.Second || RecoveryWindow > 90*time.Second {
		t.Fatalf("recovery window %v is outside the 60-90s design band", RecoveryWindow)
	}
}

func TestDroppedAssociationAlsoRecovers(t *testing.T) {
	backend, at, ctx := newBackend(t, Options{SavedSSID: "HomeNet"})
	status, _ := backend.Status(ctx)
	if status.State != proto.WiFiConnected {
		t.Fatalf("pre-seeded node is %s", status.State)
	}

	backend.Drop("router rebooted")
	status, _ = backend.Status(ctx)
	if status.State != proto.WiFiFailed {
		t.Fatalf("after a drop the state is %s", status.State)
	}

	at.at = at.at.Add(RecoveryWindow + time.Second)
	status, _ = backend.Status(ctx)
	if status.State != proto.WiFiProvisioningAP {
		t.Fatalf("a dropped association did not recover, state is %s", status.State)
	}
}

func TestForgetReturnsToProvisioning(t *testing.T) {
	backend, _, ctx := newBackend(t, Options{SavedSSID: "HomeNet"})
	status, err := backend.Forget(ctx)
	if err != nil {
		t.Fatalf("forget: %v", err)
	}
	if status.State != proto.WiFiProvisioningAP {
		t.Fatalf("forget left the node in %s", status.State)
	}
	if status.SavedSSID != "" {
		t.Fatalf("forget kept the saved network %q", status.SavedSSID)
	}
}

func TestConnectValidatesInput(t *testing.T) {
	backend, _, ctx := newBackend(t, Options{})

	_, err := backend.Connect(ctx, proto.WiFiConnectRequest{})
	if proto.CodeOf(err) != proto.ErrorInvalidArgument {
		t.Fatalf("empty ssid returned %s", proto.CodeOf(err))
	}
	_, err = backend.Connect(ctx, proto.WiFiConnectRequest{SSID: "HomeNet"})
	if proto.CodeOf(err) != proto.ErrorInvalidArgument {
		t.Fatalf("missing psk on a protected network returned %s", proto.CodeOf(err))
	}
	// An explicitly open network needs no credential.
	if _, err := backend.Connect(ctx, proto.WiFiConnectRequest{SSID: "FreeWiFi", Security: proto.WiFiSecurityOpen}); err != nil {
		t.Fatalf("open network connect: %v", err)
	}
}

func TestConcurrentConnectIsRefused(t *testing.T) {
	backend, _, ctx := newBackend(t, Options{})
	if _, err := backend.Connect(ctx, proto.WiFiConnectRequest{SSID: "HomeNet", PSK: "x"}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	_, err := backend.Connect(ctx, proto.WiFiConnectRequest{SSID: "Other", PSK: "y"})
	if proto.CodeOf(err) != proto.ErrorConflict {
		t.Fatalf("overlapping connect returned %s", proto.CodeOf(err))
	}
}

func TestStatusNeverCarriesACredential(t *testing.T) {
	// The strongest guarantee available is structural: WiFiStatus has no field
	// that could hold a PSK. This test pins that, so a future field addition
	// has to go through a failing test rather than through a silent leak.
	backend, at, ctx := newBackend(t, Options{Passwords: map[string]string{"HomeNet": "correct-horse"}})
	if _, err := backend.Connect(ctx, proto.WiFiConnectRequest{SSID: "HomeNet", PSK: "correct-horse"}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	at.at = at.at.Add(ConnectDelay + time.Second)
	status, _ := backend.Status(ctx)

	encoded := marshal(t, status)
	if contains(encoded, "correct-horse") {
		t.Fatalf("wifi status leaked the credential: %s", encoded)
	}
}

func TestScanReturnsNeighbourhood(t *testing.T) {
	backend, _, ctx := newBackend(t, Options{})
	result, err := backend.Scan(ctx)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Networks) == 0 {
		t.Fatal("scan returned nothing")
	}
	if result.ScannedAt.IsZero() {
		t.Fatal("scan result has no timestamp")
	}
}

func marshal(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(encoded)
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
