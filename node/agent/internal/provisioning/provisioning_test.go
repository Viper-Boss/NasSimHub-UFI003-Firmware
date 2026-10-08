package provisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	netmock "github.com/human-agent65535/nassimhub-node/agent/netbackend/mock"
	"github.com/human-agent65535/nassimhub-node/proto"
)

const (
	deviceID = "NSH-410-A83F29"
	// Values a leak test looks for. They are the things a Node knows that an
	// unauthenticated caller must never learn.
	secretICCID  = "89860412345678901234"
	secretIMSI   = "460001234567890"
	secretNumber = "+8610000000001"
	secretPSK    = "SuperSecretWifiPassword"
)

type stubPairing struct{ state proto.PairingState }

func (s stubPairing) State() proto.PairingState { return s.state }

func newHarness(t *testing.T, saved string) (*netmock.Backend, http.Handler) {
	t.Helper()
	network := netmock.New(netmock.Options{DeviceID: deviceID, SavedSSID: saved})
	t.Cleanup(func() { _ = network.Close() })
	_, handler, err := NewHandler(Options{
		Identity: Identity{DeviceID: deviceID, Platform: proto.PlatformMSM8916, Model: "UFI003", AgentVersion: "test"},
		Network:  network,
		Pairing:  stubPairing{state: proto.PairingUnpaired},
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	return network, handler
}

// call issues a request with a chosen source address, which is what the subnet
// guard keys on.
func call(t *testing.T, handler http.Handler, method, path, from string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}
	request := httptest.NewRequest(method, path, reader)
	request.RemoteAddr = from
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// ---------------------------------------------------------------------------
// Surface
// ---------------------------------------------------------------------------

func TestOnlyThreeRoutesExist(t *testing.T) {
	// Each route gets its own device. A successful connect ends provisioning -
	// that is the point of the design - so reusing one handler here would make
	// the result depend on which route was tried first.
	for _, route := range []string{
		"GET /provision/status",
		"POST /provision/scan",
		"POST /provision/connect",
	} {
		parts := strings.SplitN(route, " ", 2)
		var body any
		if parts[1] == "/provision/connect" {
			body = ConnectRequest{SSID: "HomeNet", PSK: "x"}
		}
		_, handler := newHarness(t, "")
		response := call(t, handler, parts[0], parts[1], "192.168.4.20:5000", body)
		if response.Code == http.StatusNotFound {
			t.Fatalf("%s should exist but returned 404", route)
		}
	}
}

// The corollary, stated on purpose: once the device has joined a network the
// provisioning API is gone, even from the AP subnet. Without this the test
// above could pass with a handler that never closes.
func TestTheAPIDisappearsOnceTheDeviceHasJoined(t *testing.T) {
	_, handler := newHarness(t, "")
	if response := call(t, handler, http.MethodPost, "/provision/connect",
		"192.168.4.20:5000", ConnectRequest{SSID: "HomeNet", PSK: "x"}); response.Code == http.StatusNotFound {
		t.Fatalf("connect returned 404 while still provisioning")
	}
	for _, route := range [][2]string{
		{http.MethodGet, "/provision/status"},
		{http.MethodPost, "/provision/scan"},
	} {
		response := call(t, handler, route[0], route[1], "192.168.4.20:5000", nil)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s %s returned %d after the device joined a network; "+
				"the provisioning API must not outlive provisioning",
				route[0], route[1], response.Code)
		}
	}
}

func TestNodeAPIPathsAreNotReachableHere(t *testing.T) {
	// The whole point of a second listener: none of the privileged Node
	// endpoints exist on it, so there is no window in which they are anonymous.
	_, handler := newHarness(t, "")
	for _, path := range []string{
		"/v1/sms", "/v1/sms/send", "/v1/calls", "/v1/calls/dial",
		"/v1/sim", "/v1/network", "/v1/signal", "/v1/logs", "/v1/events",
		"/v1/node", "/v1/health", "/v1/capabilities", "/v1/pair", "/v1/session",
		"/v1/wifi", "/v1/wifi/connect",
	} {
		for _, method := range []string{"GET", "POST", "DELETE"} {
			response := call(t, handler, method, path, "192.168.4.20:5000", nil)
			if response.Code != http.StatusNotFound {
				t.Fatalf("%s %s returned %d on the provisioning listener; it must not exist here",
					method, path, response.Code)
			}
		}
	}
}

func TestUnknownPathsAre404(t *testing.T) {
	_, handler := newHarness(t, "")
	// "/" is excluded: it serves the setup page. Everything else, including
	// paths that merely look like they might be under /provision, is absent.
	for _, path := range []string{"/provision", "/provision/", "/provision/logs", "/admin",
		"/index.html", "/static/app.js", "/ui"} {
		response := call(t, handler, "GET", path, "192.168.4.20:5000", nil)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d, want 404", path, response.Code)
		}
	}
}

// The setup page is served at the root, and only from inside the access point,
// and only while provisioning. It is subject to exactly the same guard as the
// API - a page that were reachable from the household LAN would be a device
// inventory for anyone on the network.
func TestTheSetupPageIsServedUnderTheSameGuard(t *testing.T) {
	_, handler := newHarness(t, "")

	response := call(t, handler, "GET", "/", "192.168.4.20:5000", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("the setup page returned %d from the access point subnet", response.Code)
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("the setup page is served as %q", contentType)
	}

	if outside := call(t, handler, "GET", "/", "192.168.1.20:5000", nil); outside.Code != http.StatusForbidden {
		t.Fatalf("the setup page returned %d from the household LAN, want 403", outside.Code)
	}
}

// The page must be self-contained. A device in provisioning mode has no
// internet connection, so anything fetched from elsewhere would hang and leave
// the user looking at a blank screen at the worst possible moment.
func TestTheSetupPageLoadsNothingFromOutside(t *testing.T) {
	page := string(setupPage)
	if len(page) == 0 {
		t.Fatal("the setup page is empty")
	}
	for _, forbidden := range []string{
		"http://", "https://", "//cdn", "googleapis", "unpkg", "jsdelivr",
		"cdnjs", "@import", "integrity=",
	} {
		if strings.Contains(strings.ToLower(page), forbidden) {
			t.Fatalf("the setup page references %q; it must load nothing from outside the device",
				forbidden)
		}
	}
	// And it must not have grown a build step.
	for _, marker := range []string{"webpack", "vite", "sourceMappingURL"} {
		if strings.Contains(page, marker) {
			t.Fatalf("the setup page carries %q, so it is no longer hand-written", marker)
		}
	}
}

// The page must not display anything the API refuses to serve.
func TestTheSetupPageShowsNothingSensitive(t *testing.T) {
	page := strings.ToLower(string(setupPage))
	for _, forbidden := range []string{"iccid", "imsi", "/v1/sms", "/v1/calls", "/v1/logs",
		"/v1/sim", "/v1/pair", "bearer"} {
		if strings.Contains(page, forbidden) {
			t.Fatalf("the setup page mentions %q", forbidden)
		}
	}
}

// ---------------------------------------------------------------------------
// Source restriction
// ---------------------------------------------------------------------------

func TestOnlyTheAccessPointSubnetIsServed(t *testing.T) {
	_, handler := newHarness(t, "")
	allowed := []string{"192.168.4.1:1024", "192.168.4.20:5000", "192.168.4.254:40000"}
	refused := []string{
		"192.168.1.20:5000",  // the household LAN
		"10.55.0.2:5000",     // the USB link
		"10.64.0.2:5000",     // the cellular bearer
		"127.0.0.1:5000",     // loopback
		"[2001:db8::1]:5000", // a routed v6 address
		"203.0.113.9:5000",   // the internet
	}
	for _, from := range allowed {
		response := call(t, handler, "GET", "/provision/status", from, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("%s was refused with %d", from, response.Code)
		}
	}
	for _, from := range refused {
		response := call(t, handler, "GET", "/provision/status", from, nil)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s reached the provisioning API with %d, want 403", from, response.Code)
		}
	}
}

func TestOffSubnetCallerCannotConnectWiFi(t *testing.T) {
	// The dangerous one: joining the device to an attacker's network.
	network, handler := newHarness(t, "")
	response := call(t, handler, "POST", "/provision/connect", "192.168.1.50:5000",
		ConnectRequest{SSID: "EvilNet", PSK: "x"})
	if response.Code != http.StatusForbidden {
		t.Fatalf("an off-subnet connect returned %d, want 403", response.Code)
	}
	status, err := network.Status(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.State != proto.WiFiProvisioningAP {
		t.Fatalf("a refused request still changed Wi-Fi state to %s", status.State)
	}
}

func TestMalformedSourceAddressIsRefused(t *testing.T) {
	_, handler := newHarness(t, "")
	for _, from := range []string{"", "not-an-address", "192.168.4", "example.com:80"} {
		response := call(t, handler, "GET", "/provision/status", from, nil)
		if response.Code != http.StatusForbidden {
			t.Fatalf("source %q returned %d, want 403", from, response.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// State gating
// ---------------------------------------------------------------------------

func TestAPIIsDeadOutsideProvisioningState(t *testing.T) {
	// Pre-seeded with a saved network, so the backend starts CONNECTED.
	_, handler := newHarness(t, "HomeNet")
	for _, c := range []struct {
		method string
		path   string
		body   any
	}{
		{"GET", "/provision/status", nil},
		{"POST", "/provision/scan", nil},
		{"POST", "/provision/connect", ConnectRequest{SSID: "HomeNet", PSK: "x"}},
	} {
		response := call(t, handler, c.method, c.path, "192.168.4.20:5000", c.body)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s %s answered with %d while CONNECTED; it must be gone",
				c.method, c.path, response.Code)
		}
	}
}

func TestAPIClosesAsSoonAsTheNodeJoins(t *testing.T) {
	network, handler := newHarness(t, "")
	if response := call(t, handler, "GET", "/provision/status", "192.168.4.20:5000", nil); response.Code != http.StatusOK {
		t.Fatalf("provisioning status returned %d", response.Code)
	}

	// Join a network the mock accepts, then let the join window elapse.
	if response := call(t, handler, "POST", "/provision/connect", "192.168.4.20:5000",
		ConnectRequest{SSID: "HomeNet", PSK: secretPSK}); response.Code != http.StatusAccepted {
		t.Fatalf("connect returned %d", response.Code)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status, err := network.Status(context.Background())
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if status.State == proto.WiFiConnected {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	response := call(t, handler, "GET", "/provision/status", "192.168.4.20:5000", nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("provisioning API still answered %d after the node joined", response.Code)
	}
}

// ---------------------------------------------------------------------------
// Disclosure
// ---------------------------------------------------------------------------

func TestNoResponseCarriesSubscriberOrCredentialData(t *testing.T) {
	_, handler := newHarness(t, "")
	bodies := []string{}

	bodies = append(bodies, call(t, handler, "GET", "/provision/status", "192.168.4.20:5000", nil).Body.String())
	bodies = append(bodies, call(t, handler, "POST", "/provision/scan", "192.168.4.20:5000", nil).Body.String())
	bodies = append(bodies, call(t, handler, "POST", "/provision/connect", "192.168.4.20:5000",
		ConnectRequest{SSID: "HomeNet", PSK: secretPSK}).Body.String())

	for index, body := range bodies {
		for _, secret := range []string{secretICCID, secretIMSI, secretNumber, secretPSK} {
			if strings.Contains(body, secret) {
				t.Fatalf("provisioning response %d disclosed %q: %s", index, secret, body)
			}
		}
		for _, field := range []string{"iccid", "imsi", "phone_number", "psk", "messages", "calls", "records", "signal_rsrp"} {
			if strings.Contains(body, field) {
				t.Fatalf("provisioning response %d carries field %q: %s", index, field, body)
			}
		}
	}
}

func TestStatusStructHasNoSensitiveFields(t *testing.T) {
	// Structural: marshalling a fully-populated Status must not be able to emit
	// a subscriber field, because no such field exists on the type.
	encoded, err := json.Marshal(Status{
		DeviceID: deviceID, Platform: proto.PlatformMSM8916, Model: "UFI003",
		AgentVersion: "test", PairingState: proto.PairingUnpaired,
		WiFiState: proto.WiFiProvisioningAP, SSID: "HomeNet", APSSID: "NasSimHub-3F29",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, field := range []string{"iccid", "imsi", "phone", "operator", "message", "call", "log", "key"} {
		if strings.Contains(strings.ToLower(string(encoded)), field) {
			t.Fatalf("Status carries a %q field: %s", field, encoded)
		}
	}
}

// ---------------------------------------------------------------------------
// Supervisor lifecycle
// ---------------------------------------------------------------------------

func TestSupervisorOpensAndClosesWithState(t *testing.T) {
	network := netmock.New(netmock.Options{DeviceID: deviceID})
	defer network.Close()

	supervisor, err := NewSupervisor(Options{
		Identity:       Identity{DeviceID: deviceID, Platform: proto.PlatformMSM8916},
		Network:        network,
		Pairing:        stubPairing{state: proto.PairingUnpaired},
		Listen:         "127.0.0.1:0",
		AllowedSubnets: []string{"127.0.0.0/8"},
	}, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("supervisor: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { supervisor.Run(ctx); close(done) }()

	waitFor(t, time.Second, supervisor.Serving, "provisioning listener never opened")
	address := supervisor.Address()
	if address == "" {
		t.Fatal("supervisor reported no address while serving")
	}
	if code := get(t, "http://"+address+"/provision/status"); code != http.StatusOK {
		t.Fatalf("provisioning status over the real listener returned %d", code)
	}

	// Join a network: the supervisor must take the listener down.
	if _, err := network.Connect(ctx, proto.WiFiConnectRequest{SSID: "HomeNet", PSK: secretPSK}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool { return !supervisor.Serving() },
		"provisioning listener stayed open after the node joined")

	// And the port is genuinely released, not merely marked closed.
	if _, err := net.DialTimeout("tcp", address, 250*time.Millisecond); err == nil {
		t.Fatal("provisioning port still accepts connections after shutdown")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor did not return after cancellation")
	}
	starts, stops := supervisor.Counters()
	if starts == 0 || stops == 0 {
		t.Fatalf("lifecycle counters are starts=%d stops=%d", starts, stops)
	}
}

func TestSupervisorReopensWhenProvisioningResumes(t *testing.T) {
	// A device that loses its network must be reachable again.
	network := netmock.New(netmock.Options{DeviceID: deviceID, SavedSSID: "HomeNet"})
	defer network.Close()

	supervisor, err := NewSupervisor(Options{
		Identity:       Identity{DeviceID: deviceID},
		Network:        network,
		Listen:         "127.0.0.1:0",
		AllowedSubnets: []string{"127.0.0.0/8"},
	}, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("supervisor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go supervisor.Run(ctx)

	// Starts CONNECTED, so nothing should be listening.
	time.Sleep(200 * time.Millisecond)
	if supervisor.Serving() {
		t.Fatal("provisioning listener opened while the node was connected")
	}

	if _, err := network.Forget(ctx); err != nil {
		t.Fatalf("forget: %v", err)
	}
	waitFor(t, 2*time.Second, supervisor.Serving,
		"provisioning listener did not reopen after the network was forgotten")
}

func TestSupervisorRejectsBadSubnet(t *testing.T) {
	network := netmock.New(netmock.Options{DeviceID: deviceID})
	defer network.Close()
	if _, err := NewSupervisor(Options{
		Network:        network,
		AllowedSubnets: []string{"not-a-cidr"},
	}, time.Second); err == nil {
		t.Fatal("a malformed subnet was accepted")
	}
}

func waitFor(t *testing.T, limit time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(message)
}

func get(t *testing.T, url string) int {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer response.Body.Close()
	return response.StatusCode
}

var _ = fmt.Sprintf
