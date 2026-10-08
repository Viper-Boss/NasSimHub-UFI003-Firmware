package networkmanager

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

func TestScanParsesEscapesDeduplicatesAndSorts(t *testing.T) {
	backend := New(Options{Run: func(_ context.Context, arguments ...string) (string, error) {
		return "Home\\:IoT:80:WPA2:6\nOpen:22::1\nHome\\:IoT:60:WPA2:6\nNext:90:WPA3:11\n", nil
	}})
	result, err := backend.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Networks) != 3 {
		t.Fatalf("got %d networks", len(result.Networks))
	}
	if got := result.Networks[0]; got.SSID != "Next" || got.SignalDBM != -55 || got.Security != proto.WiFiSecurityWPA3 {
		t.Fatalf("strongest network = %#v", got)
	}
	if got := result.Networks[1]; got.SSID != "Home:IoT" || got.SignalDBM != -60 || got.Channel != 6 {
		t.Fatalf("escaped network = %#v", got)
	}
	if got := result.Networks[2]; got.Security != proto.WiFiSecurityOpen {
		t.Fatalf("open network = %#v", got)
	}
}

func TestStatusConnectedHasSSIDAddressAndSignal(t *testing.T) {
	run := func(_ context.Context, arguments ...string) (string, error) {
		command := strings.Join(arguments, " ")
		switch {
		case strings.Contains(command, "DEVICE,TYPE,STATE,CONNECTION"):
			return "wlan0:wifi:connected:nassimhub-wifi\n", nil
		case strings.Contains(command, "802-11-wireless.ssid"):
			return "Home\n", nil
		case strings.Contains(command, "IP4.ADDRESS"):
			return "192.168.1.44/24\n", nil
		case strings.Contains(command, "SSID,SIGNAL"):
			return "Home:70\n", nil
		default:
			return "", errors.New("unexpected command: " + command)
		}
	}
	backend := New(Options{Run: run})
	status, err := backend.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.State != proto.WiFiConnected || status.SSID != "Home" || status.IPv4 != "192.168.1.44" {
		t.Fatalf("status = %#v", status)
	}
	if status.SignalDBM == nil || *status.SignalDBM != -65 {
		t.Fatalf("signal = %#v", status.SignalDBM)
	}
}

func TestConnectKeepsPSKOutOfArgumentsAndRemovesSecret(t *testing.T) {
	var mu sync.Mutex
	var calls [][]string
	done := make(chan struct{})
	psk := "not-in-argv-123"
	run := func(_ context.Context, arguments ...string) (string, error) {
		mu.Lock()
		calls = append(calls, append([]string(nil), arguments...))
		if strings.Contains(strings.Join(arguments, " "), "connection up") {
			select {
			case <-done:
			default:
				close(done)
			}
		}
		mu.Unlock()
		return "", nil
	}
	backend := New(Options{StateDir: t.TempDir(), Run: run})
	status, err := backend.Connect(context.Background(), proto.WiFiConnectRequest{SSID: "Home", PSK: psk, Security: proto.WiFiSecurityWPA2})
	if err != nil || status.State != proto.WiFiConnecting {
		t.Fatalf("connect = %#v, %v", status, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connect did not finish")
	}
	deadline := time.Now().Add(time.Second)
	for {
		entries, err := os.ReadDir(backend.stateDir)
		if err != nil {
			t.Fatal(err)
		}
		secret := false
		for _, entry := range entries {
			secret = secret || strings.HasPrefix(entry.Name(), ".wifi-secret-")
		}
		if !secret {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("credential file was not removed")
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	addIndex, upIndex, deleteOldIndex := -1, -1, -1
	for index, call := range calls {
		if strings.Contains(strings.Join(call, "\x00"), psk) {
			t.Fatalf("credential appeared in argv: %#v", call)
		}
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "connection add") {
			addIndex = index
			if !strings.Contains(joined, "connection.autoconnect no") {
				t.Fatalf("new profile may activate before credentials exist: %#v", call)
			}
		}
		if strings.Contains(joined, "connection up") {
			upIndex = index
			if len(call) < 2 || call[len(call)-2] != "passwd-file" {
				t.Fatalf("password file is not a connection-up argument: %#v", call)
			}
		}
		if joined == "connection delete id "+previousProfile {
			deleteOldIndex = index
		}
	}
	if addIndex < 0 || upIndex <= addIndex || deleteOldIndex <= upIndex {
		t.Fatalf("profile activation or replacement order is unsafe: %#v", calls)
	}
}

func TestConnectValidation(t *testing.T) {
	backend := New(Options{Run: func(context.Context, ...string) (string, error) { return "", nil }})
	for _, request := range []proto.WiFiConnectRequest{
		{},
		{SSID: "Home", Security: proto.WiFiSecurityWPA2},
		{SSID: "Home", PSK: "short", Security: proto.WiFiSecurityWPA2},
		{SSID: strings.Repeat("x", 33), Security: proto.WiFiSecurityOpen},
	} {
		if _, err := backend.Connect(context.Background(), request); proto.CodeOf(err) != proto.ErrorInvalidArgument {
			t.Fatalf("request %#v: %v", request, err)
		}
	}
}

// connectAndWait runs one Connect to completion against a scripted nmcli and
// returns every command it issued.
func connectAndWait(t *testing.T, fail func(joined string) bool, request proto.WiFiConnectRequest) (*Backend, []string) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	run := func(_ context.Context, arguments ...string) (string, error) {
		joined := strings.Join(arguments, " ")
		mu.Lock()
		calls = append(calls, joined)
		mu.Unlock()
		if fail(joined) {
			return "", errors.New("scripted failure")
		}
		return "", nil
	}
	backend := New(Options{StateDir: t.TempDir(), Run: run})
	if _, err := backend.Connect(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		backend.mu.Lock()
		settled := backend.state != proto.WiFiConnecting
		backend.mu.Unlock()
		if settled {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("connect did not settle")
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	return backend, append([]string(nil), calls...)
}

func indexOf(calls []string, match func(string) bool) int {
	for index, call := range calls {
		if match(call) {
			return index
		}
	}
	return -1
}

func TestFailedJoinKeepsTheSavedNetworkAndRejoinsIt(t *testing.T) {
	request := proto.WiFiConnectRequest{SSID: "New", PSK: "wrong-passphrase", Security: proto.WiFiSecurityWPA2}
	backend, calls := connectAndWait(t, func(joined string) bool {
		return strings.Contains(joined, "connection up id nsh-agent-")
	}, request)
	backend.mu.Lock()
	state, failure := backend.state, backend.failure
	backend.mu.Unlock()
	if state != proto.WiFiFailed || failure == "" {
		t.Fatalf("state after a failed join: %s %q", state, failure)
	}
	for _, call := range calls {
		if call == "connection delete id "+defaultProfile || strings.Contains(call, "connection.id "+previousProfile) {
			t.Fatalf("a failed join touched the saved network: %q", call)
		}
	}
	failed := indexOf(calls, func(c string) bool { return strings.Contains(c, "connection up id nsh-agent-") })
	removed := indexOf(calls, func(c string) bool { return strings.HasPrefix(c, "connection delete id nsh-agent-") })
	rejoin := indexOf(calls, func(c string) bool { return strings.Contains(c, "connection up id "+defaultProfile) })
	if failed < 0 || removed < failed || rejoin < removed {
		t.Fatalf("the temporary profile must be removed and the saved network rejoined: %#v", calls)
	}
}

func TestSuccessfulJoinNeverLeavesTheDeviceWithoutASavedNetwork(t *testing.T) {
	request := proto.WiFiConnectRequest{SSID: "New", PSK: "correct-passphrase", Security: proto.WiFiSecurityWPA2}
	_, calls := connectAndWait(t, func(string) bool { return false }, request)
	aside := indexOf(calls, func(c string) bool {
		return c == "connection modify id "+defaultProfile+" connection.id "+previousProfile
	})
	renamed := indexOf(calls, func(c string) bool {
		return strings.HasPrefix(c, "connection modify id nsh-agent-") && strings.HasSuffix(c, "connection.id "+defaultProfile)
	})
	dropped := indexOf(calls, func(c string) bool { return c == "connection delete id "+previousProfile })
	if aside < 0 || renamed < aside || dropped < renamed {
		t.Fatalf("old profile must be set aside, then replaced, then deleted: %#v", calls)
	}
	if indexOf(calls, func(c string) bool { return c == "connection delete id "+defaultProfile }) >= 0 {
		t.Fatalf("the saved network must never be deleted outright: %#v", calls)
	}

	// The rename of the new profile fails: the old one gets its name back and
	// is brought up again, and is not deleted.
	backend, calls := connectAndWait(t, func(joined string) bool {
		return strings.HasPrefix(joined, "connection modify id nsh-agent-") && strings.HasSuffix(joined, "connection.id "+defaultProfile)
	}, request)
	backend.mu.Lock()
	state := backend.state
	backend.mu.Unlock()
	back := indexOf(calls, func(c string) bool {
		return c == "connection modify id "+previousProfile+" connection.id "+defaultProfile
	})
	rejoin := indexOf(calls, func(c string) bool { return strings.Contains(c, "connection up id "+defaultProfile) })
	if state != proto.WiFiFailed || back < 0 || rejoin < back {
		t.Fatalf("a failed save must put the previous network back: %s %#v", state, calls)
	}
	if indexOf(calls, func(c string) bool { return c == "connection delete id "+previousProfile }) >= 0 {
		t.Fatalf("the previous network was deleted although the new one was not saved: %#v", calls)
	}
}

func TestRawWPA2KeyIsAcceptedOnlyAsSixtyFourHexDigitsAndNeverForSAE(t *testing.T) {
	hexKey := strings.Repeat("0123456789abcdef", 4)
	if !validPSK(hexKey, proto.WiFiSecurityWPA2) || validPSK(hexKey, proto.WiFiSecurityWPA3) {
		t.Fatal("a 64-digit hexadecimal key is a WPA2 form only")
	}
	if validPSK(strings.Repeat("z", 64), proto.WiFiSecurityWPA2) || validPSK(strings.Repeat("a", 65), proto.WiFiSecurityWPA2) || validPSK("short", proto.WiFiSecurityWPA2) {
		t.Fatal("only 8-63 characters or 64 hexadecimal digits are a key")
	}
}
