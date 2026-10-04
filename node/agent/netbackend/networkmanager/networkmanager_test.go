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
		if joined == "connection delete id "+defaultProfile {
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
