package networkmanager

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/netbackend"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// These scenarios run the backend against fakeNM with an injected clock. They
// are simulations: they show the sequence of nmcli commands and the states the
// backend goes through, and say nothing about what the UFI003's driver does
// with those commands.

func TestFirstBootOffersTheAccessPointThenJoinsAndSurvivesAReboot(t *testing.T) {
	s := newSimulation(t, ProvisioningAPAuto)
	s.nm.inRange(simHome, simHomePSK)
	s.nm.inRange(simNeighbour, "synthetic-neighbour-key")

	if state := s.state(); state != "" {
		t.Fatalf("a backend that has not looked at the radio claims %s", state)
	}
	s.tick()
	if s.state() != proto.WiFiProvisioningAPReady || s.nm.activeConnection() != apProfile {
		t.Fatalf("after the first step: %s, active %q\n%s", s.state(), s.nm.activeConnection(), s.log())
	}
	status := s.status()
	if status.State != proto.WiFiProvisioningAP || status.APSSID != simAPSSID || status.APAddress != "192.168.4.1" ||
		status.ProvisioningState != proto.WiFiProvisioningAPReady || status.SSID != "" || status.IPv4 != "" {
		t.Fatalf("an access point must be reported as one and never as a client connection: %#v", status)
	}
	ap, _ := s.nm.profile(apProfile)
	for key, want := range map[string]string{
		"802-11-wireless.mode": "ap", "ipv4.method": "shared", "connection.autoconnect": "no",
		"802-11-wireless-security.key-mgmt": "wpa-psk", "802-11-wireless-security.proto": "rsn",
		"ipv4.addresses": "192.168.4.1/24",
	} {
		if ap.settings[key] != want {
			t.Fatalf("access point profile has %s = %q, want %q", key, ap.settings[key], want)
		}
	}
	if ap.ssid != simAPSSID || len(ap.psk) < 16 || ap.psk != s.passphrase() {
		t.Fatalf("the access point is not protected by the device's own passphrase: ssid %q, %d characters", ap.ssid, len(ap.psk))
	}

	s.join(simHome, simHomePSK)
	if s.state() != proto.WiFiProvisioningJoined || s.nm.activeConnection() != defaultProfile {
		t.Fatalf("after a correct join: %s, active %q\n%s", s.state(), s.nm.activeConnection(), s.log())
	}
	saved, ok := s.nm.profile(defaultProfile)
	if !ok || saved.ssid != simHome || !saved.autoconnect {
		t.Fatalf("the joined network was not saved for automatic reconnection: %#v", saved)
	}
	status = s.status()
	if status.State != proto.WiFiConnected || status.SSID != simHome || status.APSSID != "" || status.ProvisioningState != proto.WiFiProvisioningJoined {
		t.Fatalf("status after joining: %#v", status)
	}
	// Stopping the access point comes before the client profile is created.
	calls := s.nm.recorded()
	down := indexOf(calls, func(c string) bool { return c == "connection down id "+apProfile })
	add := indexOf(calls, func(c string) bool {
		return strings.HasPrefix(c, "connection add type wifi ifname wlan0 con-name nsh-agent-")
	})
	if down < 0 || add < down {
		t.Fatalf("the access point must be stopped before the join starts: down %d, add %d", down, add)
	}

	// Reboot: a new agent over the same NetworkManager and state directory.
	before := len(s.nm.recorded())
	s.boot()
	s.tick()
	if s.state() != proto.WiFiProvisioningJoined || s.status().State != proto.WiFiConnected {
		t.Fatalf("after a reboot: %s %#v", s.state(), s.status())
	}
	for _, call := range s.nm.recorded()[before:] {
		if isAPCommand(call) {
			t.Fatalf("a device with a working saved network issued an access point command after reboot: %q", call)
		}
	}
	if !strings.Contains(s.log(), `target "`+simHome+`"`) || strings.Contains(s.log(), simNeighbour) {
		t.Fatalf("the log names the target network and no other:\n%s", s.log())
	}
	s.check(simHomePSK)
}

func TestWrongPassphraseBringsTheAccessPointBackAndSavesNothing(t *testing.T) {
	s := newSimulation(t, ProvisioningAPAuto)
	s.nm.inRange(simHome, simHomePSK)
	s.tick()
	s.join(simHome, simWrongPSK)

	if s.state() != proto.WiFiProvisioningAPReady || s.nm.activeConnection() != apProfile {
		t.Fatalf("after a wrong passphrase: %s, active %q\n%s", s.state(), s.nm.activeConnection(), s.log())
	}
	for _, name := range s.nm.profileNames() {
		if name != apProfile {
			t.Fatalf("a failed first join left the profile %q behind", name)
		}
	}
	status := s.status()
	if status.State != proto.WiFiProvisioningAP || status.FailureReason == "" || status.SavedSSID != "" {
		t.Fatalf("the setup page must be reachable again and say why the join failed: %#v", status)
	}
	// The same person can try again straight away, and succeed.
	s.join(simHome, simHomePSK)
	if s.state() != proto.WiFiProvisioningJoined {
		t.Fatalf("second attempt: %s\n%s", s.state(), s.log())
	}
	s.check(simHomePSK, simWrongPSK)
}

func TestWrongNewCredentialsGoBackToTheSavedNetworkWithoutAnAccessPoint(t *testing.T) {
	s := newSimulation(t, ProvisioningAPAuto)
	s.nm.inRange(simHome, simHomePSK)
	s.nm.inRange(simOther, simOtherPSK)
	s.nm.save(simHome, simHomePSK)
	s.nm.autoconnect()
	s.tick()
	if s.state() != proto.WiFiProvisioningJoined {
		t.Fatalf("boot with a reachable saved network: %s", s.state())
	}
	s.join(simOther, simWrongPSK)

	if s.state() != proto.WiFiProvisioningJoined || s.nm.activeConnection() != defaultProfile {
		t.Fatalf("after a failed switch: %s, active %q\n%s", s.state(), s.nm.activeConnection(), s.log())
	}
	if saved, _ := s.nm.profile(defaultProfile); saved.ssid != simHome {
		t.Fatalf("the saved network changed to %q", saved.ssid)
	}
	if n := s.nm.count(isAPCommand); n != 0 {
		t.Fatalf("%d access point command(s) were issued although the saved network was there", n)
	}
	s.run(2 * netbackend.SavedNetworkGrace)
	if n := s.nm.count(isAPCommand); n != 0 || s.state() != proto.WiFiProvisioningJoined {
		t.Fatalf("a device back on its network must stay there: %s, %d access point command(s)", s.state(), n)
	}
	s.check(simHomePSK, simWrongPSK)
}

func TestSavedNetworkUnreachableAtBootOffersTheAccessPointAndRejoinsWhenItReturns(t *testing.T) {
	s := newSimulation(t, ProvisioningAPAuto)
	s.nm.save(simHome, simHomePSK) // the router is switched off
	s.tick()
	status := s.status()
	if s.state() != proto.WiFiProvisioningSavedNetworkSearching || status.State != proto.WiFiNoConfig || status.SavedSSID != simHome {
		t.Fatalf("boot without the saved network in range: %s %#v", s.state(), status)
	}
	s.run(netbackend.SavedNetworkGrace - netbackend.SuperviseInterval)
	if n := s.nm.count(isAPCommand); n != 0 || s.state() != proto.WiFiProvisioningSavedNetworkSearching {
		t.Fatalf("the access point was offered before the grace period ended: %s, %d command(s)", s.state(), n)
	}
	s.run(netbackend.SuperviseInterval)
	if s.state() != proto.WiFiProvisioningAPReady || s.nm.activeConnection() != apProfile {
		t.Fatalf("after the grace period: %s, active %q\n%s", s.state(), s.nm.activeConnection(), s.log())
	}
	if !strings.Contains(s.log(), string(proto.WiFiProvisioningSavedNetworkLost)) {
		t.Fatalf("SAVED_NETWORK_LOST was not passed through:\n%s", s.log())
	}
	if saved, ok := s.nm.profile(defaultProfile); !ok || saved.ssid != simHome || saved.psk != simHomePSK {
		t.Fatal("offering the access point removed or changed the saved network")
	}
	if status := s.status(); status.State != proto.WiFiProvisioningAP || status.SavedSSID != simHome {
		t.Fatalf("status must show the access point and that a saved network is kept: %#v", status)
	}

	// The router comes back. The device notices at its next look and goes home.
	s.nm.inRange(simHome, simHomePSK)
	s.run(netbackend.SavedProbeInterval)
	if s.state() != proto.WiFiProvisioningJoined || s.nm.activeConnection() != defaultProfile {
		t.Fatalf("after the saved network returned: %s, active %q\n%s", s.state(), s.nm.activeConnection(), s.log())
	}
	if status := s.status(); status.State != proto.WiFiConnected || status.APSSID != "" {
		t.Fatalf("status after rejoining: %#v", status)
	}
	s.check(simHomePSK)
}

func TestARadioThatCannotScanAsAnAccessPointStillFindsItsWayHome(t *testing.T) {
	s := newSimulation(t, ProvisioningAPAuto)
	s.nm.scanFailsInAP = true
	s.nm.save(simHome, simHomePSK)
	s.tick()
	s.run(netbackend.SavedNetworkGrace)
	if s.state() != proto.WiFiProvisioningAPReady {
		t.Fatalf("expected the access point: %s", s.state())
	}
	// Still off at the first periodic attempt: the access point goes down for
	// the attempt and must come back, with the saved network kept.
	s.run(netbackend.SavedRejoinInterval)
	downs := s.nm.count(func(c string) bool { return c == "connection down id "+apProfile })
	if downs == 0 || s.state() != proto.WiFiProvisioningAPReady || s.nm.activeConnection() != apProfile {
		t.Fatalf("after a fruitless periodic attempt: %s, active %q, %d stop(s)\n%s", s.state(), s.nm.activeConnection(), downs, s.log())
	}
	if _, ok := s.nm.profile(defaultProfile); !ok {
		t.Fatal("a fruitless attempt removed the saved network")
	}
	// The router is back but cannot be seen from access point mode.
	s.nm.inRange(simHome, simHomePSK)
	s.run(netbackend.SavedRejoinInterval - netbackend.SavedProbeInterval)
	if s.state() != proto.WiFiProvisioningAPReady {
		t.Fatalf("the access point was taken down before the periodic attempt was due: %s", s.state())
	}
	s.run(2 * netbackend.SavedProbeInterval)
	if s.state() != proto.WiFiProvisioningJoined {
		t.Fatalf("the periodic attempt did not rejoin: %s\n%s", s.state(), s.log())
	}
	s.check(simHomePSK)
}

func TestSomeoneOnTheSetupPageKeepsTheAccessPointForABoundedTime(t *testing.T) {
	s := newSimulation(t, ProvisioningAPAuto)
	s.nm.scanFailsInAP = true
	s.nm.save(simHome, simHomePSK)
	s.tick()
	s.run(netbackend.SavedNetworkGrace)
	started := s.nm.count(func(c string) bool { return strings.Contains(c, "connection up id "+apProfile) })
	for elapsed := time.Duration(0); elapsed < netbackend.SavedRejoinInterval+netbackend.MaxRejoinDeferral-netbackend.SavedProbeInterval; elapsed += netbackend.SuperviseInterval {
		s.backend.NoteSetupActivity()
		s.advance(netbackend.SuperviseInterval)
		s.tick()
	}
	if n := s.nm.count(func(c string) bool { return c == "connection down id "+apProfile }); n != 0 {
		t.Fatalf("the access point was stopped %d time(s) under an active setup page", n)
	}
	for elapsed := time.Duration(0); elapsed < 2*netbackend.SavedProbeInterval; elapsed += netbackend.SuperviseInterval {
		s.backend.NoteSetupActivity()
		s.advance(netbackend.SuperviseInterval)
		s.tick()
	}
	restarted := s.nm.count(func(c string) bool { return strings.Contains(c, "connection up id "+apProfile) })
	if restarted != started+1 || s.state() != proto.WiFiProvisioningAPReady {
		t.Fatalf("a page left open must not keep the device off its network for ever: %d start(s), then %d; %s", started, restarted, s.state())
	}
	s.check(simHomePSK)
}

func TestForgetGoesBackToTheAccessPoint(t *testing.T) {
	s := newSimulation(t, ProvisioningAPAuto)
	s.nm.inRange(simHome, simHomePSK)
	s.tick()
	s.join(simHome, simHomePSK)

	status := s.forget()
	if _, ok := s.nm.profile(defaultProfile); ok {
		t.Fatal("forget left the saved network in place")
	}
	if s.state() != proto.WiFiProvisioningUnconfigured || status.State != proto.WiFiNoConfig || status.APSSID != "" {
		t.Fatalf("forget reports what is true at that moment, not the access point to come: %s %#v", s.state(), status)
	}
	s.run(netbackend.SuperviseInterval)
	if s.state() != proto.WiFiProvisioningAPReady || s.status().State != proto.WiFiProvisioningAP {
		t.Fatalf("after forget: %s %#v\n%s", s.state(), s.status(), s.log())
	}
	s.check(simHomePSK)

	// Forgetting while the access point is offered beside a lost network
	// keeps the access point up.
	lost := newSimulation(t, ProvisioningAPAuto)
	lost.nm.save(simHome, simHomePSK)
	lost.tick()
	lost.run(netbackend.SavedNetworkGrace)
	if status := lost.forget(); status.State != proto.WiFiProvisioningAP || lost.state() != proto.WiFiProvisioningAPReady {
		t.Fatalf("forget beside the access point: %s %#v", lost.state(), status)
	}
	if _, ok := lost.nm.profile(defaultProfile); ok || lost.nm.activeConnection() != apProfile {
		t.Fatal("forget must remove the saved network and nothing else")
	}
	lost.check(simHomePSK)
}

func TestAccessPointFailureIsVisibleAndRetriedWithBoundedBackoff(t *testing.T) {
	s := newSimulation(t, ProvisioningAPAuto)
	s.nm.apUpFails, s.nm.apUpEchoesSecret = true, true
	s.nm.inRange(simHome, simHomePSK)
	s.tick()

	status := s.status()
	if s.state() != proto.WiFiProvisioningAPFailed || status.ProvisioningState != proto.WiFiProvisioningAPFailed ||
		status.State != proto.WiFiNoConfig || !strings.Contains(status.ProvisioningReason, "does not support access point mode") {
		t.Fatalf("a failed access point must be a visible state with nmcli's reason: %s %#v", s.state(), status)
	}
	if strings.Contains(status.ProvisioningReason, s.passphrase()) || !strings.Contains(status.ProvisioningReason, "[redacted]") {
		t.Fatalf("the reason quotes the passphrase: %q", status.ProvisioningReason)
	}
	if !strings.Contains(s.log(), "USB management is unaffected") {
		t.Fatalf("the log does not say the USB path still works:\n%s", s.log())
	}
	if s.nm.activeConnection() != "" {
		t.Fatalf("a failed start left %q holding the radio", s.nm.activeConnection())
	}

	// Record when each attempt is made over three quarters of an hour.
	isStart := func(c string) bool { return strings.Contains(c, "connection up id "+apProfile) }
	var gaps []time.Duration
	last, attempts := time.Duration(0), s.nm.count(isStart)
	for elapsed := 5 * time.Second; elapsed <= 45*time.Minute; elapsed += 5 * time.Second {
		s.advance(5 * time.Second)
		s.tick()
		if now := s.nm.count(isStart); now != attempts {
			gaps, last, attempts = append(gaps, elapsed-last), elapsed, now
		}
	}
	want := []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	if len(gaps) < len(want) {
		t.Fatalf("only %d retries in 45 minutes: %v", len(gaps), gaps)
	}
	for index, gap := range gaps {
		expected := netbackend.APRetryMax
		if index < len(want) {
			expected = want[index]
		}
		if gap != expected {
			t.Fatalf("retry %d came after %s, want %s (all: %v)", index+1, gap, expected, gaps)
		}
	}

	// The provisioning path that does not use the radio as an access point -
	// the authenticated API reached over USB - still joins a network.
	s.join(simHome, simHomePSK)
	if s.state() != proto.WiFiProvisioningJoined || s.status().State != proto.WiFiConnected {
		t.Fatalf("joining while the access point is failed: %s\n%s", s.state(), s.log())
	}
	s.check(simHomePSK)

	// And a driver that starts working is picked up at the next retry.
	healed := newSimulation(t, ProvisioningAPAuto)
	healed.nm.apAddFails = true
	healed.tick()
	if status := healed.status(); status.ProvisioningState != proto.WiFiProvisioningAPFailed || !strings.Contains(status.ProvisioningReason, "refused the access point profile") {
		t.Fatalf("a refused profile: %#v", status)
	}
	healed.nm.apAddFails = false
	healed.run(netbackend.APRetryInitial + netbackend.SuperviseInterval)
	if healed.state() != proto.WiFiProvisioningAPReady || healed.status().ProvisioningReason != "" {
		t.Fatalf("after the fault cleared: %s %#v", healed.state(), healed.status())
	}
	healed.check()
}

func TestProvisioningAPOffNeverIssuesAnAccessPointCommand(t *testing.T) {
	for _, mode := range []string{ProvisioningAPOff, "", "anything-else"} {
		s := newSimulation(t, mode)
		s.nm.inRange(simHome, simHomePSK)

		finished := make(chan struct{})
		go func() { s.backend.Run(context.Background()); close(finished) }()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatalf("mode %q: the supervision loop runs although there is nothing to supervise", mode)
		}
		s.run(3 * netbackend.SavedNetworkGrace)
		if n := len(s.nm.recorded()); n != 0 {
			t.Fatalf("mode %q: supervision issued %d command(s)", mode, n)
		}
		if status := s.status(); status.ProvisioningState != proto.WiFiProvisioningDisabled || status.State != proto.WiFiNoConfig {
			t.Fatalf("mode %q: %#v", mode, status)
		}
		// Every path that would lead to the access point in auto mode.
		s.join(simHome, simWrongPSK)
		s.join(simHome, simHomePSK)
		s.nm.outOfRange(simHome)
		s.run(3 * netbackend.SavedNetworkGrace)
		s.forget()
		s.run(netbackend.SavedNetworkGrace)
		if n := s.nm.count(isAPCommand); n != 0 {
			t.Fatalf("mode %q: %d access point command(s) were issued", mode, n)
		}
		if _, err := os.Stat(filepath.Join(s.dir, apPassphraseFile)); !os.IsNotExist(err) {
			t.Fatalf("mode %q: an access point passphrase was created for an access point that is off", mode)
		}
		if s.state() != proto.WiFiProvisioningDisabled {
			t.Fatalf("mode %q: state %s", mode, s.state())
		}
		s.check(simHomePSK, simWrongPSK)
	}
}

func TestConcurrentRequestsDoNotInterleave(t *testing.T) {
	s := newSimulation(t, ProvisioningAPAuto)
	s.nm.inRange(simHome, simHomePSK)
	s.nm.inRange(simOther, simOtherPSK)
	s.nm.save(simHome, simHomePSK)
	s.nm.autoconnect()
	s.tick()

	s.nm.mu.Lock()
	s.nm.gate, s.nm.entered = make(chan struct{}), make(chan struct{})
	gate, entered := s.nm.gate, s.nm.entered
	s.nm.mu.Unlock()

	if _, err := s.backend.Connect(context.Background(), proto.WiFiConnectRequest{SSID: simOther, PSK: simOtherPSK, Security: proto.WiFiSecurityWPA2}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the join never reached its activation")
	}
	// The first join is in the middle of its command sequence.
	before := len(s.nm.recorded())
	_, err := s.backend.Connect(context.Background(), proto.WiFiConnectRequest{SSID: simHome, PSK: simHomePSK, Security: proto.WiFiSecurityWPA2})
	if proto.CodeOf(err) != proto.ErrorConflict {
		t.Fatalf("a second join during a join must get a definite busy answer: %v", err)
	}
	if _, err := s.backend.Forget(context.Background()); proto.CodeOf(err) != proto.ErrorConflict {
		t.Fatalf("a forget during a join must get a definite busy answer: %v", err)
	}
	s.advance(time.Hour)
	s.tick()
	if after := len(s.nm.recorded()); after != before {
		t.Fatalf("%d command(s) were issued into the middle of a join: %v", after-before, s.nm.recorded()[before:])
	}
	if status := s.status(); status.State != proto.WiFiConnecting || status.SSID != simOther || status.ProvisioningState != proto.WiFiProvisioningJoining {
		t.Fatalf("status during a join: %#v", status)
	}
	close(gate)
	s.settle()

	if s.state() != proto.WiFiProvisioningJoined || s.nm.activeConnection() != defaultProfile {
		t.Fatalf("after the join: %s, active %q\n%s", s.state(), s.nm.activeConnection(), s.log())
	}
	if saved, _ := s.nm.profile(defaultProfile); saved.ssid != simOther {
		t.Fatalf("the winner's network was not saved: %q", saved.ssid)
	}
	if n := s.nm.count(func(c string) bool { return strings.HasPrefix(c, "connection add ") }); n != 1 {
		t.Fatalf("%d profiles were created for one accepted join", n)
	}
	s.check(simHomePSK, simOtherPSK)
}

func TestWiFiGoingAwayAndComingBackIsReportedWhileTheUSBLinkIsLeftAlone(t *testing.T) {
	s := newSimulation(t, ProvisioningAPAuto)
	s.nm.inRange(simHome, simHomePSK)
	s.nm.save(simHome, simHomePSK)
	s.nm.autoconnect()
	s.tick()
	if status := s.status(); status.State != proto.WiFiConnected || status.IPv4 != "192.0.2.44" {
		t.Fatalf("connected status: %#v", status)
	}

	s.nm.outOfRange(simHome)
	s.run(netbackend.SuperviseInterval)
	status := s.status()
	if status.State != proto.WiFiNoConfig || status.IPv4 != "" || status.SSID != "" || status.SavedSSID != simHome ||
		status.ProvisioningState != proto.WiFiProvisioningSavedNetworkSearching {
		t.Fatalf("a lost network must not be reported as connected or keep its old address: %#v", status)
	}

	// Back within the grace period: NetworkManager reconnects by itself and
	// the access point is never involved.
	s.run(netbackend.SavedNetworkGrace / 2)
	s.nm.inRange(simHome, simHomePSK)
	if !s.nm.autoconnect() {
		t.Fatal("the fake NetworkManager did not reconnect")
	}
	s.run(netbackend.SuperviseInterval)
	if status := s.status(); status.State != proto.WiFiConnected || status.IPv4 != "192.0.2.44" || status.ProvisioningState != proto.WiFiProvisioningJoined {
		t.Fatalf("a returned network: %#v", status)
	}
	if n := s.nm.count(isAPCommand); n != 0 {
		t.Fatalf("a short outage started the access point (%d command(s))", n)
	}
	// check() asserts that no command named usb0, its profile or its subnet.
	s.check(simHomePSK)
}

func TestARestartedAgentAdoptsARunningAccessPoint(t *testing.T) {
	s := newSimulation(t, ProvisioningAPAuto)
	s.tick()
	passphrase := s.passphrase()
	starts := s.nm.count(func(c string) bool { return strings.Contains(c, "connection up id "+apProfile) })

	s.boot()
	if status := s.status(); status.State != proto.WiFiProvisioningAP || status.ProvisioningState != "" {
		t.Fatalf("before its first look the new agent reports the radio and no provisioning state: %#v", status)
	}
	s.tick()
	if s.state() != proto.WiFiProvisioningAPReady {
		t.Fatalf("after a restart: %s", s.state())
	}
	if again := s.nm.count(func(c string) bool { return strings.Contains(c, "connection up id "+apProfile) }); again != starts {
		t.Fatal("the access point was restarted under the phone that was using it")
	}
	if s.passphrase() != passphrase {
		t.Fatal("the passphrase changed across a restart")
	}
	s.check()
}

func TestNetworkManagerNotAnsweringLeavesTheStateAloneAndSaysSoOnce(t *testing.T) {
	s := newSimulation(t, ProvisioningAPAuto)
	s.nm.save(simHome, simHomePSK)
	s.nm.inRange(simHome, simHomePSK)
	s.nm.autoconnect()
	s.tick()
	s.nm.mu.Lock()
	s.nm.silent = true
	s.nm.mu.Unlock()
	s.run(time.Minute)
	if s.state() != proto.WiFiProvisioningJoined {
		t.Fatalf("an unanswered question changed the state to %s", s.state())
	}
	if _, err := s.backend.Status(context.Background()); proto.CodeOf(err) != proto.ErrorUnavailable {
		t.Fatalf("status with NetworkManager down must be an error, not a guess: %v", err)
	}
	if n := strings.Count(s.log(), "NetworkManager is not answering"); n != 1 {
		t.Fatalf("the outage was logged %d times", n)
	}
	s.nm.mu.Lock()
	s.nm.silent = false
	s.nm.mu.Unlock()
	s.run(netbackend.SuperviseInterval)
	if !strings.Contains(s.log(), "answering again") {
		t.Fatal("the recovery was not logged")
	}
}

func TestSetupPassphraseIsPerDeviceGeneratedAndPrivate(t *testing.T) {
	first := newSimulation(t, ProvisioningAPAuto)
	second := newSimulation(t, ProvisioningAPAuto)
	ssid, passphrase, err := first.backend.SetupAPCredential()
	if err != nil || ssid != simAPSSID {
		t.Fatalf("credential: %q %v", ssid, err)
	}
	if other := second.passphrase(); other == passphrase {
		t.Fatal("two devices generated the same passphrase: it is a default, not a secret")
	}
	if !validSetupPassphrase(passphrase) || len(passphrase) < 16 {
		t.Fatalf("passphrase has an unexpected shape (%d characters)", len(passphrase))
	}
	info, err := os.Stat(filepath.Join(first.dir, apPassphraseFile))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("passphrase file: %v %v", info, err)
	}
	first.boot()
	if again := first.passphrase(); again != passphrase {
		t.Fatal("the passphrase did not survive a restart")
	}
	// A state directory that cannot be written means no access point - never
	// an open one, never one with a built-in password.
	blocked := newSimulation(t, ProvisioningAPAuto)
	blocked.backend.stateDir = filepath.Join(blocked.dir, "missing\x00dir")
	blocked.tick()
	if blocked.state() != proto.WiFiProvisioningAPFailed {
		t.Fatalf("without a stored passphrase the state is %s", blocked.state())
	}
	if n := blocked.nm.count(func(c string) bool {
		return strings.Contains(c, "connection up id "+apProfile) || strings.Contains(c, "mode ap")
	}); n != 0 {
		t.Fatal("an access point was configured without a passphrase")
	}
	for _, name := range []string{"", "NSH-410-", "nodash"} {
		backend := New(Options{DeviceID: name})
		if got := backend.apSSID(); !strings.HasPrefix(got, "NasSimHub-") || len(got) > 32 {
			t.Fatalf("device id %q gives the access point name %q", name, got)
		}
	}
}

func TestScanMarksWhatIsNotVerifiedAndHidesNothing(t *testing.T) {
	backend := New(Options{Run: func(context.Context, ...string) (string, error) {
		return strings.Join([]string{
			"Plain24:70:WPA2:6",
			"Mixed24:70:WPA2 WPA3:11",
			"Only5:70:WPA2:36",
			"PureSAE:70:WPA3:1",
			"Corp:70:WPA2 802.1X:1",
			"Old:70:WPA1:1",
			"Cafe:70::1",
			"Dual:90:WPA2:149",
			"Dual:40:WPA2:6",
		}, "\n") + "\n", nil
	}})
	result, err := backend.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]proto.WiFiNetwork{}
	for _, network := range result.Networks {
		got[network.SSID] = network
	}
	for ssid, want := range map[string]proto.WiFiSupport{
		"Plain24": proto.WiFiSupportVerified, "Mixed24": proto.WiFiSupportVerified,
		"Only5": proto.WiFiSupportUnverified, "PureSAE": proto.WiFiSupportUnverified,
		"Corp": proto.WiFiSupportUnsupported, "Old": proto.WiFiSupportUnverified,
		"Cafe": proto.WiFiSupportUnverified, "Dual": proto.WiFiSupportVerified,
	} {
		network, listed := got[ssid]
		if !listed {
			t.Fatalf("%s was hidden from the scan result", ssid)
		}
		if network.Support != want || network.SupportReason == "" {
			t.Fatalf("%s: support %q (%q), want %q", ssid, network.Support, network.SupportReason, want)
		}
	}
	if dual := got["Dual"]; dual.Channel != 6 || !strings.Contains(dual.SupportReason, "also seen") {
		t.Fatalf("a name on both bands must list the verified radio and say the other exists: %#v", dual)
	}
	encoded, _ := json.Marshal(got["PureSAE"])
	if !strings.Contains(string(encoded), `"support":"unverified"`) || !strings.Contains(string(encoded), `"support_reason":`) {
		t.Fatalf("the hint is not in the document: %s", encoded)
	}
}

func TestScanWhileTheAccessPointIsUpFallsBackToTheListTakenBeforeIt(t *testing.T) {
	s := newSimulation(t, ProvisioningAPAuto)
	s.nm.scanFailsInAP = true
	s.nm.inRange(simHome, simHomePSK)
	s.tick()
	taken := s.backend.now()
	s.advance(time.Minute)
	result, err := s.backend.Scan(context.Background())
	if err != nil || !result.FromCache || len(result.Networks) != 1 || result.Networks[0].SSID != simHome || !result.ScannedAt.Equal(taken) {
		t.Fatalf("scan in access point mode: %#v %v", result, err)
	}
	s.check()
}
