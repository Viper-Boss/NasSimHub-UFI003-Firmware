package networkmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/netbackend"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// fakeNM is a NetworkManager with one Wi-Fi radio and a USB gadget link, driven
// through the same nmcli argument lists the backend issues on a device. It is
// a model written from nmcli's documented behaviour, not a recording of the
// UFI003: what it proves is the backend's logic, never the hardware's.
type fakeNM struct {
	mu       sync.Mutex
	profiles map[string]*fakeProfile
	// active is the connection active on wlan0, or empty.
	active string
	// air is the networks in range: name to what they accept.
	air map[string]fakeNetwork
	// calls is every command, joined; argv keeps the separate arguments.
	calls []string
	argv  [][]string

	// apAddFails and apUpFails make the access point fail to be created or
	// started. apUpEchoesSecret makes the failure quote the passphrase, which
	// nmcli has no reason to do and the backend must survive anyway.
	apAddFails       bool
	apUpFails        bool
	apUpEchoesSecret bool
	// scanFailsInAP models a radio that cannot scan while it is an access
	// point. silent makes NetworkManager not answer at all.
	scanFailsInAP bool
	silent        bool
	// gate, when set, holds a client activation until it is closed; entered
	// is closed when the activation is reached.
	gate    chan struct{}
	entered chan struct{}
}

type fakeProfile struct {
	ssid        string
	accessPoint bool
	autoconnect bool
	keyMgmt     string
	psk         string
	settings    map[string]string
}

type fakeNetwork struct {
	psk      string
	security string
	signal   int
	channel  int
}

func newFakeNM() *fakeNM {
	return &fakeNM{profiles: map[string]*fakeProfile{}, air: map[string]fakeNetwork{}}
}

const (
	// Obviously synthetic values; none is a real network or credential.
	simHome      = "Example-Home"
	simHomePSK   = "synthetic-correct-passphrase"
	simWrongPSK  = "synthetic-wrong-passphrase"
	simOther     = "Example-Other"
	simOtherPSK  = "synthetic-other-passphrase"
	simNeighbour = "Example-Neighbour"
	simDeviceID  = "NSH-410-A83F29"
	simAPSSID    = "NasSimHub-A83F29"
)

func (f *fakeNM) inRange(ssid, psk string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.air[ssid] = fakeNetwork{psk: psk, security: "WPA2", signal: 70, channel: 6}
}

func (f *fakeNM) outOfRange(ssid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.air, ssid)
	if profile, ok := f.profiles[f.active]; ok && !profile.accessPoint && profile.ssid == ssid {
		f.active = ""
	}
}

// save puts a client profile in place as an earlier successful join left it.
func (f *fakeNM) save(ssid, psk string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.profiles[defaultProfile] = &fakeProfile{ssid: ssid, psk: psk, keyMgmt: "wpa-psk", autoconnect: true, settings: map[string]string{}}
}

// autoconnect is NetworkManager joining the saved network by itself, which it
// does when the radio is free and the profile allows it.
func (f *fakeNM) autoconnect() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.active != "" {
		return false
	}
	for name, profile := range f.profiles {
		if profile.accessPoint || !profile.autoconnect {
			continue
		}
		if network, ok := f.air[profile.ssid]; ok && network.psk == profile.psk {
			f.active = name
			return true
		}
	}
	return false
}

func (f *fakeNM) activeConnection() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active
}

func (f *fakeNM) profile(name string) (fakeProfile, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	profile, ok := f.profiles[name]
	if !ok {
		return fakeProfile{}, false
	}
	return *profile, true
}

func (f *fakeNM) profileNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(f.profiles))
	for name := range f.profiles {
		names = append(names, name)
	}
	return names
}

func (f *fakeNM) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeNM) count(match func(string) bool) int {
	total := 0
	for _, call := range f.recorded() {
		if match(call) {
			total++
		}
	}
	return total
}

func nmcliFailure(stderr string) error {
	// A zero ExitError reports exit code -1, which is enough for the
	// backend's "what did nmcli say" path.
	return &exec.ExitError{Stderr: []byte(stderr)}
}

func after(arguments []string, key string) string {
	for index, argument := range arguments {
		if argument == key && index+1 < len(arguments) {
			return arguments[index+1]
		}
	}
	return ""
}

func (f *fakeNM) run(_ context.Context, arguments ...string) (string, error) {
	joined := strings.Join(arguments, " ")
	f.mu.Lock()
	f.calls = append(f.calls, joined)
	f.argv = append(f.argv, append([]string(nil), arguments...))
	if f.silent {
		f.mu.Unlock()
		return "", errors.New("NetworkManager is not running")
	}
	defer f.mu.Unlock()

	switch {
	case strings.HasSuffix(joined, "DEVICE,TYPE,STATE,CONNECTION device"):
		// The USB gadget link is always there and never this package's concern.
		wifi := "wlan0:wifi:disconnected:"
		if f.active != "" {
			wifi = "wlan0:wifi:connected:" + f.active
		}
		return "usb0:ethernet:connected:usb-gadget\n" + wifi + "\nlo:loopback:unmanaged:\n", nil

	case strings.Contains(joined, "802-11-wireless.ssid connection show "):
		profile, ok := f.profiles[arguments[len(arguments)-1]]
		if !ok {
			return "", nmcliFailure("Error: no such connection profile.")
		}
		return profile.ssid + "\n", nil

	case strings.Contains(joined, "IP4.ADDRESS device show"):
		profile, ok := f.profiles[f.active]
		switch {
		case !ok:
			return "", nil
		case profile.accessPoint:
			return profile.settings["ipv4.addresses"] + "\n", nil
		default:
			return "192.0.2.44/24\n", nil
		}

	case strings.Contains(joined, "device wifi list"):
		if profile, ok := f.profiles[f.active]; ok && profile.accessPoint && f.scanFailsInAP {
			return "", nmcliFailure("Error: Scanning not allowed while in AP mode.")
		}
		var rows strings.Builder
		for ssid, network := range f.air {
			if strings.Contains(joined, "SSID,SIGNAL,SECURITY,CHAN") {
				fmt.Fprintf(&rows, "%s:%d:%s:%d\n", ssid, network.signal, network.security, network.channel)
			} else {
				fmt.Fprintf(&rows, "%s:%d\n", ssid, network.signal)
			}
		}
		return rows.String(), nil

	case strings.HasPrefix(joined, "connection add "):
		name := after(arguments, "con-name")
		profile := &fakeProfile{ssid: after(arguments, "ssid"), settings: map[string]string{}}
		for index := 0; index+1 < len(arguments); index++ {
			if strings.Contains(arguments[index], ".") {
				profile.settings[arguments[index]] = arguments[index+1]
			}
		}
		profile.accessPoint = profile.settings["802-11-wireless.mode"] == "ap"
		profile.autoconnect = profile.settings["connection.autoconnect"] != "no"
		profile.keyMgmt = profile.settings["802-11-wireless-security.key-mgmt"]
		if profile.accessPoint && f.apAddFails {
			return "", nmcliFailure("Error: Failed to add connection: not authorized.")
		}
		if _, exists := f.profiles[name]; exists {
			return "", nmcliFailure("Error: a connection with that name exists.")
		}
		f.profiles[name] = profile
		return "", nil

	case strings.HasPrefix(joined, "connection modify id "):
		name, key, value := arguments[3], arguments[4], arguments[5]
		profile, ok := f.profiles[name]
		if !ok {
			return "", nmcliFailure("Error: unknown connection.")
		}
		switch key {
		case "connection.id":
			if _, taken := f.profiles[value]; taken {
				return "", nmcliFailure("Error: a connection with that name exists.")
			}
			delete(f.profiles, name)
			f.profiles[value] = profile
			if f.active == name {
				f.active = value
			}
		case "connection.autoconnect":
			profile.autoconnect = value == "yes"
		case "802-11-wireless-security.key-mgmt":
			profile.keyMgmt = value
		}
		return "", nil

	case strings.Contains(joined, "connection up id "):
		name := after(arguments, "id")
		profile, ok := f.profiles[name]
		if !ok {
			return "", nmcliFailure("Error: unknown connection.")
		}
		secret := ""
		if path := after(arguments, "passwd-file"); path != "" {
			raw, err := os.ReadFile(path)
			if err != nil {
				return "", nmcliFailure("Error: the password file could not be read.")
			}
			secret = strings.TrimSpace(strings.TrimPrefix(string(raw), "802-11-wireless-security.psk:"))
		}
		if profile.accessPoint {
			if f.apUpFails {
				detail := "Error: Connection activation failed: the device does not support access point mode."
				if f.apUpEchoesSecret {
					detail += " key=" + secret
				}
				return "", nmcliFailure(detail)
			}
			if len(secret) < 8 {
				return "", nmcliFailure("Error: Connection activation failed: no secrets were provided.")
			}
			profile.psk = secret
			f.active = name
			return "", nil
		}
		if f.gate != nil && name != defaultProfile {
			gate, entered := f.gate, f.entered
			f.mu.Unlock()
			close(entered)
			<-gate
			f.mu.Lock()
		}
		if secret != "" {
			profile.psk = secret
		}
		// Activating a profile takes the radio away from whatever had it.
		f.active = ""
		network, visible := f.air[profile.ssid]
		if !visible || network.psk != profile.psk {
			return "", nmcliFailure("Error: Connection activation failed: secrets were required, but not provided.")
		}
		f.active = name
		return "", nil

	case strings.HasPrefix(joined, "connection down id "):
		name := arguments[3]
		if f.active != name {
			return "", nmcliFailure("Error: the connection is not active.")
		}
		f.active = ""
		return "", nil

	case strings.HasPrefix(joined, "connection delete id "):
		name := arguments[3]
		if _, ok := f.profiles[name]; !ok {
			return "", nmcliFailure("Error: unknown connection.")
		}
		delete(f.profiles, name)
		if f.active == name {
			f.active = ""
		}
		return "", nil
	}
	return "", errors.New("fakeNM: unexpected command: " + joined)
}

// simulation is one device: a fake NetworkManager, a state directory and a
// clock that outlive any one agent process, and the agent's backend.
type simulation struct {
	t       *testing.T
	nm      *fakeNM
	dir     string
	mode    string
	backend *Backend

	mu      sync.Mutex
	now     time.Time
	logs    []string
	forgets int
}

func newSimulation(t *testing.T, mode string) *simulation {
	t.Helper()
	s := &simulation{t: t, nm: newFakeNM(), dir: t.TempDir(), mode: mode, now: time.Unix(1_700_000_000, 0)}
	s.boot()
	return s
}

// boot starts a new agent over the same NetworkManager and state directory,
// which is what a reboot or an agent restart is from the backend's side.
func (s *simulation) boot() {
	s.backend = New(Options{
		StateDir: s.dir, DeviceID: simDeviceID, ProvisioningAP: s.mode, Run: s.nm.run,
		Now: func() time.Time {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.now
		},
		Logf: func(format string, arguments ...any) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.logs = append(s.logs, fmt.Sprintf(format, arguments...))
		},
	})
}

func (s *simulation) advance(duration time.Duration) {
	s.mu.Lock()
	s.now = s.now.Add(duration)
	s.mu.Unlock()
}

func (s *simulation) tick() { s.backend.Tick(context.Background()) }

// run advances the clock in supervision steps, as the agent's ticker would.
func (s *simulation) run(duration time.Duration) {
	for elapsed := time.Duration(0); elapsed < duration; elapsed += netbackend.SuperviseInterval {
		s.advance(netbackend.SuperviseInterval)
		s.tick()
	}
}

func (s *simulation) state() proto.WiFiProvisioningState {
	state, _ := s.backend.machine.State()
	return state
}

func (s *simulation) status() proto.WiFiStatus {
	s.t.Helper()
	status, err := s.backend.Status(context.Background())
	if err != nil {
		s.t.Fatalf("status: %v", err)
	}
	return status
}

func (s *simulation) log() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.logs, "\n")
}

// settle waits for an accepted join to reach its verdict and for everything
// that follows it under the operation lock - a restore, an access point start.
func (s *simulation) settle() {
	s.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.backend.mu.Lock()
		settled := s.backend.state != proto.WiFiConnecting
		s.backend.mu.Unlock()
		if settled {
			break
		}
		if time.Now().After(deadline) {
			s.t.Fatal("the join did not settle")
		}
		time.Sleep(time.Millisecond)
	}
	s.backend.opMu.Lock()
	s.backend.opMu.Unlock()
}

func (s *simulation) join(ssid, psk string) {
	s.t.Helper()
	status, err := s.backend.Connect(context.Background(), proto.WiFiConnectRequest{SSID: ssid, PSK: psk, Security: proto.WiFiSecurityWPA2})
	if err != nil || status.State != proto.WiFiConnecting {
		s.t.Fatalf("connect: %#v %v", status, err)
	}
	s.settle()
}

func (s *simulation) forget() proto.WiFiStatus {
	s.t.Helper()
	s.forgets++
	status, err := s.backend.Forget(context.Background())
	if err != nil {
		s.t.Fatalf("forget: %v", err)
	}
	return status
}

func (s *simulation) passphrase() string {
	s.t.Helper()
	_, passphrase, err := s.backend.SetupAPCredential()
	if err != nil {
		s.t.Fatalf("setup access point credential: %v", err)
	}
	return passphrase
}

func isAPCommand(call string) bool {
	return strings.Contains(call, apProfile) || strings.Contains(call, "802-11-wireless.mode ap")
}

// check asserts what must hold at the end of every scenario, whatever it did:
// the saved network is removed only by a forget, nothing names the USB link,
// the access point's commands never name the client profile, and no secret is
// anywhere it can be read.
func (s *simulation) check(secrets ...string) {
	s.t.Helper()
	deletes := 0
	for _, call := range s.nm.recorded() {
		if call == "connection delete id "+defaultProfile {
			deletes++
		}
		if strings.Contains(call, "connection down id "+defaultProfile) {
			s.t.Fatalf("the saved network was taken down: %q", call)
		}
		if strings.Contains(call, "usb0") || strings.Contains(call, "usb-gadget") || strings.Contains(call, "10.55.0.") {
			s.t.Fatalf("a command names the USB link: %q", call)
		}
		if isAPCommand(call) && (strings.Contains(call, "id "+defaultProfile) || strings.Contains(call, previousProfile)) {
			s.t.Fatalf("an access point command names the saved network: %q", call)
		}
	}
	if deletes > s.forgets {
		s.t.Fatalf("the saved network was deleted %d time(s) with %d forget request(s):\n%s", deletes, s.forgets, strings.Join(s.nm.recorded(), "\n"))
	}
	s.nm.mu.Lock()
	argv := append([][]string(nil), s.nm.argv...)
	s.nm.mu.Unlock()
	for _, arguments := range argv {
		for index, argument := range arguments {
			if argument == "ifname" && arguments[index+1] != defaultDevice {
				s.t.Fatalf("a command addresses another interface: %q", arguments)
			}
		}
	}
	if stored, err := os.ReadFile(s.dir + "/" + apPassphraseFile); err == nil {
		secrets = append(secrets, strings.TrimSpace(string(stored)))
	}
	status, statusErr := s.backend.Status(context.Background())
	document, _ := json.Marshal(status)
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		for _, arguments := range argv {
			if strings.Contains(strings.Join(arguments, "\x00"), secret) {
				s.t.Fatalf("a secret is in a command line: %q", arguments[:2])
			}
		}
		if strings.Contains(s.log(), secret) {
			s.t.Fatal("a secret is in the log")
		}
		if strings.Contains(string(document), secret) || (statusErr != nil && strings.Contains(statusErr.Error(), secret)) {
			s.t.Fatal("a secret is in the status document")
		}
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		s.t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".wifi-secret-") || strings.HasPrefix(entry.Name(), ".setup-ap-") {
			s.t.Fatalf("a temporary secret file was left behind: %s", entry.Name())
		}
	}
}
