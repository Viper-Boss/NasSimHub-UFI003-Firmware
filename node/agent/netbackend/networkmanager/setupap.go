package networkmanager

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/netbackend"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// The setup access point.
//
// The UFI003 has one Wi-Fi radio, so it is either a client of the owner's
// network or the access point a phone joins to configure it - never both. This
// file is the access point half and the supervision step that decides, from
// the table in netbackend/statemachine.go, which half the radio is.
//
// Three rules are kept by construction rather than by care:
//
//   - Every command here names the access point's own profile and the Wi-Fi
//     device. None names the saved client profile, and none names another
//     interface, so bringing the access point up or down cannot disturb the
//     saved network or the USB link that is the way back in.
//   - The access point is never open and never has a built-in password. Its
//     passphrase is generated on the device at first use and reaches nmcli
//     through a file, like the client credential, never through argv.
//   - Whether this chipset and driver can be an access point at all is not
//     known from here. Every failure to start it becomes AP_FAILED with a
//     reason anyone reading the status can see, and nothing else depends on
//     it: management over USB does not go through the radio.

const (
	// ProvisioningAPAuto and ProvisioningAPOff are the values of the
	// provisioning_ap configuration key.
	ProvisioningAPAuto = "auto"
	ProvisioningAPOff  = "off"

	// apProfile is the NetworkManager profile of the setup access point. It
	// is not the saved client profile and shares no prefix with the temporary
	// join profiles, so no command aimed at one can match another.
	apProfile = "nassimhub-setup-ap"
	// apAddress is the address the setup page is served on; the provisioning
	// listener and its source-address check are built around this subnet.
	apAddress = "192.168.4.1"
	apPrefix  = "/24"
	// apPassphraseFile holds the access point passphrase in the state
	// directory, mode 0600, beside the device identity.
	apPassphraseFile = "setup-ap-passphrase"
	// apActivationWait is how long nmcli waits for NetworkManager to report
	// the access point active. Starting an access point involves no peer, so
	// a start that has not finished in this time has failed.
	apActivationWait = "30"
)

// apState is what the supervision step remembers between runs. It is guarded
// by Backend.mu.
type apState struct {
	// failure is why the last start failed; attempts and retryAt are the
	// backoff. All three are cleared when a start succeeds.
	failure  string
	attempts int
	retryAt  time.Time
	// readyAt is when the access point last came up. probedAt, rejoinDue and
	// rejoinNotBefore schedule the looks for, and attempts on, a saved
	// network that was lost.
	readyAt         time.Time
	probedAt        time.Time
	rejoinDue       time.Time
	rejoinNotBefore time.Time
	// activity is when the setup page or a scan last used the backend.
	activity time.Time
	// scanCache is the scan taken just before the access point started.
	scanCache *proto.WiFiScanResult
	// unavailable remembers that NetworkManager did not answer, so the fact
	// is logged when it changes rather than every ten seconds.
	unavailable bool
}

// observation is one look at NetworkManager.
type observation struct {
	// client: the radio is associated to a network as a station.
	client bool
	// ap: the setup access point is the active connection.
	ap bool
	// saved: the saved client profile exists.
	saved     bool
	savedSSID string
}

func (b *Backend) observe(ctx context.Context) (observation, error) {
	rows, err := b.run(ctx, "-t", "--escape", "yes", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device")
	if err != nil {
		return observation{}, err
	}
	var seen observation
	found := false
	for _, line := range nonemptyLines(rows) {
		fields := splitEscaped(line, ':')
		if len(fields) < 4 || fields[0] != b.device {
			continue
		}
		found = true
		if fields[2] == "connected" && fields[3] != "" && fields[3] != "--" {
			seen.ap = fields[3] == apProfile
			seen.client = !seen.ap
		}
		break
	}
	if !found {
		return observation{}, errors.New("the Wi-Fi device is not managed by NetworkManager")
	}
	if ssid, err := b.connectionSSID(ctx, defaultProfile); err == nil && ssid != "" {
		seen.saved, seen.savedSSID = true, ssid
	}
	return seen, nil
}

// Run supervises the radio until ctx is cancelled. With the access point
// switched off it returns at once: there is nothing to supervise, and a loop
// that only polled would be commands issued for no decision.
//
// The access point is deliberately left as it is on return. An agent that
// restarts for an update finds it still up and carries on, instead of dropping
// the phone that was in the middle of setting the device up.
func (b *Backend) Run(ctx context.Context) {
	if b.apMode != ProvisioningAPAuto {
		return
	}
	ticker := time.NewTicker(netbackend.SuperviseInterval)
	defer ticker.Stop()
	b.Tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.Tick(ctx)
		}
	}
}

// Tick is one supervision step: look at the radio, and take whichever edge of
// the state machine the observation and the clock call for. It is exported so
// a test can drive the machine with an injected clock and no timer.
func (b *Backend) Tick(ctx context.Context) {
	if b.apMode != ProvisioningAPAuto {
		return
	}
	// A join or a forget is running, or a join has been accepted and is about
	// to run. It ends in a definite state by itself, and this step would only
	// be reading the radio in the middle of it - or starting an access point
	// the join would stop a moment later.
	b.mu.Lock()
	joining := b.state == proto.WiFiConnecting
	b.mu.Unlock()
	if joining || !b.opMu.TryLock() {
		return
	}
	defer b.opMu.Unlock()

	seen, err := b.observe(ctx)
	b.mu.Lock()
	changed := b.ap.unavailable != (err != nil)
	b.ap.unavailable = err != nil
	b.mu.Unlock()
	if err != nil {
		if changed {
			b.logf("provisioning: NetworkManager is not answering; the state is left as it is")
		}
		return
	}
	if changed {
		b.logf("provisioning: NetworkManager is answering again")
	}

	now := b.now()
	state, since := b.machine.State()
	if state == "" {
		switch {
		case seen.client:
			state = proto.WiFiProvisioningJoined
		case seen.ap:
			// The agent restarted while the access point was up.
			state = proto.WiFiProvisioningAPReady
			b.markAPReady(now)
		case seen.saved:
			state = proto.WiFiProvisioningSavedNetworkSearching
		default:
			state = proto.WiFiProvisioningUnconfigured
		}
		b.machine.Start(state, "")
		state, since = b.machine.State()
	}

	switch state {
	case proto.WiFiProvisioningUnconfigured:
		switch {
		case seen.client:
			b.fire(netbackend.EventLinkUp, "")
		case seen.saved:
			b.fire(netbackend.EventSavedNetworkFound, "")
		default:
			b.startAP(ctx, netbackend.EventAPStart)
		}

	case proto.WiFiProvisioningAPReady:
		switch {
		case seen.client:
			b.fire(netbackend.EventLinkUp, "")
		case !seen.ap:
			b.apFailed(netbackend.EventAPError, "the access point stopped unexpectedly")
		case seen.saved:
			b.considerRejoin(ctx, seen.savedSSID)
		}

	case proto.WiFiProvisioningAPFailed:
		b.mu.Lock()
		retryAt := b.ap.retryAt
		b.mu.Unlock()
		switch {
		case seen.client:
			b.fire(netbackend.EventLinkUp, "")
		case seen.ap:
			// nmcli gave up waiting but NetworkManager finished the start.
			b.fire(netbackend.EventAPUp, "")
			b.markAPReady(now)
		case !now.Before(retryAt):
			b.startAP(ctx, netbackend.EventAPRetry)
		}

	case proto.WiFiProvisioningJoined:
		if !seen.client {
			b.fire(netbackend.EventLinkLost, "")
		}

	case proto.WiFiProvisioningSavedNetworkSearching:
		switch {
		case seen.client:
			b.fire(netbackend.EventLinkUp, "")
		case !seen.saved:
			b.fire(netbackend.EventSavedProfileGone, "")
		case now.Sub(since) >= netbackend.SavedNetworkGrace:
			b.fire(netbackend.EventSavedNetworkUnreachable, "the saved network is kept")
			b.startAP(ctx, netbackend.EventAPStart)
		}

	case proto.WiFiProvisioningSavedNetworkLost:
		switch {
		case seen.client:
			b.fire(netbackend.EventLinkUp, "")
		case !seen.saved:
			b.fire(netbackend.EventSavedProfileGone, "")
		default:
			b.startAP(ctx, netbackend.EventAPStart)
		}

	case proto.WiFiProvisioningAPStarting, proto.WiFiProvisioningJoining, proto.WiFiProvisioningJoinFailed:
		// These last only while an operation holds opMu, which this step
		// could not have taken. Reaching here means an operation was cut
		// short; resolve from what the radio is actually doing.
		b.resolveInterrupted(ctx, state, seen)
	}
}

// resolveInterrupted leaves a transient state that no operation is driving.
func (b *Backend) resolveInterrupted(ctx context.Context, state proto.WiFiProvisioningState, seen observation) {
	switch state {
	case proto.WiFiProvisioningAPStarting:
		if seen.ap {
			b.fire(netbackend.EventAPUp, "")
			b.markAPReady(b.now())
			return
		}
		b.apFailed(netbackend.EventAPError, "the access point start was interrupted")
	case proto.WiFiProvisioningJoining:
		if seen.client {
			b.fire(netbackend.EventJoinOK, "")
			return
		}
		b.fire(netbackend.EventJoinError, "the join was interrupted")
		b.resolveInterrupted(ctx, proto.WiFiProvisioningJoinFailed, seen)
	case proto.WiFiProvisioningJoinFailed:
		switch {
		case seen.client:
			b.fire(netbackend.EventSavedNetworkRestored, "")
		case seen.saved:
			b.fire(netbackend.EventRestoreFailed, "")
		default:
			b.startAP(ctx, netbackend.EventNoSavedNetwork)
		}
	}
}

// fire takes an edge when the machine is running. With the access point
// switched off, or before the radio has been looked at, there is no machine
// state to move and the legacy Wi-Fi state alone describes the device.
func (b *Backend) fire(event netbackend.Event, detail string) bool {
	if !b.machineActive() {
		return false
	}
	_, err := b.machine.Fire(event, detail)
	return err == nil
}

func (b *Backend) machineActive() bool {
	state, _ := b.machine.State()
	return state != "" && state != proto.WiFiProvisioningDisabled
}

// NoteSetupActivity records that someone is using the setup page, so the
// access point is not taken down under them for a rejoin attempt.
func (b *Backend) NoteSetupActivity() {
	b.mu.Lock()
	b.ap.activity = b.now()
	b.mu.Unlock()
}

// beginJoin records the join and, when the access point is up, stops it. It
// reports whether the access point was up, which decides where a failed join
// goes back to.
func (b *Backend) beginJoin(ctx context.Context, ssid string) bool {
	if !b.machineActive() {
		return false
	}
	state, _ := b.machine.State()
	b.fire(netbackend.EventJoinRequested, fmt.Sprintf("target %q", ssid))
	if state != proto.WiFiProvisioningAPReady {
		return false
	}
	b.stopAP(ctx)
	return true
}

// joinFailed records a failed join and puts the radio back where it was.
//
// restore says there may be a saved network to go back to, and it is tried
// here. apWasUp says the access point was serving before the attempt: if the
// saved network cannot be reached either, the person on the setup page gets
// the access point back now rather than after the grace period, because they
// are evidently there.
func (b *Backend) joinFailed(reason string, restore, apWasUp bool) {
	tracked := b.fire(netbackend.EventJoinError, reason)
	restored := restore && b.restorePrevious(defaultProfile)
	// The failure becomes visible only now, so that whoever reads "failed"
	// reads it about a radio that has already been sent back.
	b.fail(reason)
	if !tracked {
		return
	}
	observeContext, cancelObserve := context.WithTimeout(context.Background(), netbackend.ObserveTimeout)
	seen, err := b.observe(observeContext)
	cancelObserve()
	switch {
	case restored || (err == nil && seen.client):
		b.fire(netbackend.EventSavedNetworkRestored, "")
	case err == nil && !seen.saved:
		b.startAP(context.Background(), netbackend.EventNoSavedNetwork)
	case err == nil && apWasUp:
		b.fire(netbackend.EventSavedNetworkUnreachable, "the saved network is kept")
		b.startAP(context.Background(), netbackend.EventAPStart)
	default:
		// Also when NetworkManager did not answer: nothing is known, so
		// nothing is started, and the supervision step sorts it out.
		b.fire(netbackend.EventRestoreFailed, "")
	}
}

// startAP brings the setup access point up. The caller holds opMu. event is
// the edge into AP_STARTING; the function always leaves that state, to
// AP_READY or to AP_FAILED with a reason.
func (b *Backend) startAP(ctx context.Context, event netbackend.Event) {
	if !b.fire(event, "") {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, netbackend.APStartTimeout)
	defer cancel()

	// The last look at the neighbourhood before the radio stops being able
	// to look. It is best effort: an empty list only means the setup page
	// asks for the network name to be typed.
	if result, err := b.scan(ctx); err == nil {
		b.mu.Lock()
		b.ap.scanCache = &result
		b.mu.Unlock()
	}

	passphrase, err := b.setupAPPassphrase()
	if err != nil {
		b.apFailed(netbackend.EventAPError, "could not prepare the access point passphrase in the state directory")
		return
	}
	passwordFile, err := b.writePasswordFile(passphrase)
	if err != nil {
		b.apFailed(netbackend.EventAPError, "could not prepare the access point passphrase in the state directory")
		return
	}
	defer os.Remove(passwordFile)

	// The profile is rebuilt on every start, so it is always what this
	// version of the agent means by it. Deleting it touches nothing else, and
	// a missing profile is the normal case on first boot.
	_, _ = b.run(ctx, "connection", "delete", "id", apProfile)
	if _, err := b.run(ctx, "connection", "add", "type", "wifi", "ifname", b.device, "con-name", apProfile,
		"ssid", b.apSSID(),
		// Never started by NetworkManager on its own: the state machine
		// decides when the radio is an access point.
		"connection.autoconnect", "no",
		"802-11-wireless.mode", "ap",
		// 2.4 GHz: the band every phone can see and the only one verified
		// on this hardware.
		"802-11-wireless.band", "bg",
		// WPA2-PSK with CCMP only. An open access point would hand the
		// setup page to anyone in radio range.
		"802-11-wireless-security.key-mgmt", "wpa-psk",
		"802-11-wireless-security.proto", "rsn",
		"802-11-wireless-security.pairwise", "ccmp",
		"802-11-wireless-security.group", "ccmp",
		// "shared" makes NetworkManager run DHCP for the phone that joins.
		"ipv4.method", "shared",
		"ipv4.addresses", apAddress+apPrefix,
		"ipv6.method", "disabled",
	); err != nil {
		b.apFailed(netbackend.EventAPError, "NetworkManager refused the access point profile"+describeFailure(err, passphrase))
		return
	}
	if _, err := b.run(ctx, "--wait", apActivationWait, "connection", "up", "id", apProfile, "ifname", b.device, "passwd-file", passwordFile); err != nil {
		// Make sure a half-started access point is not left holding the
		// radio: the saved network, if there is one, needs it back.
		b.stopAP(ctx)
		b.apFailed(netbackend.EventAPError, "NetworkManager could not start the access point"+describeFailure(err, passphrase))
		return
	}
	b.fire(netbackend.EventAPUp, fmt.Sprintf("access point %q", b.apSSID()))
	b.markAPReady(b.now())
}

func (b *Backend) markAPReady(now time.Time) {
	b.mu.Lock()
	b.ap.failure, b.ap.attempts, b.ap.retryAt = "", 0, time.Time{}
	b.ap.readyAt, b.ap.probedAt = now, now
	b.ap.rejoinDue = now.Add(netbackend.SavedRejoinInterval)
	b.mu.Unlock()
}

// apFailed records why the access point is not up and schedules the retry.
func (b *Backend) apFailed(event netbackend.Event, reason string) {
	b.mu.Lock()
	b.ap.attempts++
	delay := apRetryDelay(b.ap.attempts)
	b.ap.failure = reason
	b.ap.retryAt = b.now().Add(delay)
	b.mu.Unlock()
	b.fire(event, fmt.Sprintf("%s; next attempt in %s; USB management is unaffected", reason, delay))
}

// apRetryDelay doubles from APRetryInitial and stops at APRetryMax.
func apRetryDelay(attempt int) time.Duration {
	delay := netbackend.APRetryInitial
	for step := 1; step < attempt && delay < netbackend.APRetryMax; step++ {
		delay *= 2
	}
	if delay > netbackend.APRetryMax {
		delay = netbackend.APRetryMax
	}
	return delay
}

// stopAP takes the access point down. It names only the access point's own
// profile; "not active" is not an error worth reporting.
func (b *Backend) stopAP(ctx context.Context) {
	_, _ = b.run(ctx, "connection", "down", "id", apProfile)
}

// considerRejoin runs while the access point is offered although a saved
// network exists. The saved network is the device's real home, so it is looked
// for, and tried, without anyone asking.
func (b *Backend) considerRejoin(ctx context.Context, savedSSID string) {
	now := b.now()
	b.mu.Lock()
	probeDue := now.Sub(b.ap.probedAt) >= netbackend.SavedProbeInterval
	if probeDue {
		b.ap.probedAt = now
	}
	quiet := b.ap.activity.IsZero() || now.Sub(b.ap.activity) >= netbackend.SetupQuietPeriod
	rejoinDue, notBefore := b.ap.rejoinDue, b.ap.rejoinNotBefore
	b.mu.Unlock()
	if !probeDue {
		return
	}
	// Someone is on the setup page: leave the access point alone, but not
	// beyond MaxRejoinDeferral past the time a rejoin was due.
	overdue := !now.Before(rejoinDue.Add(netbackend.MaxRejoinDeferral))
	if !quiet && !overdue {
		return
	}
	trigger := ""
	switch {
	case !now.Before(rejoinDue):
		trigger = "periodic attempt"
	case !now.Before(notBefore) && b.savedVisible(ctx, savedSSID):
		trigger = "the saved network is visible again"
	default:
		return
	}

	b.fire(netbackend.EventSavedNetworkRetry, trigger)
	b.stopAP(ctx)
	if b.restorePrevious(defaultProfile) {
		b.fire(netbackend.EventLinkUp, "back on the saved network")
		return
	}
	b.mu.Lock()
	// A network that is visible but refuses the saved credential must not
	// take the access point down once a minute - the access point is how the
	// credential gets corrected.
	b.ap.rejoinNotBefore = b.now().Add(netbackend.SavedRejoinInterval)
	b.mu.Unlock()
	b.fire(netbackend.EventSavedNetworkUnreachable, "the saved network is kept")
	b.startAP(ctx, netbackend.EventAPStart)
}

// savedVisible reports whether a scan lists the saved network. A radio that
// cannot scan while it is an access point simply reports false, and the
// periodic attempt covers that case.
func (b *Backend) savedVisible(ctx context.Context, ssid string) bool {
	result, err := b.scan(ctx)
	if err != nil {
		return false
	}
	for _, network := range result.Networks {
		if network.SSID == ssid {
			return true
		}
	}
	return false
}

// apSSID is the access point's name: the product name and the last group of
// the device id, which is what the NAS and the management console show too.
func (b *Backend) apSSID() string {
	suffix := ""
	if parts := strings.Split(b.deviceID, "-"); len(parts) > 0 {
		for _, character := range strings.ToUpper(parts[len(parts)-1]) {
			if (character >= '0' && character <= '9') || (character >= 'A' && character <= 'Z') {
				suffix += string(character)
			}
		}
	}
	if len(suffix) > 6 {
		suffix = suffix[len(suffix)-6:]
	}
	if suffix == "" {
		return "NasSimHub-Setup"
	}
	return "NasSimHub-" + suffix
}

// SetupAPCredential returns the access point's name and passphrase, creating
// the passphrase if this device does not have one yet.
//
// See netbackend.SetupAPCredentialSource for where the result may be shown.
// Nothing in this package passes it to a status document, a log or an error.
func (b *Backend) SetupAPCredential() (ssid, passphrase string, err error) {
	passphrase, err = b.setupAPPassphrase()
	if err != nil {
		return "", "", errors.New("the access point passphrase is unavailable")
	}
	return b.apSSID(), passphrase, nil
}

// passphraseAlphabet leaves out the characters people misread from a screen
// (0/O, 1/l/I) because this passphrase is typed into a phone by hand.
const passphraseAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"

// setupAPPassphrase reads the device's access point passphrase, generating
// and storing it on first use. There is no default: a device with no stored
// passphrase and no way to store one has no access point.
func (b *Backend) setupAPPassphrase() (string, error) {
	path := filepath.Join(b.stateDir, apPassphraseFile)
	if raw, err := os.ReadFile(path); err == nil {
		if stored := strings.TrimSpace(string(raw)); validSetupPassphrase(stored) {
			return stored, nil
		}
		// Unreadable as a passphrase: replace it rather than start an
		// access point nobody can join.
	} else if !os.IsNotExist(err) {
		return "", err
	}
	// 16 characters of a 32-letter alphabet: 80 bits, in four groups so it
	// can be read aloud. 256 is a multiple of 32, so the bytes map evenly.
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	var builder strings.Builder
	for index, value := range random {
		if index > 0 && index%4 == 0 {
			builder.WriteByte('-')
		}
		builder.WriteByte(passphraseAlphabet[int(value)%len(passphraseAlphabet)])
	}
	passphrase := builder.String()
	if err := os.MkdirAll(b.stateDir, 0700); err != nil {
		return "", err
	}
	// Written to a private temporary file and renamed, so the passphrase
	// never exists under its final name with wider permissions or half
	// written.
	file, err := os.CreateTemp(b.stateDir, ".setup-ap-*")
	if err != nil {
		return "", err
	}
	temporary := file.Name()
	if err = file.Chmod(0600); err == nil {
		_, err = file.WriteString(passphrase + "\n")
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporary, path)
	}
	if err != nil {
		_ = os.Remove(temporary)
		return "", err
	}
	return passphrase, nil
}

func validSetupPassphrase(value string) bool {
	if len(value) < 16 || len(value) > 63 {
		return false
	}
	for _, character := range value {
		if character != '-' && !strings.ContainsRune(passphraseAlphabet, character) {
			return false
		}
	}
	return true
}

// describeFailure adds what nmcli said to a failure reason. The reason is
// shown in the status document, so the passphrase is removed from it even
// though nmcli has no reason to repeat it.
func describeFailure(err error, secret string) string {
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		if errors.Is(err, context.DeadlineExceeded) {
			return " (timed out)"
		}
		return ""
	}
	detail := fmt.Sprintf(" (nmcli exit %d", exit.ExitCode())
	if line := firstLine(string(exit.Stderr)); line != "" {
		if secret != "" {
			line = strings.ReplaceAll(line, secret, "[redacted]")
		}
		if len(line) > 160 {
			line = line[:160]
		}
		detail += ": " + line
	}
	return detail + ")"
}
