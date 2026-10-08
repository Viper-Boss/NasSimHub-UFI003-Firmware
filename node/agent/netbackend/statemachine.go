package netbackend

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// The provisioning state machine.
//
// It lives in this package, beside the Backend contract, rather than in
// agent/internal/provisioning or inside one backend, for three reasons. The
// contract at the top of backend.go is this machine in prose, and a table next
// to it can be checked where prose cannot. The provisioning package serves HTTP
// and imports this one; a backend that had to import it back to learn its own
// states would be a cycle in everything but the compiler's sense. And the table
// says nothing about nmcli, so a second hardware backend drives the same table
// instead of growing a private variant of it.
//
// The machine itself does nothing to the radio. A backend performs an action
// and fires the event that names what happened; the machine refuses an event
// that has no edge from the current state, so a transition that is not in the
// table cannot happen quietly.

// Timeouts. Each bounds one state, and the table test checks that every state
// in which the radio is doing nothing has one.
const (
	// SuperviseInterval is how often a backend looks at the radio and lets the
	// machine move. It bounds how long UNCONFIGURED and SAVED_NETWORK_LOST
	// last before the access point is started.
	SuperviseInterval = 10 * time.Second

	// APStartTimeout bounds bringing the access point up, including the scan
	// taken just before it (the radio cannot scan once it is an access point).
	APStartTimeout = 60 * time.Second

	// JoinTimeout bounds one join attempt from submission to a verdict. It is
	// longer than NetworkManager's own activation wait so that the verdict is
	// NetworkManager's whenever it gives one.
	JoinTimeout = 90 * time.Second

	// RestoreTimeout bounds the attempt to get back onto the saved network
	// after a failed join of a new one.
	RestoreTimeout = 45 * time.Second

	// SaveRecoveryTimeout bounds giving the previous network its name back
	// when the newly joined one could not be saved under it.
	SaveRecoveryTimeout = 10 * time.Second

	// ObserveTimeout bounds one look at NetworkManager after a failed join,
	// which decides where the radio goes back to.
	ObserveTimeout = 15 * time.Second

	// SavedNetworkGrace is how long a saved network may stay unreachable
	// before the access point is offered again. A router that is rebooting or
	// updating its firmware comes back within this; starting the access point
	// sooner would take the radio away from the network just as it returns.
	SavedNetworkGrace = 5 * time.Minute

	// APRetryInitial and APRetryMax bound the backoff between attempts to
	// start an access point that failed to start. The attempts do not stop:
	// with no saved network the access point is the only thing the radio can
	// usefully do, and the cap is what keeps a driver that cannot do it from
	// being asked more than once every five minutes.
	APRetryInitial = 15 * time.Second
	APRetryMax     = 5 * time.Minute

	// SavedProbeInterval is how often, while the access point is offered
	// because the saved network was lost, the backend looks for that network.
	SavedProbeInterval = time.Minute

	// SavedRejoinInterval is how often the backend stops the access point to
	// try the saved network without having seen it. It is needed because a
	// radio serving an access point may be unable to scan at all, and because
	// a hidden network never shows in a scan.
	SavedRejoinInterval = 10 * time.Minute

	// SetupQuietPeriod keeps the access point up while someone is using the
	// setup page: a rejoin attempt is put off until the page has been quiet
	// this long. MaxRejoinDeferral caps the putting off, so a phone left on
	// the setup page cannot keep the device off its network for ever.
	SetupQuietPeriod  = 2 * time.Minute
	MaxRejoinDeferral = 30 * time.Minute
)

// MaxIdleRadio is the longest the radio may be left neither serving the access
// point nor working as a client: in any single state, and across any run of
// such states that follow one another.
//
// The bounds hold while NetworkManager answers. When it does not, a backend
// leaves the state as it is and says so in the log: there is then nothing it
// could do to the radio in any case, and USB management does not depend on it.
const MaxIdleRadio = APRetryMax

// Radio is what the single Wi-Fi radio is doing in a state.
type Radio string

const (
	// RadioIdle: neither an access point nor a client attempt is in progress.
	RadioIdle Radio = "idle"
	// RadioAP: the access point is up or being brought up.
	RadioAP Radio = "ap"
	// RadioClient: associated, associating, or left to NetworkManager's
	// automatic reconnection of the saved network.
	RadioClient Radio = "client"
	// RadioOperator: the access point is switched off by configuration; what
	// the radio does is the operator's business and USB is the way in.
	RadioOperator Radio = "operator"
)

// StateInfo describes one state for the table test and the documentation.
type StateInfo struct {
	Radio Radio
	// MaxDwell bounds the state. Zero means it may last indefinitely, which is
	// only acceptable when the radio is not idle.
	MaxDwell time.Duration
}

// States is every state of the machine.
var States = map[proto.WiFiProvisioningState]StateInfo{
	proto.WiFiProvisioningUnconfigured:          {RadioIdle, 2 * SuperviseInterval},
	proto.WiFiProvisioningAPStarting:            {RadioAP, APStartTimeout},
	proto.WiFiProvisioningAPReady:               {RadioAP, 0},
	proto.WiFiProvisioningAPFailed:              {RadioIdle, APRetryMax},
	proto.WiFiProvisioningJoining:               {RadioClient, JoinTimeout + SaveRecoveryTimeout},
	proto.WiFiProvisioningJoined:                {RadioClient, 0},
	proto.WiFiProvisioningJoinFailed:            {RadioIdle, RestoreTimeout + ObserveTimeout},
	proto.WiFiProvisioningSavedNetworkSearching: {RadioClient, SavedNetworkGrace},
	proto.WiFiProvisioningSavedNetworkLost:      {RadioIdle, 2 * SuperviseInterval},
	proto.WiFiProvisioningDisabled:              {RadioOperator, 0},
}

// Event names what happened. Events are facts a backend observed or a request
// a user made; none of them is a command.
type Event string

const (
	// EventAPStart: the backend begins bringing the access point up.
	EventAPStart Event = "ap_start"
	// EventAPUp: NetworkManager reports the access point active.
	EventAPUp Event = "ap_up"
	// EventAPError: bringing the access point up failed, or it stopped.
	EventAPError Event = "ap_error"
	// EventAPRetry: the backoff after a failed start has run out.
	EventAPRetry Event = "ap_retry"
	// EventJoinRequested: a user submitted a network to join.
	EventJoinRequested Event = "join_requested"
	// EventJoinOK: the submitted network was joined and saved.
	EventJoinOK Event = "join_ok"
	// EventJoinError: the submitted network could not be joined or saved.
	EventJoinError Event = "join_error"
	// EventNoSavedNetwork: after a failed join there is no saved network to
	// go back to.
	EventNoSavedNetwork Event = "no_saved_network"
	// EventSavedNetworkRestored: after a failed join the device is back on
	// the saved network.
	EventSavedNetworkRestored Event = "saved_network_restored"
	// EventRestoreFailed: after a failed join the saved network exists but
	// could not be rejoined, and the radio was a client before the attempt.
	EventRestoreFailed Event = "restore_failed"
	// EventSavedNetworkUnreachable: the saved network exists and has stayed
	// out of reach for as long as this state allows.
	EventSavedNetworkUnreachable Event = "saved_network_unreachable"
	// EventSavedNetworkFound: a saved network exists where none was known.
	EventSavedNetworkFound Event = "saved_network_found"
	// EventSavedNetworkRetry: the access point is stopped to try the saved
	// network again.
	EventSavedNetworkRetry Event = "saved_network_retry"
	// EventSavedProfileGone: the saved network was removed outside the agent.
	EventSavedProfileGone Event = "saved_profile_gone"
	// EventLinkUp: the radio is associated as a client.
	EventLinkUp Event = "link_up"
	// EventLinkLost: the radio is no longer associated.
	EventLinkLost Event = "link_lost"
	// EventForget: a user asked for the saved network to be removed.
	EventForget Event = "forget"
)

// Transition is one edge of the machine.
type Transition struct {
	From  proto.WiFiProvisioningState
	Event Event
	To    proto.WiFiProvisioningState
	// DeletesSavedProfile marks the only edges on which a backend may remove
	// the saved network. A backend checks it before deleting anything.
	DeletesSavedProfile bool
	// Timed marks an edge taken without anyone asking: by a timeout, or as
	// the outcome of an operation that is itself bounded. Every bounded state
	// needs one, or its bound would be a number with nothing behind it.
	Timed bool
}

const (
	sUnconfigured = proto.WiFiProvisioningUnconfigured
	sAPStarting   = proto.WiFiProvisioningAPStarting
	sAPReady      = proto.WiFiProvisioningAPReady
	sAPFailed     = proto.WiFiProvisioningAPFailed
	sJoining      = proto.WiFiProvisioningJoining
	sJoined       = proto.WiFiProvisioningJoined
	sJoinFailed   = proto.WiFiProvisioningJoinFailed
	sSearching    = proto.WiFiProvisioningSavedNetworkSearching
	sLost         = proto.WiFiProvisioningSavedNetworkLost
)

// Transitions is the whole machine. DISABLED has no edges: the access point
// is switched off in the configuration file, which is read at start.
var Transitions = []Transition{
	// First boot: no saved network, so the access point is the way in.
	{From: sUnconfigured, Event: EventAPStart, To: sAPStarting, Timed: true},
	{From: sUnconfigured, Event: EventSavedNetworkFound, To: sSearching},
	{From: sUnconfigured, Event: EventLinkUp, To: sJoined},
	{From: sUnconfigured, Event: EventJoinRequested, To: sJoining},
	{From: sUnconfigured, Event: EventForget, To: sUnconfigured, DeletesSavedProfile: true},

	{From: sAPStarting, Event: EventAPUp, To: sAPReady, Timed: true},
	{From: sAPStarting, Event: EventAPError, To: sAPFailed, Timed: true},

	// The access point is up. Submitting credentials stops it, because one
	// radio cannot be an access point and a client at once.
	{From: sAPReady, Event: EventJoinRequested, To: sJoining},
	{From: sAPReady, Event: EventAPError, To: sAPFailed},
	{From: sAPReady, Event: EventLinkUp, To: sJoined},
	{From: sAPReady, Event: EventSavedNetworkRetry, To: sSearching},
	{From: sAPReady, Event: EventForget, To: sAPReady, DeletesSavedProfile: true},

	// The access point did not start. USB still works; the start is retried.
	{From: sAPFailed, Event: EventAPRetry, To: sAPStarting, Timed: true},
	{From: sAPFailed, Event: EventAPUp, To: sAPReady},
	{From: sAPFailed, Event: EventLinkUp, To: sJoined},
	{From: sAPFailed, Event: EventJoinRequested, To: sJoining},
	{From: sAPFailed, Event: EventForget, To: sAPFailed, DeletesSavedProfile: true},

	{From: sJoining, Event: EventJoinOK, To: sJoined, Timed: true},
	{From: sJoining, Event: EventJoinError, To: sJoinFailed, Timed: true},

	// A failed join goes back to where the device was: to the access point
	// when there is no saved network, to the saved network when there is one.
	{From: sJoinFailed, Event: EventNoSavedNetwork, To: sAPStarting, Timed: true},
	{From: sJoinFailed, Event: EventSavedNetworkRestored, To: sJoined, Timed: true},
	{From: sJoinFailed, Event: EventRestoreFailed, To: sSearching, Timed: true},
	{From: sJoinFailed, Event: EventSavedNetworkUnreachable, To: sLost, Timed: true},

	{From: sJoined, Event: EventLinkLost, To: sSearching},
	{From: sJoined, Event: EventJoinRequested, To: sJoining},
	{From: sJoined, Event: EventForget, To: sUnconfigured, DeletesSavedProfile: true},

	// The saved network is out of reach. It is kept: the access point is
	// offered beside it, never instead of it.
	{From: sSearching, Event: EventLinkUp, To: sJoined},
	{From: sSearching, Event: EventSavedNetworkUnreachable, To: sLost, Timed: true},
	{From: sSearching, Event: EventSavedProfileGone, To: sUnconfigured},
	{From: sSearching, Event: EventJoinRequested, To: sJoining},
	{From: sSearching, Event: EventForget, To: sUnconfigured, DeletesSavedProfile: true},

	{From: sLost, Event: EventAPStart, To: sAPStarting, Timed: true},
	{From: sLost, Event: EventLinkUp, To: sJoined},
	{From: sLost, Event: EventSavedProfileGone, To: sUnconfigured},
	{From: sLost, Event: EventJoinRequested, To: sJoining},
	{From: sLost, Event: EventForget, To: sUnconfigured, DeletesSavedProfile: true},
}

// Lookup returns the edge for an event in a state.
func Lookup(from proto.WiFiProvisioningState, event Event) (Transition, bool) {
	for _, transition := range Transitions {
		if transition.From == from && transition.Event == event {
			return transition, true
		}
	}
	return Transition{}, false
}

// Machine holds the current state and takes only edges that are in the table.
type Machine struct {
	mu    sync.Mutex
	state proto.WiFiProvisioningState
	since time.Time
	now   func() time.Time
	logf  func(format string, arguments ...any)
}

// NewMachine returns a machine with no state yet. A backend calls Start once
// it has looked at the radio; until then State reports the empty value, which
// the status document leaves out rather than guessing.
func NewMachine(now func() time.Time, logf func(format string, arguments ...any)) *Machine {
	if now == nil {
		now = time.Now
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Machine{now: now, logf: logf}
}

// Start sets the first state from what the backend observed. It does nothing
// once the machine has a state.
func (m *Machine) Start(initial proto.WiFiProvisioningState, detail string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != "" {
		return
	}
	m.state, m.since = initial, m.now()
	m.logf("provisioning: starting in %s%s", initial, suffix(detail))
}

// State is the current state and when it was entered.
func (m *Machine) State() (proto.WiFiProvisioningState, time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state, m.since
}

// Fire takes the edge for event from the current state and logs it.
//
// detail is written to the log as given, so the caller passes only what may be
// logged: a fixed reason, or the name of the network the user asked for. It
// must never be a credential or the name of any other network.
func (m *Machine) Fire(event Event, detail string) (Transition, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	transition, ok := Lookup(m.state, event)
	if !ok {
		m.logf("provisioning: refused event %s in state %s: no such transition", event, m.state)
		return Transition{}, fmt.Errorf("no transition for %s in state %s", event, m.state)
	}
	if transition.To != m.state {
		m.since = m.now()
	}
	m.state = transition.To
	m.logf("provisioning: %s -> %s (%s)%s", transition.From, transition.To, event, suffix(detail))
	return transition, nil
}

func suffix(detail string) string {
	if detail == "" {
		return ""
	}
	return ": " + detail
}

// Supervised is implemented by a backend that has to look at the radio from
// time to time by itself - to start the access point, to notice a lost
// network. The agent runs it for as long as it serves.
type Supervised interface {
	Run(ctx context.Context)
}

// SetupActivityNoter is implemented by a backend that wants to know the setup
// page is in use, so it does not take the access point away from under it.
type SetupActivityNoter interface {
	NoteSetupActivity()
}

// SetupAPCredentialSource is implemented by a backend that runs a
// password-protected setup access point.
//
// The passphrase is per device, generated on the device, and is a credential:
// it lets a person standing nearby reach the setup page. It may be shown only
// where ownership is already established - the authenticated management API
// reached over the USB link, or the first-time setup proof flow - and it must
// never be added to the Wi-Fi status document, a log line, a diagnostics
// bundle or the provisioning API, all of which are readable more widely.
type SetupAPCredentialSource interface {
	SetupAPCredential() (ssid, passphrase string, err error)
}
