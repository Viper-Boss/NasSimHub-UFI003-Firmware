package netbackend

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

func TestEveryStateTheProtocolNamesIsInTheTableAndReachable(t *testing.T) {
	named := []proto.WiFiProvisioningState{
		proto.WiFiProvisioningUnconfigured, proto.WiFiProvisioningAPStarting, proto.WiFiProvisioningAPReady,
		proto.WiFiProvisioningAPFailed, proto.WiFiProvisioningJoining, proto.WiFiProvisioningJoined,
		proto.WiFiProvisioningJoinFailed, proto.WiFiProvisioningSavedNetworkSearching,
		proto.WiFiProvisioningSavedNetworkLost, proto.WiFiProvisioningDisabled,
	}
	if len(named) != len(States) {
		t.Fatalf("the table describes %d states, the protocol names %d", len(States), len(named))
	}
	reached := map[proto.WiFiProvisioningState]bool{proto.WiFiProvisioningUnconfigured: true}
	for changed := true; changed; {
		changed = false
		for _, edge := range Transitions {
			if reached[edge.From] && !reached[edge.To] {
				reached[edge.To], changed = true, true
			}
		}
	}
	for _, state := range named {
		if _, ok := States[state]; !ok {
			t.Fatalf("%s has no entry in States", state)
		}
		// DISABLED is entered from configuration, never by an event.
		if state != proto.WiFiProvisioningDisabled && !reached[state] {
			t.Fatalf("%s cannot be reached from UNCONFIGURED", state)
		}
	}
	seen := map[string]bool{}
	for _, edge := range Transitions {
		if _, ok := States[edge.From]; !ok {
			t.Fatalf("edge from unknown state %q", edge.From)
		}
		if _, ok := States[edge.To]; !ok {
			t.Fatalf("edge to unknown state %q", edge.To)
		}
		if edge.From == proto.WiFiProvisioningDisabled || edge.To == proto.WiFiProvisioningDisabled {
			t.Fatalf("DISABLED is set by configuration and has no edges: %+v", edge)
		}
		key := string(edge.From) + "/" + string(edge.Event)
		if seen[key] {
			t.Fatalf("two edges for %s: the machine would not be deterministic", key)
		}
		seen[key] = true
	}
}

// The saved network is the device's way home. Only a person asking for it to
// be forgotten may remove it; no timeout, failure or recovery edge may.
func TestOnlyAnExplicitForgetMayDeleteTheSavedProfile(t *testing.T) {
	forgets := 0
	for _, edge := range Transitions {
		if edge.DeletesSavedProfile != (edge.Event == EventForget) {
			t.Fatalf("edge %s --%s--> %s: deletes=%v, but only %s may delete the saved profile, and it always does",
				edge.From, edge.Event, edge.To, edge.DeletesSavedProfile, EventForget)
		}
		if edge.DeletesSavedProfile {
			forgets++
			if edge.Timed {
				t.Fatalf("edge %s --%s--> %s deletes the saved profile without anyone asking", edge.From, edge.Event, edge.To)
			}
		}
	}
	if forgets == 0 {
		t.Fatal("the table has no forget edge at all")
	}
	// The states that mean "the saved network is unreachable" keep it.
	for _, state := range []proto.WiFiProvisioningState{proto.WiFiProvisioningSavedNetworkSearching, proto.WiFiProvisioningSavedNetworkLost, proto.WiFiProvisioningJoinFailed} {
		for _, edge := range Transitions {
			if edge.From == state && edge.Event != EventForget && edge.DeletesSavedProfile {
				t.Fatalf("%s loses the saved profile on %s", state, edge.Event)
			}
		}
	}
}

// No state, and no run of states, leaves the radio neither an access point nor
// a client for longer than MaxIdleRadio.
func TestTheRadioIsNeverIdleForLongerThanTheBound(t *testing.T) {
	timedOut := func(state proto.WiFiProvisioningState) []Transition {
		var edges []Transition
		for _, edge := range Transitions {
			if edge.From == state && edge.Timed {
				edges = append(edges, edge)
			}
		}
		return edges
	}
	for state, info := range States {
		switch info.Radio {
		case RadioIdle:
			if info.MaxDwell <= 0 || info.MaxDwell > MaxIdleRadio {
				t.Fatalf("%s leaves the radio idle for %s; the bound is %s", state, info.MaxDwell, MaxIdleRadio)
			}
		case RadioAP, RadioClient, RadioOperator:
		default:
			t.Fatalf("%s has no radio activity recorded", state)
		}
		// A bound with no edge that enforces it is only a number.
		if info.MaxDwell > 0 && len(timedOut(state)) == 0 {
			t.Fatalf("%s is bounded to %s but has no timed edge out", state, info.MaxDwell)
		}
		if info.MaxDwell == 0 && info.Radio == RadioIdle {
			t.Fatalf("%s may last for ever with the radio idle", state)
		}
	}
	// Idle states that follow one another through timed edges add up.
	var longest func(state proto.WiFiProvisioningState, path []proto.WiFiProvisioningState) time.Duration
	longest = func(state proto.WiFiProvisioningState, path []proto.WiFiProvisioningState) time.Duration {
		for _, earlier := range path {
			if earlier == state {
				t.Fatalf("idle states form a loop: %v -> %s", path, state)
			}
		}
		worst := time.Duration(0)
		for _, edge := range timedOut(state) {
			if States[edge.To].Radio == RadioIdle && edge.To != state {
				if next := longest(edge.To, append(path, state)); next > worst {
					worst = next
				}
			}
		}
		return States[state].MaxDwell + worst
	}
	for state, info := range States {
		if info.Radio != RadioIdle {
			continue
		}
		if total := longest(state, nil); total > MaxIdleRadio {
			t.Fatalf("starting in %s the radio can stay idle for %s; the bound is %s", state, total, MaxIdleRadio)
		}
	}
}

func TestTheTableContainsTheRequiredJourneys(t *testing.T) {
	walk := func(start proto.WiFiProvisioningState, events ...Event) proto.WiFiProvisioningState {
		state := start
		for _, event := range events {
			edge, ok := Lookup(state, event)
			if !ok {
				t.Fatalf("no edge for %s in %s", event, state)
			}
			state = edge.To
		}
		return state
	}
	for name, journey := range map[string]struct {
		events []Event
		want   proto.WiFiProvisioningState
	}{
		"first boot to joined":              {[]Event{EventAPStart, EventAPUp, EventJoinRequested, EventJoinOK}, sJoined},
		"wrong passphrase, nothing saved":   {[]Event{EventAPStart, EventAPUp, EventJoinRequested, EventJoinError, EventNoSavedNetwork, EventAPUp}, sAPReady},
		"access point cannot start":         {[]Event{EventAPStart, EventAPError, EventAPRetry, EventAPUp}, sAPReady},
		"wrong new network, saved one":      {[]Event{EventLinkUp, EventJoinRequested, EventJoinError, EventSavedNetworkRestored}, sJoined},
		"saved network lost and back":       {[]Event{EventSavedNetworkFound, EventSavedNetworkUnreachable, EventAPStart, EventAPUp, EventSavedNetworkRetry, EventLinkUp}, sJoined},
		"forget goes back to the beginning": {[]Event{EventLinkUp, EventForget, EventAPStart, EventAPUp}, sAPReady},
	} {
		if got := walk(sUnconfigured, journey.events...); got != journey.want {
			t.Fatalf("%s: ended in %s, want %s", name, got, journey.want)
		}
	}
}

func TestMachineRefusesAnEdgeThatIsNotInTheTableAndLogsEveryMove(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	clock := time.Unix(1_700_000_000, 0)
	machine := NewMachine(func() time.Time { return clock }, func(format string, arguments ...any) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf(format, arguments...))
		mu.Unlock()
	})
	if state, _ := machine.State(); state != "" {
		t.Fatalf("a machine that has not looked at the radio reports %q", state)
	}
	machine.Start(sUnconfigured, "")
	machine.Start(sJoined, "") // ignored: the machine already has a state
	if _, err := machine.Fire(EventJoinOK, ""); err == nil {
		t.Fatal("JOIN_OK was accepted in UNCONFIGURED")
	}
	if state, _ := machine.State(); state != sUnconfigured {
		t.Fatalf("a refused event moved the machine to %s", state)
	}
	clock = clock.Add(time.Minute)
	edge, err := machine.Fire(EventJoinRequested, `target "Example-Net"`)
	if err != nil || edge.To != sJoining {
		t.Fatalf("fire: %+v %v", edge, err)
	}
	if state, since := machine.State(); state != sJoining || !since.Equal(clock) {
		t.Fatalf("state %s entered at %s", state, since)
	}
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"starting in UNCONFIGURED", "refused event join_ok in state UNCONFIGURED", `UNCONFIGURED -> JOINING (join_requested): target "Example-Net"`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("log is missing %q:\n%s", want, joined)
		}
	}
}

func TestSupportMarksOnlyWhatWasJoinedOnHardwareAsVerified(t *testing.T) {
	for _, tc := range []struct {
		security   proto.WiFiSecurity
		channel    int
		enterprise bool
		want       proto.WiFiSupport
		reason     string
	}{
		{proto.WiFiSecurityWPA2, 6, false, proto.WiFiSupportVerified, "2.4 GHz"},
		{proto.WiFiSecurityWPA2, 13, false, proto.WiFiSupportVerified, ""},
		{proto.WiFiSecurityWPA2, 36, false, proto.WiFiSupportUnverified, "5 GHz"},
		{proto.WiFiSecurityWPA3, 1, false, proto.WiFiSupportUnverified, "SAE"},
		{proto.WiFiSecurityWPA3, 149, false, proto.WiFiSupportUnverified, "5 GHz"},
		{proto.WiFiSecurityOpen, 1, false, proto.WiFiSupportUnverified, "open"},
		{proto.WiFiSecurityUnknown, 1, false, proto.WiFiSupportUnverified, "not recognised"},
		{proto.WiFiSecurityWPA2, 0, false, proto.WiFiSupportUnverified, "band is unknown"},
		{proto.WiFiSecurityWPA2, 6, true, proto.WiFiSupportUnsupported, "802.1X"},
	} {
		got, reason := SupportFor(tc.security, tc.channel, tc.enterprise)
		if got != tc.want || reason == "" || !strings.Contains(reason, tc.reason) {
			t.Fatalf("SupportFor(%s, %d, %v) = %s %q; want %s mentioning %q", tc.security, tc.channel, tc.enterprise, got, reason, tc.want, tc.reason)
		}
	}
}
