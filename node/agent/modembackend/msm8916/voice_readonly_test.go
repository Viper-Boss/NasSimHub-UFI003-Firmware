package msm8916

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/human-agent65535/nassimhub-node/proto"
)

func TestReadOnlyVoiceListEmptyOnTargetFormat(t *testing.T) {
	backend := New(Options{ReadOnly: true, Run: func(_ context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "-K -L":
			return "modem-list.value[1] : /org/freedesktop/ModemManager1/Modem/1\n", nil
		case "-K -m /org/freedesktop/ModemManager1/Modem/1 --voice-list-calls":
			return "modem.voice.call : 0\n", nil
		default:
			return "", errors.New("unexpected command")
		}
	}})
	calls, err := backend.ListCalls(context.Background())
	if err != nil || calls == nil || len(calls) != 0 {
		t.Fatalf("empty calls = %#v, %v", calls, err)
	}
}

func TestReadOnlyVoiceListMapsIncomingCall(t *testing.T) {
	const modem = "/org/freedesktop/ModemManager1/Modem/1"
	const call = "/org/freedesktop/ModemManager1/Call/7"
	const sim = "/org/freedesktop/ModemManager1/SIM/1"
	backend := New(Options{ReadOnly: true, CallEpoch: func(context.Context) (string, error) { return modemCallEpoch("boot", "bus", ":1.2"), nil }, Run: func(_ context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "-K -L":
			return "modem-list.value[1] : " + modem + "\n", nil
		case "-K -m " + modem + " --voice-list-calls":
			return "modem.voice.call.length : 1\nmodem.voice.call.value[1] : " + call + "\n", nil
		case "-K -m " + modem:
			return "modem.generic.state : registered\nmodem.generic.sim : " + sim + "\n", nil
		case "-K -i " + sim:
			return "sim.properties.iccid : 8900000000000000000\n", nil
		default:
			return "", errors.New("unexpected command")
		}
	}, RunBusctl: func(_ context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "get-property org.freedesktop.ModemManager1 " + call + " org.freedesktop.ModemManager1.Call Direction":
			return "i 1", nil
		case "get-property org.freedesktop.ModemManager1 " + call + " org.freedesktop.ModemManager1.Call State":
			return "i 3", nil
		case "get-property org.freedesktop.ModemManager1 " + call + " org.freedesktop.ModemManager1.Call Number":
			return `s "+8610000000000"`, nil
		default:
			return "", errors.New("unexpected busctl property")
		}
	}})
	calls, err := backend.ListCalls(context.Background())
	if err != nil || len(calls) != 1 {
		t.Fatalf("calls = %#v, %v", calls, err)
	}
	got := calls[0]
	if got.ID != scopeCallID(modemCallEpoch("boot", "bus", ":1.2"), "mm-7") || got.SIMID != "8900000000000000000" || got.Direction != proto.DirectionIncoming || got.State != proto.CallRinging {
		t.Fatalf("incoming call mapping = %#v", got)
	}
}

func TestBusctlVoicePropertiesRejectMalformedValues(t *testing.T) {
	if _, err := busctlInteger("i 1 extra"); err == nil {
		t.Fatal("accepted extra integer tokens")
	}
	if _, err := busctlString(`s "unclosed`); err == nil {
		t.Fatal("accepted malformed string")
	}
}

func TestReadOnlyVoiceListRejectsInvalidCallPath(t *testing.T) {
	backend := New(Options{ReadOnly: true, Run: func(_ context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "-K -L":
			return "modem-list.value[1] : /org/freedesktop/ModemManager1/Modem/1\n", nil
		case "-K -m /org/freedesktop/ModemManager1/Modem/1 --voice-list-calls":
			return "modem.voice.call.length : 1\nmodem.voice.call.value[1] : /tmp/not-a-call\n", nil
		case "-K -m /org/freedesktop/ModemManager1/Modem/1":
			return "modem.generic.state : registered\n", nil
		default:
			return "", errors.New("unexpected command")
		}
	}})
	if _, err := backend.ListCalls(context.Background()); proto.CodeOf(err) != proto.ErrorUnavailable {
		t.Fatalf("invalid call path error = %v", err)
	}
}

func TestObservedVoiceCapabilityDoesNotClaimWorkingCallAudio(t *testing.T) {
	backend := New(Options{ReadOnly: true, Run: func(_ context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "-K -L":
			return "modem-list.value[1] : /org/freedesktop/ModemManager1/Modem/1\n", nil
		case "-K -m /org/freedesktop/ModemManager1/Modem/1 --voice-status":
			return "modem.voice.emergency-only : no\n", nil
		default:
			return "", errors.New("unexpected command")
		}
	}})
	capability, err := backend.GetVoiceCapability(context.Background())
	if err != nil || capability.Control || capability.Audio || capability.VoLTE != proto.TriUnknown || capability.Source != "modemmanager" {
		t.Fatalf("unvalidated voice capability = %+v, %v", capability, err)
	}
}
