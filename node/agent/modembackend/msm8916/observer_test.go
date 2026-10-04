package msm8916

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/human-agent65535/nassimhub-node/proto"
)

func TestReadOnlyObserverReportsModemAndSIMWithoutClaimingMessaging(t *testing.T) {
	var calls [][]string
	backend := New(Options{ReadOnly: true, Run: func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, append([]string(nil), args...))
		switch {
		case reflect.DeepEqual(args, []string{"-K", "-L"}):
			return "modem-list.length : 1\nmodem-list.value[1] : /org/freedesktop/ModemManager1/Modem/1\n", nil
		case reflect.DeepEqual(args, []string{"-K", "-m", "/org/freedesktop/ModemManager1/Modem/1"}):
			return "modem.generic.state : registered\nmodem.generic.unlock-required : sim-pin2\nmodem.generic.sim : /org/freedesktop/ModemManager1/SIM/1\nmodem.generic.access-technologies.value[1] : lte\nmodem.generic.signal-quality.value : 81\nmodem.3gpp.registration-state : home\nmodem.3gpp.operator-name : Carrier\nmodem.3gpp.operator-code : 00101\n", nil
		case reflect.DeepEqual(args, []string{"-K", "-m", "/org/freedesktop/ModemManager1/Modem/1", "--signal-get"}):
			return "modem.signal.lte.rsrp : -95\nmodem.signal.lte.rsrq : -12\nmodem.signal.lte.snr : 8\n", nil
		case reflect.DeepEqual(args, []string{"-K", "-i", "/org/freedesktop/ModemManager1/SIM/1"}):
			return "sim.properties.iccid : 8900000000000000000\nsim.properties.imsi : 001010000000001\n", nil
		default:
			return "", errors.New("unexpected command")
		}
	}})
	status, err := backend.GetStatus(context.Background())
	if status.Signal.RSRP == nil || *status.Signal.RSRP != -95 {
		t.Fatalf("missing measured RSRP: %+v", status.Signal)
	}
	if err != nil || status.State != proto.ModemReady || status.SIM.State != proto.SIMReady || status.Network.Registration != proto.RegRegistered || status.Network.AccessTechnology != proto.AccessLTE || status.Signal.Bars != 5 {
		t.Fatalf("status = %#v, %v", status, err)
	}
	if status.SIM.ICCID == "" || status.SIM.IMSI == "" || len(calls) != 4 {
		t.Fatalf("SIM identity was not read: %#v, calls=%d", status.SIM, len(calls))
	}
	capabilities, _ := backend.Capabilities(context.Background())
	if capabilities.SMS || capabilities.VoiceControl || capabilities.VoiceAudio || capabilities.MobileData {
		t.Fatal("read-only status must not advertise unverified radio actions")
	}
}

func TestReadOnlyObserverFailsClosedWhenServiceIsUnavailable(t *testing.T) {
	backend := New(Options{ReadOnly: true, Run: func(context.Context, ...string) (string, error) {
		return "", errors.New("service masked")
	}})
	status, err := backend.GetStatus(context.Background())

	if err != nil || status.State != proto.ModemOffline || status.Reason == "" {
		t.Fatalf("status = %#v, %v", status, err)
	}
}

func TestReadOnlyObserverKeepsPINLockedSIMUnknownToApplications(t *testing.T) {
	backend := New(Options{ReadOnly: true, Run: func(_ context.Context, args ...string) (string, error) {
		if reflect.DeepEqual(args, []string{"-K", "-L"}) {
			return "modem-list.value[1] : /org/freedesktop/ModemManager1/Modem/0\n", nil
		}
		if reflect.DeepEqual(args, []string{"-K", "-m", "/org/freedesktop/ModemManager1/Modem/0"}) {
			return "modem.generic.state : locked\nmodem.generic.unlock-required : sim-pin\nmodem.generic.sim : /org/freedesktop/ModemManager1/SIM/0\n", nil
		}
		return "", errors.New("SIM details not available")
	}})
	status, _ := backend.GetStatus(context.Background())
	if status.SIM.State != proto.SIMPINLocked || status.SIM.ICCID != "" || status.State == proto.ModemReady {
		t.Fatalf("locked SIM was overstated: %#v", status)
	}
}

func TestReadOnlyObserverRequiresAListedModem(t *testing.T) {
	backend := New(Options{ReadOnly: true, Run: func(_ context.Context, args ...string) (string, error) {
		if reflect.DeepEqual(args, []string{"-K", "-L"}) {
			return "modem-list.length : 0\n", nil
		}
		return "", errors.New("unexpected modem query")
	}})
	status, err := backend.GetStatus(context.Background())

	if err != nil || status.State != proto.ModemOffline || status.SIM.State != proto.SIMUnknown {
		t.Fatalf("missing modem must remain offline: %#v, %v", status, err)
	}
}
