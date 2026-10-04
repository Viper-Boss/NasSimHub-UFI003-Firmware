package msm8916

import (
	"fmt"
	"github.com/godbus/dbus/v5"
	"github.com/human-agent65535/nassimhub-node/proto"
	"testing"
)

func voiceObjectsFixture(count int) managedVoiceObjects {
	objects := managedVoiceObjects{}
	sim := dbus.ObjectPath("/org/freedesktop/ModemManager1/SIM/1")
	paths := make([]dbus.ObjectPath, count)
	for i := range paths {
		paths[i] = dbus.ObjectPath(fmt.Sprintf("%s%d", callPathPrefix, i))
		objects[paths[i]] = map[string]map[string]dbus.Variant{callInterface: {"State": dbus.MakeVariant(int32(7))}}
	}
	objects[sim] = map[string]map[string]dbus.Variant{"org.freedesktop.ModemManager1.Sim": {"SimIdentifier": dbus.MakeVariant("test-current-sim")}}
	objects["/org/freedesktop/ModemManager1/Modem/0"] = map[string]map[string]dbus.Variant{"org.freedesktop.ModemManager1.Modem": {"Sim": dbus.MakeVariant(sim)}, "org.freedesktop.ModemManager1.Modem.Voice": {"Calls": dbus.MakeVariant(paths)}}
	return objects
}
func TestNativeCallSnapshotIgnoresLongTerminatedHistory(t *testing.T) {
	objects := voiceObjectsFixture(100)
	p := dbus.ObjectPath(callPathPrefix + "99")
	objects[p][callInterface] = map[string]dbus.Variant{"State": dbus.MakeVariant(int32(4)), "Direction": dbus.MakeVariant(int32(2)), "Number": dbus.MakeVariant("10000")}
	calls, err := callsFromManagedObjects(objects)
	if err != nil || len(calls) != 1 {
		t.Fatalf("calls=%v err=%v", calls, err)
	}
	if calls[0].ID != "mm-99" || calls[0].State != proto.CallActive || calls[0].SIMID != "test-current-sim" {
		t.Fatalf("wrong current call: %+v", calls[0])
	}
	objects[p][callInterface]["State"] = dbus.MakeVariant(int32(7))
	calls, err = callsFromManagedObjects(objects)
	if err != nil || len(calls) != 0 {
		t.Fatalf("hung-up call replayed: %v %v", calls, err)
	}
}
func TestNativeCallSnapshotRejectsIncompleteData(t *testing.T) {
	for _, kind := range []string{"state", "sim", "path", "missing"} {
		t.Run(kind, func(t *testing.T) {
			objects := voiceObjectsFixture(1)
			p := dbus.ObjectPath(callPathPrefix + "0")
			switch kind {
			case "state":
				objects[p][callInterface]["State"] = dbus.MakeVariant("active")
			case "sim":
				delete(objects, "/org/freedesktop/ModemManager1/SIM/1")
			case "path":
				objects["/org/freedesktop/ModemManager1/Modem/0"]["org.freedesktop.ModemManager1.Modem.Voice"]["Calls"] = dbus.MakeVariant([]dbus.ObjectPath{"/tmp/not-call"})
			case "missing":
				delete(objects, p)
			}
			if _, err := callsFromManagedObjects(objects); err == nil {
				t.Fatal("invalid snapshot accepted as known call state")
			}
		})
	}
}
func TestNativeCallSnapshotReadsCurrentSIMAfterSwap(t *testing.T) {
	objects := voiceObjectsFixture(1)
	p := dbus.ObjectPath(callPathPrefix + "0")
	objects[p][callInterface] = map[string]dbus.Variant{"State": dbus.MakeVariant(int32(3)), "Direction": dbus.MakeVariant(int32(1)), "Number": dbus.MakeVariant("10000")}
	sim := dbus.ObjectPath("/org/freedesktop/ModemManager1/SIM/2")
	objects["/org/freedesktop/ModemManager1/Modem/0"]["org.freedesktop.ModemManager1.Modem"]["Sim"] = dbus.MakeVariant(sim)
	objects[sim] = map[string]map[string]dbus.Variant{"org.freedesktop.ModemManager1.Sim": {"SimIdentifier": dbus.MakeVariant("replacement-sim")}}
	calls, err := callsFromManagedObjects(objects)
	if err != nil || len(calls) != 1 || calls[0].SIMID != "replacement-sim" || calls[0].Direction != proto.DirectionIncoming {
		t.Fatalf("wrong SIM call: %v %v", calls, err)
	}
}

func TestNativeHealthStateKeepsModemLifecycle(t *testing.T) {
	for _, tt := range []struct {
		state int32
		want  proto.ModemState
	}{{-1, proto.ModemFailed}, {0, proto.ModemUnknown}, {1, proto.ModemRestarting}, {2, proto.ModemOffline}, {3, proto.ModemOffline}, {4, proto.ModemRestarting}, {5, proto.ModemRestarting}, {6, proto.ModemReady}, {7, proto.ModemReady}, {8, proto.ModemReady}, {11, proto.ModemReady}} {
		if got := modemHealthState(tt.state); got != tt.want {
			t.Fatalf("state %d mapped to %s want %s", tt.state, got, tt.want)
		}
	}
}
