package msm8916

import (
	"github.com/godbus/dbus/v5"
	"github.com/human-agent65535/nassimhub-node/proto"
	"testing"
)

func TestCommandSnapshotIncludesTerminatedAndRinging(t *testing.T) {
	for _, tc := range []struct {
		raw   int32
		state proto.CallState
	}{{3, proto.CallRinging}, {4, proto.CallActive}, {7, proto.CallTerminated}} {
		props := map[string]dbus.Variant{"State": dbus.MakeVariant(tc.raw), "Direction": dbus.MakeVariant(int32(1)), "Number": dbus.MakeVariant("10000")}
		got, err := commandCallFromProperties(callPathPrefix+"1", props)
		if err != nil || got.State != tc.state || got.ID != "mm-1" {
			t.Fatal(got, err)
		}
	}
}
func TestCommandSnapshotFailsClosedOnInvalidProperty(t *testing.T) {
	for _, key := range []string{"State", "Direction", "Number"} {
		props := map[string]dbus.Variant{"State": dbus.MakeVariant(int32(3)), "Direction": dbus.MakeVariant(int32(1)), "Number": dbus.MakeVariant("10000")}
		delete(props, key)
		if _, err := commandCallFromProperties(callPathPrefix+"1", props); err == nil {
			t.Fatal("incomplete state allowed a command")
		}
	}
}
