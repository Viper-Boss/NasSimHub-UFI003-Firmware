package msm8916

import (
	"context"
	"fmt"
	"sort"

	"github.com/godbus/dbus/v5"
	"github.com/human-agent65535/nassimhub-node/proto"
	"strings"
)

type managedVoiceObjects map[dbus.ObjectPath]map[string]map[string]dbus.Variant

// Read fresh ModemManager objects and call properties, including terminated calls.
// No per-call subprocesses, activation, cached call state, or modem writes.
func (b *Backend) listCallsDBus(ctx context.Context) ([]proto.Call, error) {
	conn, err := activeBus(ctx)
	if err != nil {
		return nil, proto.Unavailable("list_calls", "ModemManager is unavailable", err)
	}
	var objects managedVoiceObjects
	err = conn.Object(modemManagerService, dbus.ObjectPath("/org/freedesktop/ModemManager1")).CallWithContext(ctx, "org.freedesktop.DBus.ObjectManager.GetManagedObjects", dbus.FlagNoAutoStart).Store(&objects)
	if err != nil {
		return nil, proto.Unavailable("list_calls", "cannot read modem call snapshot", err)
	}
	// SIM objects are exported outside ObjectManager on the target MM version.
	for _, interfaces := range objects {
		if modem, ok := interfaces["org.freedesktop.ModemManager1.Modem"]; ok {
			if simPath, ok := modem["Sim"].Value().(dbus.ObjectPath); ok && simPath != "/" {
				if _, present := objects[simPath]["org.freedesktop.ModemManager1.Sim"]; !present {
					var props map[string]dbus.Variant
					if err := conn.Object(modemManagerService, simPath).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart, "org.freedesktop.ModemManager1.Sim").Store(&props); err != nil {
						return nil, proto.Unavailable("list_calls", "cannot read current SIM identity", err)
					}
					objects[simPath] = map[string]map[string]dbus.Variant{"org.freedesktop.ModemManager1.Sim": props}
				}
			}
		}
	}
	for _, interfaces := range objects {
		if voice, ok := interfaces["org.freedesktop.ModemManager1.Modem.Voice"]; ok {
			paths, ok := voice["Calls"].Value().([]dbus.ObjectPath)
			if !ok || len(paths) > 4096 {
				return nil, proto.Unavailable("list_calls", "invalid call listing", nil)
			}
			for _, p := range paths {
				if !validCallPath(string(p)) {
					return nil, proto.Unavailable("list_calls", "invalid call path", nil)
				}
				if _, present := objects[p][callInterface]; !present {
					var props map[string]dbus.Variant
					if err := conn.Object(modemManagerService, p).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart, callInterface).Store(&props); err != nil {
						return nil, proto.Unavailable("list_calls", "cannot read call properties", err)
					}
					objects[p] = map[string]map[string]dbus.Variant{callInterface: props}
				}
			}
		}
	}
	calls, err := callsFromManagedObjects(objects)
	if err != nil {
		return nil, proto.Unavailable("list_calls", "invalid modem call snapshot", err)
	}
	return calls, nil
}

func callsFromManagedObjects(objects managedVoiceObjects) ([]proto.Call, error) {
	if len(objects) > 8192 {
		return nil, fmt.Errorf("excessive managed object listing")
	}
	paths := []string{}
	for p, interfaces := range objects {
		if _, ok := interfaces["org.freedesktop.ModemManager1.Modem"]; ok {
			paths = append(paths, string(p))
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no modem is available")
	}
	modem := objects[dbus.ObjectPath(paths[0])]
	voice, ok := modem["org.freedesktop.ModemManager1.Modem.Voice"]
	if !ok {
		return nil, fmt.Errorf("modem has no voice interface")
	}
	listed, ok := voice["Calls"].Value().([]dbus.ObjectPath)
	if !ok || len(listed) > 4096 {
		return nil, fmt.Errorf("invalid call listing")
	}
	if len(listed) == 0 {
		return []proto.Call{}, nil
	}
	simPath, ok := modem["org.freedesktop.ModemManager1.Modem"]["Sim"].Value().(dbus.ObjectPath)
	if !ok || simPath == "/" {
		return nil, fmt.Errorf("current SIM is missing")
	}
	simID, ok := objects[simPath]["org.freedesktop.ModemManager1.Sim"]["SimIdentifier"].Value().(string)
	if !ok || strings.TrimSpace(simID) == "" {
		return nil, fmt.Errorf("current SIM identity is missing")
	}
	calls := make([]proto.Call, 0, len(listed))
	for _, p := range listed {
		if !validCallPath(string(p)) {
			return nil, fmt.Errorf("invalid call path")
		}
		props, ok := objects[p][callInterface]
		if !ok {
			return nil, fmt.Errorf("call properties missing")
		}
		state, ok := props["State"].Value().(int32)
		if !ok {
			return nil, fmt.Errorf("invalid call state")
		}
		if state == 7 {
			continue
		}
		direction, ok := props["Direction"].Value().(int32)
		if !ok {
			return nil, fmt.Errorf("invalid call direction")
		}
		peer, ok := props["Number"].Value().(string)
		if !ok || len(peer) > 128 {
			return nil, fmt.Errorf("invalid call number")
		}
		// Reuse the same state and direction mapping as the legacy reader.
		call, known, err := callFromDBusValues(string(p), simID, state, direction, peer)
		if err != nil {
			return nil, err
		}
		if known {
			calls = append(calls, call)
		}
	}
	return calls, nil
}

func callFromDBusValues(path, simID string, state, direction int32, peer string) (proto.Call, bool, error) {
	fields := map[string]string{"call.properties.number": peer}
	switch direction {
	case 1:
		fields["call.properties.direction"] = "incoming"
	case 2:
		fields["call.properties.direction"] = "outgoing"
	default:
		return proto.Call{}, false, nil
	}
	states := map[int32]string{1: "dialing", 2: "ringing-out", 3: "ringing-in", 4: "active", 5: "held", 6: "waiting", 7: "terminated"}
	fields["call.properties.state"] = states[state]
	call, known := callFromProperties(path, simID, fields)

	return call, known, nil
}

// HealthState is an optional lightweight liveness query. Link selection calls
// health before every request; it must not collect SIM, signal or bearer data.
func (b *Backend) HealthState(ctx context.Context) (proto.ModemState, error) {
	if !b.options.ReadOnly {
		return proto.ModemUnknown, nil
	}
	if b.options.Run != nil {
		status, err := b.GetStatus(ctx)
		return status.State, err
	}
	conn, err := activeBus(ctx)
	if err != nil {
		return proto.ModemUnknown, err
	}
	var objects managedVoiceObjects
	err = conn.Object(modemManagerService, dbus.ObjectPath("/org/freedesktop/ModemManager1")).CallWithContext(ctx, "org.freedesktop.DBus.ObjectManager.GetManagedObjects", dbus.FlagNoAutoStart).Store(&objects)
	if err != nil {
		return proto.ModemUnknown, err
	}
	paths := []string{}
	for p, interfaces := range objects {
		if _, ok := interfaces["org.freedesktop.ModemManager1.Modem"]; ok {
			paths = append(paths, string(p))
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return proto.ModemOffline, nil
	}
	state, ok := objects[dbus.ObjectPath(paths[0])]["org.freedesktop.ModemManager1.Modem"]["State"].Value().(int32)
	if !ok {
		return proto.ModemUnknown, fmt.Errorf("invalid modem state")
	}
	return modemHealthState(state), nil
}

// Values from ModemManager/include/ModemManager-enums.h (MMModemState).
func modemHealthState(state int32) proto.ModemState {
	switch state {
	case -1:
		return proto.ModemFailed
	case 1, 4, 5:
		return proto.ModemRestarting
	case 6, 7, 8, 11:
		return proto.ModemReady
	case 0:
		return proto.ModemUnknown
	default:
		return proto.ModemOffline
	}
}
