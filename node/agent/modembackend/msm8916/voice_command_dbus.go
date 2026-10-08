package msm8916

import (
	"context"
	"fmt"
	"github.com/godbus/dbus/v5"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// Query only the selected call before accepting/hanging up. Old call history
// cannot delay control, and no cached state authorizes a modem write.
func commandCallFromProperties(path string, props map[string]dbus.Variant) (proto.Call, error) {
	state, ok := props["State"].Value().(int32)
	if !ok {
		return proto.Call{}, fmt.Errorf("invalid call state")
	}
	direction, ok := props["Direction"].Value().(int32)
	if !ok {
		return proto.Call{}, fmt.Errorf("invalid call direction")
	}
	number, ok := props["Number"].Value().(string)
	if !ok || len(number) > 128 {
		return proto.Call{}, fmt.Errorf("invalid call number")
	}
	call, known, err := callFromDBusValues(path, "", state, direction, number)
	if err != nil {
		return proto.Call{}, err
	}
	if !known {
		return proto.Call{}, fmt.Errorf("unknown call state")
	}
	return call, nil
}

func (b *Backend) commandVoiceDBus(ctx context.Context, operation, id, path, service string, incomingOnly bool) (proto.CallReceipt, error) {
	conn, err := activeBus(ctx)
	if err != nil {
		return proto.CallReceipt{}, proto.Unavailable(operation, "ModemManager is unavailable", err)
	}
	var props map[string]dbus.Variant
	object := conn.Object(service, dbus.ObjectPath(path))
	err = object.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart, callInterface).Store(&props)
	if err != nil {
		if e, ok := err.(dbus.Error); ok && e.Name == "org.freedesktop.DBus.Error.UnknownObject" {
			return proto.CallReceipt{}, proto.NotFound(operation, "call does not exist")
		}
		return proto.CallReceipt{}, proto.Unavailable(operation, "cannot read selected call", err)
	}
	selected, err := commandCallFromProperties(path, props)
	if err != nil {
		return proto.CallReceipt{}, proto.Unavailable(operation, "invalid selected call", err)
	}
	if incomingOnly && (selected.Direction != proto.DirectionIncoming || selected.State != proto.CallRinging) {
		return proto.CallReceipt{}, proto.FailedPrecondition(operation, "call is not ringing in")
	}
	if !incomingOnly && selected.State == proto.CallTerminated {
		return proto.CallReceipt{}, proto.FailedPrecondition(operation, "call already ended")
	}
	method := "Hangup"
	state := proto.CallTerminated
	if incomingOnly {
		method = "Accept"
		state = proto.CallActive
	}
	if err = object.CallWithContext(ctx, callInterface+"."+method, dbus.FlagNoAutoStart).Err; err != nil {
		return proto.CallReceipt{}, proto.Unavailable(operation, "call command failed", err)
	}
	return proto.CallReceipt{CallID: id, State: state}, nil
}
