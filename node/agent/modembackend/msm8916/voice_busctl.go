package msm8916

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

const (
	modemManagerService = "org.freedesktop.ModemManager1"
	callInterface       = "org.freedesktop.ModemManager1.Call"
)

// runBusctlReadOnly uses GetProperty only. Never run it before confirming the
// ModemManager service is already active: D-Bus activation must stay disabled.
func runBusctlReadOnly(ctx context.Context, args ...string) (string, error) {
	check, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := exec.CommandContext(check, "systemctl", "is-active", "--quiet", "ModemManager.service").Run(); err != nil {
		return "", errors.New("ModemManager is not active")
	}
	query, stop := context.WithTimeout(ctx, 4*time.Second)
	defer stop()
	output, err := exec.CommandContext(query, "busctl", args...).Output()
	if err != nil || len(output) > 512 {
		return "", errors.New("ModemManager call property query failed")
	}
	return strings.TrimSpace(string(output)), nil
}

func (b *Backend) readCallBusctl(ctx context.Context, path, simID string) (proto.Call, bool, error) {
	property := func(name string) (string, error) {
		return b.runBusctl(ctx, "get-property", modemManagerService, path, callInterface, name)
	}
	state, err := property("State")
	if err != nil {
		return proto.Call{}, false, err
	}
	stateValue, err := busctlInteger(state)
	if err != nil {
		return proto.Call{}, false, err
	}
	if stateValue == 7 {
		return proto.Call{}, false, nil
	}
	direction, err := property("Direction")
	if err != nil {
		return proto.Call{}, false, err
	}
	number, err := property("Number")
	if err != nil {
		return proto.Call{}, false, err
	}
	directionValue, err := busctlInteger(direction)
	if err != nil {
		return proto.Call{}, false, err
	}
	peer, err := busctlString(number)
	if err != nil {
		return proto.Call{}, false, err
	}
	call := proto.Call{ID: "mm-" + strings.TrimPrefix(path, callPathPrefix), SIMID: simID, Peer: peer}
	switch directionValue {
	case 1:
		call.Direction = proto.DirectionIncoming
	case 2:
		call.Direction = proto.DirectionOutgoing
	default:
		return proto.Call{}, false, nil
	}
	switch stateValue {
	case 1:
		call.State = proto.CallDialing
	case 2, 3:
		call.State = proto.CallRinging
	case 4:
		call.State = proto.CallActive
	case 5:
		call.State = proto.CallState("held")
	case 6:
		call.State = proto.CallState("waiting")
	case 7:
		call.State = proto.CallTerminated
	default:
		return proto.Call{}, false, nil
	}
	return call, true, nil
}

func busctlInteger(output string) (int, error) {
	parts := strings.Fields(output)
	if len(parts) != 2 || parts[0] != "i" {
		return 0, errors.New("invalid call integer property")
	}
	return strconv.Atoi(parts[1])
}

func busctlString(output string) (string, error) {
	if !strings.HasPrefix(output, "s ") || len(output) > 260 {
		return "", errors.New("invalid call string property")
	}
	value, err := strconv.Unquote(strings.TrimSpace(strings.TrimPrefix(output, "s ")))
	if err != nil || len(value) > 128 {
		return "", errors.New("invalid call string value")
	}
	return value, nil
}
