package msm8916

import (
	"context"
	"strconv"
	"strings"

	"github.com/human-agent65535/nassimhub-node/proto"
)

const callPathPrefix = "/org/freedesktop/ModemManager1/Call/"

// listReadOnlyCalls observes ModemManager call objects. It never creates,
// answers, terminates, or deletes a call. A reported call has no audio claim.
func (b *Backend) listReadOnlyCalls(ctx context.Context) ([]proto.Call, error) {
	list, err := b.run(ctx, "-K", "-L")
	if err != nil {
		return nil, proto.Unavailable("list_calls", "ModemManager is unavailable", err)
	}
	modemPath := listedModemPath(list)
	if modemPath == "" {
		return nil, proto.Unavailable("list_calls", "no modem is available", nil)
	}
	listed, err := b.run(ctx, "-K", "-m", modemPath, "--voice-list-calls")
	if err != nil {
		return nil, proto.Unavailable("list_calls", "cannot list modem calls", err)
	}
	fields := parseKeyValues(listed)
	count, err := voiceCallCount(fields)
	if err != nil || count > 32 {
		return nil, proto.Unavailable("list_calls", "invalid or excessive call listing", nil)
	}
	if count == 0 {
		return []proto.Call{}, nil
	}
	modemInfo, err := b.run(ctx, "-K", "-m", modemPath)
	if err != nil {
		return nil, proto.Unavailable("list_calls", "cannot read current SIM", err)
	}
	simPath := printableValue(parseKeyValues(modemInfo)["modem.generic.sim"])
	simID := ""
	if simPath != "" {
		sim, err := b.run(ctx, "-K", "-i", simPath)
		if err != nil {
			return nil, proto.Unavailable("list_calls", "cannot identify current SIM", err)
		}
		simID = printableValue(parseKeyValues(sim)["sim.properties.iccid"])
	}
	calls := make([]proto.Call, 0, count)
	for index := 1; index <= count; index++ {
		path := fields["modem.voice.call.value["+strconv.Itoa(index)+"]"]
		if !validCallPath(path) {
			return nil, proto.Unavailable("list_calls", "invalid call path", nil)
		}
		call, ok, err := b.readCallBusctl(ctx, path, simID)
		if err != nil {
			return nil, proto.Unavailable("list_calls", "cannot read call state", err)
		}
		if ok {
			calls = append(calls, call)
		}
	}
	return calls, nil
}

func voiceCallCount(fields map[string]string) (int, error) {
	value := fields["modem.voice.call.length"]
	if value == "" {
		value = fields["modem.voice.call"] // empty-list form on the target MM version
	}
	count, err := strconv.Atoi(value)
	if err != nil || count < 0 {
		return 0, strconv.ErrSyntax
	}
	return count, nil
}

func validCallPath(path string) bool {
	if !strings.HasPrefix(path, callPathPrefix) {
		return false
	}
	_, err := strconv.ParseUint(strings.TrimPrefix(path, callPathPrefix), 10, 32)
	return err == nil
}

func callFromProperties(path, simID string, fields map[string]string) (proto.Call, bool) {
	state := strings.ToLower(printableValue(fields["call.properties.state"]))
	call := proto.Call{
		ID:    "mm-" + strings.TrimPrefix(path, callPathPrefix),
		SIMID: simID,
		Peer:  printableValue(fields["call.properties.number"]),
	}
	switch strings.ToLower(printableValue(fields["call.properties.direction"])) {
	case "incoming":
		call.Direction = proto.DirectionIncoming
	case "outgoing":
		call.Direction = proto.DirectionOutgoing
	default:
		return proto.Call{}, false
	}
	switch state {
	case "dialing":
		call.State = proto.CallDialing
	case "ringing-in", "ringing-out":
		call.State = proto.CallRinging
	case "active":
		call.State = proto.CallActive
	case "terminated":
		call.State = proto.CallTerminated
	case "held", "waiting":
		call.State = proto.CallState(state)
	default:
		return proto.Call{}, false
	}
	return call, true
}
