package msm8916

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

var voiceNumber = regexp.MustCompile(`^\+?[0-9]{2,20}$`)
var createdCall = regexp.MustCompile(`^Successfully created new call: (/org/freedesktop/ModemManager1/Call/[0-9]+)$`)

// VoiceWrite gates call commands separately from status and SMS access.
// Production leaves it off until the media bridge has been validated.
func (b *Backend) voiceEnabled(operation string) error {
	if !b.options.ReadOnly || !b.options.VoiceWrite {
		return proto.NotSupported(operation, "call control is disabled")
	}
	return nil
}

func (b *Backend) dialVoice(ctx context.Context, request proto.DialRequest) (proto.CallReceipt, error) {
	const operation = "dial"
	if err := b.voiceEnabled(operation); err != nil {
		return proto.CallReceipt{}, err
	}
	if request.RequestID == "" || len(request.RequestID) > 128 {
		return proto.CallReceipt{}, proto.InvalidArgument(operation, "request_id must have 1 to 128 bytes")
	}
	if !voiceNumber.MatchString(request.To) {
		return proto.CallReceipt{}, proto.InvalidArgument(operation, "to must be a phone number")
	}
	if !b.imsVoiceReady(ctx) {
		return proto.CallReceipt{}, proto.FailedPrecondition(operation, "IMS voice service is not ready on this device")
	}
	b.voiceMu.Lock()
	defer b.voiceMu.Unlock()
	calls, err := b.listReadOnlyCalls(ctx)
	if err != nil {
		return proto.CallReceipt{}, err
	}
	for _, call := range calls {
		if call.State != proto.CallTerminated {
			return proto.CallReceipt{}, proto.Conflict(operation, "another call is in progress")
		}
	}
	list, err := b.run(ctx, "-K", "-L")
	if err != nil {
		return proto.CallReceipt{}, proto.Unavailable(operation, "modem is unavailable", err)
	}
	modem := listedModemPath(list)
	if modem == "" {
		return proto.CallReceipt{}, proto.Unavailable(operation, "modem is unavailable", nil)
	}
	output, err := b.run(ctx, "-m", modem, "--voice-create-call=number="+request.To)
	if err != nil {
		return proto.CallReceipt{}, proto.Unavailable(operation, "could not create call", err)
	}
	match := createdCall.FindStringSubmatch(strings.TrimSpace(output))
	if len(match) != 2 {
		return proto.CallReceipt{}, proto.Unavailable(operation, "cannot identify created call", nil)
	}
	path := match[1]
	if _, err := b.run(ctx, "-o", path, "--start"); err != nil {
		// The request may have timed out after the modem accepted the start.
		// Cleanup must not inherit the already-cancelled HTTP context.
		cleanup, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		_, _ = b.run(cleanup, "-o", path, "--hangup")
		return proto.CallReceipt{}, proto.Unavailable(operation, "could not start call", err)
	}
	return proto.CallReceipt{RequestID: request.RequestID, CallID: "mm-" + strings.TrimPrefix(path, callPathPrefix), State: proto.CallDialing}, nil
}

func (b *Backend) answerVoice(ctx context.Context, id string) (proto.CallReceipt, error) {
	return b.commandVoice(ctx, "answer", id, "--accept", true)
}

func (b *Backend) hangupVoice(ctx context.Context, id string) (proto.CallReceipt, error) {
	return b.commandVoice(ctx, "hangup", id, "--hangup", false)
}

func (b *Backend) commandVoice(ctx context.Context, operation, id, flag string, incomingOnly bool) (proto.CallReceipt, error) {
	if err := b.voiceEnabled(operation); err != nil {
		return proto.CallReceipt{}, err
	}
	path, ok := callIDPath(id)
	if !ok {
		return proto.CallReceipt{}, proto.InvalidArgument(operation, "invalid call id")
	}
	b.voiceMu.Lock()
	defer b.voiceMu.Unlock()
	calls, err := b.listReadOnlyCalls(ctx)
	if err != nil {
		return proto.CallReceipt{}, err
	}
	var selected *proto.Call
	for index := range calls {
		if calls[index].ID == id {
			selected = &calls[index]
			break
		}
	}
	if selected == nil {
		return proto.CallReceipt{}, proto.NotFound(operation, "call does not exist")
	}
	if incomingOnly && (selected.Direction != proto.DirectionIncoming || selected.State != proto.CallRinging) {
		return proto.CallReceipt{}, proto.FailedPrecondition(operation, "call is not ringing in")
	}
	if !incomingOnly && selected.State == proto.CallTerminated {
		return proto.CallReceipt{}, proto.FailedPrecondition(operation, "call already ended")
	}
	if _, err := b.run(ctx, "-o", path, flag); err != nil {
		return proto.CallReceipt{}, proto.Unavailable(operation, "call command failed", err)
	}
	state := proto.CallActive
	if !incomingOnly {
		state = proto.CallTerminated
	}
	return proto.CallReceipt{CallID: id, State: state}, nil
}

func callIDPath(id string) (string, bool) {
	if !strings.HasPrefix(id, "mm-") {
		return "", false
	}
	path := callPathPrefix + strings.TrimPrefix(id, "mm-")
	return path, validCallPath(path)
}
