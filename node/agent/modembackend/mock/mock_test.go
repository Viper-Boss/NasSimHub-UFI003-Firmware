package mock

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/modembackend"
	"github.com/human-agent65535/nassimhub-node/proto"
)

func newBackend(t *testing.T, scenario Scenario) (*Backend, context.Context) {
	t.Helper()
	backend := New(Options{Scenario: scenario, DeviceID: "NSH-MOCK-000001"})
	t.Cleanup(func() { _ = backend.Close() })
	return backend, context.Background()
}

func codeOf(t *testing.T, err error) proto.ErrorCode {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	return proto.CodeOf(err)
}

func TestSIMReadyReportsIdentity(t *testing.T) {
	backend, ctx := newBackend(t, ChinaMobile)
	info, err := backend.GetSIMInfo(ctx)
	if err != nil {
		t.Fatalf("sim: %v", err)
	}
	if info.State != proto.SIMReady {
		t.Fatalf("sim state is %s", info.State)
	}
	if info.SIMID() != ChinaMobile.ICCID {
		t.Fatalf("sim id is %q", info.SIMID())
	}
	if info.OperatorName != "中国移动" {
		t.Fatalf("operator is %q", info.OperatorName)
	}
}

func TestSIMMissingHidesIdentityAndBlocksSend(t *testing.T) {
	backend, ctx := newBackend(t, ChinaMobile)
	backend.SetSIMState(proto.SIMMissing)

	info, err := backend.GetSIMInfo(ctx)
	if err != nil {
		t.Fatalf("sim: %v", err)
	}
	if info.State != proto.SIMMissing {
		t.Fatalf("sim state is %s", info.State)
	}
	if info.SIMID() != "" {
		t.Fatal("a missing SIM reported an identifier")
	}
	_, err = backend.SendSMS(ctx, proto.SendSMSRequest{RequestID: "r1", To: "+8613800138000", Text: "hi"})
	if got := codeOf(t, err); got != proto.ErrorFailedPrecondition {
		t.Fatalf("send with no SIM returned %s", got)
	}
}

func TestPINLockedStateIsDistinctFromMissing(t *testing.T) {
	backend, ctx := newBackend(t, ChinaMobile)
	backend.SetSIMState(proto.SIMPINLocked)
	info, err := backend.GetSIMInfo(ctx)
	if err != nil {
		t.Fatalf("sim: %v", err)
	}
	if info.State != proto.SIMPINLocked {
		t.Fatalf("sim state is %s", info.State)
	}
	if info.PINRetries == nil || *info.PINRetries != 3 {
		t.Fatal("a PIN-locked card must report remaining attempts")
	}
	if info.SIMID() == "" {
		t.Fatal("a PIN-locked card should still identify itself")
	}
	if info.PhoneNumber != "" {
		t.Fatal("a locked card must not report a subscriber number")
	}
}

func TestLTERegisteredAndSignalLevel(t *testing.T) {
	backend, ctx := newBackend(t, ChinaMobile)
	network, err := backend.GetNetwork(ctx)
	if err != nil {
		t.Fatalf("network: %v", err)
	}
	if network.Registration != proto.RegRegistered || network.AccessTechnology != proto.AccessLTE {
		t.Fatalf("network is %+v", network)
	}
	signal, err := backend.GetSignal(ctx)
	if err != nil {
		t.Fatalf("signal: %v", err)
	}
	if !signal.Known || signal.DBM == nil || *signal.DBM != -76 {
		t.Fatalf("signal is %+v", signal)
	}
	if signal.Bars != proto.BarsFromDBM(-76) {
		t.Fatalf("bars %d disagree with the shared scale", signal.Bars)
	}

	backend.SetSignalDBM(-103)
	signal, err = backend.GetSignal(ctx)
	if err != nil {
		t.Fatalf("signal: %v", err)
	}
	if *signal.DBM != -103 || signal.Bars != 1 {
		t.Fatalf("signal did not follow the scenario change: %+v", signal)
	}
}

func TestIncomingAndOutgoingSMS(t *testing.T) {
	backend, ctx := newBackend(t, ChinaMobile)

	received, err := backend.InjectIncomingSMS("10086", "your balance is 42 yuan")
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if received.Direction != proto.DirectionIncoming || received.State != proto.SMSReceived {
		t.Fatalf("received message is %+v", received)
	}
	if received.SIMID != ChinaMobile.ICCID {
		t.Fatal("an incoming message was not attributed to the card")
	}

	sent, err := backend.SendSMS(ctx, proto.SendSMSRequest{RequestID: "r1", To: "+8613100131000", Text: "hello"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if sent.State != proto.SMSSent {
		t.Fatalf("sent state is %s", sent.State)
	}

	messages, err := backend.ListSMS(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(messages))
	}
	for _, message := range messages {
		if message.SIMID != ChinaMobile.ICCID {
			t.Fatalf("message %s is not bound to a card", message.ID)
		}
	}
}

func TestSendSMSIsIdempotentPerRequestID(t *testing.T) {
	backend, ctx := newBackend(t, ChinaMobile)
	first, err := backend.SendSMS(ctx, proto.SendSMSRequest{RequestID: "same", To: "+8613100131000", Text: "hello"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	second, err := backend.SendSMS(ctx, proto.SendSMSRequest{RequestID: "same", To: "+8613100131000", Text: "hello"})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if first.MessageID != second.MessageID {
		t.Fatal("a retry produced a second message")
	}
	messages, err := backend.ListSMS(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("retry created %d messages", len(messages))
	}
}

func TestDeleteSMS(t *testing.T) {
	backend, ctx := newBackend(t, ChinaMobile)
	message, err := backend.InjectIncomingSMS("10086", "text")
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if err := backend.DeleteSMS(ctx, message.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := codeOf(t, backend.DeleteSMS(ctx, message.ID)); got != proto.ErrorNotFound {
		t.Fatalf("second delete returned %s", got)
	}
}

func TestIncomingCallRingingAnswerHangup(t *testing.T) {
	backend, ctx := newBackend(t, ChinaMobile)

	call, err := backend.InjectIncomingCall("+8613900139000")
	if err != nil {
		t.Fatalf("inject call: %v", err)
	}
	if call.State != proto.CallRinging {
		t.Fatalf("call state is %s", call.State)
	}

	answered, err := backend.Answer(ctx, call.ID)
	if err != nil {
		t.Fatalf("answer: %v", err)
	}
	if answered.State != proto.CallActive {
		t.Fatalf("answered state is %s", answered.State)
	}

	ended, err := backend.Hangup(ctx, call.ID)
	if err != nil {
		t.Fatalf("hangup: %v", err)
	}
	if ended.State != proto.CallTerminated {
		t.Fatalf("ended state is %s", ended.State)
	}

	// A repeated hangup converges rather than erroring, so a Core retry after a
	// link drop is safe.
	if _, err := backend.Hangup(ctx, call.ID); err != nil {
		t.Fatalf("repeat hangup: %v", err)
	}
}

func TestAnswerRejectsWrongState(t *testing.T) {
	backend, ctx := newBackend(t, ChinaMobile)
	receipt, err := backend.Dial(ctx, proto.DialRequest{RequestID: "d1", To: "+8613900139000"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if got := codeOf(t, mustErr(backend.Answer(ctx, receipt.CallID))); got != proto.ErrorFailedPrecondition {
		t.Fatalf("answering a dialing call returned %s", got)
	}
}

func mustErr(_ proto.CallReceipt, err error) error { return err }

func TestVoiceCapabilityFalseBlocksDial(t *testing.T) {
	backend, ctx := newBackend(t, ChinaUnicom) // VoiceControl is false.

	capabilities, err := backend.Capabilities(ctx)
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	if capabilities.VoiceControl {
		t.Fatal("the unicom scenario should have no voice control")
	}
	_, err = backend.Dial(ctx, proto.DialRequest{RequestID: "d1", To: "+8613900139000"})
	if got := codeOf(t, err); got != proto.ErrorNotSupported {
		t.Fatalf("dial on a voiceless node returned %s, want not_supported", got)
	}

	voice, err := backend.GetVoiceCapability(ctx)
	if err != nil {
		t.Fatalf("voice capability: %v", err)
	}
	if voice.Control || voice.Audio {
		t.Fatalf("voice capability is %+v", voice)
	}
	if voice.VoLTE != proto.TriUnknown {
		t.Fatalf("VoLTE should be unknown, got %s", voice.VoLTE)
	}
}

func TestVoiceControlWithoutAudioIsReportedSeparately(t *testing.T) {
	backend, ctx := newBackend(t, ChinaMobile) // control true, audio false.
	voice, err := backend.GetVoiceCapability(ctx)
	if err != nil {
		t.Fatalf("voice: %v", err)
	}
	if !voice.Control {
		t.Fatal("control should be available")
	}
	if voice.Audio {
		t.Fatal("audio should not be claimed")
	}
	if voice.Reason == "" {
		t.Fatal("a partial capability must explain itself")
	}
}

func TestModemOfflineReturnsCorrectErrors(t *testing.T) {
	backend, ctx := newBackend(t, ChinaMobile)
	backend.SetModemState(proto.ModemOffline)

	// Status must still answer; it is how Core learns the modem is down.
	status, err := backend.GetStatus(ctx)
	if err != nil {
		t.Fatalf("status on an offline modem must not error: %v", err)
	}
	if status.State != proto.ModemOffline {
		t.Fatalf("status state is %s", status.State)
	}
	if status.Reason == "" {
		t.Fatal("an offline modem must explain itself")
	}

	// Capability must collapse so the UI stops offering actions.
	capabilities, err := backend.Capabilities(ctx)
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	if capabilities.SMS || capabilities.VoiceControl || capabilities.MobileData {
		t.Fatalf("an offline modem still advertises capability: %+v", capabilities)
	}

	// Operations must fail with unavailable, not with a generic internal error.
	if _, err := backend.ListSMS(ctx); codeOf(t, err) != proto.ErrorUnavailable {
		t.Fatalf("list sms returned %s", proto.CodeOf(err))
	}
	if _, err := backend.ListCalls(ctx); codeOf(t, err) != proto.ErrorUnavailable {
		t.Fatalf("list calls returned %s", proto.CodeOf(err))
	}
	_, err = backend.SendSMS(ctx, proto.SendSMSRequest{RequestID: "r1", To: "+8613100131000", Text: "x"})
	if codeOf(t, err) != proto.ErrorUnavailable {
		t.Fatalf("send sms returned %s", proto.CodeOf(err))
	}
	_, err = backend.Dial(ctx, proto.DialRequest{RequestID: "d1", To: "+8613100131000"})
	if codeOf(t, err) != proto.ErrorUnavailable {
		t.Fatalf("dial returned %s", proto.CodeOf(err))
	}
}

func TestModemRestartClearsCallsAndRecovers(t *testing.T) {
	at := time.Now().UTC()
	clock := &at
	backend := New(Options{Scenario: ChinaMobile, Now: func() time.Time { return *clock }})
	defer backend.Close()
	ctx := context.Background()

	call, err := backend.InjectIncomingCall("+8613900139000")
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	backend.RestartModem(10 * time.Second)

	status, err := backend.GetStatus(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.State != proto.ModemRestarting {
		t.Fatalf("state during restart is %s", status.State)
	}

	*clock = at.Add(11 * time.Second)
	status, err = backend.GetStatus(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.State != proto.ModemReady {
		t.Fatalf("modem did not recover, state is %s", status.State)
	}

	calls, err := backend.ListCalls(ctx)
	if err != nil {
		t.Fatalf("calls: %v", err)
	}
	for _, existing := range calls {
		if existing.ID == call.ID && existing.State != proto.CallTerminated {
			t.Fatal("a call survived a modem restart")
		}
		if existing.ID == call.ID && existing.EndReason != "modem_restart" {
			t.Fatalf("end reason is %q", existing.EndReason)
		}
	}
}

func TestConcurrentCallIsRefused(t *testing.T) {
	backend, ctx := newBackend(t, ChinaMobile)
	if _, err := backend.Dial(ctx, proto.DialRequest{RequestID: "d1", To: "+8613900139000"}); err != nil {
		t.Fatalf("first dial: %v", err)
	}
	_, err := backend.Dial(ctx, proto.DialRequest{RequestID: "d2", To: "+8613900139001"})
	if got := codeOf(t, err); got != proto.ErrorConflict {
		t.Fatalf("second dial returned %s, want conflict", got)
	}
}

func TestEventsAreDelivered(t *testing.T) {
	backend, _ := newBackend(t, ChinaMobile)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := backend.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if _, err := backend.InjectIncomingSMS("10086", "hello"); err != nil {
		t.Fatalf("inject: %v", err)
	}
	select {
	case event := <-stream:
		if event.Kind != modembackend.EventSMS {
			t.Fatalf("event kind is %s", event.Kind)
		}
		if event.SIMID != ChinaMobile.ICCID {
			t.Fatal("event is not attributed to a card")
		}
	case <-time.After(time.Second):
		t.Fatal("no event was delivered")
	}
}

func TestTwoNodesDoNotCrossCards(t *testing.T) {
	// Two independent mock Nodes must keep their messages on their own cards.
	// This is the regression guard for the "two Nodes receive an SMS at the
	// same time" case: nothing is shared between backends, and every message
	// carries the ICCID of the card that received it.
	nodeA, ctxA := newBackend(t, ChinaMobile)
	nodeB, ctxB := newBackend(t, ChinaUnicom)

	if _, err := nodeA.InjectIncomingSMS("10086", "from mobile"); err != nil {
		t.Fatalf("inject a: %v", err)
	}
	if _, err := nodeB.InjectIncomingSMS("10010", "from unicom"); err != nil {
		t.Fatalf("inject b: %v", err)
	}

	messagesA, err := nodeA.ListSMS(ctxA)
	if err != nil {
		t.Fatalf("list a: %v", err)
	}
	messagesB, err := nodeB.ListSMS(ctxB)
	if err != nil {
		t.Fatalf("list b: %v", err)
	}
	if len(messagesA) != 1 || len(messagesB) != 1 {
		t.Fatalf("message counts are %d and %d", len(messagesA), len(messagesB))
	}
	if messagesA[0].SIMID != ChinaMobile.ICCID {
		t.Fatalf("node A message carries sim %q", messagesA[0].SIMID)
	}
	if messagesB[0].SIMID != ChinaUnicom.ICCID {
		t.Fatalf("node B message carries sim %q", messagesB[0].SIMID)
	}
	if messagesA[0].SIMID == messagesB[0].SIMID {
		t.Fatal("two nodes reported the same card")
	}
}

func TestScenarioByName(t *testing.T) {
	for _, name := range []string{"mobile", "unicom", "telecom"} {
		if _, ok := ScenarioByName(name); !ok {
			t.Fatalf("preset %q is missing", name)
		}
	}
	if _, ok := ScenarioByName("nonexistent"); ok {
		t.Fatal("an unknown preset resolved")
	}
}

func TestErrorsAreCodedNotGeneric(t *testing.T) {
	backend, ctx := newBackend(t, ChinaMobile)
	_, err := backend.SendSMS(ctx, proto.SendSMSRequest{To: "x", Text: "y"})
	var operationError *proto.OperationError
	if !errors.As(err, &operationError) {
		t.Fatalf("error %v is not a coded operation error", err)
	}
	if operationError.Operation != "send_sms" {
		t.Fatalf("operation is %q", operationError.Operation)
	}
}
