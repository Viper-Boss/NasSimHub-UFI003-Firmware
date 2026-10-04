// Package mock is a complete, scriptable ModemBackend with no hardware behind
// it. It is not a placeholder: it is the reference implementation of the
// contract, and the whole NasSimHub Node system - Core, pairing, transport
// failover and the web UI - is developed and regression-tested against it.
//
// It can be driven two ways. A Scenario sets the steady state (which operator,
// what signal, whether a SIM is present, whether the modem answers at all), and
// the Inject* methods fire one-off events (a message arrives, a call comes in,
// the SIM is pulled out, the modem restarts). Between them they cover every
// state the UI has to render without a single piece of silicon.
package mock

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/modembackend"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// Scenario is the steady state a mock Node presents.
type Scenario struct {
	// Operator identity.
	OperatorName string
	OperatorCode string
	ICCID        string
	IMSI         string
	PhoneNumber  string

	// Radio.
	SignalDBM        float64
	AccessTechnology proto.AccessTechnology
	Registration     proto.RegistrationState
	Roaming          bool
	DataConnected    bool
	APN              string

	// Faults and capability shape.
	SIMState     proto.SIMState
	ModemState   proto.ModemState
	VoiceControl bool
	VoiceAudio   bool
	VoLTE        proto.Tristate
	SMSSupported bool
}

// Preset scenarios for the three mainland operators, so a multi-Node demo
// looks like a real household rather than three copies of one device.
var (
	ChinaMobile = Scenario{
		OperatorName: "中国移动", OperatorCode: "46000",
		ICCID: "89860412345678901234", IMSI: "460001234567890",
		PhoneNumber: "+8613800138000",
		SignalDBM:   -76, AccessTechnology: proto.AccessLTE,
		Registration: proto.RegRegistered, DataConnected: true, APN: "cmnet",
		SIMState: proto.SIMReady, ModemState: proto.ModemReady,
		VoiceControl: true, VoiceAudio: false, VoLTE: proto.TriUnknown, SMSSupported: true,
	}
	ChinaUnicom = Scenario{
		OperatorName: "中国联通", OperatorCode: "46001",
		ICCID: "89860298765432109876", IMSI: "460019876543210",
		PhoneNumber: "+8613100131000",
		SignalDBM:   -83, AccessTechnology: proto.AccessLTE,
		Registration: proto.RegRegistered, DataConnected: true, APN: "3gnet",
		SIMState: proto.SIMReady, ModemState: proto.ModemReady,
		VoiceControl: false, VoiceAudio: false, VoLTE: proto.TriUnknown, SMSSupported: true,
	}
	ChinaTelecom = Scenario{
		OperatorName: "中国电信", OperatorCode: "46011",
		ICCID: "89860311122233344455", IMSI: "460111112223334",
		PhoneNumber: "+8618000180000",
		SignalDBM:   -91, AccessTechnology: proto.AccessLTE,
		Registration: proto.RegRegistered, DataConnected: true, APN: "ctnet",
		SIMState: proto.SIMReady, ModemState: proto.ModemReady,
		VoiceControl: true, VoiceAudio: true, VoLTE: proto.TriYes, SMSSupported: true,
	}
)

// ScenarioByName resolves a preset for command-line use.
func ScenarioByName(name string) (Scenario, bool) {
	switch name {
	case "mobile", "cmcc", "china-mobile":
		return ChinaMobile, true
	case "unicom", "cu", "china-unicom":
		return ChinaUnicom, true
	case "telecom", "ct", "china-telecom":
		return ChinaTelecom, true
	}
	return Scenario{}, false
}

// Backend is a mock modem. It is safe for concurrent use.
type Backend struct {
	mu       sync.Mutex
	scenario Scenario
	deviceID string
	now      func() time.Time

	messages  []proto.SMS
	calls     []proto.Call
	sequence  int
	requests  map[string]proto.SendSMSResponse
	dialIDs   map[string]proto.CallReceipt
	observers []chan modembackend.Event

	restartUntil time.Time
}

// Options configures a mock Backend.
type Options struct {
	Scenario Scenario
	DeviceID string
	Now      func() time.Time
}

// New builds a mock backend.
func New(options Options) *Backend {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	scenario := options.Scenario
	if scenario.ModemState == "" {
		scenario.ModemState = proto.ModemReady
	}
	if scenario.SIMState == "" {
		scenario.SIMState = proto.SIMReady
	}
	if scenario.AccessTechnology == "" {
		scenario.AccessTechnology = proto.AccessUnknown
	}
	if scenario.Registration == "" {
		scenario.Registration = proto.RegUnknown
	}
	if scenario.VoLTE == "" {
		scenario.VoLTE = proto.TriUnknown
	}
	return &Backend{
		scenario: scenario,
		deviceID: options.DeviceID,
		now:      now,
		requests: map[string]proto.SendSMSResponse{},
		dialIDs:  map[string]proto.CallReceipt{},
	}
}

func (b *Backend) Name() string { return "mock" }

func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, observer := range b.observers {
		close(observer)
	}
	b.observers = nil
	return nil
}

// modemStateLocked resolves the effective modem state, accounting for a
// scripted restart that has not finished yet.
func (b *Backend) modemStateLocked() proto.ModemState {
	if !b.restartUntil.IsZero() {
		if b.now().Before(b.restartUntil) {
			return proto.ModemRestarting
		}
		b.restartUntil = time.Time{}
		b.scenario.ModemState = proto.ModemReady
	}
	return b.scenario.ModemState
}

// online reports whether the radio can serve a request at all.
func (b *Backend) onlineLocked() bool {
	return b.modemStateLocked() == proto.ModemReady
}

func (b *Backend) Capabilities(context.Context) (proto.Capabilities, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	online := b.onlineLocked()
	return proto.Capabilities{
		// An offline modem advertises no radio capability. Reporting SMS as
		// available while the modem is down would let the UI offer a send
		// button that can only fail.
		SMS:              b.scenario.SMSSupported && online,
		MobileData:       online && b.scenario.DataConnected,
		VoiceControl:     b.scenario.VoiceControl && online,
		VoiceAudio:       b.scenario.VoiceAudio && online,
		VoLTE:            b.scenario.VoLTE,
		WiFiProvisioning: true,
		Logs:             true,
		OTA:              false,
	}, nil
}

func (b *Backend) GetStatus(ctx context.Context) (proto.ModemStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	observed := b.now().UTC()
	state := b.modemStateLocked()
	status := proto.ModemStatus{
		State:      state,
		SIM:        b.simLocked(observed),
		Network:    b.networkLocked(observed),
		Signal:     b.signalLocked(observed),
		ObservedAt: observed,
	}
	switch state {
	case proto.ModemOffline:
		status.Reason = "modem is not responding"
	case proto.ModemRestarting:
		status.Reason = "modem is restarting"
	case proto.ModemFailed:
		status.Reason = "modem reported a failure"
	}
	return status, nil
}

func (b *Backend) simLocked(observed time.Time) proto.SIMInfo {
	if !b.onlineLocked() {
		return proto.SIMInfo{State: proto.SIMUnknown, ObservedAt: observed}
	}
	info := proto.SIMInfo{State: b.scenario.SIMState, ObservedAt: observed}
	switch b.scenario.SIMState {
	case proto.SIMReady:
		info.ICCID = b.scenario.ICCID
		info.IMSI = b.scenario.IMSI
		info.OperatorName = b.scenario.OperatorName
		info.OperatorCode = b.scenario.OperatorCode
		info.PhoneNumber = b.scenario.PhoneNumber
	case proto.SIMPINLocked:
		retries := 3
		info.PINRetries = &retries
		// A PIN-locked card still reports its ICCID; that is what lets the NAS
		// recognise which card is waiting for a PIN.
		info.ICCID = b.scenario.ICCID
	case proto.SIMPUKLocked:
		retries := 0
		info.PINRetries = &retries
		info.ICCID = b.scenario.ICCID
	}
	return info
}

func (b *Backend) networkLocked(observed time.Time) proto.NetworkStatus {
	if !b.onlineLocked() || b.scenario.SIMState != proto.SIMReady {
		return proto.NetworkStatus{
			Registration:     proto.RegUnregistered,
			AccessTechnology: proto.AccessUnknown,
			ObservedAt:       observed,
		}
	}
	return proto.NetworkStatus{
		Registration:     b.scenario.Registration,
		AccessTechnology: b.scenario.AccessTechnology,
		OperatorName:     b.scenario.OperatorName,
		OperatorCode:     b.scenario.OperatorCode,
		Roaming:          b.scenario.Roaming,
		DataConnected:    b.scenario.DataConnected,
		APN:              b.scenario.APN,
		IPv4:             "10.64.0.2",
		ObservedAt:       observed,
	}
}

func (b *Backend) signalLocked(observed time.Time) proto.Signal {
	if !b.onlineLocked() || b.scenario.SIMState != proto.SIMReady {
		return proto.Signal{Known: false, ObservedAt: observed}
	}
	dbm := b.scenario.SignalDBM
	rsrp := dbm - 20
	rsrq := -10.5
	snr := 12.0
	return proto.Signal{
		DBM:        &dbm,
		RSRP:       &rsrp,
		RSRQ:       &rsrq,
		SNR:        &snr,
		Bars:       proto.BarsFromDBM(dbm),
		Known:      true,
		ObservedAt: observed,
	}
}

func (b *Backend) GetSIMInfo(context.Context) (proto.SIMInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.simLocked(b.now().UTC()), nil
}

func (b *Backend) GetNetwork(context.Context) (proto.NetworkStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.networkLocked(b.now().UTC()), nil
}

func (b *Backend) GetSignal(context.Context) (proto.Signal, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.signalLocked(b.now().UTC()), nil
}

func (b *Backend) ListSMS(context.Context) ([]proto.SMS, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.onlineLocked() {
		return nil, proto.Unavailable("list_sms", "modem is not available", nil)
	}
	copied := make([]proto.SMS, len(b.messages))
	copy(copied, b.messages)
	return copied, nil
}

func (b *Backend) SendSMS(_ context.Context, request proto.SendSMSRequest) (proto.SendSMSResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if request.RequestID == "" {
		return proto.SendSMSResponse{}, proto.InvalidArgument("send_sms", "request_id is required")
	}
	// Idempotency first: a retry after a dropped link must not send twice.
	if existing, ok := b.requests[request.RequestID]; ok {
		return existing, nil
	}
	if !b.scenario.SMSSupported {
		return proto.SendSMSResponse{}, proto.NotSupported("send_sms", "this node has no messaging capability")
	}
	if !b.onlineLocked() {
		return proto.SendSMSResponse{}, proto.Unavailable("send_sms", "modem is not available", nil)
	}
	if b.scenario.SIMState != proto.SIMReady {
		return proto.SendSMSResponse{}, proto.FailedPrecondition("send_sms", fmt.Sprintf("sim is %s", b.scenario.SIMState))
	}
	if request.To == "" {
		return proto.SendSMSResponse{}, proto.InvalidArgument("send_sms", "to is required")
	}
	if request.Text == "" {
		return proto.SendSMSResponse{}, proto.InvalidArgument("send_sms", "text is required")
	}

	b.sequence++
	message := proto.SMS{
		ID:        fmt.Sprintf("sms-%d", b.sequence),
		SIMID:     b.scenario.ICCID,
		Direction: proto.DirectionOutgoing,
		State:     proto.SMSSent,
		Peer:      request.To,
		Text:      request.Text,
		Timestamp: b.now().UTC(),
	}
	b.messages = append(b.messages, message)
	response := proto.SendSMSResponse{RequestID: request.RequestID, MessageID: message.ID, State: message.State}
	b.requests[request.RequestID] = response
	b.emitLocked(modembackend.Event{Kind: modembackend.EventSMS, MessageID: message.ID, SIMID: message.SIMID})
	return response, nil
}

func (b *Backend) DeleteSMS(_ context.Context, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for index, message := range b.messages {
		if message.ID == id {
			b.messages = append(b.messages[:index], b.messages[index+1:]...)
			return nil
		}
	}
	return proto.NotFound("delete_sms", "message does not exist")
}

func (b *Backend) ListCalls(context.Context) ([]proto.Call, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.onlineLocked() {
		return nil, proto.Unavailable("list_calls", "modem is not available", nil)
	}
	copied := make([]proto.Call, len(b.calls))
	copy(copied, b.calls)
	return copied, nil
}

func (b *Backend) Dial(_ context.Context, request proto.DialRequest) (proto.CallReceipt, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if request.RequestID == "" {
		return proto.CallReceipt{}, proto.InvalidArgument("dial", "request_id is required")
	}
	if existing, ok := b.dialIDs[request.RequestID]; ok {
		return existing, nil
	}
	// The capability gate comes before any other validation so that a Node
	// without telephony answers the same way regardless of the argument.
	if !b.scenario.VoiceControl {
		return proto.CallReceipt{}, proto.NotSupported("dial", "this node has no voice control capability")
	}
	if !b.onlineLocked() {
		return proto.CallReceipt{}, proto.Unavailable("dial", "modem is not available", nil)
	}
	if b.scenario.SIMState != proto.SIMReady {
		return proto.CallReceipt{}, proto.FailedPrecondition("dial", fmt.Sprintf("sim is %s", b.scenario.SIMState))
	}
	if request.To == "" {
		return proto.CallReceipt{}, proto.InvalidArgument("dial", "to is required")
	}
	for _, call := range b.calls {
		if call.State != proto.CallTerminated {
			return proto.CallReceipt{}, proto.Conflict("dial", "another call is already in progress")
		}
	}

	b.sequence++
	call := proto.Call{
		ID:        fmt.Sprintf("call-%d", b.sequence),
		SIMID:     b.scenario.ICCID,
		Direction: proto.DirectionOutgoing,
		State:     proto.CallDialing,
		Peer:      request.To,
		StartedAt: b.now().UTC(),
	}
	b.calls = append(b.calls, call)
	receipt := proto.CallReceipt{RequestID: request.RequestID, CallID: call.ID, State: call.State}
	b.dialIDs[request.RequestID] = receipt
	b.emitLocked(modembackend.Event{Kind: modembackend.EventCall, CallID: call.ID, SIMID: call.SIMID, Detail: string(call.State)})
	return receipt, nil
}

func (b *Backend) Answer(_ context.Context, callID string) (proto.CallReceipt, error) {
	return b.transition("answer", callID, func(call *proto.Call) error {
		if !b.scenario.VoiceControl {
			return proto.NotSupported("answer", "this node has no voice control capability")
		}
		if call.State != proto.CallRinging {
			return proto.FailedPrecondition("answer", fmt.Sprintf("call is %s, not ringing", call.State))
		}
		answered := b.now().UTC()
		call.State = proto.CallActive
		call.AnsweredAt = &answered
		return nil
	})
}

func (b *Backend) Hangup(_ context.Context, callID string) (proto.CallReceipt, error) {
	return b.transition("hangup", callID, func(call *proto.Call) error {
		if call.State == proto.CallTerminated {
			// Hanging up an already-ended call is not an error. A NAS retrying
			// after a link drop must be able to converge on "the call is over".
			return nil
		}
		ended := b.now().UTC()
		call.State = proto.CallTerminated
		call.EndedAt = &ended
		call.EndReason = "local_hangup"
		return nil
	})
}

func (b *Backend) transition(operation, callID string, apply func(*proto.Call) error) (proto.CallReceipt, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.onlineLocked() {
		return proto.CallReceipt{}, proto.Unavailable(operation, "modem is not available", nil)
	}
	for index := range b.calls {
		if b.calls[index].ID != callID {
			continue
		}
		if err := apply(&b.calls[index]); err != nil {
			return proto.CallReceipt{}, err
		}
		call := b.calls[index]
		b.emitLocked(modembackend.Event{Kind: modembackend.EventCall, CallID: call.ID, SIMID: call.SIMID, Detail: string(call.State)})
		return proto.CallReceipt{CallID: call.ID, State: call.State}, nil
	}
	return proto.CallReceipt{}, proto.NotFound(operation, "call does not exist")
}

func (b *Backend) GetVoiceCapability(context.Context) (modembackend.VoiceCapability, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	capability := modembackend.VoiceCapability{
		Control: b.scenario.VoiceControl && b.onlineLocked(),
		Audio:   b.scenario.VoiceAudio && b.onlineLocked(),
		VoLTE:   b.scenario.VoLTE,
		Source:  "mock-scenario",
	}
	switch {
	case !b.onlineLocked():
		capability.Reason = "modem is not available"
	case !b.scenario.VoiceControl:
		capability.Reason = "scenario does not provide voice control"
	case !b.scenario.VoiceAudio:
		capability.Reason = "call control is available but no host audio path is configured"
	}
	return capability, nil
}

// Subscribe implements modembackend.EventSource.
func (b *Backend) Subscribe(ctx context.Context) (<-chan modembackend.Event, error) {
	b.mu.Lock()
	stream := make(chan modembackend.Event, 16)
	b.observers = append(b.observers, stream)
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		b.mu.Lock()
		defer b.mu.Unlock()
		for index, observer := range b.observers {
			if observer == stream {
				b.observers = append(b.observers[:index], b.observers[index+1:]...)
				close(stream)
				return
			}
		}
	}()
	return stream, nil
}

func (b *Backend) emitLocked(event modembackend.Event) {
	for _, observer := range b.observers {
		select {
		case observer <- event:
		default:
			// A subscriber that cannot keep up loses events rather than
			// blocking the modem. Core re-reads state on reconnect, so a
			// dropped notification costs a refresh, not correctness.
		}
	}
}

// ---------------------------------------------------------------------------
// Scenario control. These are the levers the mock Node CLI and the tests pull.
// ---------------------------------------------------------------------------

// InjectIncomingSMS delivers a message as if the network had sent it.
func (b *Backend) InjectIncomingSMS(from, text string) (proto.SMS, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.onlineLocked() {
		return proto.SMS{}, proto.Unavailable("inject_sms", "modem is not available", nil)
	}
	if b.scenario.SIMState != proto.SIMReady {
		return proto.SMS{}, proto.FailedPrecondition("inject_sms", "sim is not ready")
	}
	b.sequence++
	message := proto.SMS{
		ID:        fmt.Sprintf("sms-%d", b.sequence),
		SIMID:     b.scenario.ICCID,
		Direction: proto.DirectionIncoming,
		State:     proto.SMSReceived,
		Peer:      from,
		Text:      text,
		Timestamp: b.now().UTC(),
	}
	b.messages = append(b.messages, message)
	b.emitLocked(modembackend.Event{Kind: modembackend.EventSMS, MessageID: message.ID, SIMID: message.SIMID})
	return message, nil
}

// InjectIncomingCall makes the Node ring.
func (b *Backend) InjectIncomingCall(from string) (proto.Call, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.onlineLocked() {
		return proto.Call{}, proto.Unavailable("inject_call", "modem is not available", nil)
	}
	if !b.scenario.VoiceControl {
		return proto.Call{}, proto.NotSupported("inject_call", "this node has no voice capability")
	}
	b.sequence++
	call := proto.Call{
		ID:        fmt.Sprintf("call-%d", b.sequence),
		SIMID:     b.scenario.ICCID,
		Direction: proto.DirectionIncoming,
		State:     proto.CallRinging,
		Peer:      from,
		StartedAt: b.now().UTC(),
	}
	b.calls = append(b.calls, call)
	b.emitLocked(modembackend.Event{Kind: modembackend.EventCall, CallID: call.ID, SIMID: call.SIMID, Detail: string(call.State)})
	return call, nil
}

// SetSIMState simulates insertion, removal and lock states.
func (b *Backend) SetSIMState(state proto.SIMState) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.scenario.SIMState = state
	b.emitLocked(modembackend.Event{Kind: modembackend.EventSIMState, Detail: string(state)})
}

// SetModemState takes the radio up or down.
func (b *Backend) SetModemState(state proto.ModemState) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.scenario.ModemState = state
	b.restartUntil = time.Time{}
	b.emitLocked(modembackend.Event{Kind: modembackend.EventModemState, Detail: string(state)})
}

// RestartModem puts the radio into ModemRestarting for the given duration and
// then returns it to ready, which is what a real reset looks like to Core.
func (b *Backend) RestartModem(duration time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.scenario.ModemState = proto.ModemRestarting
	b.restartUntil = b.now().Add(duration)
	// An in-progress call does not survive a modem reset.
	for index := range b.calls {
		if b.calls[index].State != proto.CallTerminated {
			ended := b.now().UTC()
			b.calls[index].State = proto.CallTerminated
			b.calls[index].EndedAt = &ended
			b.calls[index].EndReason = "modem_restart"
		}
	}
	b.emitLocked(modembackend.Event{Kind: modembackend.EventModemState, Detail: string(proto.ModemRestarting)})
}

// SetSignalDBM changes reported radio quality.
func (b *Backend) SetSignalDBM(dbm float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.scenario.SignalDBM = dbm
	b.emitLocked(modembackend.Event{Kind: modembackend.EventSignal, Detail: fmt.Sprintf("%.0f", dbm)})
}

// SetRegistration changes network attachment, for simulating a network switch.
func (b *Backend) SetRegistration(state proto.RegistrationState, technology proto.AccessTechnology) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.scenario.Registration = state
	b.scenario.AccessTechnology = technology
	b.emitLocked(modembackend.Event{Kind: modembackend.EventNetwork, Detail: string(state)})
}

// SetVoiceCapability rewrites the capability shape at runtime, which is how a
// test proves the UI reacts to capability rather than to hardware model.
func (b *Backend) SetVoiceCapability(control, audio bool, volte proto.Tristate) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.scenario.VoiceControl = control
	b.scenario.VoiceAudio = audio
	b.scenario.VoLTE = volte
}

// Scenario returns a copy of the current steady state.
func (b *Backend) Scenario() Scenario {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.scenario
}

var _ modembackend.Backend = (*Backend)(nil)
var _ modembackend.EventSource = (*Backend)(nil)
