// Package modembackend defines the single interface every NasSimHub Node
// modem implementation satisfies, and nothing else.
//
// The interface is the contract between the transport-agnostic HTTP layer and
// whatever actually drives a radio. Two implementations exist: mock, which is
// complete and is what the whole system is developed and tested against, and
// msm8916, which is a stub in this stage. The HTTP layer must not be able to
// tell them apart, and must never reach around the interface to ask what kind
// of hardware it is talking to.
package modembackend

import (
	"context"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// Backend is the capability surface of a Node's radio.
//
// Every method may legitimately fail with proto.ErrorNotSupported. Callers must
// consult Capabilities first and must not treat an unsupported operation as a
// malfunction: a Node with no telephony is a correctly working Node, not a
// broken one.
type Backend interface {
	// Name identifies the implementation for diagnostics.
	Name() string

	// Capabilities is the Node's self-description. It may change at runtime -
	// voice capability in particular is only knowable after the modem has come
	// up - so callers must re-read it rather than caching it at start.
	Capabilities(ctx context.Context) (proto.Capabilities, error)

	// GetStatus is the one call that always works, even when the modem is
	// offline. An offline modem reports ModemOffline with a reason; it does not
	// return an error, because "the radio is down" is information the UI needs
	// rather than a failure of the request.
	GetStatus(ctx context.Context) (proto.ModemStatus, error)

	GetSIMInfo(ctx context.Context) (proto.SIMInfo, error)
	GetNetwork(ctx context.Context) (proto.NetworkStatus, error)
	GetSignal(ctx context.Context) (proto.Signal, error)

	ListSMS(ctx context.Context) ([]proto.SMS, error)
	SendSMS(ctx context.Context, request proto.SendSMSRequest) (proto.SendSMSResponse, error)
	DeleteSMS(ctx context.Context, id string) error

	ListCalls(ctx context.Context) ([]proto.Call, error)
	Dial(ctx context.Context, request proto.DialRequest) (proto.CallReceipt, error)
	Answer(ctx context.Context, callID string) (proto.CallReceipt, error)
	Hangup(ctx context.Context, callID string) (proto.CallReceipt, error)

	// GetVoiceCapability is broken out from Capabilities because determining it
	// on real hardware is expensive and intrusive - it may involve probing the
	// modem - while the rest of Capabilities is cheap. Callers that only need
	// to render a status page must not be forced to pay for a voice probe.
	GetVoiceCapability(ctx context.Context) (VoiceCapability, error)

	// Close releases whatever the backend owns.
	Close() error
}

// VoiceCapability is the detailed answer behind Capabilities.VoiceControl.
//
// Control and audio are independent facts and are reported separately. A modem
// can accept ATD and set up a call leg while having no usable PCM path to the
// host; presenting that as a single boolean is what produces a dial button that
// connects a call nobody can hear.
// DTMFSender is optional so frozen modem backends need not implement it.
type DTMFSender interface {
	SendDTMF(context.Context, string, proto.DTMFRequest) (proto.CallReceipt, error)
}

type VoiceCapability struct {
	// Control is whether the Node can originate, answer and end calls.
	Control bool `json:"control"`
	// Audio is whether a two-way media path to the host exists.
	Audio bool `json:"audio"`
	// VoLTE is tri-state: on unflashed MSM8916 hardware it is genuinely
	// unknown, and reporting false would be a claim we have not earned.
	VoLTE proto.Tristate `json:"volte"`
	// Reason explains a negative or unknown answer in human terms.
	Reason string `json:"reason,omitempty"`
	// Source names what produced the verdict, for diagnostics.
	Source string `json:"source,omitempty"`
}

// EventKind classifies an asynchronous backend notification.
type EventKind string

const (
	EventModemState EventKind = "modem_state"
	EventSIMState   EventKind = "sim_state"
	EventNetwork    EventKind = "network"
	EventSignal     EventKind = "signal"
	EventSMS        EventKind = "sms"
	EventCall       EventKind = "call"
)

// Event is an asynchronous notification a backend may emit.
//
// SMS carries the message identifier rather than the body: the event stream is
// a change notification, and putting message text in it would mean the text
// exists in one more place that could be logged.
type Event struct {
	Kind      EventKind `json:"kind"`
	MessageID string    `json:"message_id,omitempty"`
	CallID    string    `json:"call_id,omitempty"`
	SIMID     string    `json:"sim_id,omitempty"`
	Detail    string    `json:"detail,omitempty"`
}

// EventSource is implemented by backends that can push changes. It is optional:
// a backend that cannot observe changes simply omits it, and the HTTP layer
// answers 501 for the event stream rather than pretending.
type EventSource interface {
	Subscribe(ctx context.Context) (<-chan Event, error)
}
