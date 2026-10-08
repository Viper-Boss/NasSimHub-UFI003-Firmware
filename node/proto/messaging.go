package proto

import "time"

// Direction is shared by messages and calls.
type Direction string

const (
	DirectionIncoming Direction = "incoming"
	DirectionOutgoing Direction = "outgoing"
)

// SMSState is the delivery lifecycle of one message on the Node. Core keeps its
// own durable history; these states describe only what the modem knows.
type SMSState string

const (
	SMSReceived SMSState = "received"
	SMSSending  SMSState = "sending"
	SMSSent     SMSState = "sent"
	SMSFailed   SMSState = "failed"
)

// SMS is one message as the Node sees it.
//
// NodeID and SIMID are populated by Core, not by the Node: the Node knows its
// own device_id but a message is only meaningful to Core once it is attributed
// to both the Node and the specific card that carried it. Two Nodes receiving
// a message in the same second must never be able to collapse into one thread,
// which is why SIMID is part of the identity rather than a display field.
type SMS struct {
	ID        string    `json:"id"`
	NodeID    string    `json:"node_id,omitempty"`
	SIMID     string    `json:"sim_id,omitempty"`
	Direction Direction `json:"direction"`
	State     SMSState  `json:"state"`
	Peer      string    `json:"peer"`
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
}

// SendSMSRequest asks the Node to submit one message.
//
// RequestID makes the operation idempotent. A Node that has already accepted a
// RequestID returns the original receipt instead of sending a second message,
// so a Core retry after a dropped USB link cannot double-send.
type SendSMSRequest struct {
	RequestID string `json:"request_id"`
	To        string `json:"to"`
	Text      string `json:"text"`
}

// SendSMSResponse acknowledges submission. It is not a delivery confirmation:
// the caller must read the message back to learn its state.
type SendSMSResponse struct {
	RequestID string   `json:"request_id"`
	MessageID string   `json:"message_id"`
	State     SMSState `json:"state"`
}

// SMSList is the envelope for GET /v1/sms.
type SMSList struct {
	Messages []SMS `json:"messages"`
}

// CallState is the lifecycle of one call leg.
type CallState string

const (
	CallDialing    CallState = "dialing"
	CallRinging    CallState = "ringing"
	CallActive     CallState = "active"
	CallTerminated CallState = "terminated"
)

// Call is one call leg as the Node sees it. Like SMS it carries SIMID so Core
// can attribute it to a card rather than to whatever link happened to be up.
type Call struct {
	ID         string     `json:"id"`
	NodeID     string     `json:"node_id,omitempty"`
	SIMID      string     `json:"sim_id,omitempty"`
	Direction  Direction  `json:"direction"`
	State      CallState  `json:"state"`
	Peer       string     `json:"peer"`
	StartedAt  time.Time  `json:"started_at"`
	AnsweredAt *time.Time `json:"answered_at,omitempty"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
	EndReason  string     `json:"end_reason,omitempty"`
}

// DialRequest asks the Node to originate a call. It is rejected with
// ErrorNotSupported when Capabilities.VoiceControl is false; no Node may be
// assumed to have telephony.
type DialRequest struct {
	RequestID string `json:"request_id"`
	To        string `json:"to"`
}

// DTMFRequest sends one bounded sequence on an already active call. A request
// ID is an at-most-once attempt; an uncertain response must not be retried.
type DTMFRequest struct {
	RequestID string `json:"request_id"`
	Digits    string `json:"digits"`
}

// CallReceipt acknowledges a call command.
type CallReceipt struct {
	RequestID string    `json:"request_id"`
	CallID    string    `json:"call_id"`
	State     CallState `json:"state"`
}

// CallList is the envelope for GET /v1/calls.
type CallList struct {
	Calls []Call `json:"calls"`
}
