// Package media is the interface real-time audio will use, and the rule that
// keeps it off the control transport.
//
// Nothing here implements audio. There is no Opus encoder, no SRTP, no jitter
// buffer, and no packet ever leaves this package. What it defines is the shape
// of the thing that will, and - more importantly - the boundary that must not
// be crossed while it does not exist.
//
// # Why audio must not use the reliable transport
//
// Reliability and real time are opposing goals, and the opposition is not a
// matter of degree.
//
// A reliable ordered stream delivers byte N before byte N+1, always. When a
// packet is lost, everything behind it waits for the retransmission - so a
// single loss on a 200 ms link costs 400 ms, and during those 400 ms the audio
// that was recorded meanwhile keeps arriving and queueing. The delay does not
// recover; it accumulates. Twenty seconds into a bad call the two people are a
// second and a half apart and talking over each other.
//
// Real-time audio wants the opposite trade. A lost 20 ms frame should be
// concealed - the decoder interpolates, the listener hears a faint artefact -
// and the stream should stay current. A frame that arrives after its playout
// deadline is worthless and must be discarded, not delivered.
//
// So: control uses KCP, media must not. That is not a performance preference,
// it is the difference between a call that degrades and a call that collapses.
// The structural test in the integration suite enforces it by checking that
// nothing in this package is reachable from the control transport, because a
// rule documented and not enforced is a rule that lasts until the first person
// in a hurry.
//
// # What a real implementation will need
//
//	Opus            the codec; frames are independent, which is what makes
//	                concealment possible at all
//	SRTP            media encryption, keyed from the control channel's TLS
//	                session - not a second identity, not a second pairing
//	QUIC datagrams  or plain UDP: unreliable, unordered, and that is correct
//	FEC             in-band parity, because retransmission is not available
//	Jitter buffer   adaptive, bounded; the bound is a latency budget
//	PLC             packet loss concealment in the decoder
//
// All of it is hardware-phase work. On MSM8916 it also depends on the audio
// path existing at all, which is a question about q6voice and ALSA rather than
// about this interface.
package media

import (
	"errors"
	"time"
)

// ErrNotImplemented reports that real-time media does not exist yet.
//
// Every method returns it. That is deliberate: an interface whose methods
// silently did nothing would let a caller be written against it and appear to
// work, and the failure would surface as a silent call with no audio.
var ErrNotImplemented = errors.New(
	"media: real-time audio is not implemented in the software-only stage")

// ErrReliableTransport reports an attempt to carry media over a reliable
// transport.
//
// It exists so the refusal has a name a test can assert on and a person can
// search for.
var ErrReliableTransport = errors.New(
	"media: real-time audio must not use a reliable transport; " +
		"head-of-line blocking turns a lost frame into accumulating delay")

// Frame is one unit of encoded audio.
//
// It carries a sequence number and a timestamp because concealment needs to
// know what is missing and playout needs to know when a frame was for - and it
// carries a deadline because a frame that misses it must be dropped rather than
// played late.
type Frame struct {
	Sequence  uint16
	Timestamp uint32
	Payload   []byte
	// Deadline is when this frame stops being worth playing.
	Deadline time.Time
}

// TransportKind is what carries media. The list is exhaustive on purpose: a
// reliable transport is not on it.
type TransportKind string

const (
	// KindDatagram is an unreliable datagram flow - QUIC datagrams, or plain
	// UDP. The only two acceptable answers.
	KindDatagram TransportKind = "datagram"
	// KindNone is the current state.
	KindNone TransportKind = "none"
)

// MediaTransport carries real-time audio.
//
// Send does not block and does not retry. A frame that cannot go now is
// dropped, because by the time it could go it would be too late to play.
type MediaTransport interface {
	// Kind reports what carries the media. It must never be a reliable
	// transport; see Policy below.
	Kind() TransportKind
	// Send transmits one frame, best effort.
	Send(frame Frame) error
	// Receive returns the next frame that is still worth playing.
	Receive() (Frame, error)
	// Stats reports delivery quality.
	Stats() Stats
	// Close releases the flow.
	Close() error
}

// Stats is what a media flow reports. Counters and timings only - never
// payload, and never anything from which speech could be reconstructed.
type Stats struct {
	FramesSent      uint64
	FramesReceived  uint64
	FramesLost      uint64
	FramesLate      uint64
	FramesConcealed uint64
	JitterBufferMS  int
	RoundTripMS     int
}

// Unavailable is the MediaTransport this stage ships.
//
// It refuses everything. A caller that somehow reaches it gets an error naming
// the stage rather than silence.
type Unavailable struct{}

// Kind reports that nothing carries media yet.
func (Unavailable) Kind() TransportKind { return KindNone }

// Send refuses.
func (Unavailable) Send(Frame) error { return ErrNotImplemented }

// Receive refuses.
func (Unavailable) Receive() (Frame, error) { return Frame{}, ErrNotImplemented }

// Stats reports nothing, because nothing has happened.
func (Unavailable) Stats() Stats { return Stats{} }

// Close succeeds; there is nothing to release.
func (Unavailable) Close() error { return nil }

// Policy is the rule, in code.
//
// A real implementation calls this before binding to a transport, so that
// wiring media onto the control channel fails at construction rather than in
// production on someone's call.
func Policy(kind TransportKind, reliable bool) error {
	if reliable {
		return ErrReliableTransport
	}
	switch kind {
	case KindDatagram:
		return nil
	case KindNone:
		return ErrNotImplemented
	default:
		return errors.New("media: unknown transport kind " + string(kind))
	}
}
