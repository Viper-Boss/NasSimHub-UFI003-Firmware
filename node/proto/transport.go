package proto

import (
	"fmt"
	"time"
)

// Transport selection.
//
// Four modes, one protocol. The business layer - SMS, calls, pairing,
// diagnostics, events - does not know which one is in use and must never learn:
// every mode carries the same NasSimHub Node Protocol over the same TLS 1.3
// session, and the only difference is what moves the bytes underneath.
//
//	NasSimHub Protocol
//	  └── TLS 1.3 (hybrid post-quantum)
//	        └── STANDARD: TCP        KCP: reliable stream over UDP        QUIC: streams
//
// KCP is below TLS, not beside it. It provides reliability - ordering,
// retransmission, congestion control, optionally forward error correction - and
// nothing else. It holds no keys, authenticates nothing, and has no notion of
// who the peer is. Putting a pre-shared key or a home-made AEAD into it, which
// is what most KCP deployments do, would create a second security mechanism
// whose failures the pinning model cannot see.

// TransportMode is how a Node is reached.
type TransportMode string

const (
	// TransportStandard is TCP. The default, and what every deployment should
	// use unless something specific is wrong.
	TransportStandard TransportMode = "standard"
	// TransportKCP is a reliable stream over UDP, for links that lose packets.
	TransportKCP TransportMode = "kcp"
	// TransportQUIC is QUIC. See xport/quicmock for what exists today.
	TransportQUIC TransportMode = "quic"
	// TransportAuto lets the product choose - conservatively. See
	// AutoSelect below: it never chooses KCP on its own.
	TransportAuto TransportMode = "auto"
)

// ValidateTransportMode rejects an unknown mode rather than defaulting.
func ValidateTransportMode(mode TransportMode) error {
	switch mode {
	case TransportStandard, TransportKCP, TransportQUIC, TransportAuto:
		return nil
	default:
		return fmt.Errorf("unknown transport mode %q; use standard, kcp, quic or auto", mode)
	}
}

// LinkSample is one observation of link quality.
type LinkSample struct {
	PacketLoss  float64       `json:"packet_loss"`
	RTT         time.Duration `json:"rtt"`
	Jitter      time.Duration `json:"jitter"`
	Retransmits int           `json:"retransmits"`
	At          time.Time     `json:"at"`
}

// LinkAdvice is what the product tells the user about their link.
type LinkAdvice string

const (
	// AdviceNormal means the link is fine and nothing should change.
	AdviceNormal LinkAdvice = "normal"
	// AdviceWeakNetwork means a weak-network transport would probably help.
	AdviceWeakNetwork LinkAdvice = "weak_network"
	// AdviceSevereLoss means the link is bad enough that the user should be
	// told regardless of which transport they choose.
	AdviceSevereLoss LinkAdvice = "severe_loss"
)

// Thresholds for advice. They are exported so a test can state them rather
// than rediscover them, and so the documentation cannot drift from the code.
const (
	// WeakNetworkLoss is where a reliable-UDP transport starts to earn its
	// overhead. Below this, TCP's own retransmission handles it and KCP just
	// adds bytes.
	WeakNetworkLoss = 0.02
	// SevereLoss is where the user should be told something is wrong with
	// their network rather than with the product.
	SevereLoss = 0.08
	// WeakNetworkRTT is a round trip long enough that TCP's recovery costs
	// whole seconds.
	WeakNetworkRTT = 250 * time.Millisecond
	// SevereRTT is where interactive use stops working.
	SevereRTT = 700 * time.Millisecond
)

// Recommender turns a stream of link samples into advice, slowly.
//
// Slowly is the point. A recommendation that flickers between "normal" and
// "weak network" every few seconds is worse than no recommendation: it teaches
// the user to ignore it, and if it were ever wired to switch transports
// automatically it would spend its time reconnecting instead of working.
//
// Two mechanisms enforce that, and they are different:
//
//   - Consecutive agreement. A change needs several samples in a row pointing
//     the same way, so one bad moment does not move the needle.
//   - Dwell time. Even with agreement, advice does not change again until it
//     has held for a minimum period. This is what stops a link sitting exactly
//     on a threshold from oscillating.
//
// Together they are hysteresis: getting worse and getting better use the same
// thresholds, but crossing them costs time in both directions.
type Recommender struct {
	// Samples is how many consecutive samples must agree. Zero uses 5.
	Samples int
	// Dwell is the minimum time advice must hold. Zero uses 60s.
	Dwell time.Duration
	// Now is injected for tests.
	Now func() time.Time

	current   LinkAdvice
	candidate LinkAdvice
	agreeing  int
	changedAt time.Time
}

// NewRecommender builds one that starts out believing the link is fine.
func NewRecommender() *Recommender {
	return &Recommender{current: AdviceNormal}
}

// classify is the instantaneous reading of one sample, before any smoothing.
func classify(sample LinkSample) LinkAdvice {
	switch {
	case sample.PacketLoss >= SevereLoss || sample.RTT >= SevereRTT:
		return AdviceSevereLoss
	case sample.PacketLoss >= WeakNetworkLoss || sample.RTT >= WeakNetworkRTT:
		return AdviceWeakNetwork
	default:
		return AdviceNormal
	}
}

// Observe feeds in a sample and returns the advice to show.
func (r *Recommender) Observe(sample LinkSample) LinkAdvice {
	now := r.Now
	if now == nil {
		now = time.Now
	}
	samples := r.Samples
	if samples <= 0 {
		samples = 5
	}
	dwell := r.Dwell
	if dwell <= 0 {
		dwell = 60 * time.Second
	}
	if r.current == "" {
		r.current = AdviceNormal
	}
	at := sample.At
	if at.IsZero() {
		at = now()
	}
	if r.changedAt.IsZero() {
		r.changedAt = at
	}

	reading := classify(sample)
	if reading == r.current {
		// Agreement with what is already shown resets the count towards a
		// change: a run of "things are fine" should undo a partial run of
		// "things are bad", not sit alongside it.
		r.candidate = ""
		r.agreeing = 0
		return r.current
	}
	if reading != r.candidate {
		r.candidate = reading
		r.agreeing = 1
		return r.current
	}
	r.agreeing++
	if r.agreeing < samples {
		return r.current
	}
	if at.Sub(r.changedAt) < dwell {
		// Enough agreement, not enough time. The advice stands.
		return r.current
	}
	r.current = reading
	r.candidate = ""
	r.agreeing = 0
	r.changedAt = at
	return r.current
}

// Advice reports the current recommendation without feeding a sample.
func (r *Recommender) Advice() LinkAdvice {
	if r.current == "" {
		return AdviceNormal
	}
	return r.current
}

// AutoSelect resolves TransportAuto to a concrete mode.
//
// It never returns TransportKCP. That is the conservative policy stated for
// this first version, and it is a policy rather than a limitation: switching a
// working connection onto a different transport without being asked is a
// decision with user-visible consequences - a reconnect, a new session, a
// moment where a message might be in flight - and the product does not yet have
// enough evidence about real links to make it well. Advice is offered; the
// choice stays with the user.
//
// quicReady is whether a real QUIC transport is available in this build. It is
// false in the software-only stage, so AUTO resolves to STANDARD.
func AutoSelect(advice LinkAdvice, quicReady bool) TransportMode {
	if quicReady {
		return TransportQUIC
	}
	return TransportStandard
}

// TransportStatus is what the status page shows.
//
// Every field here is an observation about the link. None of it is key
// material, and none of it can be: the counters come from the reliability layer
// underneath TLS, which has no access to keys by construction.
type TransportStatus struct {
	Mode       TransportMode  `json:"mode"`
	Resolved   TransportMode  `json:"resolved_mode"`
	Advice     LinkAdvice     `json:"advice"`
	Connection ConnectionType `json:"connection_type"`

	RTT         time.Duration `json:"rtt"`
	Jitter      time.Duration `json:"jitter"`
	PacketLoss  float64       `json:"packet_loss"`
	Retransmits int           `json:"retransmits"`

	FECRecovered int     `json:"fec_recovered"`
	FECOverhead  float64 `json:"fec_overhead"`

	Security SecurityCapability `json:"security"`
}

// ---------------------------------------------------------------------------
// Control plane and media plane
// ---------------------------------------------------------------------------

// PlaneKind separates what may use a reliable transport from what must not.
type PlaneKind string

const (
	// PlaneControl is everything the Node Protocol carries: API calls, SMS,
	// call control, events, pairing, diagnostics. All of it must arrive, in
	// order, exactly once - so a reliable transport is right for it.
	PlaneControl PlaneKind = "control"

	// PlaneMedia is real-time audio. It must NOT use a reliable transport.
	//
	// The reason is not efficiency, it is that reliability and real-time are
	// contradictory goals. A reliable stream delays everything behind a lost
	// packet until that packet has been retransmitted; for a voice call that
	// turns a 40 ms glitch into a growing delay that never recovers, because
	// the audio behind it keeps arriving while the stream waits. Voice wants
	// the opposite trade: drop the late packet, conceal the gap, stay current.
	//
	// Hence MediaTransport as a separate interface, and the structural test
	// that keeps audio out of the control transport.
	PlaneMedia PlaneKind = "media"
)

// ---------------------------------------------------------------------------
// Replay safety
// ---------------------------------------------------------------------------

// SideEffecting reports whether a request may not be replayed.
//
// This exists for 0-RTT. QUIC's early data can be replayed by an attacker who
// captured it - that is inherent to how it works, not a defect - so an endpoint
// that changes something must never be reachable over it. Sending a message
// twice because a recording was replayed is exactly the failure a user cannot
// be asked to tolerate.
//
// The rule is a deny-list of methods plus a deny-list of paths, and it is
// deliberately conservative in both directions: anything that is not a plain
// read is side-effecting, and the read paths that ARE allowed are enumerated
// rather than inferred, so a new endpoint is unsafe until someone has thought
// about it.
func SideEffecting(method, path string) bool {
	switch method {
	case "GET", "HEAD":
		// Even a GET can be side-effecting or privacy-relevant. Only the
		// paths listed below are considered replay-safe.
		return !replaySafePaths[path]
	default:
		return true
	}
}

// replaySafePaths are the reads that carry no side effect and no private
// content, so replaying one tells an attacker nothing they could not get by
// connecting themselves.
//
// /v1/node and /v1/health are already served without authentication, which is
// the strongest possible argument that replaying them leaks nothing.
//
// Notably absent: /v1/sms, /v1/calls, /v1/sim, /v1/logs, /v1/diagnostics,
// /v1/events. Those are reads, but a replayed read returns subscriber data to
// whoever replayed it.
var replaySafePaths = map[string]bool{
	"/v1/node":   true,
	"/v1/health": true,
}

// ReplaySafePaths lists the allow-list, for tests and documentation.
func ReplaySafePaths() []string {
	paths := make([]string, 0, len(replaySafePaths))
	for path := range replaySafePaths {
		paths = append(paths, path)
	}
	return paths
}
