// Package kcp is a reliable ordered stream over an unreliable packet link.
//
// It exists for one situation: a link that loses packets. TCP recovers from
// loss on a timescale set by the round trip and by a congestion controller that
// assumes loss means congestion. On a 4G link that drops 5% of packets for
// reasons that have nothing to do with congestion, that assumption is wrong,
// and the result is a connection that spends most of its time waiting. An ARQ
// tuned for loss rather than for congestion recovers in a fraction of the time,
// at the cost of sending more bytes.
//
// # What this layer is and is not
//
// It is reliability: ordering, acknowledgement, retransmission, a send window,
// and optionally forward error correction. That is the whole job.
//
// It is NOT security. There is no key here, no authentication, no notion of who
// the peer is - by design, and against the grain of most KCP deployments, which
// bolt on a pre-shared key and a home-made AEAD. That arrangement creates a
// second security mechanism with its own failure modes, invisible to the
// certificate pinning that is supposed to be deciding who the peer is. Here the
// stack is:
//
//	NasSimHub Protocol → TLS 1.3 (hybrid PQ) → KCP → UDP
//
// TLS sits ABOVE this layer, so every byte KCP moves is already ciphertext and
// KCP could not read it if it wanted to. An attacker who forges KCP segments
// can corrupt or stall a connection - a denial of service, which they could
// achieve by dropping packets anyway - but cannot read, forge or replay
// anything the protocol above cares about, because TLS's own record layer
// rejects it.
//
// # The algorithm
//
// This is the KCP protocol as publicly documented: a 24-byte header, four
// commands, selective acknowledgement, RTT estimation in the style of RFC 6298,
// and fast retransmit after a configurable number of later acknowledgements.
// The implementation is written against that description rather than ported,
// which is why the bounds below exist - every queue has a cap, because the
// reference design has none and an unbounded queue on a 256 MB device is a
// crash waiting for a bad network.
package kcp

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// Wire format.
const (
	// HeaderSize is conv(4) cmd(1) frg(1) wnd(2) ts(4) sn(4) una(4) len(4).
	HeaderSize = 24

	cmdPush = 81 // data
	cmdAck  = 82 // acknowledge
	cmdWask = 83 // ask the peer for its window
	cmdWins = 84 // tell the peer our window
)

// Defaults. Every one of these is also a bound - see the package doc.
const (
	defaultMTU         = 1200 // conservative for the public internet plus tunnels
	defaultSendWindow  = 128
	defaultRecvWindow  = 128
	defaultInterval    = 20 * time.Millisecond
	defaultRTOMin      = 100 * time.Millisecond
	defaultRTOMax      = 30 * time.Second
	defaultDeadLink    = 20 // retransmissions of one segment before giving up
	defaultFastResend  = 2
	maxSegmentBacklog  = 4096 // hard cap on segments held in any one queue
	maxAckBacklog      = 4096
	probeInitial       = 7000 * time.Millisecond
	probeIncrementStep = 2
)

// ErrDeadLink reports a peer that stopped acknowledging.
var ErrDeadLink = errors.New("kcp: peer stopped acknowledging; link is dead")

// ErrOverflow reports a bounded queue that would have grown past its cap.
//
// Returning an error rather than dropping silently is deliberate: the caller
// can slow down, and a connection that is being pushed harder than the link can
// carry should say so rather than accumulate.
var ErrOverflow = errors.New("kcp: send queue is full")

// segment is one unit on the wire.
type segment struct {
	conv     uint32
	cmd      uint8
	frg      uint8 // fragments remaining after this one
	wnd      uint16
	ts       uint32
	sn       uint32
	una      uint32
	resendTS uint32
	rto      uint32
	fastAck  uint32
	xmit     uint32
	data     []byte
}

func (s *segment) encode(buffer []byte) []byte {
	binary.LittleEndian.PutUint32(buffer[0:], s.conv)
	buffer[4] = s.cmd
	buffer[5] = s.frg
	binary.LittleEndian.PutUint16(buffer[6:], s.wnd)
	binary.LittleEndian.PutUint32(buffer[8:], s.ts)
	binary.LittleEndian.PutUint32(buffer[12:], s.sn)
	binary.LittleEndian.PutUint32(buffer[16:], s.una)
	binary.LittleEndian.PutUint32(buffer[20:], uint32(len(s.data)))
	return buffer[HeaderSize:]
}

// Stats is what the diagnostics surface reports.
//
// Counters only - no payload, no addresses, no timing that could identify a
// conversation. See agent/diag for why that boundary is drawn here rather than
// filtered later.
type Stats struct {
	SegmentsSent     uint64
	SegmentsReceived uint64
	BytesSent        uint64
	BytesReceived    uint64
	Retransmits      uint64
	FastRetransmits  uint64
	TimeoutRetrans   uint64
	AcksSent         uint64
	AcksReceived     uint64
	Dropped          uint64
	SRTT             time.Duration
	RTTVar           time.Duration
	RTO              time.Duration
	SendWindow       uint32
	RecvWindow       uint32
	CongestionWindow uint32
	InFlight         int
	SendQueue        int
	RecvQueue        int
}

// Config tunes the ARQ. The named profiles in profile.go are the supported way
// to set these; the fields are exported so a test can be specific.
type Config struct {
	MTU        int
	SendWindow uint32
	RecvWindow uint32
	Interval   time.Duration
	// NoDelay turns off the delayed-acknowledgement style behaviour and makes
	// the RTO grow more slowly, which is the trade a lossy link wants.
	NoDelay bool
	// FastResend retransmits a segment once this many later segments have been
	// acknowledged, without waiting for its timer. Zero disables it.
	FastResend uint32
	// NoCongestionWindow removes the congestion window from the send
	// calculation. Appropriate only where loss genuinely is not congestion,
	// which on a shared link it usually is - hence not the default.
	NoCongestionWindow bool
	// MaxBacklog caps every internal queue. Zero uses maxSegmentBacklog.
	MaxBacklog int
}

// KCP is one direction-independent reliable channel.
//
// It performs no I/O: output is a callback, input is a method. That keeps the
// protocol testable without a network and lets the same state machine sit on a
// UDP socket, on the deterministic emulator, or on a pipe in a test.
type KCP struct {
	mu sync.Mutex

	conv    uint32
	mtu     int
	mss     int
	state   int32
	deadLnk uint32

	sndUna, sndNxt, rcvNxt uint32
	ssthresh               uint32
	rxRTTVal, rxSRTT       int32
	rxRTO, rxMinRTO        int32
	sndWnd, rcvWnd         uint32
	rmtWnd, cwnd, probe    uint32
	interval, tsFlush      uint32
	nodelay, updated       bool
	tsProbe, probeWait     uint32
	incr                   uint32
	fastResend             uint32
	noCwnd                 bool
	maxBacklog             int

	sndQueue []segment
	rcvQueue []segment
	sndBuf   []segment
	rcvBuf   []segment
	ackList  []ackEntry

	buffer []byte
	output func([]byte)
	stats  Stats
	dead   bool
}

type ackEntry struct {
	sn uint32
	ts uint32
}

// New builds a channel. conv must match on both ends; output is called with
// complete datagrams ready to hand to the packet layer.
func New(conv uint32, config Config, output func([]byte)) *KCP {
	k := &KCP{
		conv:   conv,
		sndUna: 0,
		sndNxt: 0,
		rcvNxt: 0,
		// Slow start must actually happen. ikcp initialises the threshold to 2,
		// which with a 128-segment window means the very first acknowledgement
		// leaves slow start and enters congestion avoidance - where the window
		// grows by a fraction of a segment per round trip. The result is a
		// transport that takes seconds to move a quarter of a megabyte on a
		// clean 20 ms link, which the benchmark caught.
		ssthresh:   defaultSendWindow / 2,
		rxRTO:      int32(defaultRTOMin / time.Millisecond),
		rxMinRTO:   int32(defaultRTOMin / time.Millisecond),
		sndWnd:     defaultSendWindow,
		rcvWnd:     defaultRecvWindow,
		rmtWnd:     defaultRecvWindow,
		cwnd:       1,
		interval:   uint32(defaultInterval / time.Millisecond),
		deadLnk:    defaultDeadLink,
		fastResend: defaultFastResend,
		maxBacklog: maxSegmentBacklog,
		output:     output,
	}
	k.applyLocked(config)
	k.buffer = make([]byte, k.mtu+HeaderSize)
	return k
}

func (k *KCP) applyLocked(config Config) {
	k.mtu = defaultMTU
	if config.MTU > HeaderSize+64 {
		k.mtu = config.MTU
	}
	k.mss = k.mtu - HeaderSize
	if config.SendWindow > 0 {
		k.sndWnd = config.SendWindow
		if half := k.sndWnd / 2; half > 2 {
			k.ssthresh = half
		}
	}
	if config.RecvWindow > 0 {
		k.rcvWnd = config.RecvWindow
		k.rmtWnd = config.RecvWindow
	}
	if config.Interval > 0 {
		k.interval = uint32(config.Interval / time.Millisecond)
		if k.interval < 5 {
			k.interval = 5
		}
	}
	k.nodelay = config.NoDelay
	if config.FastResend > 0 {
		k.fastResend = config.FastResend
	}
	k.noCwnd = config.NoCongestionWindow
	if config.MaxBacklog > 0 {
		k.maxBacklog = config.MaxBacklog
	}
	// The receive window must be at least as large as the peer's send window
	// can be, or a full window never drains.
	if k.rcvWnd < 2 {
		k.rcvWnd = 2
	}
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

// Send queues application bytes, fragmenting to the MSS.
//
// It refuses rather than growing without bound: the caller is writing faster
// than the link can carry, and a queue that absorbs that silently turns a slow
// network into an out-of-memory kill.
func (k *KCP) Send(data []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(data) == 0 {
		return nil
	}
	count := (len(data) + k.mss - 1) / k.mss
	if count == 0 {
		count = 1
	}
	if len(k.sndQueue)+count > k.maxBacklog {
		k.stats.Dropped++
		return ErrOverflow
	}
	for i := 0; i < count; i++ {
		size := k.mss
		if len(data) < size {
			size = len(data)
		}
		piece := make([]byte, size)
		copy(piece, data[:size])
		data = data[size:]
		// Stream mode is not used: each Send is framed by fragment count, so
		// the receiver reassembles exactly what was sent. The TLS record layer
		// above has its own framing, and two framings that disagree about
		// message boundaries is a class of bug not worth inviting.
		k.sndQueue = append(k.sndQueue, segment{
			frg:  uint8(count - i - 1),
			data: piece,
		})
	}
	return nil
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

// Recv returns the next complete message, or nil when none is ready.
func (k *KCP) Recv() []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.recvLocked()
}

func (k *KCP) recvLocked() []byte {
	if len(k.rcvQueue) == 0 {
		return nil
	}
	// A message is complete when its last fragment (frg == 0) has arrived. A
	// partially arrived message is left alone: returning half of it would hand
	// the TLS record layer above a truncated record, which it would then
	// reject as a protocol violation rather than as the missing packet it is.
	size, count, complete := 0, 0, false
	for index := range k.rcvQueue {
		size += len(k.rcvQueue[index].data)
		count++
		if k.rcvQueue[index].frg == 0 {
			complete = true
			break
		}
	}
	if !complete {
		return nil
	}
	out := make([]byte, 0, size)
	for i := 0; i < count; i++ {
		out = append(out, k.rcvQueue[i].data...)
	}
	k.rcvQueue = append(k.rcvQueue[:0], k.rcvQueue[count:]...)
	k.moveToQueueLocked()
	return out
}

// moveToQueueLocked promotes in-order segments from the reassembly buffer.
func (k *KCP) moveToQueueLocked() {
	moved := 0
	for index := range k.rcvBuf {
		if k.rcvBuf[index].sn != k.rcvNxt || uint32(len(k.rcvQueue)) >= k.rcvWnd {
			break
		}
		k.rcvQueue = append(k.rcvQueue, k.rcvBuf[index])
		k.rcvNxt++
		moved++
	}
	if moved > 0 {
		k.rcvBuf = append(k.rcvBuf[:0], k.rcvBuf[moved:]...)
	}
}

// Input feeds one received datagram in.
func (k *KCP) Input(data []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if len(data) < HeaderSize {
		return errors.New("kcp: datagram shorter than a header")
	}
	k.stats.BytesReceived += uint64(len(data))
	oldUna := k.sndUna
	inFlightBefore := len(k.sndBuf)
	var maxAck uint32
	var sawAck bool

	for len(data) >= HeaderSize {
		conv := binary.LittleEndian.Uint32(data[0:])
		if conv != k.conv {
			// Another conversation, or noise. Dropping is correct: this layer
			// has no way to tell a stale peer from an attacker, and TLS above
			// is what decides who is real.
			return nil
		}
		cmd := data[4]
		frg := data[5]
		wnd := binary.LittleEndian.Uint16(data[6:])
		ts := binary.LittleEndian.Uint32(data[8:])
		sn := binary.LittleEndian.Uint32(data[12:])
		una := binary.LittleEndian.Uint32(data[16:])
		length := binary.LittleEndian.Uint32(data[20:])
		data = data[HeaderSize:]
		if uint32(len(data)) < length {
			return errors.New("kcp: datagram truncated")
		}
		payload := data[:length]
		data = data[length:]

		k.stats.SegmentsReceived++
		k.rmtWnd = uint32(wnd)
		k.removeAckedLocked(una)
		k.shrinkSendBufferLocked()

		switch cmd {
		case cmdAck:
			k.stats.AcksReceived++
			now := currentMillis()
			if timeDiff(now, ts) >= 0 {
				k.updateRTTLocked(timeDiff(now, ts))
			}
			k.ackSegmentLocked(sn)
			k.shrinkSendBufferLocked()
			if !sawAck || timeDiff(sn, maxAck) > 0 {
				maxAck, sawAck = sn, true
			}
		case cmdPush:
			if timeDiff(sn, k.rcvNxt+k.rcvWnd) < 0 {
				if len(k.ackList) < maxAckBacklog {
					k.ackList = append(k.ackList, ackEntry{sn: sn, ts: ts})
				}
				if timeDiff(sn, k.rcvNxt) >= 0 {
					k.insertReceivedLocked(segment{
						conv: conv, cmd: cmd, frg: frg, wnd: wnd,
						ts: ts, sn: sn, una: una,
						data: append([]byte(nil), payload...),
					})
				}
			}
		case cmdWask:
			k.probe |= 2 // send our window back
		case cmdWins:
			// The peer told us its window; already recorded above.
		default:
			return errors.New("kcp: unknown command")
		}
	}

	if sawAck {
		k.markFastAckLocked(maxAck)
	}
	// Congestion window growth, on acknowledged progress.
	//
	// Once per acknowledged SEGMENT, not once per datagram. Acknowledgements
	// are batched - several arrive in one packet - so growing once per packet
	// makes slow start grow linearly instead of exponentially, and a window
	// that should reach 64 in six round trips takes sixty.
	if !k.noCwnd && timeDiff(k.sndUna, oldUna) > 0 {
		acknowledged := inFlightBefore - len(k.sndBuf)
		if acknowledged < 1 {
			acknowledged = 1
		}
		for i := 0; i < acknowledged; i++ {
			k.growWindowLocked()
		}
	}
	return nil
}

func (k *KCP) growWindowLocked() {
	if k.cwnd >= k.rmtWnd {
		return
	}
	mss := uint32(k.mss)
	if k.cwnd < k.ssthresh {
		k.cwnd++
		k.incr += mss
		return
	}
	if k.incr < mss {
		k.incr = mss
	}
	k.incr += (mss*mss)/k.incr + mss/16
	if (k.cwnd+1)*mss <= k.incr {
		k.cwnd = (k.incr + mss - 1) / mss
	}
	if k.cwnd > k.rmtWnd {
		k.cwnd = k.rmtWnd
		k.incr = k.rmtWnd * mss
	}
}

func (k *KCP) insertReceivedLocked(seg segment) {
	if len(k.rcvBuf) >= k.maxBacklog {
		k.stats.Dropped++
		return
	}
	position := len(k.rcvBuf)
	duplicate := false
	for index := len(k.rcvBuf) - 1; index >= 0; index-- {
		if k.rcvBuf[index].sn == seg.sn {
			duplicate = true
			break
		}
		if timeDiff(seg.sn, k.rcvBuf[index].sn) > 0 {
			position = index + 1
			break
		}
		position = index
	}
	if duplicate {
		return
	}
	k.rcvBuf = append(k.rcvBuf, segment{})
	copy(k.rcvBuf[position+1:], k.rcvBuf[position:])
	k.rcvBuf[position] = seg
	k.moveToQueueLocked()
}

func (k *KCP) removeAckedLocked(una uint32) {
	removed := 0
	for index := range k.sndBuf {
		if timeDiff(una, k.sndBuf[index].sn) > 0 {
			removed++
			continue
		}
		break
	}
	if removed > 0 {
		k.sndBuf = append(k.sndBuf[:0], k.sndBuf[removed:]...)
	}
}

func (k *KCP) ackSegmentLocked(sn uint32) {
	if timeDiff(sn, k.sndUna) < 0 || timeDiff(sn, k.sndNxt) >= 0 {
		return
	}
	for index := range k.sndBuf {
		if sn == k.sndBuf[index].sn {
			k.sndBuf = append(k.sndBuf[:index], k.sndBuf[index+1:]...)
			return
		}
		if timeDiff(sn, k.sndBuf[index].sn) < 0 {
			return
		}
	}
}

func (k *KCP) markFastAckLocked(sn uint32) {
	if timeDiff(sn, k.sndUna) < 0 || timeDiff(sn, k.sndNxt) >= 0 {
		return
	}
	for index := range k.sndBuf {
		if timeDiff(sn, k.sndBuf[index].sn) < 0 {
			break
		}
		if sn != k.sndBuf[index].sn {
			k.sndBuf[index].fastAck++
		}
	}
}

func (k *KCP) shrinkSendBufferLocked() {
	if len(k.sndBuf) > 0 {
		k.sndUna = k.sndBuf[0].sn
		return
	}
	k.sndUna = k.sndNxt
}

func (k *KCP) updateRTTLocked(rtt int32) {
	if rtt < 0 {
		return
	}
	if k.rxSRTT == 0 {
		k.rxSRTT = rtt
		k.rxRTTVal = rtt / 2
	} else {
		delta := rtt - k.rxSRTT
		if delta < 0 {
			delta = -delta
		}
		k.rxRTTVal = (3*k.rxRTTVal + delta) / 4
		k.rxSRTT = (7*k.rxSRTT + rtt) / 8
		if k.rxSRTT < 1 {
			k.rxSRTT = 1
		}
	}
	rto := k.rxSRTT + max32(int32(k.interval), 4*k.rxRTTVal)
	k.rxRTO = bound32(k.rxMinRTO, rto, int32(defaultRTOMax/time.Millisecond))
	k.stats.SRTT = time.Duration(k.rxSRTT) * time.Millisecond
	k.stats.RTTVar = time.Duration(k.rxRTTVal) * time.Millisecond
	k.stats.RTO = time.Duration(k.rxRTO) * time.Millisecond
}

// ---------------------------------------------------------------------------
// Flush and update
// ---------------------------------------------------------------------------

// Update drives timers. Call it at roughly the configured interval.
func (k *KCP) Update(now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	current := millisOf(now)
	if !k.updated {
		k.updated = true
		k.tsFlush = current
	}
	slap := timeDiff(current, k.tsFlush)
	if slap >= 10000 || slap < -10000 {
		k.tsFlush = current
		slap = 0
	}
	if slap >= 0 {
		k.tsFlush += k.interval
		if timeDiff(current, k.tsFlush) >= 0 {
			k.tsFlush = current + k.interval
		}
		k.flushLocked(current)
	}
}

// Flush sends whatever is pending right now.
func (k *KCP) Flush(now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.updated = true
	k.flushLocked(millisOf(now))
}

func (k *KCP) flushLocked(current uint32) {
	if k.dead {
		return
	}
	buffer := k.buffer[:0]
	window := k.availableWindowLocked()

	emit := func(seg *segment) {
		if len(buffer)+HeaderSize+len(seg.data) > k.mtu {
			k.send(buffer)
			buffer = k.buffer[:0]
		}
		start := len(buffer)
		buffer = buffer[:start+HeaderSize+len(seg.data)]
		seg.encode(buffer[start:])
		copy(buffer[start+HeaderSize:], seg.data)
		k.stats.SegmentsSent++
	}

	// Acknowledgements first: they unblock the peer.
	for _, ack := range k.ackList {
		seg := segment{conv: k.conv, cmd: cmdAck, wnd: uint16(window), una: k.rcvNxt, sn: ack.sn, ts: ack.ts}
		emit(&seg)
		k.stats.AcksSent++
	}
	k.ackList = k.ackList[:0]

	// Window probing, when the peer has told us it has no room.
	if k.rmtWnd == 0 {
		if k.probeWait == 0 {
			k.probeWait = uint32(probeInitial / time.Millisecond)
			k.tsProbe = current + k.probeWait
		} else if timeDiff(current, k.tsProbe) >= 0 {
			k.probeWait += k.probeWait / probeIncrementStep
			k.tsProbe = current + k.probeWait
			k.probe |= 1
		}
	} else {
		k.tsProbe, k.probeWait = 0, 0
	}
	if k.probe&1 != 0 {
		seg := segment{conv: k.conv, cmd: cmdWask, wnd: uint16(window), una: k.rcvNxt}
		emit(&seg)
	}
	if k.probe&2 != 0 {
		seg := segment{conv: k.conv, cmd: cmdWins, wnd: uint16(window), una: k.rcvNxt}
		emit(&seg)
	}
	k.probe = 0

	// Move newly queued segments into the send buffer, within the window.
	limit := min32(k.sndWnd, k.rmtWnd)
	if !k.noCwnd {
		limit = min32(limit, k.cwnd)
	}
	moved := 0
	for len(k.sndQueue) > moved && timeDiff(k.sndNxt, k.sndUna+limit) < 0 {
		seg := k.sndQueue[moved]
		seg.conv = k.conv
		seg.cmd = cmdPush
		seg.wnd = uint16(window)
		seg.ts = current
		seg.sn = k.sndNxt
		seg.una = k.rcvNxt
		seg.resendTS = current
		seg.rto = uint32(k.rxRTO)
		k.sndNxt++
		k.sndBuf = append(k.sndBuf, seg)
		moved++
	}
	if moved > 0 {
		k.sndQueue = append(k.sndQueue[:0], k.sndQueue[moved:]...)
	}

	resent := uint32(0)
	if k.fastResend > 0 {
		resent = k.fastResend
	}
	lost := false
	fastRetransmitted := false

	for index := range k.sndBuf {
		seg := &k.sndBuf[index]
		needsSend := false
		switch {
		case seg.xmit == 0:
			needsSend = true
			seg.rto = uint32(k.rxRTO)
			seg.resendTS = current + seg.rto
		case timeDiff(current, seg.resendTS) >= 0:
			needsSend = true
			if k.nodelay {
				// Grow the timeout by half rather than doubling. On a link
				// that loses packets for reasons unrelated to congestion,
				// doubling punishes a loss that will not repeat.
				seg.rto += seg.rto / 2
			} else {
				seg.rto += seg.rto
			}
			if seg.rto > uint32(defaultRTOMax/time.Millisecond) {
				seg.rto = uint32(defaultRTOMax / time.Millisecond)
			}
			seg.resendTS = current + seg.rto
			lost = true
			k.stats.TimeoutRetrans++
		case resent > 0 && seg.fastAck >= resent:
			needsSend = true
			seg.fastAck = 0
			seg.resendTS = current + seg.rto
			fastRetransmitted = true
			k.stats.FastRetransmits++
		}
		if !needsSend {
			continue
		}
		if seg.xmit > 0 {
			k.stats.Retransmits++
		}
		seg.xmit++
		seg.ts = current
		seg.wnd = uint16(window)
		seg.una = k.rcvNxt
		emit(seg)
		if seg.xmit >= k.deadLnk {
			k.dead = true
		}
	}

	if len(buffer) > 0 {
		k.send(buffer)
	}

	if !k.noCwnd {
		if fastRetransmitted {
			inflight := k.sndNxt - k.sndUna
			k.ssthresh = max32u(inflight/2, 2)
			k.cwnd = k.ssthresh + resent
			k.incr = k.cwnd * uint32(k.mss)
		}
		if lost {
			k.ssthresh = max32u(k.cwnd/2, 2)
			k.cwnd = 1
			k.incr = uint32(k.mss)
		}
		if k.cwnd < 1 {
			k.cwnd = 1
			k.incr = uint32(k.mss)
		}
	}

	k.stats.SendWindow = k.sndWnd
	k.stats.RecvWindow = k.rcvWnd
	k.stats.CongestionWindow = k.cwnd
	k.stats.InFlight = len(k.sndBuf)
	k.stats.SendQueue = len(k.sndQueue)
	k.stats.RecvQueue = len(k.rcvQueue)
}

func (k *KCP) send(datagram []byte) {
	if len(datagram) == 0 || k.output == nil {
		return
	}
	out := make([]byte, len(datagram))
	copy(out, datagram)
	k.stats.BytesSent += uint64(len(out))
	k.output(out)
}

func (k *KCP) availableWindowLocked() uint32 {
	if uint32(len(k.rcvQueue)) >= k.rcvWnd {
		return 0
	}
	return k.rcvWnd - uint32(len(k.rcvQueue))
}

// Dead reports a link whose peer stopped acknowledging.
func (k *KCP) Dead() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.dead
}

// Stats snapshots the counters.
func (k *KCP) Stats() Stats {
	k.mu.Lock()
	defer k.mu.Unlock()
	s := k.stats
	s.InFlight = len(k.sndBuf)
	s.SendQueue = len(k.sndQueue)
	s.RecvQueue = len(k.rcvQueue)
	s.CongestionWindow = k.cwnd
	return s
}

// WaitingToSend reports whether anything is queued or unacknowledged, which is
// what a caller needs to know before deciding a flush is finished.
func (k *KCP) WaitingToSend() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.sndQueue) + len(k.sndBuf)
}

// MSS is the largest payload one segment carries.
func (k *KCP) MSS() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.mss
}

// ---------------------------------------------------------------------------

func currentMillis() uint32 { return millisOf(time.Now()) }

func millisOf(t time.Time) uint32 {
	return uint32(t.UnixNano() / int64(time.Millisecond))
}

// timeDiff compares two wrapping 32-bit values.
func timeDiff(later, earlier uint32) int32 { return int32(later - earlier) }

func max32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}

func max32u(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func min32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func bound32(low, value, high int32) int32 {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}
