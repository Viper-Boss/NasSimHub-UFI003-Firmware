package kcp

import (
	"encoding/binary"
	"sync"
)

// Forward error correction.
//
// FEC trades bandwidth for latency. Retransmission costs a round trip; parity
// costs bytes that are sent whether they are needed or not. On a link with 200
// ms of round trip and 5% loss, a lost segment costs 400 ms to recover by
// retransmission and nothing at all to recover from parity - so on exactly that
// link the trade is worth making, and on a clean one it is pure waste.
//
// The scheme is XOR parity over a group: any ONE lost packet in a group can be
// reconstructed from the rest. It is not Reed-Solomon, and that is a deliberate
// limit rather than a first step. Reed-Solomon recovers from several losses per
// group at the cost of a field arithmetic implementation, and this project does
// not write its own cryptography-adjacent primitives. XOR parity recovers the
// case that dominates real links - isolated loss - with code that is obviously
// correct.
//
// Overhead is bounded and reported. A scheme that raises redundancy when loss
// rises will, on a link that is losing packets BECAUSE it is saturated, send
// more and lose more; the ratios here are fixed per profile for that reason,
// and the measured overhead is exposed so an operator can see what they are
// paying.

// FEC packet kinds.
const (
	fecHeaderSize = 6
	fecTypeData   = 0xf1
	fecTypeParity = 0xf2
	// fecSizeField is the two bytes prefixed to a data payload before parity
	// is computed, so that shards of different lengths can be XORed and the
	// original length recovered.
	fecSizeField = 2
)

// FECMode is how much redundancy to add.
type FECMode string

const (
	// FECOff sends no parity. The default: most links do not need it, and the
	// overhead is real.
	FECOff FECMode = "off"
	// FECBalanced adds one parity packet per ten data packets - 10% overhead,
	// recovering isolated loss up to roughly that rate.
	FECBalanced FECMode = "balanced"
	// FECAggressive adds one per four - 25% overhead. For a link that is
	// visibly bad and where the alternative is not working at all.
	FECAggressive FECMode = "aggressive"
)

// Shards returns the data and parity counts for a mode.
func (m FECMode) Shards() (data, parity int) {
	switch m {
	case FECBalanced:
		return 10, 1
	case FECAggressive:
		return 4, 1
	default:
		return 0, 0
	}
}

// Overhead is the redundancy ratio a mode costs, before any packet is sent.
func (m FECMode) Overhead() float64 {
	data, parity := m.Shards()
	if data == 0 {
		return 0
	}
	return float64(parity) / float64(data)
}

// ValidFECMode reports whether a mode is one of the three.
func ValidFECMode(mode FECMode) bool {
	switch mode {
	case FECOff, FECBalanced, FECAggressive:
		return true
	default:
		return false
	}
}

// FECStats is what diagnostics reports. Counters only.
type FECStats struct {
	DataPackets   uint64
	ParityPackets uint64
	Recovered     uint64
	// Overhead is measured, not configured: parity bytes over data bytes
	// actually sent. A configured 10% and a measured 10% agreeing is how an
	// operator knows the thing is doing what it says.
	OverheadRatio float64
	dataBytes     uint64
	parityBytes   uint64
}

// fecEncoder wraps outgoing datagrams.
type fecEncoder struct {
	mu        sync.Mutex
	mode      FECMode
	data      int
	parity    int
	seq       uint32
	group     [][]byte // padded shard bodies for the current group
	maxLen    int
	stats     FECStats
	groupSize int
}

func newFECEncoder(mode FECMode) *fecEncoder {
	data, parity := mode.Shards()
	return &fecEncoder{mode: mode, data: data, parity: parity, groupSize: data + parity}
}

// encode returns the packets to put on the wire for one datagram: the wrapped
// datagram, plus a parity packet whenever a group completes.
func (e *fecEncoder) encode(payload []byte) [][]byte {
	if e.data == 0 {
		// FEC off: the packet still gets a header, so a receiver with FEC on
		// and a sender with it off remain compatible in framing.
		return [][]byte{wrapFEC(0, fecTypeData, payload)}
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	seq := e.seq
	e.seq++
	out := [][]byte{wrapFEC(seq, fecTypeData, payload)}
	e.stats.DataPackets++
	e.stats.dataBytes += uint64(len(payload))

	// Keep the padded body for parity: [size][payload], zero-filled to the
	// longest body in the group.
	body := make([]byte, fecSizeField+len(payload))
	binary.LittleEndian.PutUint16(body, uint16(len(payload)))
	copy(body[fecSizeField:], payload)
	if len(body) > e.maxLen {
		e.maxLen = len(body)
	}
	e.group = append(e.group, body)

	if len(e.group) < e.data {
		e.updateOverheadLocked()
		return out
	}

	parity := make([]byte, e.maxLen)
	for _, shard := range e.group {
		for index := range shard {
			parity[index] ^= shard[index]
		}
	}
	out = append(out, wrapFEC(e.seq, fecTypeParity, parity))
	e.seq++
	e.stats.ParityPackets++
	e.stats.parityBytes += uint64(len(parity))
	e.group = e.group[:0]
	e.maxLen = 0
	e.updateOverheadLocked()
	return out
}

func (e *fecEncoder) updateOverheadLocked() {
	if e.stats.dataBytes == 0 {
		e.stats.OverheadRatio = 0
		return
	}
	e.stats.OverheadRatio = float64(e.stats.parityBytes) / float64(e.stats.dataBytes)
}

func (e *fecEncoder) Stats() FECStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

func wrapFEC(seq uint32, kind uint16, payload []byte) []byte {
	out := make([]byte, fecHeaderSize+len(payload))
	binary.LittleEndian.PutUint32(out, seq)
	binary.LittleEndian.PutUint16(out[4:], kind)
	copy(out[fecHeaderSize:], payload)
	return out
}

// fecDecoder reassembles groups and recovers a single loss.
//
// It holds at most maxGroups groups. A receiver that kept every incomplete
// group would be a memory leak driven by the attacker's packet loss, which is
// the exact shape of bug this project's bounds exist to prevent.
type fecDecoder struct {
	mu        sync.Mutex
	data      int
	parity    int
	groupSize int
	groups    map[uint32]*fecGroup
	order     []uint32
	stats     FECStats
}

type fecGroup struct {
	shards  map[int][]byte // index within the group -> padded body
	parity  []byte
	haveP   bool
	emitted bool
}

const maxFECGroups = 64

func newFECDecoder(mode FECMode) *fecDecoder {
	data, parity := mode.Shards()
	return &fecDecoder{
		data:      data,
		parity:    parity,
		groupSize: data + parity,
		groups:    map[uint32]*fecGroup{},
	}
}

// decode unwraps a received packet and returns the datagrams it yields: the
// packet itself when it carries data, plus any datagram recovered from parity.
func (d *fecDecoder) decode(packet []byte) [][]byte {
	if len(packet) < fecHeaderSize {
		return nil
	}
	seq := binary.LittleEndian.Uint32(packet)
	kind := binary.LittleEndian.Uint16(packet[4:])
	payload := packet[fecHeaderSize:]

	if d.data == 0 {
		if kind == fecTypeData {
			return [][]byte{append([]byte(nil), payload...)}
		}
		// Parity from a peer with FEC on, received by one with it off. It
		// carries no new data, so dropping it is correct.
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	groupID := seq / uint32(d.groupSize)
	index := int(seq % uint32(d.groupSize))
	group, known := d.groups[groupID]
	if !known {
		group = &fecGroup{shards: map[int][]byte{}}
		d.groups[groupID] = group
		d.order = append(d.order, groupID)
		d.evictLocked()
	}

	var out [][]byte
	switch kind {
	case fecTypeData:
		out = append(out, append([]byte(nil), payload...))
		body := make([]byte, fecSizeField+len(payload))
		binary.LittleEndian.PutUint16(body, uint16(len(payload)))
		copy(body[fecSizeField:], payload)
		group.shards[index] = body
	case fecTypeParity:
		group.parity = append([]byte(nil), payload...)
		group.haveP = true
	default:
		return nil
	}

	if recovered := d.recoverLocked(group); recovered != nil {
		d.stats.Recovered++
		out = append(out, recovered)
	}
	return out
}

// recoverLocked reconstructs the one missing data shard, when exactly one is
// missing and the parity has arrived.
func (d *fecDecoder) recoverLocked(group *fecGroup) []byte {
	if group.emitted || !group.haveP || len(group.shards) != d.data-1 {
		return nil
	}
	missing := -1
	for index := 0; index < d.data; index++ {
		if _, present := group.shards[index]; !present {
			missing = index
			break
		}
	}
	if missing < 0 {
		return nil
	}
	recovered := append([]byte(nil), group.parity...)
	for _, shard := range group.shards {
		for index := range shard {
			if index < len(recovered) {
				recovered[index] ^= shard[index]
			}
		}
	}
	if len(recovered) < fecSizeField {
		return nil
	}
	size := int(binary.LittleEndian.Uint16(recovered))
	if size <= 0 || fecSizeField+size > len(recovered) {
		// A corrupt or inconsistent group. Dropping is right: the layer above
		// will retransmit, and handing up a wrong-length datagram would make
		// TLS treat a lost packet as a protocol violation.
		return nil
	}
	group.emitted = true
	return append([]byte(nil), recovered[fecSizeField:fecSizeField+size]...)
}

func (d *fecDecoder) evictLocked() {
	for len(d.order) > maxFECGroups {
		oldest := d.order[0]
		d.order = d.order[1:]
		delete(d.groups, oldest)
	}
}

func (d *fecDecoder) Stats() FECStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}
