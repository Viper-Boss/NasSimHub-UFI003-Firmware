package kcp

import (
	"bytes"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/xport/netem"
)

// Forward error correction.
//
// The claim FEC makes is narrow and worth testing exactly: one lost packet per
// group is reconstructed without a round trip. Anything more than one loss in a
// group is not recovered - XOR parity cannot - and a test that did not
// distinguish the two would let a broken implementation look fine.

func TestParityReconstructsASingleLoss(t *testing.T) {
	t.Parallel()

	encoder := newFECEncoder(FECBalanced)
	decoder := newFECDecoder(FECBalanced)
	data, _ := FECBalanced.Shards()

	originals := make([][]byte, 0, data)
	var wire [][]byte
	for i := 0; i < data; i++ {
		payload := bytes.Repeat([]byte{byte('a' + i)}, 40+i*7)
		originals = append(originals, payload)
		wire = append(wire, encoder.encode(payload)...)
	}
	// data packets plus one parity.
	if len(wire) != data+1 {
		t.Fatalf("a group of %d produced %d packets", data, len(wire))
	}

	// Drop one data packet - the third - and feed the rest in.
	dropped := 2
	var delivered [][]byte
	for index, packet := range wire {
		if index == dropped {
			continue
		}
		delivered = append(delivered, decoder.decode(packet)...)
	}

	if recovered := decoder.Stats().Recovered; recovered != 1 {
		t.Fatalf("parity recovered %d packets, want 1", recovered)
	}
	var found bool
	for _, datagram := range delivered {
		if bytes.Equal(datagram, originals[dropped]) {
			found = true
		}
	}
	if !found {
		t.Fatal("the reconstructed packet is not the one that was lost")
	}
}

// Two losses in a group cannot be recovered, and the implementation must not
// pretend otherwise - a wrongly "recovered" packet would be corruption handed
// to the layer above as if it were data.
func TestParityCannotRecoverTwoLosses(t *testing.T) {
	t.Parallel()

	encoder := newFECEncoder(FECBalanced)
	decoder := newFECDecoder(FECBalanced)
	data, _ := FECBalanced.Shards()

	var wire [][]byte
	for i := 0; i < data; i++ {
		wire = append(wire, encoder.encode(bytes.Repeat([]byte{byte(i)}, 50))...)
	}
	for index, packet := range wire {
		if index == 1 || index == 4 {
			continue
		}
		decoder.decode(packet)
	}
	if recovered := decoder.Stats().Recovered; recovered != 0 {
		t.Fatalf("parity claimed to recover %d packets from a group with two losses", recovered)
	}
}

// Overhead must match what the mode advertises, and must be measured rather
// than assumed - an operator deciding whether to pay for it needs the real
// number.
func TestOverheadIsBoundedAndMeasured(t *testing.T) {
	t.Parallel()

	for _, mode := range []FECMode{FECOff, FECBalanced, FECAggressive} {
		encoder := newFECEncoder(mode)
		payload := bytes.Repeat([]byte{0x5a}, 1000)
		for i := 0; i < 200; i++ {
			encoder.encode(payload)
		}
		stats := encoder.Stats()
		expected := mode.Overhead()
		if mode == FECOff {
			if stats.ParityPackets != 0 || stats.OverheadRatio != 0 {
				t.Fatalf("fec off produced %d parity packets", stats.ParityPackets)
			}
			continue
		}
		// Measured overhead should be within a few percent of configured: the
		// difference is padding to the longest shard in each group.
		if stats.OverheadRatio < expected*0.8 || stats.OverheadRatio > expected*1.3 {
			t.Fatalf("%s: configured overhead %.3f, measured %.3f",
				mode, expected, stats.OverheadRatio)
		}
		t.Logf("%s: configured %.1f%%, measured %.1f%% over %d data packets",
			mode, expected*100, stats.OverheadRatio*100, stats.DataPackets)
	}
}

// Redundancy is fixed per mode and must not grow. A scheme that raised parity
// when loss rose would, on a link that is losing packets because it is
// saturated, send more and lose more.
func TestRedundancyDoesNotGrow(t *testing.T) {
	t.Parallel()

	encoder := newFECEncoder(FECAggressive)
	payload := bytes.Repeat([]byte{1}, 800)
	var ratios []float64
	for round := 0; round < 10; round++ {
		for i := 0; i < 40; i++ {
			encoder.encode(payload)
		}
		ratios = append(ratios, encoder.Stats().OverheadRatio)
	}
	first, last := ratios[0], ratios[len(ratios)-1]
	if last > first*1.1 {
		t.Fatalf("overhead grew from %.3f to %.3f over the run", first, last)
	}
}

// The decoder holds a bounded number of groups. An incomplete group per lost
// packet, kept forever, is a memory leak an attacker drives by dropping
// packets.
func TestTheDecoderIsBounded(t *testing.T) {
	t.Parallel()

	encoder := newFECEncoder(FECBalanced)
	decoder := newFECDecoder(FECBalanced)
	payload := bytes.Repeat([]byte{7}, 100)

	// Feed only the first packet of each group, so every group stays open.
	for i := 0; i < maxFECGroups*10; i++ {
		packets := encoder.encode(payload)
		decoder.decode(packets[0])
	}
	decoder.mu.Lock()
	held := len(decoder.groups)
	decoder.mu.Unlock()
	if held > maxFECGroups+1 {
		t.Fatalf("the decoder is holding %d incomplete groups with a cap of %d",
			held, maxFECGroups)
	}
}

// End to end: FEC on a lossy link recovers packets that would otherwise have
// cost a retransmission.
func TestFECRecoversOnALossyLink(t *testing.T) {
	t.Parallel()

	link := netem.Profile{Loss: 0.05, RTT: 200 * time.Millisecond, Seed: 17}
	client, server := pair(t, link, Options{Profile: ProfileAggressive, FEC: FECAggressive})

	payload := bytes.Repeat([]byte("nassimhub"), 8000)
	go func() { _, _ = client.Write(payload) }()

	received := make([]byte, len(payload))
	if err := readFull(server, received); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(payload, received) {
		t.Fatal("the stream was corrupted")
	}
	recovered := server.RecoveredByFEC()
	_, fec := client.Stats()
	t.Logf("5%% loss with aggressive FEC: %d datagrams recovered by parity, "+
		"measured overhead %.1f%%", recovered, fec.OverheadRatio*100)
	if recovered == 0 {
		t.Fatal("5% loss over 72 KB recovered nothing from parity; " +
			"either the parity is not being sent or the decoder is not using it")
	}
}
