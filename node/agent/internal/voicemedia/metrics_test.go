package voicemedia

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestMediaCountersDoNotRetainOrLogAudio(t *testing.T) {
	pcm := []byte{0, 128, 42, 0, 255, 127, 0, 0}
	before := append([]byte(nil), pcm...)
	var stats mediaStats
	if !stats.observe(pcm) || stats.peak != 32768 || stats.nonzero != 1 {
		t.Fatalf("wrong signed PCM peak: %+v", stats)
	}
	if !bytes.Equal(pcm, before) {
		t.Fatal("metrics changed audio payload")
	}
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	stats.report("mm-123", "uplink")
	if strings.Contains(output.String(), string(pcm)) {
		t.Fatal("audio payload entered diagnostic log")
	}
	if stats.peak != 0 || stats.frames != 1 || stats.nonzero != 1 {
		t.Fatal("window reset changed cumulative counters")
	}
	for i := 2; i <= 250; i++ {
		if stats.observe(make([]byte, FrameBytes)) != (i == 250) {
			t.Fatalf("unbounded reporting at frame %d", i)
		}
	}
	if stats.nonzero != 1 || stats.peak != 0 {
		t.Fatal("silence reported as nonzero PCM")
	}
}
