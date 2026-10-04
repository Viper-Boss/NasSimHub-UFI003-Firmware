package voicemedia

import (
	"encoding/binary"
	"log"
)

// mediaStats keeps only packet counts and a windowed amplitude. It never
// stores PCM, phone numbers or RTP payloads, including after the call ends.
type mediaStats struct {
	frames  uint64
	nonzero uint64
	peak    int32
}

func (s *mediaStats) observe(pcm []byte) bool {
	s.frames++
	var peak int32
	for i := 0; i+1 < len(pcm); i += 2 {
		v := int32(int16(binary.LittleEndian.Uint16(pcm[i : i+2])))
		if v < 0 {
			v = -v
		}
		if v > peak {
			peak = v
		}
	}
	if peak != 0 {
		s.nonzero++
	}
	if peak > s.peak {
		s.peak = peak
	}
	return s.frames == 1 || s.frames%250 == 0
}

func (s *mediaStats) report(callID, direction string) {
	if s.frames == 0 {
		return
	}
	log.Printf("voice media counters call=%s direction=%s frames=%d nonzero=%d window_peak=%d", callID, direction, s.frames, s.nonzero, s.peak)
	s.peak = 0
}
