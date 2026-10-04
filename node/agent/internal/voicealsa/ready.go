package voicealsa

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Ready only advertises the audio path after a device-local duplex acceptance.
// Generic firmware must not ship the acceptance marker.
func Ready(ctx context.Context) bool {
	const marker = "/etc/nassimhub/voice-audio.verified"
	info, err := os.Lstat(marker)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return false
	}
	contents, err := os.ReadFile(marker)
	if err != nil || strings.TrimSpace(string(contents)) != "ufi003-q6voice-16k-v1" {
		return false
	}
	for _, name := range []string{"/usr/bin/amixer", "/usr/bin/arecord", "/usr/bin/aplay", "/usr/lib/nassimhub/hold-cs-voice"} {
		info, err := os.Stat(name)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return false
		}
	}
	probe, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	output, err := exec.CommandContext(probe, "/usr/bin/amixer", "-c", card, "controls").Output()
	if err != nil {
		return false
	}
	for _, control := range controls {
		if !strings.Contains(string(output), "name='"+control+"'") {
			return false
		}
	}
	return true
}
