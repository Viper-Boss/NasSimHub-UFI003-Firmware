package msm8916

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

const defaultIMSProfilePath = "/etc/nassimhub/local-volte.enabled"

// imsRegistration never changes the modem. A generic image has no local
// validation marker, so it cannot advertise VoLTE merely from the chip model.
func (b *Backend) imsRegistration(ctx context.Context) proto.Tristate {
	if !b.options.ReadOnly {
		return proto.TriUnknown
	}
	marker := b.options.IMSProfilePath
	if marker == "" {
		marker = defaultIMSProfilePath
	}
	if _, err := os.Stat(marker); err != nil {
		return proto.TriUnknown
	}
	b.imsMu.Lock()
	defer b.imsMu.Unlock()
	if !b.imsAt.IsZero() && b.now().Sub(b.imsAt) < 8*time.Second {
		return b.imsState
	}
	probe := b.options.RunQMI
	if probe == nil {
		return proto.TriUnknown
	}
	out, err := probe(ctx)
	b.imsAt = b.now()
	b.imsState = proto.TriUnknown
	b.imsVoiceState = proto.TriUnknown
	if err == nil {
		b.imsVoiceState = imsVoiceService(out)
	}
	if err == nil && imsStatusRegistered(out) {
		b.imsState = proto.TriYes
	}
	return b.imsState
}

func imsStatusRegistered(output string) bool {
	if len(output) > 2048 || !strings.Contains(output, "IMS registration:") {
		return false
	}
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "Status: 'registered'" {
			return true
		}
	}
	return false
}

// imsVoiceService keeps registration and actual voice readiness separate.
func imsVoiceService(output string) proto.Tristate {
	if len(output) > 2048 {
		return proto.TriUnknown
	}
	inVoice := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "Voice service" {
			inVoice = true
			continue
		}
		if !inVoice {
			continue
		}
		if line == "Status: 'available'" {
			return proto.TriYes
		}
		if line == "Status: 'unavailable'" {
			return proto.TriNo
		}
		if strings.HasSuffix(line, "service") {
			break
		}
	}
	return proto.TriUnknown
}

func (b *Backend) imsVoiceReady(ctx context.Context) bool {
	if b.imsRegistration(ctx) != proto.TriYes {
		return false
	}
	b.imsMu.Lock()
	defer b.imsMu.Unlock()
	return b.imsVoiceState == proto.TriYes
}
