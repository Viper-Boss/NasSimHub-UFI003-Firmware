package config

import (
	"strings"
	"testing"
)

func TestDTMFNeedsExplicitVoiceConfiguration(t *testing.T) {
	if Default().VoiceDTMF {
		t.Fatal("DTMF must default to disabled")
	}
	settings, err := Parse(strings.NewReader("voice_dtmf = true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err = Validate(settings); err == nil {
		t.Fatal("DTMF enabled without voice_media")
	}
	settings, err = Parse(strings.NewReader("modem_backend = msm8916\nplatform = msm8916\nvoice_media = true\nvoice_dtmf = true\n"))
	if err != nil || !settings.VoiceDTMF {
		t.Fatalf("explicit voice configuration: %+v %v", settings, err)
	}
	if err = Validate(settings); err != nil {
		t.Fatal(err)
	}
}
