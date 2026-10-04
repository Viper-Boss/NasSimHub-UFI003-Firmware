package msm8916

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestVoiceRequiresDuplexAcceptanceAndLiveIMSService(t *testing.T) {
	for _, tc := range []struct {
		name         string
		write, audio bool
		service      string
		want         bool
	}{
		{"verified", true, true, "available", true},
		{"write disabled", false, true, "available", false},
		{"audio unavailable", true, false, "available", false},
		{"voice unavailable", true, true, "unavailable", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "profile")
			if err := os.WriteFile(marker, []byte("device local"), 0600); err != nil {
				t.Fatal(err)
			}
			b := New(Options{ReadOnly: true, VoiceWrite: tc.write, VoiceAudioReady: func(context.Context) bool { return tc.audio }, IMSProfilePath: marker, RunQMI: func(context.Context) (string, error) {
				return "IMS registration:\n Status: 'registered'\nIMS services:\n Voice service\n Status: '" + tc.service + "'\n", nil
			}})
			c, err := b.Capabilities(context.Background())
			if err != nil || c.VoiceControl != tc.want || c.VoiceAudio != tc.want {
				t.Fatalf("capabilities %+v error %v", c, err)
			}
		})
	}
}
