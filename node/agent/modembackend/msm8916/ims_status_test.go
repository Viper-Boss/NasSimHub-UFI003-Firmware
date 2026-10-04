package msm8916

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/human-agent65535/nassimhub-node/proto"
)

func TestIMSRegistrationRequiresLocalProfileAndCurrentQuery(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "local-volte.enabled")
	queries := 0
	backend := New(Options{
		ReadOnly:       true,
		IMSProfilePath: marker,
		RunQMI: func(context.Context) (string, error) {
			queries++
			return "[/dev/wwan0qmi0] IMS registration:\n Status: 'registered'\n Technology: 'wwan'\n", nil
		},
	})
	if cap, _ := backend.Capabilities(context.Background()); cap.VoLTE != proto.TriUnknown || queries != 0 {
		t.Fatalf("unmarked device advertised IMS: %+v, queries=%d", cap, queries)
	}
	if err := os.WriteFile(marker, []byte("validated on this device\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cap, err := backend.Capabilities(context.Background())
	if err != nil || cap.VoLTE != proto.TriYes || cap.VoiceControl || cap.VoiceAudio || queries != 1 {
		t.Fatalf("registered IMS must remain signaling-only: %+v, %v, queries=%d", cap, err, queries)
	}
	voice, err := backend.GetVoiceCapability(context.Background())
	if err != nil || voice.VoLTE != proto.TriYes || voice.Control || voice.Audio || queries != 1 {
		t.Fatalf("voice detail inconsistent: %+v, %v, queries=%d", voice, err, queries)
	}
}

func TestIMSQueryFailureDoesNotAdvertiseVoLTE(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "local-volte.enabled")
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	backend := New(Options{ReadOnly: true, IMSProfilePath: marker, RunQMI: func(context.Context) (string, error) {
		return "", errors.New("modem offline")
	}})
	if got := backend.imsRegistration(context.Background()); got != proto.TriUnknown {
		t.Fatalf("failed query advertised IMS: %q", got)
	}
	for _, text := range []string{
		"Status: 'registered'",
		"IMS registration:\n Status: 'not-registered'\n",
	} {
		if imsStatusRegistered(text) {
			t.Fatalf("accepted non-registered response: %q", text)
		}
	}
}
