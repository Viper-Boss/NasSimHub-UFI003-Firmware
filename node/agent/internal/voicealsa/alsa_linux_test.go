//go:build linux

package voicealsa

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/internal/voicemedia"
)

func TestOpenerRunsRoutesAndReleasesPCMProcesses(t *testing.T) {
	dir := t.TempDir()
	routeLog := filepath.Join(dir, "routes")
	playbackLog := filepath.Join(dir, "playback")
	amixer := script(t, dir, "amixer", "#!/bin/sh\necho \"$*\" >> \""+routeLog+"\"\n")
	holder := script(t, dir, "holder", "#!/bin/sh\necho \"$1 CS-Voice prepared and held\"\nexec sleep 60\n")
	arecord := script(t, dir, "arecord", "#!/bin/sh\nhead -c 640 /dev/zero\nexec sleep 60\n")
	aplay := script(t, dir, "aplay", "#!/bin/sh\ncat > \""+playbackLog+"\"\n")
	opener, err := New(Options{HolderPath: holder, AmixerPath: amixer, ArecordPath: arecord, AplayPath: aplay})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pcm, err := opener.Open(ctx, "mm-0123456789abcdef0123456789abcdef-7")
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, voicemedia.FrameBytes)
	if err := pcm.ReadPCM(ctx, frame); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame, make([]byte, voicemedia.FrameBytes)) {
		t.Fatal("capture frame changed")
	}
	if err := pcm.WritePCM(ctx, bytes.Repeat([]byte{0x6a}, voicemedia.FrameBytes)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, _ := os.ReadFile(playbackLog)
		if len(data) == voicemedia.FrameBytes {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("playback length = %d", len(data))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := pcm.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pcm.Close(); err != nil {
		t.Fatal(err)
	}
	routes, err := os.ReadFile(routeLog)
	if err != nil || strings.Count(string(routes), "\n") != len(controls) {
		t.Fatalf("routes = %q, %v", routes, err)
	}
}

func TestOpenerRejectsInvalidCallBeforeCommands(t *testing.T) {
	opener, err := New(Options{HolderPath: "/no/such/holder"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opener.Open(context.Background(), "mm-7;reboot"); err == nil {
		t.Fatal("invalid ID reached command execution")
	}
}

func script(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}
