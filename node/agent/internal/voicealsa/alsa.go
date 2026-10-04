package voicealsa

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/internal/voicemedia"
)

const card = "nassimhubufi003"

var controls = []string{
	"Voice Session VoLTE",
	"PRI_MI2S_RX Voice Mixer CS-Voice",
	"CS-Voice Capture Mixer TERT_MI2S_TX",
	"MultiMedia2 Mixer VOICE_RECORD_RX",
	"VOICE_PLAYBACK_TX Audio Mixer MultiMedia1",
	"Voice Record Downlink",
	"Voice Playback Uplink",
}

type Options struct {
	HolderPath  string
	AmixerPath  string
	ArecordPath string
	AplayPath   string
}

// Opener connects one active VoLTE call to the q6 PCM devices verified on
// UFI003. The HTTP layer owns authentication and call-state validation.
type Opener struct{ options Options }

func New(options Options) (*Opener, error) {
	if options.HolderPath == "" {
		options.HolderPath = "/usr/lib/nassimhub/hold-cs-voice"
	}
	if !strings.HasPrefix(options.HolderPath, "/") {
		return nil, errors.New("CS-Voice holder path must be absolute")
	}
	if options.AmixerPath == "" {
		options.AmixerPath = "/usr/bin/amixer"
	}
	if options.ArecordPath == "" {
		options.ArecordPath = "/usr/bin/arecord"
	}
	if options.AplayPath == "" {
		options.AplayPath = "/usr/bin/aplay"
	}
	return &Opener{options: options}, nil
}

func (o *Opener) Open(ctx context.Context, callID string) (voicemedia.PCM, error) {
	if !strings.HasPrefix(callID, "mm-") {
		return nil, errors.New("invalid ModemManager call ID")
	}
	if _, err := strconv.ParseUint(strings.TrimPrefix(callID, "mm-"), 10, 32); err != nil {
		return nil, errors.New("invalid ModemManager call ID")
	}
	for _, name := range controls {
		commandContext, cancel := context.WithTimeout(ctx, 3*time.Second)
		cmd := exec.CommandContext(commandContext, o.options.AmixerPath,
			"-c", card, "cset", "name="+name, "on")
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			return nil, fmt.Errorf("set voice route %q: %w: %s", name, err, strings.TrimSpace(string(output)))
		}
	}
	result := &session{}
	defer func() {
		if result.capture == nil || result.playback == nil {
			_ = result.Close()
		}
	}()
	for _, direction := range []string{"playback", "capture"} {
		cmd, err := startHolder(ctx, o.options.HolderPath, direction)
		if err != nil {
			return nil, err
		}
		result.commands = append(result.commands, cmd)
	}
	capture := exec.CommandContext(ctx, o.options.ArecordPath,
		"-q", "-D", "hw:"+card+",1", "-f", "S16_LE", "-r", "16000", "-c", "1", "-t", "raw")
	captureOut, err := capture.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := capture.Start(); err != nil {
		return nil, err
	}
	result.commands = append(result.commands, capture)
	result.capture = captureOut
	playback := exec.CommandContext(ctx, o.options.AplayPath,
		"-q", "-D", "hw:"+card+",0", "-f", "S16_LE", "-r", "16000", "-c", "1", "-t", "raw")
	playbackIn, err := playback.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := playback.Start(); err != nil {
		return nil, err
	}
	result.commands = append(result.commands, playback)
	result.playback = playbackIn
	return result, nil
}

func startHolder(ctx context.Context, path, direction string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, path, direction)
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	ready := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(output).ReadString('\n')
		if err == nil && !strings.Contains(line, direction+" CS-Voice prepared and held") {
			err = errors.New("CS-Voice holder did not report readiness")
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil, fmt.Errorf("%s holder: %w", direction, err)
		}
		return cmd, nil
	case <-time.After(4 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("%s holder readiness timed out", direction)
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, ctx.Err()
	}
}

type session struct {
	commands  []*exec.Cmd
	capture   io.ReadCloser
	playback  io.WriteCloser
	closeOnce sync.Once
}

func (s *session) ReadPCM(_ context.Context, destination []byte) error {
	if len(destination) != voicemedia.FrameBytes {
		return voicemedia.ErrFrame
	}
	_, err := io.ReadFull(s.capture, destination)
	return err
}

func (s *session) WritePCM(_ context.Context, source []byte) error {
	if len(source) != voicemedia.FrameBytes {
		return voicemedia.ErrFrame
	}
	for len(source) != 0 {
		n, err := s.playback.Write(source)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		source = source[n:]
	}
	return nil
}

func (s *session) Close() error {
	s.closeOnce.Do(func() {
		if s.capture != nil {
			_ = s.capture.Close()
		}
		if s.playback != nil {
			_ = s.playback.Close()
		}
		for _, command := range s.commands {
			if command.Process != nil {
				_ = command.Process.Kill()
			}
		}
		for _, command := range s.commands {
			_ = command.Wait()
		}
	})
	return nil
}

var _ voicemedia.Opener = (*Opener)(nil)
var _ voicemedia.PCM = (*session)(nil)
