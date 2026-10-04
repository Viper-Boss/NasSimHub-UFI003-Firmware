package voicemedia

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// PCM is one active call's fixed-format full-duplex endpoint. Close must
// unblock ReadPCM and WritePCM so a disconnected NAS releases ALSA devices.
type PCM interface {
	ReadPCM(context.Context, []byte) error
	WritePCM(context.Context, []byte) error
	Close() error
}

type Opener interface {
	Open(context.Context, string) (PCM, error)
}

// Serve accepts the NAS media core's START/STARTED and 20 ms MDM2 frames.
// The caller must authenticate TLS, validate the active call ID, and hold a
// single-call lease before invoking this function.
func Serve(ctx context.Context, conn net.Conn, buffered *bufio.Reader, callID string, opener Opener) error {
	defer conn.Close()
	sessionContext, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-sessionContext.Done()
		_ = conn.Close()
	}()
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	start, err := ReadFrame(buffered)
	if err != nil {
		return err
	}
	if start.Type != TypeStart || start.Sequence != 0 || len(start.Payload) != 0 {
		return ErrFrame
	}
	_ = conn.SetReadDeadline(time.Time{})
	pcm, err := opener.Open(sessionContext, callID)
	if err != nil {
		_ = WriteFrame(conn, Frame{Type: TypeError, Payload: []byte("media_unavailable")})
		return err
	}
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { cancel(); _ = conn.Close(); _ = pcm.Close() }) }
	defer stop()
	var writeMu sync.Mutex
	if err := WriteFrame(conn, Frame{Type: TypeStarted}); err != nil {
		return err
	}
	captureDone := make(chan error, 1)
	go func() {
		var sequence uint32
		for {
			frame := make([]byte, FrameBytes)
			if err := pcm.ReadPCM(sessionContext, frame); err != nil {
				captureDone <- err
				stop()
				return
			}
			writeMu.Lock()
			_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			err := WriteFrame(conn, Frame{Type: TypeCapture, Sequence: sequence, Payload: frame})
			writeMu.Unlock()
			if err != nil {
				captureDone <- err
				stop()
				return
			}
			sequence++
		}
	}()
	var playbackSequence uint32
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		frame, err := ReadFrame(buffered)
		if err != nil {
			select {
			case captureError := <-captureDone:
				if !errors.Is(captureError, io.EOF) {
					return captureError
				}
			default:
			}
			return err
		}
		switch frame.Type {
		case TypeClose:
			if len(frame.Payload) != 0 {
				return ErrFrame
			}
			return nil
		case TypePlayback:
			if frame.Sequence != playbackSequence || len(frame.Payload) != FrameBytes {
				return ErrFrame
			}
			if err := pcm.WritePCM(sessionContext, frame.Payload); err != nil {
				return err
			}
			playbackSequence++
		default:
			return ErrFrame
		}
	}
}
