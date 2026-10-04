package voicemedia

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeOpener struct {
	pcm    *fakePCM
	opened string
}

type fixedPCMOpener struct{ pcm PCM }

func (o fixedPCMOpener) Open(context.Context, string) (PCM, error) { return o.pcm, nil }

type stalledPlayback struct{ entered, fail chan struct{} }

func (p *stalledPlayback) ReadPCM(ctx context.Context, dst []byte) error {
	select {
	case <-p.fail:
		return errors.New("capture failed")
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *stalledPlayback) WritePCM(ctx context.Context, src []byte) error {
	close(p.entered)
	<-ctx.Done()
	return ctx.Err()
}
func (p *stalledPlayback) Close() error { return nil }

func TestCaptureFailureUnblocksStalledPlayback(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	pcm := &stalledPlayback{entered: make(chan struct{}), fail: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), server, bufio.NewReader(server), "mm-1", fixedPCMOpener{pcm})
	}()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := WriteFrame(client, Frame{Type: TypeStart}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(client); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(client, Frame{Type: TypePlayback, Payload: make([]byte, FrameBytes)}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pcm.entered:
	case <-time.After(time.Second):
		t.Fatal("playback did not start")
	}
	close(pcm.fail)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("capture failure left playback blocked")
	}
}

func (f *fakeOpener) Open(_ context.Context, id string) (PCM, error) {
	f.opened = id
	return f.pcm, nil
}

type fakePCM struct {
	capture  chan []byte
	playback chan []byte
	closed   chan struct{}
	once     sync.Once
}

func (f *fakePCM) ReadPCM(ctx context.Context, dst []byte) error {
	select {
	case data := <-f.capture:
		copy(dst, data)
		return nil
	case <-f.closed:
		return errors.New("closed")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *fakePCM) WritePCM(ctx context.Context, src []byte) error {
	select {
	case f.playback <- bytes.Clone(src):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *fakePCM) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func TestDuplexMediaProtocolAndCleanup(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	pcm := &fakePCM{
		capture:  make(chan []byte, 1),
		playback: make(chan []byte, 1),
		closed:   make(chan struct{}),
	}
	opener := &fakeOpener{pcm: pcm}
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), server, bufio.NewReader(server), "mm-7", opener)
	}()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := WriteFrame(client, Frame{Type: TypeStart}); err != nil {
		t.Fatal(err)
	}
	started, err := ReadFrame(client)
	if err != nil || started.Type != TypeStarted || opener.opened != "mm-7" {
		t.Fatalf("start = %+v, %v, opened = %q", started, err, opener.opened)
	}
	captured := bytes.Repeat([]byte{0x23, 0x42}, FrameBytes/2)
	pcm.capture <- captured
	got, err := ReadFrame(client)
	if err != nil || got.Type != TypeCapture || got.Sequence != 0 || !bytes.Equal(got.Payload, captured) {
		t.Fatalf("capture = %+v, %v", got, err)
	}
	playback := bytes.Repeat([]byte{0x13}, FrameBytes)
	if err := WriteFrame(client, Frame{Type: TypePlayback, Payload: playback}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-pcm.playback:
		if !bytes.Equal(got, playback) {
			t.Fatal("playback bytes changed")
		}
	case <-time.After(time.Second):
		t.Fatal("playback did not reach PCM")
	}
	if err := WriteFrame(client, Frame{Type: TypeClose}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("serve error = %v", err)
	}
	select {
	case <-pcm.closed:
	default:
		t.Fatal("PCM lease not closed")
	}
}

func TestMalformedStartNeverOpensPCM(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	opener := &fakeOpener{}
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), server, bufio.NewReader(server), "mm-7", opener)
	}()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := WriteFrame(client, Frame{Type: TypePlayback, Payload: make([]byte, FrameBytes)}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrFrame) || opener.opened != "" {
		t.Fatalf("malformed START error = %v, opened = %q", err, opener.opened)
	}
}
