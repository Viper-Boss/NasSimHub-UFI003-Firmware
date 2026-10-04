package httpapi

import (
	"context"
	"errors"
	"github.com/human-agent65535/nassimhub-node/proto"
	"sync/atomic"
	"testing"
	"time"
)

func TestMediaStopsWhenExactModemCallEnds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var queries atomic.Int32
	stopped := make(chan struct{})
	go keepCallMediaActive(ctx, "target", time.Millisecond, func(context.Context) ([]proto.Call, error) {
		state := proto.CallActive
		if queries.Add(1) > 2 {
			state = proto.CallTerminated
		}
		return []proto.Call{{ID: "target", State: state}, {ID: "another", State: proto.CallActive}}, nil
	}, func() { close(stopped) })
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("ended call retained its media")
	}
	if queries.Load() != 3 {
		t.Fatal("active call stopped prematurely")
	}
}

func TestMediaToleratesTransientReadFailureButStopsUnobservableCall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var queries atomic.Int32
	stopped := make(chan struct{})
	go keepCallMediaActive(ctx, "target", time.Millisecond, func(context.Context) ([]proto.Call, error) {
		n := queries.Add(1)
		if n == 3 {
			return []proto.Call{{ID: "target", State: proto.CallActive}}, nil
		}
		return nil, errors.New("modem temporarily unavailable")
	}, func() { close(stopped) })
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("unobservable call retained its media")
	}
	if queries.Load() != 6 {
		t.Fatal("transient failures did not reset after recovery", queries.Load())
	}
}

func TestMediaWatchStopsQueryingAfterStreamCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		keepCallMediaActive(ctx, "target", time.Millisecond, func(context.Context) ([]proto.Call, error) { t.Error("query after cancellation"); return nil, nil }, func() { t.Error("redundant media stop") })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("media watcher leaked")
	}
}
