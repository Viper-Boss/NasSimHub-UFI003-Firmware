package httpapi

import (
	"context"
	"github.com/human-agent65535/nassimhub-node/proto"
	"time"
)

// keepCallMediaActive binds DSP media to the exact live modem call. A terminal
// observation closes immediately. Transient query failures tolerate three
// polls, but an indefinitely unobservable call must not retain ALSA resources.
func keepCallMediaActive(ctx context.Context, id string, interval time.Duration, list func(context.Context) ([]proto.Call, error), stop func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		query, cancel := context.WithTimeout(ctx, 2*time.Second)
		calls, err := list(query)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			failures++
			if failures < 3 {
				continue
			}
			stop()
			return
		}
		failures = 0
		active := false
		for _, call := range calls {
			if call.ID == id && call.State == proto.CallActive {
				active = true
				break
			}
		}
		if !active {
			stop()
			return
		}
	}
}
