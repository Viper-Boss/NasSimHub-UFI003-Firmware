package systemstats

import (
	"context"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

const (
	// sampleInterval is how often the device is read while somebody is
	// looking. It is the interval the on-demand reader used to cache for.
	sampleInterval = 2 * time.Second
	// idleAfter is how long after the last reader the sampler keeps going. A
	// Node nobody is watching should not spend its one small CPU reading
	// /proc a hundred times every two seconds.
	idleAfter = 30 * time.Second
	// staleAfter is the age beyond which a snapshot is no longer served as
	// the device's current state.
	staleAfter = 3 * sampleInterval
	// firstSampleWait bounds how long a reader waits for the sampler when
	// there is nothing current to serve: the first request, or the first
	// after an idle period. One pass over procfs takes far less.
	firstSampleWait = 400 * time.Millisecond
)

// Sampler owns the Collector. One goroutine reads the device on a fixed
// interval and publishes an immutable snapshot; readers are served from
// memory and never touch the filesystem themselves.
type Sampler struct {
	collector *Collector
	now       func() time.Time
	interval  time.Duration
	wait      time.Duration

	mu         sync.Mutex
	latest     *proto.SystemResources
	latestAt   time.Time
	lastDemand time.Time
	published  chan struct{}
	wake       chan struct{}
}

func NewSampler(collector *Collector) *Sampler {
	return &Sampler{collector: collector, now: collector.now, interval: sampleInterval, wait: firstSampleWait, published: make(chan struct{}), wake: make(chan struct{}, 1)}
}

// Run samples until ctx ends.
func (s *Sampler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.step(false)
		case <-s.wake:
			// A reader found nothing current. Sample now and restart the
			// interval, so the next tick is a full interval away and the
			// rates are not computed over a sliver of time.
			if s.step(true) {
				ticker.Reset(s.interval)
			}
		}
	}
}

// step takes one sample if anybody wants one. It reports whether it sampled.
func (s *Sampler) step(woken bool) bool {
	now := s.now()
	s.mu.Lock()
	wanted := !s.lastDemand.IsZero() && now.Sub(s.lastDemand) <= idleAfter
	// A wake that raced with a regular tick must not produce two samples
	// back to back.
	fresh := woken && s.latest != nil && now.Sub(s.latestAt) < s.interval/2
	s.mu.Unlock()
	if !wanted || fresh {
		return false
	}
	sample := s.collector.Sample()
	s.mu.Lock()
	s.latest, s.latestAt = sample, now
	close(s.published)
	s.published = make(chan struct{})
	s.mu.Unlock()
	return true
}

// Snapshot returns the latest sample, or nil when there is none that is
// current. The result is shared and must not be modified.
func (s *Sampler) Snapshot() *proto.SystemResources {
	s.mu.Lock()
	now := s.now()
	s.lastDemand = now
	if current := s.currentLocked(now); current != nil || s.wait <= 0 {
		s.mu.Unlock()
		return current
	}
	published := s.published
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
	timer := time.NewTimer(s.wait)
	defer timer.Stop()
	select {
	case <-published:
	case <-timer.C:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentLocked(s.now())
}

func (s *Sampler) currentLocked(now time.Time) *proto.SystemResources {
	if s.latest == nil || now.Sub(s.latestAt) > staleAfter {
		return nil
	}
	return s.latest
}
