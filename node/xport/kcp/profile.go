package kcp

import (
	"fmt"
	"time"
)

// Profiles.
//
// KCP has a dozen knobs and most deployments get them wrong in the same
// direction: everything turned up, because each individual setting looks like
// it makes things faster. What it actually produces is a connection that sends
// several copies of everything and calls the resulting throughput a win.
//
// So the product exposes two named profiles and not the knobs. The Config
// fields exist for tests and for someone who has measured their own link; the
// UI offers balanced and aggressive, and the difference between them is a
// deliberate, documented trade rather than a slider.

// Profile names a tuning.
type Profile string

const (
	// ProfileBalanced is the default. It keeps the congestion window, which
	// means it backs off when the link is genuinely congested rather than
	// shouting over other traffic on the same household connection.
	ProfileBalanced Profile = "balanced"

	// ProfileAggressive removes the congestion window and shortens the timers.
	// It recovers faster on a link whose loss is not congestion - a marginal
	// cellular signal - and it is antisocial on a link where the loss IS
	// congestion, because it responds to a full queue by sending more. The
	// name is a warning, not a recommendation.
	ProfileAggressive Profile = "aggressive"
)

// ValidProfile reports whether a profile name is known.
func ValidProfile(profile Profile) bool {
	switch profile {
	case ProfileBalanced, ProfileAggressive:
		return true
	default:
		return false
	}
}

// ConfigFor returns the tuning for a profile.
//
// The bounds are part of the profile, not an afterthought: a window is both a
// throughput setting and a memory cap, and on a device with 256 MB there is no
// version of "as large as possible" that is safe.
func ConfigFor(profile Profile) (Config, error) {
	switch profile {
	case ProfileBalanced:
		return Config{
			MTU:        1200,
			SendWindow: 128,
			RecvWindow: 128,
			Interval:   20 * time.Millisecond,
			NoDelay:    true,
			FastResend: 2,
			// Congestion control stays on. See the profile doc.
			NoCongestionWindow: false,
			MaxBacklog:         2048,
		}, nil
	case ProfileAggressive:
		return Config{
			MTU:                1200,
			SendWindow:         256,
			RecvWindow:         256,
			Interval:           10 * time.Millisecond,
			NoDelay:            true,
			FastResend:         2,
			NoCongestionWindow: true,
			MaxBacklog:         4096,
		}, nil
	default:
		return Config{}, fmt.Errorf("unknown kcp profile %q; use balanced or aggressive", profile)
	}
}

// MemoryBudget estimates the worst-case bytes one session can hold.
//
// It is reported rather than merely enforced so that "how much can a hundred
// bad connections cost me" has an answer an operator can compute, instead of
// being discovered when the device runs out.
func (c Config) MemoryBudget() int {
	mtu := c.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}
	backlog := c.MaxBacklog
	if backlog <= 0 {
		backlog = maxSegmentBacklog
	}
	send := c.SendWindow
	if send == 0 {
		send = defaultSendWindow
	}
	receive := c.RecvWindow
	if receive == 0 {
		receive = defaultRecvWindow
	}
	// send queue + send buffer + receive buffer + receive queue, each bounded.
	return (backlog + int(send) + backlog + int(receive)) * mtu
}
