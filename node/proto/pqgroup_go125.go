//go:build go1.25

package proto

import "crypto/tls"

// Reading back the negotiated key agreement group, on a toolchain that can.
//
// crypto/tls gained ConnectionState.CurveID in Go 1.25. This file and its
// counterpart exist because the product must build on both sides of that line
// and must not claim, on the older one, to know something it cannot see.
//
// This file is about OBSERVATION only. Which groups a build can actually
// PERFORM is a separate question with a separate line (Go 1.26) and lives in
// pqgroup_go126.go. They were in one file before, and merging them made a
// build that could not read the group back indistinguishable from one that
// could not do the key agreement at all.

// GroupObservable reports whether this build can read the negotiated group.
const GroupObservable = true

// NegotiatedGroup returns the key agreement group a completed handshake used.
func NegotiatedGroup(state tls.ConnectionState) (uint16, bool) {
	return uint16(state.CurveID), state.CurveID != 0
}
