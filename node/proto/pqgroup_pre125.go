//go:build !go1.25

package proto

import "crypto/tls"

// Reading back the negotiated key agreement group, on a toolchain that cannot.
//
// ConnectionState.CurveID does not exist before Go 1.25, so there is no way to
// ask which group was used. The product reports pq_active as "unknown" here
// rather than inferring it from what was requested: a request is an intention,
// and reporting an intention as a fact is how a security indicator becomes a
// decoration.
//
// Enforcement does not depend on this. A REQUIRED policy offers only
// post-quantum groups, so a classical handshake cannot complete in the first
// place - see proto/security.go.
//
// This file is about OBSERVATION only. Which groups a build can actually
// PERFORM is a separate question with a separate line (Go 1.26) and lives in
// pqgroup_pre126.go.

// GroupObservable reports whether this build can read the negotiated group.
const GroupObservable = false

// NegotiatedGroup cannot answer on this toolchain and says so.
func NegotiatedGroup(tls.ConnectionState) (uint16, bool) { return 0, false }
