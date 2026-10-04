package proto

import "time"

// The one protocol addition this round makes: an authenticated endpoint that
// hands the Core the Node's KCP transport secret.
//
//	POST /v1/transport/key     authenticated, TLS only
//
// # Why it needs an endpoint of its own
//
// The secret has to travel exactly once, over a channel that is already
// authenticated by the pairing. Putting it in the pair response would work for
// issuance and not for rotation, and rotation is not optional: a transport key
// that cannot be rotated is a permanent authenticator for anyone who ever
// obtained a NAS backup.
//
// # Why this is a minor version bump and not a major one
//
// Adding an endpoint is additive. A Core that does not know about it never
// calls it and keeps working over TCP; a Node that does not serve it answers
// 404 and the Core reports that the weak-network transport is unavailable on
// that device. Neither side breaks, which is the test for a minor bump.
//
// # What must never happen to this response
//
// It must not be logged, must not reach a diagnostics bundle, and must not be
// written anywhere except the Core's own store. There are tests for the first
// two. The field is named Secret rather than something softer for exactly that
// reason: a reviewer scanning for what must not be logged should be able to
// find it by name.

// TransportKeyRequest asks for the transport secret.
type TransportKeyRequest struct {
	// Rotate asks the Node to issue a NEW secret at the next epoch rather than
	// return the current one. The Core sets it when re-keying; the Node's
	// previous epoch stays acceptable for the grace window so that packets
	// already in flight survive the change.
	Rotate bool `json:"rotate"`
}

// TransportKeyResponse carries it back.
type TransportKeyResponse struct {
	KeyID string `json:"key_id"`
	Epoch uint32 `json:"epoch"`
	// Secret is base64 raw key material. The only field in this protocol that
	// is.
	Secret   string    `json:"secret"`
	IssuedAt time.Time `json:"issued_at"`
	// GraceSeconds is how long the Node will keep accepting the previous
	// epoch. The Core uses it to decide when it is safe to consider a rotation
	// complete.
	GraceSeconds int `json:"grace_seconds"`
}

// TransportKeyPath is the endpoint, named once so that the client, the server
// and the replay-safety allow-list cannot drift apart.
const TransportKeyPath = "/v1/transport/key"
