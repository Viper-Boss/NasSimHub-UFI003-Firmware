//go:build go1.26

package proto

// Which key agreement groups THIS build can actually perform.
//
// The split is at Go 1.26, and it is a different line from the one in
// pqgroup_go125.go. Two independent facts were being conflated before:
//
//	go1.25  crypto/tls can REPORT the negotiated group (ConnectionState.CurveID)
//	go1.26  crypto/tls can PERFORM SecP256r1MLKEM768 and SecP384r1MLKEM1024
//
// Go 1.24 implements X25519MLKEM768 and the classical groups, and nothing else
// post-quantum. Conflating the two lines made a build that could not read back
// the group look like a build that could not do the key agreement, which is how
// PQ_EXTREME came to be described as "unsupported" rather than as "needs a
// newer toolchain than the one this container has".

// BuildSupportsGroup reports whether this build's crypto/tls can perform a key
// agreement with the group, as opposed to merely naming it.
//
// Offering a group the standard library does not implement produces "no
// supported elliptic curves for ECDHE" locally, before anything is sent - a
// safe failure, but an opaque one. Knowing the answer in advance lets the
// product say which toolchain is needed instead.
func BuildSupportsGroup(group uint16) bool {
	switch group {
	case GroupX25519MLKEM768, GroupSecP256r1MLKEM768, GroupSecP384r1MLKEM1024,
		GroupX25519, GroupP256, GroupP384:
		return true
	default:
		return false
	}
}
