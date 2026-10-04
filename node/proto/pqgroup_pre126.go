//go:build !go1.26

package proto

// Which key agreement groups this build can perform, before Go 1.26.
//
// Go 1.24 and 1.25 implement X25519MLKEM768 and the classical groups. They do
// not implement the SecP hybrids; offering one fails locally with "no supported
// elliptic curves for ECDHE", which was confirmed by running it on go1.24.7
// rather than assumed from release notes.
//
// A false answer here means "not in THIS build". It does not mean the group is
// unsupported by the product: the main repository targets go1.26.5, where these
// groups exist. See GroupStatus in seclevel.go for the distinction, which is
// the difference between "your NAS needs updating" and "this will never work".

// BuildSupportsGroup reports whether this build's crypto/tls can perform a key
// agreement with the group.
func BuildSupportsGroup(group uint16) bool {
	switch group {
	case GroupX25519MLKEM768, GroupX25519, GroupP256, GroupP384:
		return true
	default:
		return false
	}
}
