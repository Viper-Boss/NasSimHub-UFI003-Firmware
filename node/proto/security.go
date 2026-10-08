package proto

import (
	"errors"
	"fmt"
)

// Post-quantum key exchange.
//
// What this adds and what it deliberately does not:
//
//	adds        a hybrid post-quantum key AGREEMENT for the TLS 1.3 handshake
//	unchanged   Ed25519 device identity, device_id derivation, TLS identity
//	            binding, public-key pinning, pairing, request signing
//
// The separation matters. An attacker recording traffic today and breaking the
// key exchange in fifteen years would read those recordings; hybrid key
// agreement is what stops that, and it is a property of the SESSION. Whether a
// device is who it says it is remains an Ed25519 question, answered live, and a
// future attacker cannot retroactively impersonate a device to a conversation
// that already happened. So identity is not made post-quantum here, and that is
// a considered decision rather than an omission - changing it would mean a new
// device_id derivation and a flag day for every deployed device, to defend
// against an attack that does not exist.
//
// Nothing in this package implements cryptography. ML-KEM, X25519, HKDF and the
// AEADs all come from crypto/tls in the Go standard library. What is here is the
// IANA code points, the policy, and the rules for when a handshake must fail.
//
// # How a policy is enforced
//
// By restricting the groups offered, not by inspecting the result. A client
// configured for REQUIRED lists only post-quantum groups in CurvePreferences,
// so a peer that cannot do one produces a TLS handshake failure from the
// standard library itself. There is no code path where this product observes a
// classical handshake and decides to tolerate it - the handshake never
// completes. That was verified empirically against Go 1.24.7:
//
//	client PQ-only  / server PQ-only         handshake OK
//	client PQ-only  / server classical-only  handshake failure
//	client classical / server PQ-only        handshake failure
//	client PQ+classical / server classical   handshake OK  (PREFERRED's fallback)
//
// # Reading back what was negotiated
//
// Reporting pq_active needs the negotiated group, which crypto/tls exposes as
// ConnectionState.CurveID from Go 1.25 on. On an older toolchain the field does
// not exist, so this product reports pq_active as "unknown" there rather than
// guessing. Enforcement is unaffected: it never depended on observation.

// PQProfile is how much post-quantum protection to ask for.
type PQProfile string

const (
	// PQStandard is the profile for ordinary use: X25519MLKEM768, which is
	// what the wider ecosystem has settled on and what browsers and servers
	// actually negotiate today. Being interoperable is part of being secure -
	// a profile nothing else speaks protects nobody.
	PQStandard PQProfile = "pq_standard"

	// PQExtreme allows the larger parameter set as well. It costs more
	// handshake bytes and more CPU, on a device that has little of either, so
	// it is opt-in rather than the default.
	PQExtreme PQProfile = "pq_extreme"
)

// PQPolicy is what to do when the peer cannot do post-quantum key agreement.
type PQPolicy string

const (
	// PQPreferred offers post-quantum first and accepts a classical handshake
	// if the peer cannot. Compatible with older Nodes - and the UI must say
	// plainly when a connection ended up classical, or "preferred" quietly
	// becomes "absent".
	PQPreferred PQPolicy = "preferred"

	// PQRequired offers only post-quantum groups. A peer that cannot do one
	// gets a handshake failure. There is no silent downgrade because there is
	// no classical group on offer to downgrade to.
	PQRequired PQPolicy = "required"
)

// TLS group code points, from the IANA TLS Supported Groups registry.
//
// These are identifiers, not algorithms. They are written out here because
// SecP384r1MLKEM1024 has no named constant before Go 1.25, and a build that
// targets an older toolchain must still be able to express the policy - it
// simply cannot satisfy it, which is the correct and safe outcome.
const (
	// GroupX25519MLKEM768 is crypto/tls's tls.X25519MLKEM768.
	GroupX25519MLKEM768 uint16 = 0x11ec
	// GroupSecP256r1MLKEM768 is tls.SecP256r1MLKEM768 on Go 1.25 and later.
	GroupSecP256r1MLKEM768 uint16 = 0x11eb
	// GroupSecP384r1MLKEM1024 is tls.SecP384r1MLKEM1024 on Go 1.25 and later.
	GroupSecP384r1MLKEM1024 uint16 = 0x11ed

	// Classical groups, offered only under PQPreferred.
	GroupX25519 uint16 = 0x001d
	GroupP256   uint16 = 0x0017
	GroupP384   uint16 = 0x0018
)

// Errors.
var (
	// ErrPQUnavailable reports that the local build cannot offer a group the
	// requested profile needs.
	ErrPQUnavailable = errors.New("this build cannot offer the requested post-quantum group")
	// ErrPQRequired reports a connection refused because post-quantum key
	// agreement was required and could not be established.
	ErrPQRequired = errors.New("post-quantum key agreement is required and was not available")
)

// PQGroups returns the TLS groups to offer, most preferred first.
//
// Under PQRequired the classical groups are absent, and their absence is the
// enforcement. Under PQPreferred they are appended, and a connection that ends
// up using one is a connection the UI must describe as not post-quantum.
//
// The extreme profile, REQUIRED, offers SecP384r1MLKEM1024 and nothing else.
// That combination is the PQ_EXTREME level, whose contract is that this one
// group is required (RequiredGroupFor). It previously also listed the two
// ML-KEM-768 hybrids "so a peer that cannot do 1024 still has 768", and the
// effect was not the one intended: crypto/tls prefers a group the client
// already sent a key share for, the client sends a share for X25519MLKEM768
// whenever it is offered, and so two peers that both implemented 1024 settled
// on 768 every time. A level named for the largest group was never using it,
// and nothing said so. Listing only the required group makes the level mean
// what it says: a peer that cannot do 1024 fails the handshake, visibly, which
// is what "required" promises - and is the same enforcement-by-omission the
// classical groups get above.
//
// The extreme profile under PREFERRED keeps its fallbacks. That combination is
// not PQ_EXTREME (LevelFor maps it to STANDARD); it exists so a configuration
// written before levels did still loads, and it promises nothing it must keep.
func PQGroups(profile PQProfile, policy PQPolicy) []uint16 {
	var groups []uint16
	switch {
	case profile == PQExtreme && policy == PQRequired:
		groups = []uint16{GroupSecP384r1MLKEM1024}
	case profile == PQExtreme:
		groups = []uint16{GroupSecP384r1MLKEM1024, GroupX25519MLKEM768, GroupSecP256r1MLKEM768}
	default:
		groups = []uint16{GroupX25519MLKEM768}
	}
	if policy == PQRequired {
		return groups
	}
	return append(groups, GroupX25519, GroupP256, GroupP384)
}

// IsPQGroup reports whether a group is a hybrid post-quantum key agreement.
func IsPQGroup(group uint16) bool {
	switch group {
	case GroupX25519MLKEM768, GroupSecP256r1MLKEM768, GroupSecP384r1MLKEM1024:
		return true
	default:
		return false
	}
}

// GroupName renders a group for display and diagnostics.
func GroupName(group uint16) string {
	switch group {
	case GroupX25519MLKEM768:
		return "X25519MLKEM768"
	case GroupSecP256r1MLKEM768:
		return "SecP256r1MLKEM768"
	case GroupSecP384r1MLKEM1024:
		return "SecP384r1MLKEM1024"
	case GroupX25519:
		return "X25519"
	case GroupP256:
		return "P-256"
	case GroupP384:
		return "P-384"
	case 0:
		return ""
	default:
		return fmt.Sprintf("group-0x%04x", group)
	}
}

// ValidatePQProfile and ValidatePQPolicy reject settings rather than silently
// substituting a default, because a mistyped security setting that quietly
// becomes the weaker option is the failure this whole area exists to prevent.
func ValidatePQProfile(profile PQProfile) error {
	switch profile {
	case PQStandard, PQExtreme:
		return nil
	default:
		return fmt.Errorf("unknown post-quantum profile %q; use %s or %s",
			profile, PQStandard, PQExtreme)
	}
}

// ValidatePQPolicy checks a policy value.
func ValidatePQPolicy(policy PQPolicy) error {
	switch policy {
	case PQPreferred, PQRequired:
		return nil
	default:
		return fmt.Errorf("unknown post-quantum policy %q; use %s or %s",
			policy, PQPreferred, PQRequired)
	}
}

// SecurityCapability is what a Node publishes about its transport security, and
// what Core shows the user.
//
// Supported, active and fallback are three different states and the UI must be
// able to tell them apart:
//
//	pq_supported=false               this build cannot do it at all
//	pq_supported=true, active=no     it can, and this connection did not
//	pq_supported=true, active=yes    this connection is post-quantum
//	pq_supported=true, active=unknown it can, and this build cannot observe
//	                                 which group was negotiated (Go < 1.25)
//
// The fourth state is the honest one on an older toolchain. Reporting "yes"
// because post-quantum was requested would be reporting an intention as a fact.
type SecurityCapability struct {
	PQSupported bool      `json:"pq_supported"`
	PQActive    Tristate  `json:"pq_active"`
	PQGroup     string    `json:"pq_group,omitempty"`
	PQProfile   PQProfile `json:"pq_profile"`
	PQPolicy    PQPolicy  `json:"pq_policy"`
	TLSVersion  string    `json:"tls_version,omitempty"`
	// Observable reports whether this build can read the negotiated group
	// back. It exists so the UI can explain an "unknown" rather than showing
	// a shrug.
	Observable bool `json:"group_observable"`
}

// Fallback reports a connection that could have been post-quantum and was not.
// This is the state PQPreferred exists to allow and the UI must not hide.
func (s SecurityCapability) Fallback() bool {
	return s.PQSupported && s.PQActive == TriNo
}
