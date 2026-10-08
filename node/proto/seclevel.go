package proto

import "fmt"

// The three security levels the product exposes, and the difference between
// "this build cannot" and "this will never work".
//
// # Why levels replaced profile-plus-policy on the outside
//
// The previous round exposed two orthogonal settings - a profile (which groups)
// and a policy (fail or fall back). Two knobs make four combinations, of which
// only three are coherent, and the fourth (extreme groups, preferred policy)
// promises strength while permitting classical key agreement. Levels remove
// the incoherent combination by construction. The profile and policy types
// remain as the INTERNAL representation the TLS configuration is built from;
// they are no longer something a user picks.
//
// # What each level actually asserts
//
//	STANDARD     TLS 1.3 with hybrid preferred and classical permitted.
//	             Ed25519 identity. Reachable from anything.
//	PQ           X25519MLKEM768 REQUIRED - a classical peer cannot connect.
//	             Ed25519 identity, post-quantum identity when available.
//	PQ_EXTREME   SecP384r1MLKEM1024 REQUIRED, dual identity REQUIRED, dual OTA
//	             signatures REQUIRED. Nothing about it degrades.
//
// Three different things can be post-quantum and they are NOT the same claim:
//
//	confidentiality  the session key. ML-KEM, in crypto/tls, working today.
//	authentication   who the peer is. ML-DSA, on a toolchain that has it.
//	OTA authenticity who signed this update. ML-DSA, on a toolchain that has it.
//
// A deployment with only ML-KEM has post-quantum CONFIDENTIALITY and classical
// AUTHENTICATION. Calling that "quantum-resistant identity" would be false, and
// the capability document keeps the three apart for exactly that reason.

// SecurityLevel is the setting a user chooses.
type SecurityLevel string

const (
	// LevelStandard is the default: interoperable, hybrid where possible.
	LevelStandard SecurityLevel = "STANDARD"
	// LevelPQ requires post-quantum key agreement. A peer that cannot do it
	// fails to connect rather than falling back.
	LevelPQ SecurityLevel = "PQ"
	// LevelPQExtreme requires the largest hybrid group, post-quantum identity
	// on both sides, and dual-signed updates.
	LevelPQExtreme SecurityLevel = "PQ_EXTREME"
)

// TargetGoVersion is the toolchain the main repository builds with.
//
// It is recorded here because the honest answer to "is PQ_EXTREME supported"
// depends on which toolchain is being asked about, and a container used for
// development is not the answer that matters to a user.
const TargetGoVersion = "go1.26.5"

// Toolchain requirements, as officially documented for the standard library.
// These are properties of Go, not of this project, and they are what makes a
// missing capability a version statement rather than a defect.
const (
	// GoVersionForX25519MLKEM768 is when crypto/tls gained the standard hybrid.
	GoVersionForX25519MLKEM768 = "go1.24"
	// GoVersionForSecPHybrids is when it gained SecP256r1MLKEM768 and
	// SecP384r1MLKEM1024 - the groups PQ_EXTREME needs.
	GoVersionForSecPHybrids = "go1.26"
	// GoVersionForGroupObservation is when ConnectionState.CurveID appeared.
	GoVersionForGroupObservation = "go1.25"
	// GoVersionForMLDSA is when the standard library gained crypto/mldsa
	// (FIPS 204). A build from this version on carries the real post-quantum
	// signature provider (pqmldsa_go127.go); an older one reports the
	// capability as unavailable and names this version as the remedy.
	GoVersionForMLDSA = "go1.27"
)

// GroupStatus says whether a key agreement group is usable, and if not, why.
type GroupStatus string

const (
	// GroupAvailable means this build can perform it now.
	GroupAvailable GroupStatus = "available"
	// GroupNeedsToolchain means the product supports it and THIS build's Go
	// does not. The remedy is a newer toolchain, not a design change.
	//
	// This is the case that was previously reported as "unsupported", which
	// turned a property of a development container into a statement about the
	// product. A user reading "unsupported" reasonably concludes the feature
	// does not exist.
	GroupNeedsToolchain GroupStatus = "needs_toolchain"
	// GroupUnknown means the group is not one this product knows about.
	GroupUnknown GroupStatus = "unknown_group"
)

// StatusOfGroup reports whether a group can be used in this build, and
// distinguishes "not in this build" from "not a thing".
func StatusOfGroup(group uint16) GroupStatus {
	if BuildSupportsGroup(group) {
		return GroupAvailable
	}
	switch group {
	case GroupSecP256r1MLKEM768, GroupSecP384r1MLKEM1024:
		// Present in the standard library from GoVersionForSecPHybrids, which
		// the target toolchain satisfies.
		return GroupNeedsToolchain
	case GroupX25519MLKEM768, GroupX25519, GroupP256, GroupP384:
		// Every supported toolchain has these, so a build without them is a
		// build this product does not claim to run on.
		return GroupNeedsToolchain
	default:
		return GroupUnknown
	}
}

// RequiredGroupFor is the one group a level insists on. STANDARD insists on
// nothing, which is what makes it interoperable.
func RequiredGroupFor(level SecurityLevel) (uint16, bool) {
	switch level {
	case LevelPQ:
		return GroupX25519MLKEM768, true
	case LevelPQExtreme:
		return GroupSecP384r1MLKEM1024, true
	default:
		return 0, false
	}
}

// ToolchainFor names the minimum Go version a level needs, for a message a
// human can act on.
func ToolchainFor(level SecurityLevel) string {
	switch level {
	case LevelPQExtreme:
		return GoVersionForSecPHybrids
	case LevelPQ:
		return GoVersionForX25519MLKEM768
	default:
		return GoVersionForX25519MLKEM768
	}
}

// LevelStatus is whether a level can be used by this build.
type LevelStatus string

const (
	// LevelAvailable means every primitive the level requires is present.
	LevelAvailable LevelStatus = "available"
	// LevelNeedsToolchain means the level is supported by the product and this
	// build's Go is too old. The UI must say which version is needed, and must
	// NOT offer to proceed at a lower level: silently running PQ where
	// PQ_EXTREME was asked for is the downgrade this whole design refuses.
	LevelNeedsToolchain LevelStatus = "needs_toolchain"
	// LevelUnsupported means this runtime cannot provide the level at all.
	LevelUnsupported LevelStatus = "unsupported"
)

// StatusOfLevel reports whether this build can satisfy a level.
//
// It answers about the KEY AGREEMENT only. Post-quantum identity and dual OTA
// signatures are reported separately by IdentityStatus and OTASignatureStatus,
// because a build can have one and not the other and a single boolean would
// have to lie about one of them.
func StatusOfLevel(level SecurityLevel) LevelStatus {
	group, required := RequiredGroupFor(level)
	if !required {
		return LevelAvailable
	}
	switch StatusOfGroup(group) {
	case GroupAvailable:
		return LevelAvailable
	case GroupNeedsToolchain:
		return LevelNeedsToolchain
	default:
		return LevelUnsupported
	}
}

// ValidateSecurityLevel rejects an unknown level rather than defaulting.
//
// Defaulting an unrecognised level to STANDARD would turn a typo in a
// configuration file into a silent downgrade, which is precisely the failure
// mode the levels exist to prevent.
func ValidateSecurityLevel(level SecurityLevel) error {
	switch level {
	case LevelStandard, LevelPQ, LevelPQExtreme:
		return nil
	default:
		return fmt.Errorf("unknown security level %q; use %s, %s or %s",
			level, LevelStandard, LevelPQ, LevelPQExtreme)
	}
}

// ---------------------------------------------------------------------------
// Mapping a level onto the internal knobs
// ---------------------------------------------------------------------------

// ProfileAndPolicyFor converts a level into the internal TLS settings.
//
// This is the only place the mapping exists. Levels are what a user chooses;
// profile and policy are how the TLS configuration is built. Keeping one
// conversion point is what stops a third combination appearing somewhere else
// in the codebase.
func ProfileAndPolicyFor(level SecurityLevel) (PQProfile, PQPolicy) {
	switch level {
	case LevelPQ:
		return PQStandard, PQRequired
	case LevelPQExtreme:
		return PQExtreme, PQRequired
	default:
		return PQStandard, PQPreferred
	}
}

// LevelFor is the inverse, for reading records written before levels existed.
//
// An extreme profile that was not required maps to PQ rather than PQ_EXTREME:
// that old combination permitted classical key agreement, and calling it
// PQ_EXTREME afterwards would retroactively overstate what it did. Mapping
// downward is the honest direction.
func LevelFor(profile PQProfile, policy PQPolicy) SecurityLevel {
	if policy != PQRequired {
		return LevelStandard
	}
	if profile == PQExtreme {
		return LevelPQExtreme
	}
	return LevelPQ
}

// IdentityRequirementFor is how much identity a level demands.
func IdentityRequirementFor(level SecurityLevel) PQIdentityPolicy {
	switch level {
	case LevelPQExtreme:
		return PQIdentityRequired
	case LevelPQ:
		return PQIdentityPreferred
	default:
		return PQIdentityOptional
	}
}

// OTARequirementFor is how much signing a level demands of an update.
func OTARequirementFor(level SecurityLevel) OTASignaturePolicy {
	if level == LevelPQExtreme {
		return OTASignatureRequired
	}
	return OTASignaturePreferred
}
