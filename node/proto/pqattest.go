package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// Live identity attestation: how the dual-signed pairing transcript is actually
// exchanged, and the rule that a post-quantum identity, once seen, is never
// silently dropped.
//
// pqidentity.go defines the transcript and the two-signatures-or-nothing rule.
// This file is the wire around it. It adds one endpoint and one optional field,
// both additive (protocol 1.3):
//
//	POST /v1/identity/attest   bearer-authenticated. Core sends a fresh nonce;
//	                           the Node answers with a PairingTranscript naming
//	                           both parties as the NODE sees them, signed with
//	                           its Ed25519 key and, when it holds one, its
//	                           ML-DSA key.
//	PairRequest.core_pq        the Core's own ML-DSA public key, so the Node can
//	                           pin it and demand a second signature on the
//	                           requests the Core signs.
//
// An older Node answers the endpoint with 404 and an older Core never calls it;
// both keep working classically, and the outcome is reported as classical-only
// rather than inferred.
//
// # Why the Node fills in the Core's half
//
// The transcript carries the Core id, key and post-quantum key the Node has
// PINNED, not values echoed from the request. The Core then compares them with
// its own. That turns "did the device pin the key I think it pinned" from an
// assumption into something both signatures cover, and it is how a Core
// notices a pairing made before it had a post-quantum key and upgrades it.
//
// # Sticky pins
//
// A Core that has verified a dual signature from a device records the device's
// post-quantum key. From then on that device must present the same key and a
// valid signature under EVERY policy, including optional. Without this, an
// attacker able to forge Ed25519 - the adversary this exists for - would simply
// present as an old device with no post-quantum identity, and "preferred" would
// let them in. The same rule holds on the Node for the Core's key.
//
// Replacing a pinned key is therefore always an explicit act by the owner
// (reset the pin, or unpair and pair again), never something a peer can cause.

// IdentityAttestPath is the attestation endpoint.
const IdentityAttestPath = "/v1/identity/attest"

// Headers carrying the Core's post-quantum signature over the same canonical
// bytes its Ed25519 signature covers (see SigningString).
const (
	HeaderPQSignature = "X-NSH-PQ-Signature"
	HeaderPQAlgorithm = "X-NSH-PQ-Algorithm"
)

// Attestation nonce bounds, in decoded bytes.
const (
	AttestNonceMinBytes = 16
	AttestNonceMaxBytes = 64
)

// IdentityAttestRequest asks the Node to prove its identity now.
type IdentityAttestRequest struct {
	// Nonce is fresh random bytes, base64. It is what makes the answer a proof
	// of possession at this moment rather than a recording.
	Nonce string `json:"nonce"`
}

// IdentityAttestResponse is the signed transcript.
type IdentityAttestResponse struct {
	Transcript PairingTranscript `json:"transcript"`
	Signature  DualSignature     `json:"signature"`
}

// Errors of the attestation exchange. Distinct from the verification errors in
// pqidentity.go because these describe a transcript that is about the wrong
// thing, which no signature can repair.
var (
	// ErrAttestationMismatch means the transcript does not describe this
	// exchange: wrong device, wrong Core, wrong nonce, wrong protocol.
	ErrAttestationMismatch = errors.New("identity attestation does not describe this exchange")
	// ErrPQIdentityChanged means a peer presented a post-quantum key different
	// from the one pinned for it.
	ErrPQIdentityChanged = errors.New("post-quantum identity differs from the pinned one")
	// ErrPQIdentityWithdrawn means a peer with a pinned post-quantum key
	// presented none.
	ErrPQIdentityWithdrawn = errors.New("peer no longer presents its pinned post-quantum identity")
)

// NewAttestNonce returns a fresh nonce.
func NewAttestNonce() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate attestation nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// ValidateAttestNonce bounds a nonce before it is signed over.
func ValidateAttestNonce(nonce string) error {
	raw, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return errors.New("nonce is not base64")
	}
	if len(raw) < AttestNonceMinBytes || len(raw) > AttestNonceMaxBytes {
		return fmt.Errorf("nonce must be %d to %d bytes", AttestNonceMinBytes, AttestNonceMaxBytes)
	}
	return nil
}

// SamePQIdentity reports whether two identities are the same key.
func SamePQIdentity(a, b PQIdentity) bool {
	return a.Algorithm == b.Algorithm && a.PublicKey == b.PublicKey
}

// AttestationExpectation is what a Core knows before it asks.
type AttestationExpectation struct {
	// Nonce is the nonce that was sent.
	Nonce string
	// DeviceID and DeviceKey are the pinned classical identity.
	DeviceID  string
	DeviceKey ed25519.PublicKey
	// PinnedPQ is the device's post-quantum key from an earlier dual
	// verification, or empty when none has been seen.
	PinnedPQ PQIdentity
	// CoreID, CoreKey and CorePQ are this Core's own identity.
	CoreID  string
	CoreKey ed25519.PublicKey
	CorePQ  PQIdentity
	// Policy is what the security level demands.
	Policy PQIdentityPolicy
}

// AttestationResult is what a verified attestation established.
type AttestationResult struct {
	Outcome IdentityOutcome
	// DevicePQ is the key the device proved possession of. Empty unless the
	// outcome is dual. It is what the Core pins.
	DevicePQ PQIdentity
	// CorePQPinned reports whether the device has pinned this Core's
	// post-quantum key. False on a pairing that predates it, which is the
	// Core's cue to upgrade the pairing.
	CorePQPinned bool
}

// VerifyIdentityAttestation checks a Node's answer.
//
// Every check that can fail returns an error; there is no branch that notes a
// problem and carries on. In order:
//
//  1. the transcript is about this exchange (protocol, device, Core, nonce);
//  2. a pinned post-quantum key, if any, is the one presented - a different
//     or missing key is refused under every policy;
//  3. both signatures verify, under the stricter of the configured policy and
//     the one the pin implies.
//
// IssuedAt is NOT compared with the local clock. An MSM8916 with no RTC
// battery boots with an arbitrary date, and the nonce already makes the
// transcript unusable twice; rejecting on the device's clock would make a
// correct device fail attestation until NTP lands.
func VerifyIdentityAttestation(response IdentityAttestResponse, expect AttestationExpectation) (AttestationResult, error) {
	if err := ValidatePQIdentityPolicy(expect.Policy); err != nil {
		return AttestationResult{}, err
	}
	transcript := response.Transcript
	switch {
	case transcript.ProtocolMajor != ProtocolMajor:
		return AttestationResult{}, fmt.Errorf("%w: protocol %d", ErrAttestationMismatch, transcript.ProtocolMajor)
	case expect.Nonce == "" || transcript.Nonce != expect.Nonce:
		return AttestationResult{}, fmt.Errorf("%w: nonce", ErrAttestationMismatch)
	case transcript.DeviceID != expect.DeviceID:
		return AttestationResult{}, fmt.Errorf("%w: device id", ErrAttestationMismatch)
	case len(expect.DeviceKey) != ed25519.PublicKeySize || transcript.DevicePublicKey != EncodeKey(expect.DeviceKey):
		return AttestationResult{}, fmt.Errorf("%w: device key", ErrAttestationMismatch)
	case transcript.CoreID != expect.CoreID:
		return AttestationResult{}, fmt.Errorf("%w: core id", ErrAttestationMismatch)
	case len(expect.CoreKey) != ed25519.PublicKeySize || transcript.CorePublicKey != EncodeKey(expect.CoreKey):
		return AttestationResult{}, fmt.Errorf("%w: core key", ErrAttestationMismatch)
	}
	// The device may have pinned no post-quantum key for this Core yet. If it
	// pinned one, it must be ours: a device that pinned someone else's key is
	// paired, at the post-quantum layer, with someone else.
	if transcript.CorePQ.Present() && !SamePQIdentity(transcript.CorePQ, expect.CorePQ) {
		return AttestationResult{}, fmt.Errorf("%w: core post-quantum key", ErrAttestationMismatch)
	}

	policy := expect.Policy
	if expect.PinnedPQ.Present() {
		if !transcript.DevicePQ.Present() || !response.Signature.HasPQ() {
			return AttestationResult{}, ErrPQIdentityWithdrawn
		}
		if !SamePQIdentity(transcript.DevicePQ, expect.PinnedPQ) {
			return AttestationResult{}, ErrPQIdentityChanged
		}
		policy = PQIdentityRequired
	}
	// A device that publishes a post-quantum key and does not sign with it is
	// not an old device. Treating it as classical-only would let the key be
	// advertised without ever being proven.
	if transcript.DevicePQ.Present() && !response.Signature.HasPQ() {
		return AttestationResult{}, fmt.Errorf("%w: key published without a signature", ErrPQIdentityInvalid)
	}

	outcome, err := VerifyPairingTranscript(transcript, response.Signature, expect.DeviceKey, transcript.DevicePQ, policy)
	if err != nil {
		return AttestationResult{}, err
	}
	result := AttestationResult{Outcome: outcome, CorePQPinned: transcript.CorePQ.Present()}
	if outcome == IdentityDual {
		result.DevicePQ = transcript.DevicePQ
	}
	return result, nil
}

// VerifyCorePQSignature checks the Core's post-quantum signature on a signed
// request, for the Node.
//
// pinned is the Core key the Node recorded at pairing; offered is the key in
// the pair request being processed, used only when nothing is pinned yet. The
// return value says whether a post-quantum signature was verified.
//
// The rules mirror the Core side: a pinned key makes the signature mandatory;
// a signature that is offered must verify; and under a required policy the
// absence of one is a refusal, never a fallback.
func VerifyCorePQSignature(
	message []byte,
	signature string,
	algorithm PQSignatureAlgorithm,
	pinned, offered PQIdentity,
	policy PQIdentityPolicy,
) (bool, error) {
	if err := ValidatePQIdentityPolicy(policy); err != nil {
		return false, err
	}
	identity := pinned
	if !identity.Present() {
		identity = offered
	}
	if pinned.Present() && offered.Present() && !SamePQIdentity(pinned, offered) {
		return false, ErrPQIdentityChanged
	}
	hasSignature := signature != "" && algorithm != ""
	if !hasSignature {
		if pinned.Present() {
			return false, ErrPQIdentityWithdrawn
		}
		if offered.Present() {
			return false, fmt.Errorf("%w: key offered without a signature", ErrPQIdentityInvalid)
		}
		if policy == PQIdentityRequired {
			return false, fmt.Errorf("%w: %w", ErrPQIdentityRequired, ErrPQIdentityMissing)
		}
		return false, nil
	}
	if !identity.Present() {
		// A signature with no key to check it against: a Core that gained a
		// post-quantum key after this pairing was made, signing a request that
		// does not carry the key. There is nothing to downgrade from, so it is
		// a classical request - unless the policy demands more, in which case
		// the Core must pair again and present the key.
		if policy == PQIdentityRequired {
			return false, fmt.Errorf("%w: %w", ErrPQIdentityRequired, ErrPQIdentityMissing)
		}
		return false, nil
	}
	if err := identity.Validate(); err != nil {
		return false, fmt.Errorf("%w: %s", ErrPQIdentityInvalid, err)
	}
	if algorithm != identity.Algorithm {
		return false, fmt.Errorf("%w: signature claims %s, identity is %s", ErrPQIdentityInvalid, algorithm, identity.Algorithm)
	}
	verifier, err := PQVerifierFor(algorithm)
	if err != nil {
		if policy == PQIdentityRequired || pinned.Present() {
			return false, fmt.Errorf("%w: %w", ErrPQIdentityRequired, err)
		}
		// This build cannot check it and nothing demands it. The signature
		// contributes nothing and the caller must not pin the key.
		return false, nil
	}
	publicKey, err := base64.StdEncoding.DecodeString(identity.PublicKey)
	if err != nil {
		return false, fmt.Errorf("%w: public key is not base64", ErrPQIdentityInvalid)
	}
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("%w: signature is not base64", ErrPQIdentityInvalid)
	}
	if err := verifier.Verify(publicKey, message, raw); err != nil {
		return false, fmt.Errorf("%w: %s", ErrPQIdentityInvalid, err)
	}
	return true, nil
}

// ErrPQAlgorithmTooWeak reports a post-quantum key whose parameter set is below
// what the security level demands.
var ErrPQAlgorithmTooWeak = errors.New("post-quantum key does not meet the security level")

// CheckPQAlgorithmForLevel reports whether a peer's post-quantum key is of a
// parameter set the level accepts.
//
// STANDARD and PQ accept both ML-DSA-65 and ML-DSA-87. PQ_EXTREME accepts only
// ML-DSA-87: it is the level whose whole promise is that nothing about it is
// the smaller option, and a category 3 identity under a category 5 key
// agreement would be exactly that. An empty identity is not this function's
// concern - whether one is required is the identity policy's.
func CheckPQAlgorithmForLevel(level SecurityLevel, identity PQIdentity) error {
	if !identity.Present() || level != LevelPQExtreme {
		return nil
	}
	if identity.Algorithm != PQSigMLDSA87 {
		return fmt.Errorf("%w: %s presented, %s requires %s",
			ErrPQAlgorithmTooWeak, identity.Algorithm, level, PQSigMLDSA87)
	}
	return nil
}
