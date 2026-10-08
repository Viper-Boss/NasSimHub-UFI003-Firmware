package proto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// Hybrid post-quantum IDENTITY: the schema, the transcript, and the rule that
// two signatures must both verify or neither counts.
//
// # What this is not
//
// It is not an implementation of ML-DSA. There is none here and there must
// never be one written here: a lattice signature scheme implemented by this
// project would be a second unreviewed cryptographic implementation in a
// codebase whose entire security argument is that it implements no primitives.
// ML-DSA comes from the Go standard library (crypto/mldsa, from
// GoVersionForMLDSA) through pqmldsa_go127.go, which only adapts it to the
// interfaces below. A build with an older toolchain has no provider and says
// so. This file is the schema, the interface and the rules, and it is the same
// on every toolchain.
//
// # What stays exactly as it is
//
// device_id is derived from the Ed25519 key and that derivation does not
// change. Not now, and not when ML-DSA is enabled. Every deployed device would
// otherwise get a new identity - a flag day where every Node disappears from
// every NAS - to defend against an attack nobody is mounting. The post-quantum
// key is ADDITIONAL: a second key the same device also holds.
//
// So the identity story has two halves that must not be confused:
//
//	classical  Ed25519. Derives device_id. Present on every device, always.
//	pq         ML-DSA. Additional. Present on newer devices. Never derives
//	           anything, never replaces anything.
//
// # Why "no silent fallback" is the whole point
//
// A dual signature scheme that accepts one signature when the other is missing
// provides exactly the security of the weaker half, while displaying the
// stronger one's name. An attacker who can forge Ed25519 (the future this
// defends against) simply omits the ML-DSA signature. So under
// PQIdentityRequired a missing or invalid post-quantum signature is a failure,
// reported as a failure, with no path that continues.

// PQSignatureAlgorithm names a post-quantum signature scheme.
//
// Only the two NIST ML-DSA parameter sets this product uses are listed. A
// value outside this set is refused rather than passed through to whatever
// happens to be registered.
type PQSignatureAlgorithm string

const (
	// PQSigMLDSA65 is the recommended parameter set (NIST category 3).
	PQSigMLDSA65 PQSignatureAlgorithm = "ml-dsa-65"
	// PQSigMLDSA87 is the parameter set PQ_EXTREME uses (NIST category 5).
	PQSigMLDSA87 PQSignatureAlgorithm = "ml-dsa-87"
)

// ValidatePQSignatureAlgorithm rejects anything that is not one of the two.
func ValidatePQSignatureAlgorithm(algorithm PQSignatureAlgorithm) error {
	switch algorithm {
	case PQSigMLDSA65, PQSigMLDSA87:
		return nil
	default:
		return fmt.Errorf("unknown post-quantum signature algorithm %q; use %s or %s",
			algorithm, PQSigMLDSA65, PQSigMLDSA87)
	}
}

// PQAlgorithmFor is the algorithm a security level expects.
func PQAlgorithmFor(level SecurityLevel) PQSignatureAlgorithm {
	if level == LevelPQExtreme {
		return PQSigMLDSA87
	}
	return PQSigMLDSA65
}

// PQIdentityPolicy is how much post-quantum identity is demanded.
type PQIdentityPolicy string

const (
	// PQIdentityOptional accepts a peer with no post-quantum identity.
	PQIdentityOptional PQIdentityPolicy = "optional"
	// PQIdentityPreferred uses the post-quantum signature when the peer has
	// one and accepts a peer that does not - but the UI must say which
	// happened. "Preferred" that cannot be distinguished from "present" is
	// indistinguishable from a lie.
	PQIdentityPreferred PQIdentityPolicy = "preferred"
	// PQIdentityRequired refuses a peer without a valid post-quantum
	// signature. Both signatures must verify.
	PQIdentityRequired PQIdentityPolicy = "required"
)

// ValidatePQIdentityPolicy rejects an unknown policy rather than defaulting it,
// for the same reason an unknown security level is refused.
func ValidatePQIdentityPolicy(policy PQIdentityPolicy) error {
	switch policy {
	case PQIdentityOptional, PQIdentityPreferred, PQIdentityRequired:
		return nil
	default:
		return fmt.Errorf("unknown post-quantum identity policy %q; use %s, %s or %s",
			policy, PQIdentityOptional, PQIdentityPreferred, PQIdentityRequired)
	}
}

// Errors the dual-identity path can produce. They are distinct values because
// the UI must tell "this device has no post-quantum identity" apart from "this
// device presented one and it did not verify" - the first is an old device, the
// second is an attack or a bug.
var (
	// ErrPQIdentityUnavailable means this build has no ML-DSA implementation.
	ErrPQIdentityUnavailable = errors.New("post-quantum identity is not available in this build")
	// ErrPQIdentityMissing means the peer presented no post-quantum identity.
	ErrPQIdentityMissing = errors.New("peer presented no post-quantum identity")
	// ErrPQIdentityInvalid means a post-quantum signature did not verify.
	ErrPQIdentityInvalid = errors.New("post-quantum signature did not verify")
	// ErrClassicalIdentityInvalid means the Ed25519 signature did not verify.
	ErrClassicalIdentityInvalid = errors.New("classical signature did not verify")
	// ErrPQIdentityRequired means policy demanded a post-quantum identity that
	// was absent or unusable. It is deliberately not the same error as a
	// verification failure: one is a policy refusal, the other is evidence.
	ErrPQIdentityRequired = errors.New("post-quantum identity is required and was not usable")
)

// PQIdentity is the additional post-quantum public key a device holds.
//
// PublicKey is base64, like the Ed25519 key in the identity document, so the
// document stays one shape. There is no fingerprint field: device_id already
// identifies the device and a second identifier would invite code that keys on
// the wrong one.
type PQIdentity struct {
	Algorithm PQSignatureAlgorithm `json:"algorithm"`
	PublicKey string               `json:"public_key"`
}

// Validate checks the algorithm and that the key decodes.
func (p PQIdentity) Validate() error {
	if err := ValidatePQSignatureAlgorithm(p.Algorithm); err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(p.PublicKey)
	if err != nil {
		return fmt.Errorf("post-quantum public key is not base64: %w", err)
	}
	if len(key) == 0 {
		return errors.New("post-quantum public key is empty")
	}
	return nil
}

// Present reports whether an identity was supplied at all.
func (p PQIdentity) Present() bool { return p.Algorithm != "" && p.PublicKey != "" }

// ---------------------------------------------------------------------------
// The transcript
// ---------------------------------------------------------------------------

// PairingTranscript is what both signatures cover.
//
// Both. That is the design: one transcript, two signatures over the same bytes,
// so the two cannot be made to describe different pairings. A scheme where each
// signature covers its own serialisation would let an attacker who controls one
// of them pair a different device than the other signature attested to.
type PairingTranscript struct {
	// ProtocolMajor pins the transcript to a protocol generation, so a
	// signature cannot be replayed into a future version whose fields mean
	// something else.
	ProtocolMajor int `json:"protocol_major"`

	DeviceID        string     `json:"device_id"`
	DevicePublicKey string     `json:"device_public_key"`
	DevicePQ        PQIdentity `json:"device_pq,omitempty"`

	CoreID        string     `json:"core_id"`
	CorePublicKey string     `json:"core_public_key"`
	CorePQ        PQIdentity `json:"core_pq,omitempty"`

	// Nonce is fresh per pairing attempt and makes a transcript unusable
	// twice.
	Nonce string `json:"nonce"`
	// IssuedAt is unix seconds. It bounds how long a captured transcript is
	// worth anything, in the same way the request signing window does.
	IssuedAt int64 `json:"issued_at"`
}

// transcriptDomain separates these bytes from every other signature this
// product makes.
//
// Domain separation is not decoration. Without it, a signature produced for one
// purpose can sometimes be presented as one produced for another - and this
// product already signs API requests with the same Ed25519 key. The label makes
// a pairing signature useless as a request signature and the reverse.
const transcriptDomain = "nassimhub-node/pairing-transcript/v1"

// SigningBytes is the canonical encoding both signatures cover.
//
// Length-prefixed fields rather than a delimiter or JSON. Two reasons, both
// concrete: JSON field order and whitespace are not canonical, so two encoders
// could produce different bytes for the same transcript and a valid signature
// would fail to verify; and a delimiter-joined encoding lets a field containing
// the delimiter shift meaning between fields, so a device_id containing the
// separator could impersonate a different pairing.
func (t PairingTranscript) SigningBytes() []byte {
	var out []byte
	appendField := func(value []byte) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		out = append(out, length[:]...)
		out = append(out, value...)
	}
	appendField([]byte(transcriptDomain))

	var major [4]byte
	binary.BigEndian.PutUint32(major[:], uint32(t.ProtocolMajor))
	appendField(major[:])

	appendField([]byte(t.DeviceID))
	appendField([]byte(t.DevicePublicKey))
	appendField([]byte(t.DevicePQ.Algorithm))
	appendField([]byte(t.DevicePQ.PublicKey))
	appendField([]byte(t.CoreID))
	appendField([]byte(t.CorePublicKey))
	appendField([]byte(t.CorePQ.Algorithm))
	appendField([]byte(t.CorePQ.PublicKey))
	appendField([]byte(t.Nonce))

	var issued [8]byte
	binary.BigEndian.PutUint64(issued[:], uint64(t.IssuedAt))
	appendField(issued[:])

	return out
}

// DualSignature carries both signatures over one transcript.
//
// PQAlgorithm is recorded alongside the signature rather than looked up from
// the identity, so a verifier checks the signature against the algorithm the
// SIGNER named. A verifier that picks the algorithm itself can be steered into
// checking a strong signature with a weak verifier.
type DualSignature struct {
	Classical   string               `json:"classical_signature"`
	PQ          string               `json:"pq_signature,omitempty"`
	PQAlgorithm PQSignatureAlgorithm `json:"pq_algorithm,omitempty"`
}

// HasPQ reports whether a post-quantum signature was supplied.
func (d DualSignature) HasPQ() bool { return d.PQ != "" && d.PQAlgorithm != "" }

// ---------------------------------------------------------------------------
// The verifier
// ---------------------------------------------------------------------------

// PQSigner produces post-quantum signatures. The real implementation wraps the
// standard library (MLDSASigner); this product implements no primitive.
type PQSigner interface {
	Algorithm() PQSignatureAlgorithm
	PublicKey() []byte
	Sign(message []byte) ([]byte, error)
}

// PQVerifier checks post-quantum signatures.
type PQVerifier interface {
	Algorithm() PQSignatureAlgorithm
	Verify(publicKey, message, signature []byte) error
}

// pqProvider is the registered source of post-quantum signature verification.
//
// A registry rather than a direct call, so that enabling ML-DSA on a newer
// toolchain is one registration at start-up and touches none of the call sites
// that enforce policy. Nothing is registered by default: a build with no
// provider reports the capability as unavailable, which is the truth.
var pqRegistryMu sync.RWMutex

var pqProvider func(PQSignatureAlgorithm) (PQVerifier, bool)

// RegisterPQProvider installs the post-quantum verifier source.
//
// Configure the provider at start-up. Reads and registration are synchronized
// so diagnostics and verification can safely run while initialization completes.
func RegisterPQProvider(provider func(PQSignatureAlgorithm) (PQVerifier, bool)) {
	pqRegistryMu.Lock()
	defer pqRegistryMu.Unlock()
	pqProvider = provider
}

// PQIdentityAvailable reports whether this build can verify post-quantum
// signatures at all.
func PQIdentityAvailable() bool {
	pqRegistryMu.RLock()
	defer pqRegistryMu.RUnlock()
	return pqProvider != nil
}

// PQVerifierFor returns the verifier for an algorithm.
func PQVerifierFor(algorithm PQSignatureAlgorithm) (PQVerifier, error) {
	if err := ValidatePQSignatureAlgorithm(algorithm); err != nil {
		return nil, err
	}
	pqRegistryMu.RLock()
	provider := pqProvider
	pqRegistryMu.RUnlock()
	if provider == nil {
		return nil, ErrPQIdentityUnavailable
	}
	verifier, ok := provider(algorithm)
	if !ok {
		return nil, fmt.Errorf("%w: no verifier for %s", ErrPQIdentityUnavailable, algorithm)
	}
	return verifier, nil
}

// IdentityOutcome is what a verification actually established. It is reported
// to the UI, which must distinguish these rather than reduce them to a tick.
type IdentityOutcome string

const (
	// IdentityClassicalOnly means Ed25519 verified and there was no
	// post-quantum signature. Correct for an older device; must be VISIBLE.
	IdentityClassicalOnly IdentityOutcome = "classical_only"
	// IdentityDual means both signatures verified.
	IdentityDual IdentityOutcome = "dual"
)

// VerifyPairingTranscript checks a dual signature under a policy.
//
// The order is deliberate: the classical signature is checked first and a
// failure there ends it. A post-quantum signature over a transcript whose
// classical signature is wrong proves nothing about a device whose identity IS
// the classical key.
//
// Under PQIdentityRequired every path that does not produce two valid
// signatures returns an error. There is no branch in this function that
// continues after a post-quantum failure, which is what makes "cannot silently
// fall back" a property of the code rather than a promise about it.
func VerifyPairingTranscript(
	transcript PairingTranscript,
	signature DualSignature,
	classicalKey ed25519.PublicKey,
	pq PQIdentity,
	policy PQIdentityPolicy,
) (IdentityOutcome, error) {
	if err := ValidatePQIdentityPolicy(policy); err != nil {
		return "", err
	}
	message := transcript.SigningBytes()

	classical, err := base64.StdEncoding.DecodeString(signature.Classical)
	if err != nil {
		return "", fmt.Errorf("%w: signature is not base64", ErrClassicalIdentityInvalid)
	}
	if len(classicalKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: no usable public key", ErrClassicalIdentityInvalid)
	}
	if !ed25519.Verify(classicalKey, message, classical) {
		return "", ErrClassicalIdentityInvalid
	}

	if !signature.HasPQ() {
		if policy == PQIdentityRequired {
			return "", fmt.Errorf("%w: %w", ErrPQIdentityRequired, ErrPQIdentityMissing)
		}
		return IdentityClassicalOnly, nil
	}

	// A post-quantum signature was offered. From here a failure is a failure
	// under EVERY policy, not only under required: a peer that presents a
	// signature which does not verify is not an old peer, and treating it like
	// one would let an attacker downgrade by sending garbage.
	if !pq.Present() {
		return "", fmt.Errorf("%w: signature offered with no public key", ErrPQIdentityInvalid)
	}
	if err := pq.Validate(); err != nil {
		return "", fmt.Errorf("%w: %s", ErrPQIdentityInvalid, err)
	}
	if signature.PQAlgorithm != pq.Algorithm {
		return "", fmt.Errorf("%w: signature claims %s, identity is %s",
			ErrPQIdentityInvalid, signature.PQAlgorithm, pq.Algorithm)
	}
	verifier, err := PQVerifierFor(signature.PQAlgorithm)
	if err != nil {
		if policy == PQIdentityRequired {
			return "", fmt.Errorf("%w: %w", ErrPQIdentityRequired, err)
		}
		// Preferred, and this build cannot check it. The signature is NOT
		// treated as valid and the outcome is not "dual": an unverified
		// signature contributes nothing, and reporting it as dual would be the
		// exact overstatement this file exists to prevent.
		return IdentityClassicalOnly, nil
	}
	publicKey, err := base64.StdEncoding.DecodeString(pq.PublicKey)
	if err != nil {
		return "", fmt.Errorf("%w: public key is not base64", ErrPQIdentityInvalid)
	}
	raw, err := base64.StdEncoding.DecodeString(signature.PQ)
	if err != nil {
		return "", fmt.Errorf("%w: signature is not base64", ErrPQIdentityInvalid)
	}
	if err := verifier.Verify(publicKey, message, raw); err != nil {
		return "", fmt.Errorf("%w: %s", ErrPQIdentityInvalid, err)
	}
	return IdentityDual, nil
}

// SignPairingTranscript produces a dual signature.
//
// The post-quantum signer is optional; the Ed25519 one is not. A signer that
// fails is an error rather than a silently classical-only signature: a device
// that believes it signed twice and did not would present itself as dual-capable
// and then fail verification, which is a worse outcome than refusing to pair.
func SignPairingTranscript(
	transcript PairingTranscript,
	classical ed25519.PrivateKey,
	pq PQSigner,
) (DualSignature, error) {
	if len(classical) != ed25519.PrivateKeySize {
		return DualSignature{}, errors.New("signing a transcript requires an ed25519 private key")
	}
	message := transcript.SigningBytes()
	signature := DualSignature{
		Classical: base64.StdEncoding.EncodeToString(ed25519.Sign(classical, message)),
	}
	if pq == nil {
		return signature, nil
	}
	if err := ValidatePQSignatureAlgorithm(pq.Algorithm()); err != nil {
		return DualSignature{}, err
	}
	raw, err := pq.Sign(message)
	if err != nil {
		return DualSignature{}, fmt.Errorf("post-quantum signing failed: %w", err)
	}
	signature.PQ = base64.StdEncoding.EncodeToString(raw)
	signature.PQAlgorithm = pq.Algorithm()
	return signature, nil
}

// IdentityCapability is what a peer publishes about its identity, for the
// capability document and the status page.
//
// Three separate facts, because they are separately true. A device can hold a
// post-quantum key (Present) on a build that cannot verify one (Available),
// under a policy that does not require it (Policy), and every combination of
// those means something different to a user deciding whether to trust it.
type IdentityCapability struct {
	// Classical is always true: every device has an Ed25519 identity and
	// device_id derives from it. It is reported rather than assumed so that
	// the document says what it means on its own.
	Classical bool `json:"classical"`
	// PQPresent is whether this device holds a post-quantum identity key.
	PQPresent bool `json:"pq_present"`
	// PQAvailable is whether this BUILD can verify post-quantum signatures.
	PQAvailable bool `json:"pq_available"`
	// PQAlgorithm is which parameter set, when present.
	PQAlgorithm PQSignatureAlgorithm `json:"pq_algorithm,omitempty"`
	// Policy is what is being demanded.
	Policy PQIdentityPolicy `json:"pq_policy"`
	// Outcome is what the last completed verification established. Empty
	// before anything has been verified.
	Outcome IdentityOutcome `json:"outcome,omitempty"`
	// Backend names where post-quantum verification comes from. "none" when
	// there is none, and "mock" when it is the test model - which must be
	// visible, so that a mock can never be mistaken for the real thing on a
	// status page.
	Backend string `json:"pq_backend"`
	// RequiresToolchain names the Go version that would make it real.
	RequiresToolchain string `json:"requires_toolchain,omitempty"`
}

// DescribeIdentity builds the capability document for this build.
func DescribeIdentity(pq PQIdentity, policy PQIdentityPolicy) IdentityCapability {
	capability := IdentityCapability{
		Classical:   true,
		PQPresent:   pq.Present(),
		PQAvailable: PQIdentityAvailable(),
		PQAlgorithm: pq.Algorithm,
		Policy:      policy,
		Backend:     PQBackendName(),
	}
	if !capability.PQAvailable {
		capability.RequiresToolchain = GoVersionForMLDSA
	}
	return capability
}

// pqBackendName is set alongside the provider so the UI can name it.
var pqBackendName = "none"

// PQBackendName reports where post-quantum verification comes from.
func PQBackendName() string {
	pqRegistryMu.RLock()
	defer pqRegistryMu.RUnlock()
	if pqProvider == nil {
		return "none"
	}
	return pqBackendName
}

// SetPQBackendName records the provider's name. It is called by whatever calls
// RegisterPQProvider.
func SetPQBackendName(name string) {
	pqRegistryMu.Lock()
	defer pqRegistryMu.Unlock()
	pqBackendName = name
}
