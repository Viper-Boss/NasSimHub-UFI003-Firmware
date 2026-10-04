package proto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Hybrid signatures for update manifests: who signed this, in a world with a
// quantum computer.
//
// This is the THIRD of the three post-quantum questions, and it is worth
// separating from the other two because they fail at different times:
//
//	confidentiality   protects a session recorded today from being read later.
//	                  ML-KEM. Working now.
//	authentication    proves who a peer is, live. ML-DSA. Designed, not enabled.
//	OTA authenticity  proves who built this update. ML-DSA. Designed, not
//	                  enabled - and the one with the longest tail, because a
//	                  device installs what it is told to install, and a forged
//	                  update is game over in a way a forged session is not.
//
// An attacker who can forge Ed25519 in 2040 can sign an update for a device
// still running in 2040. That device is in a cupboard and nobody is watching
// it. Which is why the policy below refuses to install classical-only updates
// when it is set to require both, rather than warning and proceeding.

// OTASignaturePolicy is how many signatures an update must carry.
type OTASignaturePolicy string

const (
	// OTASignaturePreferred accepts a classical-only manifest, which is what
	// older publishers produce - but the UI and diagnostics must say
	// "classical-only" plainly. A silent acceptance is how a fleet ends up
	// believing it has post-quantum updates when it has not.
	OTASignaturePreferred OTASignaturePolicy = "preferred"
	// OTASignatureRequired refuses any manifest without two valid signatures.
	OTASignatureRequired OTASignaturePolicy = "required"
)

// ValidateOTASignaturePolicy rejects an unknown policy.
func ValidateOTASignaturePolicy(policy OTASignaturePolicy) error {
	switch policy {
	case OTASignaturePreferred, OTASignatureRequired:
		return nil
	default:
		return fmt.Errorf("unknown OTA signature policy %q; use %s or %s",
			policy, OTASignaturePreferred, OTASignatureRequired)
	}
}

// OTAPQKeyring maps key ids to post-quantum release signing identities.
//
// Separate from OTAKeyring rather than a field added to it. The two key sets
// rotate independently, and a combined structure would make "this key id has a
// classical key but no post-quantum one" an awkward state to represent - which
// is exactly the state a fleet is in while it migrates.
type OTAPQKeyring map[string]PQIdentity

// Errors specific to the post-quantum half.
var (
	// ErrOTAPQUnsigned reports a manifest with no usable post-quantum
	// signature where one was required.
	ErrOTAPQUnsigned = errors.New("update manifest carries no valid post-quantum signature")
	// ErrOTAPQUnavailable reports a build that cannot check one.
	ErrOTAPQUnavailable = errors.New("this build cannot verify post-quantum update signatures")
)

// OTASignatureOutcome is what verification established about the signatures.
type OTASignatureOutcome string

const (
	// OTAClassicalOnly means the Ed25519 signature verified and there was no
	// post-quantum signature. Must be surfaced, never inferred as fine.
	OTAClassicalOnly OTASignatureOutcome = "classical_only"
	// OTADualSigned means both verified.
	OTADualSigned OTASignatureOutcome = "dual_signed"
)

// VerifyManifestHybrid checks a manifest under a signature policy.
//
// The classical signature is checked first, against the raw bytes, before any
// decoding - unchanged from VerifyManifest, and for the same reason: a manifest
// that fails verification must never become a structure some later code might
// use by accident.
//
// The post-quantum check follows on the SAME bytes. Every failure path returns
// an error; there is no branch that records a post-quantum failure and
// continues, because a policy that can be satisfied by a failed check is not a
// policy.
func VerifyManifestHybrid(
	signed OTASignedManifest,
	keyring OTAKeyring,
	pqKeyring OTAPQKeyring,
	policy OTASignaturePolicy,
) (OTAManifest, OTASignatureOutcome, error) {
	if err := ValidateOTASignaturePolicy(policy); err != nil {
		return OTAManifest{}, "", err
	}

	// Classical first. A post-quantum signature over a manifest whose
	// classical signature is wrong establishes nothing useful: the device
	// trusts the classical keyring today, and an update it cannot attribute
	// classically is an update from an unknown party.
	manifest, err := VerifyManifest(signed, keyring)
	if err != nil {
		return OTAManifest{}, "", err
	}

	hasPQ := signed.PQSignature != "" && signed.PQKeyID != ""
	if !hasPQ {
		if policy == OTASignatureRequired {
			return OTAManifest{}, "", fmt.Errorf(
				"%w: policy requires a post-quantum signature and the manifest has none",
				ErrOTAPQUnsigned)
		}
		return manifest, OTAClassicalOnly, nil
	}

	// A post-quantum signature was offered. From here it must verify under
	// EVERY policy. A manifest that presents a broken signature is not an old
	// manifest, and accepting it as one would let an attacker turn REQUIRED
	// into PREFERRED by appending noise.
	identity, known := pqKeyring[signed.PQKeyID]
	if !known {
		return OTAManifest{}, "", fmt.Errorf("%w: post-quantum key id %q is not in this device's keyring",
			ErrOTAPQUnsigned, signed.PQKeyID)
	}
	if err := identity.Validate(); err != nil {
		return OTAManifest{}, "", fmt.Errorf("%w: %s", ErrOTAPQUnsigned, err)
	}
	if signed.PQAlgorithm != identity.Algorithm {
		return OTAManifest{}, "", fmt.Errorf(
			"%w: manifest claims %s, key %q is %s",
			ErrOTAPQUnsigned, signed.PQAlgorithm, signed.PQKeyID, identity.Algorithm)
	}
	verifier, err := PQVerifierFor(signed.PQAlgorithm)
	if err != nil {
		// This build cannot check it. Under REQUIRED that is a refusal - the
		// device must not install an update it cannot fully verify. Under
		// PREFERRED the outcome is classical_only, NOT dual_signed: an
		// unverified signature contributes nothing to what was established.
		if policy == OTASignatureRequired {
			return OTAManifest{}, "", fmt.Errorf("%w: %w", ErrOTAPQUnavailable, err)
		}
		return manifest, OTAClassicalOnly, nil
	}
	publicKey, err := base64.StdEncoding.DecodeString(identity.PublicKey)
	if err != nil {
		return OTAManifest{}, "", fmt.Errorf("%w: key %q is not base64", ErrOTAPQUnsigned, signed.PQKeyID)
	}
	signature, err := base64.StdEncoding.DecodeString(signed.PQSignature)
	if err != nil {
		return OTAManifest{}, "", fmt.Errorf("%w: signature is not base64", ErrOTAPQUnsigned)
	}
	if err := verifier.Verify(publicKey, signed.Manifest, signature); err != nil {
		return OTAManifest{}, "", fmt.Errorf("%w: %s", ErrOTAPQUnsigned, err)
	}
	return manifest, OTADualSigned, nil
}

// SignManifestHybrid produces a manifest signed classically and, when a
// post-quantum signer is supplied, with both.
//
// A post-quantum signer that fails is an error rather than a classical-only
// manifest. A publisher that believes it dual-signed and did not would ship
// updates that every REQUIRED device refuses, discovered at the worst moment.
func SignManifestHybrid(
	manifest OTAManifest,
	keyID string,
	key ed25519.PrivateKey,
	pqKeyID string,
	pq PQSigner,
) (OTASignedManifest, error) {
	signed, err := SignManifest(manifest, keyID, key)
	if err != nil {
		return OTASignedManifest{}, err
	}
	if pq == nil {
		return signed, nil
	}
	if pqKeyID == "" {
		return OTASignedManifest{}, errors.New("post-quantum signing requires a key id")
	}
	if err := ValidatePQSignatureAlgorithm(pq.Algorithm()); err != nil {
		return OTASignedManifest{}, err
	}
	raw, err := pq.Sign(signed.Manifest)
	if err != nil {
		return OTASignedManifest{}, fmt.Errorf("post-quantum signing failed: %w", err)
	}
	signed.PQSignature = base64.StdEncoding.EncodeToString(raw)
	signed.PQKeyID = pqKeyID
	signed.PQAlgorithm = pq.Algorithm()
	return signed, nil
}

// OTASignatureCapability is what the UI and diagnostics show about an update's
// signatures.
type OTASignatureCapability struct {
	Policy  OTASignaturePolicy  `json:"policy"`
	Outcome OTASignatureOutcome `json:"outcome,omitempty"`
	// PQAvailable is whether this build could check a post-quantum signature
	// at all, which is the difference between "the publisher did not sign it"
	// and "we could not tell".
	PQAvailable bool `json:"pq_available"`
	// RequiresToolchain names what would make it checkable.
	RequiresToolchain string `json:"requires_toolchain,omitempty"`
}

// DescribeOTASignatures builds that document.
func DescribeOTASignatures(policy OTASignaturePolicy, outcome OTASignatureOutcome) OTASignatureCapability {
	capability := OTASignatureCapability{
		Policy:      policy,
		Outcome:     outcome,
		PQAvailable: PQIdentityAvailable(),
	}
	if !capability.PQAvailable {
		capability.RequiresToolchain = GoVersionForMLDSA
	}
	return capability
}

// ManifestRaw exposes the exact bytes a signature covers, so a caller can
// re-check without re-encoding.
func ManifestRaw(signed OTASignedManifest) json.RawMessage { return signed.Manifest }
