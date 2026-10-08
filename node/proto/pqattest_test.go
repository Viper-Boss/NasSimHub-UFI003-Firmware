package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

// These tests pin the attestation RULES and therefore run on the model
// provider, so they hold on every toolchain. The same rules are exercised on
// real ML-DSA in pqmldsa_go127_test.go and in the agent and Core packages.

type attestFixture struct {
	devicePublic  ed25519.PublicKey
	devicePrivate ed25519.PrivateKey
	corePublic    ed25519.PublicKey
	devicePQ      *MockPQKeyPair
	corePQ        *MockPQKeyPair
	deviceID      string
}

func newAttestFixture(t *testing.T) attestFixture {
	t.Helper()
	EnableMockPQIdentity()
	t.Cleanup(DisableMockPQIdentity)
	devicePublic, devicePrivate, _ := ed25519.GenerateKey(rand.Reader)
	corePublic, _, _ := ed25519.GenerateKey(rand.Reader)
	devicePQ, _ := NewMockPQKeyPair(PQSigMLDSA65)
	corePQ, _ := NewMockPQKeyPair(PQSigMLDSA65)
	return attestFixture{
		devicePublic: devicePublic, devicePrivate: devicePrivate, corePublic: corePublic,
		devicePQ: devicePQ, corePQ: corePQ,
		deviceID: DeviceID(PlatformMSM8916, devicePublic),
	}
}

func (f attestFixture) answer(t *testing.T, nonce string, withPQ, corePinned bool) IdentityAttestResponse {
	t.Helper()
	transcript := PairingTranscript{
		ProtocolMajor:   ProtocolMajor,
		DeviceID:        f.deviceID,
		DevicePublicKey: EncodeKey(f.devicePublic),
		CoreID:          "core-1",
		CorePublicKey:   EncodeKey(f.corePublic),
		Nonce:           nonce,
		IssuedAt:        42,
	}
	var signer PQSigner
	if withPQ {
		transcript.DevicePQ = f.devicePQ.Identity()
		signer = f.devicePQ
	}
	if corePinned {
		transcript.CorePQ = f.corePQ.Identity()
	}
	signature, err := SignPairingTranscript(transcript, f.devicePrivate, signer)
	if err != nil {
		t.Fatal(err)
	}
	return IdentityAttestResponse{Transcript: transcript, Signature: signature}
}

func (f attestFixture) expect(nonce string, policy PQIdentityPolicy) AttestationExpectation {
	return AttestationExpectation{
		Nonce: nonce, DeviceID: f.deviceID, DeviceKey: f.devicePublic,
		CoreID: "core-1", CoreKey: f.corePublic, CorePQ: f.corePQ.Identity(),
		Policy: policy,
	}
}

func TestAttestationDualIsVerifiedAndReturnsTheKeyToPin(t *testing.T) {
	f := newAttestFixture(t)
	nonce, err := NewAttestNonce()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAttestNonce(nonce); err != nil {
		t.Fatal(err)
	}
	result, err := VerifyIdentityAttestation(f.answer(t, nonce, true, true), f.expect(nonce, PQIdentityRequired))
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != IdentityDual || !SamePQIdentity(result.DevicePQ, f.devicePQ.Identity()) || !result.CorePQPinned {
		t.Fatalf("result: %+v", result)
	}
}

func TestAttestationClassicalOnlyIsNamedAndPinsNothing(t *testing.T) {
	f := newAttestFixture(t)
	nonce, _ := NewAttestNonce()
	result, err := VerifyIdentityAttestation(f.answer(t, nonce, false, false), f.expect(nonce, PQIdentityPreferred))
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != IdentityClassicalOnly || result.DevicePQ.Present() || result.CorePQPinned {
		t.Fatalf("result: %+v", result)
	}
	if _, err := VerifyIdentityAttestation(f.answer(t, nonce, false, false), f.expect(nonce, PQIdentityRequired)); !errors.Is(err, ErrPQIdentityRequired) {
		t.Fatalf("required accepted a classical-only device: %v", err)
	}
}

func TestAttestationPinIsStickyUnderEveryPolicy(t *testing.T) {
	f := newAttestFixture(t)
	nonce, _ := NewAttestNonce()
	for _, policy := range []PQIdentityPolicy{PQIdentityOptional, PQIdentityPreferred, PQIdentityRequired} {
		expect := f.expect(nonce, policy)
		expect.PinnedPQ = f.devicePQ.Identity()

		// The pinned key, presented and signed: fine.
		if result, err := VerifyIdentityAttestation(f.answer(t, nonce, true, true), expect); err != nil || result.Outcome != IdentityDual {
			t.Fatalf("%s: pinned key refused: %+v %v", policy, result, err)
		}
		// No post-quantum identity at all: a downgrade, refused.
		if _, err := VerifyIdentityAttestation(f.answer(t, nonce, false, true), expect); !errors.Is(err, ErrPQIdentityWithdrawn) {
			t.Fatalf("%s: a withdrawn identity was accepted: %v", policy, err)
		}
		// A different key, validly signed: a substitution, refused.
		other := f
		other.devicePQ, _ = NewMockPQKeyPair(PQSigMLDSA65)
		if _, err := VerifyIdentityAttestation(other.answer(t, nonce, true, true), expect); !errors.Is(err, ErrPQIdentityChanged) {
			t.Fatalf("%s: a replaced key was accepted: %v", policy, err)
		}
	}
}

func TestAttestationRefusesATranscriptAboutSomethingElse(t *testing.T) {
	f := newAttestFixture(t)
	nonce, _ := NewAttestNonce()
	otherNonce, _ := NewAttestNonce()
	good := f.expect(nonce, PQIdentityPreferred)

	replay := f.answer(t, otherNonce, true, true)
	if _, err := VerifyIdentityAttestation(replay, good); !errors.Is(err, ErrAttestationMismatch) {
		t.Fatalf("a transcript for another nonce was accepted: %v", err)
	}

	mutations := map[string]func(*AttestationExpectation){
		"device id":  func(e *AttestationExpectation) { e.DeviceID = "NSH-410-FFFFFF" },
		"device key": func(e *AttestationExpectation) { e.DeviceKey = f.corePublic },
		"core id":    func(e *AttestationExpectation) { e.CoreID = "core-2" },
		"core key":   func(e *AttestationExpectation) { e.CoreKey = f.devicePublic },
		"core pq": func(e *AttestationExpectation) {
			other, _ := NewMockPQKeyPair(PQSigMLDSA65)
			e.CorePQ = other.Identity()
		},
		"empty nonce": func(e *AttestationExpectation) { e.Nonce = "" },
	}
	for name, mutate := range mutations {
		expect := good
		mutate(&expect)
		if _, err := VerifyIdentityAttestation(f.answer(t, nonce, true, true), expect); !errors.Is(err, ErrAttestationMismatch) {
			t.Errorf("%s: accepted: %v", name, err)
		}
	}

	wrongMajor := f.answer(t, nonce, true, true)
	wrongMajor.Transcript.ProtocolMajor = ProtocolMajor + 1
	if _, err := VerifyIdentityAttestation(wrongMajor, good); !errors.Is(err, ErrAttestationMismatch) {
		t.Fatalf("another protocol major was accepted: %v", err)
	}
}

func TestAttestationRefusesForgedOrHalfSignedAnswers(t *testing.T) {
	f := newAttestFixture(t)
	nonce, _ := NewAttestNonce()
	expect := f.expect(nonce, PQIdentityOptional)

	// Edited after signing.
	edited := f.answer(t, nonce, true, true)
	edited.Transcript.IssuedAt++
	if _, err := VerifyIdentityAttestation(edited, expect); !errors.Is(err, ErrClassicalIdentityInvalid) {
		t.Fatalf("an edited transcript was accepted: %v", err)
	}

	// A published key with no signature is not an old device.
	published := f.answer(t, nonce, true, true)
	published.Signature.PQ, published.Signature.PQAlgorithm = "", ""
	if _, err := VerifyIdentityAttestation(published, expect); !errors.Is(err, ErrPQIdentityInvalid) {
		t.Fatalf("a key published without a signature was accepted: %v", err)
	}

	// Garbage in the post-quantum signature fails under optional too.
	garbage := f.answer(t, nonce, true, true)
	garbage.Signature.PQ = base64.StdEncoding.EncodeToString(make([]byte, 64))
	if _, err := VerifyIdentityAttestation(garbage, expect); !errors.Is(err, ErrPQIdentityInvalid) {
		t.Fatalf("a garbage signature was accepted: %v", err)
	}

	// A post-quantum signature by a key the classical signature did not cover.
	other, _ := NewMockPQKeyPair(PQSigMLDSA65)
	swapped := f.answer(t, nonce, true, true)
	raw, _ := other.Sign(swapped.Transcript.SigningBytes())
	swapped.Signature.PQ = base64.StdEncoding.EncodeToString(raw)
	if _, err := VerifyIdentityAttestation(swapped, expect); !errors.Is(err, ErrPQIdentityInvalid) {
		t.Fatalf("a signature by an unbound key was accepted: %v", err)
	}
}

func TestAttestationWithoutAProviderNeverReportsDual(t *testing.T) {
	f := newAttestFixture(t)
	nonce, _ := NewAttestNonce()
	answer := f.answer(t, nonce, true, true)
	DisableMockPQIdentity()

	result, err := VerifyIdentityAttestation(answer, f.expect(nonce, PQIdentityPreferred))
	if err != nil || result.Outcome != IdentityClassicalOnly || result.DevicePQ.Present() {
		t.Fatalf("an unverifiable signature must be classical-only and pin nothing: %+v %v", result, err)
	}
	if _, err := VerifyIdentityAttestation(answer, f.expect(nonce, PQIdentityRequired)); !errors.Is(err, ErrPQIdentityRequired) {
		t.Fatalf("required passed without a provider: %v", err)
	}
	pinned := f.expect(nonce, PQIdentityOptional)
	pinned.PinnedPQ = f.devicePQ.Identity()
	if _, err := VerifyIdentityAttestation(answer, pinned); !errors.Is(err, ErrPQIdentityRequired) {
		t.Fatalf("a pinned device passed on a build that cannot verify it: %v", err)
	}
}

func TestAttestNonceBounds(t *testing.T) {
	for _, bad := range []string{"", "!!!", base64.StdEncoding.EncodeToString(make([]byte, 8)), base64.StdEncoding.EncodeToString(make([]byte, 65))} {
		if ValidateAttestNonce(bad) == nil {
			t.Errorf("nonce %q was accepted", bad)
		}
	}
}

func TestCorePQSignatureRules(t *testing.T) {
	EnableMockPQIdentity()
	t.Cleanup(DisableMockPQIdentity)
	key, _ := NewMockPQKeyPair(PQSigMLDSA65)
	other, _ := NewMockPQKeyPair(PQSigMLDSA65)
	message := SigningString("POST", "/v1/session", "2026-01-01T00:00:00Z", "n", []byte("{}"))
	sign := func(k *MockPQKeyPair) string {
		raw, _ := k.Sign(message)
		return base64.StdEncoding.EncodeToString(raw)
	}
	none := PQIdentity{}

	// Nothing offered, nothing pinned.
	if ok, err := VerifyCorePQSignature(message, "", "", none, none, PQIdentityPreferred); ok || err != nil {
		t.Fatalf("classical request under preferred: %v %v", ok, err)
	}
	if _, err := VerifyCorePQSignature(message, "", "", none, none, PQIdentityRequired); !errors.Is(err, ErrPQIdentityRequired) {
		t.Fatalf("classical request under required: %v", err)
	}
	// First offer verifies against the offered key.
	if ok, err := VerifyCorePQSignature(message, sign(key), PQSigMLDSA65, none, key.Identity(), PQIdentityPreferred); !ok || err != nil {
		t.Fatalf("first dual request: %v %v", ok, err)
	}
	// A key offered without a signature is refused, not ignored.
	if _, err := VerifyCorePQSignature(message, "", "", none, key.Identity(), PQIdentityOptional); !errors.Is(err, ErrPQIdentityInvalid) {
		t.Fatalf("an unsigned offer was accepted: %v", err)
	}
	// A signature with no key anywhere - a Core that gained its key after
	// pairing - is a classical request, and a refusal only under required.
	if ok, err := VerifyCorePQSignature(message, sign(key), PQSigMLDSA65, none, none, PQIdentityPreferred); ok || err != nil {
		t.Fatalf("keyless signature under preferred: %v %v", ok, err)
	}
	if _, err := VerifyCorePQSignature(message, sign(key), PQSigMLDSA65, none, none, PQIdentityRequired); !errors.Is(err, ErrPQIdentityRequired) {
		t.Fatalf("keyless signature under required: %v", err)
	}
	// Pinned: the signature becomes mandatory under every policy.
	if _, err := VerifyCorePQSignature(message, "", "", key.Identity(), none, PQIdentityOptional); !errors.Is(err, ErrPQIdentityWithdrawn) {
		t.Fatalf("a pinned core dropped its signature: %v", err)
	}
	if ok, err := VerifyCorePQSignature(message, sign(key), PQSigMLDSA65, key.Identity(), none, PQIdentityOptional); !ok || err != nil {
		t.Fatalf("pinned core, valid signature: %v %v", ok, err)
	}
	// Pinned: another key cannot be offered in its place.
	if _, err := VerifyCorePQSignature(message, sign(other), PQSigMLDSA65, key.Identity(), other.Identity(), PQIdentityOptional); !errors.Is(err, ErrPQIdentityChanged) {
		t.Fatalf("a replacement key was accepted: %v", err)
	}
	// Pinned: a signature by another key fails.
	if _, err := VerifyCorePQSignature(message, sign(other), PQSigMLDSA65, key.Identity(), none, PQIdentityOptional); !errors.Is(err, ErrPQIdentityInvalid) {
		t.Fatalf("a signature by another key was accepted: %v", err)
	}
	// Algorithm named by the signer must match the identity.
	if _, err := VerifyCorePQSignature(message, sign(key), PQSigMLDSA87, key.Identity(), none, PQIdentityOptional); !errors.Is(err, ErrPQIdentityInvalid) {
		t.Fatalf("an algorithm mismatch was accepted: %v", err)
	}
	// A signature over other bytes fails.
	if _, err := VerifyCorePQSignature([]byte("other"), sign(key), PQSigMLDSA65, key.Identity(), none, PQIdentityOptional); !errors.Is(err, ErrPQIdentityInvalid) {
		t.Fatalf("a signature over other bytes was accepted: %v", err)
	}

	// Without a provider: an unpinned offer contributes nothing and must not be
	// pinned; a pinned or required one is refused.
	DisableMockPQIdentity()
	if ok, err := VerifyCorePQSignature(message, sign(key), PQSigMLDSA65, none, key.Identity(), PQIdentityPreferred); ok || err != nil {
		t.Fatalf("unverifiable offer under preferred: %v %v", ok, err)
	}
	if _, err := VerifyCorePQSignature(message, sign(key), PQSigMLDSA65, key.Identity(), none, PQIdentityPreferred); !errors.Is(err, ErrPQIdentityRequired) {
		t.Fatalf("pinned key on a build without a provider: %v", err)
	}
	if _, err := VerifyCorePQSignature(message, sign(key), PQSigMLDSA65, none, key.Identity(), PQIdentityRequired); !errors.Is(err, ErrPQIdentityRequired) {
		t.Fatalf("required on a build without a provider: %v", err)
	}
}

func TestPairRequestCarriesTheCoreKeyOnlyWhenItHasOne(t *testing.T) {
	if (PairRequest{}).OfferedPQ().Present() {
		t.Fatal("an empty pair request offers a post-quantum key")
	}
	identity := PQIdentity{Algorithm: PQSigMLDSA65, PublicKey: "QUJD"}
	if !SamePQIdentity((PairRequest{CorePQ: &identity}).OfferedPQ(), identity) {
		t.Fatal("the offered key was not returned")
	}
}

func TestExtremeLevelAcceptsOnlyTheLargestParameterSet(t *testing.T) {
	small := PQIdentity{Algorithm: PQSigMLDSA65, PublicKey: "QUJD"}
	large := PQIdentity{Algorithm: PQSigMLDSA87, PublicKey: "QUJD"}
	for _, level := range []SecurityLevel{LevelStandard, LevelPQ} {
		if CheckPQAlgorithmForLevel(level, small) != nil || CheckPQAlgorithmForLevel(level, large) != nil {
			t.Fatalf("%s refused a valid parameter set", level)
		}
	}
	if err := CheckPQAlgorithmForLevel(LevelPQExtreme, small); !errors.Is(err, ErrPQAlgorithmTooWeak) {
		t.Fatalf("PQ_EXTREME accepted ml-dsa-65: %v", err)
	}
	if err := CheckPQAlgorithmForLevel(LevelPQExtreme, large); err != nil {
		t.Fatal(err)
	}
	if err := CheckPQAlgorithmForLevel(LevelPQExtreme, PQIdentity{}); err != nil {
		t.Fatalf("an absent identity is the policy's concern, not this check's: %v", err)
	}
}
