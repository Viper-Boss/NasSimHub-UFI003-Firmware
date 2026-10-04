package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

// The dual-identity rules, and the version semantics that decide what a build
// may claim about itself.

func transcript(t *testing.T, devicePQ, corePQ PQIdentity) (PairingTranscript, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return PairingTranscript{
		ProtocolMajor:   ProtocolMajor,
		DeviceID:        "NSH-410-A83F29",
		DevicePublicKey: EncodeKey(public),
		DevicePQ:        devicePQ,
		CoreID:          "core-a",
		CorePublicKey:   "core-key",
		CorePQ:          corePQ,
		Nonce:           "nonce-1",
		IssuedAt:        1789000000,
	}, public, private
}

func TestATranscriptEncodesUnambiguously(t *testing.T) {
	// The failure this guards against: a field boundary an attacker can move.
	// With a delimiter-joined encoding, a device_id containing the delimiter
	// could make one transcript encode identically to a different one.
	left, _, _ := transcript(t, PQIdentity{}, PQIdentity{})
	right := left
	left.DeviceID = "A"
	left.CoreID = "BC"
	right.DeviceID = "AB"
	right.CoreID = "C"
	if string(left.SigningBytes()) == string(right.SigningBytes()) {
		t.Fatal("two different transcripts encode to the same bytes")
	}
}

func TestATranscriptIsDomainSeparated(t *testing.T) {
	document, _, _ := transcript(t, PQIdentity{}, PQIdentity{})
	bytes := document.SigningBytes()
	if !containsSub(bytes, []byte(transcriptDomain)) {
		t.Fatal("the transcript carries no domain separator, so a pairing signature could be replayed as another kind of signature")
	}
}

func containsSub(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

func TestClassicalOnlyPairingIsAcceptedUnderPreferredAndNamedAsSuch(t *testing.T) {
	DisableMockPQIdentity()
	document, public, private := transcript(t, PQIdentity{}, PQIdentity{})
	signature, err := SignPairingTranscript(document, private, nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := VerifyPairingTranscript(document, signature, public, PQIdentity{}, PQIdentityPreferred)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != IdentityClassicalOnly {
		t.Fatalf("outcome is %q, want classical_only", outcome)
	}
}

// The central rule: REQUIRED refuses a peer with no post-quantum identity.
func TestRequiredRefusesAClassicalOnlyPeer(t *testing.T) {
	EnableMockPQIdentity()
	defer DisableMockPQIdentity()

	document, public, private := transcript(t, PQIdentity{}, PQIdentity{})
	signature, err := SignPairingTranscript(document, private, nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := VerifyPairingTranscript(document, signature, public, PQIdentity{}, PQIdentityRequired)
	if !errors.Is(err, ErrPQIdentityRequired) {
		t.Fatalf("a classical-only peer under REQUIRED returned %v", err)
	}
	if outcome != "" {
		t.Fatalf("a refused verification produced outcome %q", outcome)
	}
}

func TestDualSigningVerifiesUnderEveryPolicy(t *testing.T) {
	EnableMockPQIdentity()
	defer DisableMockPQIdentity()

	pair, err := NewMockPQKeyPair(PQSigMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	document, public, private := transcript(t, pair.Identity(), PQIdentity{})
	signature, err := SignPairingTranscript(document, private, pair)
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range []PQIdentityPolicy{PQIdentityOptional, PQIdentityPreferred, PQIdentityRequired} {
		outcome, err := VerifyPairingTranscript(document, signature, public, pair.Identity(), policy)
		if err != nil {
			t.Fatalf("policy %s: %v", policy, err)
		}
		if outcome != IdentityDual {
			t.Fatalf("policy %s produced outcome %q", policy, outcome)
		}
	}
}

// A post-quantum signature that does not verify is a failure under EVERY
// policy, not only under required. Otherwise an attacker downgrades by sending
// noise: a preferred verifier that shrugged at a broken signature would accept
// a peer who deliberately broke it.
func TestABrokenPostQuantumSignatureFailsUnderEveryPolicy(t *testing.T) {
	EnableMockPQIdentity()
	defer DisableMockPQIdentity()

	pair, err := NewMockPQKeyPair(PQSigMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	document, public, private := transcript(t, pair.Identity(), PQIdentity{})
	signature, err := SignPairingTranscript(document, private, pair)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(signature.PQ)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xFF
	signature.PQ = base64.StdEncoding.EncodeToString(raw)

	for _, policy := range []PQIdentityPolicy{PQIdentityOptional, PQIdentityPreferred, PQIdentityRequired} {
		if _, err := VerifyPairingTranscript(document, signature, public, pair.Identity(), policy); err == nil {
			t.Fatalf("policy %s accepted a broken post-quantum signature", policy)
		}
	}
}

// A build that cannot verify post-quantum signatures must not report a dual
// outcome. Reporting one would be the overstatement the whole design avoids.
func TestAnUnverifiableSignatureIsNotReportedAsDual(t *testing.T) {
	EnableMockPQIdentity()
	pair, err := NewMockPQKeyPair(PQSigMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	document, public, private := transcript(t, pair.Identity(), PQIdentity{})
	signature, err := SignPairingTranscript(document, private, pair)
	if err != nil {
		t.Fatal(err)
	}
	// Now take the provider away: this is a build with no ML-DSA.
	DisableMockPQIdentity()

	outcome, err := VerifyPairingTranscript(document, signature, public, pair.Identity(), PQIdentityPreferred)
	if err != nil {
		t.Fatal(err)
	}
	if outcome == IdentityDual {
		t.Fatal("a build that cannot verify post-quantum signatures reported a dual identity")
	}
	if outcome != IdentityClassicalOnly {
		t.Fatalf("outcome is %q", outcome)
	}
	// And under REQUIRED it is a refusal, not a shrug.
	if _, err := VerifyPairingTranscript(document, signature, public, pair.Identity(), PQIdentityRequired); !errors.Is(err, ErrPQIdentityRequired) {
		t.Fatalf("REQUIRED on a build with no verifier returned %v", err)
	}
}

func TestAnAlgorithmMismatchIsRefused(t *testing.T) {
	EnableMockPQIdentity()
	defer DisableMockPQIdentity()

	pair, err := NewMockPQKeyPair(PQSigMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	document, public, private := transcript(t, pair.Identity(), PQIdentity{})
	signature, err := SignPairingTranscript(document, private, pair)
	if err != nil {
		t.Fatal(err)
	}
	// The signature claims a different parameter set from the identity. A
	// verifier that picked the algorithm itself could be steered into checking
	// a strong signature with a weak verifier.
	signature.PQAlgorithm = PQSigMLDSA87
	if _, err := VerifyPairingTranscript(document, signature, public, pair.Identity(), PQIdentityRequired); !errors.Is(err, ErrPQIdentityInvalid) {
		t.Fatalf("an algorithm mismatch returned %v", err)
	}
}

func TestAWrongClassicalSignatureEndsItImmediately(t *testing.T) {
	EnableMockPQIdentity()
	defer DisableMockPQIdentity()

	pair, err := NewMockPQKeyPair(PQSigMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	document, public, private := transcript(t, pair.Identity(), PQIdentity{})
	signature, err := SignPairingTranscript(document, private, pair)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = public
	if _, err := VerifyPairingTranscript(document, signature, other, pair.Identity(), PQIdentityRequired); !errors.Is(err, ErrClassicalIdentityInvalid) {
		t.Fatalf("a wrong classical key returned %v", err)
	}
}

func TestTheMockBackendIsNamedInTheCapability(t *testing.T) {
	DisableMockPQIdentity()
	if PQBackendName() != "none" {
		t.Fatalf("backend is %q with no provider", PQBackendName())
	}
	capability := DescribeIdentity(PQIdentity{}, PQIdentityOptional)
	if capability.PQAvailable {
		t.Fatal("a build with no provider reported post-quantum identity as available")
	}
	if capability.RequiresToolchain != GoVersionForMLDSA {
		t.Fatalf("requires_toolchain is %q", capability.RequiresToolchain)
	}

	EnableMockPQIdentity()
	defer DisableMockPQIdentity()
	if PQBackendName() != MockBackendName {
		t.Fatalf("backend is %q with the mock enabled", PQBackendName())
	}
	// A device running the model must be visibly running the model. If this
	// ever reports something that could be mistaken for a real implementation,
	// a screenshot of a status page becomes a false claim.
	capability = DescribeIdentity(PQIdentity{}, PQIdentityPreferred)
	if capability.Backend != MockBackendName {
		t.Fatalf("the capability document reports backend %q", capability.Backend)
	}
}

// ---------------------------------------------------------------------------
// Security levels and toolchain semantics
// ---------------------------------------------------------------------------

func TestTheThreeLevelsMapOntoCoherentSettings(t *testing.T) {
	cases := []struct {
		level   SecurityLevel
		profile PQProfile
		policy  PQPolicy
	}{
		{LevelStandard, PQStandard, PQPreferred},
		{LevelPQ, PQStandard, PQRequired},
		{LevelPQExtreme, PQExtreme, PQRequired},
	}
	for _, testCase := range cases {
		profile, policy := ProfileAndPolicyFor(testCase.level)
		if profile != testCase.profile || policy != testCase.policy {
			t.Fatalf("%s maps to %s/%s", testCase.level, profile, policy)
		}
	}
	// There is no level that combines extreme groups with a fallback, which is
	// the incoherent combination the levels exist to remove.
	for _, level := range []SecurityLevel{LevelStandard, LevelPQ, LevelPQExtreme} {
		profile, policy := ProfileAndPolicyFor(level)
		if profile == PQExtreme && policy != PQRequired {
			t.Fatalf("%s permits classical key agreement while promising extreme", level)
		}
	}
}

func TestAnOldRecordMapsDownwardNotUpward(t *testing.T) {
	// Extreme profile, preferred policy: an old combination that PERMITTED
	// classical key agreement. Reading it back as PQ_EXTREME would
	// retroactively overstate what that connection did.
	if level := LevelFor(PQExtreme, PQPreferred); level == LevelPQExtreme {
		t.Fatal("a preferred policy read back as PQ_EXTREME")
	}
	if level := LevelFor(PQExtreme, PQRequired); level != LevelPQExtreme {
		t.Fatalf("extreme+required read back as %q", level)
	}
	if level := LevelFor(PQStandard, PQRequired); level != LevelPQ {
		t.Fatalf("standard+required read back as %q", level)
	}
}

func TestAnUnknownLevelIsRefusedRatherThanDefaulted(t *testing.T) {
	if err := ValidateSecurityLevel("PQ_ULTRA"); err == nil {
		t.Fatal("an unknown level was accepted, so a typo becomes a silent downgrade")
	}
	for _, level := range []SecurityLevel{LevelStandard, LevelPQ, LevelPQExtreme} {
		if err := ValidateSecurityLevel(level); err != nil {
			t.Fatalf("%s: %v", level, err)
		}
	}
}

// The version-semantics fix. On a toolchain without the SecP hybrids,
// PQ_EXTREME must report "needs a newer toolchain", NOT "unsupported": the
// product supports it and the target toolchain has it.
func TestExtremeReportsAToolchainRequirementRatherThanUnsupported(t *testing.T) {
	status := StatusOfLevel(LevelPQExtreme)
	if status == LevelUnsupported {
		t.Fatal("PQ_EXTREME reports unsupported, which describes this container rather than the product")
	}
	if !BuildSupportsGroup(GroupSecP384r1MLKEM1024) && status != LevelNeedsToolchain {
		t.Fatalf("on a toolchain without the SecP hybrids, PQ_EXTREME reports %q", status)
	}
	if BuildSupportsGroup(GroupSecP384r1MLKEM1024) && status != LevelAvailable {
		t.Fatalf("on a toolchain with the SecP hybrids, PQ_EXTREME reports %q", status)
	}
}

func TestTheGroupStatusNamesTheRightToolchain(t *testing.T) {
	if ToolchainFor(LevelPQExtreme) != GoVersionForSecPHybrids {
		t.Fatalf("PQ_EXTREME asks for %q, want %q", ToolchainFor(LevelPQExtreme), GoVersionForSecPHybrids)
	}
	if ToolchainFor(LevelPQ) != GoVersionForX25519MLKEM768 {
		t.Fatalf("PQ asks for %q", ToolchainFor(LevelPQ))
	}
	// X25519MLKEM768 exists from Go 1.24, which every supported toolchain has.
	if StatusOfGroup(GroupX25519MLKEM768) != GroupAvailable {
		t.Fatal("the standard hybrid is not available, which no supported toolchain should produce")
	}
	// A group this product does not know is unknown, not "needs a toolchain":
	// no upgrade will ever produce it.
	if StatusOfGroup(0xFFFF) != GroupUnknown {
		t.Fatalf("an unknown group reports %q", StatusOfGroup(0xFFFF))
	}
}

func TestTheTargetToolchainIsRecorded(t *testing.T) {
	// The honest answer to "is PQ_EXTREME supported" depends on which
	// toolchain is being asked about. Recording the target is what lets the
	// documentation and the UI say "needs go1.26" rather than "no".
	if TargetGoVersion == "" {
		t.Fatal("no target toolchain is recorded")
	}
	if GoVersionForSecPHybrids != "go1.26" {
		t.Fatalf("the SecP hybrid requirement is recorded as %q", GoVersionForSecPHybrids)
	}
	if GoVersionForX25519MLKEM768 != "go1.24" {
		t.Fatalf("the standard hybrid requirement is recorded as %q", GoVersionForX25519MLKEM768)
	}
	if GoVersionForMLDSA != "go1.27" {
		t.Fatalf("the ML-DSA requirement is recorded as %q", GoVersionForMLDSA)
	}
}

func TestExtremeDemandsDualIdentityAndDualSignatures(t *testing.T) {
	if IdentityRequirementFor(LevelPQExtreme) != PQIdentityRequired {
		t.Fatal("PQ_EXTREME does not require a post-quantum identity")
	}
	if OTARequirementFor(LevelPQExtreme) != OTASignatureRequired {
		t.Fatal("PQ_EXTREME does not require dual-signed updates")
	}
	// And the weaker levels do not, or they would be unusable today.
	if OTARequirementFor(LevelPQ) != OTASignaturePreferred {
		t.Fatal("PQ requires dual-signed updates, which no publisher can produce yet")
	}
	if IdentityRequirementFor(LevelStandard) != PQIdentityOptional {
		t.Fatal("STANDARD demands a post-quantum identity")
	}
}

func TestThePQAlgorithmFollowsTheLevel(t *testing.T) {
	if PQAlgorithmFor(LevelPQExtreme) != PQSigMLDSA87 {
		t.Fatal("PQ_EXTREME does not use ML-DSA-87")
	}
	if PQAlgorithmFor(LevelPQ) != PQSigMLDSA65 {
		t.Fatal("PQ does not use ML-DSA-65")
	}
	if err := ValidatePQSignatureAlgorithm("ml-dsa-44"); err == nil {
		t.Fatal("an algorithm outside the two this product uses was accepted")
	}
}
