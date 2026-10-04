package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

// Hybrid update signatures: what is accepted, what is refused, and what the
// device is told about which happened.

func releaseKeys(t *testing.T) (OTAKeyring, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return OTAKeyring{"release-1": public}, private
}

func simpleManifest() OTAManifest {
	return OTAManifest{
		SchemaVersion: OTASchemaVersion,
		Version:       "1.2.0",
		Artifacts: []OTAArtifact{{
			Name:   "nassimhub-agent",
			SHA256: ArtifactDigest([]byte("binary")),
			Size:   int64(len("binary")),
		}},
	}
}

func TestAClassicalOnlyManifestIsAcceptedUnderPreferredAndNamed(t *testing.T) {
	DisableMockPQIdentity()
	keyring, private := releaseKeys(t)
	signed, err := SignManifest(simpleManifest(), "release-1", private)
	if err != nil {
		t.Fatal(err)
	}
	manifest, outcome, err := VerifyManifestHybrid(signed, keyring, nil, OTASignaturePreferred)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != OTAClassicalOnly {
		t.Fatalf("outcome is %q", outcome)
	}
	if manifest.Version != "1.2.0" {
		t.Fatalf("manifest version is %q", manifest.Version)
	}
}

// The rule that matters: a device set to REQUIRED must not install an update
// that carries only a classical signature.
func TestRequiredRefusesAClassicalOnlyManifest(t *testing.T) {
	EnableMockPQIdentity()
	defer DisableMockPQIdentity()

	keyring, private := releaseKeys(t)
	signed, err := SignManifest(simpleManifest(), "release-1", private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyManifestHybrid(signed, keyring, nil, OTASignatureRequired); !errors.Is(err, ErrOTAPQUnsigned) {
		t.Fatalf("a classical-only manifest under REQUIRED returned %v", err)
	}
}

func TestADualSignedManifestVerifies(t *testing.T) {
	EnableMockPQIdentity()
	defer DisableMockPQIdentity()

	keyring, private := releaseKeys(t)
	pair, err := NewMockPQKeyPair(PQSigMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignManifestHybrid(simpleManifest(), "release-1", private, "pq-release-1", pair)
	if err != nil {
		t.Fatal(err)
	}
	pqKeyring := OTAPQKeyring{"pq-release-1": pair.Identity()}
	for _, policy := range []OTASignaturePolicy{OTASignaturePreferred, OTASignatureRequired} {
		_, outcome, err := VerifyManifestHybrid(signed, keyring, pqKeyring, policy)
		if err != nil {
			t.Fatalf("policy %s: %v", policy, err)
		}
		if outcome != OTADualSigned {
			t.Fatalf("policy %s produced outcome %q", policy, outcome)
		}
	}
}

// Both signatures cover the same bytes, so tampering breaks both.
func TestTamperingBreaksBothSignatures(t *testing.T) {
	EnableMockPQIdentity()
	defer DisableMockPQIdentity()

	keyring, private := releaseKeys(t)
	pair, err := NewMockPQKeyPair(PQSigMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignManifestHybrid(simpleManifest(), "release-1", private, "pq-release-1", pair)
	if err != nil {
		t.Fatal(err)
	}
	signed.Manifest = append([]byte(nil), signed.Manifest...)
	signed.Manifest[10] ^= 0x20

	if _, _, err := VerifyManifestHybrid(signed, keyring,
		OTAPQKeyring{"pq-release-1": pair.Identity()}, OTASignaturePreferred); err == nil {
		t.Fatal("a tampered manifest verified")
	}
}

// A broken post-quantum signature is a failure under every policy: otherwise
// appending noise turns REQUIRED into PREFERRED.
func TestABrokenPostQuantumManifestSignatureFailsUnderEveryPolicy(t *testing.T) {
	EnableMockPQIdentity()
	defer DisableMockPQIdentity()

	keyring, private := releaseKeys(t)
	pair, err := NewMockPQKeyPair(PQSigMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignManifestHybrid(simpleManifest(), "release-1", private, "pq-release-1", pair)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(signed.PQSignature)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xFF
	signed.PQSignature = base64.StdEncoding.EncodeToString(raw)

	pqKeyring := OTAPQKeyring{"pq-release-1": pair.Identity()}
	for _, policy := range []OTASignaturePolicy{OTASignaturePreferred, OTASignatureRequired} {
		if _, _, err := VerifyManifestHybrid(signed, keyring, pqKeyring, policy); err == nil {
			t.Fatalf("policy %s accepted a broken post-quantum signature", policy)
		}
	}
}

func TestAnUnknownPostQuantumKeyIDIsRefused(t *testing.T) {
	EnableMockPQIdentity()
	defer DisableMockPQIdentity()

	keyring, private := releaseKeys(t)
	pair, err := NewMockPQKeyPair(PQSigMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignManifestHybrid(simpleManifest(), "release-1", private, "pq-release-1", pair)
	if err != nil {
		t.Fatal(err)
	}
	// The device's ring does not contain that key id.
	if _, _, err := VerifyManifestHybrid(signed, keyring, OTAPQKeyring{}, OTASignaturePreferred); !errors.Is(err, ErrOTAPQUnsigned) {
		t.Fatalf("an unknown post-quantum key id returned %v", err)
	}
}

// A build that cannot check the signature must refuse under REQUIRED, and must
// not call the result dual-signed under PREFERRED.
func TestABuildWithoutMLDSARefusesRequiredAndDoesNotClaimDual(t *testing.T) {
	EnableMockPQIdentity()
	keyring, private := releaseKeys(t)
	pair, err := NewMockPQKeyPair(PQSigMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignManifestHybrid(simpleManifest(), "release-1", private, "pq-release-1", pair)
	if err != nil {
		t.Fatal(err)
	}
	pqKeyring := OTAPQKeyring{"pq-release-1": pair.Identity()}
	DisableMockPQIdentity()

	if _, _, err := VerifyManifestHybrid(signed, keyring, pqKeyring, OTASignatureRequired); !errors.Is(err, ErrOTAPQUnavailable) {
		t.Fatalf("REQUIRED on a build with no verifier returned %v", err)
	}
	_, outcome, err := VerifyManifestHybrid(signed, keyring, pqKeyring, OTASignaturePreferred)
	if err != nil {
		t.Fatal(err)
	}
	if outcome == OTADualSigned {
		t.Fatal("a build that cannot verify post-quantum signatures called the manifest dual-signed")
	}
}

// The classical signature is still checked first and still decides.
func TestAWrongClassicalSignatureIsRefusedEvenWhenDualSigned(t *testing.T) {
	EnableMockPQIdentity()
	defer DisableMockPQIdentity()

	_, private := releaseKeys(t)
	otherKeyring, _ := releaseKeys(t)
	pair, err := NewMockPQKeyPair(PQSigMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignManifestHybrid(simpleManifest(), "release-1", private, "pq-release-1", pair)
	if err != nil {
		t.Fatal(err)
	}
	// otherKeyring holds a different key under the same id.
	if _, _, err := VerifyManifestHybrid(signed, otherKeyring,
		OTAPQKeyring{"pq-release-1": pair.Identity()}, OTASignaturePreferred); !errors.Is(err, ErrOTAUnsigned) {
		t.Fatalf("a wrong classical signature returned %v", err)
	}
}

func TestTheSignatureCapabilityNamesWhatIsMissing(t *testing.T) {
	DisableMockPQIdentity()
	capability := DescribeOTASignatures(OTASignaturePreferred, OTAClassicalOnly)
	if capability.PQAvailable {
		t.Fatal("a build with no provider reported post-quantum verification as available")
	}
	if capability.RequiresToolchain != GoVersionForMLDSA {
		t.Fatalf("requires_toolchain is %q", capability.RequiresToolchain)
	}
	if capability.Outcome != OTAClassicalOnly {
		t.Fatalf("outcome is %q", capability.Outcome)
	}
}

func TestAnUnknownSignaturePolicyIsRefused(t *testing.T) {
	if err := ValidateOTASignaturePolicy("whenever"); err == nil {
		t.Fatal("an unknown OTA signature policy was accepted")
	}
}
