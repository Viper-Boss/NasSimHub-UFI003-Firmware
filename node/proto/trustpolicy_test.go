package proto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// testTrustKey is derived from a constant seed. It is a fixture, not a secret:
// nothing outside this test trusts it.
func testTrustKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
}

func testTrustPolicy() TrustPolicy {
	return TrustPolicy{
		Version: TrustPolicyVersion, DeviceID: "NSH-410-TESTDEVICE01", CoreID: "core-test-0001", Generation: 7,
		State: TrustObservation, Mode: TrustEnforce,
		Deny:   []TrustAction{TrustActionDial, TrustActionDTMF, TrustActionSendSMS},
		Reason: "first binding", IssuedAt: "2026-10-05T08:00:00Z", ExpiresAt: "2026-10-06T08:00:00Z",
	}
}

func testTrustExpectation(key ed25519.PrivateKey) TrustPolicyExpectation {
	return TrustPolicyExpectation{DeviceID: "NSH-410-TESTDEVICE01", CoreID: "core-test-0001",
		CoreKey: key.Public().(ed25519.PublicKey), PQPolicy: PQIdentityOptional}
}

// The golden vector pins the signed bytes. If this test fails, every policy a
// deployed gateway has signed stops verifying: change TrustPolicyDomain's
// version rather than this vector.
const goldenTrustCanonical = "nsh-domain=trust-policy-v1\n" +
	"version=1\n" +
	"device_id=NSH-410-TESTDEVICE01\n" +
	"core_id=core-test-0001\n" +
	"generation=7\n" +
	"state=OBSERVATION\n" +
	"mode=enforce\n" +
	"deny=dial,dtmf,send_sms\n" +
	"reason=first binding\n" +
	"issued_at=2026-10-05T08:00:00Z\n" +
	"expires_at=2026-10-06T08:00:00Z\n"

const goldenTrustSignature = "HYdIXPUs1x1ApJWqru6Rpla60fUx2nHj9ljNp4Cq/E0uxOxGMb1GKmTMK0fRVCBNBBHQJTz3W1vYveYIoLALDQ=="

func TestTrustPolicyCanonicalGoldenVector(t *testing.T) {
	canonical, err := testTrustPolicy().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != goldenTrustCanonical {
		t.Fatalf("canonical bytes changed:\n%q\nwant\n%q", canonical, goldenTrustCanonical)
	}
	signed, err := SignTrustPolicy(testTrustPolicy(), testTrustKey(0x42), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Ed25519 is deterministic, so the signature is part of the vector.
	if signed.Signature != goldenTrustSignature {
		t.Fatalf("signature over the golden bytes changed: %s", signed.Signature)
	}
	// An empty deny list is a line with an empty value, not a missing line.
	empty := testTrustPolicy()
	empty.Deny, empty.Reason, empty.State = []TrustAction{}, "", TrustTrusted
	canonical, err = empty.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(canonical), "\ndeny=\nreason=\nissued_at=") {
		t.Fatalf("empty fields must keep their lines: %q", canonical)
	}
	// The signed bytes do not depend on how the JSON was laid out.
	encoded, _ := json.MarshalIndent(signed, "  ", "\t")
	decoded, err := DecodeSignedTrustPolicy(encoded)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := decoded.Canonical()
	if string(again) != goldenTrustCanonical || !SameSignedTrustPolicy(signed, decoded) {
		t.Fatal("a policy must survive its JSON envelope unchanged")
	}
}

func TestTrustPolicySignatureVerifies(t *testing.T) {
	key := testTrustKey(0x42)
	signed, err := SignTrustPolicy(testTrustPolicy(), key, nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := VerifyTrustPolicy(signed, testTrustExpectation(key))
	if err != nil || outcome != IdentityClassicalOnly {
		t.Fatalf("verify: %s %v", outcome, err)
	}
	// Another key, the right device and core names.
	if _, err := VerifyTrustPolicy(signed, testTrustExpectation(testTrustKey(0x43))); !errors.Is(err, ErrTrustPolicySignature) {
		t.Fatalf("a policy signed by another key must be refused: %v", err)
	}
	// Replayed at another device, or presented as another core's.
	other := testTrustExpectation(key)
	other.DeviceID = "NSH-410-TESTDEVICE02"
	if _, err := VerifyTrustPolicy(signed, other); !errors.Is(err, ErrTrustPolicyWrongDevice) {
		t.Fatalf("a policy for another device must be refused: %v", err)
	}
	other = testTrustExpectation(key)
	other.CoreID = "core-test-0002"
	if _, err := VerifyTrustPolicy(signed, other); !errors.Is(err, ErrTrustPolicyWrongCore) {
		t.Fatalf("a policy from another core must be refused: %v", err)
	}
	// An expectation with nothing pinned verifies nothing.
	if _, err := VerifyTrustPolicy(signed, TrustPolicyExpectation{PQPolicy: PQIdentityOptional}); err == nil {
		t.Fatal("an empty expectation must not verify a policy")
	}
	signed.Signature = "not base64!"
	if _, err := VerifyTrustPolicy(signed, testTrustExpectation(key)); !errors.Is(err, ErrTrustPolicySignature) {
		t.Fatalf("garbage signature: %v", err)
	}
}

func TestTrustPolicyEveryTamperedFieldIsRefused(t *testing.T) {
	key := testTrustKey(0x42)
	signed, err := SignTrustPolicy(testTrustPolicy(), key, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Each mutation leaves a well-formed policy that names the right device
	// and core where it can, so what refuses it is the signature.
	mutations := map[string]func(*SignedTrustPolicy){
		"generation": func(p *SignedTrustPolicy) { p.Generation++ },
		"state":      func(p *SignedTrustPolicy) { p.State = TrustTrusted },
		"mode":       func(p *SignedTrustPolicy) { p.Mode = TrustMonitor },
		"deny-less":  func(p *SignedTrustPolicy) { p.Deny = []TrustAction{TrustActionDial} },
		"deny-none":  func(p *SignedTrustPolicy) { p.Deny = []TrustAction{} },
		"deny-more": func(p *SignedTrustPolicy) {
			p.Deny = []TrustAction{TrustActionDial, TrustActionDTMF, TrustActionForwardOTP, TrustActionSendSMS}
		},
		"reason":     func(p *SignedTrustPolicy) { p.Reason = "something else" },
		"issued_at":  func(p *SignedTrustPolicy) { p.IssuedAt = "2026-10-05T08:00:01Z" },
		"expires_at": func(p *SignedTrustPolicy) { p.ExpiresAt = "2026-10-09T08:00:00Z" },
	}
	for name, mutate := range mutations {
		tampered := signed
		tampered.Deny = append([]TrustAction{}, signed.Deny...)
		mutate(&tampered)
		if _, err := VerifyTrustPolicy(tampered, testTrustExpectation(key)); !errors.Is(err, ErrTrustPolicySignature) {
			t.Errorf("%s: a tampered policy must fail its signature, got %v", name, err)
		}
	}
	// device_id and core_id are covered too: with the expectation moved along
	// with the tampered field, only the signature is left to refuse it.
	tampered := signed
	tampered.DeviceID = "NSH-410-TESTDEVICE02"
	expect := testTrustExpectation(key)
	expect.DeviceID = tampered.DeviceID
	if _, err := VerifyTrustPolicy(tampered, expect); !errors.Is(err, ErrTrustPolicySignature) {
		t.Errorf("device_id is not covered by the signature: %v", err)
	}
	tampered = signed
	tampered.CoreID = "core-test-0002"
	expect = testTrustExpectation(key)
	expect.CoreID = tampered.CoreID
	if _, err := VerifyTrustPolicy(tampered, expect); !errors.Is(err, ErrTrustPolicySignature) {
		t.Errorf("core_id is not covered by the signature: %v", err)
	}
	// version: only 1 exists, so a changed version is refused as malformed.
	tampered = signed
	tampered.Version = 2
	if _, err := VerifyTrustPolicy(tampered, testTrustExpectation(key)); !errors.Is(err, ErrTrustPolicyInvalid) {
		t.Errorf("version: %v", err)
	}
}

func TestTrustPolicyValidation(t *testing.T) {
	bad := map[string]func(*TrustPolicy){
		"version":            func(p *TrustPolicy) { p.Version = 0 },
		"no device":          func(p *TrustPolicy) { p.DeviceID = "" },
		"device newline":     func(p *TrustPolicy) { p.DeviceID = "a\nstate=TRUSTED" },
		"device space":       func(p *TrustPolicy) { p.DeviceID = "a b" },
		"no core":            func(p *TrustPolicy) { p.CoreID = "" },
		"generation zero":    func(p *TrustPolicy) { p.Generation = 0 },
		"state":              func(p *TrustPolicy) { p.State = "FINE" },
		"mode":               func(p *TrustPolicy) { p.Mode = "off" },
		"unknown action":     func(p *TrustPolicy) { p.Deny = []TrustAction{"answer"} },
		"unsorted deny":      func(p *TrustPolicy) { p.Deny = []TrustAction{TrustActionSendSMS, TrustActionDial} },
		"duplicate deny":     func(p *TrustPolicy) { p.Deny = []TrustAction{TrustActionDial, TrustActionDial} },
		"reason newline":     func(p *TrustPolicy) { p.Reason = "x\ndeny=" },
		"reason control":     func(p *TrustPolicy) { p.Reason = "x\x1fy" },
		"reason long":        func(p *TrustPolicy) { p.Reason = strings.Repeat("r", TrustPolicyReasonMaxBytes+1) },
		"reason not utf-8":   func(p *TrustPolicy) { p.Reason = "\xff" },
		"issued not utc":     func(p *TrustPolicy) { p.IssuedAt = "2026-10-05T16:00:00+08:00" },
		"issued fractional":  func(p *TrustPolicy) { p.IssuedAt = "2026-10-05T08:00:00.5Z" },
		"issued garbage":     func(p *TrustPolicy) { p.IssuedAt = "yesterday" },
		"expires not after":  func(p *TrustPolicy) { p.ExpiresAt = p.IssuedAt },
		"expires before":     func(p *TrustPolicy) { p.ExpiresAt = "2026-10-04T08:00:00Z" },
		"valid for too long": func(p *TrustPolicy) { p.ExpiresAt = "2026-10-12T08:00:01Z" },
	}
	for name, mutate := range bad {
		policy := testTrustPolicy()
		mutate(&policy)
		if err := policy.Validate(); !errors.Is(err, ErrTrustPolicyInvalid) {
			t.Errorf("%s: want a validation error, got %v", name, err)
		}
		if _, err := SignTrustPolicy(policy, testTrustKey(0x42), nil); err == nil {
			t.Errorf("%s: an invalid policy must not be signable", name)
		}
	}
	// Exactly seven days is the bound, not past it.
	policy := testTrustPolicy()
	policy.ExpiresAt = "2026-10-12T08:00:00Z"
	if err := policy.Validate(); err != nil {
		t.Fatalf("seven days must be accepted: %v", err)
	}
	if got := NormalizeTrustDeny([]TrustAction{TrustActionSendSMS, TrustActionDial, TrustActionSendSMS}); len(got) != 2 || got[0] != TrustActionDial || got[1] != TrustActionSendSMS {
		t.Fatalf("normalize: %v", got)
	}
	if got := FormatTrustTime(time.Date(2026, 10, 5, 16, 0, 0, 999, time.FixedZone("x", 8*3600))); got != "2026-10-05T08:00:00Z" {
		t.Fatalf("format: %s", got)
	}
}

func TestTrustPolicyEnvelopeIsStrict(t *testing.T) {
	signed, err := SignTrustPolicy(testTrustPolicy(), testTrustKey(0x42), nil)
	if err != nil {
		t.Fatal(err)
	}
	good, _ := json.Marshal(signed)
	if _, err := DecodeSignedTrustPolicy(good); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	_ = json.Unmarshal(good, &fields)
	with := func(change func(map[string]any)) []byte {
		copyOf := map[string]any{}
		for key, value := range fields {
			copyOf[key] = value
		}
		change(copyOf)
		encoded, _ := json.Marshal(copyOf)
		return encoded
	}
	cases := map[string][]byte{
		"unknown field":      with(func(m map[string]any) { m["allow"] = []string{"dial"} }),
		"unknown nested":     with(func(m map[string]any) { m["policy"] = map[string]any{"state": "TRUSTED"} }),
		"no signature":       with(func(m map[string]any) { delete(m, "signature") }),
		"no deny":            with(func(m map[string]any) { delete(m, "deny") }),
		"null deny":          with(func(m map[string]any) { m["deny"] = nil }),
		"pq without alg":     with(func(m map[string]any) { m["pq_signature"] = "AAAA" }),
		"alg without pq":     with(func(m map[string]any) { m["pq_algorithm"] = "ml-dsa-65" }),
		"negative gen":       with(func(m map[string]any) { m["generation"] = -1 }),
		"fractional gen":     with(func(m map[string]any) { m["generation"] = 1.5 }),
		"string gen":         with(func(m map[string]any) { m["generation"] = "7" }),
		"trailing value":     append(append([]byte{}, good...), []byte(` {"state":"TRUSTED"}`)...),
		"array":              []byte(`[]`),
		"empty":              []byte(``),
		"not json":           []byte(`nsh-domain=trust-policy-v1`),
		"extra field inline": []byte(strings.Replace(string(good), `"version":1`, `"version":1,"extra":1`, 1)),
	}
	for name, raw := range cases {
		if _, err := DecodeSignedTrustPolicy(raw); !errors.Is(err, ErrTrustPolicyInvalid) {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}
}

// A signature made for one purpose must never verify as another. The Core's
// identity key signs requests and policies; the same construction (Ed25519
// over canonical bytes) signs pairing transcripts and update manifests.
func TestTrustPolicyDomainSeparation(t *testing.T) {
	key := testTrustKey(0x42)
	public := key.Public().(ed25519.PublicKey)
	policy := testTrustPolicy()
	canonical, _ := policy.Canonical()
	if !bytes.HasPrefix(canonical, []byte(TrustPolicyDomain+"\n")) {
		t.Fatal("the signed bytes must begin with the domain line")
	}

	transcript := PairingTranscript{ProtocolMajor: ProtocolMajor, DeviceID: policy.DeviceID, DevicePublicKey: EncodeKey(public),
		CoreID: policy.CoreID, CorePublicKey: EncodeKey(public), Nonce: "bm9uY2Utbm9uY2Utbm9uY2U=", IssuedAt: 1}
	manifest, err := SignManifest(OTAManifest{}, "test", key)
	_ = err // an empty manifest may be refused; the request string below is the case that matters for the Core key
	others := map[string][]byte{
		"pairing transcript":               transcript.SigningBytes(),
		"request":                          SigningString("POST", TrustPolicyPath, "2026-10-05T08:00:00Z", "nonce", canonical),
		"request whose path is the domain": SigningString("nsh-domain=trust-policy-v1", "", "", "", nil),
		"update manifest":                  manifest.Manifest,
		"json envelope":                    mustJSON(t, policy),
	}
	for name, message := range others {
		if len(message) == 0 {
			continue
		}
		if bytes.HasPrefix(message, []byte(TrustPolicyDomain+"\n")) {
			t.Errorf("%s bytes can begin with the policy domain line", name)
		}
		// A genuine signature over the other kind of bytes, presented as the
		// policy's signature.
		forged := SignedTrustPolicy{TrustPolicy: policy, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, message))}
		if _, err := VerifyTrustPolicy(forged, testTrustExpectation(key)); !errors.Is(err, ErrTrustPolicySignature) {
			t.Errorf("a %s signature verified as a policy: %v", name, err)
		}
	}

	// And the reverse: a genuine policy signature is not a transcript
	// signature, nor a request signature.
	signed, err := SignTrustPolicy(policy, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPairingTranscript(transcript, DualSignature{Classical: signed.Signature}, public, PQIdentity{}, PQIdentityOptional); !errors.Is(err, ErrClassicalIdentityInvalid) {
		t.Fatalf("a policy signature verified as a pairing transcript: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(signed.Signature)
	if ed25519.Verify(public, SigningString("POST", TrustPolicyPath, policy.IssuedAt, "nonce", mustJSON(t, signed)), raw) {
		t.Fatal("a policy signature verified as a request signature")
	}
	// A transcript's first field is length-prefixed, so its first byte is a
	// length byte (zero for any realistic size) and never 'n'.
	if transcript.SigningBytes()[0] == TrustPolicyDomain[0] {
		t.Fatal("transcript bytes start like a policy")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestTrustPolicyPostQuantumMatrix(t *testing.T) {
	EnableMockPQIdentity()
	defer DisableMockPQIdentity()
	key := testTrustKey(0x42)
	pq, err := NewMockPQKeyPair(PQSigMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	otherPQ, _ := NewMockPQKeyPair(PQSigMLDSA65)
	strongPQ, _ := NewMockPQKeyPair(PQSigMLDSA87)

	classical, _ := SignTrustPolicy(testTrustPolicy(), key, nil)
	dual, err := SignTrustPolicy(testTrustPolicy(), key, pq)
	if err != nil || dual.PQSignature == "" || dual.PQAlgorithm != PQSigMLDSA65 {
		t.Fatalf("dual sign: %+v %v", dual, err)
	}
	wrongKey, _ := SignTrustPolicy(testTrustPolicy(), key, otherPQ)
	wrongAlgorithm, _ := SignTrustPolicy(testTrustPolicy(), key, strongPQ)
	garbage := dual
	garbage.PQSignature = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64))
	// The post-quantum half is right and the classical half is not.
	classicalBroken := dual
	classicalBroken.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(testTrustKey(0x43), []byte(goldenTrustCanonical)))

	type row struct {
		name    string
		signed  SignedTrustPolicy
		pinned  PQIdentity
		policy  PQIdentityPolicy
		outcome IdentityOutcome
		refuse  error
	}
	rows := []row{
		{"optional, nothing pinned, classical", classical, PQIdentity{}, PQIdentityOptional, IdentityClassicalOnly, nil},
		{"optional, pinned, classical is accepted", classical, pq.Identity(), PQIdentityOptional, IdentityClassicalOnly, nil},
		{"preferred, pinned, classical is accepted", classical, pq.Identity(), PQIdentityPreferred, IdentityClassicalOnly, nil},
		{"optional, pinned, dual", dual, pq.Identity(), PQIdentityOptional, IdentityDual, nil},
		{"preferred, pinned, dual", dual, pq.Identity(), PQIdentityPreferred, IdentityDual, nil},
		{"required, pinned, dual", dual, pq.Identity(), PQIdentityRequired, IdentityDual, nil},
		{"required, pinned, classical is refused", classical, pq.Identity(), PQIdentityRequired, "", ErrPQIdentityRequired},
		{"required, nothing pinned, classical is refused", classical, PQIdentity{}, PQIdentityRequired, "", ErrPQIdentityRequired},
		{"required, nothing pinned, dual is refused", dual, PQIdentity{}, PQIdentityRequired, "", ErrPQIdentityRequired},
		{"optional, nothing pinned, a signature establishes nothing", dual, PQIdentity{}, PQIdentityOptional, IdentityClassicalOnly, nil},
		{"optional, present but another key", wrongKey, pq.Identity(), PQIdentityOptional, "", ErrPQIdentityInvalid},
		{"preferred, present but garbage", garbage, pq.Identity(), PQIdentityPreferred, "", ErrPQIdentityInvalid},
		{"required, present but garbage", garbage, pq.Identity(), PQIdentityRequired, "", ErrPQIdentityInvalid},
		{"optional, present under another algorithm", wrongAlgorithm, pq.Identity(), PQIdentityOptional, "", ErrPQIdentityInvalid},
		{"required, valid post-quantum over a bad classical", classicalBroken, pq.Identity(), PQIdentityRequired, "", ErrTrustPolicySignature},
	}
	for _, r := range rows {
		expect := testTrustExpectation(key)
		expect.CorePQ, expect.PQPolicy = r.pinned, r.policy
		outcome, err := VerifyTrustPolicy(r.signed, expect)
		if r.refuse != nil {
			if !errors.Is(err, r.refuse) {
				t.Errorf("%s: want %v, got %s %v", r.name, r.refuse, outcome, err)
			}
			continue
		}
		if err != nil || outcome != r.outcome {
			t.Errorf("%s: want %s, got %s %v", r.name, r.outcome, outcome, err)
		}
	}

	// A build with no verifier cannot honour "present must verify".
	DisableMockPQIdentity()
	expect := testTrustExpectation(key)
	expect.CorePQ = pq.Identity()
	if _, err := VerifyTrustPolicy(dual, expect); !errors.Is(err, ErrPQIdentityRequired) {
		t.Errorf("a signature this build cannot check must not be waved through: %v", err)
	}
	if _, err := VerifyTrustPolicy(dual, TrustPolicyExpectation{DeviceID: expect.DeviceID, CoreID: expect.CoreID, CoreKey: expect.CoreKey, PQPolicy: "sometimes"}); err == nil {
		t.Error("an unknown identity policy must be refused")
	}
}
