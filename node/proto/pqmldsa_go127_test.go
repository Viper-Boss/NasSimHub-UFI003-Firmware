//go:build go1.27

package proto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha3"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
)

// useStandardPQ registers the real provider for one test and removes it again,
// so the rest of the suite keeps the no-provider default it was written for.
func useStandardPQ(t *testing.T) {
	t.Helper()
	if !EnableStandardPQ() {
		t.Fatal("this build should carry crypto/mldsa")
	}
	t.Cleanup(func() {
		RegisterPQProvider(nil)
		SetPQBackendName("none")
	})
}

// The accumulated known-answer test, run THROUGH the adapter.
//
// The expected digests are the published accumulated vectors for FIPS 204
// (the same constants crypto/mldsa pins in its own tests, cross-checked there
// against other implementations): 100 keys from a SHAKE128 stream, the public
// key and the deterministic signature of the empty message absorbed into a
// second SHAKE128. If the adapter derived keys, encoded public keys or signed
// differently from the standard in any way, these would not match.
func TestMLDSAAccumulatedKnownAnswers(t *testing.T) {
	useStandardPQ(t)
	cases := []struct {
		algorithm PQSignatureAlgorithm
		expected  string
	}{
		{PQSigMLDSA65, "8358a1843220194417cadbc2651295cd8fc65125b5a5c1a239a16dc8b57ca199"},
		{PQSigMLDSA87, "8c3ad714777622b8f21ce31bb35f71394f23bc0fcf3c78ace5d608990f3b061b"},
	}
	for _, test := range cases {
		t.Run(string(test.algorithm), func(t *testing.T) {
			verifier, err := PQVerifierFor(test.algorithm)
			if err != nil {
				t.Fatal(err)
			}
			source := sha3.NewSHAKE128()
			output := sha3.NewSHAKE128()
			seed := make([]byte, MLDSASeedSize)
			message := []byte{}
			for i := 0; i < 100; i++ {
				_, _ = source.Read(seed)
				signer, err := NewMLDSASigner(test.algorithm, seed)
				if err != nil {
					t.Fatal(err)
				}
				public := signer.PublicKey()
				_, _ = output.Write(public)
				signature, err := signer.signDeterministic(message)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = output.Write(signature)
				if err := verifier.Verify(public, message, signature); err != nil {
					t.Fatalf("key %d: adapter refused a standard signature: %v", i, err)
				}
			}
			sum := make([]byte, 32)
			_, _ = output.Read(sum)
			if got := hex.EncodeToString(sum); got != test.expected {
				t.Fatalf("accumulated digest %s, want %s", got, test.expected)
			}
		})
	}
}

// Both directions against the standard library used directly, with no adapter
// on the other side.
func TestMLDSAInteroperatesWithStandardLibrary(t *testing.T) {
	useStandardPQ(t)
	for _, test := range []struct {
		algorithm  PQSignatureAlgorithm
		parameters mldsa.Parameters
	}{{PQSigMLDSA65, mldsa.MLDSA65()}, {PQSigMLDSA87, mldsa.MLDSA87()}} {
		t.Run(string(test.algorithm), func(t *testing.T) {
			message := []byte("nassimhub interop message")

			seed, err := NewMLDSASeed()
			if err != nil {
				t.Fatal(err)
			}
			signer, err := NewMLDSASigner(test.algorithm, seed)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := signer.Sign(message)
			if err != nil {
				t.Fatal(err)
			}
			if len(signature) != PQSignatureSize(test.algorithm) || len(signer.PublicKey()) != PQPublicKeySize(test.algorithm) {
				t.Fatalf("sizes: signature %d, key %d", len(signature), len(signer.PublicKey()))
			}
			public, err := mldsa.NewPublicKey(test.parameters, signer.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			if err := mldsa.Verify(public, message, signature, nil); err != nil {
				t.Fatalf("standard library refused the adapter's signature: %v", err)
			}

			direct, err := mldsa.GenerateKey(test.parameters)
			if err != nil {
				t.Fatal(err)
			}
			directSignature, err := direct.Sign(rand.Reader, message, nil)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := PQVerifierFor(test.algorithm)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifier.Verify(direct.PublicKey().Bytes(), message, directSignature); err != nil {
				t.Fatalf("adapter refused a standard library signature: %v", err)
			}

			// A signature made with a context string is a different signature.
			contextual, err := direct.Sign(rand.Reader, message, &mldsa.Options{Context: "other-purpose"})
			if err != nil {
				t.Fatal(err)
			}
			if verifier.Verify(direct.PublicKey().Bytes(), message, contextual) == nil {
				t.Fatal("a signature made under another context verified")
			}

			// The stored seed reproduces the same key.
			again, err := NewMLDSASigner(test.algorithm, seed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again.PublicKey(), signer.PublicKey()) {
				t.Fatal("the same seed produced a different public key")
			}
		})
	}
}

func TestMLDSARejectsBadKeysSignaturesAndAlgorithms(t *testing.T) {
	useStandardPQ(t)
	message := []byte("message")
	seed65, _ := NewMLDSASeed()
	seed87, _ := NewMLDSASeed()
	signer65, err := NewMLDSASigner(PQSigMLDSA65, seed65)
	if err != nil {
		t.Fatal(err)
	}
	signer87, err := NewMLDSASigner(PQSigMLDSA87, seed87)
	if err != nil {
		t.Fatal(err)
	}
	signature65, _ := signer65.Sign(message)
	signature87, _ := signer87.Sign(message)
	verifier65, _ := PQVerifierFor(PQSigMLDSA65)
	verifier87, _ := PQVerifierFor(PQSigMLDSA87)

	flipped := append([]byte{}, signature65...)
	flipped[len(flipped)/2] ^= 0x01
	otherSeed, _ := NewMLDSASeed()
	other, _ := NewMLDSASigner(PQSigMLDSA65, otherSeed)

	failures := map[string]error{
		"flipped bit":           verifier65.Verify(signer65.PublicKey(), message, flipped),
		"other message":         verifier65.Verify(signer65.PublicKey(), []byte("other"), signature65),
		"other key":             verifier65.Verify(other.PublicKey(), message, signature65),
		"truncated signature":   verifier65.Verify(signer65.PublicKey(), message, signature65[:len(signature65)-1]),
		"padded signature":      verifier65.Verify(signer65.PublicKey(), message, append(append([]byte{}, signature65...), 0)),
		"empty signature":       verifier65.Verify(signer65.PublicKey(), message, nil),
		"truncated key":         verifier65.Verify(signer65.PublicKey()[:100], message, signature65),
		"empty key":             verifier65.Verify(nil, message, signature65),
		"87 signature under 65": verifier65.Verify(signer65.PublicKey(), message, signature87),
		"65 signature under 87": verifier87.Verify(signer87.PublicKey(), message, signature65),
		"65 key under 87":       verifier87.Verify(signer65.PublicKey(), message, signature87),
		"ed25519 as ml-dsa":     verifier65.Verify(make([]byte, ed25519.PublicKeySize), message, make([]byte, ed25519.SignatureSize)),
	}
	for name, err := range failures {
		if err == nil {
			t.Errorf("%s: verified", name)
		}
	}

	if _, err := NewMLDSASigner("ml-dsa-44", seed65); err == nil {
		t.Error("ml-dsa-44 is not a parameter set this product uses")
	}
	if _, err := NewMLDSASigner(PQSigMLDSA65, seed65[:31]); err == nil {
		t.Error("a 31-byte seed loaded")
	}
	if _, err := PQVerifierFor("ml-dsa-44"); err == nil {
		t.Error("a verifier was returned for ml-dsa-44")
	}
}

func TestStandardProviderIsNamedAndReported(t *testing.T) {
	if PQIdentityAvailable() {
		t.Fatal("a provider is registered before any test enabled one")
	}
	useStandardPQ(t)
	if PQBackendName() != StandardPQBackendName {
		t.Fatalf("backend is %q", PQBackendName())
	}
	capability := DescribeIdentity(PQIdentity{}, PQIdentityPreferred)
	if !capability.PQAvailable || capability.RequiresToolchain != "" || capability.Backend != "crypto/mldsa" {
		t.Fatalf("capability: %+v", capability)
	}
	if !StandardPQSupported() {
		t.Fatal("this build reports no standard support")
	}
}

// The full dual-signature rule set, on the real algorithm.
func TestPairingTranscriptWithRealMLDSA(t *testing.T) {
	useStandardPQ(t)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	for _, algorithm := range []PQSignatureAlgorithm{PQSigMLDSA65, PQSigMLDSA87} {
		seed, _ := NewMLDSASeed()
		signer, err := NewMLDSASigner(algorithm, seed)
		if err != nil {
			t.Fatal(err)
		}
		transcript := PairingTranscript{
			ProtocolMajor:   ProtocolMajor,
			DeviceID:        DeviceID(PlatformMSM8916, public),
			DevicePublicKey: EncodeKey(public),
			DevicePQ:        signer.Identity(),
			CoreID:          "core-1",
			CorePublicKey:   EncodeKey(public),
			Nonce:           "bm9uY2Utbm9uY2Utbm9uY2U=",
			IssuedAt:        1,
		}
		signature, err := SignPairingTranscript(transcript, private, signer)
		if err != nil {
			t.Fatal(err)
		}
		outcome, err := VerifyPairingTranscript(transcript, signature, public, signer.Identity(), PQIdentityRequired)
		if err != nil || outcome != IdentityDual {
			t.Fatalf("%s: outcome %q, err %v", algorithm, outcome, err)
		}

		// A changed transcript fails the post-quantum half even when the
		// classical half is re-signed correctly: the two cover the same bytes.
		altered := transcript
		altered.CoreID = "core-2"
		resigned, _ := SignPairingTranscript(altered, private, nil)
		resigned.PQ, resigned.PQAlgorithm = signature.PQ, signature.PQAlgorithm
		if _, err := VerifyPairingTranscript(altered, resigned, public, signer.Identity(), PQIdentityOptional); !errors.Is(err, ErrPQIdentityInvalid) {
			t.Fatalf("%s: a stale post-quantum signature was accepted: %v", algorithm, err)
		}

		// Missing under required is refused; missing under preferred is
		// classical-only, visibly.
		classical, _ := SignPairingTranscript(transcript, private, nil)
		if _, err := VerifyPairingTranscript(transcript, classical, public, signer.Identity(), PQIdentityRequired); !errors.Is(err, ErrPQIdentityRequired) {
			t.Fatalf("%s: required accepted a classical-only signature: %v", algorithm, err)
		}
		if outcome, err := VerifyPairingTranscript(transcript, classical, public, PQIdentity{}, PQIdentityPreferred); err != nil || outcome != IdentityClassicalOnly {
			t.Fatalf("%s: preferred: %q %v", algorithm, outcome, err)
		}

		// The signer names the algorithm; a mismatch with the identity is a
		// failure, not a hint.
		wrong := signature
		if algorithm == PQSigMLDSA65 {
			wrong.PQAlgorithm = PQSigMLDSA87
		} else {
			wrong.PQAlgorithm = PQSigMLDSA65
		}
		if _, err := VerifyPairingTranscript(transcript, wrong, public, signer.Identity(), PQIdentityPreferred); !errors.Is(err, ErrPQIdentityInvalid) {
			t.Fatalf("%s: algorithm confusion was accepted: %v", algorithm, err)
		}
	}
}

func TestHybridManifestWithRealMLDSA(t *testing.T) {
	useStandardPQ(t)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	seed, _ := NewMLDSASeed()
	signer, err := NewMLDSASigner(PQSigMLDSA87, seed)
	if err != nil {
		t.Fatal(err)
	}
	manifest := simpleManifest()
	keyring := OTAKeyring{"release-1": public}
	pqKeyring := OTAPQKeyring{"release-pq-1": signer.Identity()}

	signed, err := SignManifestHybrid(manifest, "release-1", private, "release-pq-1", signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, outcome, err := VerifyManifestHybrid(signed, keyring, pqKeyring, OTASignatureRequired); err != nil || outcome != OTADualSigned {
		t.Fatalf("dual manifest: %q %v", outcome, err)
	}

	// Signature covers the exact bytes: re-encoding the same manifest with
	// different whitespace is a different message.
	reencoded := signed
	reencoded.Manifest = append(append([]byte{}, signed.Manifest...), ' ')
	if _, _, err := VerifyManifestHybrid(reencoded, keyring, pqKeyring, OTASignaturePreferred); err == nil {
		t.Fatal("a re-encoded manifest verified")
	}

	classical, _ := SignManifestHybrid(manifest, "release-1", private, "", nil)
	if _, _, err := VerifyManifestHybrid(classical, keyring, pqKeyring, OTASignatureRequired); !errors.Is(err, ErrOTAPQUnsigned) {
		t.Fatalf("required accepted a classical-only manifest: %v", err)
	}

	bad := signed
	raw, _ := base64.StdEncoding.DecodeString(bad.PQSignature)
	raw[10] ^= 0xff
	bad.PQSignature = base64.StdEncoding.EncodeToString(raw)
	if _, _, err := VerifyManifestHybrid(bad, keyring, pqKeyring, OTASignaturePreferred); !errors.Is(err, ErrOTAPQUnsigned) {
		t.Fatalf("a corrupted post-quantum signature was accepted under preferred: %v", err)
	}

	unknown := signed
	unknown.PQKeyID = "release-pq-2"
	if _, _, err := VerifyManifestHybrid(unknown, keyring, pqKeyring, OTASignaturePreferred); !errors.Is(err, ErrOTAPQUnsigned) {
		t.Fatalf("an unknown post-quantum key id was accepted: %v", err)
	}

	confused := signed
	confused.PQAlgorithm = PQSigMLDSA65
	if _, _, err := VerifyManifestHybrid(confused, keyring, pqKeyring, OTASignaturePreferred); !errors.Is(err, ErrOTAPQUnsigned) {
		t.Fatalf("an algorithm mismatch was accepted: %v", err)
	}
}

// Verification is safe from many goroutines at once: the provider is read-only
// after start-up and keys are immutable.
func TestMLDSAConcurrentSignAndVerify(t *testing.T) {
	useStandardPQ(t)
	seed, _ := NewMLDSASeed()
	signer, err := NewMLDSASigner(PQSigMLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := PQVerifierFor(PQSigMLDSA65)
	var group sync.WaitGroup
	failures := make(chan error, 64)
	for worker := 0; worker < 16; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for i := 0; i < 20; i++ {
				message := []byte{byte(worker), byte(i)}
				signature, err := signer.Sign(message)
				if err != nil {
					failures <- err
					return
				}
				if err := verifier.Verify(signer.PublicKey(), message, signature); err != nil {
					failures <- err
					return
				}
			}
		}(worker)
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
}

func BenchmarkMLDSA65Sign(b *testing.B)   { benchmarkSign(b, PQSigMLDSA65) }
func BenchmarkMLDSA87Sign(b *testing.B)   { benchmarkSign(b, PQSigMLDSA87) }
func BenchmarkMLDSA65Verify(b *testing.B) { benchmarkVerify(b, PQSigMLDSA65) }
func BenchmarkMLDSA87Verify(b *testing.B) { benchmarkVerify(b, PQSigMLDSA87) }

func benchmarkSign(b *testing.B, algorithm PQSignatureAlgorithm) {
	seed, _ := NewMLDSASeed()
	signer, err := NewMLDSASigner(algorithm, seed)
	if err != nil {
		b.Fatal(err)
	}
	message := make([]byte, 256)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := signer.Sign(message); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkVerify(b *testing.B, algorithm PQSignatureAlgorithm) {
	EnableStandardPQ()
	defer func() { RegisterPQProvider(nil); SetPQBackendName("none") }()
	seed, _ := NewMLDSASeed()
	signer, err := NewMLDSASigner(algorithm, seed)
	if err != nil {
		b.Fatal(err)
	}
	message := make([]byte, 256)
	signature, _ := signer.Sign(message)
	verifier, _ := PQVerifierFor(algorithm)
	public := signer.PublicKey()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(public, message, signature); err != nil {
			b.Fatal(err)
		}
	}
}

// EnableStandardPQ is called by more than one layer at start-up (each main,
// ota.Launch, nodeserver.New) so that none of them can come too late. That is
// only sound if calling it again changes nothing and if it goes through the
// registry's lock while verification is already running. Run with -race.
func TestEnableStandardPQIsIdempotentAndSafeWhileVerifying(t *testing.T) {
	if !EnableStandardPQ() {
		t.Skip("this toolchain has no crypto/mldsa")
	}
	t.Cleanup(func() { RegisterPQProvider(nil); SetPQBackendName("none") })
	seed, _ := NewMLDSASeed()
	signer, err := NewMLDSASigner(PQSigMLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("nsh-test: idempotent provider registration")
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func(enable bool) {
			defer group.Done()
			for round := 0; round < 25; round++ {
				if enable {
					if !EnableStandardPQ() {
						t.Error("EnableStandardPQ reported no provider")
					}
					continue
				}
				verifier, err := PQVerifierFor(PQSigMLDSA65)
				if err != nil {
					t.Errorf("no verifier while the provider is being registered again: %v", err)
					return
				}
				if err := verifier.Verify(signer.PublicKey(), message, signature); err != nil {
					t.Errorf("verify: %v", err)
				}
				if !PQIdentityAvailable() || PQBackendName() != StandardPQBackendName {
					t.Errorf("registry state: available=%v backend=%q", PQIdentityAvailable(), PQBackendName())
				}
			}
		}(worker%2 == 0)
	}
	group.Wait()
}
