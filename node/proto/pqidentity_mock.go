package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// A model of post-quantum identity, for testing the PROTOCOL before the
// primitive exists.
//
// # What this is, exactly
//
// Ed25519 standing in for ML-DSA. Not an approximation of ML-DSA, not a
// simplified lattice scheme, not a "close enough" construction - a completely
// different, real, standard-library signature scheme wearing an ML-DSA label so
// that the dual-signature control flow can be exercised end to end.
//
// That choice is deliberate and the alternatives were worse:
//
//   - Writing a small ML-DSA would mean this project implementing a lattice
//     signature scheme. Never.
//   - A MAC-based stand-in would not be publicly verifiable, so the mock would
//     have a fundamentally different shape from the thing it models, and every
//     test written against it would be testing the wrong flow.
//   - A no-op that always verifies would make every downgrade test pass for the
//     wrong reason, which is the worst possible outcome for a test suite whose
//     entire job is proving that failures are refused.
//
// Ed25519 has none of those problems. It verifies from a public key, it fails
// on a bad signature, and nobody can mistake its 64 bytes for ML-DSA-65's 3309.
//
// # Why it cannot be switched on by accident
//
// Nothing registers it at init. A build must call EnableMockPQIdentity, which
// says what it is in its name, and the capability document then reports the
// backend as "mock-ed25519" everywhere it appears - the status page, the
// diagnostics bundle, the capability response. A device running the mock is
// therefore visibly running the mock.
//
// When crypto/tls and crypto/x509 carry ML-DSA in GoVersionForMLDSA, the real
// provider registers through the same RegisterPQProvider call and every
// enforcement path above it is unchanged. That is the point of doing this now:
// the rules get written and tested while there is nothing to rush.
//
// **Go 1.27 HOST VERIFICATION REQUIRED** - none of the sizes, timings or
// certificate interactions below predict the real thing.

// MockBackendName is what the capability document reports while the model is in
// use. It names the substitute rather than the thing being modelled, so a
// screenshot of a status page cannot be misread as a working ML-DSA device.
const MockBackendName = "mock-ed25519"

// ErrMockKeySize reports a key that is not the model's size.
var ErrMockKeySize = errors.New("mock post-quantum key is the wrong size")

// MockPQKeyPair is a modelled post-quantum identity.
type MockPQKeyPair struct {
	algorithm PQSignatureAlgorithm
	public    ed25519.PublicKey
	private   ed25519.PrivateKey
}

// NewMockPQKeyPair generates one.
func NewMockPQKeyPair(algorithm PQSignatureAlgorithm) (*MockPQKeyPair, error) {
	if err := ValidatePQSignatureAlgorithm(algorithm); err != nil {
		return nil, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &MockPQKeyPair{algorithm: algorithm, public: public, private: private}, nil
}

// Algorithm reports the algorithm being modelled.
func (m *MockPQKeyPair) Algorithm() PQSignatureAlgorithm { return m.algorithm }

// PublicKey is the raw public key.
func (m *MockPQKeyPair) PublicKey() []byte { return m.public }

// Identity is the public half in the form the protocol carries.
func (m *MockPQKeyPair) Identity() PQIdentity {
	return PQIdentity{
		Algorithm: m.algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(m.public),
	}
}

// Sign implements PQSigner.
func (m *MockPQKeyPair) Sign(message []byte) ([]byte, error) {
	if len(m.private) != ed25519.PrivateKeySize {
		return nil, ErrMockKeySize
	}
	return ed25519.Sign(m.private, message), nil
}

// mockVerifier implements PQVerifier for the model.
type mockVerifier struct{ algorithm PQSignatureAlgorithm }

func (v mockVerifier) Algorithm() PQSignatureAlgorithm { return v.algorithm }

func (v mockVerifier) Verify(publicKey, message, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: %d bytes", ErrMockKeySize, len(publicKey))
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return errors.New("mock post-quantum signature does not verify")
	}
	return nil
}

// EnableMockPQIdentity registers the model as the post-quantum provider.
//
// For tests and for a development build that wants to exercise the dual-identity
// path. It is never called by a shipping binary: the shipping binary registers
// nothing until a real provider exists, and reports the capability as
// unavailable, which is the honest answer.
func EnableMockPQIdentity() {
	RegisterPQProvider(func(algorithm PQSignatureAlgorithm) (PQVerifier, bool) {
		if err := ValidatePQSignatureAlgorithm(algorithm); err != nil {
			return nil, false
		}
		return mockVerifier{algorithm: algorithm}, true
	})
	SetPQBackendName(MockBackendName)
}

// DisableMockPQIdentity removes it again, so a test that needs the
// "no provider" behaviour can have it.
func DisableMockPQIdentity() {
	RegisterPQProvider(nil)
	SetPQBackendName("none")
}
