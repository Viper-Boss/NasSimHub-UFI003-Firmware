//go:build go1.27

package proto

import (
	"crypto/mldsa"
	"crypto/rand"
	"errors"
	"fmt"
)

// The real post-quantum signature provider: crypto/mldsa from the Go standard
// library (FIPS 204), available from Go 1.27.
//
// Nothing in this file implements a primitive. It adapts the standard library
// to the PQSigner / PQVerifier interfaces that pqidentity.go and ota_pq.go
// already enforce policy through, so every rule written against the mock now
// runs against ML-DSA with no change to the call sites.
//
// A build with an older toolchain compiles pqmldsa_pre127.go instead and keeps
// reporting the capability as unavailable, which stays the truth for it.

// StandardPQBackendName is what the capability document reports when the
// standard library provider is registered.
const StandardPQBackendName = "crypto/mldsa"

// MLDSASeedSize is the size of the private seed an ML-DSA key is stored as.
const MLDSASeedSize = mldsa.PrivateKeySize

// StandardPQSupported reports whether this build carries the standard library
// ML-DSA implementation. It says nothing about whether it has been enabled.
func StandardPQSupported() bool { return true }

// EnableStandardPQ registers crypto/mldsa as the post-quantum provider.
//
// Each binary calls it once at start-up. It is explicit rather than an init
// side effect so that "which provider is this process using" is answered by
// one line in main, and so a test that needs the no-provider behaviour still
// has it by default. Calling it again is harmless. Like RegisterPQProvider it
// belongs in start-up code, before any request is served.
//
// It reports whether the provider is now registered, which is always true in a
// build that has this file.
func EnableStandardPQ() bool {
	RegisterPQProvider(func(algorithm PQSignatureAlgorithm) (PQVerifier, bool) {
		if _, ok := mldsaParameters(algorithm); !ok {
			return nil, false
		}
		return mldsaVerifier{algorithm: algorithm}, true
	})
	SetPQBackendName(StandardPQBackendName)
	return true
}

func mldsaParameters(algorithm PQSignatureAlgorithm) (mldsa.Parameters, bool) {
	switch algorithm {
	case PQSigMLDSA65:
		return mldsa.MLDSA65(), true
	case PQSigMLDSA87:
		return mldsa.MLDSA87(), true
	default:
		return mldsa.Parameters{}, false
	}
}

// PQPublicKeySize is the encoded public key size for an algorithm, or zero for
// an algorithm this build does not carry.
func PQPublicKeySize(algorithm PQSignatureAlgorithm) int {
	parameters, ok := mldsaParameters(algorithm)
	if !ok {
		return 0
	}
	return parameters.PublicKeySize()
}

// PQSignatureSize is the signature size for an algorithm, or zero.
func PQSignatureSize(algorithm PQSignatureAlgorithm) int {
	parameters, ok := mldsaParameters(algorithm)
	if !ok {
		return 0
	}
	return parameters.SignatureSize()
}

type mldsaVerifier struct{ algorithm PQSignatureAlgorithm }

func (v mldsaVerifier) Algorithm() PQSignatureAlgorithm { return v.algorithm }

// Verify checks a pure ML-DSA signature with the empty context.
//
// Sizes are checked before the key is parsed so that a truncated or padded
// value is reported as what it is rather than as a generic parse failure, and
// so a key of one parameter set can never be accepted under the other's name.
func (v mldsaVerifier) Verify(publicKey, message, signature []byte) error {
	parameters, ok := mldsaParameters(v.algorithm)
	if !ok {
		return fmt.Errorf("%s is not available in this build", v.algorithm)
	}
	if len(publicKey) != parameters.PublicKeySize() {
		return fmt.Errorf("%s public key must be %d bytes, got %d",
			v.algorithm, parameters.PublicKeySize(), len(publicKey))
	}
	if len(signature) != parameters.SignatureSize() {
		return fmt.Errorf("%s signature must be %d bytes, got %d",
			v.algorithm, parameters.SignatureSize(), len(signature))
	}
	key, err := mldsa.NewPublicKey(parameters, publicKey)
	if err != nil {
		return fmt.Errorf("%s public key is not valid: %w", v.algorithm, err)
	}
	if err := mldsa.Verify(key, message, signature, nil); err != nil {
		return errors.New("signature does not verify")
	}
	return nil
}

// MLDSASigner is an ML-DSA private key behind the PQSigner interface.
type MLDSASigner struct {
	algorithm PQSignatureAlgorithm
	key       *mldsa.PrivateKey
}

// NewMLDSASeed returns a fresh private seed from the system random source.
func NewMLDSASeed() ([]byte, error) {
	seed := make([]byte, MLDSASeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate post-quantum key: %w", err)
	}
	return seed, nil
}

// NewMLDSASigner rebuilds a signer from its stored seed.
//
// The seed is the only private form this product stores. The expanded key is
// derived on load, so a truncated file cannot yield a usable but wrong key.
func NewMLDSASigner(algorithm PQSignatureAlgorithm, seed []byte) (*MLDSASigner, error) {
	if err := ValidatePQSignatureAlgorithm(algorithm); err != nil {
		return nil, err
	}
	parameters, ok := mldsaParameters(algorithm)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPQIdentityUnavailable, algorithm)
	}
	if len(seed) != MLDSASeedSize {
		return nil, fmt.Errorf("post-quantum seed must be %d bytes, got %d", MLDSASeedSize, len(seed))
	}
	key, err := mldsa.NewPrivateKey(parameters, seed)
	if err != nil {
		return nil, fmt.Errorf("load post-quantum key: %w", err)
	}
	return &MLDSASigner{algorithm: algorithm, key: key}, nil
}

// Algorithm implements PQSigner.
func (s *MLDSASigner) Algorithm() PQSignatureAlgorithm { return s.algorithm }

// PublicKey implements PQSigner.
func (s *MLDSASigner) PublicKey() []byte { return s.key.PublicKey().Bytes() }

// Identity is the public half in the form the protocol carries.
func (s *MLDSASigner) Identity() PQIdentity {
	return PQIdentity{Algorithm: s.algorithm, PublicKey: EncodeKey(s.PublicKey())}
}

// Sign implements PQSigner with the hedged (randomised) variant, which is the
// FIPS 204 default.
func (s *MLDSASigner) Sign(message []byte) ([]byte, error) {
	return s.key.Sign(nil, message, nil)
}

// signDeterministic exists for known-answer tests only.
func (s *MLDSASigner) signDeterministic(message []byte) ([]byte, error) {
	return s.key.SignDeterministic(message, nil)
}
