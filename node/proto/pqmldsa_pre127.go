//go:build !go1.27

package proto

import "fmt"

// A toolchain older than Go 1.27 has no crypto/mldsa. This build therefore
// carries no post-quantum signature provider: the capability is reported as
// unavailable and every REQUIRED policy refuses, which is the correct
// behaviour for it. See pqmldsa_go127.go for the real provider.

// StandardPQBackendName is the name the real provider reports. It is defined
// here too so callers can compare against it on any toolchain.
const StandardPQBackendName = "crypto/mldsa"

// MLDSASeedSize is the size of an ML-DSA private seed (FIPS 204).
const MLDSASeedSize = 32

// StandardPQSupported reports whether this build carries crypto/mldsa.
func StandardPQSupported() bool { return false }

// EnableStandardPQ does nothing in this build and reports false.
func EnableStandardPQ() bool { return false }

// PQPublicKeySize is zero: no algorithm is available.
func PQPublicKeySize(PQSignatureAlgorithm) int { return 0 }

// PQSignatureSize is zero: no algorithm is available.
func PQSignatureSize(PQSignatureAlgorithm) int { return 0 }

// MLDSASigner cannot be constructed in this build.
type MLDSASigner struct{}

// NewMLDSASeed is unavailable in this build.
func NewMLDSASeed() ([]byte, error) {
	return nil, fmt.Errorf("%w: build with %s or newer", ErrPQIdentityUnavailable, GoVersionForMLDSA)
}

// NewMLDSASigner is unavailable in this build.
func NewMLDSASigner(algorithm PQSignatureAlgorithm, _ []byte) (*MLDSASigner, error) {
	if err := ValidatePQSignatureAlgorithm(algorithm); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: build with %s or newer", ErrPQIdentityUnavailable, GoVersionForMLDSA)
}

// Algorithm implements PQSigner.
func (*MLDSASigner) Algorithm() PQSignatureAlgorithm { return "" }

// PublicKey implements PQSigner.
func (*MLDSASigner) PublicKey() []byte { return nil }

// Identity is empty in this build.
func (*MLDSASigner) Identity() PQIdentity { return PQIdentity{} }

// Sign implements PQSigner and always fails in this build.
func (*MLDSASigner) Sign([]byte) ([]byte, error) { return nil, ErrPQIdentityUnavailable }
