package proto

import (
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// TLS trust model.
//
// The binding between the TLS identity and the device identity is not a claim
// that has to be checked - they are the same key. A Node's X.509 certificate is
// self-signed with the very Ed25519 key that device_id is derived from, so:
//
//	certificate public key  ==  device public key  ==  the key device_id hashes
//
// Three consequences follow, and they are what make the rest of the design work:
//
//   - There is no certificate authority to run, distribute or protect. A Node
//     that can prove possession of its identity key can prove possession of its
//     TLS identity, and nothing else can.
//   - Core pins the PUBLIC KEY, never the certificate bytes. A certificate that
//     expires is reissued from the same key and the pin still matches, so
//     routine renewal never looks like an attack - while substituting the key
//     always does.
//   - An attacker who relays the discovery document cannot complete the
//     handshake, because completing it requires the private half. Trust on
//     first use is therefore reduced to "is this the device the user meant",
//     which the user answers by reading device_id, rather than "is this a
//     device at all".
//
// In the steady state Core sets no InsecureSkipVerify at all: it builds a
// one-certificate root pool from the certificate it has already pinned and runs
// ordinary chain verification, then re-checks the leaf key against the pin.
//
// Renewal cannot be handled that way, and the reason is worth recording because
// it is not obvious. Go's chain builder treats a candidate parent that shares
// the leaf's subject AND public key as a loop (crypto/x509 alreadyInChain) and
// discards it. A renewed self-signed certificate has exactly that relationship
// to the one it replaces, so although its signature verifies against the old
// certificate's key, no chain can be built and verification fails with
// "certificate signed by unknown authority". This was confirmed empirically
// against Go 1.24 rather than assumed.
//
// So renewal takes a second, explicit path: Core notices the strict handshake
// failing, reconnects with PKI verification replaced by a mandatory key-pin
// callback, and accepts the new certificate only when it carries the same
// device key. That keeps the key as the thing being trusted, keeps the ordinary
// path on standard verification, and makes "the device changed its key" - the
// case that must fail - impossible to confuse with "the device renewed".

// DeviceCertificateLifetime is how long an issued Node certificate is valid.
//
// Long enough that a device offline for months still works, short enough that a
// certificate is not a permanent artifact. Expiry is not a security boundary
// here - the key is - so this is about hygiene rather than containment.
const DeviceCertificateLifetime = 825 * 24 * time.Hour

// DeviceHostnameSuffix is appended to a device_id to form the TLS server name.
const DeviceHostnameSuffix = ".node.nassimhub.local"

// ErrCertificateBinding reports that a certificate does not belong to the
// device it claims.
var ErrCertificateBinding = errors.New("certificate is not bound to this device identity")

// DeviceHostname is the TLS server name for a device.
//
// It is derived from device_id rather than from an address, for the same reason
// device_id is: a Node that moves from USB to Wi-Fi must keep one identity, and
// a certificate tied to an IP would have to be reissued on every DHCP lease.
func DeviceHostname(deviceID string) string {
	return strings.ToLower(deviceID) + DeviceHostnameSuffix
}

// DeviceCertificateTemplate builds the X.509 template for a Node.
//
// addresses are added as IP SANs purely so that a human using curl against a
// bare address gets a sensible result; Core always connects by the derived
// hostname and never relies on them.
func DeviceCertificateTemplate(deviceID string, platform Platform, addresses []net.IP, notBefore time.Time) (*x509.Certificate, error) {
	if deviceID == "" {
		return nil, errors.New("certificate template requires a device id")
	}
	serial, err := certificateSerial(deviceID)
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         deviceID,
			Organization:       []string{"NasSimHub Node"},
			OrganizationalUnit: []string{string(platform)},
		},
		NotBefore: notBefore.Add(-time.Hour),
		NotAfter:  notBefore.Add(DeviceCertificateLifetime),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		// The certificate is its own root, so Core can put it in a pool and run
		// ordinary chain verification instead of disabling verification.
		//
		// No path-length constraint is set. A renewed certificate is also
		// self-signed and therefore also a CA, and a pathlen:0 root would
		// refuse to be the parent of one - which would make routine renewal
		// indistinguishable from an attack, the exact failure this whole design
		// exists to avoid. Nothing is lost by omitting it: the pool Core builds
		// contains this one certificate and is used for this one device, so
		// there is no wider population of certificates it could vouch for.
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{DeviceHostname(deviceID)},
		IPAddresses:           addresses,
	}, nil
}

// certificateSerial derives a stable, non-zero serial from the device id.
func certificateSerial(deviceID string) (*big.Int, error) {
	serial := new(big.Int).SetBytes([]byte(deviceID))
	if serial.Sign() == 0 {
		return nil, errors.New("device id produced a zero certificate serial")
	}
	// Keep it inside the 20-octet limit RFC 5280 puts on serial numbers.
	limit := new(big.Int).Lsh(big.NewInt(1), 158)
	return serial.Mod(serial, limit).Add(serial, big.NewInt(1)), nil
}

// CertificatePublicKey extracts the Ed25519 key a certificate carries.
func CertificatePublicKey(certificate *x509.Certificate) (ed25519.PublicKey, error) {
	if certificate == nil {
		return nil, errors.New("certificate is nil")
	}
	key, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: certificate key is %T, want ed25519", ErrCertificateBinding, certificate.PublicKey)
	}
	return key, nil
}

// VerifyCertificateBinding checks that a certificate belongs to the device it
// names, and - when a pin is supplied - that it is the device Core already
// trusts.
//
// With no pin this answers "this certificate is internally consistent: its key
// derives the device_id it claims". That is what makes first contact safe to
// show to a user. With a pin it additionally answers "and it is the same key we
// adopted", which is what makes every later connection safe without one.
func VerifyCertificateBinding(certificate *x509.Certificate, deviceID string, platform Platform, pinned ed25519.PublicKey) error {
	key, err := CertificatePublicKey(certificate)
	if err != nil {
		return err
	}
	if !ValidateDeviceID(deviceID, platform, key) {
		return fmt.Errorf("%w: certificate key derives %q, not %q",
			ErrCertificateBinding, DeviceID(platform, key), deviceID)
	}
	if certificate.Subject.CommonName != deviceID {
		return fmt.Errorf("%w: certificate names %q, expected %q",
			ErrCertificateBinding, certificate.Subject.CommonName, deviceID)
	}
	// The certificate must be self-signed by the same key: anything else would
	// mean the key in the certificate is not the key that authorised it.
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return fmt.Errorf("%w: certificate is not self-signed by its own key: %v", ErrCertificateBinding, err)
	}
	if len(pinned) > 0 && !pinned.Equal(key) {
		return fmt.Errorf("%w: certificate key does not match the pinned device key", ErrCertificateBinding)
	}
	return nil
}
