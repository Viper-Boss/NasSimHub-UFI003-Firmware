// Package nodetls issues and keeps the Node's TLS certificate.
//
// The certificate is signed with the device's own Ed25519 identity key, so it
// is not a second secret to protect: losing it costs a reissue, and it cannot
// be used to impersonate the device without the identity key that Core pins.
//
// Only the certificate is stored here. The private key stays where it already
// lives, in the identity package, and is passed in for signing.
package nodetls

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// FileName is the stored certificate inside the state directory.
const FileName = "device-cert.pem"

const filePerm fs.FileMode = 0o644

// renewBefore is how long before expiry a certificate is reissued.
const renewBefore = 30 * 24 * time.Hour

// Options configures certificate issuance.
type Options struct {
	// Dir is the state directory holding device-cert.pem.
	Dir string
	// DeviceID and Platform must match the identity the key belongs to.
	DeviceID string
	Platform proto.Platform
	// PrivateKey is the device's Ed25519 identity key.
	PrivateKey ed25519.PrivateKey
	// Addresses are optional IP SANs, for humans using curl.
	Addresses []net.IP
	// Now is injectable for tests.
	Now func() time.Time
}

// EnsureCertificate returns the Node's TLS certificate, issuing one if none
// exists and reissuing one that is expiring.
//
// Reissue keeps the same key on purpose. Core pins the key, so a renewed
// certificate continues to verify without any re-pairing; had the pin been on
// the certificate, every renewal would look exactly like an attack.
func EnsureCertificate(options Options) (tls.Certificate, error) {
	if len(options.PrivateKey) != ed25519.PrivateKeySize {
		return tls.Certificate{}, errors.New("node tls requires the device identity key")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	path := filepath.Join(options.Dir, FileName)

	if existing, err := load(path, options, now()); err == nil {
		return existing, nil
	} else if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errNeedsReissue) {
		return tls.Certificate{}, err
	}
	return issue(path, options, now())
}

var errNeedsReissue = errors.New("certificate needs reissue")

func load(path string, options Options, now time.Time) (tls.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return tls.Certificate{}, errNeedsReissue
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return tls.Certificate{}, errNeedsReissue
	}
	public := options.PrivateKey.Public().(ed25519.PublicKey)
	// A stored certificate that does not belong to the current key is not an
	// error to report, it is simply stale - reissue rather than refuse to boot.
	if err := proto.VerifyCertificateBinding(certificate, options.DeviceID, options.Platform, public); err != nil {
		return tls.Certificate{}, errNeedsReissue
	}
	if now.After(certificate.NotAfter.Add(-renewBefore)) {
		return tls.Certificate{}, errNeedsReissue
	}
	return tls.Certificate{
		Certificate: [][]byte{certificate.Raw},
		PrivateKey:  options.PrivateKey,
		Leaf:        certificate,
	}, nil
}

func issue(path string, options Options, now time.Time) (tls.Certificate, error) {
	template, err := proto.DeviceCertificateTemplate(options.DeviceID, options.Platform, options.Addresses, now)
	if err != nil {
		return tls.Certificate{}, err
	}
	public := options.PrivateKey.Public().(ed25519.PublicKey)
	der, err := x509.CreateCertificate(nil, template, template, public, options.PrivateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("issue device certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse issued certificate: %w", err)
	}
	if options.Dir != "" {
		encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if err := os.MkdirAll(options.Dir, 0o700); err != nil {
			return tls.Certificate{}, fmt.Errorf("create certificate directory: %w", err)
		}
		temporary := path + ".tmp"
		if err := os.WriteFile(temporary, encoded, filePerm); err != nil {
			return tls.Certificate{}, fmt.Errorf("write certificate: %w", err)
		}
		if err := os.Rename(temporary, path); err != nil {
			_ = os.Remove(temporary)
			return tls.Certificate{}, fmt.Errorf("install certificate: %w", err)
		}
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  options.PrivateKey,
		Leaf:        certificate,
	}, nil
}

// ServerConfig builds the Node's TLS server configuration.
//
// TLS 1.3 only: every peer is a NasSimHub Core built from this repository, so
// there is no legacy client to accommodate and nothing is gained by offering
// older versions.
func ServerConfig(certificate tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	}
}
