package localadmin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Certificate uses a browser-compatible key independently of the Ed25519
// identity pinned by NAS. It never substitutes a key in the Node protocol.
func Certificate(dir, deviceID string, addresses []net.IP) (tls.Certificate, error) {
	keyPath := filepath.Join(dir, "admin-tls-key.pem")
	certPath := filepath.Join(dir, "admin-tls-cert.pem")
	var key *ecdsa.PrivateKey
	b, err := os.ReadFile(keyPath)
	if err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return tls.Certificate{}, errors.New("invalid admin TLS key")
		}
		parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return tls.Certificate{}, e
		}
		var ok bool
		key, ok = parsed.(*ecdsa.PrivateKey)
		if !ok || key.Curve != elliptic.P256() {
			return tls.Certificate{}, errors.New("invalid admin TLS key type")
		}
	}
	if os.IsNotExist(err) {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		if err = writePrivate(dir, "admin-tls-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
			return tls.Certificate{}, err
		}
	} else if err != nil {
		return tls.Certificate{}, err
	}
	// Keep the key across address changes and renewals. Never silently replace a
	// corrupt existing key, which would invalidate the owner's trust anchor.
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		leaf, e := x509.ParseCertificate(cert.Certificate[0])
		if e == nil && time.Now().Before(leaf.NotAfter.Add(-30*24*time.Hour)) {
			covers := true
			for _, ip := range addresses {
				if leaf.VerifyHostname(ip.String()) != nil {
					covers = false
				}
			}
			if covers {
				return cert, nil
			}
		}
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: deviceID + " Local Management"}, DNSNames: []string{deviceID + ".local", "localhost"}, IPAddresses: append([]net.IP{net.ParseIP("10.55.0.2"), net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, addresses...), NotBefore: now.Add(-24 * time.Hour), NotAfter: now.AddDate(3, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err = writePrivate(dir, "admin-tls-cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}
