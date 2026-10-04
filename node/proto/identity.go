package proto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// DeviceIDPrefix is the fixed leading segment of every Node identifier.
const DeviceIDPrefix = "NSH"

// DeviceID derives the stable device identifier from the Node's public key.
//
// Deriving rather than randomising has one decisive property: the identifier is
// verifiable. When Core sees NSH-410-A83F29 it can recompute it from the public
// key the Node presented and know the Node did not simply claim someone else's
// name. It also makes the identifier survive everything that is not a key
// rotation - reboots, moving from USB to Wi-Fi, a new DHCP lease, a different
// NAS - because none of those touch the key.
//
// The identifier deliberately contains no network address. Core must never
// infer identity from an IP, or a Node that changes link would appear twice.
func DeviceID(platform Platform, publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return fmt.Sprintf("%s-%s-%s", DeviceIDPrefix, platform.ShortCode(), strings.ToUpper(fmt.Sprintf("%X", digest[:3])))
}

// ValidateDeviceID reports whether id is the identifier that platform and
// publicKey produce. Core calls this before trusting a discovery document.
func ValidateDeviceID(id string, platform Platform, publicKey ed25519.PublicKey) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return id == DeviceID(platform, publicKey)
}

// EncodeKey renders a key for JSON transport.
func EncodeKey(key []byte) string { return base64.StdEncoding.EncodeToString(key) }

// DecodePublicKey parses a transported Ed25519 public key.
func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("public key is not valid base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// CoreFingerprint is the short, human-comparable form of a Core's public key.
// It is what the Node stores and what the UI shows when a second Core is
// refused, so the user can tell which NAS already owns the device.
func CoreFingerprint(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return strings.ToUpper(fmt.Sprintf("%X", digest[:4]))
}
