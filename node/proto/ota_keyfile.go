package proto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// The release key file: the public keys a device, or a Core checking a release
// before it carries it, accepts update signatures from. One format, parsed in
// one place, so the publisher's tool, the device and the Core cannot disagree
// about what a key file says.

// OTAKeyFile is the on-disk form of the release keyring. It holds PUBLIC keys
// only; there is no field for anything else, and unknown fields are refused so
// a file that grew one would not load.
type OTAKeyFile struct {
	Version int `json:"version"`
	// Ed25519 maps key ids to base64 public keys.
	Ed25519 map[string]string `json:"ed25519"`
	// MLDSA maps key ids to post-quantum release identities. Optional: a
	// publisher that has not started dual-signing ships none.
	MLDSA map[string]PQIdentity `json:"ml_dsa,omitempty"`
}

var otaKeyID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// OTAMaxKeyFileBytes bounds the file. A handful of ML-DSA-87 keys is under 20 kB.
const OTAMaxKeyFileBytes = 256 << 10

// ParseOTAKeyFile decodes and validates a key file.
func ParseOTAKeyFile(raw []byte) (OTAKeyring, OTAPQKeyring, error) {
	var file OTAKeyFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, nil, fmt.Errorf("release key file is not valid: %w", err)
	}
	if decoder.More() {
		return nil, nil, errors.New("release key file has trailing content")
	}
	if file.Version != 1 {
		return nil, nil, fmt.Errorf("release key file version %d is not supported", file.Version)
	}
	classical := make(OTAKeyring, len(file.Ed25519))
	for id, encoded := range file.Ed25519 {
		if !otaKeyID.MatchString(id) {
			return nil, nil, fmt.Errorf("release key id %q is not usable", id)
		}
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("release key %q is not an ed25519 public key", id)
		}
		classical[id] = ed25519.PublicKey(key)
	}
	postQuantum := make(OTAPQKeyring, len(file.MLDSA))
	for id, identity := range file.MLDSA {
		if !otaKeyID.MatchString(id) {
			return nil, nil, fmt.Errorf("post-quantum release key id %q is not usable", id)
		}
		if err := identity.Validate(); err != nil {
			return nil, nil, fmt.Errorf("post-quantum release key %q: %w", id, err)
		}
		// On a build that has ML-DSA the size is checked too, so a truncated
		// key is reported at start-up rather than at the first update.
		if want := PQPublicKeySize(identity.Algorithm); want != 0 {
			key, _ := base64.StdEncoding.DecodeString(identity.PublicKey)
			if len(key) != want {
				return nil, nil, fmt.Errorf("post-quantum release key %q is %d bytes, %s keys are %d",
					id, len(key), identity.Algorithm, want)
			}
		}
		postQuantum[id] = identity
	}
	return classical, postQuantum, nil
}

// EncodeOTAKeyFile renders a key file. It is used by the release tooling; the
// device only ever reads one.
func EncodeOTAKeyFile(classical OTAKeyring, postQuantum OTAPQKeyring) ([]byte, error) {
	file := OTAKeyFile{Version: 1, Ed25519: map[string]string{}}
	for id, key := range classical {
		if !otaKeyID.MatchString(id) || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release key %q is not usable", id)
		}
		file.Ed25519[id] = base64.StdEncoding.EncodeToString(key)
	}
	if len(postQuantum) > 0 {
		file.MLDSA = map[string]PQIdentity{}
		for id, identity := range postQuantum {
			if !otaKeyID.MatchString(id) {
				return nil, fmt.Errorf("post-quantum release key id %q is not usable", id)
			}
			if err := identity.Validate(); err != nil {
				return nil, err
			}
			file.MLDSA[id] = identity
		}
	}
	return json.MarshalIndent(file, "", "  ")
}
