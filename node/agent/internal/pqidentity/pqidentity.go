// Package pqidentity owns the Node's ADDITIONAL post-quantum identity key.
//
// It is deliberately a separate file from device.json and a separate package
// from identity:
//
//   - device_id derives from the Ed25519 key alone and must never change.
//     Keeping the ML-DSA key out of device.json means no code path that touches
//     the new key can rewrite, reorder or regenerate the old one.
//   - A device that predates this package has a device.json and nothing else.
//     Starting a newer agent on it adds pq-identity.json beside it and leaves
//     everything that was there byte for byte the same - that is the whole
//     migration.
//
// # Lifecycle, including the failures
//
//	first start on a build with ML-DSA   the key is generated once and stored.
//	every later start                    the stored seed is loaded; the public
//	                                     key is recomputed and compared with
//	                                     the stored one.
//	build without ML-DSA                 nothing is generated or read; the
//	                                     device reports no post-quantum
//	                                     identity and stays classical.
//	file unreadable or inconsistent      the device does NOT generate a
//	                                     replacement. It reports no
//	                                     post-quantum identity and logs why.
//	                                     A Core that pinned the old key then
//	                                     refuses the device until the owner
//	                                     resets the pin - which is the correct
//	                                     outcome for "the key changed and
//	                                     nobody decided it should".
//	deliberate rotation                  the owner removes pq-identity.json (or
//	                                     changes the algorithm); the next start
//	                                     generates a new key, and the Core
//	                                     reports the change until the owner
//	                                     accepts it there.
//
// Silent regeneration is the one thing this package never does: a key that can
// replace itself is a key an attacker can replace.
package pqidentity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// FileName is the key document inside the state directory.
const FileName = "pq-identity.json"

const (
	filePerm fs.FileMode = 0o600
	dirPerm  fs.FileMode = 0o700
)

// Status says why the device does or does not hold a post-quantum identity.
type Status string

const (
	// StatusActive means a key is loaded and usable.
	StatusActive Status = "active"
	// StatusUnavailable means this build has no ML-DSA implementation.
	StatusUnavailable Status = "unavailable"
	// StatusDisabled means the operator turned it off in configuration.
	StatusDisabled Status = "disabled"
	// StatusDamaged means a key file exists and could not be used.
	StatusDamaged Status = "damaged"
)

// document is the on-disk form. Like device.json it stores the seed, not the
// expanded key.
type document struct {
	Version     int                        `json:"version"`
	DeviceID    string                     `json:"device_id"`
	Algorithm   proto.PQSignatureAlgorithm `json:"algorithm"`
	PrivateSeed string                     `json:"private_seed"`
	PublicKey   string                     `json:"public_key"`
	CreatedAt   time.Time                  `json:"created_at"`
	// Binding is the Ed25519 signature, by the device identity key, over the
	// device id, the algorithm and the post-quantum public key. It is checked
	// on load so a key file copied from another device is refused.
	Binding string `json:"binding"`
}

// Store is the loaded post-quantum identity, or the reason there is none.
type Store struct {
	status    Status
	detail    string
	signer    *proto.MLDSASigner
	identity  proto.PQIdentity
	createdAt time.Time
}

// Options configures loading.
type Options struct {
	// Dir is the state directory holding device.json.
	Dir string
	// DeviceID and DeviceKey are the device's classical identity.
	DeviceID  string
	DeviceKey ed25519.PrivateKey
	// Algorithm is the parameter set to generate when no key exists. A stored
	// key of another parameter set is kept: changing the level is not a reason
	// to change the key behind the owner's back.
	Algorithm proto.PQSignatureAlgorithm
	// Disabled turns the post-quantum identity off without deleting a key.
	Disabled bool
	// Now is injectable for tests.
	Now func() time.Time
}

const bindingDomain = "nassimhub-node/pq-identity-binding/v1"

// bindingBytes is what the device key signs to claim a post-quantum key.
func bindingBytes(deviceID string, identity proto.PQIdentity) []byte {
	transcript := proto.PairingTranscript{
		ProtocolMajor: proto.ProtocolMajor,
		DeviceID:      deviceID,
		DevicePQ:      identity,
		Nonce:         bindingDomain,
	}
	return transcript.SigningBytes()
}

// LoadOrCreate returns the device's post-quantum identity.
//
// It never returns an error for a missing capability or a damaged file: those
// are states the device runs in, reported through Status. It returns an error
// only when it cannot write a key it has just generated, because a key that
// exists in memory and not on disk would be a different key after a restart.
func LoadOrCreate(options Options) (*Store, error) {
	if options.Disabled {
		return &Store{status: StatusDisabled, detail: "post-quantum identity is disabled in configuration"}, nil
	}
	if !proto.StandardPQSupported() {
		return &Store{
			status: StatusUnavailable,
			detail: "this build has no ML-DSA; it needs " + proto.GoVersionForMLDSA + " or newer",
		}, nil
	}
	if options.DeviceID == "" || len(options.DeviceKey) != ed25519.PrivateKeySize {
		return nil, errors.New("post-quantum identity requires the device identity")
	}
	algorithm := options.Algorithm
	if algorithm == "" {
		algorithm = proto.PQSigMLDSA65
	}
	if err := proto.ValidatePQSignatureAlgorithm(algorithm); err != nil {
		return nil, err
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	path := filepath.Join(options.Dir, FileName)

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		store, loadErr := load(raw, options)
		if loadErr != nil {
			return &Store{status: StatusDamaged, detail: loadErr.Error()}, nil
		}
		return store, nil
	case errors.Is(err, fs.ErrNotExist):
		return create(path, options, algorithm, now().UTC())
	default:
		return &Store{status: StatusDamaged, detail: "key file could not be read"}, nil
	}
}

func load(raw []byte, options Options) (*Store, error) {
	var stored document
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, errors.New("key file is not valid JSON")
	}
	if stored.DeviceID != options.DeviceID {
		return nil, errors.New("key file belongs to another device")
	}
	if err := proto.ValidatePQSignatureAlgorithm(stored.Algorithm); err != nil {
		return nil, errors.New("key file names an unknown algorithm")
	}
	seed, err := base64.StdEncoding.DecodeString(stored.PrivateSeed)
	if err != nil {
		return nil, errors.New("key file has an unreadable seed")
	}
	signer, err := proto.NewMLDSASigner(stored.Algorithm, seed)
	if err != nil {
		return nil, errors.New("key file has an unusable seed")
	}
	identity := signer.Identity()
	// The stored public key is not trusted; it is recomputed and compared, the
	// same way device.json recomputes device_id.
	if stored.PublicKey != identity.PublicKey {
		return nil, errors.New("key file's public key does not match its seed")
	}
	binding, err := base64.StdEncoding.DecodeString(stored.Binding)
	if err != nil || !ed25519.Verify(options.DeviceKey.Public().(ed25519.PublicKey), bindingBytes(options.DeviceID, identity), binding) {
		return nil, errors.New("key file is not bound to this device identity")
	}
	return &Store{status: StatusActive, signer: signer, identity: identity, createdAt: stored.CreatedAt}, nil
}

func create(path string, options Options, algorithm proto.PQSignatureAlgorithm, created time.Time) (*Store, error) {
	seed, err := proto.NewMLDSASeed()
	if err != nil {
		return nil, err
	}
	signer, err := proto.NewMLDSASigner(algorithm, seed)
	if err != nil {
		return nil, err
	}
	identity := signer.Identity()
	stored := document{
		Version:     1,
		DeviceID:    options.DeviceID,
		Algorithm:   algorithm,
		PrivateSeed: base64.StdEncoding.EncodeToString(seed),
		PublicKey:   identity.PublicKey,
		CreatedAt:   created,
		Binding:     base64.StdEncoding.EncodeToString(ed25519.Sign(options.DeviceKey, bindingBytes(options.DeviceID, identity))),
	}
	encoded, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode post-quantum identity: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, fmt.Errorf("create identity directory: %w", err)
	}
	// A uniquely named temporary file and a no-replace link, so two agents
	// racing through first boot cannot each believe they own the key: exactly
	// one link succeeds, and the loser adopts the winner's key.
	file, err := os.CreateTemp(filepath.Dir(path), FileName+".*.tmp")
	if err != nil {
		return nil, fmt.Errorf("write post-quantum identity: %w", err)
	}
	temporary := file.Name()
	chmodErr := file.Chmod(filePerm)
	_, writeErr := file.Write(encoded)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(chmodErr, writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(temporary)
		return nil, fmt.Errorf("write post-quantum identity: %w", err)
	}
	if err := os.Link(temporary, path); err != nil {
		_ = os.Remove(temporary)
		if errors.Is(err, fs.ErrExist) {
			// Another start created it first. Use theirs.
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return &Store{status: StatusDamaged, detail: "key file could not be read"}, nil
			}
			store, loadErr := load(raw, options)
			if loadErr != nil {
				return &Store{status: StatusDamaged, detail: loadErr.Error()}, nil
			}
			return store, nil
		}
		return nil, fmt.Errorf("install post-quantum identity: %w", err)
	}
	_ = os.Remove(temporary)
	return &Store{status: StatusActive, signer: signer, identity: identity, createdAt: created}, nil
}

// Status reports whether a key is usable and, if not, which kind of not.
func (s *Store) Status() Status {
	if s == nil {
		return StatusUnavailable
	}
	return s.status
}

// Detail is a human-readable reason for a non-active status. It never contains
// key material or a path.
func (s *Store) Detail() string {
	if s == nil {
		return ""
	}
	return s.detail
}

// Identity is the public half, or an empty identity.
func (s *Store) Identity() proto.PQIdentity {
	if s == nil || s.status != StatusActive {
		return proto.PQIdentity{}
	}
	return s.identity
}

// Signer returns the signer, or nil when the device holds no usable key. The
// nil is a true interface nil so callers can pass it straight to
// proto.SignPairingTranscript.
func (s *Store) Signer() proto.PQSigner {
	if s == nil || s.status != StatusActive || s.signer == nil {
		return nil
	}
	return s.signer
}
