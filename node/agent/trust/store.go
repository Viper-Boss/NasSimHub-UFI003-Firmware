package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SignedRecord binds a trust snapshot to the existing Node identity. It is
// tamper-evident, but without a remote generation registry it is not rollback
// proof: an attacker with full eMMC access can restore an older valid file.
type SignedRecord struct {
	Record    Record `json:"record"`
	Signature string `json:"signature"`
}

func Save(path string, record Record, private ed25519.PrivateKey) error {
	if len(private) != ed25519.PrivateKeySize || record.DeviceID == "" || record.Generation == 0 {
		return errors.New("invalid trust identity, key or generation")
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	envelope, err := json.MarshalIndent(SignedRecord{
		Record: record,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload)),
	}, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".trust-record-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(envelope); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return nil
}

func Load(path, expectedDeviceID string, public ed25519.PublicKey) (Record, error) {
	if expectedDeviceID == "" || len(public) != ed25519.PublicKeySize {
		return Record{}, errors.New("expected identity and public key are required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Record{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64*1024 || info.Mode().Perm()&0o077 != 0 {
		return Record{}, errors.New("trust record is not a private regular file")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return Record{}, err
	}
	var envelope SignedRecord
	if err := json.Unmarshal(content, &envelope); err != nil {
		return Record{}, err
	}
	if envelope.Record.DeviceID != expectedDeviceID || envelope.Record.Generation == 0 {
		return Record{}, errors.New("trust record belongs to another or invalid device")
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return Record{}, err
	}
	payload, err := json.Marshal(envelope.Record)
	if err != nil {
		return Record{}, err
	}
	if !ed25519.Verify(public, payload, signature) {
		return Record{}, fmt.Errorf("trust record signature failed for %s", expectedDeviceID)
	}
	return envelope.Record, nil
}

// LoadEngine admits only a verified snapshot into the policy engine. The
// caller must compare Generation with the NAS revocation registry before
// treating a previously Trusted state as authoritative.
func LoadEngine(path, expectedDeviceID string, public ed25519.PublicKey) (*Engine, error) {
	record, err := Load(path, expectedDeviceID, public)
	if err != nil {
		return nil, err
	}
	switch record.State {
	case Unbound, Observation, Trusted, Restricted, Quarantine:
	default:
		return nil, errors.New("unknown trust state")
	}
	if record.State != Unbound && (len(record.BindingHash) != 64 || !isHex(record.BindingHash)) && record.State != Restricted && record.State != Quarantine {
		return nil, errors.New("trust record lacks a valid binding")
	}
	return &Engine{record: record}, nil
}
