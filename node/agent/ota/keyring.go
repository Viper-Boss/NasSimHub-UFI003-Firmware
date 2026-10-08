package ota

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// DefaultKeyFile is where the release keys a device trusts are installed.
//
// It lives in the configuration directory, which the agent's service user can
// read and cannot write. That is the point: the agent verifies updates against
// keys it is unable to change, so a fault in the agent cannot add a key and
// then install something signed with it.
const DefaultKeyFile = "/etc/nassimhub/ota-keys.json"

// KeyFile is the on-disk form of the release keyring; see proto.OTAKeyFile.
type KeyFile = proto.OTAKeyFile

const maxKeyFileBytes = proto.OTAMaxKeyFileBytes

// LoadKeyring reads the release keys.
//
// A missing file is not an error and yields empty keyrings: the device then
// trusts no publisher, verifies no update, and reports updates as unsupported
// with that reason. A file that exists and cannot be read in full IS an error.
// Loading the keys that parsed and skipping the ones that did not would let a
// damaged file silently shrink the set of people who can sign for the device -
// or, worse, appear to work while a rotation was half applied.
func LoadKeyring(path string) (proto.OTAKeyring, proto.OTAPQKeyring, error) {
	classical, postQuantum := proto.OTAKeyring{}, proto.OTAPQKeyring{}
	if path == "" {
		return classical, postQuantum, nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return classical, postQuantum, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("release key file: %w", err)
	}
	if info.Size() > maxKeyFileBytes {
		return nil, nil, fmt.Errorf("release key file is %d bytes; refusing to read more than %d", info.Size(), maxKeyFileBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("release key file: %w", err)
	}
	return ParseKeyring(raw)
}

// ParseKeyring decodes and validates a key file.
func ParseKeyring(raw []byte) (proto.OTAKeyring, proto.OTAPQKeyring, error) {
	return proto.ParseOTAKeyFile(raw)
}

// EncodeKeyring renders a key file. It is used by the release tooling; the
// device only ever reads one.
func EncodeKeyring(classical proto.OTAKeyring, postQuantum proto.OTAPQKeyring) ([]byte, error) {
	return proto.EncodeOTAKeyFile(classical, postQuantum)
}
