// Package hwid reads the one hardware identifier this device can credibly
// report, for the gateway's "the module was replaced" detection.
//
// On an MSM8916 the modem is part of the SoC, so "the module" is the SoC, and
// the kernel's Qualcomm socinfo driver exposes its serial number. That serial
// is the only source. When it cannot be read the answer is "not present", with
// the reason - never a substitute. An IMEI is configuration that can be
// rewritten, a MAC address and an interface name are software, the eMMC's
// identity belongs to storage that can be swapped without touching the modem,
// and a generated value identifies nothing; any of them would let the gateway
// believe it is watching the hardware when it is not.
//
// The raw serial does not leave this package. What is reported is a
// domain-separated SHA-256 of it, and nothing here logs.
package hwid

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// SocinfoDir is where the kernel's socinfo driver publishes the SoC.
const SocinfoDir = "/sys/devices/soc0"

// qualcommFamily is what drivers/soc/qcom/socinfo.c reports as the family.
// Other vendors' drivers also create soc0 with a serial_number; a serial from
// one of those is not what "qcom-socinfo" claims, so it is not reported.
const qualcommFamily = "Snapdragon"

const maxAttributeBytes = 128

// ReadFile returns a file's content. It is injected so the reader is tested
// against fixture directories; the device's own is bounded.
type ReadFile func(name string) ([]byte, error)

// System reads the identifier from this machine's sysfs.
func System() proto.HardwareIdentity { return Read(SocinfoDir, boundedRead) }

// Dir reads the identifier from a directory laid out like SocinfoDir. It
// exists for the mock Node and for tests.
func Dir(directory string) func() proto.HardwareIdentity {
	return func() proto.HardwareIdentity { return Read(directory, boundedRead) }
}

func boundedRead(name string) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, maxAttributeBytes+1))
}

func absent(reason string) proto.HardwareIdentity {
	return proto.HardwareIdentity{Present: false, Reason: reason}
}

// printable reports whether a sysfs attribute is short printable ASCII.
func printable(value string) bool {
	if value == "" || len(value) > maxAttributeBytes {
		return false
	}
	for _, character := range value {
		if character < ' ' || character > '~' {
			return false
		}
	}
	return true
}

// allZero reports a serial that is zero however it was printed (0, 00000000,
// 0x0): an unprogrammed or unreported value, shared by every such device.
func allZero(serial string) bool {
	digits := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(serial), "0x"), "0X")
	return strings.Trim(digits, "0") == ""
}

// Read reports the hardware identity found under directory.
func Read(directory string, read ReadFile) proto.HardwareIdentity {
	attribute := func(name string) (string, error) {
		raw, err := read(path.Join(directory, name))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	}
	family, err := attribute("family")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return absent("the kernel does not expose " + SocinfoDir + " (no SoC information driver)")
	case err != nil:
		return absent("the SoC information could not be read")
	case family != qualcommFamily:
		return absent("soc0 is not published by the Qualcomm socinfo driver")
	}
	serial, err := attribute("serial_number")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return absent("the Qualcomm socinfo driver does not expose a serial number on this kernel")
	case errors.Is(err, fs.ErrPermission):
		return absent("the agent is not permitted to read the SoC serial number")
	case err != nil:
		return absent("the SoC serial number could not be read")
	case serial == "":
		return absent("the SoC serial number is empty")
	case !printable(serial):
		return absent("the SoC serial number is not in a recognised form")
	case allZero(serial):
		return absent("the SoC serial number is all zeros")
	}
	digest := sha256.Sum256([]byte(proto.HardwareHashDomain + serial))
	identity := proto.HardwareIdentity{Present: true, Source: proto.HardwareSourceSocinfo, SerialSHA256: hex.EncodeToString(digest[:])}
	// Context only: shared by every device of the model, and reported as read
	// or not at all.
	if value, err := attribute("soc_id"); err == nil && printable(value) {
		identity.SocID = value
	}
	if value, err := attribute("machine"); err == nil && printable(value) {
		identity.Machine = value
	}
	return identity
}
