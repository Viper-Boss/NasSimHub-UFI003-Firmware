package hwid

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSoc is an injected filesystem. The serial is an obviously fake value.
type fakeSoc map[string]string

func (f fakeSoc) read(name string) ([]byte, error) {
	value, ok := f[name]
	switch {
	case !ok:
		return nil, fs.ErrNotExist
	case value == "EACCES":
		return nil, fs.ErrPermission
	case value == "EIO":
		return nil, os.ErrDeadlineExceeded
	}
	return []byte(value), nil
}

const fakeSerial = "1234567890"

func qualcomm(serial string) fakeSoc {
	return fakeSoc{"/sys/devices/soc0/family": "Snapdragon\n", "/sys/devices/soc0/serial_number": serial,
		"/sys/devices/soc0/soc_id": "206\n", "/sys/devices/soc0/machine": "MSM8916\n"}
}

func TestSerialIsReportedOnlyAsADomainSeparatedDigest(t *testing.T) {
	identity := Read(SocinfoDir, qualcomm(fakeSerial+"\n").read)
	want := sha256.Sum256([]byte("nsh-hw-v1\x00" + fakeSerial))
	if !identity.Present || identity.Source != "qcom-socinfo" || identity.SerialSHA256 != hex.EncodeToString(want[:]) ||
		identity.SocID != "206" || identity.Machine != "MSM8916" || identity.Reason != "" {
		t.Fatalf("identity: %+v", identity)
	}
	encoded, _ := json.Marshal(identity)
	if strings.Contains(string(encoded), fakeSerial) {
		t.Fatalf("the raw serial left the package: %s", encoded)
	}
	// A plain SHA-256 of the serial is not what is reported.
	plain := sha256.Sum256([]byte(fakeSerial))
	if identity.SerialSHA256 == hex.EncodeToString(plain[:]) {
		t.Fatal("the digest is not domain separated")
	}
	other := Read(SocinfoDir, qualcomm("1234567891").read)
	if !other.Present || other.SerialSHA256 == identity.SerialSHA256 {
		t.Fatalf("another serial must give another digest: %+v", other)
	}
}

func TestAbsentWhenThereIsNoCredibleSerial(t *testing.T) {
	cases := map[string]fakeSoc{
		"no soc0 at all":      {},
		"not qualcomm":        {"/sys/devices/soc0/family": "Other Vendor", "/sys/devices/soc0/serial_number": fakeSerial},
		"no serial attribute": {"/sys/devices/soc0/family": "Snapdragon"},
		"unreadable serial":   qualcomm("EACCES"),
		"io error":            qualcomm("EIO"),
		"empty":               qualcomm("\n"),
		"zero":                qualcomm("0\n"),
		"zeros":               qualcomm("00000000"),
		"hex zero":            qualcomm("0x00000000"),
		"binary":              qualcomm("\x00\x01\x02"),
		"too long":            qualcomm(strings.Repeat("7", 200)),
		"unreadable family":   {"/sys/devices/soc0/family": "EIO", "/sys/devices/soc0/serial_number": fakeSerial},
	}
	for name, files := range cases {
		identity := Read(SocinfoDir, files.read)
		if identity.Present || identity.Reason == "" || identity.SerialSHA256 != "" || identity.Source != "" {
			t.Errorf("%s: want absent with a reason and nothing else, got %+v", name, identity)
		}
	}
	// Missing context does not make a real serial absent, and is not invented.
	files := qualcomm(fakeSerial)
	delete(files, "/sys/devices/soc0/soc_id")
	delete(files, "/sys/devices/soc0/machine")
	if identity := Read(SocinfoDir, files.read); !identity.Present || identity.SocID != "" || identity.Machine != "" {
		t.Fatalf("context: %+v", identity)
	}
}

// Nothing else on the device is ever consulted: the reader asks only for
// files under the socinfo directory.
func TestOnlyTheSocinfoDirectoryIsRead(t *testing.T) {
	var asked []string
	Read(SocinfoDir, func(name string) ([]byte, error) {
		asked = append(asked, name)
		return qualcomm(fakeSerial).read(name)
	})
	Read(SocinfoDir, func(name string) ([]byte, error) {
		asked = append(asked, name)
		return nil, fs.ErrNotExist
	})
	for _, name := range asked {
		if !strings.HasPrefix(name, SocinfoDir+"/") {
			t.Fatalf("read outside the socinfo directory: %s", name)
		}
	}
}

func TestDirReadsARealDirectoryAndIsNotCached(t *testing.T) {
	directory := t.TempDir()
	write := func(name, value string) {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := Dir(directory)
	if identity := read(); identity.Present {
		t.Fatalf("empty directory: %+v", identity)
	}
	write("family", "Snapdragon\n")
	write("serial_number", fakeSerial+"\n")
	first := read()
	write("serial_number", "1234567891\n")
	second := read()
	if !first.Present || !second.Present || first.SerialSHA256 == second.SerialSHA256 {
		t.Fatalf("each call reads the current value: %+v %+v", first, second)
	}
}
