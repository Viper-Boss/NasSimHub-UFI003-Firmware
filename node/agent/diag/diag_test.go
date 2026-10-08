package diag

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/internal/logbuf"
	"github.com/human-agent65535/nassimhub-node/agent/modembackend/mock"
	netmock "github.com/human-agent65535/nassimhub-node/agent/netbackend/mock"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// The values below are planted in every source the collector reads. If any of
// them reaches the bundle, the scan at the bottom of this file finds it.
//
// They are written here as one list rather than scattered through the tests so
// that adding a new secret to the product means adding one line here, and the
// test that has to be updated is the one a reviewer will look at.
const (
	secretICCID    = "89860412345678901234"
	secretIMSI     = "460001234567890"
	secretPhone    = "+8610000000001"
	secretPeer     = "+8610000000010"
	secretSMSBody  = "your verification code is 493127"
	secretCode     = "493127"
	secretToken    = "eyJhbGciOiJFZDI1NTE5In0.dGVzdA.c2lnbmF0dXJl"
	secretWiFiPSK  = "correct-horse-battery-staple"
	secretSIMPIN   = "8261"
	secretSIMPUK   = "47193058"
	secretKeySeed  = "d9f1c4a6b2e87350a1c4d9f1c4a6b2e87350a1c4d9f1c4a6b2e87350a1c4d9f1c"
	secretSSIDName = "Wang-Family-5G"
)

func allSecrets() []string {
	return []string{
		secretICCID, secretIMSI, secretPhone, secretPeer, secretSMSBody,
		secretCode, secretToken, secretWiFiPSK, secretSIMPIN, secretSIMPUK,
		secretKeySeed, secretSSIDName,
	}
}

// loaded builds a Node whose every surface is carrying something that must not
// escape: a real SIM identity, real messages, and logs written by code that was
// careless.
func loaded(t *testing.T) Options {
	t.Helper()

	scenario := mock.ChinaMobile
	scenario.ICCID = secretICCID
	scenario.IMSI = secretIMSI
	scenario.PhoneNumber = secretPhone
	modem := mock.New(mock.Options{Scenario: scenario})

	if _, err := modem.SendSMS(context.Background(), proto.SendSMSRequest{
		RequestID: "r1", To: secretPeer, Text: secretSMSBody,
	}); err != nil {
		t.Fatalf("seed sms: %v", err)
	}

	network := netmock.New(netmock.Options{DeviceID: "NSH-MOCK-AAAAAA"})
	if _, err := network.Connect(context.Background(), proto.WiFiConnectRequest{
		SSID: secretSSIDName, PSK: secretWiFiPSK,
	}); err != nil {
		t.Fatalf("seed wifi: %v", err)
	}

	logs := logbuf.New(logbuf.Options{})
	// Deliberately careless logging, of the kind that happens under deadline.
	// logbuf redacts on the way in; the bundle must not depend on that having
	// worked, and this is what checks both layers at once.
	logs.Errorf("modem", "send to %s failed: %s", secretPeer, secretSMSBody)
	logs.Warnf("auth", "token=%s rejected", secretToken)
	logs.Errorf("wifi", "join %s failed, psk=%s", secretSSIDName, secretWiFiPSK)
	logs.Errorf("sim", "iccid %s imsi %s pin=%s puk=%s", secretICCID, secretIMSI, secretSIMPIN, secretSIMPUK)
	logs.Errorf("identity", "private_seed=%s", secretKeySeed)
	t.Cleanup(func() { _ = logs.Close() })

	return Options{
		Identity: Identity{
			DeviceID:  "NSH-MOCK-AAAAAA",
			Platform:  proto.PlatformMock,
			Model:     "test",
			BootID:    "boot-1",
			StartedAt: time.Now().Add(-90 * time.Minute),
		},
		AgentVersion: "1.2.3",
		BuildDate:    "2026-09-13",
		Modem:        modem,
		Network:      network,
		Pairing:      stubPairing{},
		Logs:         logs,
		Connection:   proto.ConnectionUSB,
		ListenPorts:  []int{7580},
		TLS:          true,
	}
}

type stubPairing struct{}

func (stubPairing) State() proto.PairingState { return proto.PairingPaired }
func (stubPairing) NonceCacheSize() int       { return 7 }
func (stubPairing) SessionCount() int         { return 2 }

// ---------------------------------------------------------------------------
// The rule
// ---------------------------------------------------------------------------

// This is the test the whole package exists to pass. It scans the finished
// bundle - the bytes a user would actually send - for every planted secret.
func TestNoSecretReachesTheBundle(t *testing.T) {
	t.Parallel()

	bundle := Collect(context.Background(), loaded(t))

	document, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	summary := Summary(bundle)

	var archive bytes.Buffer
	if err := WriteArchive(&archive, bundle); err != nil {
		t.Fatal(err)
	}
	unpacked := unpack(t, archive.Bytes())

	surfaces := map[string]string{
		"json":    string(document),
		"summary": summary,
		"archive": strings.Join(values(unpacked), "\n"),
	}
	for name, content := range surfaces {
		lowered := strings.ToLower(content)
		for _, secret := range allSecrets() {
			if strings.Contains(lowered, strings.ToLower(secret)) {
				t.Fatalf("the %s surface carries %q", name, secret)
			}
		}
	}
}

// A bundle that contained nothing would trivially pass the test above. This one
// checks it is actually useful.
func TestTheBundleIsActuallyUseful(t *testing.T) {
	t.Parallel()

	bundle := Collect(context.Background(), loaded(t))

	if bundle.Device.DeviceID != "NSH-MOCK-AAAAAA" {
		t.Fatalf("device id is %q", bundle.Device.DeviceID)
	}
	if bundle.Device.BootID != "boot-1" || !bundle.Device.Paired {
		t.Fatalf("device section is %+v", bundle.Device)
	}
	if bundle.Software.AgentVersion != "1.2.3" || bundle.Software.ProtocolMajor != proto.ProtocolMajor {
		t.Fatalf("software section is %+v", bundle.Software)
	}
	if bundle.Link.Connection != proto.ConnectionUSB || !bundle.Link.TLS {
		t.Fatalf("link section is %+v", bundle.Link)
	}
	if bundle.Modem.State == "" || bundle.Modem.Backend == "" {
		t.Fatalf("modem section is %+v", bundle.Modem)
	}
	if bundle.Modem.SIMState != proto.SIMReady || !bundle.Modem.SIMPresent {
		t.Fatalf("sim state is %q", bundle.Modem.SIMState)
	}
	// The operator NAME is useful and allowed; the code is not included.
	if bundle.Network.OperatorName == "" {
		t.Fatal("the operator name is missing; a support case cannot tell which network")
	}
	if bundle.WiFi.State == "" || !bundle.WiFi.HasSSID {
		t.Fatalf("wifi section is %+v; the fact that a network is configured is diagnostic",
			bundle.WiFi)
	}
	if bundle.Runtime.Goroutines <= 0 || bundle.Runtime.UptimeSeconds <= 0 {
		t.Fatalf("runtime section is %+v", bundle.Runtime)
	}
	if bundle.Runtime.ActiveSessions != 2 || bundle.Runtime.NonceCacheSize != 7 {
		t.Fatalf("pairing counters are %+v", bundle.Runtime)
	}
	if len(bundle.Errors) == 0 {
		t.Fatal("no recent errors were collected; the logs had five")
	}
	for _, record := range bundle.Errors {
		if record.Source == "" || record.Message == "" {
			t.Fatalf("an error record is empty: %+v", record)
		}
	}
}

// The careless log lines must still be present as evidence - redacted, not
// dropped. A bundle that silently discards the failing lines is worse than one
// that redacts them, because the reader concludes nothing went wrong.
func TestCarelessLogLinesSurviveRedacted(t *testing.T) {
	t.Parallel()

	bundle := Collect(context.Background(), loaded(t))

	var sawModem, sawAuth, sawWiFi bool
	for _, record := range bundle.Errors {
		switch record.Source {
		case "modem":
			sawModem = true
		case "auth":
			sawAuth = true
		case "wifi":
			sawWiFi = true
		}
		if !strings.Contains(record.Message, logbuf.Redacted) &&
			(record.Source == "auth" || record.Source == "sim" || record.Source == "identity") {
			t.Fatalf("a line that carried a credential shows no redaction marker: %q", record.Message)
		}
	}
	if !sawModem || !sawAuth || !sawWiFi {
		t.Fatalf("log evidence was dropped rather than redacted: modem=%t auth=%t wifi=%t",
			sawModem, sawAuth, sawWiFi)
	}
}

// The SSID is deliberately reduced to a boolean. This pins that decision, since
// "we have the field, why not include it" is the exact pressure that erodes it.
func TestTheSSIDIsReducedToABoolean(t *testing.T) {
	t.Parallel()

	bundle := Collect(context.Background(), loaded(t))
	if !bundle.WiFi.HasSSID {
		t.Fatal("a configured network reported has_ssid false")
	}
	document, err := json.Marshal(bundle.WiFi)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(document), secretSSIDName) {
		t.Fatalf("the wifi section names the network: %s", document)
	}
}

// A bundle from a device with nothing configured must still be produced, with
// notes explaining the gaps. This is the state a device in trouble is often in.
func TestABareDeviceStillProducesABundle(t *testing.T) {
	t.Parallel()

	bundle := Collect(context.Background(), Options{
		Identity:     Identity{DeviceID: "NSH-MOCK-BBBBBB", StartedAt: time.Now().Add(-time.Minute)},
		AgentVersion: "1.0.0",
	})
	if bundle.FormatVersion != proto.DiagnosticsFormatVersion {
		t.Fatalf("format version is %d", bundle.FormatVersion)
	}
	if len(bundle.Notes) < 2 {
		t.Fatalf("a device with no backends produced notes %v; the gaps should be explained",
			bundle.Notes)
	}
	var archive bytes.Buffer
	if err := WriteArchive(&archive, bundle); err != nil {
		t.Fatalf("a bare bundle could not be written: %v", err)
	}
}

// The archive has to be a real gzipped tar with both files, or the user cannot
// open it to check what they are sending.
func TestTheArchiveIsReadable(t *testing.T) {
	t.Parallel()

	bundle := Collect(context.Background(), loaded(t))
	var archive bytes.Buffer
	if err := WriteArchive(&archive, bundle); err != nil {
		t.Fatal(err)
	}
	entries := unpack(t, archive.Bytes())
	if len(entries) != 2 {
		t.Fatalf("the archive holds %d entries: %v", len(entries), names(entries))
	}
	document, ok := entries["diagnostics.json"]
	if !ok {
		t.Fatalf("no diagnostics.json in %v", names(entries))
	}
	var round proto.DiagnosticsBundle
	if err := json.Unmarshal([]byte(document), &round); err != nil {
		t.Fatalf("diagnostics.json does not parse: %v", err)
	}
	if round.Device.DeviceID != bundle.Device.DeviceID {
		t.Fatal("the archived document is not the bundle")
	}
	summary, ok := entries["summary.txt"]
	if !ok {
		t.Fatalf("no summary.txt in %v", names(entries))
	}
	if !strings.Contains(summary, "safe to attach") {
		t.Fatal("the summary does not tell the user what the bundle contains")
	}
}

func TestFileNameIsSortableAndSafe(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 9, 13, 19, 4, 5, 0, time.UTC)
	name := FileName("NSH-410-A83F29", at)
	if name != "nassimhub-nsh-410-a83f29-20260913-190405.tar.gz" {
		t.Fatalf("file name is %q", name)
	}
	if strings.ContainsAny(name, `/\ :`) {
		t.Fatalf("file name %q contains a character that breaks on some systems", name)
	}
}

// ---------------------------------------------------------------------------

func unpack(t *testing.T, archive []byte) map[string]string {
	t.Helper()
	decompressor, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("the archive is not gzip: %v", err)
	}
	defer decompressor.Close()

	entries := map[string]string{}
	reader := tar.NewReader(decompressor)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("the archive is not a readable tar: %v", err)
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = string(content)
	}
	return entries
}

func names(entries map[string]string) []string {
	out := make([]string, 0, len(entries))
	for name := range entries {
		out = append(out, name)
	}
	return out
}

func values(entries map[string]string) []string {
	out := make([]string, 0, len(entries))
	for _, value := range entries {
		out = append(out, value)
	}
	return out
}

// The transport section must not become a way around the allowlist.
//
// It is filled in from a different package, which is exactly the shape of
// change that reintroduces a leak: someone adds a field there, and the bundle
// starts carrying it without anyone editing this package. So the planted
// secrets are pushed through the transport section too.
func TestTheTransportSectionCarriesNoSecrets(t *testing.T) {
	t.Parallel()

	options := loaded(t)
	options.Transport = proto.TransportSection{
		Mode:     proto.TransportKCP,
		Resolved: proto.TransportKCP,
		Advice:   proto.AdviceWeakNetwork,
		RTT:      "180ms",
		Jitter:   "22ms",
		// A caller trying to be helpful, putting things in that must not be
		// there. The section has no field for them, which is the primary
		// defence; this checks the secondary one.
		FECMode:      "aggressive",
		FECRecovered: 12,
		FECOverhead:  0.25,
		Measured:     true,
		Security: proto.SecurityCapability{
			PQSupported: true,
			PQActive:    proto.TriYes,
			PQGroup:     "X25519MLKEM768",
			PQProfile:   proto.PQStandard,
			PQPolicy:    proto.PQPreferred,
			TLSVersion:  "TLS 1.3",
			Observable:  true,
		},
	}

	bundle := Collect(context.Background(), options)
	document, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	surfaces := []string{string(document), Summary(bundle)}
	for _, content := range surfaces {
		lowered := strings.ToLower(content)
		for _, secret := range allSecrets() {
			if strings.Contains(lowered, strings.ToLower(secret)) {
				t.Fatalf("the transport section let %q through", secret)
			}
		}
	}

	// And it must actually report the link, or it is not worth having.
	if bundle.Transport.Mode != proto.TransportKCP || !bundle.Transport.Measured {
		t.Fatalf("the transport section is %+v", bundle.Transport)
	}
	if !strings.Contains(Summary(bundle), "X25519MLKEM768") {
		t.Fatal("the summary does not say which key agreement was used")
	}
	if !strings.Contains(Summary(bundle), "aggressive") {
		t.Fatal("the summary does not report the FEC mode")
	}
}

// A build that cannot observe the negotiated group must say so in the bundle
// rather than leaving a reader to conclude the connection was classical.
func TestAnUnobservableBuildExplainsItself(t *testing.T) {
	t.Parallel()

	options := loaded(t)
	options.Transport = proto.TransportSection{
		Mode: proto.TransportStandard,
		Security: proto.SecurityCapability{
			PQSupported: true,
			PQActive:    proto.TriUnknown,
			Observable:  false,
			PQProfile:   proto.PQStandard,
			PQPolicy:    proto.PQPreferred,
			TLSVersion:  "TLS 1.3",
		},
	}
	summary := Summary(Collect(context.Background(), options))
	if !strings.Contains(summary, "cannot read back") {
		t.Fatalf("an unknown pq state is unexplained in the summary:\n%s", summary)
	}
}
