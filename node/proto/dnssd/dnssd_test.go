package dnssd

import (
	"net"
	"strings"
	"testing"
	"time"
)

func sample() Instance {
	return Instance{
		InstanceName: "NSH-410-A83F29",
		Host:         "nsh-410-a83f29.local.",
		Port:         7580,
		Addresses:    []net.IP{net.ParseIP("192.168.1.64").To4()},
		TXT: map[string]string{
			TXTKeyDeviceID:  "NSH-410-A83F29",
			TXTKeyPlatform:  "msm8916",
			TXTKeyProtocol:  "nassimhub-node/1",
			TXTKeyPublicKey: "Zm9vYmFyCg==",
			TXTKeyPaired:    "false",
		},
	}
}

func TestAnnouncementRoundTrip(t *testing.T) {
	packet, err := BuildAnnouncement(sample(), 120)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	instances, err := ParseInstances(packet)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(instances) != 1 {
		t.Fatalf("parsed %d instances", len(instances))
	}
	got := instances[0]
	if got.InstanceName != "NSH-410-A83F29" {
		t.Fatalf("instance name is %q", got.InstanceName)
	}
	if got.Port != 7580 {
		t.Fatalf("port is %d", got.Port)
	}
	if got.Host != "nsh-410-a83f29.local." {
		t.Fatalf("host is %q", got.Host)
	}
	if len(got.Addresses) != 1 || !got.Addresses[0].Equal(net.ParseIP("192.168.1.64")) {
		t.Fatalf("addresses are %v", got.Addresses)
	}
	if got.TXT[TXTKeyPlatform] != "msm8916" {
		t.Fatalf("txt is %v", got.TXT)
	}
	if got.ClaimedDeviceID() != "NSH-410-A83F29" {
		t.Fatalf("claimed device id is %q", got.ClaimedDeviceID())
	}
}

func TestIPv6AnnouncementRoundTrip(t *testing.T) {
	instance := sample()
	instance.Addresses = []net.IP{net.ParseIP("fe80::1")}
	packet, err := BuildAnnouncement(instance, 120)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	instances, err := ParseInstances(packet)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(instances) != 1 || len(instances[0].Addresses) != 1 {
		t.Fatalf("parsed %+v", instances)
	}
	if !instances[0].Addresses[0].Equal(net.ParseIP("fe80::1")) {
		t.Fatalf("address is %v", instances[0].Addresses[0])
	}
}

func TestQueryRoundTrip(t *testing.T) {
	packet, err := BuildQuery()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !IsQuery(packet) {
		t.Fatal("a query we built was not recognised as one")
	}
	// A response must not be mistaken for a query, or a responder would answer
	// its own announcements forever.
	announcement, err := BuildAnnouncement(sample(), 120)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if IsQuery(announcement) {
		t.Fatal("an announcement was treated as a query")
	}
	instances, err := ParseInstances(packet)
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	if len(instances) != 0 {
		t.Fatalf("a query yielded %d instances", len(instances))
	}
}

func TestTXTEncodingIsDeterministic(t *testing.T) {
	first, err := BuildAnnouncement(sample(), 120)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := BuildAnnouncement(sample(), 120)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if string(again) != string(first) {
			t.Fatal("announcement bytes vary between builds; map ordering leaked into the wire format")
		}
	}
}

// ---------------------------------------------------------------------------
// Hostile input
// ---------------------------------------------------------------------------

func TestTruncatedPacketsDoNotPanic(t *testing.T) {
	packet, err := BuildAnnouncement(sample(), 120)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for cut := 0; cut < len(packet); cut++ {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("parsing a %d-byte prefix panicked: %v", cut, recovered)
				}
			}()
			_, _ = ParseInstances(packet[:cut])
			_ = IsQuery(packet[:cut])
		}()
	}
}

func TestCompressionPointerLoopIsRejected(t *testing.T) {
	// A pointer that points at itself is the classic way to hang a naive DNS
	// parser. It must terminate, not spin.
	packet := []byte{
		0, 0, // id
		0x84, 0x00, // response
		0, 0, // questions
		0, 1, // answers
		0, 0, 0, 0,
		0xC0, 0x0C, // a name that is a pointer to offset 12 - itself
		0, 12, 0, 1, 0, 0, 0, 120, 0, 0,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = ParseInstances(packet)
	}()
	select {
	case <-done:
	case <-timeoutAfter():
		t.Fatal("parsing a self-referential compression pointer did not terminate")
	}
}

func TestRandomGarbageIsRejectedCleanly(t *testing.T) {
	inputs := [][]byte{
		{},
		{0},
		{0xFF, 0xFF, 0xFF, 0xFF},
		[]byte(strings.Repeat("\xff", 512)),
		[]byte("this is not a dns packet at all"),
	}
	for index, input := range inputs {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("input %d panicked: %v", index, recovered)
				}
			}()
			_, _ = ParseInstances(input)
			_ = IsQuery(input)
		}()
	}
}

func TestOtherServicesOnTheNetworkAreIgnored(t *testing.T) {
	// A household network is full of mDNS. A printer announcement must not
	// become a candidate Node.
	other := Instance{InstanceName: "Office Printer", Host: "printer.local.", Port: 631}
	packet, err := BuildAnnouncement(other, 120)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Rewrite the service type so the packet advertises a printer service.
	rewritten := strings.Replace(string(packet), "\x0f_nassimhub-node", "\x0f_ipp-----------", -1)
	instances, err := ParseInstances([]byte(rewritten))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, instance := range instances {
		if strings.Contains(instance.InstanceName, "Printer") && instance.Port == 631 {
			t.Fatal("a non-Node service was returned as a Node candidate")
		}
	}
}

// ---------------------------------------------------------------------------
// The identity rule
// ---------------------------------------------------------------------------

// TestDiscoveryDataIsOnlyEverAClaim pins the naming that keeps callers honest.
// If the accessor were ever renamed to something that reads like a fact, code
// downstream would start trusting it.
func TestDiscoveryDataIsOnlyEverAClaim(t *testing.T) {
	instance := sample()
	// An announcement can say anything at all, including another device's id.
	instance.TXT[TXTKeyDeviceID] = "NSH-410-VICTIM"
	instance.TXT[TXTKeyPublicKey] = "not-a-real-key"
	packet, err := BuildAnnouncement(instance, 120)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	parsed, err := ParseInstances(packet)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("parsed %d", len(parsed))
	}
	// The package accepts it without complaint - that is correct, because the
	// package is not where identity is decided.
	if parsed[0].ClaimedDeviceID() != "NSH-410-VICTIM" {
		t.Fatalf("claimed id is %q", parsed[0].ClaimedDeviceID())
	}
}

func timeoutAfter() <-chan time.Time {
	return time.After(3 * time.Second)
}
