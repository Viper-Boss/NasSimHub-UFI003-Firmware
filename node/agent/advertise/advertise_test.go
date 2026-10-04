package advertise

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
	"github.com/human-agent65535/nassimhub-node/proto/dnssd"
)

const deviceID = "NSH-410-A83F29"

func pair(t *testing.T) (node, nas net.PacketConn) {
	t.Helper()
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestResponderAnswersABrowseQuery(t *testing.T) {
	nodeConn, nasConn := pair(t)
	responder, err := New(Options{
		DeviceID: deviceID, Platform: proto.PlatformMSM8916, Port: 7580,
		Addresses: []net.IP{net.ParseIP("192.168.1.64").To4()},
		Conn:      nodeConn, To: nasConn.LocalAddr(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = responder.Serve(ctx) }()

	query, err := dnssd.BuildQuery()
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if _, err := nasConn.WriteTo(query, nodeConn.LocalAddr()); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = nasConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 4096)
	for {
		count, _, err := nasConn.ReadFrom(buffer)
		if err != nil {
			t.Fatalf("no answer to the browse query: %v", err)
		}
		instances, err := dnssd.ParseInstances(buffer[:count])
		if err != nil || len(instances) == 0 {
			continue // the unsolicited announcement, or noise
		}
		if instances[0].ClaimedDeviceID() != deviceID {
			t.Fatalf("answer claims %q", instances[0].ClaimedDeviceID())
		}
		if instances[0].Port != 7580 {
			t.Fatalf("answer advertises port %d", instances[0].Port)
		}
		return
	}
}

func TestResponderIgnoresAnnouncementsIncludingItsOwn(t *testing.T) {
	// Two Nodes on one network would answer each other forever if
	// announcements were treated as queries.
	nodeConn, nasConn := pair(t)
	responder, err := New(Options{
		DeviceID: deviceID, Platform: proto.PlatformMSM8916, Port: 7580,
		Conn: nodeConn, To: nasConn.LocalAddr(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = responder.Serve(ctx) }()

	// Drain the start-up announcement.
	_ = nasConn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4096)
	_, _, _ = nasConn.ReadFrom(buffer)

	before := responder.Answered()
	other, err := dnssd.BuildAnnouncement(dnssd.Instance{
		InstanceName: "NSH-410-B00002", Port: 7580,
	}, 120)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := nasConn.WriteTo(other, nodeConn.LocalAddr()); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	time.Sleep(400 * time.Millisecond)
	if responder.Answered() != before {
		t.Fatalf("the responder replied to %d announcements", responder.Answered()-before)
	}
}

func TestAnnouncementCarriesNoSubscriberData(t *testing.T) {
	// An mDNS packet reaches every device on the network, including ones that
	// will never be allowed to pair.
	nodeConn, nasConn := pair(t)
	responder, err := New(Options{
		DeviceID: deviceID, Platform: proto.PlatformMSM8916, Port: 7580,
		Addresses: []net.IP{net.ParseIP("192.168.1.64").To4()},
		Conn:      nodeConn, To: nasConn.LocalAddr(),
		Paired: func() bool { return true },
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := responder.Announce(); err != nil {
		t.Fatalf("announce: %v", err)
	}
	_ = nasConn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4096)
	count, _, err := nasConn.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	packet := strings.ToLower(string(buffer[:count]))
	for _, forbidden := range []string{
		"iccid", "imsi", "8986", "4600", "+86", "operator", "signal", "sms", "call",
	} {
		if strings.Contains(packet, forbidden) {
			t.Fatalf("the announcement contains %q", forbidden)
		}
	}
	instances, err := dnssd.ParseInstances(buffer[:count])
	if err != nil || len(instances) != 1 {
		t.Fatalf("parse: %v %+v", err, instances)
	}
	if instances[0].TXT[dnssd.TXTKeyPaired] != "true" {
		t.Fatalf("paired hint is %q", instances[0].TXT[dnssd.TXTKeyPaired])
	}
}

func TestServeStopsOnCancellation(t *testing.T) {
	// A responder that outlived its context would hold the socket open and leak
	// a goroutine for the life of the process.
	nodeConn, nasConn := pair(t)
	responder, err := New(Options{
		DeviceID: deviceID, Port: 7580, Conn: nodeConn, To: nasConn.LocalAddr(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- responder.Serve(ctx) }()

	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after cancellation")
	}
}

func TestResponderRequiresIdentityAndSocket(t *testing.T) {
	conn, to := pair(t)
	if _, err := New(Options{Conn: conn, To: to.LocalAddr()}); err == nil {
		t.Fatal("a responder without a device id was accepted")
	}
	if _, err := New(Options{DeviceID: deviceID}); err == nil {
		t.Fatal("a responder without a socket was accepted")
	}
}
