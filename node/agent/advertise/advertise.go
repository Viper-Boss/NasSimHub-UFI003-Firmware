// Package advertise makes a Node findable over mDNS/DNS-SD.
//
// The responder publishes only what a NAS needs in order to know where to look:
// an instance name, an address, a port, and a few TXT hints. It does not publish
// anything about the SIM, the subscriber or the operator, because an mDNS
// announcement is broadcast to every device on the network - including devices
// that will never be allowed to pair.
package advertise

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
	"github.com/human-agent65535/nassimhub-node/proto/dnssd"
)

// DefaultTTL is the record lifetime in seconds.
const DefaultTTL = 120

// Options configures a responder.
type Options struct {
	DeviceID  string
	Platform  proto.Platform
	Port      uint16
	Addresses []net.IP
	// Paired is read at announcement time so the UI can grey out a device that
	// already has an owner before the user tries to add it.
	Paired func() bool
	// Conn is the packet connection to answer on, injected for testability.
	Conn net.PacketConn
	// To is where announcements are sent.
	To  net.Addr
	TTL uint32
}

// Responder answers DNS-SD browse queries for this Node.
type Responder struct {
	options Options

	mu       sync.Mutex
	answered int
}

// New builds a responder.
func New(options Options) (*Responder, error) {
	if options.DeviceID == "" {
		return nil, errors.New("responder requires the device id")
	}
	if options.Conn == nil || options.To == nil {
		return nil, errors.New("responder requires a connection and a destination")
	}
	if options.TTL == 0 {
		options.TTL = DefaultTTL
	}
	return &Responder{options: options}, nil
}

// Announce sends one unsolicited announcement.
func (r *Responder) Announce() error {
	packet, err := dnssd.BuildAnnouncement(r.instance(), r.options.TTL)
	if err != nil {
		return err
	}
	_, err = r.options.Conn.WriteTo(packet, r.options.To)
	return err
}

// Serve answers browse queries until ctx is cancelled.
//
// It returns only after the read loop has stopped, so a caller that cancels can
// rely on the socket no longer being used - there is no goroutine left behind
// holding it.
func (r *Responder) Serve(ctx context.Context) error {
	// One announcement at start, so a NAS already browsing sees a Node that has
	// just booted without waiting for its next query.
	_ = r.Announce()

	buffer := make([]byte, 9000)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A deadline rather than a blocking read: it is what lets cancellation
		// be noticed promptly without a second goroutine to close the socket.
		_ = r.options.Conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		count, from, err := r.options.Conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if !dnssd.IsQuery(buffer[:count]) {
			// Announcements from other responders, and our own echoed back, are
			// ignored. Answering them would make two Nodes on one network talk
			// to each other forever.
			continue
		}
		packet, err := dnssd.BuildAnnouncement(r.instance(), r.options.TTL)
		if err != nil {
			continue
		}
		destination := r.options.To
		if from != nil {
			// Answer the asker directly when we can; it halves the traffic a
			// browse generates on a busy network.
			destination = from
		}
		if _, err := r.options.Conn.WriteTo(packet, destination); err == nil {
			r.mu.Lock()
			r.answered++
			r.mu.Unlock()
		}
	}
}

// Answered counts replies sent, for tests and diagnostics.
func (r *Responder) Answered() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.answered
}

func (r *Responder) instance() dnssd.Instance {
	paired := "false"
	if r.options.Paired != nil && r.options.Paired() {
		paired = "true"
	}
	return dnssd.Instance{
		InstanceName: r.options.DeviceID,
		Port:         r.options.Port,
		Addresses:    r.options.Addresses,
		TXT: map[string]string{
			dnssd.TXTKeyDeviceID: r.options.DeviceID,
			dnssd.TXTKeyPlatform: string(r.options.Platform),
			dnssd.TXTKeyProtocol: proto.ProtocolVersion,
			dnssd.TXTKeyPaired:   paired,
			// No SIM, operator, number or signal field exists here. An mDNS
			// announcement reaches every device on the network, including ones
			// that will never be allowed to pair.
		},
	}
}
