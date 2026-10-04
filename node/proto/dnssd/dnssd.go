// Package dnssd is the minimal DNS-SD wire format NasSimHub Nodes use to be
// found on a local network.
//
// It is hand-written against RFC 1035 and RFC 6763 rather than pulled from a
// library because the agent must stay a single static binary with no
// dependencies beyond the standard library, and because the subset actually
// needed here is small: one service type, PTR/SRV/TXT/A/AAAA, no probing, no
// conflict resolution, no cache-flush semantics.
//
// The security rule that shapes the whole package: NOTHING HERE IS IDENTITY.
// A responder can claim any name, any TXT value and any address, so a discovery
// result is a candidate address and nothing more. The device_id and public key
// in a TXT record exist only so the UI can show something while the real check
// runs; the real check is fetching the discovery document over TLS and
// verifying that the key which completed the handshake derives the device_id.
// Callers are expected to treat every field here as a hint.
package dnssd

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ServiceType is the DNS-SD service NasSimHub Nodes advertise.
const ServiceType = "_nassimhub-node._tcp.local."

// MulticastGroupV4 and MulticastPort are the standard mDNS endpoint.
const (
	MulticastGroupV4 = "224.0.0.251"
	MulticastPort    = 5353
)

// TXT keys. They are advisory, never trusted.
const (
	TXTKeyDeviceID  = "id"
	TXTKeyPlatform  = "plat"
	TXTKeyProtocol  = "proto"
	TXTKeyPublicKey = "pk"
	TXTKeyPaired    = "paired"
)

// Record types used here.
const (
	typeA    = 1
	typePTR  = 12
	typeTXT  = 16
	typeAAAA = 28
	typeSRV  = 33
)

const classIN = 1

// ErrMalformed reports a packet that could not be parsed.
var ErrMalformed = errors.New("malformed dns message")

// Instance is one advertised Node.
//
// Every field is attacker-controllable. Treat DeviceID and PublicKey as claims
// to be checked, not as facts.
type Instance struct {
	// InstanceName is the DNS-SD instance label, conventionally the device id.
	InstanceName string
	Host         string
	Port         uint16
	Addresses    []net.IP
	TXT          map[string]string
}

// ClaimedDeviceID reports the device id the TXT record claims.
//
// The name says "claimed" deliberately: callers that use this for anything
// other than display are using it wrong.
func (i Instance) ClaimedDeviceID() string { return i.TXT[TXTKeyDeviceID] }

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

type builder struct {
	buffer []byte
}

func (b *builder) u8(value byte)    { b.buffer = append(b.buffer, value) }
func (b *builder) u16(value uint16) { b.buffer = append(b.buffer, byte(value>>8), byte(value)) }
func (b *builder) u32(value uint32) {
	b.buffer = append(b.buffer, byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

// name writes a domain name in uncompressed label form. Compression is omitted
// on purpose: these packets are small, and a compression pointer written wrong
// is a parsing bug in every other implementation on the network.
func (b *builder) name(value string) error {
	value = strings.TrimSuffix(value, ".")
	if value != "" {
		for _, label := range strings.Split(value, ".") {
			if len(label) == 0 || len(label) > 63 {
				return fmt.Errorf("dns label %q is not 1-63 bytes", label)
			}
			b.u8(byte(len(label)))
			b.buffer = append(b.buffer, label...)
		}
	}
	b.u8(0)
	return nil
}

func (b *builder) record(name string, recordType uint16, ttl uint32, data []byte) error {
	if err := b.name(name); err != nil {
		return err
	}
	b.u16(recordType)
	b.u16(classIN)
	b.u32(ttl)
	b.u16(uint16(len(data)))
	b.buffer = append(b.buffer, data...)
	return nil
}

// BuildQuery encodes a DNS-SD browse query for the Node service.
func BuildQuery() ([]byte, error) {
	b := &builder{}
	b.u16(0) // transaction id; mDNS ignores it
	b.u16(0) // flags: standard query
	b.u16(1) // one question
	b.u16(0)
	b.u16(0)
	b.u16(0)
	if err := b.name(ServiceType); err != nil {
		return nil, err
	}
	b.u16(typePTR)
	b.u16(classIN)
	return b.buffer, nil
}

// BuildAnnouncement encodes the PTR/SRV/TXT/A answer set for one instance.
func BuildAnnouncement(instance Instance, ttl uint32) ([]byte, error) {
	if instance.InstanceName == "" {
		return nil, errors.New("an announcement needs an instance name")
	}
	full := instance.InstanceName + "." + ServiceType
	host := instance.Host
	if host == "" {
		host = strings.ToLower(instance.InstanceName) + ".local."
	}

	answers := &builder{}
	count := 0

	ptr := &builder{}
	if err := ptr.name(full); err != nil {
		return nil, err
	}
	if err := answers.record(ServiceType, typePTR, ttl, ptr.buffer); err != nil {
		return nil, err
	}
	count++

	srv := &builder{}
	srv.u16(0) // priority
	srv.u16(0) // weight
	srv.u16(instance.Port)
	if err := srv.name(host); err != nil {
		return nil, err
	}
	if err := answers.record(full, typeSRV, ttl, srv.buffer); err != nil {
		return nil, err
	}
	count++

	txt := encodeTXT(instance.TXT)
	if err := answers.record(full, typeTXT, ttl, txt); err != nil {
		return nil, err
	}
	count++

	for _, address := range instance.Addresses {
		if v4 := address.To4(); v4 != nil {
			if err := answers.record(host, typeA, ttl, v4); err != nil {
				return nil, err
			}
			count++
			continue
		}
		if v6 := address.To16(); v6 != nil {
			if err := answers.record(host, typeAAAA, ttl, v6); err != nil {
				return nil, err
			}
			count++
		}
	}

	header := &builder{}
	header.u16(0)
	header.u16(0x8400) // response, authoritative
	header.u16(0)
	header.u16(uint16(count))
	header.u16(0)
	header.u16(0)
	return append(header.buffer, answers.buffer...), nil
}

// encodeTXT writes key=value strings in DNS-SD character-string form.
func encodeTXT(values map[string]string) []byte {
	if len(values) == 0 {
		return []byte{0}
	}
	// Deterministic order keeps packets byte-stable, which makes a failing test
	// reproducible instead of ordering-dependent.
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sortStrings(keys)

	encoded := []byte{}
	for _, key := range keys {
		entry := key + "=" + values[key]
		if len(entry) > 255 {
			entry = entry[:255]
		}
		encoded = append(encoded, byte(len(entry)))
		encoded = append(encoded, entry...)
	}
	return encoded
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

type parser struct {
	data   []byte
	offset int
}

func (p *parser) u8() (byte, error) {
	if p.offset >= len(p.data) {
		return 0, ErrMalformed
	}
	value := p.data[p.offset]
	p.offset++
	return value, nil
}

func (p *parser) u16() (uint16, error) {
	if p.offset+2 > len(p.data) {
		return 0, ErrMalformed
	}
	value := uint16(p.data[p.offset])<<8 | uint16(p.data[p.offset+1])
	p.offset += 2
	return value, nil
}

func (p *parser) u32() (uint32, error) {
	if p.offset+4 > len(p.data) {
		return 0, ErrMalformed
	}
	value := uint32(p.data[p.offset])<<24 | uint32(p.data[p.offset+1])<<16 |
		uint32(p.data[p.offset+2])<<8 | uint32(p.data[p.offset+3])
	p.offset += 4
	return value, nil
}

func (p *parser) bytes(count int) ([]byte, error) {
	if count < 0 || p.offset+count > len(p.data) {
		return nil, ErrMalformed
	}
	value := p.data[p.offset : p.offset+count]
	p.offset += count
	return value, nil
}

// name reads a domain name, following compression pointers.
//
// The jump budget is what stops a crafted packet with a pointer loop from
// spinning forever - a real and well-known way to hang a naive DNS parser.
func (p *parser) name() (string, error) {
	return p.nameAt(p.offset, true)
}

func (p *parser) nameAt(start int, advance bool) (string, error) {
	labels := []string{}
	offset := start
	jumps := 0
	ended := false
	for {
		if offset >= len(p.data) {
			return "", ErrMalformed
		}
		length := int(p.data[offset])
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(p.data) {
				return "", ErrMalformed
			}
			pointer := (length&0x3F)<<8 | int(p.data[offset+1])
			if !ended && advance {
				p.offset = offset + 2
				ended = true
			}
			jumps++
			if jumps > 16 || pointer >= len(p.data) || pointer == offset {
				return "", ErrMalformed
			}
			offset = pointer
			continue
		}
		if length == 0 {
			if !ended && advance {
				p.offset = offset + 1
			}
			break
		}
		if length > 63 || offset+1+length > len(p.data) {
			return "", ErrMalformed
		}
		labels = append(labels, string(p.data[offset+1:offset+1+length]))
		offset += 1 + length
	}
	if len(labels) == 0 {
		return ".", nil
	}
	return strings.Join(labels, ".") + ".", nil
}

// ParseInstances reads the announcements in a response packet.
//
// Unparseable records are skipped rather than failing the whole packet: a
// household network carries other mDNS traffic, and one unfamiliar record must
// not blind Core to a Node in the same response.
func ParseInstances(packet []byte) ([]Instance, error) {
	p := &parser{data: packet}
	if _, err := p.u16(); err != nil { // transaction id
		return nil, err
	}
	flags, err := p.u16()
	if err != nil {
		return nil, err
	}
	if flags&0x8000 == 0 {
		// A query, not a response.
		return nil, nil
	}
	questions, err := p.u16()
	if err != nil {
		return nil, err
	}
	answers, err := p.u16()
	if err != nil {
		return nil, err
	}
	authority, err := p.u16()
	if err != nil {
		return nil, err
	}
	additional, err := p.u16()
	if err != nil {
		return nil, err
	}
	for i := 0; i < int(questions); i++ {
		if _, err := p.name(); err != nil {
			return nil, err
		}
		if _, err := p.u16(); err != nil {
			return nil, err
		}
		if _, err := p.u16(); err != nil {
			return nil, err
		}
	}

	type partial struct {
		instance Instance
		host     string
	}
	instances := map[string]*partial{}
	addresses := map[string][]net.IP{}
	order := []string{}

	total := int(answers) + int(authority) + int(additional)
	for i := 0; i < total; i++ {
		name, err := p.name()
		if err != nil {
			return nil, err
		}
		recordType, err := p.u16()
		if err != nil {
			return nil, err
		}
		if _, err := p.u16(); err != nil { // class, cache-flush bit included
			return nil, err
		}
		if _, err := p.u32(); err != nil { // ttl
			return nil, err
		}
		length, err := p.u16()
		if err != nil {
			return nil, err
		}
		start := p.offset
		body, err := p.bytes(int(length))
		if err != nil {
			return nil, err
		}

		switch recordType {
		case typePTR:
			if !strings.EqualFold(name, ServiceType) {
				continue
			}
			target, err := p.nameAt(start, false)
			if err != nil {
				continue
			}
			if _, exists := instances[target]; !exists {
				instances[target] = &partial{instance: Instance{
					InstanceName: strings.TrimSuffix(target, "."+ServiceType),
					TXT:          map[string]string{},
				}}
				order = append(order, target)
			}
		case typeSRV:
			// Only records under our own service type may create a candidate. A
			// household network carries SRV and TXT records for printers,
			// speakers and everything else, and without this check any of them
			// would be offered to the user as a Node.
			if !belongsToService(name) {
				continue
			}
			if len(body) < 7 {
				continue
			}
			port := uint16(body[4])<<8 | uint16(body[5])
			host, err := p.nameAt(start+6, false)
			if err != nil {
				continue
			}
			entry, exists := instances[name]
			if !exists {
				entry = &partial{instance: Instance{
					InstanceName: strings.TrimSuffix(name, "."+ServiceType),
					TXT:          map[string]string{},
				}}
				instances[name] = entry
				order = append(order, name)
			}
			entry.instance.Port = port
			entry.instance.Host = host
			entry.host = host
		case typeTXT:
			if !belongsToService(name) {
				continue
			}
			entry, exists := instances[name]
			if !exists {
				entry = &partial{instance: Instance{
					InstanceName: strings.TrimSuffix(name, "."+ServiceType),
					TXT:          map[string]string{},
				}}
				instances[name] = entry
				order = append(order, name)
			}
			for key, value := range parseTXT(body) {
				entry.instance.TXT[key] = value
			}
		case typeA:
			if len(body) == 4 {
				addresses[name] = append(addresses[name], net.IP(append([]byte{}, body...)))
			}
		case typeAAAA:
			if len(body) == 16 {
				addresses[name] = append(addresses[name], net.IP(append([]byte{}, body...)))
			}
		}
	}

	result := make([]Instance, 0, len(order))
	for _, key := range order {
		entry := instances[key]
		if entry.host != "" {
			entry.instance.Addresses = append(entry.instance.Addresses, addresses[entry.host]...)
		}
		result = append(result, entry.instance)
	}
	return result, nil
}

// belongsToService reports whether a record name sits under the Node service.
func belongsToService(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(ServiceType))
}

func parseTXT(body []byte) map[string]string {
	values := map[string]string{}
	offset := 0
	for offset < len(body) {
		length := int(body[offset])
		offset++
		if length == 0 || offset+length > len(body) {
			break
		}
		entry := string(body[offset : offset+length])
		offset += length
		key, value, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		values[key] = value
	}
	return values
}

// IsQuery reports whether a packet is a browse query for the Node service.
func IsQuery(packet []byte) bool {
	p := &parser{data: packet}
	if _, err := p.u16(); err != nil {
		return false
	}
	flags, err := p.u16()
	if err != nil || flags&0x8000 != 0 {
		return false
	}
	questions, err := p.u16()
	if err != nil || questions == 0 {
		return false
	}
	for i := 0; i < 3; i++ {
		if _, err := p.u16(); err != nil {
			return false
		}
	}
	name, err := p.name()
	if err != nil {
		return false
	}
	recordType, err := p.u16()
	if err != nil {
		return false
	}
	return strings.EqualFold(name, ServiceType) && (recordType == typePTR || recordType == 255)
}
