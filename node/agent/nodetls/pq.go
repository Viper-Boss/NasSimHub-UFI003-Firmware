package nodetls

import (
	"crypto/tls"
	"fmt"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// The Node's side of post-quantum key agreement.
//
// A server's role in this is smaller than a client's and worth stating
// precisely: TLS 1.3 lets the CLIENT choose which group to propose, and the
// server either supports it or does not. So a Node cannot force a Core to use
// post-quantum - it can only refuse to do anything else.
//
// That is exactly what a REQUIRED policy does here: the server's
// CurvePreferences list only post-quantum groups, and a classical ClientHello
// gets a handshake failure from crypto/tls. There is no code that inspects a
// completed classical handshake and decides, which is what makes the refusal
// structural.
//
// A device's own policy is deliberately PREFERRED by default. A Node that
// required post-quantum would become unreachable from an older NAS the moment
// it was updated, and a device the owner cannot reach is worse than a session
// key that is merely as good as last year's.

// SecureServerConfig is ServerConfig with a post-quantum policy applied.
func SecureServerConfig(certificate tls.Certificate, profile proto.PQProfile, policy proto.PQPolicy) (*tls.Config, error) {
	if err := proto.ValidatePQProfile(profile); err != nil {
		return nil, err
	}
	if err := proto.ValidatePQPolicy(policy); err != nil {
		return nil, err
	}
	groups := proto.PQGroups(profile, policy)
	curves := make([]tls.CurveID, 0, len(groups))
	for _, group := range groups {
		// Only groups this build can actually perform. An unimplemented group
		// in the list makes crypto/tls refuse every connection locally, which
		// on a device in a cupboard is indistinguishable from a dead device.
		if proto.BuildSupportsGroup(group) {
			curves = append(curves, tls.CurveID(group))
		}
	}
	if len(curves) == 0 {
		return nil, fmt.Errorf("%w: this build implements none of the groups the %s profile needs",
			proto.ErrPQUnavailable, profile)
	}
	config := ServerConfig(certificate)
	config.CurvePreferences = curves
	return config, nil
}

// Supported reports what this build can offer, for the capability document.
func Supported() proto.SecurityCapability {
	return proto.SecurityCapability{
		PQSupported: proto.BuildSupportsGroup(proto.GroupX25519MLKEM768),
		// A server cannot know whether a given connection used post-quantum
		// without being told which connection is being asked about, so the
		// static capability says "unknown" and the per-connection answer comes
		// from Observe on a live state.
		PQActive:   proto.TriUnknown,
		Observable: proto.GroupObservable,
	}
}

// ObserveServer reports what one accepted connection negotiated.
func ObserveServer(state tls.ConnectionState, profile proto.PQProfile, policy proto.PQPolicy) proto.SecurityCapability {
	capability := Supported()
	capability.PQProfile = profile
	capability.PQPolicy = policy
	switch state.Version {
	case tls.VersionTLS13:
		capability.TLSVersion = "TLS 1.3"
	case tls.VersionTLS12:
		capability.TLSVersion = "TLS 1.2"
	}
	group, known := proto.NegotiatedGroup(state)
	if !known {
		return capability
	}
	capability.PQGroup = proto.GroupName(group)
	if proto.IsPQGroup(group) {
		capability.PQActive = proto.TriYes
	} else {
		capability.PQActive = proto.TriNo
	}
	return capability
}
