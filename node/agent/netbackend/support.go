package netbackend

import (
	"strings"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// SupportFor says what is known about joining a network of this kind from the
// UFI003, and why.
//
// It reports evidence, not a guess about the chipset. What has been joined on
// the real device is 2.4 GHz with WPA2-PSK and with WPA2/WPA3 mixed mode;
// everything else is marked rather than hidden, because a list that omitted a
// network would read as "the device cannot see it", which is a different and
// false statement.
//
// channel 0 means the backend did not learn the channel. enterprise is true
// when the network uses 802.1X, which the connect request has no fields for.
func SupportFor(security proto.WiFiSecurity, channel int, enterprise bool) (proto.WiFiSupport, string) {
	if enterprise {
		return proto.WiFiSupportUnsupported, "802.1X (enterprise) networks need an identity or certificate, which this device cannot be given"
	}
	var doubts []string
	switch security {
	case proto.WiFiSecurityWPA2:
	case proto.WiFiSecurityWPA3:
		doubts = append(doubts, "WPA3-only (SAE) has not been verified on this hardware")
	case proto.WiFiSecurityOpen:
		doubts = append(doubts, "open networks have not been verified on this hardware")
	default:
		doubts = append(doubts, "the security type was not recognised")
	}
	switch {
	case channel >= 1 && channel <= 14:
	case channel > 14:
		doubts = append(doubts, "5 GHz has not been verified on this hardware")
	default:
		doubts = append(doubts, "the band is unknown")
	}
	if len(doubts) > 0 {
		return proto.WiFiSupportUnverified, strings.Join(doubts, "; ")
	}
	return proto.WiFiSupportVerified, "2.4 GHz with WPA2, or WPA2/WPA3 mixed mode joined as WPA2"
}
