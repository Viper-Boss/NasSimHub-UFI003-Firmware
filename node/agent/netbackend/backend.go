// Package netbackend defines the Node's Wi-Fi abstraction.
//
// The interface is deliberately narrow and deliberately says nothing about
// hostapd, wpa_supplicant, NetworkManager or systemd-networkd. Those are
// implementation details of a real device, and wiring them into the protocol
// would mean the whole system had to change the day the device's network stack
// changed. Everything above this interface works in terms of a state machine
// and an SSID.
package netbackend

import (
	"context"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// Backend drives the Node's Wi-Fi station and its provisioning access point.
//
// The contract the implementation must honour, and which the mock encodes:
//
//   - With no saved network the Node is in PROVISIONING_AP, serving a
//     configuration page, so a user can always reach it.
//   - Connect moves through CONNECTING to CONNECTED or FAILED.
//   - A FAILED attempt does not strand the device: after a bounded recovery
//     window the Node returns to PROVISIONING_AP on its own.
//   - Forget clears the saved network and returns to PROVISIONING_AP.
//
// That last property is why no recovery gesture is bound to the UFI003 power
// button: the software path always leads back to a reachable access point, so
// the button never needs to, and the button's existing long-press behaviour
// (Qualcomm 9008/EDL) stays untouched.
type Backend interface {
	// Name identifies the implementation for diagnostics.
	Name() string

	// Status is the current Wi-Fi state. It never contains a credential.
	Status(ctx context.Context) (proto.WiFiStatus, error)

	// Scan lists visible networks.
	Scan(ctx context.Context) (proto.WiFiScanResult, error)

	// Connect saves a network and attempts to join it. The PSK is consumed
	// here and must not be retrievable through any other method.
	Connect(ctx context.Context, request proto.WiFiConnectRequest) (proto.WiFiStatus, error)

	// Forget clears the saved network and returns to provisioning.
	Forget(ctx context.Context) (proto.WiFiStatus, error)

	// Close releases whatever the backend owns.
	Close() error
}
