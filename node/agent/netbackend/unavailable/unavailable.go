package unavailable

import (
	"context"
	"github.com/human-agent65535/nassimhub-node/proto"
)

type Backend struct{}

func New() *Backend           { return &Backend{} }
func (*Backend) Name() string { return "hardware-wifi-not-implemented" }
func (*Backend) Close() error { return nil }
func err(op string) error {
	return proto.NotSupported(op, "Hardware Wi-Fi provisioning is not implemented; use owner SSH and NetworkManager")
}
func (*Backend) Status(context.Context) (proto.WiFiStatus, error) {
	return proto.WiFiStatus{}, err("wifi.status")
}
func (*Backend) Scan(context.Context) (proto.WiFiScanResult, error) {
	return proto.WiFiScanResult{}, err("wifi.scan")
}
func (*Backend) Connect(context.Context, proto.WiFiConnectRequest) (proto.WiFiStatus, error) {
	return proto.WiFiStatus{}, err("wifi.connect")
}
func (*Backend) Forget(context.Context) (proto.WiFiStatus, error) {
	return proto.WiFiStatus{}, err("wifi.forget")
}
