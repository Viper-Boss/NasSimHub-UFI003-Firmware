package networkmanager

import (
	"context"
	"github.com/human-agent65535/nassimhub-node/proto"
	"strings"
	"testing"
)

func TestScanTransitionNetworkChoosesCompatibleWPA2AndKeepsPureWPA3(t *testing.T) {
	backend := New(Options{Run: func(context.Context, ...string) (string, error) {
		return "Cat home:100:WPA2 WPA3:1\nPure:90:WPA3:6\n", nil
	}})
	result, err := backend.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Networks) != 2 || result.Networks[0].SSID != "Cat home" || result.Networks[0].Security != proto.WiFiSecurityWPA2 || result.Networks[1].Security != proto.WiFiSecurityWPA3 {
		t.Fatal("transition mode was mistaken for mandatory SAE", result.Networks)
	}
}

func TestConnectionUsesPSKForTransitionAndDoesNotDowngradeExplicitWPA3(t *testing.T) {
	for _, tc := range []struct{ raw, key string }{{"WPA2 WPA3", "wpa-psk"}, {"WPA3", "sae"}} {
		t.Run(tc.raw, func(t *testing.T) {
			key := ""
			backend := New(Options{StateDir: t.TempDir(), Run: func(_ context.Context, args ...string) (string, error) {
				for i, a := range args {
					if a == "802-11-wireless-security.key-mgmt" && i+1 < len(args) {
						key = args[i+1]
					}
				}
				if strings.Contains(strings.Join(args, " "), "sae") && tc.raw == "WPA2 WPA3" {
					t.Fatal("transition profile forced SAE")
				}
				return "", nil
			}})
			backend.connect(context.Background(), "Example", "synthetic-only-password", classifySecurity(tc.raw))
			if key != tc.key {
				t.Fatal("incorrect key management", key)
			}
		})
	}
}
