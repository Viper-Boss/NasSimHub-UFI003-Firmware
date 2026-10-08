package proto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The provisioning state and the support hint are additions. A document from a
// Node that does not know them must still decode, and a Node that has nothing
// to say must not emit them: an absent field is "unknown", and an empty string
// in its place would be read by a strict client as a state it has never heard of.
func TestWiFiAdditionsAreOptionalInBothDirections(t *testing.T) {
	var status WiFiStatus
	old := `{"state":"CONNECTED","ssid":"Example-Home","saved_ssid":"Example-Home","observed_at":"2026-01-01T00:00:00Z"}`
	if err := json.Unmarshal([]byte(old), &status); err != nil {
		t.Fatalf("a document without the new fields: %v", err)
	}
	if status.ProvisioningState != "" || status.ProvisioningReason != "" {
		t.Fatalf("absent fields decoded as %q / %q", status.ProvisioningState, status.ProvisioningReason)
	}
	encoded, err := json.Marshal(WiFiStatus{State: WiFiConnected, ObservedAt: time.Unix(0, 0).UTC()})
	if err != nil || strings.Contains(string(encoded), "provisioning") {
		t.Fatalf("a status with no provisioning evidence emitted one: %s %v", encoded, err)
	}
	encoded, _ = json.Marshal(WiFiStatus{State: WiFiNoConfig, ProvisioningState: WiFiProvisioningAPFailed, ProvisioningReason: "example reason"})
	if !strings.Contains(string(encoded), `"provisioning_state":"AP_FAILED"`) || !strings.Contains(string(encoded), `"provisioning_reason":"example reason"`) {
		t.Fatalf("status document: %s", encoded)
	}

	var scan WiFiScanResult
	if err := json.Unmarshal([]byte(`{"networks":[{"ssid":"Example-Home","signal_dbm":-60,"security":"wpa2","channel":6}],"scanned_at":"2026-01-01T00:00:00Z"}`), &scan); err != nil {
		t.Fatalf("a scan without hints: %v", err)
	}
	if scan.Networks[0].Support != "" || scan.FromCache {
		t.Fatalf("absent hints decoded as %q / %v", scan.Networks[0].Support, scan.FromCache)
	}
	encoded, _ = json.Marshal(scan)
	if strings.Contains(string(encoded), "support") || strings.Contains(string(encoded), "from_cache") {
		t.Fatalf("a scan with no hints emitted one: %s", encoded)
	}
	encoded, _ = json.Marshal(WiFiNetwork{SSID: "Example-5", Security: WiFiSecurityWPA2, Channel: 36, Support: WiFiSupportUnverified, SupportReason: "example"})
	if !strings.Contains(string(encoded), `"support":"unverified"`) || !strings.Contains(string(encoded), `"support_reason":"example"`) {
		t.Fatalf("network document: %s", encoded)
	}
}

// The status document has no field a credential could travel in.
func TestWiFiStatusHasNoCredentialField(t *testing.T) {
	encoded, _ := json.Marshal(WiFiStatus{State: WiFiProvisioningAP, SSID: "a", IPv4: "b", APSSID: "c", APAddress: "d",
		FailureReason: "e", SavedSSID: "f", ProvisioningState: WiFiProvisioningAPReady, ProvisioningReason: "g"})
	for _, word := range []string{"psk", "pass", "secret", "key"} {
		if strings.Contains(strings.ToLower(string(encoded)), word) {
			t.Fatalf("the status document has a %q field: %s", word, encoded)
		}
	}
}
