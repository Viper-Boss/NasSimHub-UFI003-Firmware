package nodeserver

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/trust"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// The standalone console is told WHY a policy is stale, so that after a
// restart it says "the NAS has to confirm it again" and not "expired".
// Offline: a temporary directory and a throwaway key.
func TestConsoleIsToldWhyThePolicyIsStale(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 0x5a
	key := ed25519.NewKeyFromSeed(seed)
	const device, core = "node-fake-console", "core-fake-console"
	dir := t.TempDir()
	open := func() *trust.Gate {
		gate, err := trust.Open(trust.Options{Dir: dir, DeviceID: device, Owner: func() (string, ed25519.PublicKey, proto.PQIdentity, bool) {
			return core, key.Public().(ed25519.PublicKey), proto.PQIdentity{}, true
		}})
		if err != nil {
			t.Fatal(err)
		}
		return gate
	}
	now := time.Now()
	signed, err := proto.SignTrustPolicy(proto.TrustPolicy{Version: 1, DeviceID: device, CoreID: core, Generation: 1, State: proto.TrustTrusted,
		Mode: proto.TrustEnforce, Deny: []proto.TrustAction{}, Reason: "test reason",
		IssuedAt: proto.FormatTrustTime(now), ExpiresAt: proto.FormatTrustTime(now.Add(24 * time.Hour))}, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(signed)

	gate := open()
	if err := gate.Install(raw); err != nil {
		t.Fatal(err)
	}
	if report := adminTrust(gate)(); report.Freshness != "fresh" || report.Stale || !report.Installed {
		t.Fatalf("installed: %+v", report)
	}
	if refusal := adminRequireSendSMS(gate)(); refusal != nil {
		t.Fatalf("a fresh trusted policy allows the console's send: %+v", refusal)
	}

	gate = open() // the agent restarted
	if report := adminTrust(gate)(); report.Freshness != "stale_restart" || !report.Stale || report.Damaged || report.State != "TRUSTED" {
		t.Fatalf("after a restart: %+v", report)
	}
	refusal := adminRequireSendSMS(gate)()
	if refusal == nil || refusal.Denied || !refusal.Stale || refusal.Freshness != "stale_restart" {
		t.Fatalf("the console's send after a restart: %+v", refusal)
	}
	// The NAS connects and sends what it last signed.
	if err := gate.Install(raw); err != nil {
		t.Fatal(err)
	}
	if adminRequireSendSMS(gate)() != nil || adminTrust(gate)().Freshness != "fresh" {
		t.Fatal("the same policy from the owner must restore the console's send")
	}
}
