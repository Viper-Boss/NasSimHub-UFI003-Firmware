package httpapi_test

import (
	"github.com/human-agent65535/nassimhub-node/agent/modembackend/mock"
	"github.com/human-agent65535/nassimhub-node/proto"
	"net/http"
	"testing"
)

func TestDTMFUsesAuthenticatedSessionAndDeviceTrustGate(t *testing.T) {
	n := newTrustNode(t, true)
	core := newCore(t, "dtmf-core")
	token := n.pair(core)
	n.mustPush(token, core, n.policy(core, 1, proto.TrustObservation, proto.TrustActionDTMF))
	response := n.auth(token, "POST", "/v1/calls/mm-7/dtmf", proto.DTMFRequest{RequestID: "blocked", Digits: "1"})
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", response.StatusCode)
	}
	response.Body.Close()
	if n.backend.tones.Load() != 0 {
		t.Fatal("refused tones reached backend")
	}
	n.mustPush(token, core, n.policy(core, 2, proto.TrustTrusted))
	response = n.auth(token, "POST", "/v1/calls/mm-7/dtmf", proto.DTMFRequest{RequestID: "allowed", Digits: "1"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	response.Body.Close()
	if n.backend.tones.Load() != 1 {
		t.Fatal("allowed request not forwarded exactly once")
	}
}

func TestDTMFAbsentBackendDoesNotPretendSupport(t *testing.T) {
	n := newNode(t, mock.ChinaUnicom)
	core := newCore(t, "legacy-dtmf")
	token := n.pair(core)
	response := n.auth(token, "POST", "/v1/calls/mm-7/dtmf", proto.DTMFRequest{RequestID: "legacy", Digits: "1"})
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status %d", response.StatusCode)
	}
}
