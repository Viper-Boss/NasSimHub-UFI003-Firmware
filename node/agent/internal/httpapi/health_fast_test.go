package httpapi_test

import (
	"context"
	"encoding/json"
	"github.com/human-agent65535/nassimhub-node/agent/internal/httpapi"
	"github.com/human-agent65535/nassimhub-node/agent/modembackend/mock"
	"github.com/human-agent65535/nassimhub-node/proto"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fastHealthModem struct{ *mock.Backend }

func (m *fastHealthModem) GetStatus(context.Context) (proto.ModemStatus, error) {
	panic("health must not collect expensive full modem status")
}
func (m *fastHealthModem) HealthState(context.Context) (proto.ModemState, error) {
	return proto.ModemReady, nil
}
func TestHealthUsesLightweightBackendQuery(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	h := httpapi.New(httpapi.Options{Identity: n.identity, Pairing: n.pairs, Modem: &fastHealthModem{n.modem}, Network: n.wifi, Logs: n.logs, AgentVersion: "test"})
	request := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	var health proto.Health
	if err := json.Unmarshal(response.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || health.Status != proto.HealthOK || health.ModemState != "ready" {
		t.Fatalf("health=%+v status=%d", health, response.Code)
	}
}
