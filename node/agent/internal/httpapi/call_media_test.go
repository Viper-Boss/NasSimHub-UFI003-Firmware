package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/human-agent65535/nassimhub-node/agent/modembackend/mock"
	"github.com/human-agent65535/nassimhub-node/proto"
)

func TestCallMediaRejectsCleartextEvenWhenPaired(t *testing.T) {
	n := newNode(t, mock.ChinaMobile)
	token := n.pair(newCore(t, "media-core"))
	response := n.auth(token, http.MethodGet, "/v1/calls/mm-7/media", nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("cleartext media status = %d", response.StatusCode)
	}
	if code := errorBodyOf(t, response).Code; code != proto.ErrorFailedPrecondition {
		t.Fatalf("cleartext media code = %s", code)
	}
}
