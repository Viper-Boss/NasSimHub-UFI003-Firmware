package localadmin_test

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"github.com/human-agent65535/nassimhub-node/agent/internal/pairing"
	"github.com/human-agent65535/nassimhub-node/agent/modembackend/mock"
	netmock "github.com/human-agent65535/nassimhub-node/agent/netbackend/mock"
	"github.com/human-agent65535/nassimhub-node/agent/nodeserver"
	"github.com/human-agent65535/nassimhub-node/proto"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestManagementProofRequiresCurrentPairedCoreAndTLS(t *testing.T) {
	modem := mock.New(mock.Options{Scenario: mock.ChinaTelecom})
	defer modem.Close()
	network := netmock.New(netmock.Options{})
	defer network.Close()
	node, err := nodeserver.New(nodeserver.Options{StateDir: t.TempDir(), Platform: proto.PlatformMock, Modem: modem, Network: network, EnableTLS: true, EnableLocalAdmin: true, AdminListen: "127.0.0.1:7581"})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Logs.Close()
	request := func(token string, secured bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://device.test/v1/admin/access", strings.NewReader("{}"))
		r.TLS = nil
		if secured {
			r.TLS = &tls.ConnectionState{}
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		node.Handler().ServeHTTP(w, r)
		return w
	}
	if w := request("", true); w.Code != 401 {
		t.Fatal("unauthenticated access", w.Code)
	}
	if w := request("forged", true); w.Code < 400 {
		t.Fatal("unpaired access accepted")
	}
	public, private, _ := ed25519.GenerateKey(nil)
	body := proto.PairRequest{CoreID: "owner", CoreName: "test", CorePublicKey: proto.EncodeKey(public)}
	raw, _ := json.Marshal(body)
	stamp := proto.FormatTimestamp(time.Now())
	nonce := "unique-owner-pair"
	signed := pairing.SignedRequest{CoreID: body.CoreID, Method: "POST", Path: "/v1/pair", Body: raw, Timestamp: stamp, Nonce: nonce, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, proto.SigningString("POST", "/v1/pair", stamp, nonce, raw)))}
	session, err := node.Pairing.Pair(body, signed)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(session.Token, false); w.Code != 403 {
		t.Fatal("proof over plaintext", w.Code)
	}
	w := request(session.Token, true)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("paired owner access", w.Code)
	}
	var result struct {
		Configured bool
		SetupCode  string `json:"setup_code"`
		Port       int
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Configured || len(result.SetupCode) != 43 || result.Port != 7581 {
		t.Fatal("invalid owner setup result")
	}
	if _, err = node.Pairing.Unpair(); err != nil {
		t.Fatal(err)
	}
	if w := request(session.Token, true); w.Code < 400 {
		t.Fatal("former Core retained management access")
	}
}
