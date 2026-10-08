package nodeserver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/internal/httpapi"
	"github.com/human-agent65535/nassimhub-node/agent/internal/identity"
	"github.com/human-agent65535/nassimhub-node/agent/internal/localadmin"
	"github.com/human-agent65535/nassimhub-node/agent/internal/logbuf"
	"github.com/human-agent65535/nassimhub-node/agent/internal/pairing"
	"github.com/human-agent65535/nassimhub-node/agent/internal/pqidentity"
 "github.com/human-agent65535/nassimhub-node/agent/internal/systemadmin"
	"github.com/human-agent65535/nassimhub-node/agent/netbackend"
	"github.com/human-agent65535/nassimhub-node/agent/nodetls"
	"github.com/human-agent65535/nassimhub-node/agent/ota"
	"github.com/human-agent65535/nassimhub-node/agent/trust"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// AdminHandler is the independent browser console. It never serves the Core
// protocol, whose original identity, certificate and listener remain separate.
func (s *Server) AdminHandler() http.Handler { return s.adminHandler }
func (s *Server) AdminAddress() string       { return s.adminAddress }
func (s *Server) startAdmin() error {
	if s.adminHandler == nil {
		return nil
	}
	config, err := nodetls.SecureServerConfig(*s.adminCertificate, s.options.PQProfile, s.options.PQPolicy)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", s.options.AdminListen)
	if err != nil {
		return fmt.Errorf("listen for administration: %w", err)
	}
	s.adminAddress = listener.Addr().String()
	server := &http.Server{Handler: s.adminHandler, TLSConfig: config, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	s.servers = append(s.servers, server)
	go func() {
		if err := server.Serve(tls.NewListener(listener, config)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.Logs.Errorf("admin", "management listener stopped: %v", err)
		}
	}()
	s.Logs.Infof("admin", "local management ready on %s", s.adminAddress)
	return nil
}

// adminSources adapts the agent's own state to what the console displays.
//
// This is the only place the console's pages meet the identity, pairing and
// update packages, and it hands over digests, names and states: the console
// package never holds a key, public or private, so it has none to serve.
func adminSources(loaded *identity.Identity, pairs *pairing.Store, postQuantum *pqidentity.Store,
	level proto.SecurityLevel, policy proto.PQIdentityPolicy, certificate *tls.Certificate,
	updates httpapi.Updates, network netbackend.Backend, logs *logbuf.Buffer) localadmin.Sources {
	sources := localadmin.Sources{
  System: systemadmin.Client{},
		Security: func() localadmin.SecurityReport {
			return adminSecurity(loaded, pairs, postQuantum, level, policy, certificate)
		},
		// Warn, so that sign-in lockouts and password changes reach a
		// diagnostics bundle, which carries warnings and above.
		Logf: func(format string, arguments ...any) { logs.Warnf("admin", format, arguments...) },
	}
	// Assigned only when there is one: a nil service wrapped in an adapter
	// would look like a service, and the page would offer what cannot work.
	if updates != nil {
		sources.Updates = adminUpdates{updates}
	}
	if network != nil {
		sources.WiFi = network
		// Only a backend that runs a password-protected setup access point
		// has a credential. The console shows it to a signed-in owner who
		// re-enters the management password, and to nobody else.
		if credentials, ok := network.(netbackend.SetupAPCredentialSource); ok {
			sources.SetupAP = credentials
		}
	}
	return sources
}

// adminSecurity is read on every request rather than once, because pairing
// changes while the agent runs and a page showing last hour's owner would be
// a stale fact presented as current.
func adminSecurity(loaded *identity.Identity, pairs *pairing.Store, postQuantum *pqidentity.Store,
	level proto.SecurityLevel, policy proto.PQIdentityPolicy, certificate *tls.Certificate) localadmin.SecurityReport {
	report := localadmin.SecurityReport{SecurityLevel: string(level)}
	if loaded != nil {
		report.DeviceID = loaded.DeviceID
		report.IdentityAlgorithm = "Ed25519"
		report.IdentityFingerprint = groupedFingerprint(loaded.PublicKey)
	}
	report.PQIdentity = localadmin.PQIdentityReport{Policy: string(policy)}
	if postQuantum != nil {
		// A nil store is not "unavailable in this build": nothing was asked.
		report.PQIdentity.Status = string(postQuantum.Status())
		report.PQIdentity.Detail = postQuantum.Detail()
		if current := postQuantum.Identity(); current.Present() {
			report.PQIdentity.Algorithm = string(current.Algorithm)
			report.PQIdentity.Fingerprint = pqFingerprint(current)
		}
	}
	if pairs != nil {
		coreID, key, corePQ, paired := pairs.Owner()
		report.Owner.Paired, report.Owner.PQPinned = "no", "no"
		if paired {
			report.Owner.Paired = "yes"
			report.Owner.CoreID = coreID
			report.Owner.CoreFingerprint = proto.CoreFingerprint(key)
			if corePQ.Present() {
				report.Owner.PQPinned = "yes"
				report.Owner.PQAlgorithm = string(corePQ.Algorithm)
				report.Owner.PQFingerprint = pqFingerprint(corePQ)
			}
		}
	}
	if certificate != nil && len(certificate.Certificate) > 0 {
		digest := sha256.Sum256(certificate.Certificate[0])
		pairsOfHex := make([]string, 0, len(digest))
		for _, b := range digest {
			pairsOfHex = append(pairsOfHex, strings.ToUpper(hex.EncodeToString([]byte{b})))
		}
		// The form a browser shows in its certificate viewer.
		report.AdminTLS.FingerprintSHA256 = strings.Join(pairsOfHex, ":")
		if leaf, err := x509.ParseCertificate(certificate.Certificate[0]); err == nil {
			notBefore, notAfter := leaf.NotBefore.UTC(), leaf.NotAfter.UTC()
			report.AdminTLS.NotBefore, report.AdminTLS.NotAfter = &notBefore, &notAfter
			report.AdminTLS.KeyAlgorithm = leaf.PublicKeyAlgorithm.String()
		}
	}
	return report
}

// adminTrust adapts the trust gate to the console's read-only page. The page
// is given states and a reason; the policy's device and core ids are not
// passed on, and there is no function here through which the console could
// install, change or clear a policy.
func adminTrust(gate *trust.Gate) func() localadmin.TrustReport {
	return func() localadmin.TrustReport {
		if gate == nil {
			return localadmin.TrustReport{Supported: false}
		}
		status := gate.Status()
		report := localadmin.TrustReport{
			Supported: true, Installed: status.Installed, State: string(status.State), Mode: string(status.Mode),
			Reason: status.Reason, Generation: status.Generation, ExpiresAt: status.ExpiresAt,
			Stale: status.Stale, Freshness: string(status.Freshness), Damaged: status.Damaged, Enforcing: status.Enforcing, Deny: []string{},
		}
		for _, action := range status.Deny {
			report.Deny = append(report.Deny, string(action))
		}
		return report
	}
}

// adminRequireSendSMS is the console's use of the SAME gate the Core protocol
// handler uses. Check is consulted first so that a message that is allowed is
// counted once, by the handler it is forwarded to; a refusal is recorded here.
func adminRequireSendSMS(gate *trust.Gate) func() *localadmin.TrustRefusal {
	return func() *localadmin.TrustRefusal {
		if gate.Check(proto.TrustActionSendSMS) == nil {
			return nil
		}
		var refusal *trust.Refusal
		if !errors.As(gate.Require(proto.TrustActionSendSMS), &refusal) {
			return nil // the policy changed between the two calls and now allows it
		}
		return &localadmin.TrustRefusal{State: string(refusal.State), Reason: refusal.Reason,
			Denied: refusal.Denied, Stale: refusal.Stale, Damaged: refusal.Damaged, Freshness: string(refusal.Freshness)}
	}
}

// groupedFingerprint is the form the NAS shows for a device key: the first 16
// bytes of SHA-256, in groups of four hex digits. Matching it is the point -
// the owner compares the two by eye.
func groupedFingerprint(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	digest := sha256.Sum256(key)
	encoded := strings.ToUpper(hex.EncodeToString(digest[:16]))
	groups := make([]string, 0, 8)
	for index := 0; index < len(encoded); index += 4 {
		groups = append(groups, encoded[index:index+4])
	}
	return strings.Join(groups, " ")
}

func pqFingerprint(current proto.PQIdentity) string {
	raw, err := base64.StdEncoding.DecodeString(current.PublicKey)
	if err != nil {
		return ""
	}
	return groupedFingerprint(raw)
}

// adminUpdates narrows the update service to reading and rolling back, and
// translates its refusals into the console's own.
type adminUpdates struct{ service httpapi.Updates }

func (u adminUpdates) Status() proto.OTADeviceStatus { return u.service.Status() }
func (u adminUpdates) Rollback(ctx context.Context, releaseID string) (proto.OTADeviceStatus, error) {
	status, err := u.service.Rollback(ctx, releaseID)
	switch {
	case err == nil:
		return status, nil
	case errors.Is(err, ota.ErrUnsupported):
		return status, fmt.Errorf("%w: %v", localadmin.ErrUpdateUnsupported, err)
	case errors.Is(err, ota.ErrNoOffer):
		return status, fmt.Errorf("%w: %v", localadmin.ErrUpdateNoRelease, err)
	case errors.Is(err, ota.ErrNotReady):
		return status, fmt.Errorf("%w: %v", localadmin.ErrUpdateNotPending, err)
	case errors.Is(err, ota.ErrBusy):
		return status, fmt.Errorf("%w: %v", localadmin.ErrUpdateBusy, err)
	}
	return status, err
}
