package httpapi

import (
	"errors"
	"net/http"

	"github.com/human-agent65535/nassimhub-node/agent/trust"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// Device-local trust enforcement: the two endpoints, and the gate the handlers
// for outgoing use call. The rules are in agent/trust and proto/trustpolicy.go.
//
//	POST /v1/trust/policy   authenticated session AND a signed body
//	GET  /v1/trust          authenticated
//
// The session only decides who may TALK to these endpoints. What makes a
// policy acceptable is its own signature, checked against the owner key pinned
// at pairing; no header takes part in that decision.
//
// The standalone administration console is given neither route. It shows the
// state through its own read-only page and has no way to install, edit or
// clear a policy.

// registerTrust adds the endpoints when this Node enforces a policy. Without a
// gate they are not registered, so the answer is the same 404 an agent that
// predates them gives - which is what the Core reads as "does not enforce".
func (h *handler) registerTrust(mux *recordingMux) {
	if h.trust == nil {
		return
	}
	mux.HandleFunc("POST "+proto.TrustPolicyPath, h.authenticated(h.postTrustPolicy))
	mux.HandleFunc("GET "+proto.TrustStatusPath, h.authenticated(h.getTrust))
}

// requireTrust is the one gate in front of outgoing use. It is called at the
// top of a handler, before the request body is read and before any backend
// call, and it reports whether the handler may continue. A later handler for
// another outgoing action (DTMF) calls it the same way with its own action.
func (h *handler) requireTrust(w http.ResponseWriter, action proto.TrustAction, operation string) bool {
	err := h.trust.Require(action)
	if err == nil {
		return true
	}
	var refusal *trust.Refusal
	if errors.As(err, &refusal) {
		h.writeError(w, refusal.OperationError(operation))
		return false
	}
	// Require returns nothing else; if it ever does, the answer is still no.
	h.writeAPIError(w, proto.ErrorPermissionDenied, operation, "", "the trust policy could not be evaluated")
	return false
}

func (h *handler) trustStatus() proto.TrustStatus {
	status := h.trust.Status()
	if h.hardware != nil {
		status.Hardware = h.hardware()
	} else {
		status.Hardware = proto.HardwareIdentity{Present: false, Reason: "this build does not read a hardware identifier"}
	}
	return status
}

func (h *handler) getTrust(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	h.writeJSON(w, http.StatusOK, h.trustStatus())
}

func (h *handler) postTrustPolicy(w http.ResponseWriter, r *http.Request) {
	const operation = "trust_policy"
	body, err := readBody(w, r)
	if err != nil {
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", err.Error())
		return
	}
	switch err := h.trust.Install(body); {
	case err == nil:
	case errors.Is(err, proto.ErrTrustPolicyInvalid):
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "the trust policy is not a valid policy document")
		return
	case errors.Is(err, trust.ErrRollback):
		// Conflict, not a permission error: the document is genuine and older
		// than what is held. The Core reads the installed generation from
		// GET /v1/trust.
		h.writeAPIError(w, proto.ErrorConflict, operation, "", "a trust policy of the same or a newer generation is already installed")
		return
	case errors.Is(err, trust.ErrNotPaired):
		h.writeAPIError(w, proto.ErrorFailedPrecondition, operation, "", "node is not paired")
		return
	case errors.Is(err, proto.ErrTrustPolicyWrongDevice):
		h.writeAPIError(w, proto.ErrorPermissionDenied, operation, "", "the trust policy is for another device")
		return
	case errors.Is(err, proto.ErrTrustPolicyWrongCore):
		h.writeAPIError(w, proto.ErrorPermissionDenied, operation, "", "the trust policy is from a core that is not the paired owner")
		return
	case errors.Is(err, proto.ErrTrustPolicySignature):
		h.writeAPIError(w, proto.ErrorPermissionDenied, operation, "", "the trust policy is not signed by the paired owner")
		return
	case errors.Is(err, proto.ErrPQIdentityRequired), errors.Is(err, proto.ErrPQIdentityInvalid), errors.Is(err, proto.ErrPQIdentityMissing):
		h.writeAPIError(w, proto.ErrorPermissionDenied, operation, "", "the trust policy's post-quantum signature was not accepted")
		return
	default:
		h.logs.Errorf("trust", "a verified trust policy could not be stored: %v", err)
		h.writeAPIError(w, proto.ErrorInternal, operation, "", "the trust policy could not be stored")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	h.writeJSON(w, http.StatusOK, h.trustStatus())
}
