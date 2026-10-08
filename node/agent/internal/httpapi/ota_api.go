package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/human-agent65535/nassimhub-node/agent/ota"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// Updates is the part of the update service this handler needs.
//
// An interface so the handler does not depend on how releases are stored, and
// so a test can stand in a service that records what it was asked.
type Updates interface {
	Status() proto.OTADeviceStatus
	Offer(ctx context.Context, signed proto.OTASignedManifest) (proto.OTAOfferResponse, error)
	Receive(ctx context.Context, releaseID string, offset int64, body io.Reader) (proto.OTADeviceStatus, error)
	Apply(ctx context.Context, releaseID string) (proto.OTADeviceStatus, error)
	Confirm(releaseID string) (proto.OTADeviceStatus, error)
	Rollback(ctx context.Context, releaseID string) (proto.OTADeviceStatus, error)
}

// The update endpoints.
//
// They let the paired Core carry a release to the device. They do not let it
// decide what the device runs: every byte is checked against a manifest, and
// the manifest against release keys the Core has no way to change. The worst a
// Core can do through these endpoints - malicious, compromised, or simply
// handed a bad file - is make the device do some work and then refuse.
//
// Three properties are enforced here rather than further in:
//
//   - Bounded bodies. The manifest is small and capped; the artifact is capped
//     at what a release may be, before the first byte is read.
//   - No paths. Nothing in a request names a file. The release is named by an
//     id that is validated as an id.
//   - Nothing is logged that came from the body, beyond the release id after
//     it has been validated.

func (h *handler) otaUnavailable(w http.ResponseWriter, operation string) bool {
	if h.updates != nil {
		return false
	}
	h.writeAPIError(w, proto.ErrorNotSupported, operation, "", "this node has no update service")
	return true
}

func (h *handler) getOTAStatus(w http.ResponseWriter, _ *http.Request) {
	if h.otaUnavailable(w, "ota_status") {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	h.writeJSON(w, http.StatusOK, h.updates.Status())
}

func (h *handler) postOTAManifest(w http.ResponseWriter, r *http.Request) {
	const operation = "ota_offer"
	if h.otaUnavailable(w, operation) {
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "content type must be application/json")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, proto.OTAMaxManifestBytes))
	if err != nil {
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "manifest is too large or could not be read")
		return
	}
	var signed proto.OTASignedManifest
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil || len(signed.Manifest) == 0 {
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "request is not a signed manifest")
		return
	}
	response, err := h.updates.Offer(r.Context(), signed)
	if err != nil {
		h.logs.Warnf("ota", "an offered update was not accepted: %s", otaLogReason(err))
		h.writeOTAError(w, operation, err)
		return
	}
	h.logs.Infof("ota", "update %s (%s) accepted for transfer", response.Manifest.ReleaseID, response.Manifest.Version)
	h.writeJSON(w, http.StatusOK, response)
}

func (h *handler) putOTAArtifact(w http.ResponseWriter, r *http.Request) {
	const operation = "ota_artifact"
	if h.otaUnavailable(w, operation) {
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "content type must be application/octet-stream")
		return
	}
	releaseID := strings.TrimSpace(r.Header.Get(proto.HeaderOTARelease))
	if proto.ValidateOTAReleaseID(releaseID) != nil {
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "a valid release id is required")
		return
	}
	offset, err := strconv.ParseInt(strings.TrimSpace(r.Header.Get(proto.HeaderOTAOffset)), 10, 64)
	if err != nil || offset < 0 || offset > proto.OTAMaxArtifactBytes {
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "a valid upload offset is required")
		return
	}
	if r.ContentLength > proto.OTAMaxArtifactBytes {
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "the artifact is larger than this device accepts")
		return
	}
	// The cap holds for a body with no declared length too.
	body := http.MaxBytesReader(w, r.Body, proto.OTAMaxArtifactBytes+1)
	status, err := h.updates.Receive(r.Context(), releaseID, offset, body)
	if err != nil {
		if errors.Is(err, ota.ErrOffset) {
			// Not a failure of the transfer: the Core is out of step. The
			// answer carries where the device actually is, so the Core can
			// resume from there without a second request.
			w.Header().Set(proto.HeaderOTAOffset, strconv.FormatInt(status.ReceivedBytes, 10))
		}
		h.writeOTAError(w, operation, err)
		return
	}
	if status.State == proto.OTAReady {
		h.logs.Infof("ota", "update %s staged and validated", releaseID)
	}
	h.writeJSON(w, http.StatusOK, status)
}

func (h *handler) otaRelease(w http.ResponseWriter, r *http.Request, operation string) (string, bool) {
	var request proto.OTAReleaseRequest
	if !h.decode(w, r, operation, &request) {
		return "", false
	}
	releaseID := strings.TrimSpace(request.ReleaseID)
	if proto.ValidateOTAReleaseID(releaseID) != nil {
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "a valid release id is required")
		return "", false
	}
	return releaseID, true
}

func (h *handler) postOTAApply(w http.ResponseWriter, r *http.Request) {
	const operation = "ota_apply"
	if h.otaUnavailable(w, operation) {
		return
	}
	releaseID, ok := h.otaRelease(w, r, operation)
	if !ok {
		return
	}
	status, err := h.updates.Apply(r.Context(), releaseID)
	if err != nil {
		h.writeOTAError(w, operation, err)
		return
	}
	h.logs.Warnf("ota", "update %s applied; the agent will restart", releaseID)
	h.writeJSON(w, http.StatusAccepted, status)
}

func (h *handler) postOTAConfirm(w http.ResponseWriter, r *http.Request) {
	const operation = "ota_confirm"
	if h.otaUnavailable(w, operation) {
		return
	}
	releaseID, ok := h.otaRelease(w, r, operation)
	if !ok {
		return
	}
	status, err := h.updates.Confirm(releaseID)
	if err != nil {
		h.writeOTAError(w, operation, err)
		return
	}
	h.logs.Infof("ota", "update %s confirmed", releaseID)
	h.writeJSON(w, http.StatusOK, status)
}

func (h *handler) postOTARollback(w http.ResponseWriter, r *http.Request) {
	const operation = "ota_rollback"
	if h.otaUnavailable(w, operation) {
		return
	}
	releaseID, ok := h.otaRelease(w, r, operation)
	if !ok {
		return
	}
	status, err := h.updates.Rollback(r.Context(), releaseID)
	if err != nil {
		h.writeOTAError(w, operation, err)
		return
	}
	h.logs.Warnf("ota", "update %s rolled back on request; the agent will restart", releaseID)
	h.writeJSON(w, http.StatusAccepted, status)
}

// writeOTAError maps update failures to codes a Core can act on.
//
// The message for a verification failure says which check failed and no more.
// It never carries a path, and it never repeats bytes from the request.
func (h *handler) writeOTAError(w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, ota.ErrUnsupported):
		h.writeAPIError(w, proto.ErrorNotSupported, operation, "", err.Error())
	case errors.Is(err, ota.ErrNoOffer):
		h.writeAPIError(w, proto.ErrorNotFound, operation, "", "no such release has been offered to this device")
	case errors.Is(err, ota.ErrOffset):
		h.writeAPIError(w, proto.ErrorConflict, operation, "", "upload offset does not match the bytes already received")
	case errors.Is(err, ota.ErrTooLarge):
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "the artifact is larger than this device accepts or than its manifest declares")
	case errors.Is(err, ota.ErrNoSpace):
		h.writeAPIError(w, proto.ErrorFailedPrecondition, operation, "", "not enough free space on the device to stage the update")
	case errors.Is(err, ota.ErrPending):
		h.writeAPIError(w, proto.ErrorConflict, operation, "", "an applied update is awaiting confirmation; confirm it or roll it back first")
	case errors.Is(err, ota.ErrBusy):
		h.writeAPIError(w, proto.ErrorConflict, operation, "", "an update operation is already in progress")
	case errors.Is(err, proto.ErrOTAPQUnavailable):
		h.writeAPIError(w, proto.ErrorPermissionDenied, operation, "", "this device cannot verify the post-quantum signature its policy requires")
	case errors.Is(err, proto.ErrOTAPQUnsigned):
		h.writeAPIError(w, proto.ErrorPermissionDenied, operation, "", "the update's post-quantum signature is missing or not valid")
	case errors.Is(err, proto.ErrOTAUnsigned):
		h.writeAPIError(w, proto.ErrorPermissionDenied, operation, "", "the update is not signed by a release key this device trusts")
	case errors.Is(err, proto.ErrOTAHash):
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "the artifact does not match its manifest")
	case errors.Is(err, proto.ErrOTARejected):
		h.writeAPIError(w, proto.ErrorFailedPrecondition, operation, "", otaRejection(err))
	case errors.Is(err, ota.ErrNotReady):
		h.writeAPIError(w, proto.ErrorFailedPrecondition, operation, "", "the update is not in a state that allows this")
	default:
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "the artifact is larger than this device accepts")
			return
		}
		if strings.Contains(err.Error(), "upload interrupted") {
			h.writeAPIError(w, proto.ErrorUnavailable, operation, "", "the upload was interrupted; resume from the received offset")
			return
		}
		h.logs.Errorf("ota", "%s failed: %v", operation, err)
		h.writeAPIError(w, proto.ErrorFailedPrecondition, operation, "", "the update could not be staged or validated on this device")
	}
}

// otaRejection passes on why a verified manifest does not apply to this
// device. Those messages are written by proto.CheckManifest from the manifest's
// own fields and the device's version; they are safe to show.
func otaRejection(err error) string {
	message := err.Error()
	if len(message) > 240 {
		message = message[:240]
	}
	return message
}

// otaLogReason is the same, for the log.
func otaLogReason(err error) string { return otaRejection(err) }
