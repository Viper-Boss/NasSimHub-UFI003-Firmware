package proto

import (
	"fmt"
	"regexp"
)

// Delivering an agent update to a device over the pairing it already has.
//
// A Node on a USB cable frequently has no route to the internet, and a Node
// that does should not need one to be updated. So the owner's NAS carries the
// update to it: the NAS obtains a release however it likes (a release channel,
// a peer, a file the administrator picked) and pushes two things to the device
// over the authenticated Node protocol - the signed manifest, then the bytes.
//
// The NAS is a courier and nothing more. The device verifies the manifest
// against release keys installed on the device, verifies the bytes against the
// manifest, and executes them before trusting them. A NAS that has been
// compromised, or that was handed a bad file, can waste the device's time; it
// cannot install anything the release keys did not sign. That is the same
// division the manifest already draws between the download URL and the hash.
//
// The endpoints are additive (protocol 1.3). A device that does not have them
// answers 404, which a Core reports as "updates are not supported on this
// device" rather than as a failure.
//
//	GET  /v1/ota/status     where the update machine is, and what it can do
//	POST /v1/ota/manifest   offer a signed manifest; verify and decide
//	PUT  /v1/ota/artifact   send the artifact bytes, resumable by offset
//	POST /v1/ota/apply      switch to the validated release and restart
//	POST /v1/ota/confirm    the new agent works; keep it
//	POST /v1/ota/rollback   put the previous agent back
//
// Applying is always a separate, explicit request. Nothing in this protocol
// installs an update because it was offered.
const (
	OTAStatusPath   = "/v1/ota/status"
	OTAManifestPath = "/v1/ota/manifest"
	OTAArtifactPath = "/v1/ota/artifact"
	OTAApplyPath    = "/v1/ota/apply"
	OTAConfirmPath  = "/v1/ota/confirm"
	OTARollbackPath = "/v1/ota/rollback"
)

// OTAMaxArtifactBytes bounds an agent artifact.
//
// The device verifies the artifact in memory, inside a service limited to tens
// of megabytes, and stores two releases on a small flash. A static agent is
// around ten megabytes; a manifest asking for several times that is not an
// agent, and is refused before a byte is accepted.
const OTAMaxArtifactBytes = 32 << 20

// OTAMaxManifestBytes bounds a signed manifest, including an ML-DSA-87
// signature (about 6 kB once encoded).
const OTAMaxManifestBytes = 32 << 10

// Headers of the artifact upload.
const (
	// HeaderOTAOffset is the byte offset the request body starts at. It must
	// equal the number of bytes the device already holds for this release.
	HeaderOTAOffset = "X-NSH-OTA-Offset"
	// HeaderOTARelease names the release the bytes belong to, so bytes for one
	// release can never be appended to another.
	HeaderOTARelease = "X-NSH-OTA-Release"
)

var otaReleaseID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidateOTAReleaseID checks a release id before it is used as a directory
// name on the device. The two names the installer uses for its own links are
// refused, as is anything that could step out of the release directory.
func ValidateOTAReleaseID(id string) error {
	if !otaReleaseID.MatchString(id) || id == "current" || id == "previous" {
		return fmt.Errorf("%w: release id %q is not usable", ErrOTARejected, id)
	}
	return nil
}

// OTAKeyStatus says which release keys the device trusts, by count. The keys
// themselves are public and are still not echoed: the question a status page
// needs answered is "can this device verify an update at all".
type OTAKeyStatus struct {
	Classical   int `json:"classical"`
	PostQuantum int `json:"post_quantum"`
}

// OTADeviceStatus is what GET /v1/ota/status reports.
type OTADeviceStatus struct {
	OTAStatus
	// UnsupportedReason says why Supported is false: no release keys
	// installed, an installation that cannot be switched, a platform with no
	// installer. Empty when updates are supported.
	UnsupportedReason string `json:"unsupported_reason,omitempty"`
	// Signatures is the signature policy and what the last verified manifest
	// carried.
	Signatures OTASignatureCapability `json:"signatures"`
	// Keys counts the release keys installed.
	Keys OTAKeyStatus `json:"keys"`
	// ReceivedBytes and ExpectedBytes describe the artifact transfer for the
	// offered release. A Core resumes an interrupted upload from
	// ReceivedBytes.
	ReceivedBytes int64 `json:"received_bytes"`
	ExpectedBytes int64 `json:"expected_bytes"`
	// ActiveRelease is the installed release the running agent came from, or
	// empty when the factory agent is running. FactoryVersion is the agent
	// shipped in the system image, which is never replaced and is what the
	// device falls back to.
	ActiveRelease  string `json:"active_release,omitempty"`
	FactoryVersion string `json:"factory_version,omitempty"`
	// RestartPending is true between a successful apply and the restart that
	// makes it take effect.
	RestartPending bool `json:"restart_pending"`
}

// OTAOfferResponse answers POST /v1/ota/manifest.
type OTAOfferResponse struct {
	// Manifest is the verified manifest, decoded, so the Core shows the
	// administrator what the DEVICE accepted rather than what the Core sent.
	Manifest OTAManifest     `json:"manifest"`
	Status   OTADeviceStatus `json:"status"`
}

// OTAReleaseRequest names the release an action applies to. Requiring it makes
// "apply" mean "apply the release I was shown", not "apply whatever is staged
// by now".
type OTAReleaseRequest struct {
	ReleaseID string `json:"release_id"`
}
