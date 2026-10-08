package proto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Over-the-air update: the wire contract.
//
// This generation updates ONE thing - the agent binary - and it is worth being
// explicit about what that excludes, because the exclusion is a safety property
// and not an oversight. No manifest in this schema can describe a boot image, a
// device tree, a modem firmware blob, or a root filesystem. There is no artifact
// kind for them, so a manifest asking for one does not parse; an installer that
// grew the ability to write them would be writing something no manifest can
// legitimately request.
//
// The reason is the target hardware. A UFI003 that fails a rootfs update is a
// device the owner recovers with a Qualcomm 9008 cable, and a device whose modem
// partition is damaged may not be recoverable at all. An agent binary that fails
// to start, by contrast, is recovered by the supervisor putting the previous one
// back - which is what the rollback state machine below exists to do.
//
// Three checks stand between a manifest and an installed binary, and each one
// answers a different question:
//
//	signature   did the people who publish releases author this manifest?
//	hash        are these bytes the bytes that manifest describes?
//	version     is installing them a sensible thing to do on this device?
//
// A signature alone would let an attacker who can modify the download serve old
// signed bytes; a hash alone lets an attacker write their own manifest; a
// version check alone stops neither. All three are mandatory.

// OTASchemaVersion is the manifest layout version.
const OTASchemaVersion = 1

// OTAArtifactKind names what an artifact is.
//
// There is exactly one kind. Adding another is a decision to make a whole class
// of device unrecoverable by software, and should be made with that sentence in
// front of you.
type OTAArtifactKind string

// OTAArtifactAgent is the nassimhub-agent executable. It is the only kind.
const OTAArtifactAgent OTAArtifactKind = "agent"

// OTAChannel separates release streams.
type OTAChannel string

const (
	OTAChannelStable OTAChannel = "stable"
	OTAChannelBeta   OTAChannel = "beta"
)

// OTAArtifact is one downloadable file.
type OTAArtifact struct {
	Kind OTAArtifactKind `json:"kind"`
	// Name is the file name on the device, not a path. A manifest cannot
	// choose where anything lands.
	Name string `json:"name"`
	// SHA256 is hex-encoded, lowercase.
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// URL is where to fetch it. It is not trusted: the hash decides whether
	// what came back is acceptable, so a compromised mirror can cause a
	// failed update but never an installed one.
	URL string `json:"url"`
	// Arch is the target, e.g. "arm64". An artifact for another architecture
	// is refused rather than downloaded.
	Arch string `json:"arch"`
}

// OTAManifest describes one release.
type OTAManifest struct {
	SchemaVersion int        `json:"schema_version"`
	ReleaseID     string     `json:"release_id"`
	Version       string     `json:"version"`
	Channel       OTAChannel `json:"channel"`
	Platform      Platform   `json:"platform"`
	ReleasedAt    time.Time  `json:"released_at"`

	// ProtocolMajor and ProtocolMinor are what the new agent will speak. They
	// are here so a device can refuse an update that would make it unusable
	// with the Core it is paired to - the failure mode where an update
	// "succeeds" and the device disappears from the user's NAS.
	ProtocolMajor int `json:"protocol_major"`
	ProtocolMinor int `json:"protocol_minor"`
	// MinCoreVersion is what the new agent will demand of Core.
	MinCoreVersion string `json:"min_core_version"`

	Artifacts []OTAArtifact `json:"artifacts"`
	Notes     string        `json:"notes,omitempty"`
}

// OTASignedManifest is a manifest with its signature.
//
// The manifest travels as raw bytes rather than as a decoded structure, and
// that is deliberate: the signature covers exactly the bytes that were signed.
// Decoding and re-encoding before verifying would mean verifying a
// re-serialisation, and any difference in field order or numeric formatting
// between the publisher's encoder and this one would silently change what is
// being checked.
type OTASignedManifest struct {
	Manifest  json.RawMessage `json:"manifest"`
	KeyID     string          `json:"key_id"`
	Signature string          `json:"signature"`

	// The post-quantum half, optional on the wire so that a manifest signed
	// by an older publisher still parses. Optional on the WIRE is not the same
	// as optional in POLICY: under OTASignatureRequired an absent post-quantum
	// signature is a refusal. See ota_pq.go, where that rule lives.
	//
	// Both signatures cover the same Manifest bytes, for the same reason the
	// pairing transcript is signed twice over one encoding: two signatures
	// over two serialisations could attest to two different updates.
	PQSignature string               `json:"pq_signature,omitempty"`
	PQKeyID     string               `json:"pq_key_id,omitempty"`
	PQAlgorithm PQSignatureAlgorithm `json:"pq_algorithm,omitempty"`
}

// OTAErrors.
var (
	// ErrOTAUnsigned reports a manifest whose signature does not verify.
	ErrOTAUnsigned = errors.New("update manifest is not signed by a known release key")
	// ErrOTAHash reports downloaded bytes that do not match the manifest.
	ErrOTAHash = errors.New("downloaded artifact does not match its manifest hash")
	// ErrOTARejected reports a manifest that verified but must not be applied.
	ErrOTARejected = errors.New("update is not applicable to this device")
)

// OTAKeyring maps key ids to release signing keys.
//
// Key ids exist so a key can be rotated without a flag day: a device trusts
// every key in its ring, the publisher signs with the newest, and the old one
// is dropped from the ring in a later release once nothing signs with it.
type OTAKeyring map[string]ed25519.PublicKey

// SignManifest produces a signed manifest.
//
// It is in the product rather than in a build script because the signing input
// must be produced by the same code that verifies it. A publisher using a
// different encoder would produce manifests that verify by luck.
func SignManifest(manifest OTAManifest, keyID string, key ed25519.PrivateKey) (OTASignedManifest, error) {
	if keyID == "" {
		return OTASignedManifest{}, errors.New("signing requires a key id")
	}
	if len(key) != ed25519.PrivateKeySize {
		return OTASignedManifest{}, errors.New("signing requires an ed25519 private key")
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return OTASignedManifest{}, err
	}
	return OTASignedManifest{
		Manifest:  encoded,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, encoded)),
	}, nil
}

// VerifyManifest checks the signature and returns the decoded manifest.
//
// Order matters here: the signature is checked against the raw bytes BEFORE
// they are decoded, so a manifest that fails verification is never parsed into
// a structure some later code might use by accident.
func VerifyManifest(signed OTASignedManifest, keyring OTAKeyring) (OTAManifest, error) {
	key, known := keyring[signed.KeyID]
	if !known || len(key) != ed25519.PublicKeySize {
		return OTAManifest{}, fmt.Errorf("%w: key id %q is not in this device's keyring",
			ErrOTAUnsigned, signed.KeyID)
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return OTAManifest{}, fmt.Errorf("%w: signature is not base64", ErrOTAUnsigned)
	}
	if !ed25519.Verify(key, signed.Manifest, signature) {
		return OTAManifest{}, fmt.Errorf("%w: signature does not verify against key %q",
			ErrOTAUnsigned, signed.KeyID)
	}
	var manifest OTAManifest
	if err := json.Unmarshal(signed.Manifest, &manifest); err != nil {
		return OTAManifest{}, fmt.Errorf("%w: manifest is not readable: %v", ErrOTAUnsigned, err)
	}
	return manifest, nil
}

// ArtifactDigest is the hex SHA-256 of some bytes, in the form manifests use.
func ArtifactDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// VerifyArtifact checks downloaded bytes against their manifest entry.
func VerifyArtifact(artifact OTAArtifact, content []byte) error {
	if int64(len(content)) != artifact.Size {
		return fmt.Errorf("%w: %s is %d bytes, manifest says %d",
			ErrOTAHash, artifact.Name, len(content), artifact.Size)
	}
	digest := ArtifactDigest(content)
	if !strings.EqualFold(digest, artifact.SHA256) {
		return fmt.Errorf("%w: %s hashes to %s, manifest says %s",
			ErrOTAHash, artifact.Name, digest, artifact.SHA256)
	}
	return nil
}

// OTAPolicy is what a device will accept.
type OTAPolicy struct {
	Platform Platform
	Arch     string
	Channel  OTAChannel
	// CurrentVersion is what is running now.
	CurrentVersion string
	// AllowDowngrade permits installing an older version than the running one.
	//
	// Off by default, and the default is the interesting half. A signed older
	// manifest is a legitimate artifact - it was a real release - so an
	// attacker who can serve stale files can otherwise walk a device back to a
	// version with a known defect without forging anything. Turning this on is
	// a deliberate act by an operator who is holding the device.
	AllowDowngrade bool
	// CoreVersion is the paired Core, when there is one. An update that would
	// demand a newer Core than the one this device is paired to is refused:
	// the update would succeed and the device would then vanish from the
	// user's NAS, which is indistinguishable from a brick to the person who
	// owns it.
	CoreVersion string
}

// CheckManifest decides whether a verified manifest may be installed.
//
// Signature verification is assumed to have happened already - this answers the
// separate question of whether installing these particular bytes on this
// particular device is a sensible thing to do.
func CheckManifest(manifest OTAManifest, policy OTAPolicy) error {
	if manifest.SchemaVersion != OTASchemaVersion {
		return fmt.Errorf("%w: manifest schema %d, this agent understands %d",
			ErrOTARejected, manifest.SchemaVersion, OTASchemaVersion)
	}
	if manifest.Platform != policy.Platform {
		return fmt.Errorf("%w: manifest targets %s, this device is %s",
			ErrOTARejected, manifest.Platform, policy.Platform)
	}
	if policy.Channel != "" && manifest.Channel != policy.Channel {
		return fmt.Errorf("%w: manifest is on the %s channel, this device follows %s",
			ErrOTARejected, manifest.Channel, policy.Channel)
	}
	if manifest.ProtocolMajor != ProtocolMajor {
		return fmt.Errorf("%w: the update speaks protocol %d, this generation is %d; "+
			"installing it would disconnect the device from its NAS",
			ErrOTARejected, manifest.ProtocolMajor, ProtocolMajor)
	}

	candidate, err := ParseVersion(manifest.Version)
	if err != nil {
		return fmt.Errorf("%w: manifest version %q is unreadable", ErrOTARejected, manifest.Version)
	}
	if !policy.AllowDowngrade {
		if current, err := ParseVersion(policy.CurrentVersion); err == nil {
			if candidate.Compare(current) < 0 {
				return fmt.Errorf("%w: %s is older than the running %s and downgrades are not enabled",
					ErrOTARejected, candidate, current)
			}
			if candidate.Compare(current) == 0 {
				return fmt.Errorf("%w: %s is already running", ErrOTARejected, candidate)
			}
		}
	}

	// Would the new agent still work with the Core this device is paired to?
	if manifest.MinCoreVersion != "" && policy.CoreVersion != "" {
		required, err := ParseVersion(manifest.MinCoreVersion)
		if err != nil {
			return fmt.Errorf("%w: manifest states an unreadable minimum core version %q",
				ErrOTARejected, manifest.MinCoreVersion)
		}
		if paired, err := ParseVersion(policy.CoreVersion); err == nil && !paired.AtLeast(required) {
			return fmt.Errorf("%w: the update needs NasSimHub %s and this device is paired to %s; "+
				"update the NAS first", ErrOTARejected, required, paired)
		}
	}

	agents := 0
	for _, artifact := range manifest.Artifacts {
		if artifact.Kind != OTAArtifactAgent {
			return fmt.Errorf("%w: artifact kind %q is not installable by this agent",
				ErrOTARejected, artifact.Kind)
		}
		if artifact.Arch != "" && policy.Arch != "" && artifact.Arch != policy.Arch {
			return fmt.Errorf("%w: artifact %s is for %s, this device is %s",
				ErrOTARejected, artifact.Name, artifact.Arch, policy.Arch)
		}
		if len(artifact.SHA256) != 64 {
			return fmt.Errorf("%w: artifact %s has no usable sha256", ErrOTARejected, artifact.Name)
		}
		if artifact.Size <= 0 {
			return fmt.Errorf("%w: artifact %s has no size", ErrOTARejected, artifact.Name)
		}
		if strings.ContainsAny(artifact.Name, `/\`) || artifact.Name == "" {
			return fmt.Errorf("%w: artifact name %q is not a plain file name",
				ErrOTARejected, artifact.Name)
		}
		agents++
	}
	if agents != 1 {
		return fmt.Errorf("%w: a manifest must carry exactly one agent artifact, this has %d",
			ErrOTARejected, agents)
	}
	return nil
}

// ---------------------------------------------------------------------------
// The update state machine
// ---------------------------------------------------------------------------

// OTAState is where an update has got to.
//
// The states are named for what is true, not for what is happening, so a device
// found in any one of them can be reasoned about after a power cut. STAGED
// means "verified bytes are on disk and the running binary is untouched";
// PENDING_CONFIRM means "the new binary is running and has not yet proved it
// works". Those two are the states that matter for recovery.
type OTAState string

const (
	// OTAIdle is the resting state.
	OTAIdle OTAState = "IDLE"
	// OTAChecking is a manifest fetch in progress.
	OTAChecking OTAState = "CHECKING"
	// OTAAvailable means a manifest verified and passed policy.
	OTAAvailable OTAState = "AVAILABLE"
	// OTADownloading is an artifact transfer in progress.
	OTADownloading OTAState = "DOWNLOADING"
	// OTAStaged means the bytes are on disk and hash-verified. The running
	// agent has not been touched, so a power cut here costs nothing.
	OTAStaged OTAState = "STAGED"
	// OTAValidating is the staged binary being checked before it is trusted -
	// it is executed with a self-test flag and must report its own version.
	OTAValidating OTAState = "VALIDATING"
	// OTAReady means validation passed and the swap can happen.
	OTAReady OTAState = "READY"
	// OTAApplying is the swap itself.
	OTAApplying OTAState = "APPLYING"
	// OTAPendingConfirm means the new binary is running but unproven. A device
	// that reboots and finds itself here rolls back, because the most likely
	// explanation is that the new binary is why it rebooted.
	OTAPendingConfirm OTAState = "PENDING_CONFIRM"
	// OTARollingBack is the previous binary being restored.
	OTARollingBack OTAState = "ROLLING_BACK"
	// OTAFailed is a terminal failure with the old binary still running.
	OTAFailed OTAState = "FAILED"
	// OTARolledBack means an update was applied, failed, and was undone.
	OTARolledBack OTAState = "ROLLED_BACK"
)

// OTARestartReason is why the agent process started while an update was in
// flight.
//
// Telling these apart is the difference between an update mechanism that works
// and one that undoes every successful update. Applying an update REQUIRES the
// process to restart - that is how the new binary starts running - so "the
// process restarted while unconfirmed" cannot mean failure on its own. It is
// the expected step.
//
// What distinguishes them:
//
//	expected_restart   the new binary is running, this is the restart the
//	                   update asked for, and it has not been confirmed yet
//	unexpected_restart the process restarted AGAIN before confirming, which
//	                   means the new binary started and then died
//	wrong_version      the process that came up is not the version the update
//	                   installed, so the swap did not take
//	confirm_timeout    the new binary is running and never proved itself
//	health_failed      the new binary ran its self-check and failed it
type OTARestartReason string

const (
	// OTARestartExpected is the restart an update asks for. Not a failure.
	OTARestartExpected OTARestartReason = "expected_restart"
	// OTARestartUnexpected is a second restart before confirmation. The new
	// binary came up and did not stay up.
	OTARestartUnexpected OTARestartReason = "unexpected_restart"
	// OTARestartWrongVersion means the running binary is not the one the
	// update installed.
	OTARestartWrongVersion OTARestartReason = "wrong_version"
	// OTAConfirmTimeout means the new binary ran but never confirmed.
	OTAConfirmTimeout OTARestartReason = "confirm_timeout"
	// OTAHealthFailed means the new binary failed its own health check.
	OTAHealthFailed OTARestartReason = "health_failed"
	// OTARestartNone means nothing was in flight.
	OTARestartNone OTARestartReason = ""
)

// RollsBack reports whether a reason should undo the update.
//
// Exactly one reason does not: the expected restart. Every other way of
// arriving at an unconfirmed update means something went wrong, and the safe
// response to "something went wrong right after an update" is to put the old
// binary back.
func (r OTARestartReason) RollsBack() bool {
	switch r {
	case OTARestartExpected, OTARestartNone:
		return false
	default:
		return true
	}
}

// OTAConfirmWindow is how long a new binary has to prove itself.
//
// Long enough for a device with a slow boot to come up, reach its NAS and pass
// a health check; short enough that a device that never will is recovered
// while the user is still in the room.
const OTAConfirmWindow = 10 * time.Minute

// OTAStatus is what GET /v1/ota reports.
type OTAStatus struct {
	State           OTAState   `json:"state"`
	CurrentVersion  string     `json:"current_version"`
	TargetVersion   string     `json:"target_version,omitempty"`
	PreviousVersion string     `json:"previous_version,omitempty"`
	ReleaseID       string     `json:"release_id,omitempty"`
	Channel         OTAChannel `json:"channel,omitempty"`
	Progress        int        `json:"progress_percent"`
	Error           string     `json:"error,omitempty"`
	// Attempts counts how many times this release has been tried. A release
	// that has failed repeatedly is not retried forever - see agent/ota.
	Attempts int `json:"attempts"`
	// RestartReason explains an update that was undone, so the UI can say
	// "the new version did not start" rather than "update failed".
	RestartReason OTARestartReason `json:"restart_reason,omitempty"`
	// ConfirmDeadline is when an unconfirmed update will be rolled back.
	ConfirmDeadline time.Time `json:"confirm_deadline,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
	// Supported is false when this device cannot install an update: a build
	// with no installer, no release keys to verify one against, or an
	// installation that cannot be switched. It exists so Core can grey the
	// button out rather than offering an action that will always fail.
	Supported bool `json:"supported"`
}

// OTATransitions lists the states reachable from each state.
//
// It is data rather than a switch statement so that a test can assert the shape
// of the machine - in particular that there is no edge from any state into
// APPLYING except from READY, which is the edge that would let an unverified
// binary be installed.
var OTATransitions = map[OTAState][]OTAState{
	OTAIdle:           {OTAChecking},
	OTAChecking:       {OTAIdle, OTAAvailable, OTAFailed},
	OTAAvailable:      {OTADownloading, OTAIdle, OTAFailed},
	OTADownloading:    {OTAStaged, OTAFailed},
	OTAStaged:         {OTAValidating, OTAFailed},
	OTAValidating:     {OTAReady, OTAFailed},
	OTAReady:          {OTAApplying, OTAFailed},
	OTAApplying:       {OTAPendingConfirm, OTARollingBack, OTAFailed},
	OTAPendingConfirm: {OTAIdle, OTARollingBack},
	OTARollingBack:    {OTARolledBack, OTAFailed},
	OTARolledBack:     {OTAIdle, OTAChecking},
	OTAFailed:         {OTAIdle, OTAChecking},
}

// OTACanTransition reports whether a transition is allowed.
func OTACanTransition(from, to OTAState) bool {
	for _, allowed := range OTATransitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

// OTAStates lists every state, sorted, for tests and documentation.
func OTAStates() []OTAState {
	states := make([]OTAState, 0, len(OTATransitions))
	for state := range OTATransitions {
		states = append(states, state)
	}
	sort.Slice(states, func(i, j int) bool { return states[i] < states[j] })
	return states
}
