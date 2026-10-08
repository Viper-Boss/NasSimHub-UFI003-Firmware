// Package ota runs the update state machine on the device.
//
// Nothing here writes a boot image, a device tree, a modem partition or a root
// filesystem, and nothing here can be configured to. The only artifact kind the
// protocol defines is the agent executable (see proto/ota.go), and the Installer
// interface below is deliberately narrow enough that an implementation which
// touched anything else would be doing so outside the contract rather than
// through it.
//
// The installer that ships is FileInstaller (installer.go), which installs a
// release beside the device state and never touches the agent in the system
// image; MockInstaller remains for tests of the state machine itself. The two
// things any installer must preserve are stated here rather than left to be
// rediscovered:
//
//  1. The running binary is not touched until a staged one has been verified
//     AND validated. Staging is hash verification; validation is executing the
//     staged binary and making it prove it starts and reports the expected
//     version. A binary that passes the first and fails the second is the
//     common case - a build for the wrong architecture - and it must fail
//     before anything is swapped.
//
//  2. A successful swap is not the end. The new agent runs in PENDING_CONFIRM
//     until something independent confirms it works.
//
//     But "the process restarted while unconfirmed" is NOT by itself a
//     failure, and getting that wrong is the classic way to build an update
//     mechanism that can never update anything: applying an update REQUIRES
//     the process to restart, because that is how the new binary starts
//     running. A systemd restart immediately after an update is the expected
//     step, not evidence against it. What distinguishes the expected restart
//     from a broken update is which version came up, whether the restart was
//     the first one, and whether the confirmation window has closed - see
//     classifyRestart.
//
// State is persisted on every transition so that reasoning survives a power
// cut. The file is small and written whole; a partially written state file is
// treated as no state at all, which resolves to IDLE with the running binary
// intact - the safe reading.
package ota

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// StateFileName holds the persisted update state.
const StateFileName = "ota-state.json"

// StagingDirName holds verified-but-not-installed artifacts.
const StagingDirName = "ota-staging"

// MaxAttempts bounds how many times one release is retried.
//
// Without a bound, a release that fails at the same point every time turns into
// an update loop: download, stage, fail, retry, forever - on a device with a
// metered connection and 256 MB of RAM. Three attempts is enough to ride out a
// transient network failure and few enough to stop.
const MaxAttempts = 3

// ErrBusy reports an operation attempted while another is in progress.
var ErrBusy = errors.New("an update is already in progress")

// ErrNotReady reports an apply attempted before validation.
var ErrNotReady = errors.New("no validated update is ready to apply")

// Fetcher retrieves manifests and artifacts.
//
// It is an interface so that the state machine can be tested against every
// failure a network produces - truncation, corruption, substitution - without
// a network. The production implementation is an HTTP client and is not the
// interesting part; the failures are.
type Fetcher interface {
	Manifest(ctx context.Context, url string) (proto.OTASignedManifest, error)
	Artifact(ctx context.Context, artifact proto.OTAArtifact) ([]byte, error)
}

// Installer swaps the agent binary and can put the old one back.
//
// Every method must be safe to call twice: a power cut can leave the device
// anywhere, and recovery re-runs the step rather than trying to work out how
// far the previous attempt got.
type Installer interface {
	// Stage writes verified bytes somewhere the running agent is not.
	Stage(ctx context.Context, artifact proto.OTAArtifact, content []byte) error
	// Validate executes the staged binary and confirms it reports the version
	// the manifest promised. Returning nil means the bytes are known to run on
	// this device, which hash verification alone does not establish.
	Validate(ctx context.Context, artifact proto.OTAArtifact, expectedVersion string) error
	// Activate swaps the staged binary into place, keeping the previous one.
	Activate(ctx context.Context, artifact proto.OTAArtifact) error
	// Rollback restores the previous binary.
	Rollback(ctx context.Context) error
	// Supported reports whether this installer can actually install. The mock
	// used in the software-only stage answers false, so Core can grey out the
	// action rather than offering one that will fail.
	Supported() bool
}

// State is the persisted record.
type State struct {
	State           proto.OTAState   `json:"state"`
	ReleaseID       string           `json:"release_id,omitempty"`
	TargetVersion   string           `json:"target_version,omitempty"`
	PreviousVersion string           `json:"previous_version,omitempty"`
	Channel         proto.OTAChannel `json:"channel,omitempty"`
	Attempts        int              `json:"attempts"`
	Error           string           `json:"error,omitempty"`
	Progress        int              `json:"progress_percent"`
	UpdatedAt       time.Time        `json:"updated_at"`
	// StagedArtifact is what is sitting in the staging directory, if anything.
	StagedArtifact *proto.OTAArtifact `json:"staged_artifact,omitempty"`

	// The three fields below are what let a restart be classified instead of
	// assumed. See proto.OTARestartReason.
	//
	// ExpectedRestart is set by Apply and consumed by the first start that
	// follows. It is the marker that says "the process is about to restart
	// because we asked it to", and consuming it is what makes a SECOND restart
	// distinguishable from the first.
	ExpectedRestart bool `json:"expected_restart,omitempty"`
	// ConfirmDeadline bounds how long an unconfirmed update may run.
	ConfirmDeadline time.Time `json:"confirm_deadline,omitempty"`
	// RestartReason records why an update was undone.
	RestartReason proto.OTARestartReason `json:"restart_reason,omitempty"`
}

// Options configures a Manager.
type Options struct {
	// Dir is the agent's state directory. The state file and the staging
	// directory live under it.
	Dir string
	// CurrentVersion is the running agent's version.
	CurrentVersion string
	Policy         proto.OTAPolicy
	Keyring        proto.OTAKeyring
	// PQKeyring holds the post-quantum release signing identities. Empty on a
	// device whose publisher has not started dual-signing, which is the
	// expected state until ML-DSA is available.
	PQKeyring proto.OTAPQKeyring
	// SignaturePolicy decides whether a classical-only manifest may be
	// installed. PREFERRED accepts one and says so; REQUIRED refuses.
	//
	// The default is PREFERRED because REQUIRED on a fleet whose publisher
	// cannot yet dual-sign would refuse every update, including the one that
	// would fix that. PQ_EXTREME sets it to REQUIRED, which is a choice an
	// owner makes with their eyes open.
	SignaturePolicy proto.OTASignaturePolicy
	Fetcher         Fetcher
	Installer       Installer
	Logf            func(format string, arguments ...any)
	Now             func() time.Time
	// Resume loads the persisted state as it is, without resolving an
	// interrupted update. It is set by an installed release that the factory
	// agent has just started: that process already made the decision (see
	// boot.go), and making it a second time would read the restart the update
	// asked for as a second, unexpected one and undo a good update.
	Resume bool
}

// Manager drives the state machine.
type Manager struct {
	options Options
	now     func() time.Time
	logf    func(string, ...any)

	// fetcherMu serialises operations that substitute the manifest source.
	fetcherMu sync.Mutex

	mu    sync.Mutex
	state State
	busy  bool
	// currentVersion is the version of the agent that is, or is about to be,
	// running. It starts as Options.CurrentVersion and changes only at
	// start-up, when the factory agent works out which release will run.
	currentVersion string
	// signatures is what the last verified manifest carried. Reported to the
	// UI and to diagnostics so that "this device installs classical-only
	// updates" is visible rather than inferred.
	signatures proto.OTASignatureOutcome
}

// setSignatureOutcome records what the last verification established.
func (m *Manager) setSignatureOutcome(outcome proto.OTASignatureOutcome) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signatures = outcome
}

// Signatures reports the signature picture for the UI and diagnostics.
func (m *Manager) Signatures() proto.OTASignatureCapability {
	m.mu.Lock()
	outcome := m.signatures
	m.mu.Unlock()
	policy := m.options.SignaturePolicy
	if policy == "" {
		policy = proto.OTASignaturePreferred
	}
	return proto.DescribeOTASignatures(policy, outcome)
}

// New builds a Manager and recovers whatever state was left behind.
func New(options Options) (*Manager, error) {
	if options.Dir == "" {
		return nil, errors.New("an update manager requires a state directory")
	}
	if options.Installer == nil {
		return nil, errors.New("an update manager requires an installer")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	logf := options.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	manager := &Manager{options: options, now: now, logf: logf, currentVersion: options.CurrentVersion}
	if options.Resume {
		state, err := manager.read()
		if err != nil || state.State == "" {
			state = State{State: proto.OTAIdle, UpdatedAt: now().UTC()}
		}
		manager.state = state
		return manager, nil
	}
	manager.state = manager.recover()
	return manager, nil
}

// CurrentVersion is the version of the running agent as the manager sees it.
func (m *Manager) CurrentVersion() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentVersion
}

// SetCurrentVersion corrects the running version at start-up, when the release
// that was expected to run turns out not to be the one running.
func (m *Manager) SetCurrentVersion(version string) {
	m.mu.Lock()
	m.currentVersion = version
	m.mu.Unlock()
}

// failedToStart records a selected release that could not be executed. If it
// was an unconfirmed update, the update is over and the record says why.
func (m *Manager) failedToStart(releaseID string, cause error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	detail := "the installed release could not be started"
	if cause != nil {
		detail += ": " + cause.Error()
	}
	if m.state.State == proto.OTAPendingConfirm && (releaseID == "" || m.state.ReleaseID == releaseID) {
		m.state.State = proto.OTARolledBack
		m.state.RestartReason = proto.OTARestartWrongVersion
		m.state.ExpectedRestart = false
		m.state.ConfirmDeadline = time.Time{}
	}
	m.state.Error = detail
	m.state.UpdatedAt = m.now().UTC()
	if err := m.write(m.state); err != nil {
		m.logf("could not persist update state: %v", err)
	}
	m.logf("%s", detail)
}

// recover reads the persisted state and resolves anything left mid-flight.
//
// This is the function that runs after a restart, and its judgements are the
// whole safety story. The subtle one is PENDING_CONFIRM:
//
//	PENDING_CONFIRM  classify the restart (see classifyRestart). Exactly one
//	                 kind - the expected restart, with the new version running
//	                 and time left on the clock - is NOT a failure: it is how
//	                 an update takes effect, and rolling back there would undo
//	                 every successful update. Every other kind rolls back.
//	APPLYING         the swap was interrupted. Roll back; Activate and Rollback
//	                 are both idempotent, so undoing a swap that may not have
//	                 happened is safe.
//	anything else    nothing was installed, so the running binary is the old
//	                 one and IDLE is true.
func (m *Manager) recover() State {
	state, err := m.read()
	if err != nil || state.State == "" {
		return State{State: proto.OTAIdle, UpdatedAt: m.now().UTC()}
	}
	switch state.State {
	case proto.OTAPendingConfirm:
		reason := m.classifyRestart(state)
		state.RestartReason = reason
		if !reason.RollsBack() {
			// The expected restart: the new binary is running and has not
			// confirmed yet. Consume the marker - a second restart before
			// confirmation will now classify as unexpected - and let it run.
			//
			// Rolling back here would undo every successful update, because
			// restarting IS how an update takes effect. That mistake produces
			// a device that can never be updated and looks, from the outside,
			// like an update mechanism that works.
			state.ExpectedRestart = false
			state.UpdatedAt = m.now().UTC()
			m.logf("update to %s is running unconfirmed; %s",
				state.TargetVersion, describeDeadline(state.ConfirmDeadline, m.now()))
			_ = m.write(state)
			return state
		}
		m.logf("rolling back the update to %s: %s", state.TargetVersion, reason)
		return m.rollbackDuringRecovery(state, reason)
	case proto.OTAApplying:
		// The swap itself was interrupted. Activate and Rollback are both
		// idempotent, so undoing a swap that may not have happened is safe.
		state.RestartReason = proto.OTARestartUnexpected
		m.logf("the swap was interrupted; rolling back")
		return m.rollbackDuringRecovery(state, proto.OTARestartUnexpected)
	case proto.OTAStaged, proto.OTAReady:
		// Verified bytes on disk and an untouched running binary. Nothing to
		// undo, but the staged state is not resumed automatically either - a
		// restart is weak evidence that something went wrong, and a human
		// asking again is cheap.
		state.State = proto.OTAIdle
		state.UpdatedAt = m.now().UTC()
		_ = m.write(state)
		return state
	case proto.OTAChecking, proto.OTADownloading, proto.OTAValidating:
		state.State = proto.OTAIdle
		state.Error = "interrupted by a restart"
		state.UpdatedAt = m.now().UTC()
		_ = m.write(state)
		return state
	default:
		return state
	}
}

// Status reports the current state.
func (m *Manager) Status() proto.OTAStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return proto.OTAStatus{
		State:           m.state.State,
		CurrentVersion:  m.currentVersion,
		TargetVersion:   m.state.TargetVersion,
		PreviousVersion: m.state.PreviousVersion,
		ReleaseID:       m.state.ReleaseID,
		Channel:         m.state.Channel,
		Progress:        m.state.Progress,
		Error:           m.state.Error,
		Attempts:        m.state.Attempts,
		RestartReason:   m.state.RestartReason,
		ConfirmDeadline: m.state.ConfirmDeadline,
		UpdatedAt:       m.state.UpdatedAt,
		Supported:       m.options.Installer.Supported(),
	}
}

// Check fetches a manifest, verifies it and decides whether it applies.
//
// It does not download anything. Separating "is there an update and may we
// install it" from "fetch several megabytes" means a device on a metered link
// can be asked the first question cheaply.
func (m *Manager) Check(ctx context.Context, manifestURL string) (proto.OTAManifest, error) {
	if err := m.begin(); err != nil {
		return proto.OTAManifest{}, err
	}
	defer m.end()

	m.transition(proto.OTAChecking, 0, "")
	if m.options.Fetcher == nil {
		m.fail("no update source is configured")
		return proto.OTAManifest{}, errors.New("no update source is configured")
	}
	signed, err := m.options.Fetcher.Manifest(ctx, manifestURL)
	if err != nil {
		m.fail("could not fetch the update manifest: " + err.Error())
		return proto.OTAManifest{}, err
	}
	policySignatures := m.options.SignaturePolicy
	if policySignatures == "" {
		policySignatures = proto.OTASignaturePreferred
	}
	manifest, outcome, err := proto.VerifyManifestHybrid(
		signed, m.options.Keyring, m.options.PQKeyring, policySignatures)
	if err != nil {
		m.fail(err.Error())
		return proto.OTAManifest{}, err
	}
	m.setSignatureOutcome(outcome)
	if outcome == proto.OTAClassicalOnly {
		// Said plainly, every time, rather than only when something goes
		// wrong. A fleet that quietly installs classical-only updates for two
		// years and believes otherwise is the failure this line prevents.
		m.logf("update manifest is classical-only (no post-quantum signature)")
	}
	policy := m.options.Policy
	policy.CurrentVersion = m.CurrentVersion()
	if err := proto.CheckManifest(manifest, policy); err != nil {
		// Not applicable is not a failure of the device. Returning to IDLE
		// rather than FAILED keeps "you are up to date" from looking like a
		// fault in the UI.
		m.transition(proto.OTAIdle, 0, err.Error())
		return proto.OTAManifest{}, err
	}

	m.mu.Lock()
	if m.state.ReleaseID != manifest.ReleaseID {
		// A different release resets the attempt counter; the bound is per
		// release, not per device.
		m.state.Attempts = 0
	}
	m.state.ReleaseID = manifest.ReleaseID
	m.state.TargetVersion = manifest.Version
	m.state.Channel = manifest.Channel
	attempts := m.state.Attempts
	m.mu.Unlock()

	if attempts >= MaxAttempts {
		m.transition(proto.OTAIdle, 0, fmt.Sprintf(
			"release %s has failed %d times and will not be retried automatically",
			manifest.ReleaseID, attempts))
		return manifest, fmt.Errorf("release %s has failed %d times", manifest.ReleaseID, attempts)
	}
	m.transition(proto.OTAAvailable, 0, "")
	return manifest, nil
}

// Download fetches, hash-verifies and stages the artifact, then validates it.
//
// Everything up to and including validation happens without touching the
// running agent, so any failure here leaves a working device.
func (m *Manager) Download(ctx context.Context, manifest proto.OTAManifest) error {
	if err := m.begin(); err != nil {
		return err
	}
	defer m.end()

	if state := m.snapshot().State; state != proto.OTAAvailable {
		return fmt.Errorf("%w: state is %s", ErrNotReady, state)
	}
	artifact, err := agentArtifact(manifest)
	if err != nil {
		m.fail(err.Error())
		return err
	}

	m.countAttempt()
	m.transition(proto.OTADownloading, 10, "")
	content, err := m.options.Fetcher.Artifact(ctx, artifact)
	if err != nil {
		m.fail("download failed: " + err.Error())
		return err
	}
	// The hash decides. A mirror that served something else, a transfer that
	// truncated, an attacker who replaced the file - all three end here, and
	// none of them can reach the installer.
	if err := proto.VerifyArtifact(artifact, content); err != nil {
		m.fail(err.Error())
		return err
	}
	m.transition(proto.OTADownloading, 60, "")

	if err := m.options.Installer.Stage(ctx, artifact, content); err != nil {
		m.fail("staging failed: " + err.Error())
		return err
	}
	m.mu.Lock()
	staged := artifact
	m.state.StagedArtifact = &staged
	m.mu.Unlock()
	m.transition(proto.OTAStaged, 70, "")

	m.transition(proto.OTAValidating, 80, "")
	if err := m.options.Installer.Validate(ctx, artifact, manifest.Version); err != nil {
		m.fail("the staged update did not validate: " + err.Error())
		return err
	}
	m.transition(proto.OTAReady, 90, "")
	return nil
}

// Apply swaps the validated binary in. The new agent is not trusted yet.
func (m *Manager) Apply(ctx context.Context) error {
	if err := m.begin(); err != nil {
		return err
	}
	defer m.end()

	current := m.snapshot()
	if current.State != proto.OTAReady || current.StagedArtifact == nil {
		return fmt.Errorf("%w: state is %s", ErrNotReady, current.State)
	}
	m.mu.Lock()
	m.state.PreviousVersion = m.currentVersion
	m.mu.Unlock()

	m.transition(proto.OTAApplying, 95, "")
	if err := m.options.Installer.Activate(ctx, *current.StagedArtifact); err != nil {
		m.logf("activation failed, rolling back: %v", err)
		m.transition(proto.OTARollingBack, 95, err.Error())
		if rollbackErr := m.options.Installer.Rollback(ctx); rollbackErr != nil {
			m.transition(proto.OTAFailed, 0, "activation and rollback both failed: "+rollbackErr.Error())
			return rollbackErr
		}
		m.transition(proto.OTARolledBack, 0, "activation failed: "+err.Error())
		return err
	}
	// Applied but unproven. The marker and the deadline below are what let the
	// NEXT start tell "the restart we asked for" from "the new binary died" -
	// see classifyRestart. Without them, the restart that makes an update take
	// effect would itself be read as the update failing.
	m.mu.Lock()
	m.state.ExpectedRestart = true
	m.state.ConfirmDeadline = m.now().Add(proto.OTAConfirmWindow)
	m.state.RestartReason = proto.OTARestartNone
	m.mu.Unlock()
	m.transition(proto.OTAPendingConfirm, 99, "")
	return nil
}

// Confirm records that the new agent works. Only after this is the update done.
func (m *Manager) Confirm() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.State != proto.OTAPendingConfirm {
		return fmt.Errorf("%w: state is %s", ErrNotReady, m.state.State)
	}
	m.state.State = proto.OTAIdle
	m.state.Progress = 100
	m.state.Error = ""
	m.state.Attempts = 0
	m.state.StagedArtifact = nil
	m.state.ExpectedRestart = false
	m.state.ConfirmDeadline = time.Time{}
	m.state.RestartReason = proto.OTARestartNone
	m.state.UpdatedAt = m.now().UTC()
	return m.write(m.state)
}

// Rollback undoes an applied update on request.
func (m *Manager) Rollback(ctx context.Context) error {
	if err := m.begin(); err != nil {
		return err
	}
	defer m.end()

	if state := m.snapshot().State; state != proto.OTAPendingConfirm {
		return fmt.Errorf("%w: nothing to roll back, state is %s", ErrNotReady, state)
	}
	m.transition(proto.OTARollingBack, 0, "")
	if err := m.options.Installer.Rollback(ctx); err != nil {
		m.transition(proto.OTAFailed, 0, "rollback failed: "+err.Error())
		return err
	}
	m.transition(proto.OTARolledBack, 0, "rolled back on request")
	return nil
}

// ---------------------------------------------------------------------------

func agentArtifact(manifest proto.OTAManifest) (proto.OTAArtifact, error) {
	for _, artifact := range manifest.Artifacts {
		if artifact.Kind == proto.OTAArtifactAgent {
			return artifact, nil
		}
	}
	return proto.OTAArtifact{}, errors.New("manifest carries no agent artifact")
}

func (m *Manager) begin() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.busy {
		return ErrBusy
	}
	m.busy = true
	return nil
}

func (m *Manager) end() {
	m.mu.Lock()
	m.busy = false
	m.mu.Unlock()
}

func (m *Manager) snapshot() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *Manager) countAttempt() {
	m.mu.Lock()
	m.state.Attempts++
	m.mu.Unlock()
}

// transition moves the machine and persists the result.
//
// An illegal transition is a programming error, and it is refused rather than
// performed: the table in proto is the specification, and code that disagrees
// with it should not be the thing that wins.
func (m *Manager) transition(to proto.OTAState, progress int, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	from := m.state.State
	if from == "" {
		from = proto.OTAIdle
	}
	if from != to && !proto.OTACanTransition(from, to) {
		m.logf("refused an illegal update transition %s -> %s", from, to)
		return
	}
	m.state.State = to
	m.state.Progress = progress
	m.state.Error = message
	m.state.UpdatedAt = m.now().UTC()
	if err := m.write(m.state); err != nil {
		m.logf("could not persist update state: %v", err)
	}
}

func (m *Manager) fail(message string) {
	m.transition(proto.OTAFailed, 0, message)
}

func (m *Manager) statePath() string { return filepath.Join(m.options.Dir, StateFileName) }

// StagingDir is where verified artifacts wait.
func (m *Manager) StagingDir() string { return filepath.Join(m.options.Dir, StagingDirName) }

func (m *Manager) read() (State, error) {
	content, err := os.ReadFile(m.statePath())
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(content, &state); err != nil {
		// A half-written file reads as no state, which resolves to IDLE with
		// the running binary intact. That is the safe reading, and it is the
		// reason this returns an error rather than trying to repair anything.
		return State{}, err
	}
	return state, nil
}

func (m *Manager) write(state State) error {
	if err := os.MkdirAll(m.options.Dir, 0o755); err != nil {
		return err
	}
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	// Write to a temporary file and rename, so a power cut during the write
	// leaves either the old state or the new one and never a truncated file.
	temporary := m.statePath() + ".tmp"
	if err := os.WriteFile(temporary, content, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, m.statePath())
}

// classifyRestart decides why the process started with an unconfirmed update.
//
// The three signals it uses are independent, and using all three is what makes
// the answer trustworthy:
//
//   - Which version is running. If it is not the one the update installed, the
//     swap did not take and there is nothing to wait for.
//   - Whether the expected-restart marker survived. Apply sets it; the first
//     start consumes it. A start that finds it already consumed is the second
//     restart, which means the new binary came up and then died.
//   - Whether the confirmation deadline has passed. A new binary that runs but
//     never confirms is a new binary that is not working, however healthy it
//     looks from inside.
func (m *Manager) classifyRestart(state State) proto.OTARestartReason {
	if state.TargetVersion != "" && m.currentVersion != "" &&
		state.TargetVersion != m.currentVersion {
		return proto.OTARestartWrongVersion
	}
	if !state.ConfirmDeadline.IsZero() && m.now().After(state.ConfirmDeadline) {
		return proto.OTAConfirmTimeout
	}
	if !state.ExpectedRestart {
		return proto.OTARestartUnexpected
	}
	return proto.OTARestartExpected
}

func (m *Manager) rollbackDuringRecovery(state State, reason proto.OTARestartReason) State {
	if err := m.options.Installer.Rollback(context.Background()); err != nil {
		state.State = proto.OTAFailed
		state.Error = "rollback failed: " + err.Error()
	} else {
		state.State = proto.OTARolledBack
		state.Error = explainRollback(reason)
	}
	state.RestartReason = reason
	state.ExpectedRestart = false
	state.UpdatedAt = m.now().UTC()
	_ = m.write(state)
	return state
}

// explainRollback turns a reason into something a person can act on.
func explainRollback(reason proto.OTARestartReason) string {
	switch reason {
	case proto.OTARestartWrongVersion:
		return "the update did not take effect: the previous version is still running"
	case proto.OTARestartUnexpected:
		return "the new version started and then stopped before it could be confirmed"
	case proto.OTAConfirmTimeout:
		return "the new version ran but never passed its health check"
	case proto.OTAHealthFailed:
		return "the new version failed its health check"
	default:
		return "the update was not confirmed"
	}
}

func describeDeadline(deadline time.Time, now time.Time) string {
	if deadline.IsZero() {
		return "no confirmation deadline is set"
	}
	remaining := deadline.Sub(now).Round(time.Second)
	if remaining <= 0 {
		return "the confirmation deadline has passed"
	}
	return "it has " + remaining.String() + " to confirm"
}

// HealthCheckFailed is how a new binary reports that it does not work.
//
// It is separate from Rollback because the two mean different things to whoever
// reads the status afterwards: a health check failure says the new version is
// broken, where a manual rollback says somebody changed their mind.
func (m *Manager) HealthCheckFailed(ctx context.Context, detail string) error {
	if err := m.begin(); err != nil {
		return err
	}
	defer m.end()

	if state := m.snapshot().State; state != proto.OTAPendingConfirm {
		return fmt.Errorf("%w: nothing to roll back, state is %s", ErrNotReady, state)
	}
	m.transition(proto.OTARollingBack, 0, detail)
	if err := m.options.Installer.Rollback(ctx); err != nil {
		m.transition(proto.OTAFailed, 0, "rollback after a failed health check also failed: "+err.Error())
		return err
	}
	m.mu.Lock()
	m.state.RestartReason = proto.OTAHealthFailed
	m.mu.Unlock()
	m.transition(proto.OTARolledBack, 0, explainRollback(proto.OTAHealthFailed))
	return nil
}

// ExpireUnconfirmed rolls back an update whose confirmation window has closed.
//
// It is called from the agent's own supervision loop. A device that applied an
// update and then could not reach its NAS would otherwise sit in
// PENDING_CONFIRM until it next restarted, which on a device in a cupboard is
// indefinitely.
func (m *Manager) ExpireUnconfirmed(ctx context.Context) error {
	current := m.snapshot()
	if current.State != proto.OTAPendingConfirm {
		return nil
	}
	if current.ConfirmDeadline.IsZero() || !m.now().After(current.ConfirmDeadline) {
		return nil
	}
	if err := m.begin(); err != nil {
		return err
	}
	defer m.end()
	m.transition(proto.OTARollingBack, 0, "")
	if err := m.options.Installer.Rollback(ctx); err != nil {
		m.transition(proto.OTAFailed, 0, "rollback after a confirmation timeout failed: "+err.Error())
		return err
	}
	m.mu.Lock()
	m.state.RestartReason = proto.OTAConfirmTimeout
	m.mu.Unlock()
	m.transition(proto.OTARolledBack, 0, explainRollback(proto.OTAConfirmTimeout))
	return nil
}

// reset abandons an update that has not been applied, returning the machine to
// IDLE so a different release can be offered.
//
// It is refused while an update is being applied, is awaiting confirmation or
// is being undone: those states describe a binary that has been switched, and
// leaving them by any route other than confirm or rollback would lose track of
// which agent is supposed to be running.
func (m *Manager) reset() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.busy {
		return ErrBusy
	}
	switch m.state.State {
	case proto.OTAApplying, proto.OTAPendingConfirm, proto.OTARollingBack:
		return fmt.Errorf("%w: state is %s", ErrNotReady, m.state.State)
	case proto.OTAIdle:
		return nil
	}
	m.state.State = proto.OTAIdle
	m.state.Progress = 0
	m.state.Error = ""
	m.state.StagedArtifact = nil
	m.state.UpdatedAt = m.now().UTC()
	return m.write(m.state)
}

// withFetcher runs one operation against a specific source. The Updater uses
// it to hand the state machine a manifest and artifact that were pushed to the
// device rather than fetched by it; the verification that follows is the same.
func (m *Manager) withFetcher(fetcher Fetcher, run func() (proto.OTAManifest, error)) (proto.OTAManifest, error) {
	m.fetcherMu.Lock()
	defer m.fetcherMu.Unlock()
	previous := m.options.Fetcher
	m.options.Fetcher = fetcher
	defer func() { m.options.Fetcher = previous }()
	return run()
}
