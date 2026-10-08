package ota

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// Updater is the update service the Node protocol exposes: it takes a signed
// manifest and the artifact bytes from the paired Core, and drives the state
// machine through verify, stage, validate, apply, confirm and undo.
//
// It adds three things the state machine does not have on its own:
//
//   - A spool. Bytes arrive in pieces over a link that drops; they are appended
//     to a file named for the hash they must add up to, so an interrupted
//     transfer resumes where it stopped and bytes for one release can never be
//     mistaken for another's.
//   - Limits, checked before anything is accepted: the artifact size the
//     manifest declares, the space actually free, and one transfer at a time.
//   - The restart. Applying or undoing an update changes which binary should
//     be running; the Updater asks the process to restart and the factory
//     agent's start-up code (boot.go) does the rest.
//
// Nothing here decides that an update is trustworthy. That is the manifest
// signature, checked by the state machine against keys this process cannot
// write.

// Errors the HTTP layer maps to distinct answers.
var (
	// ErrUnsupported means this device cannot install updates. The wrapped
	// message says why.
	ErrUnsupported = errors.New("updates are not supported on this device")
	// ErrNoOffer means bytes or an action arrived for a release that was not
	// offered, or not the one currently offered.
	ErrNoOffer = errors.New("no such release has been offered")
	// ErrOffset means an upload did not start where the device's copy ends.
	ErrOffset = errors.New("upload offset does not match the bytes already received")
	// ErrTooLarge means the artifact, or the body sent for it, exceeds a limit.
	ErrTooLarge = errors.New("the artifact is larger than this device accepts")
	// ErrNoSpace means there is not enough free space to stage the release.
	ErrNoSpace = errors.New("not enough free space to stage the update")
	// ErrPending means an update is applied and awaiting confirmation; a new
	// one cannot begin until it is confirmed or undone.
	ErrPending = errors.New("an applied update is awaiting confirmation")

	errLockHeld = errors.New("another agent process holds the update lock")
)

const (
	lockFileName = "ota.lock"
	// spaceReserve is kept free beyond what the update itself needs, so
	// staging an update cannot be the thing that fills the state partition.
	spaceReserve = 8 << 20
	// superviseInterval is how often the confirmation deadline is checked.
	superviseInterval = 30 * time.Second
	// restartDelay lets the response to the request that caused a restart
	// reach the Core before the listener closes.
	restartDelay = 750 * time.Millisecond
)

// UpdaterOptions configures an Updater.
type UpdaterOptions struct {
	// Decision is what start-up produced.
	Decision Decision
	// StateDir is the agent's state directory.
	StateDir string
	// Keys describes the installed release keys, for the status page.
	Keys proto.OTAKeyStatus
	// Restart asks the process to exit so the supervisor starts it again. It
	// must return promptly. Nil means the device cannot restart itself, which
	// makes applying unsupported.
	Restart func(reason string)
	// FreeBytes overrides the free-space measurement (tests).
	FreeBytes func(dir string) (uint64, error)
	Logf      func(format string, arguments ...any)
	Now       func() time.Time
}

// Updater is safe for concurrent use.
type Updater struct {
	manager   *Manager
	installer *FileInstaller
	staging   string
	keys      proto.OTAKeyStatus
	restart   func(string)
	free      func(string) (uint64, error)
	logf      func(string, ...any)
	now       func() time.Time

	activeRelease  string
	factoryVersion string
	unsupported    string
	lock           *os.File

	mu             sync.Mutex
	offer          *offer
	restartPending bool
}

type offer struct {
	signed   proto.OTASignedManifest
	manifest proto.OTAManifest
	artifact proto.OTAArtifact
}

// NewUpdater builds the update service.
func NewUpdater(options UpdaterOptions) (*Updater, error) {
	if options.Decision.Manager == nil || options.Decision.Installer == nil || options.StateDir == "" {
		return nil, errors.New("an updater requires the start-up decision and the state directory")
	}
	logf := options.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	free := options.FreeBytes
	if free == nil {
		free = freeBytes
	}
	updater := &Updater{
		manager:        options.Decision.Manager,
		installer:      options.Decision.Installer,
		staging:        filepath.Join(options.StateDir, StagingDirName),
		keys:           options.Keys,
		restart:        options.Restart,
		free:           free,
		logf:           logf,
		now:            now,
		activeRelease:  options.Decision.ReleaseID,
		factoryVersion: options.Decision.FactoryVersion,
		unsupported:    options.Decision.Installer.UnsupportedReason(),
	}
	if updater.unsupported == "" && options.Restart == nil {
		updater.unsupported = "this agent cannot restart itself to finish an update"
	}
	if updater.unsupported == "" {
		if err := os.MkdirAll(options.StateDir, 0o700); err != nil {
			return nil, err
		}
		// One process installs at a time, across processes: a second agent
		// started by hand against the same state directory must not be able to
		// stage or switch underneath this one.
		lock, err := lockFile(filepath.Join(options.StateDir, lockFileName))
		switch {
		case err == nil:
			updater.lock = lock
		case errors.Is(err, errLockHeld):
			updater.unsupported = errLockHeld.Error()
		default:
			updater.unsupported = "the update lock could not be taken"
		}
	}
	if updater.unsupported == "" {
		updater.restoreOffer()
		// Leftovers from releases that are no longer wanted are removed at
		// start-up rather than accumulating.
		_ = updater.installer.Prune()
	}
	return updater, nil
}

// Close releases the update lock.
func (u *Updater) Close() error {
	if u == nil || u.lock == nil {
		return nil
	}
	return u.lock.Close()
}

// Supported reports whether this device can install updates.
func (u *Updater) Supported() bool { return u != nil && u.unsupported == "" }

func (u *Updater) unsupportedError() error {
	return fmt.Errorf("%w: %s", ErrUnsupported, u.unsupported)
}

// offerPath persists the offered manifest so an agent restart during a
// transfer does not force the Core to start again from nothing.
func (u *Updater) offerPath() string { return filepath.Join(u.staging, "offer.json") }

func (u *Updater) spoolPath(artifact proto.OTAArtifact) string {
	return filepath.Join(u.staging, strings.ToLower(artifact.SHA256)+".part")
}

// restoreOffer reloads a persisted offer. It is re-verified from its bytes: a
// file in the state directory is not trusted because it is there.
func (u *Updater) restoreOffer() {
	raw, err := os.ReadFile(u.offerPath())
	if err != nil || len(raw) > proto.OTAMaxManifestBytes*2 {
		return
	}
	var signed proto.OTASignedManifest
	if json.Unmarshal(raw, &signed) != nil {
		return
	}
	policy := u.manager.options.SignaturePolicy
	if policy == "" {
		policy = proto.OTASignaturePreferred
	}
	manifest, _, err := proto.VerifyManifestHybrid(signed, u.manager.options.Keyring, u.manager.options.PQKeyring, policy)
	if err != nil {
		u.discardOffer()
		return
	}
	artifact, err := agentArtifact(manifest)
	if err != nil {
		u.discardOffer()
		return
	}
	u.offer = &offer{signed: signed, manifest: manifest, artifact: artifact}
}

func (u *Updater) discardOffer() {
	if u.offer != nil {
		_ = os.Remove(u.spoolPath(u.offer.artifact))
	}
	u.offer = nil
	_ = os.Remove(u.offerPath())
	// Any other partial transfer is abandoned with it.
	if entries, err := os.ReadDir(u.staging); err == nil {
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".part") {
				_ = os.Remove(filepath.Join(u.staging, entry.Name()))
			}
		}
	}
}

// Status reports where the update machine is.
func (u *Updater) Status() proto.OTADeviceStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.statusLocked()
}

// statusLocked is Status for a caller already holding u.mu.
func (u *Updater) statusLocked() proto.OTADeviceStatus {
	status := proto.OTADeviceStatus{
		OTAStatus:         u.manager.Status(),
		UnsupportedReason: u.unsupported,
		Signatures:        u.manager.Signatures(),
		Keys:              u.keys,
		ActiveRelease:     u.activeRelease,
		FactoryVersion:    u.factoryVersion,
		RestartPending:    u.restartPending,
	}
	status.Supported = u.unsupported == ""
	if u.offer != nil && u.offer.manifest.ReleaseID == status.ReleaseID {
		status.ExpectedBytes = u.offer.artifact.Size
		switch status.State {
		case proto.OTAAvailable, proto.OTADownloading:
			if info, err := os.Stat(u.spoolPath(u.offer.artifact)); err == nil {
				status.ReceivedBytes = info.Size()
			}
		case proto.OTAStaged, proto.OTAValidating, proto.OTAReady, proto.OTAApplying, proto.OTAPendingConfirm:
			status.ReceivedBytes = u.offer.artifact.Size
		}
	}
	return status
}

// fixedManifest hands the state machine the manifest that was pushed.
type fixedManifest struct {
	signed proto.OTASignedManifest
	spool  string
	limit  int64
}

func (f fixedManifest) Manifest(context.Context, string) (proto.OTASignedManifest, error) {
	return f.signed, nil
}

func (f fixedManifest) Artifact(_ context.Context, artifact proto.OTAArtifact) ([]byte, error) {
	if artifact.Size <= 0 || artifact.Size > f.limit {
		return nil, ErrTooLarge
	}
	file, err := os.Open(f.spool)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	// Read at most one byte more than the manifest declares: enough to notice
	// a spool that is too long without reading an unbounded amount.
	content, err := io.ReadAll(io.LimitReader(file, artifact.Size+1))
	if err != nil {
		return nil, err
	}
	return content, nil
}

// Offer verifies a pushed manifest and decides whether it may be installed.
//
// Offering the release that is already offered is idempotent and keeps any
// bytes already received. Offering a different one abandons the previous offer
// and its partial transfer. Neither is possible while an applied update is
// awaiting confirmation: that update is resolved first.
func (u *Updater) Offer(ctx context.Context, signed proto.OTASignedManifest) (proto.OTAOfferResponse, error) {
	if !u.Supported() {
		return proto.OTAOfferResponse{}, u.unsupportedError()
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.restartPending {
		return proto.OTAOfferResponse{}, ErrPending
	}
	state := u.manager.snapshot().State
	switch state {
	case proto.OTAPendingConfirm, proto.OTAApplying, proto.OTARollingBack:
		return proto.OTAOfferResponse{}, ErrPending
	}
	if u.offer != nil && string(u.offer.signed.Manifest) == string(signed.Manifest) &&
		u.offer.signed.Signature == signed.Signature && u.offer.signed.PQSignature == signed.PQSignature {
		switch state {
		case proto.OTAAvailable, proto.OTAReady:
			return proto.OTAOfferResponse{Manifest: u.offer.manifest, Status: u.statusLocked()}, nil
		}
	}
	// A new offer starts from a clean machine.
	if err := u.manager.reset(); err != nil {
		return proto.OTAOfferResponse{}, err
	}
	previous := u.offer

	manifest, err := u.manager.withFetcher(fixedManifest{signed: signed}, func() (proto.OTAManifest, error) {
		return u.manager.Check(ctx, "")
	})
	if err != nil {
		return proto.OTAOfferResponse{}, err
	}
	artifact, err := agentArtifact(manifest)
	if err != nil {
		u.manager.fail(err.Error())
		return proto.OTAOfferResponse{}, err
	}
	if err := proto.ValidateOTAReleaseID(manifest.ReleaseID); err != nil {
		u.manager.fail(err.Error())
		return proto.OTAOfferResponse{}, err
	}
	if artifact.Size > proto.OTAMaxArtifactBytes {
		u.manager.fail(ErrTooLarge.Error())
		return proto.OTAOfferResponse{}, fmt.Errorf("%w: %d bytes declared, the limit is %d",
			ErrTooLarge, artifact.Size, proto.OTAMaxArtifactBytes)
	}
	if err := os.MkdirAll(u.staging, 0o700); err != nil {
		u.manager.fail("staging directory: " + err.Error())
		return proto.OTAOfferResponse{}, err
	}
	// Space for the spool and the staged copy, plus a reserve. Measured, not
	// assumed: a device whose state partition is nearly full must refuse here,
	// before the transfer, rather than fail halfway through staging.
	if available, err := u.free(u.staging); err == nil {
		needed := uint64(artifact.Size)*2 + spaceReserve
		if available < needed {
			u.manager.fail(ErrNoSpace.Error())
			return proto.OTAOfferResponse{}, fmt.Errorf("%w: %d bytes free, %d needed", ErrNoSpace, available, needed)
		}
	}

	if previous != nil && !strings.EqualFold(previous.artifact.SHA256, artifact.SHA256) {
		_ = os.Remove(u.spoolPath(previous.artifact))
	}
	u.offer = &offer{signed: signed, manifest: manifest, artifact: artifact}
	if encoded, err := json.Marshal(signed); err == nil {
		_ = writeFileSync(u.offerPath(), encoded, 0o600)
	}
	u.logf("update %s (%s) offered and accepted for transfer", manifest.ReleaseID, manifest.Version)
	return proto.OTAOfferResponse{Manifest: manifest, Status: u.statusLocked()}, nil
}

// Receive appends artifact bytes.
//
// The body must begin exactly where the device's copy ends. When the declared
// size has been reached the artifact is verified, staged and validated in the
// same call; a hash failure discards the spool, because bytes that do not add
// up to the manifest are not worth resuming.
func (u *Updater) Receive(ctx context.Context, releaseID string, offset int64, body io.Reader) (proto.OTADeviceStatus, error) {
	if !u.Supported() {
		return proto.OTADeviceStatus{}, u.unsupportedError()
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.offer == nil || u.offer.manifest.ReleaseID != releaseID {
		return u.statusLocked(), ErrNoOffer
	}
	current := u.offer
	if state := u.manager.snapshot().State; state != proto.OTAAvailable {
		if state == proto.OTAReady {
			// Already complete and validated; a retried final chunk is fine.
			return u.statusLocked(), nil
		}
		return u.statusLocked(), fmt.Errorf("%w: state is %s", ErrNotReady, state)
	}
	path := u.spoolPath(current.artifact)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return u.statusLocked(), err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return u.statusLocked(), err
	}
	have := info.Size()
	if have > current.artifact.Size {
		// A spool longer than the artifact cannot be this artifact.
		_ = file.Close()
		_ = os.Remove(path)
		return u.statusLocked(), ErrOffset
	}
	if offset != have {
		_ = file.Close()
		return u.statusLocked(), ErrOffset
	}
	remaining := current.artifact.Size - have
	if _, err := file.Seek(have, io.SeekStart); err != nil {
		_ = file.Close()
		return u.statusLocked(), err
	}
	// One byte beyond what is still owed is read, to tell "exactly the rest"
	// from "more than the rest" without accepting an unbounded body.
	written, copyErr := io.Copy(file, io.LimitReader(body, remaining+1))
	if written > remaining {
		_ = file.Truncate(have)
		_ = file.Close()
		return u.statusLocked(), fmt.Errorf("%w: more bytes were sent than the manifest declares", ErrTooLarge)
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(syncErr, closeErr); err != nil {
		return u.statusLocked(), err
	}
	if have+written < current.artifact.Size {
		// Not complete. What arrived is kept whether or not the link dropped;
		// the Core resumes from ReceivedBytes.
		if copyErr != nil {
			return u.statusLocked(), fmt.Errorf("upload interrupted: %w", copyErr)
		}
		return u.statusLocked(), nil
	}

	// Complete: hand it to the state machine, which trusts none of it yet.
	if err := u.installer.Prepare(current.manifest.ReleaseID, current.signed); err != nil {
		return u.statusLocked(), err
	}
	_, err = u.manager.withFetcher(
		fixedManifest{signed: current.signed, spool: path, limit: proto.OTAMaxArtifactBytes},
		func() (proto.OTAManifest, error) {
			return current.manifest, u.manager.Download(ctx, current.manifest)
		})
	// Whatever happened, the spool has served its purpose: the bytes are
	// either staged or wrong.
	_ = os.Remove(path)
	if err != nil {
		u.logf("update %s did not stage: %v", current.manifest.ReleaseID, err)
		return u.statusLocked(), err
	}
	u.logf("update %s is staged, validated and waiting to be applied", current.manifest.ReleaseID)
	return u.statusLocked(), nil
}

// Apply switches to the validated release and schedules the restart that makes
// it run. It names the release so that a Core applies what it was shown.
func (u *Updater) Apply(ctx context.Context, releaseID string) (proto.OTADeviceStatus, error) {
	if !u.Supported() {
		return proto.OTADeviceStatus{}, u.unsupportedError()
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.offer == nil || u.offer.manifest.ReleaseID != releaseID {
		return u.statusLocked(), ErrNoOffer
	}
	if u.restartPending {
		return u.statusLocked(), nil
	}
	if err := u.manager.Apply(ctx); err != nil {
		return u.statusLocked(), err
	}
	u.restartPending = true
	u.logf("update %s applied; restarting to run it", releaseID)
	u.scheduleRestart("update " + releaseID + " applied")
	return u.statusLocked(), nil
}

// Confirm records that the new agent works. The window for undoing closes.
func (u *Updater) Confirm(releaseID string) (proto.OTADeviceStatus, error) {
	if !u.Supported() {
		return proto.OTADeviceStatus{}, u.unsupportedError()
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	state := u.manager.snapshot()
	if state.ReleaseID != releaseID || state.ReleaseID == "" {
		return u.statusLocked(), ErrNoOffer
	}
	// Confirming means "the release that is RUNNING works". If the process
	// answering is not that release - the restart has not happened yet, or the
	// factory agent is running because the release would not start - there is
	// nothing to confirm.
	if u.activeRelease != releaseID {
		return u.statusLocked(), fmt.Errorf("%w: release %s is not the agent that is running", ErrNotReady, releaseID)
	}
	if err := u.manager.Confirm(); err != nil {
		return u.statusLocked(), err
	}
	if err := u.installer.Commit(); err != nil {
		u.logf("update confirmed; old releases could not be removed: %v", err)
	}
	u.discardOffer()
	u.logf("update %s confirmed", releaseID)
	return u.statusLocked(), nil
}

// Rollback undoes an applied, unconfirmed update and restarts into what ran
// before it.
func (u *Updater) Rollback(ctx context.Context, releaseID string) (proto.OTADeviceStatus, error) {
	if !u.Supported() {
		return proto.OTADeviceStatus{}, u.unsupportedError()
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if state := u.manager.snapshot(); state.ReleaseID != releaseID || state.ReleaseID == "" {
		return u.statusLocked(), ErrNoOffer
	}
	if err := u.manager.Rollback(ctx); err != nil {
		return u.statusLocked(), err
	}
	u.discardOffer()
	u.restartPending = true
	u.logf("update %s rolled back on request; restarting", releaseID)
	u.scheduleRestart("update " + releaseID + " rolled back")
	return u.statusLocked(), nil
}

// Supervise enforces the confirmation deadline until ctx ends.
//
// An applied update that nobody confirms is undone, and the process restarts
// into the previous agent. Without this a device that updated and then lost
// its NAS would run an unproven agent until its next reboot.
func (u *Updater) Supervise(ctx context.Context) {
	if !u.Supported() {
		return
	}
	ticker := time.NewTicker(superviseInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.ExpireNow(ctx)
		}
	}
}

// ExpireNow runs one supervision step. It reports whether an update was undone.
func (u *Updater) ExpireNow(ctx context.Context) bool {
	before := u.manager.snapshot().State
	if before != proto.OTAPendingConfirm {
		return false
	}
	if err := u.manager.ExpireUnconfirmed(ctx); err != nil {
		u.logf("an unconfirmed update could not be rolled back: %v", err)
		return false
	}
	if u.manager.snapshot().State != proto.OTARolledBack {
		return false
	}
	u.mu.Lock()
	u.discardOffer()
	already := u.restartPending
	u.restartPending = true
	u.mu.Unlock()
	u.logf("the update was not confirmed in time and has been rolled back; restarting")
	if !already {
		u.scheduleRestart("unconfirmed update rolled back")
	}
	return true
}

func (u *Updater) scheduleRestart(reason string) {
	restart := u.restart
	if restart == nil {
		return
	}
	go func() {
		time.Sleep(restartDelay)
		restart(reason)
	}()
}

// CleanStaging removes transfer leftovers. It is safe at any time no transfer
// is in progress.
func (u *Updater) CleanStaging() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	entries, err := os.ReadDir(u.staging)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	keep := ""
	if u.offer != nil {
		keep = filepath.Base(u.spoolPath(u.offer.artifact))
	}
	for _, entry := range entries {
		if entry.Name() == keep || entry.Name() == "offer.json" {
			continue
		}
		_ = os.RemoveAll(filepath.Join(u.staging, entry.Name()))
	}
	return nil
}
