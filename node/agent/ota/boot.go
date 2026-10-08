package ota

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// Start-up: deciding which agent runs.
//
// Every boot begins in the factory agent, because that is what systemd starts
// and it is the one binary on the device nothing can overwrite. Before it
// serves anything it answers one question - is there an installed release that
// should be running instead? - and if so replaces itself with it.
//
// The answer is worked out from scratch each time, from what is on disk and
// from the release keys, not from a remembered "this was fine last time":
//
//  1. Resolve the interrupted update, if there was one. An activation that was
//     cut off is undone. An activated release that is on its expected first
//     restart is allowed to run; one that has restarted again without being
//     confirmed, or whose confirmation window has closed, is undone. This is
//     the same classification ota.go describes, made here because this is the
//     process that can still choose.
//  2. Re-verify whatever release is now selected: the signed manifest stored
//     beside it against the release keys, and the binary against that
//     manifest. A release that fails is deselected, not run. Files in the
//     state directory are writable by the agent's own user, so a release is
//     never executed merely because it is there.
//  3. Run it, or carry on as the factory agent.
//
// A release may never be older than the factory agent it would replace. The
// factory agent is updated only by installing a new system image, so it is the
// floor: without that check, an old signed release left on the state partition
// would be re-selected after a system update and quietly undo it.

// BootOptions configures start-up.
type BootOptions struct {
	// StateDir is the agent's state directory.
	StateDir string
	// FactoryVersion is this (factory) agent's version.
	FactoryVersion string
	// Platform, Channel and CoreVersion are the update policy.
	Platform    proto.Platform
	Channel     proto.OTAChannel
	CoreVersion string
	// Keyring and PQKeyring are the release keys; SignaturePolicy whether a
	// classical-only release is acceptable.
	Keyring         proto.OTAKeyring
	PQKeyring       proto.OTAPQKeyring
	SignaturePolicy proto.OTASignaturePolicy
	// Chained is the release id from ChainedEnv when this process IS an
	// installed release, and empty in the factory agent.
	Chained string
	// Probe overrides how a staged binary is validated (tests).
	Probe Probe
	// InstallerUnsupported disables installing, with a reason.
	InstallerUnsupported string
	Logf                 func(format string, arguments ...any)
	Now                  func() time.Time
}

// Decision is the outcome of start-up.
type Decision struct {
	// Manager and Installer are ready for the process that goes on to serve.
	Manager   *Manager
	Installer *FileInstaller
	// Exec is the release binary to replace this process with, or empty to
	// continue as the running binary.
	Exec string
	// ReleaseID and Version describe the release that will be running, or are
	// empty for the factory agent.
	ReleaseID string
	Version   string
	// FactoryVersion is the version of the agent in the system image.
	FactoryVersion string
	// Notes are what start-up decided and why, for the log.
	Notes []string
}

// FactoryEnv carries the factory agent's version to the release it chains
// into, so the release can report what the device falls back to.
const FactoryEnv = "NSH_AGENT_FACTORY"

// VerifiedRelease is a release that passed every start-up check.
type VerifiedRelease struct {
	ID       string
	Manifest proto.OTAManifest
	Outcome  proto.OTASignatureOutcome
	Binary   string
}

// VerifyRelease checks an installed release from nothing: signature, identity,
// platform, architecture, hash, and the factory floor.
func VerifyRelease(installer *FileInstaller, id string, options BootOptions) (VerifiedRelease, error) {
	signed, err := installer.StoredManifest(id)
	if err != nil {
		return VerifiedRelease{}, fmt.Errorf("release %s has no readable manifest", id)
	}
	policy := options.SignaturePolicy
	if policy == "" {
		policy = proto.OTASignaturePreferred
	}
	manifest, outcome, err := proto.VerifyManifestHybrid(signed, options.Keyring, options.PQKeyring, policy)
	if err != nil {
		return VerifiedRelease{}, fmt.Errorf("release %s: %w", id, err)
	}
	if manifest.ReleaseID != id {
		return VerifiedRelease{}, fmt.Errorf("release directory %s holds the manifest of %q", id, manifest.ReleaseID)
	}
	if manifest.SchemaVersion != proto.OTASchemaVersion || manifest.ProtocolMajor != proto.ProtocolMajor {
		return VerifiedRelease{}, fmt.Errorf("release %s is for another schema or protocol generation", id)
	}
	if options.Platform != "" && manifest.Platform != options.Platform {
		return VerifiedRelease{}, fmt.Errorf("release %s targets %s, this device is %s", id, manifest.Platform, options.Platform)
	}
	artifact, err := agentArtifact(manifest)
	if err != nil {
		return VerifiedRelease{}, fmt.Errorf("release %s: %w", id, err)
	}
	if artifact.Arch != "" && artifact.Arch != runtime.GOARCH {
		return VerifiedRelease{}, fmt.Errorf("release %s is built for %s, this device is %s", id, artifact.Arch, runtime.GOARCH)
	}
	binary := installer.BinaryPath(id)
	digest, size, err := hashFile(binary)
	if err != nil {
		return VerifiedRelease{}, fmt.Errorf("release %s has no readable binary", id)
	}
	if size != artifact.Size || !strings.EqualFold(digest, artifact.SHA256) {
		return VerifiedRelease{}, fmt.Errorf("release %s does not match its signed manifest", id)
	}
	candidate, err := proto.ParseVersion(manifest.Version)
	if err != nil {
		return VerifiedRelease{}, fmt.Errorf("release %s has an unreadable version", id)
	}
	if factory, err := proto.ParseVersion(options.FactoryVersion); err == nil && candidate.Compare(factory) < 0 {
		return VerifiedRelease{}, fmt.Errorf("release %s (%s) is older than the system's own agent (%s)",
			id, manifest.Version, options.FactoryVersion)
	}
	return VerifiedRelease{ID: id, Manifest: manifest, Outcome: outcome, Binary: binary}, nil
}

// Boot runs the start-up decision.
//
// In the factory agent it resolves any interrupted update and names the release
// to run. In a chained release (options.Chained set) it only resumes the state
// the factory agent left, because the decision has been made and making it
// again would treat the restart the update asked for as a second, unexpected
// one.
func Boot(options BootOptions) (Decision, error) {
	if options.StateDir == "" {
		return Decision{}, errors.New("start-up requires the state directory")
	}
	logf := options.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	unsupported := options.InstallerUnsupported
	// A factory agent without a release version cannot be the floor releases
	// are measured against (see NotAReleaseVersion): it installs nothing and,
	// further down, starts nothing. A chained release is not asked: it was
	// started by a factory agent that passed this, and its own version is the
	// one its signed manifest carries.
	notARelease := ""
	if options.Chained == "" || options.Chained == probeMarker {
		notARelease = NotAReleaseVersion(options.FactoryVersion)
	}
	if unsupported == "" {
		unsupported = notARelease
	}
	if unsupported == "" && len(options.Keyring) == 0 {
		unsupported = "no release keys are installed on this device, so no update can be verified"
	}
	installer, err := NewFileInstaller(FileInstallerOptions{
		StateDir: options.StateDir, Probe: options.Probe, Unsupported: unsupported,
	})
	if err != nil {
		return Decision{}, err
	}
	decision := Decision{Installer: installer, FactoryVersion: options.FactoryVersion}
	if options.Chained != "" && options.Chained != probeMarker {
		decision.FactoryVersion = os.Getenv(FactoryEnv)
	}
	note := func(format string, arguments ...any) {
		message := fmt.Sprintf(format, arguments...)
		decision.Notes = append(decision.Notes, message)
		logf("%s", message)
	}
	managerOptions := Options{
		Dir:            options.StateDir,
		CurrentVersion: options.FactoryVersion,
		Policy: proto.OTAPolicy{
			Platform: options.Platform, Arch: runtime.GOARCH,
			Channel: options.Channel, CoreVersion: options.CoreVersion,
		},
		Keyring: options.Keyring, PQKeyring: options.PQKeyring,
		SignaturePolicy: options.SignaturePolicy,
		Installer:       installer,
		Logf:            logf,
		Now:             options.Now,
	}

	if options.Chained != "" && options.Chained != probeMarker {
		// This process is an installed release. Its own version is what is
		// running; the state is resumed, not re-judged.
		managerOptions.Resume = true
		manager, err := New(managerOptions)
		if err != nil {
			return Decision{}, err
		}
		decision.Manager = manager
		decision.ReleaseID = options.Chained
		decision.Version = options.FactoryVersion
		if active, ok := installer.Active(); !ok || active != options.Chained {
			// Started as a release that is no longer the selected one - run by
			// hand, or the selection changed underneath it. It can serve, but
			// it must not claim to be the installed release.
			note("this agent was started as release %s, which is not the selected release", options.Chained)
			decision.ReleaseID = ""
		}
		return decision, nil
	}

	// The factory agent. First: which release would run, and is it sound?
	runningVersion := options.FactoryVersion
	if active, ok := installer.Active(); ok {
		if verified, err := VerifyRelease(installer, active, options); err == nil {
			runningVersion = verified.Manifest.Version
		} else {
			note("the selected release will not be run: %v", err)
		}
	}
	// Resolve an interrupted update against the version that WOULD run. A
	// selected release that failed verification leaves this at the factory
	// version, which the classification reads as "the update did not take" and
	// undoes - the right outcome for an update whose files are bad.
	managerOptions.CurrentVersion = runningVersion
	manager, err := New(managerOptions)
	if err != nil {
		return Decision{}, err
	}
	decision.Manager = manager

	// Second: whatever is selected NOW, after recovery, is verified again
	// before it is run. Recovery may have changed the selection.
	if active, ok := installer.Active(); ok {
		verified, err := VerifyRelease(installer, active, options)
		if err != nil {
			note("release %s is deselected: %v", active, err)
			if deactivateErr := installer.Deactivate(); deactivateErr != nil {
				note("the release could not be deselected: %v", deactivateErr)
			}
		} else if notARelease != "" {
			// Verified in every way but the one that needs this agent's
			// version. It is not run and not deselected: nothing is wrong with
			// the release, and a factory agent with a version resumes it.
			note("release %s is installed but is not started: %s", verified.ID, notARelease)
		} else {
			decision.Exec = verified.Binary
			decision.ReleaseID = verified.ID
			decision.Version = verified.Manifest.Version
		}
	}
	if decision.Exec == "" && manager.CurrentVersion() != options.FactoryVersion {
		// Nothing will be chained after all, so the factory agent is what runs.
		manager.SetCurrentVersion(options.FactoryVersion)
	}
	return decision, nil
}

// Chain replaces the running factory agent with the release Boot selected.
//
// It returns only on failure. The caller then deselects the release and keeps
// running as the factory agent: a release that cannot even be executed must not
// be tried again on every start.
func Chain(decision Decision, arguments, environment []string) error {
	if decision.Exec == "" {
		return errors.New("no release was selected")
	}
	filtered := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, ChainedEnv+"=") && !strings.HasPrefix(entry, FactoryEnv+"=") {
			filtered = append(filtered, entry)
		}
	}
	filtered = append(filtered, ChainedEnv+"="+decision.ReleaseID)
	if decision.FactoryVersion != "" {
		filtered = append(filtered, FactoryEnv+"="+decision.FactoryVersion)
	}
	chained := append([]string{decision.Exec}, arguments...)
	return replaceProcess(decision.Exec, chained, filtered)
}

// replaceProcess is execReplace, as a variable so a test can observe whether
// start-up tried to run a release without the test process being replaced.
var replaceProcess = execReplace

// ChainFailed records that a selected release could not be executed, and makes
// the factory agent the one that runs.
func ChainFailed(decision Decision, factoryVersion string, cause error) {
	if decision.Installer != nil {
		_ = decision.Installer.Deactivate()
	}
	if decision.Manager != nil {
		decision.Manager.SetCurrentVersion(factoryVersion)
		decision.Manager.failedToStart(decision.ReleaseID, cause)
	}
}

// ChainedRelease reads the release id a chained agent was started as.
func ChainedRelease() string {
	value := os.Getenv(ChainedEnv)
	if value == probeMarker {
		return ""
	}
	return value
}

// IsProbe reports whether this process is a staged binary being validated.
func IsProbe() bool { return os.Getenv(ChainedEnv) == probeMarker }
