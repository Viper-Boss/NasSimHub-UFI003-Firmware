package ota

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

const (
	runningVersion = "1.0.0"
	newVersion     = "1.1.0"
)

type release struct {
	signed    proto.OTASignedManifest
	manifest  proto.OTAManifest
	content   []byte
	keyring   proto.OTAKeyring
	publicKey ed25519.PublicKey
	secretKey ed25519.PrivateKey
}

func newRelease(t *testing.T, version string, edit func(*proto.OTAManifest)) release {
	t.Helper()

	public, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("#!/bin/false\nnassimhub-agent " + version + "\n")
	manifest := proto.OTAManifest{
		SchemaVersion:  proto.OTASchemaVersion,
		ReleaseID:      "rel-" + version,
		Version:        version,
		Channel:        proto.OTAChannelStable,
		Platform:       proto.PlatformMSM8916,
		ReleasedAt:     time.Now().UTC(),
		ProtocolMajor:  proto.ProtocolMajor,
		ProtocolMinor:  proto.ProtocolMinor,
		MinCoreVersion: "0.1.0",
		Artifacts: []proto.OTAArtifact{{
			Kind:   proto.OTAArtifactAgent,
			Name:   "nassimhub-agent",
			SHA256: proto.ArtifactDigest(content),
			Size:   int64(len(content)),
			URL:    "https://example.invalid/nassimhub-agent",
			Arch:   "arm64",
		}},
	}
	if edit != nil {
		edit(&manifest)
	}
	signed, err := proto.SignManifest(manifest, "release-1", secret)
	if err != nil {
		t.Fatal(err)
	}
	return release{
		signed:    signed,
		manifest:  manifest,
		content:   content,
		keyring:   proto.OTAKeyring{"release-1": public},
		publicKey: public,
		secretKey: secret,
	}
}

func newManager(t *testing.T, r release, install *MockInstaller, tune func(*MemoryFetcher)) *Manager {
	t.Helper()

	fetcher := &MemoryFetcher{
		Signed:    r.signed,
		Artifacts: map[string][]byte{"nassimhub-agent": r.content},
	}
	if tune != nil {
		tune(fetcher)
	}
	manager, err := New(Options{
		Dir:            t.TempDir(),
		CurrentVersion: runningVersion,
		Policy: proto.OTAPolicy{
			Platform: proto.PlatformMSM8916,
			Arch:     "arm64",
			Channel:  proto.OTAChannelStable,
		},
		Keyring:   r.keyring,
		Fetcher:   fetcher,
		Installer: install,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

// ---------------------------------------------------------------------------
// Signing and hashing
// ---------------------------------------------------------------------------

func TestASignedManifestVerifies(t *testing.T) {
	t.Parallel()

	r := newRelease(t, newVersion, nil)
	manifest, err := proto.VerifyManifest(r.signed, r.keyring)
	if err != nil {
		t.Fatalf("a manifest we signed did not verify: %v", err)
	}
	if manifest.Version != newVersion {
		t.Fatalf("version is %q", manifest.Version)
	}
}

// Editing a manifest after signing must invalidate it, and this is the check
// that makes the signature worth having.
func TestATamperedManifestIsRefused(t *testing.T) {
	t.Parallel()

	r := newRelease(t, newVersion, nil)
	var manifest proto.OTAManifest
	if err := json.Unmarshal(r.signed.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	// An attacker who can rewrite the manifest points the download elsewhere.
	manifest.Artifacts[0].URL = "https://attacker.invalid/agent"
	rewritten, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	tampered := r.signed
	tampered.Manifest = rewritten

	if _, err := proto.VerifyManifest(tampered, r.keyring); !errors.Is(err, proto.ErrOTAUnsigned) {
		t.Fatalf("a rewritten manifest produced %v", err)
	}
}

func TestAManifestSignedByAnotherKeyIsRefused(t *testing.T) {
	t.Parallel()

	genuine := newRelease(t, newVersion, nil)
	attacker := newRelease(t, "9.9.9", nil)

	// The attacker signs their own manifest with their own key and presents it
	// under the key id the device trusts.
	forged := attacker.signed
	forged.KeyID = "release-1"
	if _, err := proto.VerifyManifest(forged, genuine.keyring); !errors.Is(err, proto.ErrOTAUnsigned) {
		t.Fatalf("a manifest signed by an unknown key produced %v", err)
	}

	// And an unknown key id is refused outright.
	unknown := genuine.signed
	unknown.KeyID = "release-99"
	if _, err := proto.VerifyManifest(unknown, genuine.keyring); !errors.Is(err, proto.ErrOTAUnsigned) {
		t.Fatalf("an unknown key id produced %v", err)
	}
}

func TestArtifactHashesAreEnforced(t *testing.T) {
	t.Parallel()

	r := newRelease(t, newVersion, nil)
	artifact := r.manifest.Artifacts[0]

	if err := proto.VerifyArtifact(artifact, r.content); err != nil {
		t.Fatalf("the genuine artifact did not verify: %v", err)
	}
	corrupted := append([]byte(nil), r.content...)
	corrupted[0] ^= 0xFF
	if err := proto.VerifyArtifact(artifact, corrupted); !errors.Is(err, proto.ErrOTAHash) {
		t.Fatalf("a corrupted artifact produced %v", err)
	}
	if err := proto.VerifyArtifact(artifact, r.content[:len(r.content)-1]); !errors.Is(err, proto.ErrOTAHash) {
		t.Fatalf("a truncated artifact produced %v", err)
	}
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

func TestDowngradesAreRefusedByDefault(t *testing.T) {
	t.Parallel()

	older := newRelease(t, "0.9.0", nil)
	policy := proto.OTAPolicy{
		Platform:       proto.PlatformMSM8916,
		Arch:           "arm64",
		Channel:        proto.OTAChannelStable,
		CurrentVersion: runningVersion,
	}
	if err := proto.CheckManifest(older.manifest, policy); !errors.Is(err, proto.ErrOTARejected) {
		t.Fatalf("a downgrade was accepted: %v", err)
	}

	// An operator holding the device can still do it deliberately.
	policy.AllowDowngrade = true
	if err := proto.CheckManifest(older.manifest, policy); err != nil {
		t.Fatalf("an explicitly permitted downgrade was refused: %v", err)
	}
}

func TestTheRunningVersionIsNotReinstalled(t *testing.T) {
	t.Parallel()

	same := newRelease(t, runningVersion, nil)
	err := proto.CheckManifest(same.manifest, proto.OTAPolicy{
		Platform: proto.PlatformMSM8916, Arch: "arm64",
		Channel: proto.OTAChannelStable, CurrentVersion: runningVersion,
	})
	if !errors.Is(err, proto.ErrOTARejected) {
		t.Fatalf("reinstalling the running version produced %v", err)
	}
}

// An update that would make the device unusable with its NAS is refused. To the
// owner, a device that vanishes from the UI after an update is a brick.
func TestAnUpdateThatWouldOrphanTheDeviceIsRefused(t *testing.T) {
	t.Parallel()

	crossGeneration := newRelease(t, "2.0.0", func(m *proto.OTAManifest) {
		m.ProtocolMajor = proto.ProtocolMajor + 1
	})
	err := proto.CheckManifest(crossGeneration.manifest, proto.OTAPolicy{
		Platform: proto.PlatformMSM8916, Arch: "arm64",
		Channel: proto.OTAChannelStable, CurrentVersion: runningVersion,
	})
	if !errors.Is(err, proto.ErrOTARejected) {
		t.Fatalf("a protocol-breaking update produced %v", err)
	}

	needsNewerCore := newRelease(t, "1.5.0", func(m *proto.OTAManifest) {
		m.MinCoreVersion = "3.0.0"
	})
	err = proto.CheckManifest(needsNewerCore.manifest, proto.OTAPolicy{
		Platform: proto.PlatformMSM8916, Arch: "arm64",
		Channel: proto.OTAChannelStable, CurrentVersion: runningVersion,
		CoreVersion: "1.0.0",
	})
	if !errors.Is(err, proto.ErrOTARejected) {
		t.Fatalf("an update needing a newer NAS produced %v", err)
	}
}

func TestOnlyAgentArtifactsAreInstallable(t *testing.T) {
	t.Parallel()

	// The kinds that must never be installable. None of these has a constant
	// in the protocol, which is the primary defence; this checks the secondary
	// one, in case a manifest carries the string anyway.
	for _, forbidden := range []string{"boot", "rootfs", "modem", "dtb", "persist", "fsg"} {
		r := newRelease(t, "1.5.0", func(m *proto.OTAManifest) {
			m.Artifacts[0].Kind = proto.OTAArtifactKind(forbidden)
		})
		err := proto.CheckManifest(r.manifest, proto.OTAPolicy{
			Platform: proto.PlatformMSM8916, Arch: "arm64",
			Channel: proto.OTAChannelStable, CurrentVersion: runningVersion,
		})
		if !errors.Is(err, proto.ErrOTARejected) {
			t.Fatalf("an artifact of kind %q was accepted: %v", forbidden, err)
		}
	}
}

func TestAnArtifactCannotNameAPath(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"../../etc/passwd", "/usr/bin/agent", `..\windows`, ""} {
		r := newRelease(t, "1.5.0", func(m *proto.OTAManifest) {
			m.Artifacts[0].Name = name
		})
		err := proto.CheckManifest(r.manifest, proto.OTAPolicy{
			Platform: proto.PlatformMSM8916, Arch: "arm64",
			Channel: proto.OTAChannelStable, CurrentVersion: runningVersion,
		})
		if !errors.Is(err, proto.ErrOTARejected) {
			t.Fatalf("artifact name %q was accepted: %v", name, err)
		}
	}
}

func TestTheWrongPlatformOrArchIsRefused(t *testing.T) {
	t.Parallel()

	r := newRelease(t, "1.5.0", nil)
	wrongPlatform := proto.OTAPolicy{
		Platform: proto.PlatformMock, Arch: "arm64",
		Channel: proto.OTAChannelStable, CurrentVersion: runningVersion,
	}
	if err := proto.CheckManifest(r.manifest, wrongPlatform); !errors.Is(err, proto.ErrOTARejected) {
		t.Fatalf("a manifest for another platform produced %v", err)
	}
	wrongArch := proto.OTAPolicy{
		Platform: proto.PlatformMSM8916, Arch: "amd64",
		Channel: proto.OTAChannelStable, CurrentVersion: runningVersion,
	}
	if err := proto.CheckManifest(r.manifest, wrongArch); !errors.Is(err, proto.ErrOTARejected) {
		t.Fatalf("a manifest for another architecture produced %v", err)
	}
}

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

// The one transition that must not exist: anything reaching APPLYING without
// passing through READY, which is the only state that means "validated".
func TestNothingReachesApplyingWithoutValidation(t *testing.T) {
	t.Parallel()

	for _, from := range proto.OTAStates() {
		if from == proto.OTAReady {
			continue
		}
		if proto.OTACanTransition(from, proto.OTAApplying) {
			t.Fatalf("%s can transition straight to APPLYING, skipping validation", from)
		}
	}
	if !proto.OTACanTransition(proto.OTAReady, proto.OTAApplying) {
		t.Fatal("READY cannot reach APPLYING; no update could ever be installed")
	}
}

func TestTheHappyPath(t *testing.T) {
	t.Parallel()

	r := newRelease(t, newVersion, nil)
	install := NewMockInstaller(t.TempDir(), runningVersion)
	install.SupportedValue = true
	manager := newManager(t, r, install, nil)

	ctx := context.Background()
	manifest, err := manager.Check(ctx, "https://example.invalid/manifest.json")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if manager.Status().State != proto.OTAAvailable {
		t.Fatalf("state after check is %s", manager.Status().State)
	}
	if err := manager.Download(ctx, manifest); err != nil {
		t.Fatalf("download: %v", err)
	}
	if manager.Status().State != proto.OTAReady {
		t.Fatalf("state after download is %s", manager.Status().State)
	}
	// The running binary must still be the old one at this point.
	if install.InstalledVersion() != runningVersion {
		t.Fatalf("the binary was replaced before apply: %s", install.InstalledVersion())
	}

	if err := manager.Apply(ctx); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if manager.Status().State != proto.OTAPendingConfirm {
		t.Fatalf("state after apply is %s", manager.Status().State)
	}
	if err := manager.Confirm(); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	status := manager.Status()
	if status.State != proto.OTAIdle || status.Progress != 100 {
		t.Fatalf("state after confirm is %+v", status)
	}
}

// Every failure before the swap must leave the running binary alone. This is
// the property that makes the whole thing safe to ship.
func TestEveryPreSwapFailureLeavesTheDeviceRunning(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		tune    func(*MemoryFetcher)
		install func(*MockInstaller)
	}{
		{name: "manifest unreachable", tune: func(f *MemoryFetcher) {
			f.ManifestError = errors.New("connection refused")
		}},
		{name: "artifact unreachable", tune: func(f *MemoryFetcher) {
			f.ArtifactError = errors.New("connection reset")
		}},
		{name: "artifact corrupted", tune: func(f *MemoryFetcher) { f.Corrupt = true }},
		{name: "artifact truncated", tune: func(f *MemoryFetcher) { f.Truncate = true }},
		{name: "staging fails", install: func(i *MockInstaller) {
			i.FailStage = errors.New("no space left on device")
		}},
		{name: "validation fails", install: func(i *MockInstaller) {
			i.ValidateVersion = "0.0.1"
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			r := newRelease(t, newVersion, nil)
			install := NewMockInstaller(t.TempDir(), runningVersion)
			install.SupportedValue = true
			if testCase.install != nil {
				testCase.install(install)
			}
			manager := newManager(t, r, install, testCase.tune)

			ctx := context.Background()
			manifest, err := manager.Check(ctx, "https://example.invalid/manifest.json")
			if err == nil {
				err = manager.Download(ctx, manifest)
			}
			if err == nil {
				t.Fatal("the failure was not reported")
			}
			if install.InstalledVersion() != runningVersion {
				t.Fatalf("the running binary changed to %s despite %s",
					install.InstalledVersion(), testCase.name)
			}
			if state := manager.Status().State; state == proto.OTAApplying ||
				state == proto.OTAPendingConfirm {
				t.Fatalf("state is %s after a pre-swap failure", state)
			}
		})
	}
}

func TestAFailedActivationRollsBack(t *testing.T) {
	t.Parallel()

	r := newRelease(t, newVersion, nil)
	install := NewMockInstaller(t.TempDir(), runningVersion)
	install.SupportedValue = true
	install.ValidateVersion = newVersion
	manager := newManager(t, r, install, nil)

	ctx := context.Background()
	manifest, err := manager.Check(ctx, "u")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Download(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	install.FailActivate = errors.New("could not replace the binary")

	if err := manager.Apply(ctx); err == nil {
		t.Fatal("a failed activation was reported as success")
	}
	if state := manager.Status().State; state != proto.OTARolledBack {
		t.Fatalf("state after a failed activation is %s", state)
	}
	if install.InstalledVersion() != runningVersion {
		t.Fatalf("the running binary is %s after a failed activation", install.InstalledVersion())
	}
}

// The important recovery case: the device restarted after the swap and before
// anything confirmed the new binary works.
func TestARestartBeforeConfirmRollsBack(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	r := newRelease(t, newVersion, nil)
	install := NewMockInstaller(filepath.Join(directory, "staging"), runningVersion)
	install.SupportedValue = true
	install.ValidateVersion = newVersion

	fetcher := &MemoryFetcher{
		Signed:    r.signed,
		Artifacts: map[string][]byte{"nassimhub-agent": r.content},
	}
	options := Options{
		Dir:            directory,
		CurrentVersion: runningVersion,
		Policy: proto.OTAPolicy{
			Platform: proto.PlatformMSM8916, Arch: "arm64", Channel: proto.OTAChannelStable,
		},
		Keyring:   r.keyring,
		Fetcher:   fetcher,
		Installer: install,
	}
	manager, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	manifest, err := manager.Check(ctx, "u")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Download(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if install.InstalledVersion() != newVersion {
		t.Fatalf("after apply the binary is %s", install.InstalledVersion())
	}

	// The device restarts. A new Manager reads the state file left behind.
	recovered, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	if state := recovered.Status().State; state != proto.OTARolledBack {
		t.Fatalf("after a restart in PENDING_CONFIRM the state is %s, want ROLLED_BACK", state)
	}
	if install.InstalledVersion() != runningVersion {
		t.Fatalf("the previous binary was not restored: running %s", install.InstalledVersion())
	}
}

// A restart with verified bytes staged but nothing applied must not roll
// anything back - there is nothing to undo, and the device is fine.
func TestARestartWhileStagedChangesNothing(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	r := newRelease(t, newVersion, nil)
	install := NewMockInstaller(filepath.Join(directory, "staging"), runningVersion)
	install.SupportedValue = true
	install.ValidateVersion = newVersion
	options := Options{
		Dir:            directory,
		CurrentVersion: runningVersion,
		Policy: proto.OTAPolicy{
			Platform: proto.PlatformMSM8916, Arch: "arm64", Channel: proto.OTAChannelStable,
		},
		Keyring: r.keyring,
		Fetcher: &MemoryFetcher{
			Signed:    r.signed,
			Artifacts: map[string][]byte{"nassimhub-agent": r.content},
		},
		Installer: install,
	}
	manager, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := manager.Check(context.Background(), "u")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Download(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}

	recovered, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	if state := recovered.Status().State; state != proto.OTAIdle {
		t.Fatalf("after a restart while staged the state is %s, want IDLE", state)
	}
	if install.InstalledVersion() != runningVersion {
		t.Fatalf("a staged-only update changed the running binary to %s",
			install.InstalledVersion())
	}
}

// A half-written state file must read as no state, not as a state that sends
// the device down a recovery path chosen by whatever bytes survived.
func TestACorruptStateFileResolvesToIdle(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, StateFileName),
		[]byte(`{"state":"PENDING_CON`), 0o600); err != nil {
		t.Fatal(err)
	}
	install := NewMockInstaller(filepath.Join(directory, "staging"), runningVersion)
	manager, err := New(Options{
		Dir: directory, CurrentVersion: runningVersion, Installer: install,
	})
	if err != nil {
		t.Fatal(err)
	}
	if state := manager.Status().State; state != proto.OTAIdle {
		t.Fatalf("a truncated state file resolved to %s", state)
	}
}

// A release that keeps failing must stop being retried, or a device on a
// metered link downloads it forever.
func TestARepeatedlyFailingReleaseStopsBeingRetried(t *testing.T) {
	t.Parallel()

	r := newRelease(t, newVersion, nil)
	install := NewMockInstaller(t.TempDir(), runningVersion)
	install.SupportedValue = true
	manager := newManager(t, r, install, func(f *MemoryFetcher) { f.Corrupt = true })

	ctx := context.Background()
	for attempt := 1; attempt <= MaxAttempts; attempt++ {
		manifest, err := manager.Check(ctx, "u")
		if err != nil {
			t.Fatalf("check on attempt %d: %v", attempt, err)
		}
		if err := manager.Download(ctx, manifest); err == nil {
			t.Fatalf("a corrupted download succeeded on attempt %d", attempt)
		}
	}
	if _, err := manager.Check(ctx, "u"); err == nil {
		t.Fatalf("the release was offered again after %d failures", MaxAttempts)
	}
	if status := manager.Status(); status.Attempts < MaxAttempts {
		t.Fatalf("attempts counted %d", status.Attempts)
	}
}

// The shipped installer must report that it cannot install, so nothing offers
// the action in this stage.
func TestTheShippedInstallerIsNotSupported(t *testing.T) {
	t.Parallel()

	install := NewMockInstaller(t.TempDir(), runningVersion)
	if install.Supported() {
		t.Fatal("the mock installer claims it can install")
	}
	manager, err := New(Options{
		Dir: t.TempDir(), CurrentVersion: runningVersion, Installer: install,
	})
	if err != nil {
		t.Fatal(err)
	}
	if manager.Status().Supported {
		t.Fatal("the status says updates are supported on a build with no installer")
	}
}

func TestApplyingWithoutValidationIsRefused(t *testing.T) {
	t.Parallel()

	r := newRelease(t, newVersion, nil)
	install := NewMockInstaller(t.TempDir(), runningVersion)
	install.SupportedValue = true
	manager := newManager(t, r, install, nil)

	if err := manager.Apply(context.Background()); !errors.Is(err, ErrNotReady) {
		t.Fatalf("applying from IDLE produced %v", err)
	}
	if _, err := manager.Check(context.Background(), "u"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background()); !errors.Is(err, ErrNotReady) {
		t.Fatalf("applying from AVAILABLE produced %v", err)
	}
	if install.InstalledVersion() != runningVersion {
		t.Fatal("a premature apply changed the running binary")
	}
}

// ---------------------------------------------------------------------------
// Restart classification
// ---------------------------------------------------------------------------

// restartable builds a Manager whose options can be reused to simulate the
// process starting again.
func restartable(t *testing.T, r release, install *MockInstaller, runningVersion string) (Options, *Manager) {
	t.Helper()
	options := Options{
		Dir:            t.TempDir(),
		CurrentVersion: runningVersion,
		Policy: proto.OTAPolicy{
			Platform: proto.PlatformMSM8916, Arch: "arm64", Channel: proto.OTAChannelStable,
		},
		Keyring: r.keyring,
		Fetcher: &MemoryFetcher{
			Signed:    r.signed,
			Artifacts: map[string][]byte{"nassimhub-agent": r.content},
		},
		Installer: install,
	}
	manager, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return options, manager
}

func applyAnUpdate(t *testing.T, manager *Manager) {
	t.Helper()
	ctx := context.Background()
	manifest, err := manager.Check(ctx, "u")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if err := manager.Download(ctx, manifest); err != nil {
		t.Fatalf("download: %v", err)
	}
	if err := manager.Apply(ctx); err != nil {
		t.Fatalf("apply: %v", err)
	}
}

// The requirement that matters most here: the ordinary systemd restart that an
// update causes must NOT be read as the update failing.
//
// Getting this wrong produces a device that rolls back every update it ever
// applies, which looks from the outside like an update system that works and
// never changes anything.
func TestTheRestartAnUpdateCausesIsNotAFailure(t *testing.T) {
	t.Parallel()

	r := newRelease(t, newVersion, nil)
	install := NewMockInstaller(t.TempDir(), runningVersion)
	install.SupportedValue = true
	install.ValidateVersion = newVersion

	options, manager := restartable(t, r, install, runningVersion)
	applyAnUpdate(t, manager)
	if install.InstalledVersion() != newVersion {
		t.Fatalf("after apply the binary is %s", install.InstalledVersion())
	}

	// systemd restarts the service. The NEW binary comes up, so the process
	// reports the new version.
	options.CurrentVersion = newVersion
	restarted, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	status := restarted.Status()
	if status.State != proto.OTAPendingConfirm {
		t.Fatalf("the expected restart left the state at %s, want PENDING_CONFIRM; "+
			"an update that rolls back on its own restart can never take effect",
			status.State)
	}
	if status.RestartReason != proto.OTARestartExpected {
		t.Fatalf("the restart was classified as %q", status.RestartReason)
	}
	if install.InstalledVersion() != newVersion {
		t.Fatalf("the expected restart rolled the binary back to %s", install.InstalledVersion())
	}

	// And the new binary then confirms itself.
	if err := restarted.Confirm(); err != nil {
		t.Fatalf("confirm after the expected restart: %v", err)
	}
	if final := restarted.Status(); final.State != proto.OTAIdle {
		t.Fatalf("state after confirm is %s", final.State)
	}
	if install.InstalledVersion() != newVersion {
		t.Fatalf("the confirmed update is not installed: %s", install.InstalledVersion())
	}
}

// A SECOND restart before confirmation means the new binary came up and then
// died. That is a failure, and it must roll back.
func TestASecondRestartBeforeConfirmRollsBack(t *testing.T) {
	t.Parallel()

	r := newRelease(t, newVersion, nil)
	install := NewMockInstaller(t.TempDir(), runningVersion)
	install.SupportedValue = true
	install.ValidateVersion = newVersion

	options, manager := restartable(t, r, install, runningVersion)
	applyAnUpdate(t, manager)

	options.CurrentVersion = newVersion
	first, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status().RestartReason != proto.OTARestartExpected {
		t.Fatalf("the first restart was classified as %q", first.Status().RestartReason)
	}

	// It crashes and systemd starts it again.
	second, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	status := second.Status()
	if status.State != proto.OTARolledBack {
		t.Fatalf("a second unconfirmed restart left the state at %s", status.State)
	}
	if status.RestartReason != proto.OTARestartUnexpected {
		t.Fatalf("the second restart was classified as %q", status.RestartReason)
	}
	if install.InstalledVersion() != runningVersion {
		t.Fatalf("the previous binary was not restored: %s", install.InstalledVersion())
	}
	if status.Error == "" {
		t.Fatal("the rollback has no explanation for the user")
	}
}

// If the process that comes up is the OLD version, the swap did not take.
// There is nothing to wait for.
func TestARestartIntoTheOldVersionRollsBack(t *testing.T) {
	t.Parallel()

	r := newRelease(t, newVersion, nil)
	install := NewMockInstaller(t.TempDir(), runningVersion)
	install.SupportedValue = true
	install.ValidateVersion = newVersion

	options, manager := restartable(t, r, install, runningVersion)
	applyAnUpdate(t, manager)

	// The old binary comes back up - the swap was undone by something outside
	// this process, or never really happened.
	restarted, err := New(options) // CurrentVersion is still runningVersion
	if err != nil {
		t.Fatal(err)
	}
	status := restarted.Status()
	if status.RestartReason != proto.OTARestartWrongVersion {
		t.Fatalf("a restart into the old version was classified as %q", status.RestartReason)
	}
	if status.State != proto.OTARolledBack {
		t.Fatalf("state is %s", status.State)
	}
}

// A new binary that runs and never confirms is rolled back when the window
// closes, without waiting for a restart that might never come.
func TestAnUnconfirmedUpdateExpires(t *testing.T) {
	t.Parallel()

	r := newRelease(t, newVersion, nil)
	install := NewMockInstaller(t.TempDir(), runningVersion)
	install.SupportedValue = true
	install.ValidateVersion = newVersion

	now := time.Now()
	options, _ := restartable(t, r, install, runningVersion)
	options.Now = func() time.Time { return now }
	manager, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	applyAnUpdate(t, manager)

	// Inside the window: nothing happens.
	if err := manager.ExpireUnconfirmed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if manager.Status().State != proto.OTAPendingConfirm {
		t.Fatalf("an update inside its window was expired early: %s", manager.Status().State)
	}

	// Past it: rolled back, with a reason that names the cause.
	now = now.Add(proto.OTAConfirmWindow + time.Minute)
	if err := manager.ExpireUnconfirmed(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := manager.Status()
	if status.State != proto.OTARolledBack {
		t.Fatalf("an update past its confirmation window is in state %s", status.State)
	}
	if status.RestartReason != proto.OTAConfirmTimeout {
		t.Fatalf("the reason is %q", status.RestartReason)
	}
	if install.InstalledVersion() != runningVersion {
		t.Fatalf("the binary was not restored: %s", install.InstalledVersion())
	}
}

// A health check that fails is distinguishable from a manual rollback and from
// a timeout, because they mean different things to whoever reads the status.
func TestAFailedHealthCheckIsItsOwnReason(t *testing.T) {
	t.Parallel()

	r := newRelease(t, newVersion, nil)
	install := NewMockInstaller(t.TempDir(), runningVersion)
	install.SupportedValue = true
	install.ValidateVersion = newVersion

	_, manager := restartable(t, r, install, runningVersion)
	applyAnUpdate(t, manager)

	if err := manager.HealthCheckFailed(context.Background(),
		"the new agent could not open its state directory"); err != nil {
		t.Fatalf("health check failure: %v", err)
	}
	status := manager.Status()
	if status.State != proto.OTARolledBack {
		t.Fatalf("state is %s", status.State)
	}
	if status.RestartReason != proto.OTAHealthFailed {
		t.Fatalf("the reason is %q", status.RestartReason)
	}
	if install.InstalledVersion() != runningVersion {
		t.Fatal("the binary was not restored after a failed health check")
	}
}

// Every reason except the expected restart must roll back. This is the table
// the classification exists to serve, stated once.
func TestOnlyTheExpectedRestartAvoidsRollback(t *testing.T) {
	t.Parallel()

	rollsBack := map[proto.OTARestartReason]bool{
		proto.OTARestartExpected:     false,
		proto.OTARestartNone:         false,
		proto.OTARestartUnexpected:   true,
		proto.OTARestartWrongVersion: true,
		proto.OTAConfirmTimeout:      true,
		proto.OTAHealthFailed:        true,
	}
	for reason, want := range rollsBack {
		if got := reason.RollsBack(); got != want {
			t.Fatalf("%q.RollsBack() = %t, want %t", reason, got, want)
		}
	}
}
