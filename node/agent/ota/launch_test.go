package ota

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// launch is Launch as a main calls it, with the exec replaced by a recorder:
// it returns what Launch returned, the updater the serving process would
// build from it, and every binary start-up tried to replace itself with.
func (f *fixture) launch(version string, disabled bool, keyFile string) (Launched, *Updater, []string) {
	f.t.Helper()
	var executed []string
	previous := replaceProcess
	replaceProcess = func(path string, _, _ []string) error {
		executed = append(executed, path)
		return errors.New("test: the process is not replaced")
	}
	defer func() { replaceProcess = previous }()
	// Launch reads the environment to learn whether it is a chained release.
	f.t.Setenv(ChainedEnv, "")
	launched, err := Launch(LaunchOptions{
		StateDir: f.stateDir, Version: version, KeyFile: keyFile, Disabled: disabled,
		Platform: proto.PlatformMSM8916, Channel: proto.OTAChannelStable,
		Arguments: []string{"-config", "/etc/nassimhub/agent.conf"}, Environment: []string{},
		Now: func() time.Time { return f.now },
	})
	if err != nil {
		f.t.Fatal(err)
	}
	updater, err := NewUpdater(UpdaterOptions{
		Decision: launched.Decision, StateDir: f.stateDir, Keys: launched.Keys,
		Restart:   func(string) {},
		FreeBytes: func(string) (uint64, error) { return f.free, nil },
		Now:       func() time.Time { return f.now },
	})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = updater.Close() })
	return launched, updater, executed
}

func (f *fixture) keyFile() string {
	f.t.Helper()
	encoded, err := EncodeKeyring(f.keyring, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	path := filepath.Join(f.t.TempDir(), "ota-keys.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		f.t.Fatal(err)
	}
	return path
}

// installConfirmed leaves a confirmed, selected release on the state directory,
// installed by a factory agent of factoryVersion.
func (f *fixture) installConfirmed(version string) built {
	f.t.Helper()
	updater, _ := f.start()
	release := f.release(version, agentBytes(version, 100), nil)
	f.deliver(updater, release)
	if _, err := updater.Apply(context.Background(), release.manifest.ReleaseID); err != nil {
		f.t.Fatal(err)
	}
	f.stop(updater)
	updater, _ = f.start()
	if _, err := updater.Confirm(release.manifest.ReleaseID); err != nil {
		f.t.Fatal(err)
	}
	f.stop(updater)
	return release
}

// The three ways updates can be off are three different things for the person
// reading the status to do, so they must not share a sentence.
func TestTheStatusSaysWhichOfTheReasonsUpdatesAreOff(t *testing.T) {
	reasons := map[string]string{}
	for name, c := range map[string]struct {
		version  string
		disabled bool
		keys     bool
		want     string
	}{
		"configuration":     {version: "1.0.0", disabled: true, keys: true, want: "updates are disabled in this agent's configuration"},
		"development build": {version: "dev", keys: true, want: `this agent is a development build (version "dev"); it cannot be updated or used as an update floor`},
		"no release keys":   {version: "1.0.0", want: "no release keys are installed on this device, so no update can be verified"},
	} {
		f := newFixture(t)
		keyFile := ""
		if c.keys {
			keyFile = f.keyFile()
		}
		_, updater, _ := f.launch(c.version, c.disabled, keyFile)
		status := updater.Status()
		if status.Supported || status.UnsupportedReason != c.want {
			t.Errorf("%s: supported=%v reason=%q, want %q", name, status.Supported, status.UnsupportedReason, c.want)
		}
		reasons[status.UnsupportedReason] = name
		_ = updater.Close()
	}
	if len(reasons) != 3 {
		t.Fatalf("the reasons are not distinguishable: %v", reasons)
	}
	// A release build with keys and updates on is none of the three.
	f := newFixture(t)
	if _, updater, _ := f.launch("1.0.0", false, f.keyFile()); !updater.Status().Supported || updater.Status().UnsupportedReason != "" {
		t.Fatalf("a release build with keys: %+v", updater.Status())
	}
}

// A factory agent whose version cannot be read as a version cannot be a floor:
// "is this release older than the system's own agent" and "is this offer older
// than what is running" have no answer. It must then behave like a development
// build - no release is run, none can be installed, and the status says why -
// instead of leaving updates on with both checks skipped.
func TestAFactoryAgentWithoutAReleaseVersionRunsAndInstallsNothing(t *testing.T) {
	for _, version := range []string{"dev", "r127-custom", "1.x", "1.2.3.4", ""} {
		t.Run("version="+version, func(t *testing.T) {
			f := newFixture(t)
			stored := f.installConfirmed("1.1.0")
			keyFile := f.keyFile()

			launched, updater, executed := f.launch(version, false, keyFile)
			if len(executed) != 0 || launched.Decision.Exec != "" || launched.Decision.ReleaseID != "" {
				t.Fatalf("a stored release was started under a factory agent with no usable version: exec=%v decision=%q", executed, launched.Decision.Exec)
			}
			status := updater.Status()
			if status.Supported || updater.Supported() {
				t.Fatalf("updates are on: %+v", status)
			}
			if !strings.Contains(status.UnsupportedReason, "cannot be updated or used as an update floor") {
				t.Fatalf("reason %q", status.UnsupportedReason)
			}
			if version != "dev" && version != "" && !strings.Contains(status.UnsupportedReason, `"`+version+`"`) {
				t.Fatalf("the reason does not name the version: %q", status.UnsupportedReason)
			}
			if strings.Contains(status.UnsupportedReason, "configuration") || strings.Contains(status.UnsupportedReason, "release keys") {
				t.Fatalf("the reason names another cause: %q", status.UnsupportedReason)
			}
			if launched.Decision.Manager.CurrentVersion() != version {
				t.Fatalf("running version %q, want the factory agent's own %q", launched.Decision.Manager.CurrentVersion(), version)
			}
			// Nothing newer, older or equal can be installed.
			for _, offered := range []string{"0.9.0", "1.1.0", "2.0.0"} {
				release := f.release(offered, agentBytes(offered, 10), nil)
				if _, err := updater.Offer(context.Background(), release.signed); !errors.Is(err, ErrUnsupported) {
					t.Fatalf("offer of %s: %v", offered, err)
				}
			}
			if _, err := updater.Apply(context.Background(), stored.manifest.ReleaseID); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("apply of the stored release: %v", err)
			}
			// The stored release is left where it is: putting a properly
			// versioned factory agent back resumes it.
			if active, ok := launched.Decision.Installer.Active(); !ok || active != stored.manifest.ReleaseID {
				t.Fatalf("the stored release was deselected (%q, %v)", active, ok)
			}
			_ = updater.Close()

			// Boot called directly reaches the same decision by itself.
			decision, err := Boot(f.bootOptions("", version))
			if err != nil {
				t.Fatal(err)
			}
			if decision.Exec != "" || decision.Installer.Supported() ||
				!strings.Contains(decision.Installer.UnsupportedReason(), "cannot be updated or used as an update floor") {
				t.Fatalf("Boot: exec=%q supported=%v reason=%q", decision.Exec, decision.Installer.Supported(), decision.Installer.UnsupportedReason())
			}
		})
	}
}

// The same device with a factory agent that has a version: nothing changes.
func TestAFactoryAgentWithAReleaseVersionStillStartsTheStoredRelease(t *testing.T) {
	for _, version := range []string{factoryVersion, "v1.0.0", "1.1.0-rc1"} {
		f := newFixture(t)
		stored := f.installConfirmed("1.1.0")
		launched, updater, executed := f.launch(version, false, f.keyFile())
		want := filepath.Join(f.stateDir, ReleasesDirName, stored.manifest.ReleaseID, BinaryName)
		if len(executed) != 1 || executed[0] != want {
			t.Fatalf("factory %s: started %v, want %s", version, executed, want)
		}
		if !updater.Status().Supported {
			t.Fatalf("factory %s: updates are off: %q", version, updater.Status().UnsupportedReason)
		}
		_ = launched
		_ = updater.Close()
	}
	// And the floor still holds for a readable factory version.
	f := newFixture(t)
	f.installConfirmed("1.1.0")
	if _, _, executed := f.launch("2.0.0", false, f.keyFile()); len(executed) != 0 {
		t.Fatalf("a release older than the factory agent was started: %v", executed)
	}
}

// A process that has just started has no post-quantum provider until someone
// registers one. Start-up verifies the stored release before anything else in
// the agent has run, so Launch must not depend on a later part of the agent
// (nodeserver.New) having registered it: under the REQUIRED policy a correctly
// dual-signed, confirmed release would fail verification at the first restart
// and be rolled back, and the device could never keep an update.
//
// The release is installed with the provider registered, as the serving agent
// has it; the registry is then emptied, which is the state every new process
// starts in; and Launch is called the way both mains call it.
func TestStartUpVerifiesADualSignedReleaseBeforeAnythingElseEnabledTheProvider(t *testing.T) {
	if !proto.StandardPQSupported() {
		t.Skip("this toolchain has no crypto/mldsa")
	}
	newProcess := func() { proto.RegisterPQProvider(nil); proto.SetPQBackendName("none") }
	t.Cleanup(newProcess)
	seed, _ := proto.NewMLDSASeed()
	signer, err := proto.NewMLDSASigner(proto.PQSigMLDSA87, seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range []proto.OTASignaturePolicy{proto.OTASignatureRequired, proto.OTASignaturePreferred} {
		f := newFixture(t)
		f.policy, f.pq = policy, signer
		f.pqKeys = proto.OTAPQKeyring{"release-pq-1": signer.Identity()}
		proto.EnableStandardPQ() // the serving agent that received the update had it
		stored := f.installConfirmed("1.1.0")
		if stored.signed.PQSignature == "" {
			t.Fatal("the fixture did not dual-sign")
		}
		encoded, err := EncodeKeyring(f.keyring, f.pqKeys)
		if err != nil {
			t.Fatal(err)
		}
		keyFile := filepath.Join(t.TempDir(), "ota-keys.json")
		if err := os.WriteFile(keyFile, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(f.stateDir, ReleasesDirName, stored.manifest.ReleaseID, BinaryName)

		// Two restarts: the release must still be the one started at the second.
		for restart := 1; restart <= 2; restart++ {
			newProcess()
			var executed, logged []string
			// A successful exec does not return. The recorder stands in for
			// that by unwinding out of Launch, so nothing after the exec runs
			// - in particular not the "could not be started" path.
			type replaced struct{}
			func() {
				previous := replaceProcess
				defer func() {
					replaceProcess = previous
					if recovered := recover(); recovered != nil {
						if _, ok := recovered.(replaced); !ok {
							panic(recovered)
						}
					}
				}()
				replaceProcess = func(path string, _, _ []string) error {
					executed = append(executed, path)
					panic(replaced{})
				}
				t.Setenv(ChainedEnv, "")
				if _, err := Launch(LaunchOptions{
					StateDir: f.stateDir, Version: factoryVersion, KeyFile: keyFile, SignaturePolicy: policy,
					Platform: proto.PlatformMSM8916, Channel: proto.OTAChannelStable, Environment: []string{},
					Logf: func(format string, arguments ...any) { logged = append(logged, fmt.Sprintf(format, arguments...)) },
					Now:  func() time.Time { return f.now },
				}); err != nil {
					t.Fatal(err)
				}
			}()
			if len(executed) != 1 || executed[0] != want {
				t.Fatalf("%s, restart %d: start-up did not run the dual-signed release (started %v): %s", policy, restart, executed, strings.Join(logged, "; "))
			}
			if !proto.PQIdentityAvailable() {
				t.Fatalf("%s: Launch left the process without a post-quantum provider", policy)
			}
			installer, err := NewFileInstaller(FileInstallerOptions{StateDir: f.stateDir, Probe: f.probe})
			if err != nil {
				t.Fatal(err)
			}
			if active, ok := installer.Active(); !ok || active != stored.manifest.ReleaseID {
				t.Fatalf("%s, restart %d: the release is no longer selected (%q, %v): %s", policy, restart, active, ok, strings.Join(logged, "; "))
			}
			// What start-up established is what the signed manifest carries:
			// both signatures, under either policy.
			verified, err := VerifyRelease(installer, stored.manifest.ReleaseID, BootOptions{
				StateDir: f.stateDir, FactoryVersion: factoryVersion, Platform: proto.PlatformMSM8916,
				Keyring: f.keyring, PQKeyring: f.pqKeys, SignaturePolicy: policy,
			})
			if err != nil || verified.Outcome != proto.OTADualSigned {
				t.Fatalf("%s, restart %d: verification after Launch: %+v %v", policy, restart, verified.Outcome, err)
			}
		}
	}
}
