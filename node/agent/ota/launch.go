package ota

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// LaunchOptions is what a binary's main knows at start-up.
type LaunchOptions struct {
	// StateDir is the agent's state directory.
	StateDir string
	// Version is THIS binary's version.
	Version string
	// KeyFile is the release key file; empty uses no keys.
	KeyFile string
	// Platform and Channel are the update policy.
	Platform proto.Platform
	Channel  proto.OTAChannel
	// SignaturePolicy is whether a classical-only release is acceptable.
	SignaturePolicy proto.OTASignaturePolicy
	// Arguments and Environment are passed to a release this process chains
	// into.
	Arguments   []string
	Environment []string
	// Disabled turns the update mechanism off entirely: nothing is chained and
	// nothing can be installed. It is the operator's switch (updates = false);
	// a binary whose Version is not a release version is treated the same way
	// by Launch itself, with its own reason, and need not be reported here.
	Disabled bool
	Logf     func(format string, arguments ...any)
	Now      func() time.Time
}

// Launched is the result of start-up for the process that goes on to serve.
type Launched struct {
	Decision Decision
	Keys     proto.OTAKeyStatus
}

// Launch is the one call a main makes before it starts serving.
//
// In the factory agent it works out which agent should run and, when that is
// an installed release, replaces this process with it - in which case Launch
// does not return. In every other case it returns the state the serving
// process needs: the factory agent with nothing installed, the factory agent
// after a release failed to start, or an installed release that has just been
// chained into.
//
// It never fails start-up because of the update mechanism. A device whose
// release key file is unreadable, or whose state directory cannot hold a
// release, still starts and still answers its NAS; it reports that updates are
// unavailable and why. An updater that could stop the agent from starting
// would be a new way to lose the device.
func Launch(options LaunchOptions) (Launched, error) {
	// The post-quantum provider, before anything is verified. Start-up checks
	// the stored release's signatures further down, and this is the first
	// thing a process does: nothing else in the agent has run yet to register
	// it. Without it a dual-signed release fails verification under the
	// REQUIRED policy at the first restart and is rolled back - the device can
	// never keep an update - and under PREFERRED it is reported as
	// classical-only. It is done here, not only in each main, so that no
	// caller can get the order wrong; registering again is harmless, and a
	// build without crypto/mldsa registers nothing, as before.
	proto.EnableStandardPQ()
	logf := options.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	// Two different reasons to run as this binary and install nothing, kept
	// apart because the person reading the status does different things about
	// them: change a setting, or install a release build.
	unsupported := ""
	disabled := options.Disabled
	if disabled {
		unsupported = "updates are disabled in this agent's configuration"
	} else if reason := NotAReleaseVersion(options.Version); reason != "" {
		disabled, unsupported = true, reason
		logf("%s", reason)
	}
	keyring, pqKeyring, err := LoadKeyring(options.KeyFile)
	if err != nil {
		// Not fatal, and not silently empty either: said once, with the reason.
		logf("release keys could not be loaded; updates are unavailable: %v", err)
		keyring, pqKeyring = proto.OTAKeyring{}, proto.OTAPQKeyring{}
		if unsupported == "" {
			unsupported = "the release key file on this device is not usable"
		}
	}
	keys := proto.OTAKeyStatus{Classical: len(keyring), PostQuantum: len(pqKeyring)}

	chained := ""
	if !disabled {
		chained = ChainedRelease()
	}
	decision, err := Boot(BootOptions{
		StateDir:             options.StateDir,
		FactoryVersion:       options.Version,
		Platform:             options.Platform,
		Channel:              options.Channel,
		Keyring:              keyring,
		PQKeyring:            pqKeyring,
		SignaturePolicy:      options.SignaturePolicy,
		Chained:              chained,
		InstallerUnsupported: unsupported,
		Logf:                 logf,
		Now:                  options.Now,
	})
	if err != nil {
		return Launched{}, fmt.Errorf("update start-up: %w", err)
	}
	if disabled {
		// Disabled means the factory agent runs, whatever is on disk.
		decision.Exec, decision.ReleaseID, decision.Version = "", "", ""
		decision.Manager.SetCurrentVersion(options.Version)
		return Launched{Decision: decision, Keys: keys}, nil
	}
	if decision.Exec == "" {
		return Launched{Decision: decision, Keys: keys}, nil
	}

	logf("starting installed release %s (%s)", decision.ReleaseID, decision.Version)
	environment := options.Environment
	if environment == nil {
		environment = os.Environ()
	}
	chainErr := Chain(decision, options.Arguments, environment)
	// Still here: the release could not be executed. It is deselected so the
	// next start does not try it again, and this process serves as itself.
	ChainFailed(decision, options.Version, chainErr)
	logf("installed release %s could not be started and has been deselected: %v", decision.ReleaseID, chainErr)
	decision.Exec, decision.ReleaseID, decision.Version = "", "", ""
	return Launched{Decision: decision, Keys: keys}, nil
}

// NotAReleaseVersion returns why an agent with this version takes no part in
// updates, or "" when the version is a release version.
//
// Every ordering the update mechanism relies on compares against the version
// of the agent in the system image: a stored release older than it is not run,
// and an offer older than what is running is refused. A version that does not
// parse - "dev" from a build without -ldflags, or anything else - gives those
// comparisons no answer. Skipping them would leave updates on with the floor
// removed, so such an agent runs as itself and installs nothing instead.
func NotAReleaseVersion(version string) string {
	if _, err := proto.ParseVersion(version); err == nil {
		return ""
	}
	if trimmed := strings.TrimSpace(version); trimmed == "" || trimmed == "dev" {
		return fmt.Sprintf("this agent is a development build (version %q); it cannot be updated or used as an update floor", trimmed)
	}
	return fmt.Sprintf("this agent's version %q is not a release version; it cannot be updated or used as an update floor", version)
}
