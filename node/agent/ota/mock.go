package ota

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// MockInstaller stages files on disk and simulates the swap.
//
// It is the installer this stage ships, and it reports Supported() false so
// nothing in the product offers an update the device cannot actually perform.
// What it does do is exercise the whole state machine against real files, which
// is what makes the rollback path testable before any hardware exists.
//
// It never replaces a running executable and never writes outside its own
// directory.
type MockInstaller struct {
	// Dir is where staged files land.
	Dir string
	// InstalledVersion is what the "running" binary reports, so a test can
	// watch it change across activate and rollback.
	mu               sync.Mutex
	installedVersion string
	previousVersion  string
	staged           string
	activated        bool

	// The knobs below let a test produce each failure the real installer will
	// eventually have to survive.
	FailStage    error
	FailValidate error
	FailActivate error
	FailRollback error
	// ValidateVersion is what the staged binary claims when executed. Setting
	// it to something other than the manifest's version reproduces the most
	// common real failure: a correctly hashed binary that is the wrong build.
	ValidateVersion string
	// SupportedValue reports whether this installer claims it can install. It
	// is false by default, matching what ships.
	SupportedValue bool
}

// NewMockInstaller builds one rooted at dir.
func NewMockInstaller(dir, currentVersion string) *MockInstaller {
	return &MockInstaller{Dir: dir, installedVersion: currentVersion}
}

// Supported reports whether this installer can install.
func (i *MockInstaller) Supported() bool { return i.SupportedValue }

// InstalledVersion is what would be running.
func (i *MockInstaller) InstalledVersion() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.installedVersion
}

// Stage writes the bytes into the staging directory.
func (i *MockInstaller) Stage(_ context.Context, artifact proto.OTAArtifact, content []byte) error {
	if i.FailStage != nil {
		return i.FailStage
	}
	if err := os.MkdirAll(i.Dir, 0o755); err != nil {
		return err
	}
	// filepath.Base defends the staging directory from a manifest that tried
	// to name a path. CheckManifest already refuses those, so this is the
	// second of two independent barriers rather than the only one.
	path := filepath.Join(i.Dir, filepath.Base(artifact.Name))
	if err := os.WriteFile(path, content, 0o755); err != nil {
		return err
	}
	i.mu.Lock()
	i.staged = path
	i.mu.Unlock()
	return nil
}

// Validate stands in for executing the staged binary and reading its version.
func (i *MockInstaller) Validate(_ context.Context, _ proto.OTAArtifact, expectedVersion string) error {
	if i.FailValidate != nil {
		return i.FailValidate
	}
	i.mu.Lock()
	staged := i.staged
	i.mu.Unlock()
	if staged == "" {
		return errors.New("nothing is staged")
	}
	if _, err := os.Stat(staged); err != nil {
		return err
	}
	reported := i.ValidateVersion
	if reported == "" {
		reported = expectedVersion
	}
	if reported != expectedVersion {
		return errors.New("the staged binary reports version " + reported +
			", the manifest promised " + expectedVersion)
	}
	return nil
}

// Activate swaps the staged file in, remembering what was there.
func (i *MockInstaller) Activate(_ context.Context, _ proto.OTAArtifact) error {
	if i.FailActivate != nil {
		return i.FailActivate
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.staged == "" {
		return errors.New("nothing is staged")
	}
	i.previousVersion = i.installedVersion
	i.installedVersion = i.ValidateVersion
	if i.installedVersion == "" {
		i.installedVersion = "staged"
	}
	i.activated = true
	return nil
}

// Rollback restores the previous binary. Calling it when nothing was activated
// is not an error: recovery re-runs steps rather than reasoning about how far a
// previous attempt got.
func (i *MockInstaller) Rollback(_ context.Context) error {
	if i.FailRollback != nil {
		return i.FailRollback
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.activated {
		return nil
	}
	i.installedVersion = i.previousVersion
	i.activated = false
	return nil
}

// ---------------------------------------------------------------------------

// MemoryFetcher serves a manifest and artifacts from memory.
type MemoryFetcher struct {
	Signed    proto.OTASignedManifest
	Artifacts map[string][]byte
	// ManifestError and ArtifactError inject transport failures.
	ManifestError error
	ArtifactError error
	// Corrupt flips a byte in every artifact, reproducing a mirror that served
	// something other than what the manifest describes.
	Corrupt bool
	// Truncate returns a short read.
	Truncate bool
}

// Manifest returns the configured manifest.
func (f *MemoryFetcher) Manifest(context.Context, string) (proto.OTASignedManifest, error) {
	if f.ManifestError != nil {
		return proto.OTASignedManifest{}, f.ManifestError
	}
	return f.Signed, nil
}

// Artifact returns the configured bytes, optionally damaged.
func (f *MemoryFetcher) Artifact(_ context.Context, artifact proto.OTAArtifact) ([]byte, error) {
	if f.ArtifactError != nil {
		return nil, f.ArtifactError
	}
	content, ok := f.Artifacts[artifact.Name]
	if !ok {
		return nil, errors.New("no such artifact: " + artifact.Name)
	}
	out := make([]byte, len(content))
	copy(out, content)
	if f.Truncate && len(out) > 1 {
		return out[:len(out)-1], nil
	}
	if f.Corrupt && len(out) > 0 {
		out[0] ^= 0xFF
	}
	return out, nil
}
