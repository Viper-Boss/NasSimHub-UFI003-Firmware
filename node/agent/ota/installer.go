package ota

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// The real installer.
//
// # What it replaces, and what it never touches
//
// The agent shipped in the system image - the FACTORY agent - is never
// modified. It sits in the root filesystem, owned by root, and the agent's
// service user cannot write it. Updates are installed beside the device state
// instead:
//
//	<state>/agent-releases/<release-id>/nassimhub-agent   the release binary
//	<state>/agent-releases/<release-id>/manifest.json     the signed manifest it came with
//	<state>/agent-releases/current -> <release-id>        which release runs, if any
//	<state>/agent-releases/rollback-target                what "undo" means right now
//
// At start-up the factory agent looks for `current`, re-verifies that release
// against the release keys, and replaces itself with it (see boot.go). If there
// is no current release, or it does not verify, or it cannot be executed, the
// factory agent simply carries on as itself.
//
// That one decision buys the properties an updater on a device in a cupboard
// needs:
//
//   - There is always an agent that starts. No sequence of failed updates,
//     power cuts or corrupted files can leave the device with nothing to run,
//     because the thing it falls back to is never written.
//   - Switching is one rename(2) of a symlink, which the filesystem performs
//     atomically. A power cut leaves the old link or the new one.
//   - Undoing is the same operation in the other direction, and is idempotent:
//     the target is recorded BEFORE the switch, so undoing twice, or undoing a
//     switch that never happened, lands in the same place.
//   - The unprivileged agent needs no new privilege. It never writes outside
//     its own state directory and never runs anything as root.
//
// It cannot install a kernel, a boot image, a device tree, modem firmware or a
// root filesystem. There is no code path here that opens a block device.

const (
	// ReleasesDirName holds installed releases, under the state directory.
	ReleasesDirName = "agent-releases"
	// BinaryName is the agent executable inside a release directory.
	BinaryName = "nassimhub-agent"
	// ManifestFileName is the signed manifest stored beside the binary.
	ManifestFileName = "manifest.json"

	currentLink        = "current"
	rollbackTargetFile = "rollback-target"
	// factoryTarget is the rollback target meaning "no installed release".
	factoryTarget = "@factory"

	probeTimeout = 15 * time.Second
)

// ChainedEnv is set in the environment of an agent the factory agent chained
// into. Its value is the release id. It is how a release binary knows it is
// running as the installed release rather than being probed or run by hand,
// and it is what stops a chained agent from trying to chain again.
const ChainedEnv = "NSH_AGENT_CHAINED"

// probeMarker is the ChainedEnv value used while a staged binary is being
// validated. A binary run with it must do nothing but answer.
const probeMarker = "@probe"

// Probe executes a staged binary and returns the version it reports.
type Probe func(ctx context.Context, path string) (string, error)

// FileInstallerOptions configures a FileInstaller.
type FileInstallerOptions struct {
	// StateDir is the agent's state directory.
	StateDir string
	// Probe overrides how a staged binary is validated. Nil uses ExecProbe.
	Probe Probe
	// Unsupported, when non-empty, makes the installer report that it cannot
	// install and why. Everything else still works for inspection.
	Unsupported string
}

// FileInstaller installs agent releases as described above.
type FileInstaller struct {
	releases    string
	probe       Probe
	unsupported string

	mu      sync.Mutex
	pending *pendingRelease
}

type pendingRelease struct {
	id     string
	signed []byte
}

// NewFileInstaller builds an installer rooted in the state directory.
func NewFileInstaller(options FileInstallerOptions) (*FileInstaller, error) {
	if options.StateDir == "" {
		return nil, errors.New("an installer requires the state directory")
	}
	probe := options.Probe
	if probe == nil {
		probe = ExecProbe
	}
	return &FileInstaller{
		releases:    filepath.Join(options.StateDir, ReleasesDirName),
		probe:       probe,
		unsupported: options.Unsupported,
	}, nil
}

// Supported reports whether this installer can install.
func (i *FileInstaller) Supported() bool { return i.unsupported == "" }

// UnsupportedReason says why not.
func (i *FileInstaller) UnsupportedReason() string { return i.unsupported }

// Prepare records which release the next Stage is for, and the signed manifest
// to store beside it. The manifest is kept exactly as it was received: the
// signature covers those bytes, and a re-encoded copy would not verify.
func (i *FileInstaller) Prepare(releaseID string, signed proto.OTASignedManifest) error {
	if err := proto.ValidateOTAReleaseID(releaseID); err != nil {
		return err
	}
	encoded, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	i.mu.Lock()
	i.pending = &pendingRelease{id: releaseID, signed: encoded}
	i.mu.Unlock()
	return nil
}

func (i *FileInstaller) pendingRelease() (*pendingRelease, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.pending == nil {
		return nil, errors.New("no release has been prepared")
	}
	copied := *i.pending
	return &copied, nil
}

func (i *FileInstaller) releaseDir(id string) string { return filepath.Join(i.releases, id) }

// BinaryPath is where a release's executable lives.
func (i *FileInstaller) BinaryPath(id string) string {
	return filepath.Join(i.releaseDir(id), BinaryName)
}

// Stage writes verified bytes into a release directory that nothing points at.
//
// The directory is assembled under a temporary name and renamed into place, so
// a release directory either does not exist or is complete. Staging the release
// that is currently running is refused: its files are in use and replacing them
// would change the running agent's binary under its feet.
func (i *FileInstaller) Stage(_ context.Context, artifact proto.OTAArtifact, content []byte) error {
	if !i.Supported() {
		return errors.New(i.unsupported)
	}
	pending, err := i.pendingRelease()
	if err != nil {
		return err
	}
	if active, ok := i.Active(); ok && active == pending.id {
		return fmt.Errorf("release %s is the one running; it cannot be staged over itself", pending.id)
	}
	if int64(len(content)) != artifact.Size || len(content) == 0 {
		return fmt.Errorf("staged content is %d bytes, the manifest says %d", len(content), artifact.Size)
	}
	if err := os.MkdirAll(i.releases, 0o700); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(i.releases, ".staging-")
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := writeFileSync(filepath.Join(temporary, BinaryName), content, 0o755); err != nil {
		return err
	}
	if err := writeFileSync(filepath.Join(temporary, ManifestFileName), pending.signed, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(temporary, 0o700); err != nil {
		return err
	}
	final := i.releaseDir(pending.id)
	// A previous attempt at the same release may have left a directory. It is
	// not referenced (checked above), so it can go.
	if err := os.RemoveAll(final); err != nil {
		return err
	}
	if err := os.Rename(temporary, final); err != nil {
		return err
	}
	cleanup = false
	return syncDir(i.releases)
}

// Validate executes the staged binary and checks the version it reports.
func (i *FileInstaller) Validate(ctx context.Context, _ proto.OTAArtifact, expectedVersion string) error {
	pending, err := i.pendingRelease()
	if err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	reported, err := i.probe(probeCtx, i.BinaryPath(pending.id))
	if err != nil {
		return err
	}
	if reported != expectedVersion {
		return fmt.Errorf("the staged agent reports version %q, the manifest promised %q", reported, expectedVersion)
	}
	return nil
}

// Activate makes the staged release the one that runs.
//
// The rollback target is written first. If the device loses power between the
// two steps, undoing lands on the release that was running, which is where the
// device still is.
func (i *FileInstaller) Activate(_ context.Context, artifact proto.OTAArtifact) error {
	if !i.Supported() {
		return errors.New(i.unsupported)
	}
	pending, err := i.pendingRelease()
	if err != nil {
		return err
	}
	// The bytes are checked once more, immediately before they become what the
	// device runs. Validation may have happened minutes ago.
	digest, size, err := hashFile(i.BinaryPath(pending.id))
	if err != nil {
		return fmt.Errorf("the staged release is not readable: %w", err)
	}
	if size != artifact.Size || !strings.EqualFold(digest, artifact.SHA256) {
		return errors.New("the staged release no longer matches its manifest")
	}
	target := factoryTarget
	if active, ok := i.Active(); ok {
		target = active
	}
	if err := writeFileSync(filepath.Join(i.releases, rollbackTargetFile), []byte(target), 0o600); err != nil {
		return err
	}
	if err := syncDir(i.releases); err != nil {
		return err
	}
	return i.point(pending.id)
}

// Rollback puts back whatever was running before the last Activate.
//
// With no activation on record there is nothing to undo and nothing is
// changed. That makes it safe to call from recovery without knowing how far an
// interrupted activation got.
func (i *FileInstaller) Rollback(context.Context) error {
	raw, err := os.ReadFile(filepath.Join(i.releases, rollbackTargetFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	target := strings.TrimSpace(string(raw))
	if target == factoryTarget || target == "" {
		return i.Deactivate()
	}
	if proto.ValidateOTAReleaseID(target) != nil {
		// An unreadable target is not followed. The factory agent is always a
		// correct place to land.
		return i.Deactivate()
	}
	if _, err := os.Stat(i.BinaryPath(target)); err != nil {
		return i.Deactivate()
	}
	return i.point(target)
}

// Commit ends the window in which the last activation can be undone, and
// removes releases nothing refers to any more.
func (i *FileInstaller) Commit() error {
	if err := os.Remove(filepath.Join(i.releases, rollbackTargetFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	i.mu.Lock()
	i.pending = nil
	i.mu.Unlock()
	return i.Prune()
}

// Prune deletes release directories that are neither running nor the rollback
// target, and any staging leftovers. It bounds what updates cost in flash.
func (i *FileInstaller) Prune() error {
	entries, err := os.ReadDir(i.releases)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	if active, ok := i.Active(); ok {
		keep[active] = true
	}
	if raw, err := os.ReadFile(filepath.Join(i.releases, rollbackTargetFile)); err == nil {
		keep[strings.TrimSpace(string(raw))] = true
	}
	i.mu.Lock()
	if i.pending != nil {
		keep[i.pending.id] = true
	}
	i.mu.Unlock()
	var firstError error
	for _, entry := range entries {
		if !entry.IsDir() || keep[entry.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(i.releases, entry.Name())); err != nil && firstError == nil {
			firstError = err
		}
	}
	return firstError
}

// Active reports which installed release is selected to run, if any.
//
// The link is read, not followed: a link that points anywhere other than a
// release directory beside it is treated as no selection at all.
func (i *FileInstaller) Active() (string, bool) {
	target, err := os.Readlink(filepath.Join(i.releases, currentLink))
	if err != nil {
		return "", false
	}
	if proto.ValidateOTAReleaseID(target) != nil {
		return "", false
	}
	return target, true
}

// Deactivate selects no installed release, so the factory agent runs.
func (i *FileInstaller) Deactivate() error {
	if err := os.Remove(filepath.Join(i.releases, currentLink)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDir(i.releases)
}

// point atomically selects a release.
func (i *FileInstaller) point(id string) error {
	if err := proto.ValidateOTAReleaseID(id); err != nil {
		return err
	}
	if err := os.MkdirAll(i.releases, 0o700); err != nil {
		return err
	}
	temporary := filepath.Join(i.releases, ".current-new")
	_ = os.Remove(temporary)
	// A relative link, so the state directory can be moved or mounted
	// elsewhere without every release becoming unreachable.
	if err := os.Symlink(id, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(i.releases, currentLink)); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDir(i.releases)
}

// StoredManifest reads the signed manifest kept beside a release.
func (i *FileInstaller) StoredManifest(id string) (proto.OTASignedManifest, error) {
	if err := proto.ValidateOTAReleaseID(id); err != nil {
		return proto.OTASignedManifest{}, err
	}
	raw, err := os.ReadFile(filepath.Join(i.releaseDir(id), ManifestFileName))
	if err != nil {
		return proto.OTASignedManifest{}, err
	}
	if len(raw) > proto.OTAMaxManifestBytes*2 {
		return proto.OTASignedManifest{}, errors.New("stored manifest is too large")
	}
	var signed proto.OTASignedManifest
	if err := json.Unmarshal(raw, &signed); err != nil {
		return proto.OTASignedManifest{}, err
	}
	return signed, nil
}

// ---------------------------------------------------------------------------

// ExecProbe is the production Probe: confirm the file is an executable for
// this machine, run it with -version, and read the version it prints.
//
// The architecture is read from the ELF header before anything is executed, so
// a build for another machine is reported as that rather than as an exec
// failure. The binary runs with an almost empty environment and the probe
// marker, with no arguments other than -version, and is killed if it has not
// answered within the timeout.
func ExecProbe(ctx context.Context, path string) (string, error) {
	if err := checkExecutable(path); err != nil {
		return "", err
	}
	command := exec.CommandContext(ctx, path, "-version")
	command.Env = []string{ChainedEnv + "=" + probeMarker, "PATH=/usr/bin:/bin"}
	command.Stdin = nil
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", errors.New("the staged agent did not answer -version in time")
		}
		return "", fmt.Errorf("the staged agent could not be executed: %w", err)
	}
	return ParseVersionLine(string(output))
}

// ParseVersionLine reads the version out of the line an agent prints for
// -version: "nassimhub-agent <version> (...)".
func ParseVersionLine(output string) (string, error) {
	line, _, _ := strings.Cut(strings.TrimSpace(output), "\n")
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != BinaryName {
		return "", errors.New("the staged binary did not identify itself as nassimhub-agent")
	}
	return fields[1], nil
}

func checkExecutable(path string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	file, err := elf.Open(path)
	if err != nil {
		return errors.New("the staged file is not an ELF executable")
	}
	defer file.Close()
	want := map[string]elf.Machine{
		"arm64": elf.EM_AARCH64, "amd64": elf.EM_X86_64, "arm": elf.EM_ARM, "386": elf.EM_386,
		"riscv64": elf.EM_RISCV,
	}[runtime.GOARCH]
	if want != 0 && file.Machine != want {
		return fmt.Errorf("the staged agent is built for %s, this device is %s", file.Machine, runtime.GOARCH)
	}
	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return errors.New("the staged file is not an executable")
	}
	return nil
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(digest.Sum(nil)), size, nil
}

// writeFileSync writes a new file and flushes it before returning.
func writeFileSync(path string, content []byte, mode fs.FileMode) error {
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

// syncDir flushes a directory so a rename inside it survives a power cut.
func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer handle.Close()
	// Some filesystems refuse fsync on a directory. The rename has still
	// happened; only its durability across a power cut is then unconfirmed,
	// and there is nothing more this process can do about that.
	_ = handle.Sync()
	return nil
}
