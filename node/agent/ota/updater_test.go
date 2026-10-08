package ota

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// The real installer, the start-up decision and the push service, exercised
// against real files in a temporary state directory. Where a test needs a
// binary that actually executes, it uses this test binary itself: TestMain
// below makes it answer -version the way an agent does when it is run as a
// probe or as a chained release.

const (
	factoryVersion = "1.0.0"
	fakeVersion    = "9.9.9"
)

func TestMain(m *testing.M) {
	switch {
	case IsProbe():
		// Run by ExecProbe: behave like `nassimhub-agent -version`.
		fmt.Printf("nassimhub-agent %s (protocol test)\n", fakeVersion)
		os.Exit(0)
	case ChainedRelease() != "":
		// Arrived here through Chain: report what the release sees. This is
		// checked before the factory case because the chained process inherits
		// the factory's environment.
		fmt.Printf("chained release=%s factory=%s args=%s\n",
			ChainedRelease(), os.Getenv(FactoryEnv), strings.Join(os.Args[1:], ","))
		os.Exit(0)
	case os.Getenv("NSH_OTA_TEST_FACTORY") != "":
		// Run by the chain test as the factory agent: decide and chain.
		os.Exit(runAsFactory(os.Getenv("NSH_OTA_TEST_FACTORY")))
	}
	os.Exit(m.Run())
}

// fixture is a publisher, a device state directory and its release keys.
type fixture struct {
	t        *testing.T
	stateDir string
	public   ed25519.PublicKey
	secret   ed25519.PrivateKey
	keyring  proto.OTAKeyring
	now      time.Time
	free     uint64
	restarts []string
	mu       sync.Mutex
	probe    Probe
	pq       *proto.MLDSASigner
	pqKeys   proto.OTAPQKeyring
	policy   proto.OTASignaturePolicy
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	public, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		t: t, stateDir: t.TempDir(), public: public, secret: secret,
		keyring: proto.OTAKeyring{"release-1": public},
		now:     time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC),
		free:    1 << 30,
	}
	// By default a staged binary "reports" whatever version its content names,
	// so tests can describe builds as text. The real ExecProbe has its own test.
	f.probe = func(_ context.Context, path string) (string, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return ParseVersionLine(string(raw))
	}
	return f
}

func agentBytes(version string, padding int) []byte {
	return []byte("nassimhub-agent " + version + " (test build)\n" + strings.Repeat("x", padding))
}

type built struct {
	manifest proto.OTAManifest
	signed   proto.OTASignedManifest
	content  []byte
}

func (f *fixture) release(version string, content []byte, edit func(*proto.OTAManifest)) built {
	f.t.Helper()
	manifest := proto.OTAManifest{
		SchemaVersion:  proto.OTASchemaVersion,
		ReleaseID:      "agent-" + version,
		Version:        version,
		Channel:        proto.OTAChannelStable,
		Platform:       proto.PlatformMSM8916,
		ReleasedAt:     f.now,
		ProtocolMajor:  proto.ProtocolMajor,
		ProtocolMinor:  proto.ProtocolMinor,
		MinCoreVersion: "0.1.0",
		Artifacts: []proto.OTAArtifact{{
			Kind: proto.OTAArtifactAgent, Name: BinaryName,
			SHA256: proto.ArtifactDigest(content), Size: int64(len(content)),
			URL: "https://example.invalid/agent", Arch: runtime.GOARCH,
		}},
	}
	if edit != nil {
		edit(&manifest)
	}
	var (
		signed proto.OTASignedManifest
		err    error
	)
	if f.pq != nil {
		signed, err = proto.SignManifestHybrid(manifest, "release-1", f.secret, "release-pq-1", f.pq)
	} else {
		signed, err = proto.SignManifest(manifest, "release-1", f.secret)
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return built{manifest: manifest, signed: signed, content: content}
}

func (f *fixture) bootOptions(chained string, version string) BootOptions {
	return BootOptions{
		StateDir: f.stateDir, FactoryVersion: version, Platform: proto.PlatformMSM8916,
		Channel: proto.OTAChannelStable, Keyring: f.keyring, PQKeyring: f.pqKeys,
		SignaturePolicy: f.policy, Chained: chained, Probe: f.probe,
		Now: func() time.Time { return f.now },
	}
}

// start is one process start: the factory agent decides, and - as the real
// binary would by exec - the selected release then resumes. It returns the
// updater of the process that ends up serving, and that process's version.
func (f *fixture) start() (*Updater, Decision) {
	f.t.Helper()
	decision, err := Boot(f.bootOptions("", factoryVersion))
	if err != nil {
		f.t.Fatal(err)
	}
	if decision.Exec != "" {
		_ = decision.Manager // the factory process is replaced; its manager dies with it
		chained, err := Boot(f.bootOptions(decision.ReleaseID, decision.Version))
		if err != nil {
			f.t.Fatal(err)
		}
		chained.FactoryVersion = factoryVersion
		chained.Version = decision.Version
		decision = chained
	}
	updater, err := NewUpdater(UpdaterOptions{
		Decision: decision, StateDir: f.stateDir,
		Keys: proto.OTAKeyStatus{Classical: len(f.keyring), PostQuantum: len(f.pqKeys)},
		Restart: func(reason string) {
			f.mu.Lock()
			f.restarts = append(f.restarts, reason)
			f.mu.Unlock()
		},
		FreeBytes: func(string) (uint64, error) { return f.free, nil },
		Now:       func() time.Time { return f.now },
	})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = updater.Close() })
	return updater, decision
}

// stop is the process exiting: the update lock is released.
func (f *fixture) stop(updater *Updater) { _ = updater.Close() }

func (f *fixture) restartCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.restarts)
}

func (f *fixture) waitForRestart(want int) {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f.restartCount() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatalf("the process was not asked to restart (have %d, want %d)", f.restartCount(), want)
}

// deliver offers a release and uploads it whole.
func (f *fixture) deliver(updater *Updater, b built) proto.OTADeviceStatus {
	f.t.Helper()
	ctx := context.Background()
	offered, err := updater.Offer(ctx, b.signed)
	if err != nil {
		f.t.Fatalf("offer: %v", err)
	}
	// Resume from wherever the device says it is, as a Core does.
	from := offered.Status.ReceivedBytes
	status, err := updater.Receive(ctx, b.manifest.ReleaseID, from, bytes.NewReader(b.content[from:]))
	if err != nil {
		f.t.Fatalf("receive: %v", err)
	}
	return status
}

// ---------------------------------------------------------------------------
// The whole life of an update
// ---------------------------------------------------------------------------

func TestAnUpdateIsDeliveredAppliedConfirmedAndTheFactoryAgentIsNeverTouched(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	updater, decision := f.start()
	if decision.Exec != "" || updater.Status().ActiveRelease != "" || !updater.Supported() {
		t.Fatalf("a fresh device: %+v", updater.Status())
	}
	if status := updater.Status(); status.State != proto.OTAIdle || status.CurrentVersion != factoryVersion ||
		status.Keys.Classical != 1 || status.FactoryVersion != factoryVersion {
		t.Fatalf("idle status: %+v", status)
	}

	release := f.release("1.1.0", agentBytes("1.1.0", 4096), nil)
	offered, err := updater.Offer(ctx, release.signed)
	if err != nil {
		t.Fatal(err)
	}
	if offered.Manifest.Version != "1.1.0" || offered.Status.State != proto.OTAAvailable ||
		offered.Status.ExpectedBytes != int64(len(release.content)) || offered.Status.ReceivedBytes != 0 {
		t.Fatalf("offer: %+v", offered.Status)
	}
	// Nothing is installed because it was offered, or because it arrived.
	status, err := updater.Receive(ctx, release.manifest.ReleaseID, 0, bytes.NewReader(release.content))
	if err != nil {
		t.Fatal(err)
	}
	if status.State != proto.OTAReady || status.ReceivedBytes != status.ExpectedBytes {
		t.Fatalf("after transfer: %+v", status)
	}
	if _, ok := decision.Installer.Active(); ok || f.restartCount() != 0 {
		t.Fatal("a release was selected before anyone applied it")
	}
	if _, err := os.Stat(filepath.Join(f.stateDir, StagingDirName, strings.ToLower(release.manifest.Artifacts[0].SHA256)+".part")); !os.IsNotExist(err) {
		t.Fatal("the spool was left behind after staging")
	}

	// Applying needs the release named; a different name is refused.
	if _, err := updater.Apply(ctx, "agent-0.0.0"); !errors.Is(err, ErrNoOffer) {
		t.Fatalf("apply of an unoffered release: %v", err)
	}
	status, err = updater.Apply(ctx, release.manifest.ReleaseID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != proto.OTAPendingConfirm || !status.RestartPending || status.ConfirmDeadline.IsZero() {
		t.Fatalf("after apply: %+v", status)
	}
	f.waitForRestart(1)
	// Confirming before the new agent is the one running is refused: the
	// process answering is still the old one.
	if _, err := updater.Confirm(release.manifest.ReleaseID); !errors.Is(err, ErrNotReady) {
		t.Fatalf("confirm before the restart: %v", err)
	}
	// A new offer cannot begin while this one is unresolved.
	if _, err := updater.Offer(ctx, f.release("1.2.0", agentBytes("1.2.0", 10), nil).signed); !errors.Is(err, ErrPending) {
		t.Fatalf("offer while pending: %v", err)
	}
	f.stop(updater)

	// The restart the update asked for. The release runs, unconfirmed.
	updater, decision = f.start()
	status = updater.Status()
	if decision.ReleaseID != release.manifest.ReleaseID || status.ActiveRelease != release.manifest.ReleaseID ||
		status.CurrentVersion != "1.1.0" || status.State != proto.OTAPendingConfirm || status.FactoryVersion != factoryVersion {
		t.Fatalf("after the expected restart: %+v", status)
	}
	status, err = updater.Confirm(release.manifest.ReleaseID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != proto.OTAIdle || status.Progress != 100 || status.Error != "" {
		t.Fatalf("after confirm: %+v", status)
	}
	f.stop(updater)

	// Every later start runs the release, with nothing left to decide.
	for i := 0; i < 3; i++ {
		updater, decision = f.start()
		if decision.ReleaseID != release.manifest.ReleaseID || updater.Status().State != proto.OTAIdle {
			t.Fatalf("start %d after confirm: %+v", i, updater.Status())
		}
		f.stop(updater)
	}
	if _, err := os.Stat(filepath.Join(f.stateDir, ReleasesDirName, rollbackTargetFile)); !os.IsNotExist(err) {
		t.Fatal("a confirmed update can still be undone by a stale rollback target")
	}
}

func TestASecondUpdateReplacesTheFirstAndRollbackReturnsToIt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	install := func(version string, confirm bool) built {
		updater, _ := f.start()
		release := f.release(version, agentBytes(version, 512), nil)
		f.deliver(updater, release)
		if _, err := updater.Apply(ctx, release.manifest.ReleaseID); err != nil {
			t.Fatal(err)
		}
		f.stop(updater)
		updater, decision := f.start()
		if decision.ReleaseID != release.manifest.ReleaseID {
			t.Fatalf("%s is not running after its restart: %q", version, decision.ReleaseID)
		}
		if confirm {
			if _, err := updater.Confirm(release.manifest.ReleaseID); err != nil {
				t.Fatal(err)
			}
		}
		f.stop(updater)
		return release
	}
	first := install("1.1.0", true)
	second := install("1.2.0", false)

	// The owner changes their mind about 1.2.0 before confirming it.
	updater, _ := f.start()
	// (this start is the SECOND one with 1.2.0 unconfirmed, so it has already
	// been undone - see the next test. Re-apply it to exercise a requested
	// rollback from a clean pending state.)
	if updater.Status().ActiveRelease != first.manifest.ReleaseID {
		t.Fatalf("a second unconfirmed start should run %s, runs %q", first.manifest.ReleaseID, updater.Status().ActiveRelease)
	}
	f.stop(updater)

	updater, _ = f.start()
	f.deliver(updater, second)
	if _, err := updater.Apply(ctx, second.manifest.ReleaseID); err != nil {
		t.Fatal(err)
	}
	f.stop(updater)
	updater, decision := f.start()
	if decision.ReleaseID != second.manifest.ReleaseID {
		t.Fatalf("1.2.0 is not running: %q", decision.ReleaseID)
	}
	before := f.restartCount()
	status, err := updater.Rollback(ctx, second.manifest.ReleaseID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != proto.OTARolledBack || !status.RestartPending {
		t.Fatalf("after a requested rollback: %+v", status)
	}
	f.waitForRestart(before + 1)
	f.stop(updater)

	updater, decision = f.start()
	if decision.ReleaseID != first.manifest.ReleaseID || updater.Status().CurrentVersion != "1.1.0" {
		t.Fatalf("rollback did not return to the previous release: %+v", updater.Status())
	}
	// Only the running release is kept once nothing refers to the other.
	entries, _ := os.ReadDir(filepath.Join(f.stateDir, ReleasesDirName))
	var directories []string
	for _, entry := range entries {
		if entry.IsDir() {
			directories = append(directories, entry.Name())
		}
	}
	if len(directories) > 2 {
		t.Fatalf("release directories accumulate: %v", directories)
	}
}

// ---------------------------------------------------------------------------
// What must be refused before anything is written
// ---------------------------------------------------------------------------

func TestOffersThatMustNotBeAccepted(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	updater, _ := f.start()
	good := agentBytes("1.1.0", 64)

	otherPublic, otherSecret, _ := ed25519.GenerateKey(rand.Reader)
	_ = otherPublic
	unknownKey, _ := proto.SignManifest(f.release("1.1.0", good, nil).manifest, "release-1", otherSecret)
	unknownID, _ := proto.SignManifest(f.release("1.1.0", good, nil).manifest, "release-9", f.secret)

	tampered := f.release("1.1.0", good, nil).signed
	tampered.Manifest = bytes.Replace(tampered.Manifest, []byte(`"1.1.0"`), []byte(`"1.1.1"`), 1)

	reencoded := f.release("1.1.0", good, nil).signed
	reencoded.Manifest = append(append([]byte{}, reencoded.Manifest...), '\n')

	cases := map[string]proto.OTASignedManifest{
		"signed by another key":  unknownKey,
		"unknown key id":         unknownID,
		"edited after signing":   tampered,
		"re-encoded":             reencoded,
		"unsigned":               {Manifest: f.release("1.1.0", good, nil).signed.Manifest},
		"another platform":       f.release("1.1.0", good, func(m *proto.OTAManifest) { m.Platform = proto.PlatformMock }).signed,
		"another architecture":   f.release("1.1.0", good, func(m *proto.OTAManifest) { m.Artifacts[0].Arch = "mips" }).signed,
		"a downgrade":            f.release("0.9.0", agentBytes("0.9.0", 8), nil).signed,
		"the running version":    f.release(factoryVersion, agentBytes(factoryVersion, 8), nil).signed,
		"another channel":        f.release("1.1.0", good, func(m *proto.OTAManifest) { m.Channel = proto.OTAChannelBeta }).signed,
		"another protocol major": f.release("1.1.0", good, func(m *proto.OTAManifest) { m.ProtocolMajor = proto.ProtocolMajor + 1 }).signed,
		"a newer schema":         f.release("1.1.0", good, func(m *proto.OTAManifest) { m.SchemaVersion = proto.OTASchemaVersion + 1 }).signed,
		"not an agent":           f.release("1.1.0", good, func(m *proto.OTAManifest) { m.Artifacts[0].Kind = "rootfs" }).signed,
		"two artifacts": f.release("1.1.0", good, func(m *proto.OTAManifest) {
			m.Artifacts = append(m.Artifacts, m.Artifacts[0])
		}).signed,
		"a path as a name":      f.release("1.1.0", good, func(m *proto.OTAManifest) { m.Artifacts[0].Name = "../agent" }).signed,
		"a path as a release":   f.release("1.1.0", good, func(m *proto.OTAManifest) { m.ReleaseID = "../../etc" }).signed,
		"the link name":         f.release("1.1.0", good, func(m *proto.OTAManifest) { m.ReleaseID = "current" }).signed,
		"larger than the limit": f.release("1.1.0", good, func(m *proto.OTAManifest) { m.Artifacts[0].Size = proto.OTAMaxArtifactBytes + 1 }).signed,
		"no size":               f.release("1.1.0", good, func(m *proto.OTAManifest) { m.Artifacts[0].Size = 0 }).signed,
		"needs a newer NAS":     f.release("1.1.0", good, func(m *proto.OTAManifest) { m.MinCoreVersion = "99.0.0" }).signed,
	}
	// "needs a newer NAS" only bites when the device knows its NAS version.
	delete(cases, "needs a newer NAS")

	for name, signed := range cases {
		if _, err := updater.Offer(ctx, signed); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if state := updater.Status().State; state == proto.OTAAvailable || state == proto.OTAReady {
			t.Errorf("%s: left the machine in %s", name, state)
		}
	}
	// Nothing was written for any of them.
	if entries, err := os.ReadDir(filepath.Join(f.stateDir, ReleasesDirName)); err == nil && len(entries) != 0 {
		t.Fatalf("refused offers left %d entries in the release directory", len(entries))
	}
	if matches, _ := filepath.Glob(filepath.Join(f.stateDir, StagingDirName, "*.part")); len(matches) != 0 {
		t.Fatalf("refused offers left spool files: %v", matches)
	}
	// And a good offer still works afterwards.
	if _, err := updater.Offer(ctx, f.release("1.1.0", good, nil).signed); err != nil {
		t.Fatalf("a good offer after the refused ones: %v", err)
	}
}

func TestAnOfferIsRefusedWhenThereIsNoRoomForIt(t *testing.T) {
	f := newFixture(t)
	release := f.release("1.1.0", agentBytes("1.1.0", 1<<20), nil)
	// Room for the artifact but not for the artifact, its staged copy and the
	// reserve: refused before a byte is transferred.
	f.free = uint64(len(release.content)) + 1024
	updater, _ := f.start()
	if _, err := updater.Offer(context.Background(), release.signed); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("offer with too little space: %v", err)
	}
	if status := updater.Status(); status.State != proto.OTAFailed || !strings.Contains(status.Error, "space") {
		t.Fatalf("status after a refused offer: %+v", status)
	}
	f.free = 1 << 30
	if _, err := updater.Offer(context.Background(), release.signed); err != nil {
		t.Fatalf("offer once there is room: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The transfer
// ---------------------------------------------------------------------------

type failingReader struct {
	data  []byte
	after int
	read  int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.read >= r.after {
		return 0, errors.New("link dropped")
	}
	n := copy(p, r.data[r.read:min(len(r.data), r.after)])
	r.read += n
	return n, nil
}

func TestAnInterruptedTransferResumesAndSurvivesAnAgentRestart(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	updater, _ := f.start()
	release := f.release("1.1.0", agentBytes("1.1.0", 200_000), nil)
	if _, err := updater.Offer(ctx, release.signed); err != nil {
		t.Fatal(err)
	}
	id := release.manifest.ReleaseID

	// The link drops partway. What arrived is kept and reported.
	status, err := updater.Receive(ctx, id, 0, &failingReader{data: release.content, after: 70_000})
	if err == nil || status.ReceivedBytes != 70_000 || status.State != proto.OTAAvailable {
		t.Fatalf("after a dropped link: %+v %v", status, err)
	}
	// Resuming from the wrong place is refused and changes nothing.
	for _, offset := range []int64{0, 69_999, 70_001, int64(len(release.content))} {
		status, err = updater.Receive(ctx, id, offset, bytes.NewReader(release.content[offset:]))
		if !errors.Is(err, ErrOffset) || status.ReceivedBytes != 70_000 {
			t.Fatalf("resume from %d: %+v %v", offset, status, err)
		}
	}
	// Bytes for another release are refused.
	if _, err := updater.Receive(ctx, "agent-other", 70_000, bytes.NewReader(release.content[70_000:])); !errors.Is(err, ErrNoOffer) {
		t.Fatalf("bytes for another release: %v", err)
	}
	// A second piece, and then the agent restarts (USB replugged, say).
	if status, err = updater.Receive(ctx, id, 70_000, bytes.NewReader(release.content[70_000:150_000])); err != nil || status.ReceivedBytes != 150_000 {
		t.Fatalf("second piece: %+v %v", status, err)
	}
	f.stop(updater)

	updater, _ = f.start()
	// The Core offers the same release again and learns where to resume.
	offered, err := updater.Offer(ctx, release.signed)
	if err != nil {
		t.Fatal(err)
	}
	if offered.Status.ReceivedBytes != 150_000 || offered.Status.State != proto.OTAAvailable {
		t.Fatalf("after an agent restart: %+v", offered.Status)
	}
	status, err = updater.Receive(ctx, id, 150_000, bytes.NewReader(release.content[150_000:]))
	if err != nil || status.State != proto.OTAReady {
		t.Fatalf("final piece: %+v %v", status, err)
	}
	// A retried final piece is harmless.
	if status, err = updater.Receive(ctx, id, 150_000, bytes.NewReader(release.content[150_000:])); err != nil || status.State != proto.OTAReady {
		t.Fatalf("retried final piece: %+v %v", status, err)
	}
}

func TestBytesThatDoNotMatchTheManifestNeverReachTheInstaller(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	release := f.release("1.1.0", agentBytes("1.1.0", 5000), nil)
	id := release.manifest.ReleaseID

	corrupted := append([]byte{}, release.content...)
	corrupted[len(corrupted)/2] ^= 0xff

	cases := map[string]func(*Updater) error{
		"one flipped byte": func(u *Updater) error {
			_, err := u.Receive(ctx, id, 0, bytes.NewReader(corrupted))
			return err
		},
		"another build of the same size": func(u *Updater) error {
			other := agentBytes("1.1.0", 5000)
			other[len(other)-1] = 'y'
			_, err := u.Receive(ctx, id, 0, bytes.NewReader(other))
			return err
		},
		"more bytes than declared": func(u *Updater) error {
			_, err := u.Receive(ctx, id, 0, bytes.NewReader(append(append([]byte{}, release.content...), 'z')))
			return err
		},
	}
	for name, send := range cases {
		t.Run(name, func(t *testing.T) {
			f.stateDir = t.TempDir()
			updater, decision := f.start()
			if _, err := updater.Offer(ctx, release.signed); err != nil {
				t.Fatal(err)
			}
			if err := send(updater); err == nil {
				t.Fatal("accepted")
			}
			if state := updater.Status().State; state == proto.OTAReady || state == proto.OTAStaged {
				t.Fatalf("state is %s", state)
			}
			if _, err := os.Stat(decision.Installer.BinaryPath(id)); !os.IsNotExist(err) {
				t.Fatal("bytes that failed verification were staged")
			}
			if _, err := updater.Apply(ctx, id); err == nil {
				t.Fatal("an unverified release was applied")
			}
			// The device can still be updated afterwards, from the start.
			if _, err := updater.Offer(ctx, release.signed); err != nil {
				t.Fatalf("offer after a bad transfer: %v", err)
			}
			if status, err := updater.Receive(ctx, id, 0, bytes.NewReader(release.content)); err != nil || status.State != proto.OTAReady {
				t.Fatalf("a good transfer after a bad one: %+v %v", status, err)
			}
		})
	}
}

func TestABuildThatDoesNotRunOrReportsAnotherVersionIsNotInstalled(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// Correctly signed, correctly hashed, and the wrong build inside.
	wrongBuild := f.release("1.1.0", agentBytes("1.0.5", 100), nil)
	updater, decision := f.start()
	if _, err := updater.Offer(ctx, wrongBuild.signed); err != nil {
		t.Fatal(err)
	}
	status, err := updater.Receive(ctx, wrongBuild.manifest.ReleaseID, 0, bytes.NewReader(wrongBuild.content))
	if err == nil || status.State != proto.OTAFailed || !strings.Contains(status.Error, "1.0.5") {
		t.Fatalf("a mislabelled build: %+v %v", status, err)
	}
	if _, ok := decision.Installer.Active(); ok {
		t.Fatal("a release was selected")
	}

	// Not an agent at all.
	junk := f.release("1.1.0", []byte("this is not an agent\n"), nil)
	if _, err := updater.Offer(ctx, junk.signed); err != nil {
		t.Fatal(err)
	}
	if status, err := updater.Receive(ctx, junk.manifest.ReleaseID, 0, bytes.NewReader(junk.content)); err == nil || status.State != proto.OTAFailed {
		t.Fatalf("junk: %+v %v", status, err)
	}
}

func TestTheRealProbeExecutesTheBinaryAndChecksItsArchitecture(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the installer runs on Linux")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) > proto.OTAMaxArtifactBytes {
		t.Skipf("the test binary is %d bytes, over the artifact limit", len(content))
	}
	f := newFixture(t)
	f.probe = nil // the real one
	ctx := context.Background()

	// The test binary, run as a probe, reports fakeVersion (see TestMain).
	updater, _ := f.start()
	release := f.release(fakeVersion, content, nil)
	if status := f.deliver(updater, release); status.State != proto.OTAReady {
		t.Fatalf("a real executable did not validate: %+v", status)
	}

	// The same bytes under a manifest promising another version fail.
	f.stateDir = t.TempDir()
	updater, _ = f.start()
	mislabelled := f.release("9.9.8", content, nil)
	if _, err := updater.Offer(ctx, mislabelled.signed); err != nil {
		t.Fatal(err)
	}
	if status, err := updater.Receive(ctx, mislabelled.manifest.ReleaseID, 0, bytes.NewReader(content)); err == nil || status.State != proto.OTAFailed {
		t.Fatalf("a mislabelled executable: %+v %v", status, err)
	}

	// An executable for another machine is refused from its header, without
	// being run.
	foreign := append([]byte{}, content...)
	foreign[18], foreign[19] = 8, 0 // e_machine = EM_MIPS
	f.stateDir = t.TempDir()
	updater, _ = f.start()
	other := f.release(fakeVersion, foreign, nil)
	if _, err := updater.Offer(ctx, other.signed); err != nil {
		t.Fatal(err)
	}
	status, err := updater.Receive(ctx, other.manifest.ReleaseID, 0, bytes.NewReader(foreign))
	if err == nil || status.State != proto.OTAFailed || !strings.Contains(status.Error, "built for") {
		t.Fatalf("a foreign executable: %+v %v", status, err)
	}

	// A script is not an agent.
	f.stateDir = t.TempDir()
	updater, _ = f.start()
	script := f.release(fakeVersion, []byte("#!/bin/sh\necho nassimhub-agent "+fakeVersion+"\n"), nil)
	if _, err := updater.Offer(ctx, script.signed); err != nil {
		t.Fatal(err)
	}
	if status, err := updater.Receive(ctx, script.manifest.ReleaseID, 0, bytes.NewReader(script.content)); err == nil || status.State != proto.OTAFailed {
		t.Fatalf("a script: %+v %v", status, err)
	}
}

// ---------------------------------------------------------------------------
// Power cuts and crashes, stage by stage
// ---------------------------------------------------------------------------

// A power cut at any point before the switch costs nothing: the device comes
// back as it was, and can be updated again.
func TestAPowerCutBeforeTheSwitchCostsNothing(t *testing.T) {
	ctx := context.Background()
	stages := map[string]func(f *fixture, u *Updater, b built){
		"after the offer": func(f *fixture, u *Updater, b built) {
			_, _ = u.Offer(ctx, b.signed)
		},
		"mid transfer": func(f *fixture, u *Updater, b built) {
			_, _ = u.Offer(ctx, b.signed)
			_, _ = u.Receive(ctx, b.manifest.ReleaseID, 0, bytes.NewReader(b.content[:len(b.content)/2]))
		},
		"staged and validated": func(f *fixture, u *Updater, b built) {
			f.deliver(u, b)
		},
		"state file torn mid-write": func(f *fixture, u *Updater, b built) {
			f.deliver(u, b)
			path := filepath.Join(f.stateDir, StateFileName)
			raw, _ := os.ReadFile(path)
			_ = os.WriteFile(path, raw[:len(raw)/2], 0o600)
		},
		"release directory half written": func(f *fixture, u *Updater, b built) {
			f.deliver(u, b)
			_ = os.Truncate(filepath.Join(f.stateDir, ReleasesDirName, b.manifest.ReleaseID, BinaryName), 10)
		},
	}
	for name, interrupt := range stages {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			updater, _ := f.start()
			release := f.release("1.1.0", agentBytes("1.1.0", 20_000), nil)
			interrupt(f, updater, release)
			f.stop(updater) // the power goes

			updater, decision := f.start()
			status := updater.Status()
			if decision.Exec != "" || status.ActiveRelease != "" || status.CurrentVersion != factoryVersion {
				t.Fatalf("the device did not come back as the factory agent: %+v", status)
			}
			if status.State == proto.OTAPendingConfirm || status.State == proto.OTAApplying || status.State == proto.OTAReady {
				t.Fatalf("an interrupted update resumed on its own: %s", status.State)
			}
			// And it is still updatable.
			if status := f.deliver(updater, release); status.State != proto.OTAReady {
				t.Fatalf("the update could not be repeated: %+v", status)
			}
		})
	}
}

// A power cut during the switch itself is undone on the next start, whichever
// side of the rename it fell on.
func TestAPowerCutDuringTheSwitchIsUndone(t *testing.T) {
	ctx := context.Background()
	for _, switched := range []bool{false, true} {
		t.Run(fmt.Sprintf("link switched=%v", switched), func(t *testing.T) {
			f := newFixture(t)
			updater, decision := f.start()
			release := f.release("1.1.0", agentBytes("1.1.0", 1000), nil)
			f.deliver(updater, release)

			// Reproduce the interrupted Apply by hand: the state says APPLYING,
			// the rollback target is written, and the link is or is not
			// switched yet.
			artifact := release.manifest.Artifacts[0]
			state := decision.Manager.snapshot()
			state.State = proto.OTAApplying
			state.PreviousVersion = factoryVersion
			if err := decision.Manager.write(state); err != nil {
				t.Fatal(err)
			}
			if switched {
				if err := decision.Installer.Activate(ctx, artifact); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = os.WriteFile(filepath.Join(f.stateDir, ReleasesDirName, rollbackTargetFile), []byte(factoryTarget), 0o600)
			}
			f.stop(updater)

			updater, decision = f.start()
			status := updater.Status()
			if decision.Exec != "" || status.ActiveRelease != "" || status.CurrentVersion != factoryVersion {
				t.Fatalf("an interrupted switch left the release selected: %+v", status)
			}
			if status.State != proto.OTARolledBack {
				t.Fatalf("state after an interrupted switch: %s", status.State)
			}
			// Starting again changes nothing further.
			f.stop(updater)
			updater, decision = f.start()
			if decision.Exec != "" {
				t.Fatal("a second start selected the release")
			}
		})
	}
}

func TestANewAgentThatDiesBeforeConfirmingIsUndoneOnTheNextStart(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	updater, _ := f.start()
	release := f.release("1.1.0", agentBytes("1.1.0", 1000), nil)
	f.deliver(updater, release)
	if _, err := updater.Apply(ctx, release.manifest.ReleaseID); err != nil {
		t.Fatal(err)
	}
	f.stop(updater)

	// First start: the expected restart. The release runs.
	updater, decision := f.start()
	if decision.ReleaseID != release.manifest.ReleaseID {
		t.Fatalf("the release did not run on its expected restart: %q", decision.ReleaseID)
	}
	f.stop(updater) // it crashes, or the power goes, before anyone confirmed

	// Second start: undone, with the reason recorded.
	updater, decision = f.start()
	status := updater.Status()
	if decision.Exec != "" || status.ActiveRelease != "" || status.CurrentVersion != factoryVersion {
		t.Fatalf("a release that died unconfirmed is still selected: %+v", status)
	}
	if status.State != proto.OTARolledBack || status.RestartReason != proto.OTARestartUnexpected || status.Error == "" {
		t.Fatalf("status after the undo: %+v", status)
	}
	// The same release is not locked out, but its failures are counted.
	if _, err := updater.Offer(ctx, release.signed); err != nil {
		t.Fatalf("re-offering the release: %v", err)
	}
	if updater.Status().Attempts != 1 {
		t.Fatalf("attempts after one failure: %d", updater.Status().Attempts)
	}
}

func TestAnUnconfirmedUpdateIsUndoneWhenItsWindowCloses(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	updater, _ := f.start()
	release := f.release("1.1.0", agentBytes("1.1.0", 1000), nil)
	f.deliver(updater, release)
	if _, err := updater.Apply(ctx, release.manifest.ReleaseID); err != nil {
		t.Fatal(err)
	}
	f.stop(updater)
	updater, decision := f.start()
	if decision.ReleaseID == "" {
		t.Fatal("the release is not running")
	}

	// Inside the window nothing happens.
	f.now = f.now.Add(proto.OTAConfirmWindow - time.Minute)
	if updater.ExpireNow(ctx) {
		t.Fatal("the update was undone inside its confirmation window")
	}
	// Past it, the running agent undoes the update itself and restarts.
	before := f.restartCount()
	f.now = f.now.Add(2 * time.Minute)
	if !updater.ExpireNow(ctx) {
		t.Fatal("the update was not undone after its window closed")
	}
	f.waitForRestart(before + 1)
	status := updater.Status()
	if status.State != proto.OTARolledBack || status.RestartReason != proto.OTAConfirmTimeout {
		t.Fatalf("status after expiry: %+v", status)
	}
	// Confirming now is too late.
	if _, err := updater.Confirm(release.manifest.ReleaseID); err == nil {
		t.Fatal("an expired update was confirmed")
	}
	f.stop(updater)
	updater, decision = f.start()
	if decision.Exec != "" || updater.Status().CurrentVersion != factoryVersion {
		t.Fatalf("after expiry the device runs %q", updater.Status().CurrentVersion)
	}

	// The same happens if the device was simply off past the deadline.
	f.deliver(updater, release)
	if _, err := updater.Apply(ctx, release.manifest.ReleaseID); err != nil {
		t.Fatal(err)
	}
	f.stop(updater)
	f.now = f.now.Add(proto.OTAConfirmWindow + time.Hour)
	updater, decision = f.start()
	if decision.Exec != "" || updater.Status().RestartReason != proto.OTAConfirmTimeout {
		t.Fatalf("a device that was off past the deadline: %+v", updater.Status())
	}
}

// ---------------------------------------------------------------------------
// What start-up refuses to run
// ---------------------------------------------------------------------------

func TestStartupRunsOnlyAReleaseThatStillVerifies(t *testing.T) {
	ctx := context.Background()
	installed := func(t *testing.T) (*fixture, built) {
		f := newFixture(t)
		updater, _ := f.start()
		release := f.release("1.1.0", agentBytes("1.1.0", 3000), nil)
		f.deliver(updater, release)
		if _, err := updater.Apply(ctx, release.manifest.ReleaseID); err != nil {
			t.Fatal(err)
		}
		f.stop(updater)
		updater, _ = f.start()
		if _, err := updater.Confirm(release.manifest.ReleaseID); err != nil {
			t.Fatal(err)
		}
		f.stop(updater)
		return f, release
	}
	dir := func(f *fixture, b built) string {
		return filepath.Join(f.stateDir, ReleasesDirName, b.manifest.ReleaseID)
	}
	damage := map[string]func(f *fixture, b built){
		"binary modified": func(f *fixture, b built) {
			raw, _ := os.ReadFile(filepath.Join(dir(f, b), BinaryName))
			raw[20] ^= 1
			_ = os.WriteFile(filepath.Join(dir(f, b), BinaryName), raw, 0o755)
		},
		"binary replaced by another signed build": func(f *fixture, b built) {
			_ = os.WriteFile(filepath.Join(dir(f, b), BinaryName), agentBytes("1.1.0", 2999), 0o755)
		},
		"binary truncated": func(f *fixture, b built) {
			_ = os.Truncate(filepath.Join(dir(f, b), BinaryName), 100)
		},
		"binary missing": func(f *fixture, b built) {
			_ = os.Remove(filepath.Join(dir(f, b), BinaryName))
		},
		"manifest missing": func(f *fixture, b built) {
			_ = os.Remove(filepath.Join(dir(f, b), ManifestFileName))
		},
		"manifest edited": func(f *fixture, b built) {
			path := filepath.Join(dir(f, b), ManifestFileName)
			raw, _ := os.ReadFile(path)
			_ = os.WriteFile(path, bytes.Replace(raw, []byte("1.1.0"), []byte("1.1.9"), 1), 0o600)
		},
		"manifest of another release": func(f *fixture, b built) {
			other := f.release("1.3.0", agentBytes("1.3.0", 10), nil)
			encoded, _ := json.Marshal(other.signed)
			_ = os.WriteFile(filepath.Join(dir(f, b), ManifestFileName), encoded, 0o600)
		},
		"release key removed from the device": func(f *fixture, b built) {
			f.keyring = proto.OTAKeyring{}
		},
		"release key replaced": func(f *fixture, b built) {
			public, _, _ := ed25519.GenerateKey(rand.Reader)
			f.keyring = proto.OTAKeyring{"release-1": public}
		},
		"link points outside the release directory": func(f *fixture, b built) {
			link := filepath.Join(f.stateDir, ReleasesDirName, currentLink)
			_ = os.Remove(link)
			_ = os.Symlink("../../../../bin", link)
		},
		"link points at an absolute path": func(f *fixture, b built) {
			link := filepath.Join(f.stateDir, ReleasesDirName, currentLink)
			_ = os.Remove(link)
			_ = os.Symlink("/bin", link)
		},
	}
	for name, corrupt := range damage {
		t.Run(name, func(t *testing.T) {
			f, release := installed(t)
			corrupt(f, release)
			decision, err := Boot(f.bootOptions("", factoryVersion))
			if err != nil {
				t.Fatal(err)
			}
			if decision.Exec != "" {
				t.Fatalf("start-up selected %s", decision.Exec)
			}
			if decision.Manager.CurrentVersion() != factoryVersion {
				t.Fatalf("the manager believes %s is running", decision.Manager.CurrentVersion())
			}
			if _, ok := decision.Installer.Active(); ok {
				t.Fatal("a release that failed verification is still selected")
			}
		})
	}
}

func TestAReleaseOlderThanTheSystemAgentIsNotRunAfterASystemUpdate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	updater, _ := f.start()
	release := f.release("1.1.0", agentBytes("1.1.0", 100), nil)
	f.deliver(updater, release)
	if _, err := updater.Apply(ctx, release.manifest.ReleaseID); err != nil {
		t.Fatal(err)
	}
	f.stop(updater)
	updater, _ = f.start()
	if _, err := updater.Confirm(release.manifest.ReleaseID); err != nil {
		t.Fatal(err)
	}
	f.stop(updater)

	// A new system image ships agent 2.0.0. The 1.1.0 release on the state
	// partition is validly signed and must not undo the system update.
	decision, err := Boot(f.bootOptions("", "2.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Exec != "" || decision.Manager.CurrentVersion() != "2.0.0" {
		t.Fatalf("an older release ran over a newer system agent: %q", decision.Exec)
	}
	if _, ok := decision.Installer.Active(); ok {
		t.Fatal("the older release is still selected")
	}
}

func TestWithoutReleaseKeysNothingCanBeInstalledAndTheStatusSaysWhy(t *testing.T) {
	f := newFixture(t)
	f.keyring = proto.OTAKeyring{}
	updater, _ := f.start()
	status := updater.Status()
	if status.Supported || updater.Supported() || !strings.Contains(status.UnsupportedReason, "release keys") || status.Keys.Classical != 0 {
		t.Fatalf("status with no keys: %+v", status)
	}
	f.keyring = proto.OTAKeyring{"release-1": f.public}
	release := f.release("1.1.0", agentBytes("1.1.0", 10), nil)
	if _, err := updater.Offer(context.Background(), release.signed); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("offer with no keys: %v", err)
	}
	if _, err := updater.Receive(context.Background(), release.manifest.ReleaseID, 0, bytes.NewReader(release.content)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("receive with no keys: %v", err)
	}
	if _, err := updater.Apply(context.Background(), release.manifest.ReleaseID); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("apply with no keys: %v", err)
	}
}

func TestOnlyOneAgentProcessCanInstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("advisory locks are a unix facility")
	}
	f := newFixture(t)
	first, _ := f.start()
	if !first.Supported() {
		t.Fatal("the first process cannot install")
	}
	// A second agent started against the same state directory.
	decision, err := Boot(f.bootOptions("", factoryVersion))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewUpdater(UpdaterOptions{Decision: decision, StateDir: f.stateDir, Restart: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.Supported() || !strings.Contains(second.Status().UnsupportedReason, "lock") {
		t.Fatalf("a second process may install: %+v", second.Status())
	}
	if _, err := second.Offer(context.Background(), f.release("1.1.0", agentBytes("1.1.0", 10), nil).signed); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("offer to the second process: %v", err)
	}
	// When the first exits, the lock is free again.
	f.stop(first)
	third, err := NewUpdater(UpdaterOptions{Decision: decision, StateDir: f.stateDir, Restart: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if !third.Supported() {
		t.Fatalf("the lock was not released: %s", third.Status().UnsupportedReason)
	}
}

func TestConcurrentRequestsCannotInterleaveATransfer(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	updater, _ := f.start()
	release := f.release("1.1.0", agentBytes("1.1.0", 300_000), nil)
	if _, err := updater.Offer(ctx, release.signed); err != nil {
		t.Fatal(err)
	}
	// Many clients send the whole artifact from offset zero at once. Exactly
	// one sequence of bytes can be accepted; the rest see an offset mismatch
	// or the completed state. The result must be the correct artifact.
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, _ = updater.Receive(ctx, release.manifest.ReleaseID, 0, bytes.NewReader(release.content))
			_ = updater.Status()
		}()
	}
	group.Wait()
	if status := updater.Status(); status.State != proto.OTAReady {
		t.Fatalf("after concurrent uploads: %+v", status)
	}
}

// ---------------------------------------------------------------------------
// Dual-signed releases
// ---------------------------------------------------------------------------

func TestDualSignedReleasesAndTheRequiredPolicy(t *testing.T) {
	if !proto.EnableStandardPQ() {
		t.Skip("this toolchain has no crypto/mldsa")
	}
	t.Cleanup(func() { proto.RegisterPQProvider(nil); proto.SetPQBackendName("none") })
	ctx := context.Background()
	seed, _ := proto.NewMLDSASeed()
	signer, err := proto.NewMLDSASigner(proto.PQSigMLDSA87, seed)
	if err != nil {
		t.Fatal(err)
	}

	// REQUIRED refuses a classical-only release, however valid.
	f := newFixture(t)
	f.policy = proto.OTASignatureRequired
	f.pqKeys = proto.OTAPQKeyring{"release-pq-1": signer.Identity()}
	updater, _ := f.start()
	classical := f.release("1.1.0", agentBytes("1.1.0", 100), nil)
	if _, err := updater.Offer(ctx, classical.signed); !errors.Is(err, proto.ErrOTAPQUnsigned) {
		t.Fatalf("a classical-only release under REQUIRED: %v", err)
	}

	// A dual-signed one installs, and the status says what was verified.
	f.pq = signer
	dual := f.release("1.1.0", agentBytes("1.1.0", 100), nil)
	if dual.signed.PQSignature == "" || dual.signed.PQAlgorithm != proto.PQSigMLDSA87 {
		t.Fatal("the fixture did not dual-sign")
	}
	status := f.deliver(updater, dual)
	if status.State != proto.OTAReady || status.Signatures.Outcome != proto.OTADualSigned ||
		status.Signatures.Policy != proto.OTASignatureRequired || !status.Signatures.PQAvailable || status.Keys.PostQuantum != 1 {
		t.Fatalf("a dual-signed release: %+v", status)
	}
	if _, err := updater.Apply(ctx, dual.manifest.ReleaseID); err != nil {
		t.Fatal(err)
	}
	f.stop(updater)
	updater, decision := f.start()
	if decision.ReleaseID != dual.manifest.ReleaseID {
		t.Fatal("the dual-signed release did not run")
	}
	if _, err := updater.Confirm(dual.manifest.ReleaseID); err != nil {
		t.Fatal(err)
	}
	f.stop(updater)

	// Start-up verifies both signatures too: with the post-quantum release key
	// gone from the device, REQUIRED no longer accepts the installed release.
	f.pqKeys = proto.OTAPQKeyring{}
	decision, err = Boot(f.bootOptions("", factoryVersion))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Exec != "" {
		t.Fatal("start-up ran a release whose post-quantum signature it could not check, under REQUIRED")
	}

	// A broken post-quantum signature fails under PREFERRED as well.
	g := newFixture(t)
	g.pq = signer
	g.pqKeys = proto.OTAPQKeyring{"release-pq-1": signer.Identity()}
	updater, _ = g.start()
	broken := g.release("1.1.0", agentBytes("1.1.0", 100), nil).signed
	raw, _ := base64.StdEncoding.DecodeString(broken.PQSignature)
	raw[100] ^= 0xff
	broken.PQSignature = base64.StdEncoding.EncodeToString(raw)
	if _, err := updater.Offer(ctx, broken); !errors.Is(err, proto.ErrOTAPQUnsigned) {
		t.Fatalf("a broken post-quantum signature under PREFERRED: %v", err)
	}
	// And a classical-only release under PREFERRED installs, named as such.
	g.pq = nil
	plain := g.release("1.1.0", agentBytes("1.1.0", 100), nil)
	if status := g.deliver(updater, plain); status.Signatures.Outcome != proto.OTAClassicalOnly {
		t.Fatalf("a classical-only release under PREFERRED: %+v", status.Signatures)
	}
}

// ---------------------------------------------------------------------------
// The exec path, for real
// ---------------------------------------------------------------------------

// runAsFactory is the factory agent's start-up, run in a child process by the
// test below so that Chain's exec can actually replace something.
func runAsFactory(stateDir string) int {
	raw, err := os.ReadFile(filepath.Join(stateDir, "test-keyring.json"))
	if err != nil {
		fmt.Println("factory: no keyring:", err)
		return 3
	}
	keyring, _, err := ParseKeyring(raw)
	if err != nil {
		fmt.Println("factory: bad keyring:", err)
		return 3
	}
	decision, err := Boot(BootOptions{
		StateDir: stateDir, FactoryVersion: factoryVersion,
		Platform: proto.PlatformMSM8916, Channel: proto.OTAChannelStable, Keyring: keyring,
	})
	if err != nil {
		fmt.Println("factory: boot:", err)
		return 3
	}
	if decision.Exec == "" {
		if os.Getenv("NSH_OTA_TEST_NOTES") != "" {
			fmt.Printf("notes: %v state=%+v\n", decision.Notes, decision.Manager.Status())
		}
		fmt.Printf("factory running version=%s\n", decision.Manager.CurrentVersion())
		return 0
	}
	err = Chain(decision, os.Args[1:], os.Environ())
	ChainFailed(decision, factoryVersion, err)
	_, selected := decision.Installer.Active()
	fmt.Printf("factory running after failed chain version=%s selected=%v state=%s\n",
		decision.Manager.CurrentVersion(), selected, decision.Manager.Status().State)
	return 0
}

func TestTheFactoryAgentChainsIntoAnInstalledReleaseAndSurvivesOneThatWillNotStart(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the installer runs on Linux")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) > proto.OTAMaxArtifactBytes {
		t.Skipf("the test binary is %d bytes, over the artifact limit", len(content))
	}
	f := newFixture(t)
	f.probe = nil
	// The child processes below read the real clock, so the fixture must too:
	// the confirmation deadline is compared with it.
	f.now = time.Now()
	ctx := context.Background()
	encoded, err := EncodeKeyring(f.keyring, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.stateDir, "test-keyring.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	factory := func() string {
		command := exec.Command(self, "-config", "/etc/nassimhub/agent.conf")
		command.Env = []string{"NSH_OTA_TEST_FACTORY=" + f.stateDir, "PATH=/usr/bin:/bin", "NSH_OTA_TEST_NOTES=" + os.Getenv("NSH_OTA_TEST_NOTES")}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("factory process: %v\n%s", err, output)
		}
		return strings.TrimSpace(string(output))
	}

	if output := factory(); !strings.HasSuffix(output, "factory running version="+factoryVersion) {
		t.Fatalf("with nothing installed: %q", output)
	}

	updater, _ := f.start()
	release := f.release(fakeVersion, content, nil)
	f.deliver(updater, release)
	if _, err := updater.Apply(ctx, release.manifest.ReleaseID); err != nil {
		t.Fatal(err)
	}
	f.stop(updater)

	// The factory agent replaces itself with the release, passing its
	// arguments through and telling it which release it is.
	want := fmt.Sprintf("chained release=%s factory=%s args=-config,/etc/nassimhub/agent.conf", release.manifest.ReleaseID, factoryVersion)
	if output := factory(); output != want {
		t.Fatalf("chained start: %q, want %q", output, want)
	}

	// The release's binary loses its execute permission (a damaged
	// filesystem, a noexec mount). It still verifies; it cannot be run. The
	// factory agent keeps running, deselects it, and records why.
	binary := filepath.Join(f.stateDir, ReleasesDirName, release.manifest.ReleaseID, BinaryName)
	// Re-arm: the previous start consumed the expected-restart marker, so
	// apply again from a clean state for an unambiguous scenario.
	_ = os.RemoveAll(filepath.Join(f.stateDir, ReleasesDirName))
	_ = os.Remove(filepath.Join(f.stateDir, StateFileName))
	updater, _ = f.start()
	f.deliver(updater, release)
	if _, err := updater.Apply(ctx, release.manifest.ReleaseID); err != nil {
		t.Fatal(err)
	}
	f.stop(updater)
	if err := os.Chmod(binary, 0o600); err != nil {
		t.Fatal(err)
	}
	// With no execute bit set at all, even root is refused by execve.
	output := factory()
	if !strings.HasPrefix(output, "factory running after failed chain version="+factoryVersion+" selected=false") ||
		!strings.Contains(output, "state="+string(proto.OTARolledBack)) {
		t.Fatalf("a release that cannot be executed: %q", output)
	}
	// And the next start is simply the factory agent.
	if output := factory(); output != "factory running version="+factoryVersion {
		t.Fatalf("the start after a failed chain: %q", output)
	}
}
