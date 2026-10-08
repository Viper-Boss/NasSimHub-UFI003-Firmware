package trust

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// Everything here is offline: a temporary directory, an injected clock and
// keys derived from constant seeds. The keys are fixtures, not secrets.

const testDevice = "NSH-410-TESTDEVICE01"

type testCore struct {
	id  string
	key ed25519.PrivateKey
	pq  *proto.MockPQKeyPair
}

func newTestCore(id string, fill byte) *testCore {
	return &testCore{id: id, key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))}
}

// owner is the pairing store's part: who the device is paired with now.
type owner struct {
	mu     sync.Mutex
	core   *testCore
	pinned proto.PQIdentity
}

func (o *owner) set(core *testCore) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.core, o.pinned = core, proto.PQIdentity{}
	if core != nil && core.pq != nil {
		o.pinned = core.pq.Identity()
	}
}

func (o *owner) get() (string, ed25519.PublicKey, proto.PQIdentity, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.core == nil {
		return "", nil, proto.PQIdentity{}, false
	}
	return o.core.id, o.core.key.Public().(ed25519.PublicKey), o.pinned, true
}

type fixture struct {
	t   *testing.T
	dir string
	// now is the wall clock and mono the monotonic one. They are separate
	// because the gate must treat them differently: advance moves both, as the
	// passing of time does; setWall moves only the wall clock, as an operator,
	// an unset RTC or NTP does.
	now   time.Time
	mono  time.Duration
	nowMu sync.Mutex
	owner *owner
	core  *testCore
	gate  *Gate
	logs  []string
	logMu sync.Mutex
}

func (f *fixture) clock() time.Time {
	f.nowMu.Lock()
	defer f.nowMu.Unlock()
	return f.now
}

func (f *fixture) monotonic() time.Duration {
	f.nowMu.Lock()
	defer f.nowMu.Unlock()
	return f.mono
}

func (f *fixture) advance(by time.Duration) {
	f.nowMu.Lock()
	f.now = f.now.Add(by)
	f.mono += by
	f.nowMu.Unlock()
}

func (f *fixture) setWall(to time.Time) {
	f.nowMu.Lock()
	f.now = to
	f.nowMu.Unlock()
}

// restart reopens the gate as a new agent process would: the file is what is
// left, and the monotonic clock starts somewhere unrelated.
func (f *fixture) restart() *Gate {
	f.nowMu.Lock()
	f.mono = 7 * time.Second
	f.nowMu.Unlock()
	return f.open(proto.PQIdentityOptional)
}

func (f *fixture) mustBe(want proto.TrustFreshness) {
	f.t.Helper()
	status := f.gate.Status()
	if status.Freshness != want || status.Stale != (want != proto.TrustFresh) {
		f.t.Fatalf("freshness: want %s, got %q (stale=%v)", want, status.Freshness, status.Stale)
	}
}

func (f *fixture) open(policy proto.PQIdentityPolicy) *Gate {
	f.t.Helper()
	gate, err := Open(Options{Dir: f.dir, DeviceID: testDevice, Owner: f.owner.get, PQPolicy: policy, Now: f.clock, Monotonic: f.monotonic,
		Logf: func(level proto.LogLevel, format string, arguments ...any) {
			f.logMu.Lock()
			f.logs = append(f.logs, string(level)+" "+fmt.Sprintf(format, arguments...))
			f.logMu.Unlock()
		}})
	if err != nil {
		f.t.Fatal(err)
	}
	f.gate = gate
	return gate
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir(), now: time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC), owner: &owner{}, core: newTestCore("core-test-0001", 0x42)}
	f.owner.set(f.core)
	f.open(proto.PQIdentityOptional)
	return f
}

// policy builds a policy issued now, valid for a day.
func (f *fixture) policy(generation uint64, state proto.TrustState, deny ...proto.TrustAction) proto.TrustPolicy {
	return proto.TrustPolicy{Version: 1, DeviceID: testDevice, CoreID: f.core.id, Generation: generation, State: state,
		Mode: proto.TrustEnforce, Deny: proto.NormalizeTrustDeny(deny), Reason: "test reason",
		IssuedAt: proto.FormatTrustTime(f.clock()), ExpiresAt: proto.FormatTrustTime(f.clock().Add(24 * time.Hour))}
}

func sign(t *testing.T, core *testCore, policy proto.TrustPolicy) []byte {
	t.Helper()
	var pq proto.PQSigner
	if core.pq != nil {
		pq = core.pq
	}
	signed, err := proto.SignTrustPolicy(policy, core.key, pq)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *fixture) install(policy proto.TrustPolicy) {
	f.t.Helper()
	if err := f.gate.Install(sign(f.t, f.core, policy)); err != nil {
		f.t.Fatalf("install generation %d: %v", policy.Generation, err)
	}
}

var outgoing = []proto.TrustAction{proto.TrustActionDial, proto.TrustActionSendSMS, proto.TrustActionDTMF}

func refusal(err error) *Refusal {
	var refused *Refusal
	errors.As(err, &refused)
	return refused
}

func (f *fixture) mustAllow(actions ...proto.TrustAction) {
	f.t.Helper()
	for _, action := range actions {
		if err := f.gate.Require(action); err != nil {
			f.t.Fatalf("%s must be allowed: %v", action, err)
		}
	}
}

func (f *fixture) mustRefuse(actions ...proto.TrustAction) {
	f.t.Helper()
	for _, action := range actions {
		if refusal(f.gate.Require(action)) == nil {
			f.t.Fatalf("%s must be refused", action)
		}
	}
}

func TestNoPolicyEnforcesNothing(t *testing.T) {
	f := newFixture(t)
	f.mustAllow(proto.TrustActions...)
	status := f.gate.Status()
	if !status.Supported || status.Installed || status.Enforcing || status.Stale || status.Damaged || status.Generation != 0 || len(status.Deny) != 0 || status.Deny == nil {
		t.Fatalf("a device with no policy reports exactly that: %+v", status)
	}
	if _, err := os.Stat(filepath.Join(f.dir, FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nothing is written before a policy arrives: %v", err)
	}
	// A nil gate is a configuration without enforcement.
	var none *Gate
	if none.Require(proto.TrustActionDial) != nil || none.Check(proto.TrustActionDial) != nil || none.Status().Installed {
		t.Fatal("a nil gate allows everything")
	}
	if none.Install([]byte(`{}`)) == nil {
		t.Fatal("a nil gate installs nothing")
	}
}

func TestInstallEnforcesTheDenyListAndNothingElse(t *testing.T) {
	f := newFixture(t)
	f.install(f.policy(1, proto.TrustObservation, outgoing...))
	f.mustRefuse(outgoing...)
	f.mustAllow(proto.TrustActionForwardOTP)

	got := refusal(f.gate.Require(proto.TrustActionSendSMS))
	if got.State != proto.TrustObservation || got.Reason != "test reason" || !got.Denied || got.Stale || got.Damaged {
		t.Fatalf("refusal: %+v", got)
	}
	operation := got.OperationError("send_sms")
	if operation.Code != proto.ErrorPermissionDenied || operation.Operation != "send_sms" ||
		!strings.Contains(operation.Message, "OBSERVATION") || !strings.Contains(operation.Message, "test reason") {
		t.Fatalf("operation error: %+v", operation)
	}
	if strings.Contains(operation.Message, testDevice) || strings.Contains(operation.Message, f.core.id) {
		t.Fatalf("a refusal carries no identifier: %s", operation.Message)
	}

	status := f.gate.Status()
	if !status.Installed || !status.Enforcing || status.Stale || status.Damaged || status.Generation != 1 || status.State != proto.TrustObservation ||
		status.Mode != proto.TrustEnforce || len(status.Deny) != 3 || status.Reason != "test reason" || status.ExpiresAt == "" || status.Refused[proto.TrustActionSendSMS] != 2 {
		t.Fatalf("status: %+v", status)
	}
	info, err := os.Stat(filepath.Join(f.dir, FileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the policy file must be private: %v %v", info, err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(f.dir, ".trust-policy-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestHigherGenerationReplacesLowerIsRefusedEqualIsIdempotent(t *testing.T) {
	f := newFixture(t)
	first := f.policy(5, proto.TrustQuarantine, proto.TrustActions...)
	f.install(first)
	f.mustRefuse(proto.TrustActions...)

	// Rollback: a genuine, older policy that would lift the quarantine.
	older := f.policy(4, proto.TrustTrusted)
	if err := f.gate.Install(sign(t, f.core, older)); !errors.Is(err, ErrRollback) {
		t.Fatalf("an older generation must be refused: %v", err)
	}
	// The same generation with other content is not "the same policy again".
	sameNumber := f.policy(5, proto.TrustTrusted)
	if err := f.gate.Install(sign(t, f.core, sameNumber)); !errors.Is(err, ErrRollback) {
		t.Fatalf("an equal generation with different content must be refused: %v", err)
	}
	f.mustRefuse(proto.TrustActions...)

	// The same signed document again is accepted and changes nothing - even
	// when its JSON is laid out differently.
	before, _ := os.ReadFile(filepath.Join(f.dir, FileName))
	if err := f.gate.Install(sign(t, f.core, first)); err != nil {
		t.Fatalf("re-pushing the installed policy must be accepted: %v", err)
	}
	var loose map[string]any
	_ = json.Unmarshal(sign(t, f.core, first), &loose)
	indented, _ := json.MarshalIndent(loose, "", "\t")
	if err := f.gate.Install(indented); err != nil {
		t.Fatalf("re-pushing the installed policy in another layout must be accepted: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(f.dir, FileName))
	if !bytes.Equal(before, after) {
		t.Fatal("an idempotent re-push must not rewrite the file")
	}

	// Higher replaces.
	f.install(f.policy(6, proto.TrustTrusted))
	f.mustAllow(proto.TrustActions...)
	if status := f.gate.Status(); status.Generation != 6 || status.State != proto.TrustTrusted || len(status.Deny) != 0 {
		t.Fatalf("status after replacement: %+v", status)
	}
	// Revocation is a higher generation in QUARANTINE.
	f.install(f.policy(7, proto.TrustQuarantine, proto.TrustActions...))
	f.mustRefuse(proto.TrustActions...)
}

func TestOnlyThePairedOwnersSignatureInstalls(t *testing.T) {
	f := newFixture(t)
	stranger := newTestCore(f.core.id, 0x99) // claims the owner's id, holds another key
	if err := f.gate.Install(sign(t, stranger, f.policy(1, proto.TrustTrusted))); !errors.Is(err, proto.ErrTrustPolicySignature) {
		t.Fatalf("a policy signed by another key must be refused: %v", err)
	}
	otherCore := newTestCore("core-test-0002", 0x99)
	policy := f.policy(1, proto.TrustTrusted)
	policy.CoreID = otherCore.id
	if err := f.gate.Install(sign(t, otherCore, policy)); !errors.Is(err, proto.ErrTrustPolicyWrongCore) {
		t.Fatalf("a policy from another core must be refused: %v", err)
	}
	// A genuine policy, signed by the owner, for a different device.
	elsewhere := f.policy(1, proto.TrustTrusted)
	elsewhere.DeviceID = "NSH-410-TESTDEVICE02"
	if err := f.gate.Install(sign(t, f.core, elsewhere)); !errors.Is(err, proto.ErrTrustPolicyWrongDevice) {
		t.Fatalf("a policy replayed at another device must be refused: %v", err)
	}
	// Tampered after signing.
	var envelope map[string]any
	_ = json.Unmarshal(sign(t, f.core, f.policy(1, proto.TrustQuarantine, proto.TrustActions...)), &envelope)
	envelope["deny"] = []string{}
	tampered, _ := json.Marshal(envelope)
	if err := f.gate.Install(tampered); !errors.Is(err, proto.ErrTrustPolicySignature) {
		t.Fatalf("a tampered policy must be refused: %v", err)
	}
	if err := f.gate.Install([]byte(`{"state":"TRUSTED"}`)); !errors.Is(err, proto.ErrTrustPolicyInvalid) {
		t.Fatalf("a malformed policy must be refused: %v", err)
	}
	if f.gate.Status().Installed {
		t.Fatal("a refused policy must leave nothing installed")
	}
	if _, err := os.Stat(filepath.Join(f.dir, FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused policy must not be written")
	}
	// Unpaired: there is no owner to verify against.
	f.owner.set(nil)
	if err := f.gate.Install(sign(t, f.core, f.policy(1, proto.TrustTrusted))); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("an unpaired node installs nothing: %v", err)
	}
}

// The document's own times are checked; the device's wall clock is not asked
// whether it agrees with them.
func TestPolicyTimesAreBounded(t *testing.T) {
	f := newFixture(t)
	// A policy issued far in what this device calls the future is accepted:
	// the device's clock is the one more likely to be wrong.
	future := f.policy(1, proto.TrustTrusted)
	future.IssuedAt = proto.FormatTrustTime(f.clock().Add(3 * 365 * 24 * time.Hour))
	future.ExpiresAt = proto.FormatTrustTime(f.clock().Add(3*365*24*time.Hour + time.Hour))
	f.install(future)
	f.mustBe(proto.TrustFresh)
	f.mustAllow(proto.TrustActions...)
	// expires_at <= issued_at and a validity over seven days cannot even be
	// signed by the honest signer, so the envelope is built by hand.
	for name, change := range map[string]func(*proto.TrustPolicy){
		"expires at issue": func(p *proto.TrustPolicy) { p.ExpiresAt = p.IssuedAt },
		"eight days":       func(p *proto.TrustPolicy) { p.ExpiresAt = proto.FormatTrustTime(f.clock().Add(8 * 24 * time.Hour)) },
		"not a time":       func(p *proto.TrustPolicy) { p.IssuedAt = "yesterday" },
	} {
		policy := f.policy(2, proto.TrustTrusted)
		change(&policy)
		raw, _ := json.Marshal(proto.SignedTrustPolicy{TrustPolicy: policy, Signature: "AAAA"})
		if err := f.gate.Install(raw); !errors.Is(err, proto.ErrTrustPolicyInvalid) {
			t.Errorf("%s: must be refused as invalid, got %v", name, err)
		}
	}
}

// "Permissions expire; restrictions do not."
func TestExpiredPolicyKeepsDenyingAndStopsAllowing(t *testing.T) {
	f := newFixture(t)
	f.install(f.policy(1, proto.TrustTrusted, proto.TrustActionForwardOTP))
	f.mustAllow(outgoing...)
	f.mustRefuse(proto.TrustActionForwardOTP)

	f.advance(24*time.Hour - time.Second)
	f.mustAllow(outgoing...)
	f.advance(time.Second) // exactly the validity the owner signed
	f.mustBe(proto.TrustStaleExpired)
	status := f.gate.Status()
	if !status.Stale || !status.Installed || !status.Enforcing || status.Damaged {
		t.Fatalf("an expired policy is stale: %+v", status)
	}
	// What was denied stays denied, however long the gateway is away...
	f.advance(400 * 24 * time.Hour)
	denied := refusal(f.gate.Require(proto.TrustActionForwardOTP))
	if denied == nil || !denied.Denied || !denied.Stale {
		t.Fatalf("a restriction must outlive its policy's expiry: %+v", denied)
	}
	// ...and what was allowed is refused until the owner sends a fresh policy.
	for _, action := range outgoing {
		stale := refusal(f.gate.Require(action))
		if stale == nil || stale.Denied || !stale.Stale {
			t.Fatalf("%s on an expired policy: %+v", action, stale)
		}
		if message := stale.OperationError("x").Message; !strings.Contains(message, "expired") || !strings.Contains(message, "NAS") {
			t.Fatalf("the refusal must say what to do: %s", message)
		}
	}
	// Winding the wall clock back to before expiry is not prevented (there is
	// no trusted clock on the device). It lifts nothing that was denied and
	// brings back nothing that had lapsed.
	f.setWall(f.clock().Add(-401 * 24 * time.Hour))
	f.mustRefuse(proto.TrustActionForwardOTP)
	f.mustRefuse(outgoing...)
	f.mustBe(proto.TrustStaleExpired)

	// A fresh policy from the owner restores the allow side.
	f.setWall(f.clock().Add(401 * 24 * time.Hour))
	f.install(f.policy(2, proto.TrustTrusted, proto.TrustActionForwardOTP))
	f.mustAllow(outgoing...)
	f.mustRefuse(proto.TrustActionForwardOTP)
	if f.gate.Status().Stale {
		t.Fatal("a fresh policy is not stale")
	}
}

var epoch = time.Date(1970, 1, 1, 0, 5, 0, 0, time.UTC)

// A UFI003 has no battery-backed clock. Booting at 1970 with only a USB cable
// to its NAS, it must still be usable: the policy the NAS sends is accepted
// and what it permits works.
func TestUnsetWallClockDoesNotLockTheDeviceOut(t *testing.T) {
	f := newFixture(t)
	issued := f.clock() // the gateway's idea of now
	f.setWall(epoch)    // the device's
	policy := f.policy(1, proto.TrustTrusted, proto.TrustActionForwardOTP)
	policy.IssuedAt, policy.ExpiresAt = proto.FormatTrustTime(issued), proto.FormatTrustTime(issued.Add(24*time.Hour))
	f.install(policy)
	f.mustBe(proto.TrustFresh)
	f.mustAllow(outgoing...)
	f.mustRefuse(proto.TrustActionForwardOTP)
	if status := f.gate.Status(); !status.Enforcing || status.Damaged || status.Generation != 1 {
		t.Fatalf("status with an unset clock: %+v", status)
	}
	// It lasts as long as the owner signed, measured without the wall clock.
	f.advance(24*time.Hour - time.Second)
	f.mustAllow(outgoing...)
	f.advance(time.Second)
	f.mustBe(proto.TrustStaleExpired)
	f.mustRefuse(outgoing...)
	f.mustRefuse(proto.TrustActionForwardOTP)
	// The next policy is accepted the same way. The wall clock is still wrong.
	next := f.policy(2, proto.TrustTrusted)
	next.IssuedAt, next.ExpiresAt = proto.FormatTrustTime(issued.Add(24*time.Hour)), proto.FormatTrustTime(issued.Add(48*time.Hour))
	f.install(next)
	f.mustAllow(proto.TrustActions...)
}

// The clock being set right while a policy is held (NTP lands) changes
// nothing: the wall clock was before issued_at and is now inside the validity.
func TestWallClockBecomingCorrectKeepsThePolicyFresh(t *testing.T) {
	f := newFixture(t)
	issued := f.clock()
	f.setWall(epoch)
	policy := f.policy(1, proto.TrustTrusted)
	policy.IssuedAt, policy.ExpiresAt = proto.FormatTrustTime(issued), proto.FormatTrustTime(issued.Add(24*time.Hour))
	f.install(policy)
	f.advance(time.Minute)
	f.setWall(issued.Add(time.Minute))
	f.mustBe(proto.TrustFresh)
	f.mustAllow(proto.TrustActions...)
	// Exactly at expires_at the wall clock has not passed it.
	f.setWall(issued.Add(24 * time.Hour))
	f.mustBe(proto.TrustFresh)
	f.setWall(issued.Add(24*time.Hour + time.Second))
	f.mustBe(proto.TrustFresh)
	f.mustAllow(proto.TrustActions...)
}

// A forward wall-clock correction must not invalidate a freshly confirmed
// permit. The original monotonic deadline still expires without a renewal.
func TestWallClockForwardCorrectionPreservesMonotonicDeadline(t *testing.T) {
	f := newFixture(t)
	f.install(f.policy(1, proto.TrustTrusted, proto.TrustActionForwardOTP))
	f.advance(time.Minute)
	f.setWall(f.clock().Add(10 * 365 * 24 * time.Hour))
	f.mustBe(proto.TrustFresh)
	f.mustAllow(outgoing...)
	f.mustRefuse(proto.TrustActionForwardOTP)
	f.advance(24*time.Hour - time.Minute)
	f.mustBe(proto.TrustStaleExpired)
	f.mustRefuse(outgoing...)
	f.mustRefuse(proto.TrustActionForwardOTP)
	// Reconfirmation by the authenticated owner restores only permitted use.
	f.install(f.storedPolicy())
	f.mustBe(proto.TrustFresh)
	f.mustAllow(outgoing...)
	f.mustRefuse(proto.TrustActionForwardOTP)
}

// Setting the wall clock BACK buys no time: the validity is counted on the
// monotonic clock, which does not move with it.
func TestWallClockSetBackDoesNotExtendFreshness(t *testing.T) {
	f := newFixture(t)
	issued := f.clock()
	f.install(f.policy(1, proto.TrustTrusted, proto.TrustActionForwardOTP))
	for hour := 1; hour <= 23; hour++ {
		f.advance(time.Hour)
		f.setWall(issued.Add(time.Minute)) // wound back every hour
		f.mustBe(proto.TrustFresh)
	}
	f.advance(time.Hour)
	f.setWall(issued.Add(time.Minute))
	f.mustBe(proto.TrustStaleExpired)
	f.mustRefuse(outgoing...)
	// Nor does winding it to before the policy existed.
	f.setWall(epoch)
	f.mustBe(proto.TrustStaleExpired)
	f.mustRefuse(outgoing...)
	f.mustRefuse(proto.TrustActionForwardOTP)
}

// storedPolicy is the policy the gate holds, for sending again unchanged.
func (f *fixture) storedPolicy() proto.TrustPolicy {
	f.t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.dir, FileName))
	if err != nil {
		f.t.Fatal(err)
	}
	signed, err := proto.DecodeSignedTrustPolicy(raw)
	if err != nil {
		f.t.Fatal(err)
	}
	return signed.TrustPolicy
}

// Monotonic time does not survive a restart, so the device does not guess how
// long it was off: what the stored policy denies is denied at once, and what
// it permits waits for the owner to send it again.
func TestRestartIsStaleUntilTheOwnerSendsThePolicyAgain(t *testing.T) {
	f := newFixture(t)
	f.install(f.policy(3, proto.TrustTrusted, proto.TrustActionForwardOTP))
	f.mustAllow(outgoing...)
	before := f.gate.Status()

	f.restart()
	after := f.gate.Status()
	if !after.Installed || after.Generation != 3 || after.State != before.State || len(after.Deny) != 1 || after.Damaged || !after.Enforcing {
		t.Fatalf("after a restart the policy is the one stored: %+v", after)
	}
	f.mustBe(proto.TrustStaleRestart)
	f.mustRefuse(proto.TrustActionForwardOTP)
	for _, action := range outgoing {
		got := refusal(f.gate.Require(action))
		if got == nil || got.Denied || !got.Stale || got.Freshness != proto.TrustStaleRestart {
			t.Fatalf("%s after a restart: %+v", action, got)
		}
		if message := got.OperationError("x").Message; !strings.Contains(message, "restarted") || !strings.Contains(message, "NAS") || strings.Contains(message, "expired") {
			t.Fatalf("the refusal must say why and what restores it: %s", message)
		}
	}
	// However long it waits and whatever the wall clock does, it stays so.
	f.advance(time.Hour)
	f.mustBe(proto.TrustStaleRestart)
	f.setWall(epoch)
	f.mustBe(proto.TrustStaleRestart)
	// The generation floor survives.
	if err := f.gate.Install(sign(t, f.core, f.policy(2, proto.TrustTrusted))); !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback after a restart: %v", err)
	}
	f.mustBe(proto.TrustStaleRestart)
	// Someone else's signature on the same policy is not the owner speaking.
	stranger := newTestCore(f.core.id, 0x77)
	if err := f.gate.Install(sign(t, stranger, f.storedPolicy())); !errors.Is(err, proto.ErrTrustPolicySignature) {
		t.Fatalf("a re-push signed by another key: %v", err)
	}
	f.mustBe(proto.TrustStaleRestart)

	// The owner sends the very same document: fresh again, nothing rewritten.
	stored, _ := os.ReadFile(filepath.Join(f.dir, FileName))
	f.install(f.storedPolicy())
	f.mustBe(proto.TrustFresh)
	f.mustAllow(outgoing...)
	f.mustRefuse(proto.TrustActionForwardOTP)
	if now, _ := os.ReadFile(filepath.Join(f.dir, FileName)); !bytes.Equal(now, stored) {
		t.Fatal("an identical policy must not rewrite the file")
	}
	// And a restricted device is refused by the device across the restart,
	// before and after the owner speaks.
	f.install(f.policy(4, proto.TrustRestricted, proto.TrustActions...))
	f.restart()
	f.mustRefuse(proto.TrustActions...)
	f.install(f.storedPolicy())
	f.mustBe(proto.TrustFresh)
	for _, action := range proto.TrustActions {
		if got := refusal(f.gate.Require(action)); got == nil || !got.Denied {
			t.Fatalf("%s must stay denied: %+v", action, got)
		}
	}
}

// The same document arriving again is the owner affirming it now: its
// permissions run again from that moment. Without this a gateway whose
// decision has not changed would have to burn a generation at every reconnect.
func TestIdenticalRepushRefreshes(t *testing.T) {
	f := newFixture(t)
	f.install(f.policy(1, proto.TrustTrusted, proto.TrustActionForwardOTP))
	policy := f.storedPolicy()
	f.advance(23 * time.Hour)
	f.setWall(epoch) // so that only the monotonic measure is in play
	f.install(policy)
	f.advance(23 * time.Hour) // 46 h after the first install, 23 h after the second
	f.mustBe(proto.TrustFresh)
	f.mustAllow(outgoing...)
	f.advance(time.Hour)
	f.mustBe(proto.TrustStaleExpired)
	f.mustRefuse(outgoing...)
	f.install(policy)
	f.mustBe(proto.TrustFresh)
	// A different document under the same generation is still a rollback, and
	// refreshes nothing.
	f.advance(24 * time.Hour)
	other := policy
	other.Reason = "another reason"
	if err := f.gate.Install(sign(t, f.core, other)); !errors.Is(err, ErrRollback) {
		t.Fatalf("same generation, different content: %v", err)
	}
	f.mustBe(proto.TrustStaleExpired)
	f.mustRefuse(proto.TrustActionForwardOTP)
}

func TestDamagedFileIsKeptReportedAndRestrictive(t *testing.T) {
	path := func(f *fixture) string { return filepath.Join(f.dir, FileName) }

	t.Run("signature no longer verifies", func(t *testing.T) {
		f := newFixture(t)
		f.install(f.policy(9, proto.TrustQuarantine, proto.TrustActions...))
		// Someone edits the file to lift the quarantine.
		var envelope map[string]any
		raw, _ := os.ReadFile(path(f))
		_ = json.Unmarshal(raw, &envelope)
		envelope["state"], envelope["deny"] = "TRUSTED", []string{"dial"}
		edited, _ := json.Marshal(envelope)
		if err := os.WriteFile(path(f), edited, 0o600); err != nil {
			t.Fatal(err)
		}
		f.open(proto.PQIdentityOptional)
		status := f.gate.Status()
		if !status.Installed || !status.Damaged || !status.Stale || !status.Enforcing || status.Generation != 9 {
			t.Fatalf("an edited policy is damaged: %+v", status)
		}
		// Nothing it now "permits" is permitted.
		f.mustRefuse(proto.TrustActions...)
		if got := refusal(f.gate.Require(proto.TrustActionSendSMS)); !got.Damaged {
			t.Fatalf("refusal: %+v", got)
		}
		// It is not deleted and not rewritten.
		kept, _ := os.ReadFile(path(f))
		if !bytes.Equal(kept, edited) {
			t.Fatal("a damaged file must be left as it was found")
		}
		joined := strings.Join(f.logs, "\n")
		if !strings.Contains(joined, "does not verify") {
			t.Fatalf("damage must be logged: %s", joined)
		}
		// Recovery needs a valid policy at least as new as the file claimed.
		if err := f.gate.Install(sign(t, f.core, f.policy(8, proto.TrustTrusted))); !errors.Is(err, ErrRollback) {
			t.Fatalf("a policy older than the damaged file's claim must be refused: %v", err)
		}
		f.install(f.policy(9, proto.TrustTrusted))
		f.mustAllow(proto.TrustActions...)
		if status := f.gate.Status(); status.Damaged || status.Stale {
			t.Fatalf("recovered: %+v", status)
		}
	})

	t.Run("not a policy at all", func(t *testing.T) {
		f := newFixture(t)
		if err := os.WriteFile(path(f), []byte("\x00\x01 not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		f.open(proto.PQIdentityOptional)
		status := f.gate.Status()
		if !status.Installed || !status.Damaged || !status.Enforcing || len(status.Deny) != len(proto.TrustActions) {
			t.Fatalf("an unreadable file gets the most restrictive reading: %+v", status)
		}
		f.mustRefuse(proto.TrustActions...)
		if _, err := os.Stat(path(f)); err != nil {
			t.Fatal("an unreadable file must be kept")
		}
		f.install(f.policy(1, proto.TrustTrusted))
		f.mustAllow(proto.TrustActions...)
	})

	t.Run("truncated but readable claims", func(t *testing.T) {
		f := newFixture(t)
		// Not a valid envelope (no signature, unknown field), but its claims
		// can still be read.
		claims := fmt.Sprintf(`{"core_id":%q,"generation":12,"deny":["send_sms","made_up"],"note":"x"}`, f.core.id)
		if err := os.WriteFile(path(f), []byte(claims), 0o600); err != nil {
			t.Fatal(err)
		}
		f.open(proto.PQIdentityOptional)
		status := f.gate.Status()
		if !status.Damaged || status.Generation != 12 || len(status.Deny) != 1 || status.Deny[0] != proto.TrustActionSendSMS {
			t.Fatalf("claims of a damaged file: %+v", status)
		}
		f.mustRefuse(proto.TrustActions...)
		if err := f.gate.Install(sign(t, f.core, f.policy(11, proto.TrustTrusted))); !errors.Is(err, ErrRollback) {
			t.Fatalf("floor from a damaged file: %v", err)
		}
		f.install(f.policy(12, proto.TrustTrusted))
	})

	t.Run("a symbolic link is not a policy file", func(t *testing.T) {
		f := newFixture(t)
		target := filepath.Join(f.dir, "elsewhere")
		_ = os.WriteFile(target, sign(t, f.core, f.policy(1, proto.TrustTrusted)), 0o600)
		if err := os.Symlink(target, path(f)); err != nil {
			t.Skip("no symlinks here")
		}
		f.open(proto.PQIdentityOptional)
		if status := f.gate.Status(); !status.Damaged {
			t.Fatalf("a link must not be followed: %+v", status)
		}
		f.mustRefuse(outgoing...)
	})
}

func TestUnpairKeepsThePolicyForItsCoreOnly(t *testing.T) {
	f := newFixture(t)
	f.install(f.policy(5, proto.TrustQuarantine, proto.TrustActions...))
	stored, _ := os.ReadFile(filepath.Join(f.dir, FileName))

	// Unpaired: the policy belongs to a Core that is no longer the owner. It
	// is kept on disk and applies to nobody.
	f.owner.set(nil)
	if status := f.gate.Status(); status.Installed || status.Enforcing {
		t.Fatalf("an unpaired device has no policy in force: %+v", status)
	}
	f.mustAllow(proto.TrustActions...)
	kept, _ := os.ReadFile(filepath.Join(f.dir, FileName))
	if !bytes.Equal(stored, kept) {
		t.Fatal("unpairing must not touch the stored policy")
	}

	// Paired again with the SAME Core: the same policy, the same floor.
	f.owner.set(f.core)
	if status := f.gate.Status(); !status.Installed || status.Generation != 5 || status.State != proto.TrustQuarantine || status.Damaged {
		t.Fatalf("re-pairing with the same core re-applies its policy: %+v", status)
	}
	f.mustRefuse(proto.TrustActions...)
	if err := f.gate.Install(sign(t, f.core, f.policy(4, proto.TrustTrusted))); !errors.Is(err, ErrRollback) {
		t.Fatalf("the generation floor survives an unpair: %v", err)
	}
	// The same holds across a restart while unpaired.
	f.owner.set(nil)
	f.open(proto.PQIdentityOptional)
	f.mustAllow(proto.TrustActions...)
	f.owner.set(f.core)
	f.mustRefuse(proto.TrustActions...)
}

func TestPairingWithADifferentCoreStartsWithNoPolicy(t *testing.T) {
	f := newFixture(t)
	f.install(f.policy(5, proto.TrustQuarantine, proto.TrustActions...))
	first := f.core

	second := newTestCore("core-test-0002", 0x77)
	f.owner.set(second)
	if status := f.gate.Status(); status.Installed || status.Damaged || status.Enforcing {
		t.Fatalf("another core's policy does not apply to the new owner: %+v", status)
	}
	f.mustAllow(proto.TrustActions...)
	// The previous owner can no longer install anything...
	if err := f.gate.Install(sign(t, first, f.policy(6, proto.TrustQuarantine, proto.TrustActions...))); !errors.Is(err, proto.ErrTrustPolicyWrongCore) {
		t.Fatalf("the previous owner's policy must be refused: %v", err)
	}
	// ...and the new one starts its own generations from wherever it likes.
	f.core = second
	f.install(f.policy(1, proto.TrustObservation, outgoing...))
	f.mustRefuse(outgoing...)
	if status := f.gate.Status(); status.Generation != 1 || status.State != proto.TrustObservation {
		t.Fatalf("new owner's policy: %+v", status)
	}
	// A different key under the SAME core id is not the same owner: the
	// stored policy does not verify, and that is damage, not a clean slate.
	impostor := newTestCore(second.id, 0x78)
	f.owner.set(impostor)
	if status := f.gate.Status(); !status.Damaged || !status.Enforcing {
		t.Fatalf("same id, other key: %+v", status)
	}
	f.mustRefuse(proto.TrustActions...)
}

func TestMonitorModeRefusesNothingAndCounts(t *testing.T) {
	f := newFixture(t)
	policy := f.policy(1, proto.TrustObservation, outgoing...)
	policy.Mode = proto.TrustMonitor
	f.install(policy)
	f.mustAllow(proto.TrustActions...)
	f.mustAllow(proto.TrustActionSendSMS)
	status := f.gate.Status()
	if status.Enforcing || !status.Installed || status.Mode != proto.TrustMonitor ||
		status.WouldRefuse[proto.TrustActionSendSMS] != 2 || status.WouldRefuse[proto.TrustActionDial] != 1 ||
		status.WouldRefuse[proto.TrustActionForwardOTP] != 0 || len(status.Refused) != 0 {
		t.Fatalf("monitor mode counts what it would have refused: %+v", status)
	}
	// Check does not count.
	if f.gate.Check(proto.TrustActionDial) != nil || f.gate.Status().WouldRefuse[proto.TrustActionDial] != 1 {
		t.Fatal("Check must not count")
	}
	// Expired monitor policy: still refuses nothing, still counts.
	f.advance(48 * time.Hour)
	f.mustAllow(proto.TrustActionForwardOTP)
	if got := f.gate.Status(); got.WouldRefuse[proto.TrustActionForwardOTP] != 1 || !got.Stale || got.Enforcing {
		t.Fatalf("stale monitor policy: %+v", got)
	}
	// Switching the same device to enforce is a higher generation.
	f.install(f.policy(2, proto.TrustObservation, outgoing...))
	f.mustRefuse(outgoing...)
}

func TestRefusalsAreLoggedAtMostOncePerActionPerTenMinutes(t *testing.T) {
	f := newFixture(t)
	f.install(f.policy(1, proto.TrustObservation, outgoing...))
	count := func(fragment string) int {
		f.logMu.Lock()
		defer f.logMu.Unlock()
		total := 0
		for _, line := range f.logs {
			if strings.Contains(line, fragment) {
				total++
			}
		}
		return total
	}
	for range 50 {
		f.mustRefuse(proto.TrustActionSendSMS)
	}
	f.mustRefuse(proto.TrustActionDial)
	if count("send_sms refused") != 1 || count("dial refused") != 1 {
		t.Fatalf("refusals must be rate limited per action: %v", f.logs)
	}
	f.advance(10*time.Minute + time.Second)
	f.mustRefuse(proto.TrustActionSendSMS)
	if count("send_sms refused") != 2 {
		t.Fatalf("a refusal is logged again after ten minutes: %v", f.logs)
	}
	if count("trust policy installed: generation 1") != 1 {
		t.Fatalf("an install is logged: %v", f.logs)
	}
	for _, line := range f.logs {
		if strings.Contains(line, testDevice) || strings.Contains(line, f.core.id) {
			t.Fatalf("a log line carries an identifier: %s", line)
		}
	}
}

func TestPostQuantumPolicyOnTheGate(t *testing.T) {
	proto.EnableMockPQIdentity()
	defer proto.DisableMockPQIdentity()
	pq, err := proto.NewMockPQKeyPair(proto.PQSigMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	classical := sign(t, f.core, f.policy(1, proto.TrustTrusted))
	f.core.pq = pq
	f.owner.set(f.core) // the owner's post-quantum key is pinned
	dual := sign(t, f.core, f.policy(2, proto.TrustTrusted))

	// required: the classical-only policy is refused, the dual one installs.
	f.open(proto.PQIdentityRequired)
	if err := f.gate.Install(classical); !errors.Is(err, proto.ErrPQIdentityRequired) {
		t.Fatalf("required: a policy without the post-quantum signature must be refused: %v", err)
	}
	if err := f.gate.Install(dual); err != nil {
		t.Fatalf("required: dual: %v", err)
	}
	// A present post-quantum signature that does not verify is refused under
	// every policy.
	var envelope map[string]any
	_ = json.Unmarshal(sign(t, f.core, f.policy(3, proto.TrustTrusted)), &envelope)
	other, _ := proto.NewMockPQKeyPair(proto.PQSigMLDSA65)
	bad, _ := proto.SignTrustPolicy(f.policy(3, proto.TrustTrusted), f.core.key, other)
	raw, _ := json.Marshal(bad)
	for _, policy := range []proto.PQIdentityPolicy{proto.PQIdentityOptional, proto.PQIdentityPreferred, proto.PQIdentityRequired} {
		f.open(policy)
		if err := f.gate.Install(raw); !errors.Is(err, proto.ErrPQIdentityInvalid) {
			t.Fatalf("%s: a bad post-quantum signature must be refused: %v", policy, err)
		}
	}
	// optional with a pinned key: an absent signature is accepted.
	f.open(proto.PQIdentityOptional)
	f.core.pq = nil
	if err := f.gate.Install(sign(t, f.core, f.policy(4, proto.TrustTrusted))); err != nil {
		t.Fatalf("optional: classical-only must be accepted: %v", err)
	}
	// A policy stored under optional and reloaded under required no longer
	// meets the bar: damaged, restrictive.
	f.open(proto.PQIdentityRequired)
	if status := f.gate.Status(); !status.Damaged {
		t.Fatalf("a stored classical-only policy under a required policy: %+v", status)
	}
}

// Concurrent pushes and requests. Run with -race.
func TestConcurrentInstallAndRequire(t *testing.T) {
	f := newFixture(t)
	const pushes = 40
	envelopes := make([][]byte, pushes)
	for index := range envelopes {
		deny := outgoing
		if index%2 == 0 {
			deny = nil
		}
		envelopes[index] = sign(t, f.core, f.policy(uint64(index+1), proto.TrustObservation, deny...))
	}
	var group sync.WaitGroup
	var installed sync.Map
	for index, envelope := range envelopes {
		group.Add(1)
		go func(index int, envelope []byte) {
			defer group.Done()
			err := f.gate.Install(envelope)
			if err != nil && !errors.Is(err, ErrRollback) {
				t.Errorf("push %d: %v", index+1, err)
			}
			if err == nil {
				installed.Store(index+1, true)
			}
		}(index, envelope)
	}
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 200 {
				_ = f.gate.Require(proto.TrustActionSendSMS)
				_ = f.gate.Status()
			}
		}()
	}
	group.Wait()
	// Whatever the interleaving, the highest generation won and is on disk.
	status := f.gate.Status()
	if status.Generation != pushes {
		t.Fatalf("the highest generation must be the one installed: %+v", status)
	}
	if _, ok := installed.Load(pushes); !ok {
		t.Fatal("the highest generation was never accepted")
	}
	reopened := f.open(proto.PQIdentityOptional).Status()
	if reopened.Generation != pushes || reopened.Damaged {
		t.Fatalf("on disk after concurrent pushes: %+v", reopened)
	}
	leftovers, _ := filepath.Glob(filepath.Join(f.dir, ".trust-policy-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestOpenRefusesAnUnusableConfiguration(t *testing.T) {
	if _, err := Open(Options{}); err == nil {
		t.Fatal("a gate needs a directory, a device id and an owner")
	}
	if _, err := Open(Options{Dir: t.TempDir(), DeviceID: testDevice, Owner: (&owner{}).get, PQPolicy: "sometimes"}); err == nil {
		t.Fatal("an unknown identity policy must be refused")
	}
}
