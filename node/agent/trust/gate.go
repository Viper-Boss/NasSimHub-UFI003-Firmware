// Package trust is the device's own enforcement of the trust policy its paired
// gateway signed.
//
// The gateway DECIDES how far this device may be used; that judgement needs
// history the device does not have and must not be something the device can
// award itself. This package ENFORCES the decision, so that a restriction
// holds when the request comes from a gateway process that is buggy or
// compromised short of its signing key, from a recording of an earlier
// request, or from this device's own standalone administration page, which
// never passes through the gateway at all.
//
// The rules, in one place:
//
//   - Only the paired owner can issue a policy. It is verified against the key
//     pinned at pairing - not against "it arrived on an authenticated session".
//   - A policy is never replaced by an older one (generation), and an equal
//     generation is accepted only when it is the same signed document.
//   - Permissions expire; restrictions do not. Once a policy has gone stale the
//     actions it denies stay denied, and the actions it allowed are refused too
//     until the owner sends it again or sends a newer one. Unplugging the
//     gateway or winding the clock therefore never lifts a restriction.
//   - The device's wall clock is never needed to USE the device. A UFI003 has
//     no battery-backed clock: it boots at 1970 or at whatever time it last
//     saved, and on USB alone it never learns better. So a policy is accepted
//     whatever the wall clock says (the signature and the generation are the
//     protection against forgery and replay), and how long its permissions
//     last is measured on the monotonic clock from the moment it was received.
//     Wall-clock corrections never shorten or extend a received permit.
//   - Monotonic time does not survive a restart, so a policy read from disk is
//     stale until the owner sends it again. The gateway does that on every new
//     session, before any outgoing request, and the same signed document
//     arriving again counts: it is the owner affirming it now.
//   - With no policy from the current owner, nothing is enforced: an agent
//     paired with a gateway that predates this behaves exactly as it always has.
//   - A stored policy that no longer verifies is neither trusted nor deleted.
//     Everything gated is refused until a valid policy at least as new arrives.
//   - The policy belongs to the Core that signed it. After an unpair it stays on
//     disk and applies again if the SAME Core pairs again, generation floor
//     included. A DIFFERENT Core starts with no policy: the device's owner chose
//     a new authority, and a UFI003 has no hardware root of trust that could
//     bind the device to anything beyond its owner.
//
// Only outgoing use is gated (dial, send an SMS, DTMF, forwarding a code).
// Answering, hanging up, receiving, status, diagnostics, Wi-Fi, updates and
// pairing never consult this package.
package trust

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// FileName is the stored policy inside the state directory.
const FileName = "trust-policy.json"

const (
	filePerm     fs.FileMode = 0o600
	dirPerm      fs.FileMode = 0o700
	maxFileBytes             = 64 << 10
	// logEvery bounds how often a refusal of one action is logged, so a retry
	// loop cannot fill the device log.
	logEvery = 10 * time.Minute
)

// Owner reports the Core this device is paired with, as the device pinned it.
// pairing.Store.Owner has this shape.
type Owner func() (coreID string, key ed25519.PublicKey, pq proto.PQIdentity, paired bool)

// Options configures a Gate.
type Options struct {
	// Dir is the agent's state directory.
	Dir      string
	DeviceID string
	Owner    Owner
	// PQPolicy is the device's post-quantum identity policy, the same one the
	// pairing store enforces on signed requests.
	PQPolicy proto.PQIdentityPolicy
	// Now is the wall clock. It is not trusted: see freshnessLocked.
	Now func() time.Time
	// Monotonic is time that only moves forward at the rate time passes,
	// measured from any fixed origin within this process. The default is the
	// runtime's monotonic clock; a test injects its own to move it apart from
	// the wall clock.
	Monotonic func() time.Duration
	// Logf records installs and refusals. Arguments never include a device
	// id, a core id, a number or message text.
	Logf func(level proto.LogLevel, format string, arguments ...any)
}

// Errors Install returns, besides the proto verification errors.
var (
	// ErrNotPaired means there is no owner to verify a policy against.
	ErrNotPaired = errors.New("the node is not paired; there is no owner to issue a trust policy")
	// ErrRollback means the policy is older than the one held, or has the same
	// generation and is a different document.
	ErrRollback = errors.New("trust policy generation is not newer than the installed one")
)

// Refusal is what Require returns when an action is not allowed.
type Refusal struct {
	Action proto.TrustAction
	// State and Reason are the policy's. Neither carries an identifier.
	State  proto.TrustState
	Reason string
	// Denied is true when the action is on the deny list. When it is false the
	// refusal is because the policy is stale or damaged.
	Denied  bool
	Stale   bool
	Damaged bool
	// Freshness says why a policy that verifies is stale; it is empty for a
	// damaged one.
	Freshness proto.TrustFreshness
}

func (r *Refusal) Error() string {
	switch {
	case r.Damaged:
		return fmt.Sprintf("%s is refused: the stored trust policy does not verify; connect the paired NAS to restore it", r.Action)
	case !r.Denied && r.Freshness == proto.TrustStaleRestart:
		return fmt.Sprintf("%s is refused: this device restarted and the paired NAS has not confirmed its trust policy since (state %s); it is restored automatically when the NAS connects", r.Action, r.State)
	case !r.Denied:
		return fmt.Sprintf("%s is refused: the trust policy has expired (state %s); connect the paired NAS to refresh it", r.Action, r.State)
	}
	message := fmt.Sprintf("%s is not allowed while this device is %s", r.Action, r.State)
	if r.Reason != "" {
		message += " (" + r.Reason + ")"
	}
	return message + "; the paired NAS decides this"
}

// OperationError renders the refusal as the protocol error a handler returns.
func (r *Refusal) OperationError(operation string) *proto.OperationError {
	return &proto.OperationError{Code: proto.ErrorPermissionDenied, Operation: operation, Message: r.Error()}
}

// stored is what the policy file held when it was last read or written.
type stored struct {
	present bool
	// parsed is true when the file is a well-formed envelope. Whether it
	// VERIFIES is a separate question that depends on the current owner.
	parsed bool
	signed proto.SignedTrustPolicy
	// For a file that is not well formed: whatever could still be read of what
	// it claims. Used only to restrict and to set the generation floor.
	claimsKnown     bool
	claimCore       string
	claimGeneration uint64
	claimDeny       []proto.TrustAction
}

// Gate holds the policy and answers Require.
type Gate struct {
	path     string
	deviceID string
	owner    Owner
	pqPolicy proto.PQIdentityPolicy
	now      func() time.Time
	mono     func() time.Duration
	logf     func(level proto.LogLevel, format string, arguments ...any)

	mu     sync.Mutex
	stored stored
	// verifiedFor and verifyErr cache the verification of stored.signed
	// against one owner; the owner can change while the agent runs.
	verifiedFor string
	verifyErr   error
	// armed is true once the owner has sent the stored policy to THIS process
	// (Install accepted it, new or identical); armedAt is the monotonic
	// instant of the latest such moment. Neither is written to disk: after a
	// restart there is no trustworthy measure of how long ago that was.
	armed       bool
	armedAt     time.Duration
	refused     map[proto.TrustAction]uint64
	wouldRefuse map[proto.TrustAction]uint64
	lastLogged  map[string]time.Time
}

// Open reads the stored policy, if there is one. A file that cannot be read
// as a policy is not an error: it is kept, reported as damaged and enforced
// restrictively. Open fails only on a configuration it cannot work with.
func Open(options Options) (*Gate, error) {
	if options.Dir == "" || options.DeviceID == "" || options.Owner == nil {
		return nil, errors.New("the trust gate requires a state directory, the device id and the owner")
	}
	policy := options.PQPolicy
	if policy == "" {
		policy = proto.PQIdentityOptional
	}
	if err := proto.ValidatePQIdentityPolicy(policy); err != nil {
		return nil, err
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	mono := options.Monotonic
	if mono == nil {
		// time.Since reads the monotonic clock that time.Now recorded, so
		// setting the wall clock does not move it.
		started := time.Now()
		mono = func() time.Duration { return time.Since(started) }
	}
	logf := options.Logf
	if logf == nil {
		logf = func(proto.LogLevel, string, ...any) {}
	}
	gate := &Gate{
		path: filepath.Join(options.Dir, FileName), deviceID: options.DeviceID, owner: options.Owner,
		pqPolicy: policy, now: now, mono: mono, logf: logf,
		refused: map[proto.TrustAction]uint64{}, wouldRefuse: map[proto.TrustAction]uint64{}, lastLogged: map[string]time.Time{},
	}
	gate.stored = readStored(gate.path)
	current := gate.evaluateLocked()
	switch {
	case current.damaged:
		logf(proto.LogError, "the stored trust policy does not verify against the paired owner; it is kept, and outgoing use is refused until the owner sends a valid one")
	case current.installed:
		logf(proto.LogInfo, "trust policy loaded: generation %d, state %s, mode %s, %d denied; its restrictions apply now, its permissions once the paired NAS confirms it again",
			current.generation, current.state, current.mode, len(current.deny))
	}
	return gate, nil
}

// readStored never fails: every way the file can be wrong is a kind of damage.
func readStored(path string) stored {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return stored{}
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return stored{present: true}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return stored{present: true}
	}
	if signed, err := proto.DecodeSignedTrustPolicy(raw); err == nil {
		return stored{present: true, parsed: true, signed: signed}
	}
	result := stored{present: true}
	var claims struct {
		CoreID     string   `json:"core_id"`
		Generation uint64   `json:"generation"`
		Deny       []string `json:"deny"`
	}
	if json.Unmarshal(raw, &claims) == nil {
		result.claimsKnown, result.claimCore, result.claimGeneration = true, claims.CoreID, claims.Generation
		for _, action := range proto.TrustActions {
			for _, claimed := range claims.Deny {
				if string(action) == claimed {
					result.claimDeny = append(result.claimDeny, action)
					break
				}
			}
		}
	}
	return result
}

// effective is the policy as it applies right now.
type effective struct {
	installed  bool
	damaged    bool
	stale      bool
	freshness  proto.TrustFreshness
	generation uint64
	state      proto.TrustState
	mode       proto.TrustMode
	deny       []proto.TrustAction
	reason     string
	expiresAt  string
}

func (g *Gate) expectation() (proto.TrustPolicyExpectation, bool) {
	coreID, key, pq, paired := g.owner()
	if !paired {
		return proto.TrustPolicyExpectation{}, false
	}
	return proto.TrustPolicyExpectation{DeviceID: g.deviceID, CoreID: coreID, CoreKey: key, CorePQ: pq, PQPolicy: g.pqPolicy}, true
}

func ownerFingerprint(expect proto.TrustPolicyExpectation) string {
	return strings.Join([]string{expect.CoreID, proto.EncodeKey(expect.CoreKey), string(expect.CorePQ.Algorithm), expect.CorePQ.PublicKey}, "\x00")
}

// freshnessLocked says whether the permissions of a verified policy still
// hold. Restrictions are not its business: they hold regardless.
//
// The measure is monotonic time since the owner last sent the policy, against
// the validity the owner signed (expires_at - issued_at). The device's wall
// clock cannot be that measure. It is wrong after every boot on hardware with
// no battery-backed clock, and whoever holds the device can set it. If it
// were needed, a stick that boots at 1970 with only a USB cable to its NAS
// could never place a call again.
//
// Only an authenticated owner can refresh the permit. Wall-clock changes
// must not invalidate a freshly confirmed permit on a device without an RTC.
func (g *Gate) freshnessLocked(issued, expires time.Time) proto.TrustFreshness {
	if !g.armed {
		return proto.TrustStaleRestart
	}
	if elapsed := g.mono() - g.armedAt; elapsed < 0 || elapsed >= expires.Sub(issued) {
		return proto.TrustStaleExpired
	}
	return proto.TrustFresh
}

// evaluateLocked works out what applies now, for the current owner and clock.
// Nothing is remembered from one call to the next except the signature check
// and when the owner last sent the policy, so a pairing change or the passing
// of time is seen at the next request.
func (g *Gate) evaluateLocked() effective {
	expect, paired := g.expectation()
	if !paired || !g.stored.present {
		return effective{}
	}
	if !g.stored.parsed {
		if g.stored.claimsKnown && g.stored.claimCore != "" && g.stored.claimCore != expect.CoreID {
			return effective{} // it says it is another authority's; it is not ours to apply
		}
		damaged := effective{installed: true, damaged: true, stale: true, mode: proto.TrustEnforce,
			generation: g.stored.claimGeneration, deny: g.stored.claimDeny,
			reason: "the stored trust policy is not readable"}
		if !g.stored.claimsKnown {
			// Nothing of it can be read, so the most restrictive reading is all
			// that is left.
			damaged.deny = append([]proto.TrustAction{}, proto.TrustActions...)
		}
		return damaged
	}
	policy := g.stored.signed.TrustPolicy
	if policy.CoreID != expect.CoreID {
		return effective{}
	}
	if fingerprint := ownerFingerprint(expect); g.verifiedFor != fingerprint {
		_, g.verifyErr = proto.VerifyTrustPolicy(g.stored.signed, expect)
		g.verifiedFor = fingerprint
	}
	if g.verifyErr != nil {
		return effective{installed: true, damaged: true, stale: true, mode: proto.TrustEnforce,
			generation: policy.Generation, state: policy.State, deny: policy.Deny, expiresAt: policy.ExpiresAt,
			reason: "the stored trust policy does not verify against the paired owner"}
	}
	issued, expires, _ := policy.Times() // validated when decoded
	freshness := g.freshnessLocked(issued, expires)
	return effective{installed: true, generation: policy.Generation, state: policy.State, mode: policy.Mode,
		deny: policy.Deny, reason: policy.Reason, expiresAt: policy.ExpiresAt,
		stale: freshness != proto.TrustFresh, freshness: freshness}
}

func (e effective) denies(action proto.TrustAction) bool {
	for _, denied := range e.deny {
		if denied == action {
			return true
		}
	}
	return false
}

// Require is the gate. A handler calls it before it does anything else with a
// request for outgoing use; nil means go ahead, and anything else is a
// *Refusal. A nil Gate allows everything: that is a build or a configuration
// without device-local enforcement.
func (g *Gate) Require(action proto.TrustAction) error {
	return g.decide(action, true)
}

// Check answers what Require would, without counting or logging it. It is for
// a caller that only needs to word a refusal before handing the request to a
// handler that calls Require itself.
func (g *Gate) Check(action proto.TrustAction) error {
	return g.decide(action, false)
}

func (g *Gate) decide(action proto.TrustAction, record bool) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	current := g.evaluateLocked()
	if !current.installed {
		return nil
	}
	denied := current.denies(action)
	if !denied && !current.stale {
		return nil
	}
	if current.mode == proto.TrustMonitor && !current.damaged {
		if record {
			g.wouldRefuse[action]++
			g.logLimitedLocked("monitor:"+string(action), proto.LogInfo,
				"%s would be refused (state %s); the policy is in monitor mode, so it is allowed", action, current.state)
		}
		return nil
	}
	if record {
		g.refused[action]++
		g.logLimitedLocked("refuse:"+string(action), proto.LogWarn,
			"%s refused by the trust policy (state %s, denied=%v, stale=%v %s, damaged=%v)", action, current.state, denied, current.stale, current.freshness, current.damaged)
	}
	return &Refusal{Action: action, State: current.state, Reason: current.reason, Denied: denied, Stale: current.stale, Damaged: current.damaged, Freshness: current.freshness}
}

func (g *Gate) logLimitedLocked(key string, level proto.LogLevel, format string, arguments ...any) {
	now := g.now()
	if last, seen := g.lastLogged[key]; seen && now.Sub(last) < logEvery && !now.Before(last) {
		return
	}
	g.lastLogged[key] = now
	g.logf(level, format, arguments...)
}

// Status reports what the device holds. Hardware is filled in by the caller.
func (g *Gate) Status() proto.TrustStatus {
	status := proto.TrustStatus{Supported: true, Deny: []proto.TrustAction{}}
	if g == nil {
		return status
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	current := g.evaluateLocked()
	if !current.installed {
		return status
	}
	status.Installed, status.Generation, status.State, status.Mode = true, current.generation, current.state, current.mode
	status.Deny = append(status.Deny, current.deny...)
	status.ExpiresAt, status.Stale, status.Damaged, status.Reason = current.expiresAt, current.stale, current.damaged, current.reason
	status.Freshness = current.freshness
	// Enforcing: the device is applying the policy rather than only counting.
	status.Enforcing = current.damaged || current.mode == proto.TrustEnforce
	status.Refused, status.WouldRefuse = copyCounts(g.refused), copyCounts(g.wouldRefuse)
	return status
}

func copyCounts(counts map[proto.TrustAction]uint64) map[proto.TrustAction]uint64 {
	if len(counts) == 0 {
		return nil
	}
	out := make(map[proto.TrustAction]uint64, len(counts))
	for action, count := range counts {
		out[action] = count
	}
	return out
}

// Install verifies a policy and, if it is the owner's and not older than the
// one held, stores it. raw is the JSON envelope exactly as it was received.
//
// The device's wall clock takes no part in whether a policy is accepted: a
// device that boots with a wrong date would otherwise refuse the very policy
// that lets it be used. What stops an old policy from being installed is the
// generation.
//
// Receiving the policy already held, byte for byte, is not a no-op: it is the
// owner affirming it now, so its permissions run again from this moment. The
// gateway relies on that after a device restart, when it sends what it last
// signed.
//
// Every check runs before anything is written, and a failure to write leaves
// the previous policy in force.
func (g *Gate) Install(raw []byte) error {
	if g == nil {
		return errors.New("this node does not enforce a trust policy")
	}
	signed, err := proto.DecodeSignedTrustPolicy(raw)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	expect, paired := g.expectation()
	if !paired {
		return ErrNotPaired
	}
	if _, err := proto.VerifyTrustPolicy(signed, expect); err != nil {
		g.logLimitedLocked("install-refused", proto.LogWarn, "a trust policy was refused: it is not the paired owner's policy for this device")
		return err
	}
	if _, _, err := signed.Times(); err != nil {
		return err
	}

	current := g.evaluateLocked()
	if current.installed {
		switch {
		case signed.Generation < current.generation:
			return fmt.Errorf("%w: %d is installed", ErrRollback, current.generation)
		case signed.Generation == current.generation && !current.damaged:
			if proto.SameSignedTrustPolicy(signed, g.stored.signed) {
				// The same document again: nothing to write. Checked against
				// the pinned key above like any other, so this is the owner.
				g.armed, g.armedAt = true, g.mono()
				return nil
			}
			return fmt.Errorf("%w: generation %d is installed with different content", ErrRollback, current.generation)
		}
		// Higher - or equal to a damaged file's claimed generation, which is
		// the documented way out of a damaged state.
	}
	if err := writeStored(g.path, signed); err != nil {
		return fmt.Errorf("store the trust policy: %w", err)
	}
	g.stored = stored{present: true, parsed: true, signed: signed}
	g.verifiedFor, g.verifyErr = ownerFingerprint(expect), nil
	g.armed, g.armedAt = true, g.mono()
	g.logf(proto.LogInfo, "trust policy installed: generation %d, state %s, mode %s, %d denied",
		signed.Generation, signed.State, signed.Mode, len(signed.Deny))
	return nil
}

// writeStored replaces the policy file atomically and durably: a power cut
// leaves either the old policy or the new one, never a torn file and never
// none. It writes inside the agent's state directory only.
func writeStored(path string, signed proto.SignedTrustPolicy) error {
	encoded, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, dirPerm); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".trust-policy-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(filePerm); err == nil {
		_, err = file.Write(append(encoded, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	// The rename is durable only once the directory entry is.
	if handle, err := os.Open(directory); err == nil {
		_ = handle.Sync()
		_ = handle.Close()
	}
	return nil
}
