// Package trust defines the Node's fail-closed personal-use capability policy.
// Binding inputs are hashes supplied by the owner/Core integration; the
// engine never stores ICCID, IMSI, phone numbers or message content.
package trust

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

type State string

const (
	Unbound     State = "UNBOUND"
	Observation State = "OBSERVATION"
	Trusted     State = "TRUSTED"
	Restricted  State = "RESTRICTED"
	Quarantine  State = "QUARANTINE"
)

type Action string

const (
	Pair        Action = "PAIR"
	ReceiveSMS  Action = "RECEIVE_SMS"
	ReceiveCall Action = "RECEIVE_CALL"
	SendSMS     Action = "SEND_SMS"
	Dial        Action = "DIAL"
	Update      Action = "UPDATE"
	Repair      Action = "REPAIR"
	Diagnose    Action = "DIAGNOSE"
)

const (
	FirstObservation    = 7 * 24 * time.Hour
	ExtendedObservation = 14 * 24 * time.Hour
	LongestObservation  = 30 * 24 * time.Hour
	MaxAccrualStep      = 10 * time.Minute
)

// Record contains hashes and counters only. Account/Core/Modem/SIM inputs are
// expected to be independently salted or keyed before they reach this type.
type Record struct {
	DeviceID          string `json:"device_id"`
	BindingHash       string `json:"binding_hash,omitempty"`
	State             State  `json:"state"`
	StableSeconds     uint64 `json:"stable_seconds"`
	RequiredSeconds   uint64 `json:"required_seconds"`
	SIMChanges        uint32 `json:"sim_changes"`
	ModemChanges      uint32 `json:"modem_changes"`
	IntegrityFailures uint32 `json:"integrity_failures"`
	RiskScore         uint32 `json:"risk_score"`
	Generation        uint64 `json:"generation"`
	LastEventHash     string `json:"last_event_hash,omitempty"`
}

// Engine is safe for concurrent API requests. It does not infer elapsed time
// from wall clock: the caller must supply a bounded monotonic healthy interval.
type Engine struct {
	mu     sync.Mutex
	record Record
}

func New(deviceID string) (*Engine, error) {
	if deviceID == "" {
		return nil, errors.New("device identity is required")
	}
	return &Engine{record: Record{DeviceID: deviceID, State: Unbound}}, nil
}

func (e *Engine) Snapshot() Record {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.record
}

// Bind starts observation. The hash must cover account, Core, Node, modem and
// SIM; an empty or changed binding cannot silently inherit earned trust.
func (e *Engine) Bind(bindingHash string) error {
	if len(bindingHash) != 64 || !isHex(bindingHash) {
		return errors.New("binding must be a SHA-256-sized hex digest")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.record.State == Quarantine || (e.record.State == Restricted && e.record.IntegrityFailures > 0) {
		return errors.New("restricted binding requires an authenticated owner recovery")
	}
	if e.record.BindingHash == bindingHash && e.record.State != Unbound {
		return nil
	}
	if e.record.BindingHash != "" {
		e.record.RiskScore += 3
	}
	e.record.BindingHash = bindingHash
	e.record.State = Observation
	e.record.StableSeconds = 0
	e.record.RequiredSeconds = uint64(observationWindow(e.record.RiskScore).Seconds())
	e.record.Generation++
	return nil
}

// Observe credits only a healthy, stable interval. Delays longer than ten
// minutes require repeated observations so a suspended agent cannot jump over
// the whole cooling period on resume. The duration must come from a monotonic
// clock; wall-clock changes do not grant trust.
func (e *Engine) Observe(elapsed time.Duration, healthy bool) error {
	if elapsed < 0 || elapsed > MaxAccrualStep {
		return fmt.Errorf("observation interval must be within 0..%s", MaxAccrualStep)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !healthy || e.record.State != Observation || e.record.BindingHash == "" {
		return nil
	}
	e.record.StableSeconds += uint64(elapsed / time.Second)
	if e.record.StableSeconds >= e.record.RequiredSeconds {
		e.record.StableSeconds = e.record.RequiredSeconds
		e.record.State = Trusted
	}
	e.record.Generation++
	return nil
}

// ChangeIdentity downgrades immediately. No local timer or changed system
// clock can promote a restricted or quarantined device back to Trusted.
func (e *Engine) ChangeIdentity(sim, modem bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if sim {
		e.record.SIMChanges++
		e.record.RiskScore += 2
	}
	if modem {
		e.record.ModemChanges++
		e.record.RiskScore += 3
	}
	if !sim && !modem {
		return
	}
	e.record.BindingHash = ""
	e.record.StableSeconds = 0
	e.record.RequiredSeconds = uint64(observationWindow(e.record.RiskScore).Seconds())
	if e.record.RiskScore >= 20 {
		e.record.State = Quarantine
	} else if e.record.State != Quarantine {
		e.record.State = Restricted
	}
	e.record.Generation++
}

func (e *Engine) IntegrityFailure() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.record.IntegrityFailures++
	e.record.RiskScore += 5
	if e.record.RiskScore >= 20 {
		e.record.State = Quarantine
	} else if e.record.State != Quarantine {
		e.record.State = Restricted
	}
	e.record.Generation++
}

func observationWindow(score uint32) time.Duration {
	switch {
	case score >= 8:
		return LongestObservation
	case score >= 5:
		return ExtendedObservation
	default:
		return FirstObservation
	}
}

func (e *Engine) Allow(action Action) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch action {
	case Update, Repair, Diagnose:
		return true
	case Pair:
		return e.record.State == Unbound
	case ReceiveSMS, ReceiveCall:
		return e.record.State == Observation || e.record.State == Trusted || e.record.State == Restricted
	case SendSMS, Dial:
		return e.record.State == Trusted
	default:
		return false
	}
}

func isHex(value string) bool {
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}
