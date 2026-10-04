package trust

import (
	"strings"
	"testing"
	"time"
)

func TestObservationCannotSendUntilStableSevenDays(t *testing.T) {
	engine, err := New("NSH-410-123456")
	if err != nil {
		t.Fatal(err)
	}
	if !engine.Allow(Pair) || engine.Allow(SendSMS) || engine.Allow(ReceiveSMS) {
		t.Fatal("unbound capabilities are wrong")
	}
	if err := engine.Bind(strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if !engine.Allow(ReceiveSMS) || !engine.Allow(ReceiveCall) || engine.Allow(SendSMS) || engine.Allow(Dial) {
		t.Fatal("observation must receive but not originate")
	}
	for i := 0; i < int(FirstObservation/MaxAccrualStep)-1; i++ {
		if err := engine.Observe(MaxAccrualStep, true); err != nil {
			t.Fatal(err)
		}
	}
	if engine.Allow(SendSMS) {
		t.Fatal("outgoing SMS unlocked early")
	}
	if err := engine.Observe(MaxAccrualStep, true); err != nil {
		t.Fatal(err)
	}
	if !engine.Allow(SendSMS) || !engine.Allow(Dial) || engine.Snapshot().State != Trusted {
		t.Fatal("stable binding did not become trusted")
	}
}

func TestClockJumpOrUnhealthyTimeCannotAdvanceObservation(t *testing.T) {
	engine, _ := New("device")
	_ = engine.Bind(strings.Repeat("b", 64))
	if err := engine.Observe(24*time.Hour, true); err == nil {
		t.Fatal("large interval bypassed monotonic bound")
	}
	if err := engine.Observe(-time.Second, true); err == nil {
		t.Fatal("negative interval was accepted")
	}
	_ = engine.Observe(MaxAccrualStep, false)
	if engine.Snapshot().StableSeconds != 0 {
		t.Fatal("unhealthy time was credited")
	}
}

func TestSIMAndModemChangeDowngradesAndExtendsObservation(t *testing.T) {
	engine, _ := New("device")
	_ = engine.Bind(strings.Repeat("c", 64))
	engine.ChangeIdentity(true, true)
	record := engine.Snapshot()
	if record.State != Restricted || record.BindingHash != "" || record.RequiredSeconds != uint64(ExtendedObservation.Seconds()) {
		t.Fatalf("change did not downgrade: %#v", record)
	}
	if engine.Allow(SendSMS) || !engine.Allow(ReceiveSMS) {
		t.Fatal("restricted capabilities are wrong")
	}
	if err := engine.Bind(strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	if engine.Snapshot().State != Observation || engine.Snapshot().RequiredSeconds != uint64(ExtendedObservation.Seconds()) {
		t.Fatal("re-binding did not restart an extended observation")
	}
}

func TestIntegrityQuarantineCannotSelfPromote(t *testing.T) {
	engine, _ := New("device")
	_ = engine.Bind(strings.Repeat("e", 64))
	engine.IntegrityFailure()
	if err := engine.Bind(strings.Repeat("f", 64)); err == nil {
		t.Fatal("integrity restriction was bypassed by re-binding")
	}
	for i := 0; i < 3; i++ {
		engine.IntegrityFailure()
	}
	if engine.Snapshot().State != Quarantine || engine.Allow(ReceiveSMS) || engine.Allow(Dial) {
		t.Fatal("quarantine did not close normal business")
	}
	if !engine.Allow(Update) || !engine.Allow(Repair) || !engine.Allow(Diagnose) {
		t.Fatal("quarantine must preserve recovery paths")
	}
	if err := engine.Bind(strings.Repeat("a", 64)); err == nil {
		t.Fatal("quarantine was bypassed locally")
	}
}
