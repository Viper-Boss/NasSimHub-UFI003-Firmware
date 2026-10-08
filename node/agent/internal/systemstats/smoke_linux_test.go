//go:build linux

package systemstats

import (
	"encoding/json"
	"testing"
)

// The one test that reads the real kernel of whatever machine runs it. It
// checks only what holds on any Linux: the sampler starts on first use and the
// first reader is served within the bounded wait.
func TestSnapshotOnThisKernel(t *testing.T) {
	r := Snapshot()
	if r == nil {
		t.Skip("procfs is not readable here")
	}
	if r.ObservedAt.IsZero() || r.CPUPercent != nil {
		t.Fatalf("first sample: observed_at=%v cpu=%v", r.ObservedAt, r.CPUPercent)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatal(err)
	}
	if testing.Verbose() {
		data, _ := json.MarshalIndent(r, "", " ")
		t.Logf("%s", data)
	}
}
