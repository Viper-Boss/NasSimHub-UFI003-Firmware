package msm8916

import (
	"context"
	"testing"
)

func TestEndedCallsDoNotReadNumberOrDirection(t *testing.T) {
	b := New(Options{ReadOnly: true, RunBusctl: func(_ context.Context, args ...string) (string, error) {
		if args[len(args)-1] != "State" {
			t.Fatalf("unnecessary terminal property: %v", args)
		}
		return "i 7", nil
	}})
	_, present, err := b.readCallBusctl(context.Background(), callPathPrefix+"4", "sim")
	if present || err != nil {
		t.Fatalf("terminal call retained: %v %v", present, err)
	}
}
