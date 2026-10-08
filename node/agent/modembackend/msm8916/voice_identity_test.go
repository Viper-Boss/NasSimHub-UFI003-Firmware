package msm8916

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/human-agent65535/nassimhub-node/proto"
)

func TestCallIdentitySeparatesModemLifetimes(t *testing.T) {
	old := modemCallEpoch("boot-a", "bus-a", ":1.2")
	if old != modemCallEpoch("boot-a\n", "bus-a", ":1.2") {
		t.Fatal("unstable lifetime")
	}
	for _, epoch := range []string{modemCallEpoch("boot-b", "bus-a", ":1.2"), modemCallEpoch("boot-a", "bus-b", ":1.2"), modemCallEpoch("boot-a", "bus-a", ":1.3")} {
		if scopeCallID(old, "mm-0") == scopeCallID(epoch, "mm-0") {
			t.Fatal("reused index resurrects old call")
		}
	}
}

func TestOldCallCannotControlReusedModemIndex(t *testing.T) {
	ctx := context.Background()
	old := modemCallEpoch("boot-a", "bus-a", ":1.2")
	now := modemCallEpoch("boot-b", "bus-a", ":1.2")
	b := New(Options{ReadOnly: true, VoiceWrite: true, VoiceDTMF: true, CallEpoch: func(context.Context) (string, error) { return now, nil }, Run: func(context.Context, ...string) (string, error) {
		t.Fatal("stale control reached modem")
		return "", nil
	}})
	for _, id := range []string{scopeCallID(old, "mm-0"), "mm-0"} {
		if _, err := b.Hangup(ctx, id); proto.CodeOf(err) != proto.ErrorNotFound {
			t.Fatalf("hangup %s: %v", id, err)
		}
		if _, err := b.Answer(ctx, id); proto.CodeOf(err) != proto.ErrorNotFound {
			t.Fatalf("answer %s: %v", id, err)
		}
		if _, err := b.SendDTMF(ctx, id, proto.DTMFRequest{RequestID: "r", Digits: "1"}); proto.CodeOf(err) != proto.ErrorNotFound {
			t.Fatalf("DTMF %s: %v", id, err)
		}
	}
	path, _, err := b.resolveCallID(ctx, "hangup", scopeCallID(now, "mm-0"))
	if err != nil || path != callPathPrefix+"0" {
		t.Fatalf("current ID: %s, %v", path, err)
	}
}

func TestCallListRejectsLifetimeChangeDuringRead(t *testing.T) {
	reads := 0
	b := New(Options{ReadOnly: true, CallEpoch: func(context.Context) (string, error) {
		reads++
		return modemCallEpoch("boot", "bus", string(rune('a'+reads))), nil
	}, Run: func(_ context.Context, args ...string) (string, error) {
		if strings.Join(args, " ") == "-K -L" {
			return "modem-list.value[1] : /org/freedesktop/ModemManager1/Modem/1\n", nil
		}
		return "modem.voice.call : 0\n", nil
	}})
	if calls, err := b.ListCalls(context.Background()); proto.CodeOf(err) != proto.ErrorUnavailable || calls != nil {
		t.Fatalf("mixed lifetimes: %v, %v", calls, err)
	}
}

func TestLifetimeUnavailableFailsBeforeDial(t *testing.T) {
	b := New(Options{ReadOnly: true, VoiceWrite: true, CallEpoch: func(context.Context) (string, error) { return "", errors.New("bus unavailable") }, Run: func(context.Context, ...string) (string, error) {
		t.Fatal("dial reached modem without identity")
		return "", nil
	}})
	if _, err := b.Dial(context.Background(), proto.DialRequest{RequestID: "r", To: "10000"}); proto.CodeOf(err) != proto.ErrorUnavailable {
		t.Fatal(err)
	}
}
