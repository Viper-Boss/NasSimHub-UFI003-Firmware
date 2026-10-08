package msm8916

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/human-agent65535/nassimhub-node/proto"
)

func dtmfBackend(t *testing.T, dir string, state *string, command func(context.Context, string, string) error) *Backend {
	t.Helper()
	const modem = "/org/freedesktop/ModemManager1/Modem/0"
	return New(Options{ReadOnly: true, VoiceWrite: true, VoiceDTMF: true, SMSStateDir: dir, DTMFCommand: command,
		Run: func(_ context.Context, args ...string) (string, error) {
			switch strings.Join(args, " ") {
			case "-K -L":
				return "modem-list.value[1] : " + modem + "\n", nil
			case "-K -m " + modem + " --voice-list-calls":
				return "modem.voice.call.length : 1\nmodem.voice.call.value[1] : /org/freedesktop/ModemManager1/Call/7\n", nil
			default:
				return "modem.generic.state : registered\n", nil
			}
		}, RunBusctl: func(_ context.Context, args ...string) (string, error) {
			switch args[len(args)-1] {
			case "State":
				return *state, nil
			case "Direction":
				return "i 2", nil
			case "Number":
				return `s "10000"`, nil
			}
			return "", errors.New("unexpected property")
		}})
}

func TestDTMFPersistentAtMostOnceAndNoDigitsOnDisk(t *testing.T) {
	dir, state, writes := t.TempDir(), "i 4", 0
	command := func(_ context.Context, path, digits string) error {
		if path != "/org/freedesktop/ModemManager1/Call/7" || digits != "1234#" {
			t.Fatal("wrong target or digits")
		}
		writes++
		return nil
	}
	backend := dtmfBackend(t, dir, &state, command)
	request := proto.DTMFRequest{RequestID: "dtmf-request", Digits: "1234#"}
	receipt, err := backend.SendDTMF(context.Background(), "mm-7", request)
	if err != nil || receipt.RequestID != request.RequestID || receipt.CallID != "mm-7" {
		t.Fatalf("receipt %+v %v", receipt, err)
	}
	backend = dtmfBackend(t, dir, &state, command)
	if _, err = backend.SendDTMF(context.Background(), "mm-7", request); proto.CodeOf(err) != proto.ErrorUnavailable {
		t.Fatal("restart replay was not refused", err)
	}
	request.Digits = "9"
	if _, err = backend.SendDTMF(context.Background(), "mm-7", request); err == nil {
		t.Fatal("reused ID with new content accepted")
	}
	if writes != 1 {
		t.Fatalf("sent %d times", writes)
	}
	data, err := os.ReadFile(filepath.Join(dir, "dtmf-requests.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "1234#") || strings.Contains(string(data), "10000") {
		t.Fatal("sensitive content in ledger")
	}
}

func TestDTMFGuardAndUncertainResult(t *testing.T) {
	dir, state, writes := t.TempDir(), "i 4", 0
	backend := dtmfBackend(t, dir, &state, func(context.Context, string, string) error { writes++; return errors.New("transport disconnected") })
	request := proto.DTMFRequest{RequestID: "uncertain", Digits: "1"}
	backend.options.VoiceDTMF = false
	if _, err := backend.SendDTMF(context.Background(), "mm-7", request); proto.CodeOf(err) != proto.ErrorNotSupported {
		t.Fatal(err)
	}
	backend.options.VoiceDTMF = true
	for _, digits := range []string{"", "1; reboot", "e", strings.Repeat("1", 33)} {
		if _, err := backend.SendDTMF(context.Background(), "mm-7", proto.DTMFRequest{RequestID: "bad", Digits: digits}); proto.CodeOf(err) != proto.ErrorInvalidArgument {
			t.Fatal(err)
		}
	}
	state = "i 3"
	if _, err := backend.SendDTMF(context.Background(), "mm-7", request); proto.CodeOf(err) != proto.ErrorFailedPrecondition {
		t.Fatal(err)
	}
	state = "i 4"
	for i := 0; i < 2; i++ {
		if _, err := backend.SendDTMF(context.Background(), "mm-7", request); proto.CodeOf(err) != proto.ErrorUnavailable {
			t.Fatal(err)
		}
	}
	if writes != 1 {
		t.Fatalf("uncertain result retried: %d", writes)
	}
}

func TestDTMFConcurrentDuplicateAndBrokenLedgerFailClosed(t *testing.T) {
	dir, state, writes := t.TempDir(), "i 4", 0
	backend := dtmfBackend(t, dir, &state, func(context.Context, string, string) error { writes++; return nil })
	var wait sync.WaitGroup
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _ = backend.SendDTMF(context.Background(), "mm-7", proto.DTMFRequest{RequestID: "parallel", Digits: "1"})
		}()
	}
	wait.Wait()
	if writes != 1 {
		t.Fatalf("concurrent duplicates: %d", writes)
	}
	if err := os.WriteFile(filepath.Join(dir, "dtmf-requests.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.SendDTMF(context.Background(), "mm-7", proto.DTMFRequest{RequestID: "different", Digits: "1"}); proto.CodeOf(err) != proto.ErrorFailedPrecondition {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatal("broken ledger reached modem")
	}
}

func TestDTMFCommitFailureAndCancellationNeverSend(t *testing.T) {
	state, writes := "i 4", 0
	dir := t.TempDir()
	backend := dtmfBackend(t, dir, &state, func(context.Context, string, string) error { writes++; return nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = backend.SendDTMF(ctx, "mm-7", proto.DTMFRequest{RequestID: "cancelled", Digits: "1"})
	if _, err := os.Stat(filepath.Join(dir, "dtmf-requests.json")); !os.IsNotExist(err) {
		t.Fatal("cancelled request created a ledger", err)
	}
	// No state directory: commit cannot succeed and the modem must stay untouched.
	backend.options.SMSStateDir = filepath.Join(dir, "absent")
	if _, err := backend.SendDTMF(context.Background(), "mm-7", proto.DTMFRequest{RequestID: "disk-failed", Digits: "1"}); err == nil {
		t.Fatal("failed commit accepted")
	}
	if writes != 0 {
		t.Fatal("uncommitted request reached the modem")
	}
}
