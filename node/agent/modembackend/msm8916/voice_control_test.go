package msm8916

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/human-agent65535/nassimhub-node/proto"
)

func TestVoiceControlRemainsDisabledByDefault(t *testing.T) {
	backend := New(Options{ReadOnly: true, Run: func(context.Context, ...string) (string, error) {
		t.Fatal("disabled call control accessed modem")
		return "", nil
	}})
	_, err := backend.Dial(context.Background(), proto.DialRequest{RequestID: "r", To: "10000"})
	if proto.CodeOf(err) != proto.ErrorNotSupported {
		t.Fatalf("disabled dial error = %v", err)
	}
}

func TestRegisteredIMSWithoutVoiceCannotDial(t *testing.T) {
	for _, service := range []string{"", "Voice service\n Status: 'unavailable'\n", "Voice service\n Status: 'not-available'\n", "Voice service\nVideo Telephony service\n Status: 'available'\n"} {
		t.Run(service, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "local-volte.enabled")
			if err := os.WriteFile(marker, nil, 0600); err != nil {
				t.Fatal(err)
			}
			backend := New(Options{ReadOnly: true, VoiceWrite: true, IMSProfilePath: marker,
				RunQMI: func(context.Context) (string, error) {
					return "IMS registration:\n Status: 'registered'\n" + service, nil
				},
				Run: func(context.Context, ...string) (string, error) {
					t.Fatal("unavailable voice accessed modem")
					return "", nil
				}})
			_, err := backend.Dial(context.Background(), proto.DialRequest{RequestID: "r", To: "10000"})
			if proto.CodeOf(err) != proto.ErrorFailedPrecondition {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestVoiceDialCreatesAndStartsOneCall(t *testing.T) {
	const modem = "/org/freedesktop/ModemManager1/Modem/1"
	const call = "/org/freedesktop/ModemManager1/Call/7"
	var commands []string
	marker := filepath.Join(t.TempDir(), "local-volte.enabled")
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	backend := New(Options{ReadOnly: true, VoiceWrite: true, CallEpoch: func(context.Context) (string, error) { return modemCallEpoch("boot", "bus", ":1.2"), nil }, IMSProfilePath: marker, RunQMI: func(context.Context) (string, error) {
		return "IMS registration:\n Status: 'registered'\nVoice service\n Status: 'available'\n", nil
	}, Run: func(_ context.Context, args ...string) (string, error) {
		command := strings.Join(args, " ")
		commands = append(commands, command)
		switch command {
		case "-K -L":
			return "modem-list.value[1] : " + modem + "\n", nil
		case "-K -m " + modem + " --voice-list-calls":
			return "modem.voice.call : 0\n", nil
		case "-m " + modem + " --voice-create-call=number=10000":
			return "Successfully created new call: " + call + "\n", nil
		case "-o " + call + " --start":
			return "success\n", nil
		default:
			t.Fatalf("unexpected command %q", command)
			return "", nil
		}
	}})
	receipt, err := backend.Dial(context.Background(), proto.DialRequest{RequestID: "r1", To: "10000"})
	if err != nil || receipt.CallID != scopeCallID(modemCallEpoch("boot", "bus", ":1.2"), "mm-7") || receipt.State != proto.CallDialing || receipt.RequestID != "r1" {
		t.Fatalf("receipt = %+v, error = %v", receipt, err)
	}
	want := []string{"-K -L", "-K -m " + modem + " --voice-list-calls", "-K -L", "-m " + modem + " --voice-create-call=number=10000", "-o " + call + " --start"}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands = %v, want %v", commands, want)
	}
}

func TestVoiceDialRejectsNumberBeforeModemAccess(t *testing.T) {
	backend := New(Options{ReadOnly: true, VoiceWrite: true, Run: func(context.Context, ...string) (string, error) {
		t.Fatal("invalid number accessed modem")
		return "", nil
	}})
	for _, number := range []string{"", "1", "10000;reboot", "+", "１２３４"} {
		_, err := backend.Dial(context.Background(), proto.DialRequest{RequestID: "r", To: number})
		if proto.CodeOf(err) != proto.ErrorInvalidArgument {
			t.Fatalf("number %q: error = %v", number, err)
		}
	}
}

func TestVoiceDialRequiresVerifiedIMSBeforeModemAccess(t *testing.T) {
	backend := New(Options{ReadOnly: true, VoiceWrite: true, Run: func(context.Context, ...string) (string, error) {
		t.Fatal("unregistered IMS accessed modem")
		return "", nil
	}})
	_, err := backend.Dial(context.Background(), proto.DialRequest{RequestID: "r", To: "10000"})
	if proto.CodeOf(err) != proto.ErrorFailedPrecondition {
		t.Fatalf("IMS precondition error = %v", err)
	}
}

func TestVoiceDialHangsUpWhenStartFails(t *testing.T) {
	const modem = "/org/freedesktop/ModemManager1/Modem/1"
	const call = "/org/freedesktop/ModemManager1/Call/9"
	hungUp := false
	marker := filepath.Join(t.TempDir(), "local-volte.enabled")
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := New(Options{ReadOnly: true, VoiceWrite: true, IMSProfilePath: marker, RunQMI: func(context.Context) (string, error) {
		return "IMS registration:\n Status: 'registered'\nVoice service\n Status: 'available'\n", nil
	}, Run: func(commandContext context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "-K -L":
			return "modem-list.value[1] : " + modem + "\n", nil
		case "-K -m " + modem + " --voice-list-calls":
			return "modem.voice.call : 0\n", nil
		case "-m " + modem + " --voice-create-call=number=10000":
			return "Successfully created new call: " + call + "\n", nil
		case "-o " + call + " --start":
			cancel()
			return "", errors.New("start failed")
		case "-o " + call + " --hangup":
			if commandContext.Err() != nil {
				t.Fatal("cleanup inherited cancelled request context")
			}
			hungUp = true
			return "", nil
		}
		t.Fatal("unexpected command")
		return "", nil
	}})
	_, err := backend.Dial(ctx, proto.DialRequest{RequestID: "r", To: "10000"})
	if proto.CodeOf(err) != proto.ErrorUnavailable || !hungUp {
		t.Fatalf("start failure = %v, hung up = %v", err, hungUp)
	}
}

func TestCallIDPathRejectsUntrustedInput(t *testing.T) {
	for _, id := range []string{"7", "mm-../7", "mm-7 --hangup", "mm-", "mm-999999999999999999999"} {
		if _, ok := callIDPath(id); ok {
			t.Fatalf("accepted %q", id)
		}
	}
}

func TestVoiceAnswerAndHangupRequireObservedCall(t *testing.T) {
	const modem = "/org/freedesktop/ModemManager1/Modem/1"
	const call = "/org/freedesktop/ModemManager1/Call/7"
	state := "i 3"
	direction := "i 1"
	var commands []string
	backend := New(Options{
		ReadOnly: true, VoiceWrite: true,
		Run: func(_ context.Context, args ...string) (string, error) {
			command := strings.Join(args, " ")
			commands = append(commands, command)
			switch command {
			case "-K -L":
				return "modem-list.value[1] : " + modem + "\n", nil
			case "-K -m " + modem + " --voice-list-calls":
				return "modem.voice.call.length : 1\nmodem.voice.call.value[1] : " + call + "\n", nil
			case "-K -m " + modem + " --signal-get":
				return "", nil
			case "-K -m " + modem:
				return "modem.generic.state : registered\n", nil
			case "-o " + call + " --accept":
				state = "i 4"
				return "success", nil
			case "-o " + call + " --hangup":
				state = "i 7"
				return "success", nil
			default:
				t.Fatalf("unexpected command %q", command)
				return "", nil
			}
		},
		RunBusctl: func(_ context.Context, args ...string) (string, error) {
			switch args[len(args)-1] {
			case "Direction":
				return direction, nil
			case "State":
				return state, nil
			case "Number":
				return `s "10000"`, nil
			default:
				t.Fatal("unexpected property")
				return "", nil
			}
		},
	})
	ctx := context.Background()
	if _, err := backend.Hangup(ctx, "mm-8"); proto.CodeOf(err) != proto.ErrorNotFound {
		t.Fatalf("unknown call hangup error = %v", err)
	}
	receipt, err := backend.Answer(ctx, "mm-7")
	if err != nil || receipt.State != proto.CallActive {
		t.Fatalf("answer = %+v, %v", receipt, err)
	}
	if _, err := backend.Answer(ctx, "mm-7"); proto.CodeOf(err) != proto.ErrorFailedPrecondition {
		t.Fatalf("second answer error = %v", err)
	}
	direction = "i 2"
	receipt, err = backend.Hangup(ctx, "mm-7")
	if err != nil || receipt.State != proto.CallTerminated {
		t.Fatalf("hangup = %+v, %v", receipt, err)
	}
	accepted, hungUp := false, false
	for _, command := range commands {
		accepted = accepted || command == "-o "+call+" --accept"
		hungUp = hungUp || command == "-o "+call+" --hangup"
	}
	if !accepted || !hungUp {
		t.Fatalf("missing call commands: %v", commands)
	}
}
