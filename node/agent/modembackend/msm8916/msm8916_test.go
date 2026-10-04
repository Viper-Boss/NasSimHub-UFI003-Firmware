package msm8916

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"

	"github.com/human-agent65535/nassimhub-node/proto"
)

func TestStubClaimsNoRadioCapability(t *testing.T) {
	backend := New(Options{})
	capabilities, err := backend.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	if capabilities.SMS || capabilities.MobileData || capabilities.VoiceControl || capabilities.VoiceAudio {
		t.Fatalf("the stub claims radio capability: %+v", capabilities)
	}
	if capabilities.VoLTE != proto.TriUnknown {
		t.Fatalf("VoLTE must stay unknown on unflashed hardware, got %s", capabilities.VoLTE)
	}
}

func TestStubStatusIsAnswerableNotAnError(t *testing.T) {
	backend := New(Options{})
	status, err := backend.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("status must answer so Core can still see the node: %v", err)
	}
	if status.State != proto.ModemOffline {
		t.Fatalf("state is %s", status.State)
	}
	if status.Reason == "" {
		t.Fatal("the stub must say why the modem is offline")
	}
}

func TestStubRefusesEveryRadioOperation(t *testing.T) {
	backend := New(Options{})
	ctx := context.Background()

	checks := map[string]error{}
	_, err := backend.ListSMS(ctx)
	checks["list_sms"] = err
	_, err = backend.SendSMS(ctx, proto.SendSMSRequest{RequestID: "r", To: "1", Text: "x"})
	checks["send_sms"] = err
	checks["delete_sms"] = backend.DeleteSMS(ctx, "id")
	_, err = backend.ListCalls(ctx)
	checks["list_calls"] = err
	_, err = backend.Dial(ctx, proto.DialRequest{RequestID: "r", To: "1"})
	checks["dial"] = err
	_, err = backend.Answer(ctx, "id")
	checks["answer"] = err
	_, err = backend.Hangup(ctx, "id")
	checks["hangup"] = err

	for name, err := range checks {
		if got := proto.CodeOf(err); got != proto.ErrorNotSupported {
			t.Fatalf("%s returned %s, want not_supported", name, got)
		}
	}
}

func TestVoiceCapabilityNeverPromotesItself(t *testing.T) {
	backend := New(Options{})
	voice, err := backend.GetVoiceCapability(context.Background())
	if err != nil {
		t.Fatalf("voice: %v", err)
	}
	if voice.Control || voice.Audio {
		t.Fatalf("the stub claims voice: %+v", voice)
	}
	if voice.VoLTE != proto.TriUnknown {
		t.Fatalf("VoLTE is %s, want unknown", voice.VoLTE)
	}
}

// Status-only observation may call mmcli. Partition, firmware and service
// control remain forbidden until the modem bring-up has a separate review.
func TestObserverTouchesNoDangerousHardwareTooling(t *testing.T) {
	forbidden := []string{
		"syscall.Exec", "qmicli", "qmi-firmware-update", "adb",
		"fastboot", "edl", "rmtfs", "modemst1", "modemst2",
		"/dev/block", "dd if=", "q6voiced", "systemctl start", "systemctl enable",
	}

	fileSet := token.NewFileSet()
	packages, err := parser.ParseDir(fileSet, ".", func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}

	for _, parsed := range packages {
		for path, file := range parsed.Files {
			// Strip comments: the doc comment legitimately names these tools in
			// order to say the package does not use them.
			file.Comments = nil
			var builder strings.Builder
			ast.Inspect(file, func(node ast.Node) bool {
				switch typed := node.(type) {
				case *ast.BasicLit:
					builder.WriteString(typed.Value)
					builder.WriteString("\n")
				case *ast.Ident:
					builder.WriteString(typed.Name)
					builder.WriteString("\n")
				}
				return true
			})
			body := strings.ToLower(builder.String())
			for _, name := range forbidden {
				if strings.Contains(body, strings.ToLower(name)) {
					t.Fatalf("%s references forbidden write-side hardware tooling %q", path, name)
				}
			}
		}
	}
}
