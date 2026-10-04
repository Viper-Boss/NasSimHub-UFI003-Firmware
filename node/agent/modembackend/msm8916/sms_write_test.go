package msm8916

import (
	"context"
	"errors"
	"github.com/human-agent65535/nassimhub-node/proto"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeSMSBus struct {
	creates, sends, deletes int
	sendErr                 error
	deletedPaths            []string
}

func (f *fakeSMSBus) Create(context.Context, string, string, string) (string, error) {
	f.creates++
	return smsPathPrefix + "42", nil
}
func (f *fakeSMSBus) Send(context.Context, string) error { f.sends++; return f.sendErr }
func (f *fakeSMSBus) Delete(_ context.Context, _, path string) error {
	f.deletes++
	f.deletedPaths = append(f.deletedPaths, path)
	return nil
}
func TestSMSRequestPersistsBeforeTransmissionAndNeverDoubleSends(t *testing.T) {
	dir := t.TempDir()
	bus := &fakeSMSBus{sendErr: errors.New("uncertain")}
	run := func(_ context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "-K -L":
			return "modem-list.value[1] : /org/freedesktop/ModemManager1/Modem/1\n", nil
		case "-K -m /org/freedesktop/ModemManager1/Modem/1":
			return "modem.generic.state : registered\nmodem.generic.sim : /org/freedesktop/ModemManager1/SIM/1\n", nil
		case "-K -i /org/freedesktop/ModemManager1/SIM/1":
			return "sim.properties.iccid : 8900000000000000000\n", nil
		}
		return "", errors.New("unexpected query")
	}
	options := Options{ReadOnly: true, SMSWrite: true, SMSStateDir: dir, SMSBus: bus, Run: run}
	request := proto.SendSMSRequest{RequestID: "once", To: "10010", Text: "test"}
	first := New(options)
	if _, err := first.SendSMS(context.Background(), request); err == nil {
		t.Fatal("uncertain send should report error")
	}
	data, err := os.ReadFile(filepath.Join(dir, "sms-requests.json"))
	if err != nil || strings.Contains(string(data), "10010") || strings.Contains(string(data), "test") {
		t.Fatal("state missing or contains SMS content")
	}
	second := New(options)
	receipt, err := second.SendSMS(context.Background(), request)
	if err != nil || receipt.MessageID != "mm-42" || receipt.State != proto.SMSSending || bus.creates != 1 || bus.sends != 1 {
		t.Fatalf("retry receipt=%+v err=%v bus=%+v", receipt, err, bus)
	}
	request.Text = "different"
	if _, err = second.SendSMS(context.Background(), request); proto.CodeOf(err) != proto.ErrorInvalidArgument {
		t.Fatalf("different payload accepted: %v", err)
	}
	if bus.creates != 1 || bus.sends != 1 {
		t.Fatal("duplicate transmission")
	}
}
func TestSMSWriteRejectsInvalidRecipientAndDeleteID(t *testing.T) {
	bus := &fakeSMSBus{}
	b := New(Options{SMSWrite: true, SMSBus: bus, SMSStateDir: t.TempDir()})
	if _, err := b.SendSMS(context.Background(), proto.SendSMSRequest{RequestID: "r", To: "10010;reboot", Text: "x"}); proto.CodeOf(err) != proto.ErrorInvalidArgument {
		t.Fatalf("invalid number: %v", err)
	}
	if err := b.DeleteSMS(context.Background(), "../../1"); proto.CodeOf(err) != proto.ErrorInvalidArgument {
		t.Fatalf("invalid id: %v", err)
	}
	if bus.creates != 0 || bus.deletes != 0 {
		t.Fatal("invalid input reached modem")
	}
}

func TestDeleteSMSRemovesOnlyExactCrossStorageTwinFirst(t *testing.T) {
	const modem = "/org/freedesktop/ModemManager1/Modem/1"
	const base = "sms.content.number : +8610000000000\nsms.content.text : 666\n" +
		"sms.properties.pdu-type : deliver\nsms.properties.timestamp : 2026-09-23T17:25:11+08\n"
	bus := &fakeSMSBus{}
	run := func(_ context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "-K -L":
			return "modem-list.value[1] : " + modem + "\n", nil
		case "-K -m " + modem + " --messaging-list-sms":
			return "modem.messaging.sms.length : 3\n" +
				"modem.messaging.sms.value[1] : " + smsPathPrefix + "0\n" +
				"modem.messaging.sms.value[2] : " + smsPathPrefix + "1\n" +
				"modem.messaging.sms.value[3] : " + smsPathPrefix + "2\n", nil
		case "-K -s " + smsPathPrefix + "0":
			return base + "sms.properties.storage : sm\n", nil
		case "-K -s " + smsPathPrefix + "1":
			return base + "sms.properties.storage : me\n", nil
		case "-K -s " + smsPathPrefix + "2":
			return base + "sms.properties.storage : sm\n", nil
		default:
			return "", errors.New("unexpected query")
		}
	}
	backend := New(Options{SMSWrite: true, SMSBus: bus, Run: run})
	if err := backend.DeleteSMS(context.Background(), "mm-0"); err != nil {
		t.Fatal(err)
	}
	if len(bus.deletedPaths) != 2 || bus.deletedPaths[0] != smsPathPrefix+"1" || bus.deletedPaths[1] != smsPathPrefix+"0" {
		t.Fatalf("deleted paths = %v; wanted only exact other-storage twin, then original", bus.deletedPaths)
	}
}
