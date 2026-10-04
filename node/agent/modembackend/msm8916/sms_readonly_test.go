package msm8916

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

func TestReadOnlySMSDeduplicatesOnlyCrossStorageCopies(t *testing.T) {
	const modem = "/org/freedesktop/ModemManager1/Modem/1"
	const sim = "/org/freedesktop/ModemManager1/SIM/1"
	const list = "modem.messaging.sms.length : 4\n" +
		"modem.messaging.sms.value[1] : /org/freedesktop/ModemManager1/SMS/0\n" +
		"modem.messaging.sms.value[2] : /org/freedesktop/ModemManager1/SMS/1\n" +
		"modem.messaging.sms.value[3] : /org/freedesktop/ModemManager1/SMS/2\n" +
		"modem.messaging.sms.value[4] : /org/freedesktop/ModemManager1/SMS/3\n"
	base := "sms.content.number : +8610000000000\nsms.content.text : 666\n" +
		"sms.properties.pdu-type : deliver\nsms.properties.state : received\n" +
		"sms.properties.timestamp : 2026-09-23T17:25:11+08\n"
	backend := New(Options{ReadOnly: true, Run: func(_ context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "-K -L":
			return "modem-list.value[1] : " + modem + "\n", nil
		case "-K -m " + modem + " --messaging-list-sms":
			return list, nil
		case "-K -m " + modem:
			return "modem.generic.state : registered\nmodem.generic.sim : " + sim + "\n", nil
		case "-K -i " + sim:
			return "sim.properties.iccid : 8900000000000000000\n", nil
		case "-K -s /org/freedesktop/ModemManager1/SMS/0":
			return base + "sms.properties.storage : sm\n", nil
		case "-K -s /org/freedesktop/ModemManager1/SMS/1":
			return base + "sms.properties.storage : me\n", nil
		case "-K -s /org/freedesktop/ModemManager1/SMS/2":
			return "sms.content.number : 10010\nsms.content.text : test\n" +
				"sms.properties.pdu-type : submit\nsms.properties.state : sent\nsms.properties.storage : --\n", nil
		case "-K -s /org/freedesktop/ModemManager1/SMS/3":
			return base + "sms.properties.storage : sm\n", nil
		default:
			return "", errors.New("unexpected mmcli query")
		}
	}})
	messages, err := backend.ListSMS(context.Background())
	if err != nil || len(messages) != 3 {
		t.Fatalf("SMS list = %#v, %v", messages, err)
	}
	if messages[0].ID != "mm-0" || messages[0].SIMID != "8900000000000000000" ||
		messages[0].Direction != proto.DirectionIncoming || messages[0].State != proto.SMSReceived ||
		!messages[0].Timestamp.Equal(time.Date(2026, 9, 23, 9, 25, 11, 0, time.UTC)) {
		t.Fatalf("incoming SMS = %#v", messages[0])
	}
	if messages[1].ID != "mm-2" || messages[1].Direction != proto.DirectionOutgoing || messages[1].State != proto.SMSSent {
		t.Fatalf("outgoing SMS = %#v", messages[1])
	}
	if messages[2].ID != "mm-3" {
		t.Fatalf("same-storage message incorrectly deduplicated: %#v", messages[2])
	}
	capabilities, _ := backend.Capabilities(context.Background())
	if capabilities.SMS {
		t.Fatal("read-only SMS listing must not advertise send capability")
	}
}

func TestReadOnlySMSRejectsInvalidListingPath(t *testing.T) {
	backend := New(Options{ReadOnly: true, Run: func(_ context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "-K -L":
			return "modem-list.value[1] : /org/freedesktop/ModemManager1/Modem/1\n", nil
		case "-K -m /org/freedesktop/ModemManager1/Modem/1 --messaging-list-sms":
			return "modem.messaging.sms.length : 1\nmodem.messaging.sms.value[1] : /tmp/evil\n", nil
		case "-K -m /org/freedesktop/ModemManager1/Modem/1":
			return "modem.generic.state : registered\nmodem.generic.sim : /org/freedesktop/ModemManager1/SIM/1\n", nil
		case "-K -i /org/freedesktop/ModemManager1/SIM/1":
			return "sim.properties.iccid : 8900000000000000000\n", nil
		default:
			return "", errors.New("unexpected query")
		}
	}})
	if _, err := backend.ListSMS(context.Background()); err == nil {
		t.Fatal("invalid SMS path was accepted")
	}
}
