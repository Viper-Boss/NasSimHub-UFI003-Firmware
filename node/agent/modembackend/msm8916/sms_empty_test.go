package msm8916

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestSMSListCountEmptyAndMalformed(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		count     int
		valid     bool
	}{
		{"scalar empty", "modem.messaging.sms : 0\n", 0, true},
		{"array empty", "modem.messaging.sms.length : 0\n", 0, true},
		{"array full", "modem.messaging.sms.length : 128\n", 128, true},
		{"missing", "", 0, false},
		{"negative", "modem.messaging.sms.length : -1\n", 0, false},
		{"excessive", "modem.messaging.sms.length : 129\n", 0, false},
		{"malformed", "modem.messaging.sms.length : invalid\nmodem.messaging.sms : 0\n", 0, false},
		{"scalar nonempty", "modem.messaging.sms : 1\n", 0, false},
		{"unknown", "modem.messaging.sms : --\n", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count, err := smsListCount(parseKeyValues(tc.raw))
			if (err == nil) != tc.valid || count != tc.count {
				t.Fatalf("count=%d error=%v", count, err)
			}
		})
	}
}

func TestSMSListAcceptsRealEmptyModemManagerOutput(t *testing.T) {
	queries := 0
	backend := New(Options{ReadOnly: true, Run: func(_ context.Context, args ...string) (string, error) {
		queries++
		switch strings.Join(args, " ") {
		case "-K -L":
			return "modem-list.value[1] : /org/freedesktop/ModemManager1/Modem/0\n", nil
		case "-K -m /org/freedesktop/ModemManager1/Modem/0 --messaging-list-sms":
			return "modem.messaging.sms : 0\n", nil
		default:
			return "", fmt.Errorf("unexpected query: %v", args)
		}
	}})
	messages, err := backend.ListSMS(context.Background())
	if err != nil || messages == nil || len(messages) != 0 || queries != 2 {
		t.Fatalf("empty inbox: messages=%v queries=%d error=%v", messages, queries, err)
	}
}
