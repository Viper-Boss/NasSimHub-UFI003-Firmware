package msm8916

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestOwnNumberFallbackIsBoundToReadySIM(t *testing.T) {
	for _, tc := range []struct {
		name, state, reported string
		reads                 int
		want                  string
	}{
		{"missing modem number", "registered", "--", 1, "+8613800138000"},
		{"modem already reports number", "registered", "+8613900139000", 0, "+8613900139000"},
		{"SIM not ready", "searching", "--", 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			backend := New(Options{ReadOnly: true, ReadOwnNumber: func(iccid string) (string, error) {
				reads++
				if iccid != "8900000000000000001" {
					t.Fatal("wrong SIM cache lookup")
				}
				return "+8613800138000", nil
			}, Run: func(_ context.Context, args ...string) (string, error) {
				joined := strings.Join(args, " ")
				switch {
				case joined == "-K -L":
					return "modem-list.value[1]: /org/freedesktop/ModemManager1/Modem/0", nil
				case strings.Contains(joined, "--signal-get"):
					return "", errors.New("no signal")
				case strings.Contains(joined, "-i "):
					return "sim.properties.iccid: 8900000000000000001", nil
				default:
					return "modem.generic.state: " + tc.state + "\nmodem.generic.sim: /org/freedesktop/ModemManager1/SIM/0\nmodem.generic.own-numbers.value[1]: " + tc.reported, nil
				}
			}})
			status, err := backend.GetStatus(context.Background())
			if err != nil || reads != tc.reads || status.SIM.PhoneNumber != tc.want {
				t.Fatal("number observation mismatch", reads, err)
			}
		})
	}
}
