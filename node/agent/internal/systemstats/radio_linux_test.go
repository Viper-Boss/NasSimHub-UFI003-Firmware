//go:build linux

package systemstats

import "testing"

func TestRadioMetricsUsesOnlyReportedServingCell(t *testing.T) {
	m := parseRadioMetrics("band=3\nearfcn=1650\npci=207\ntac=58916\ncell_id=204459039\nbandwidth=20\n")
	if m["band"] != "B3" || m["frequency_mhz"] != float64(1850) || m["cell_id_hex"] != "C2FCC1F" || m["tac_hex"] != "E624" {
		t.Fatalf("incorrect serving cell: %#v", m)
	}
	if _, ok := m["downlink_bandwidth_mhz"]; ok {
		t.Fatal("invented bandwidth")
	}
	invalid := parseRadioMetrics("pci=999\nband=invalid\nearfcn=bad\n")
	if len(invalid) != 0 {
		t.Fatalf("accepted invalid radio fields: %#v", invalid)
	}
}
