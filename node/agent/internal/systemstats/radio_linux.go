//go:build linux

package systemstats

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func readRadioMetrics() map[string]any {
	file := "/run/nassimhub-ims/radio.metrics"
	info, err := os.Stat(file)
	if err != nil || time.Since(info.ModTime()) > 90*time.Second {
		return nil
	}
	data, err := os.ReadFile(file)
	if err != nil || len(data) > 4096 {
		return nil
	}
	return parseRadioMetrics(string(data))
}
func parseRadioMetrics(data string) map[string]any {
	result := map[string]any{}
	for _, line := range strings.Split(data, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			continue
		}
		switch key {
		case "band":
			if n > 0 && n <= 256 {
				result["band"] = fmt.Sprintf("B%d", n)
			}
		case "earfcn":
			result["earfcn"] = n
		case "pci":
			if n <= 503 {
				result["pci"] = n
			}
		case "tac":
			result["tac_hex"] = fmt.Sprintf("%X", n)
		case "cell_id":
			result["cell_id_hex"] = fmt.Sprintf("%X", n)
		}
	}
	// Frequency conversion is defined for this measured E-UTRA band only.
	if result["band"] == "B3" {
		if channel, ok := result["earfcn"].(uint64); ok && channel >= 1200 && channel <= 1949 {
			result["frequency_mhz"] = 1805 + float64(channel-1200)/10
		}
	}
	return result
}
