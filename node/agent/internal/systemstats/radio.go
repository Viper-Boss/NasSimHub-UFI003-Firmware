package systemstats

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// radioMetricsFile is written by the device's radio status timer from the two
// QMI queries it already issues. The agent only ever reads it: asking the
// modem ourselves would add traffic to the channel calls and SMS depend on.
const radioMetricsFile = "/run/nassimhub-ims/radio.metrics"

// radioMaxAge is how old that file may be before the cell it names is no
// longer presented as the serving cell.
const radioMaxAge = 90 * time.Second

const radioMaxBytes = 4096

func (c *Collector) readCell(now time.Time) *proto.CellResource {
	modified, err := c.src.ModTime(radioMetricsFile)
	// A timestamp well ahead of now means the wall clock was stepped back
	// after the file was written; its real age is then unknown, and it would
	// otherwise pass as fresh for as long as the step was large.
	if age := now.Sub(modified); err != nil || age > radioMaxAge || age < -radioMaxAge {
		return nil
	}
	data, err := c.src.ReadFile(radioMetricsFile, radioMaxBytes+1)
	if err != nil || len(data) > radioMaxBytes {
		return nil
	}
	cell := parseCell(string(data))
	if cell != nil {
		cell.ObservedAt = modified.UTC()
	}
	return cell
}

// parseCell keeps only the fields the modem reported and that are in range.
// It returns nil when there are none, so "no cell" never becomes an empty one.
func parseCell(data string) *proto.CellResource {
	cell, any := proto.CellResource{}, false
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
				cell.Band, any = fmt.Sprintf("B%d", n), true
			}
		case "earfcn":
			v := uint32(n)
			cell.EARFCN, any = &v, true
		case "pci":
			if n <= 503 {
				v := uint16(n)
				cell.PCI, any = &v, true
			}
		case "tac":
			v := uint32(n)
			cell.TAC, any = &v, true
		case "cell_id":
			v := n
			cell.CellID, any = &v, true
		}
	}
	if !any {
		return nil
	}
	return &cell
}

// cellMetrics is the older map form of the serving cell, which the pages that
// read metrics.cellular were written against.
func cellMetrics(cell *proto.CellResource) map[string]any {
	result := map[string]any{}
	if cell == nil {
		return result
	}
	if cell.Band != "" {
		result["band"] = cell.Band
	}
	if cell.EARFCN != nil {
		result["earfcn"] = uint64(*cell.EARFCN)
	}
	if cell.PCI != nil {
		result["pci"] = uint64(*cell.PCI)
	}
	if cell.TAC != nil {
		result["tac_hex"] = fmt.Sprintf("%X", *cell.TAC)
	}
	if cell.CellID != nil {
		result["cell_id_hex"] = fmt.Sprintf("%X", *cell.CellID)
	}
	// Frequency conversion is defined for this measured E-UTRA band only.
	if cell.Band == "B3" && cell.EARFCN != nil {
		if channel := *cell.EARFCN; channel >= 1200 && channel <= 1949 {
			result["frequency_mhz"] = 1805 + float64(channel-1200)/10
		}
	}
	return result
}
