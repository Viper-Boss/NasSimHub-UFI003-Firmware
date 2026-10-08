//go:build linux

package systemstats

// parseRadioMetrics is the map form of one radio report, as this file has
// always exposed it. Reading and parsing moved to radio.go so they are tested
// on any host through the Source; this file stays, rather than being removed,
// because the Node tree is mirrored into other repositories by a copy that
// does not delete, and a stale copy of the old file beside radio.go would
// declare the same names twice.
func parseRadioMetrics(data string) map[string]any {
	return cellMetrics(parseCell(data))
}
