//go:build !linux

package systemstats

// Every metric here comes from Linux procfs or sysfs. Elsewhere there is no
// source, and the honest answer is that telemetry is unsupported rather than a
// document of zeros.
func platformSource() (Source, string) {
	return nil, "system telemetry is read from Linux procfs and sysfs, which this platform does not have"
}
