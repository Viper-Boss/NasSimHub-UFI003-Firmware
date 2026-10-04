//go:build !linux

package systemstats

func deviceMetrics() map[string]any { return nil }
