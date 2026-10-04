package proto

import "time"

// SystemResources is optional, authenticated device telemetry. Older agents omit it.
type SystemResources struct {
	Metrics         map[string]any    `json:"metrics,omitempty"`
	ObservedAt      time.Time         `json:"observed_at"`
	CPUPercent      *float64          `json:"cpu_percent"`
	MemoryTotal     uint64            `json:"memory_total_bytes"`
	MemoryAvailable uint64            `json:"memory_available_bytes"`
	UptimeSeconds   float64           `json:"uptime_seconds"`
	ProcessCount    int               `json:"process_count"`
	Processes       []ProcessResource `json:"processes"`
}

type ProcessResource struct {
	PID      int    `json:"pid"`
	Name     string `json:"name"`
	RSSBytes uint64 `json:"rss_bytes"`
}
