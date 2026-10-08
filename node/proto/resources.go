package proto

import "time"

// SystemResources is optional, authenticated device telemetry. Older agents omit it.
//
// The fields below Processes were added later and are all optional: a field
// that is absent means "this Node did not sample it", never zero. A reader
// must not substitute a default. Readers that predate them ignore them, and a
// Node that predates them simply never sends them, so neither side needs a
// protocol check.
type SystemResources struct {
	Metrics         map[string]any    `json:"metrics,omitempty"`
	ObservedAt      time.Time         `json:"observed_at"`
	CPUPercent      *float64          `json:"cpu_percent"`
	MemoryTotal     uint64            `json:"memory_total_bytes"`
	MemoryAvailable uint64            `json:"memory_available_bytes"`
	UptimeSeconds   float64           `json:"uptime_seconds"`
	ProcessCount    int               `json:"process_count"`
	Processes       []ProcessResource `json:"processes"`

	// ProcessScanTruncated is set when the device had more processes than one
	// bounded scan reads. ProcessCount is then a lower bound and Processes is
	// the top of what was scanned, not of everything.
	ProcessScanTruncated bool                `json:"process_scan_truncated,omitempty"`
	ThreadCount          *int                `json:"thread_count,omitempty"`
	CPU                  *CPUResources       `json:"cpu,omitempty"`
	ThermalZones         []ThermalZone       `json:"thermal_zones,omitempty"`
	Memory               *MemoryResources    `json:"memory,omitempty"`
	Storage              []StorageResource   `json:"storage,omitempty"`
	EMMC                 *EMMCHealth         `json:"emmc,omitempty"`
	Interfaces           []InterfaceResource `json:"interfaces,omitempty"`
	Agent                *AgentResource      `json:"agent,omitempty"`
	// BootID is the kernel's random per-boot identifier. It changes on every
	// boot, so it tells a reader that counters restarted; it does not identify
	// the device.
	BootID string `json:"boot_id,omitempty"`
	// Cell is the serving cell. TAC and cell ID locate the device, which is
	// why this lives only in the authenticated status document.
	Cell *CellResource `json:"cell,omitempty"`
}

type ProcessResource struct {
	PID      int    `json:"pid"`
	Name     string `json:"name"`
	RSSBytes uint64 `json:"rss_bytes"`
}

// CPUResources describes the processor beyond the single cpu_percent figure.
type CPUResources struct {
	// Model is what /proc/cpuinfo calls the processor. Many arm64 kernels say
	// nothing, and then this is empty rather than a guess from the board name.
	Model string `json:"model,omitempty"`
	// CoreCount is the number of cores the kernel reports present, online or not.
	CoreCount *int      `json:"core_count,omitempty"`
	Cores     []CPUCore `json:"cores,omitempty"`
	// Load averages are the kernel's raw run-queue averages, not percentages.
	Load1  *float64 `json:"load_1,omitempty"`
	Load5  *float64 `json:"load_5,omitempty"`
	Load15 *float64 `json:"load_15,omitempty"`
}

// CPUCore is one core. Frequencies are kHz as cpufreq reports them. Percent is
// utilisation between the previous sample and this one; the first sample, and
// a core that was offline at either end, has none.
type CPUCore struct {
	Index      int      `json:"index"`
	Online     *bool    `json:"online,omitempty"`
	CurrentKHz *uint64  `json:"current_khz,omitempty"`
	MinKHz     *uint64  `json:"min_khz,omitempty"`
	MaxKHz     *uint64  `json:"max_khz,omitempty"`
	Percent    *float64 `json:"percent,omitempty"`
}

// ThermalZone is one kernel thermal zone that answered. Type is the kernel's
// own name for the sensor; nothing here decides which zone is "the CPU".
type ThermalZone struct {
	Zone    string  `json:"zone"`
	Type    string  `json:"type,omitempty"`
	Celsius float64 `json:"celsius"`
}

// MemoryResources is /proc/meminfo, in bytes. Cached is the kernel's "Cached"
// line alone; tools such as free(1) add reclaimable slab to it.
type MemoryResources struct {
	TotalBytes     *uint64 `json:"total_bytes,omitempty"`
	AvailableBytes *uint64 `json:"available_bytes,omitempty"`
	FreeBytes      *uint64 `json:"free_bytes,omitempty"`
	BuffersBytes   *uint64 `json:"buffers_bytes,omitempty"`
	CachedBytes    *uint64 `json:"cached_bytes,omitempty"`
	SwapTotalBytes *uint64 `json:"swap_total_bytes,omitempty"`
	SwapFreeBytes  *uint64 `json:"swap_free_bytes,omitempty"`
}

// Storage roles.
const (
	StorageRoleState = "state"
	StorageRoleRoot  = "root"
)

// StorageResource is one filesystem that answered statfs. FreeBytes counts
// blocks free to root, AvailableBytes blocks free to an unprivileged writer,
// and UsedBytes is total minus free - the same three numbers df(1) prints.
type StorageResource struct {
	Role           string `json:"role"`
	Path           string `json:"path"`
	TotalBytes     uint64 `json:"total_bytes"`
	FreeBytes      uint64 `json:"free_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
	// FSType is the type the kernel's mount table gives for the mount holding
	// Path, and empty when the table could not be read.
	FSType string `json:"fs_type,omitempty"`
}

// EMMCHealth carries the eMMC's own wear registers, raw.
//
// LifeTimeEstA and LifeTimeEstB are EXT_CSD DEVICE_LIFE_TIME_EST_TYP_A/B
// (JEDEC eMMC 5.0+): 0x01 means 0-10% of the rated life used, each step is
// another 10%, 0x0A is 90-100%, 0x0B is past the rated life and 0x00 means the
// device does not report. PreEOL is PRE_EOL_INFO: 0x01 normal, 0x02 warning
// (80% of reserved blocks consumed), 0x03 urgent, 0x00 not reported. They are
// the manufacturer's estimates, so they are passed through rather than turned
// into a percentage the hardware never stated.
type EMMCHealth struct {
	Device       string `json:"device"`
	LifeTimeEstA *uint8 `json:"life_time_est_a,omitempty"`
	LifeTimeEstB *uint8 `json:"life_time_est_b,omitempty"`
	PreEOL       *uint8 `json:"pre_eol,omitempty"`
}

// InterfaceResource is one network interface's cumulative counters since boot
// (or since the interface was created) and, when two consecutive samples allow
// it, the byte rate between them. An absent rate means it is not known for
// this interval - first sample, or the counters went backwards. A rate of 0 is
// a measurement: nothing moved.
type InterfaceResource struct {
	Name             string   `json:"name"`
	RxBytes          uint64   `json:"rx_bytes"`
	TxBytes          uint64   `json:"tx_bytes"`
	RxPackets        uint64   `json:"rx_packets"`
	TxPackets        uint64   `json:"tx_packets"`
	RxErrors         uint64   `json:"rx_errors"`
	TxErrors         uint64   `json:"tx_errors"`
	RxBytesPerSecond *float64 `json:"rx_bytes_per_second,omitempty"`
	TxBytesPerSecond *float64 `json:"tx_bytes_per_second,omitempty"`
}

// AgentResource is the agent process itself. CPUPercent is on the same scale
// as SystemResources.CPUPercent: a share of all cores, so the two compare.
type AgentResource struct {
	PID        int      `json:"pid"`
	RSSBytes   *uint64  `json:"rss_bytes,omitempty"`
	CPUPercent *float64 `json:"cpu_percent,omitempty"`
}

// CellResource is the serving LTE cell as the modem last reported it.
// ObservedAt is when that report was taken, which can be older than the
// surrounding document.
type CellResource struct {
	Band       string    `json:"band,omitempty"`
	EARFCN     *uint32   `json:"earfcn,omitempty"`
	PCI        *uint16   `json:"pci,omitempty"`
	TAC        *uint32   `json:"tac,omitempty"`
	CellID     *uint64   `json:"cell_id,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}
