package proto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// legacySystemResources is the document as it was before the typed telemetry
// fields existed. It stands in for a Core built from the older source.
type legacySystemResources struct {
	Metrics         map[string]any    `json:"metrics,omitempty"`
	ObservedAt      time.Time         `json:"observed_at"`
	CPUPercent      *float64          `json:"cpu_percent"`
	MemoryTotal     uint64            `json:"memory_total_bytes"`
	MemoryAvailable uint64            `json:"memory_available_bytes"`
	UptimeSeconds   float64           `json:"uptime_seconds"`
	ProcessCount    int               `json:"process_count"`
	Processes       []ProcessResource `json:"processes"`
}

func TestOldResourcesDocumentDecodesIntoNewType(t *testing.T) {
	old := `{"state":"ready","sim":{"state":"ready","observed_at":"2026-01-02T03:04:05Z"},"network":{"registration":"registered","access_technology":"lte","roaming":false,"data_connected":true,"observed_at":"2026-01-02T03:04:05Z"},"signal":{"bars":3,"known":true,"observed_at":"2026-01-02T03:04:05Z"},"observed_at":"2026-01-02T03:04:05Z","resources":{"metrics":{"cores":4},"observed_at":"2026-01-02T03:04:05Z","cpu_percent":null,"memory_total_bytes":398229504,"memory_available_bytes":201326592,"uptime_seconds":12.5,"process_count":115,"processes":[{"pid":1,"name":"init","rss_bytes":4096}]}}`
	var status ModemStatus
	if err := json.Unmarshal([]byte(old), &status); err != nil {
		t.Fatal(err)
	}
	r := status.Resources
	if r == nil || r.MemoryTotal != 398229504 || r.ProcessCount != 115 || r.CPUPercent != nil || len(r.Processes) != 1 {
		t.Fatalf("old fields lost: %+v", r)
	}
	// Nothing the old Node did not send may look sampled.
	if r.CPU != nil || r.Memory != nil || r.Cell != nil || r.EMMC != nil || r.Agent != nil || r.ThreadCount != nil || r.ThermalZones != nil || r.Storage != nil || r.Interfaces != nil || r.BootID != "" || r.ProcessScanTruncated {
		t.Fatalf("absent telemetry decoded as present: %+v", r)
	}
}

func TestNewResourcesDocumentDecodesIntoOldType(t *testing.T) {
	n, f, u, b, on := 4, 12.5, uint64(1024), uint8(1), true
	pci, channel, tac, cell := uint16(101), uint32(1300), uint32(1), uint64(257)
	current := SystemResources{
		ObservedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), CPUPercent: &f, MemoryTotal: 2048, MemoryAvailable: 1024,
		UptimeSeconds: 9, ProcessCount: 2, Processes: []ProcessResource{{PID: 1, Name: "init", RSSBytes: 4096}},
		ThreadCount: &n, BootID: "00000000-0000-4000-8000-000000000000",
		CPU:          &CPUResources{CoreCount: &n, Load1: &f, Cores: []CPUCore{{Index: 0, Online: &on, CurrentKHz: &u, Percent: &f}}},
		ThermalZones: []ThermalZone{{Zone: "thermal_zone0", Type: "cpu0-1-thermal", Celsius: 41.5}},
		Memory:       &MemoryResources{TotalBytes: &u, SwapFreeBytes: &u},
		Storage:      []StorageResource{{Role: StorageRoleRoot, Path: "/", TotalBytes: 10, FreeBytes: 4, AvailableBytes: 3, UsedBytes: 6, FSType: "ext4"}},
		EMMC:         &EMMCHealth{Device: "mmcblk0", LifeTimeEstA: &b},
		Interfaces:   []InterfaceResource{{Name: "wwan0", RxBytes: 1, RxBytesPerSecond: &f}},
		Agent:        &AgentResource{PID: 7, RSSBytes: &u, CPUPercent: &f},
		Cell:         &CellResource{Band: "B3", EARFCN: &channel, PCI: &pci, TAC: &tac, CellID: &cell},
	}
	data, err := json.Marshal(ModemStatus{State: ModemReady, Resources: &current})
	if err != nil {
		t.Fatal(err)
	}
	var old struct {
		State     ModemState             `json:"state"`
		Resources *legacySystemResources `json:"resources"`
	}
	if err := json.Unmarshal(data, &old); err != nil {
		t.Fatalf("an older reader rejects the new document: %v", err)
	}
	if old.State != ModemReady || old.Resources == nil || old.Resources.MemoryTotal != 2048 || *old.Resources.CPUPercent != 12.5 || old.Resources.ProcessCount != 2 || old.Resources.Processes[0].Name != "init" {
		t.Fatalf("an older reader misreads the new document: %+v", old.Resources)
	}
	var status ModemStatus
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	back := status.Resources
	if back.Cell == nil || *back.Cell.CellID != 257 || *back.Interfaces[0].RxBytesPerSecond != 12.5 || *back.EMMC.LifeTimeEstA != 1 {
		t.Fatalf("new fields did not survive a round trip: %+v", back)
	}
}

// A zero is a measurement and absence is not; the two must stay distinct on
// the wire, which is what the pointers are for.
func TestResourcesKeepZeroDistinctFromUnknown(t *testing.T) {
	zero := 0.0
	known, _ := json.Marshal(InterfaceResource{Name: "wwan0", RxBytesPerSecond: &zero, TxBytesPerSecond: &zero})
	unknown, _ := json.Marshal(InterfaceResource{Name: "wwan0"})
	if !strings.Contains(string(known), `"rx_bytes_per_second":0`) || strings.Contains(string(unknown), "per_second") {
		t.Fatalf("known=%s unknown=%s", known, unknown)
	}
	empty, _ := json.Marshal(SystemResources{})
	for _, key := range []string{"cpu\"", "thermal_zones", "memory\"", "storage", "emmc", "interfaces", "agent", "boot_id", "cell", "thread_count", "process_scan_truncated"} {
		if strings.Contains(string(empty), `"`+key) {
			t.Fatalf("unsampled %s is on the wire: %s", key, empty)
		}
	}
}
