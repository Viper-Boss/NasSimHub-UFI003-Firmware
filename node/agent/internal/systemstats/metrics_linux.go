//go:build linux

package systemstats

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func deviceMetrics() map[string]any {
	m := map[string]any{"cores": runtime.NumCPU(), "cpu_model_name": "Qualcomm MSM8916"}
	read := func(p string) string { b, _ := os.ReadFile(p); return strings.TrimSpace(string(b)) }
	number := func(p string) (float64, bool) { v, e := strconv.ParseFloat(read(p), 64); return v, e == nil }
	for _, line := range strings.Split(read("/proc/meminfo"), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, e := strconv.ParseUint(f[1], 10, 64)
		if e != nil {
			continue
		}
		switch f[0] {
		case "Cached:":
			m["memory_cached_bytes"] = v * 1024
		case "Buffers:":
			m["memory_buffers_bytes"] = v * 1024
		}
	}
	for _, f := range []struct{ key, path string }{{"cpu_current_mhz", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"}, {"cpu_max_mhz", "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"}} {
		if v, ok := number(f.path); ok {
			m[f.key] = v / 1000
		}
	}
	zones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*")
	for _, z := range zones {
		kind := read(z + "/type")
		if strings.Contains(kind, "cpu") || strings.Contains(kind, "tsens") {
			if v, ok := number(z + "/temp"); ok && v > -40000 && v < 150000 {
				m["cpu_temp_celsius"] = v / 1000
				break
			}
		}
	}
	entries, _ := os.ReadDir("/proc")
	threads := 0
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		for _, line := range strings.Split(read("/proc/"+e.Name()+"/status"), "\n") {
			if strings.HasPrefix(line, "Threads:") {
				v, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Threads:")))
				threads += v
			}
		}
	}
	m["thread_count"] = threads
	var stat unix.Statfs_t
	if unix.Statfs("/var/lib/nassimhub", &stat) == nil {
		total := uint64(stat.Blocks) * uint64(stat.Bsize)
		free := uint64(stat.Bavail) * uint64(stat.Bsize)
		m["flash_total_bytes"] = total
		m["flash_free_bytes"] = free
		m["flash_path"] = "/var/lib/nassimhub"
		if total > 0 {
			m["flash_used_percent"] = 100 * float64(total-free) / float64(total)
		}
		if stat.Type == 0xef53 {
			m["flash_fs_type"] = "ext4"
		}
	}
	interfaces := []map[string]any{}
	nets, _ := os.ReadDir("/sys/class/net")
	for _, e := range nets {
		if e.Name() == "lo" {
			continue
		}
		base := "/sys/class/net/" + e.Name()
		rx, er := strconv.ParseUint(read(base+"/statistics/rx_bytes"), 10, 64)
		tx, et := strconv.ParseUint(read(base+"/statistics/tx_bytes"), 10, 64)
		if er == nil && et == nil {
			interfaces = append(interfaces, map[string]any{"name": e.Name(), "rx_bytes": rx, "tx_bytes": tx})
		}
	}
	m["interfaces"] = interfaces
	if radio := readRadioMetrics(); radio != nil {
		m["cellular_radio"] = radio
	}
	return m
}
