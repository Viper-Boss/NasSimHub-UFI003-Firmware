// Package systemstats reads bounded Linux procfs data without subprocesses.
package systemstats

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

var mu sync.Mutex
var previousTotal, previousIdle uint64
var cached *proto.SystemResources

func Snapshot() *proto.SystemResources {
	mu.Lock()
	defer mu.Unlock()
	if cached != nil && time.Since(cached.ObservedAt) < 2*time.Second {
		return cached
	}
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil
	}
	total, idle, err := cpuTicks(string(data))
	if err != nil {
		return nil
	}
	r := &proto.SystemResources{ObservedAt: time.Now().UTC(), Processes: []proto.ProcessResource{}}
	if previousTotal != 0 && total > previousTotal && idle >= previousIdle {
		busy := float64(total-previousTotal) - float64(idle-previousIdle)
		p := 100 * busy / float64(total-previousTotal)
		if p >= 0 && p <= 100 {
			r.CPUPercent = &p
		}
	}
	previousTotal, previousIdle = total, idle
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		r.MemoryTotal, r.MemoryAvailable = memory(string(data))
	}
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			r.UptimeSeconds, _ = strconv.ParseFloat(fields[0], 64)
		}
	}
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		r.ProcessCount++
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err != nil {
			continue
		} // Processes can exit while collecting.
		p := proto.ProcessResource{PID: pid}
		for _, line := range strings.Split(string(data), "\n") {
			if name, ok := strings.CutPrefix(line, "Name:"); ok {
				p.Name = strings.TrimSpace(name)
			}
			if rss, ok := strings.CutPrefix(line, "VmRSS:"); ok {
				var kb uint64
				fmt.Sscanf(rss, "%d kB", &kb)
				p.RSSBytes = kb * 1024
			}
		}
		if len(p.Name) > 64 {
			p.Name = p.Name[:64]
		}
		r.Processes = append(r.Processes, p)
	}
	sort.Slice(r.Processes, func(i, j int) bool {
		if r.Processes[i].RSSBytes == r.Processes[j].RSSBytes {
			return r.Processes[i].PID < r.Processes[j].PID
		}
		return r.Processes[i].RSSBytes > r.Processes[j].RSSBytes
	})
	if len(r.Processes) > 12 {
		r.Processes = r.Processes[:12]
	}
	r.Metrics = deviceMetrics()
	cached = r
	return r
}

func cpuTicks(data string) (uint64, uint64, error) {
	line := strings.SplitN(data, "\n", 2)[0]
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, fmt.Errorf("missing CPU counters")
	}
	var total, idle uint64
	// Guest counters are already included in user/nice and must not be counted twice.
	for i := 1; i < len(f) && i <= 8; i++ {
		v, e := strconv.ParseUint(f[i], 10, 64)
		if e != nil {
			return 0, 0, e
		}
		total += v
		if i == 4 || i == 5 {
			idle += v
		}
	}
	return total, idle, nil
}

func memory(data string) (uint64, uint64) {
	var total, available uint64
	for _, line := range strings.Split(data, "\n") {
		var kb uint64
		if strings.HasPrefix(line, "MemTotal:") {
			fmt.Sscanf(line, "MemTotal: %d kB", &kb)
			total = kb * 1024
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			fmt.Sscanf(line, "MemAvailable: %d kB", &kb)
			available = kb * 1024
		}
	}
	if available > total {
		available = total
	}
	return total, available
}
