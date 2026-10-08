// Package systemstats samples bounded Linux procfs and sysfs data without
// subprocesses, on one goroutine, and serves the result from memory.
package systemstats

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/human-agent65535/nassimhub-node/proto"
)

var (
	start         sync.Once
	defaultSample *Sampler
)

// Supported reports whether this platform has anything to sample, and if not,
// why. An unsupported platform produces no resources document at all.
func Supported() (bool, string) {
	src, reason := platformSource()
	return src != nil, reason
}

// Snapshot returns the device's current telemetry, or nil when there is none:
// the platform is unsupported, or no sample could be taken. The first call
// starts the sampler, which then runs for the life of the process and idles
// when nobody asks. The result is shared; callers must copy before changing it.
func Snapshot() *proto.SystemResources {
	start.Do(func() {
		if src, _ := platformSource(); src != nil {
			defaultSample = NewSampler(NewCollector(src, nil))
			go defaultSample.Run(context.Background())
		}
	})
	if defaultSample == nil {
		return nil
	}
	return defaultSample.Snapshot()
}

func cpuTicks(data string) (uint64, uint64, error) {
	f := strings.Fields(strings.SplitN(data, "\n", 2)[0])
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, fmt.Errorf("missing CPU counters")
	}
	t, err := sumTicks(f)
	return t.total, t.idle, err
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
