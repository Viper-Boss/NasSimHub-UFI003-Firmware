package systemstats

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// Bounds on one sample. The device has four cores, a handful of thermal zones
// and interfaces and about a hundred processes; the limits leave room for
// that and stop a pathological /proc or sysfs from turning one tick into
// thousands of reads.
const (
	maxCores       = 16
	maxZones       = 16
	maxInterfaces  = 32
	maxProcessScan = 512
	maxProcEntries = 4096
	topProcesses   = 12

	smallFile = 256
	textFile  = 16 << 10
)

// maxDeltaWindow is the longest gap between two samples that still yields a
// rate or a utilisation. After the sampler has been idle the previous counters
// are minutes old; a figure averaged over that gap is not what the device is
// doing now, so it is reported as unknown and the next tick measures afresh.
const maxDeltaWindow = 10 * time.Second

const defaultStatePath = "/var/lib/nassimhub"

type ticks struct{ total, idle uint64 }

type netCounters struct{ rx, tx uint64 }

// Collector turns one pass over procfs and sysfs into a SystemResources. It
// keeps the previous counters, because utilisation and rates only exist
// between two samples, and it caches the few values that cannot change while
// the system is up. It is not safe for concurrent use; the Sampler is its
// only caller.
type Collector struct {
	src       Source
	now       func() time.Time
	statePath string

	have     bool
	at       time.Time
	cpu      ticks
	cores    map[int]ticks
	self     uint64
	haveSelf bool
	net      map[string]netCounters

	zoneTypes  map[string]string
	freqLimits map[int][2]uint64
	model      *string
	bootID     string
}

// NewCollector reads through src. now supplies the sample time; time.Now
// carries a monotonic reading, which is what makes the rates immune to the
// wall clock being stepped by NTP shortly after boot.
func NewCollector(src Source, now func() time.Time) *Collector {
	if now == nil {
		now = time.Now
	}
	return &Collector{src: src, now: now, statePath: defaultStatePath, zoneTypes: map[string]string{}, freqLimits: map[int][2]uint64{}}
}

func (c *Collector) text(name string, limit int) (string, bool) {
	data, err := c.src.ReadFile(name, limit)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

func (c *Collector) number(name string) (uint64, bool) {
	s, ok := c.text(name, smallFile)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

// Sample reads everything once. It returns nil when the kernel's CPU counters
// cannot be read at all, which on Linux means procfs is not there.
func (c *Collector) Sample() *proto.SystemResources {
	now := c.now()
	stat, ok := c.text("/proc/stat", textFile)
	if !ok {
		c.have = false
		return nil
	}
	cpu, cores, err := parseCPUStat(stat)
	if err != nil {
		c.have = false
		return nil
	}
	elapsed := now.Sub(c.at)
	comparable := c.have && elapsed > 0 && elapsed <= maxDeltaWindow

	r := &proto.SystemResources{ObservedAt: now.UTC(), Processes: []proto.ProcessResource{}}
	if comparable {
		r.CPUPercent = percentBetween(c.cpu, cpu)
	}
	if data, ok := c.text("/proc/meminfo", textFile); ok {
		r.MemoryTotal, r.MemoryAvailable = memory(data)
		r.Memory = parseMeminfo(data)
	}
	if data, ok := c.text("/proc/uptime", smallFile); ok {
		if fields := strings.Fields(data); len(fields) > 0 {
			r.UptimeSeconds, _ = strconv.ParseFloat(fields[0], 64)
		}
	}
	if c.bootID == "" {
		if id, ok := c.text("/proc/sys/kernel/random/boot_id", smallFile); ok && len(id) <= 64 {
			c.bootID = id
		}
	}
	r.BootID = c.bootID
	r.CPU = c.sampleCPU(cores, comparable)
	r.ThermalZones = c.sampleThermal()
	r.Storage = c.sampleStorage()
	r.EMMC = c.sampleEMMC()
	r.Interfaces = c.sampleInterfaces(elapsed, comparable)
	c.sampleProcesses(r)
	r.Agent = c.sampleAgent(cpu, comparable)
	r.Cell = c.readCell(now)
	r.Metrics = legacyMetrics(r)

	c.have, c.at, c.cpu, c.cores = true, now, cpu, cores
	return r
}

// percentBetween is utilisation between two readings of the same counters. A
// counter that went backwards, or a result outside 0-100, means the readings
// are not comparable and there is no answer.
func percentBetween(before, after ticks) *float64 {
	if after.total <= before.total || after.idle < before.idle {
		return nil
	}
	span := float64(after.total - before.total)
	p := 100 * (span - float64(after.idle-before.idle)) / span
	if p < 0 || p > 100 {
		return nil
	}
	return &p
}

// parseCPUStat reads the aggregate "cpu" line and the per-core lines that
// follow it. Only online cores have a line.
func parseCPUStat(data string) (ticks, map[int]ticks, error) {
	var total ticks
	cores := map[int]ticks{}
	for i, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if i == 0 {
			if len(f) < 5 || f[0] != "cpu" {
				return ticks{}, nil, fmt.Errorf("missing CPU counters")
			}
			t, err := sumTicks(f)
			if err != nil {
				return ticks{}, nil, err
			}
			total = t
			continue
		}
		// The cpuN lines are contiguous; the first other line ends them.
		if len(f) < 5 || !strings.HasPrefix(f[0], "cpu") {
			break
		}
		index, err := strconv.Atoi(f[0][3:])
		if err != nil || index < 0 || len(cores) >= maxCores {
			continue
		}
		if t, err := sumTicks(f); err == nil {
			cores[index] = t
		}
	}
	return total, cores, nil
}

func sumTicks(f []string) (ticks, error) {
	var t ticks
	// Guest counters are already included in user/nice and must not be counted twice.
	for i := 1; i < len(f) && i <= 8; i++ {
		v, e := strconv.ParseUint(f[i], 10, 64)
		if e != nil {
			return ticks{}, e
		}
		t.total += v
		if i == 4 || i == 5 {
			t.idle += v
		}
	}
	return t, nil
}

// parseCPUList reads the kernel's range-list form, such as "0-3" or "0,2-3".
func parseCPUList(s string) ([]int, bool) {
	var out []int
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 0 {
			return nil, false
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a {
				return nil, false
			}
		}
		for i := a; i <= b && len(out) < maxCores; i++ {
			out = append(out, i)
		}
	}
	return out, true
}

func (c *Collector) sampleCPU(cores map[int]ticks, comparable bool) *proto.CPUResources {
	out := &proto.CPUResources{}
	if c.model == nil {
		// Read once: it cannot change while the system is up, and a kernel
		// that does not name the processor will not start naming it.
		model := ""
		if data, ok := c.text("/proc/cpuinfo", textFile); ok {
			model = parseCPUModel(data)
		}
		c.model = &model
	}
	out.Model = *c.model

	const base = "/sys/devices/system/cpu/"
	var present []int
	if s, ok := c.text(base+"present", smallFile); ok {
		if list, ok := parseCPUList(s); ok && len(list) > 0 {
			present = list
			n := len(list)
			out.CoreCount = &n
		}
	}
	online := map[int]bool{}
	onlineKnown := false
	if s, ok := c.text(base+"online", smallFile); ok {
		if list, ok := parseCPUList(s); ok {
			onlineKnown = true
			for _, i := range list {
				online[i] = true
			}
		}
	}
	indexes := present
	if indexes == nil {
		// Without the present list only the cores with counters are known to
		// exist, so they are listed and the count is left unstated.
		for i := range cores {
			indexes = append(indexes, i)
		}
		sort.Ints(indexes)
	}
	for _, i := range indexes {
		core := proto.CPUCore{Index: i}
		if onlineKnown {
			on := online[i]
			core.Online = &on
		}
		if !onlineKnown || online[i] {
			dir := base + "cpu" + strconv.Itoa(i) + "/cpufreq/"
			if v, ok := c.number(dir + "scaling_cur_freq"); ok {
				core.CurrentKHz = &v
			}
			limits, cached := c.freqLimits[i]
			if !cached {
				lo, okLo := c.number(dir + "cpuinfo_min_freq")
				hi, okHi := c.number(dir + "cpuinfo_max_freq")
				if okLo && okHi {
					limits, cached = [2]uint64{lo, hi}, true
					c.freqLimits[i] = limits
				}
			}
			if cached {
				lo, hi := limits[0], limits[1]
				core.MinKHz, core.MaxKHz = &lo, &hi
			}
		}
		if after, ok := cores[i]; ok && comparable {
			if before, ok := c.cores[i]; ok {
				core.Percent = percentBetween(before, after)
			}
		}
		out.Cores = append(out.Cores, core)
	}
	if data, ok := c.text("/proc/loadavg", smallFile); ok {
		if f := strings.Fields(data); len(f) >= 3 {
			a, ea := strconv.ParseFloat(f[0], 64)
			b, eb := strconv.ParseFloat(f[1], 64)
			d, ed := strconv.ParseFloat(f[2], 64)
			if ea == nil && eb == nil && ed == nil && a >= 0 && b >= 0 && d >= 0 {
				out.Load1, out.Load5, out.Load15 = &a, &b, &d
			}
		}
	}
	return out
}

// parseCPUModel returns what the kernel itself calls the processor: x86 and
// 32-bit ARM print "model name", older vendor kernels print "Hardware".
func parseCPUModel(data string) string {
	hardware := ""
	for _, line := range strings.Split(data, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) > 64 {
			value = value[:64]
		}
		switch strings.TrimSpace(key) {
		case "model name":
			if value != "" {
				return value
			}
		case "Hardware":
			hardware = value
		}
	}
	return hardware
}

func (c *Collector) sampleThermal() []proto.ThermalZone {
	const base = "/sys/class/thermal"
	names, err := c.src.ReadDir(base, 64)
	if err != nil {
		return nil
	}
	type zone struct {
		name  string
		index int
	}
	var zones []zone
	for _, name := range names {
		if n, ok := strings.CutPrefix(name, "thermal_zone"); ok {
			if i, err := strconv.Atoi(n); err == nil && i >= 0 {
				zones = append(zones, zone{name, i})
			}
		}
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].index < zones[j].index })
	if len(zones) > maxZones {
		zones = zones[:maxZones]
	}
	var out []proto.ThermalZone
	for _, z := range zones {
		s, ok := c.text(base+"/"+z.name+"/temp", smallFile)
		if !ok {
			continue // A sensor that does not answer has no temperature, not 0 °C.
		}
		milli, err := strconv.ParseInt(s, 10, 64)
		// Sensors that are powered down report sentinels far outside any
		// temperature silicon survives.
		if err != nil || milli <= -40000 || milli >= 150000 {
			continue
		}
		kind, cached := c.zoneTypes[z.name]
		if !cached {
			if kind, cached = c.text(base+"/"+z.name+"/type", smallFile); cached {
				if len(kind) > 64 {
					kind = kind[:64]
				}
				c.zoneTypes[z.name] = kind
			}
		}
		out = append(out, proto.ThermalZone{Zone: z.name, Type: kind, Celsius: float64(milli) / 1000})
	}
	return out
}

func parseMeminfo(data string) *proto.MemoryResources {
	m, any := &proto.MemoryResources{}, false
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		var target **uint64
		switch f[0] {
		case "MemTotal:":
			target = &m.TotalBytes
		case "MemAvailable:":
			target = &m.AvailableBytes
		case "MemFree:":
			target = &m.FreeBytes
		case "Buffers:":
			target = &m.BuffersBytes
		case "Cached:":
			target = &m.CachedBytes
		case "SwapTotal:":
			target = &m.SwapTotalBytes
		case "SwapFree:":
			target = &m.SwapFreeBytes
		default:
			continue
		}
		kb, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil || kb > 1<<53 {
			continue
		}
		v := kb * 1024
		*target, any = &v, true
	}
	if !any {
		return nil
	}
	return m
}

func (c *Collector) sampleStorage() []proto.StorageResource {
	mounts, _ := c.text("/proc/self/mounts", textFile)
	var out []proto.StorageResource
	for _, target := range []struct{ role, path string }{{proto.StorageRoleState, c.statePath}, {proto.StorageRoleRoot, "/"}} {
		stat, err := c.src.Statfs(target.path)
		if err != nil || stat.Blocks == 0 || stat.Free > stat.Blocks || stat.Available > stat.Blocks {
			continue
		}
		out = append(out, proto.StorageResource{
			Role: target.role, Path: target.path,
			TotalBytes: stat.Blocks * stat.BlockSize, FreeBytes: stat.Free * stat.BlockSize,
			AvailableBytes: stat.Available * stat.BlockSize, UsedBytes: (stat.Blocks - stat.Free) * stat.BlockSize,
			FSType: mountType(mounts, target.path),
		})
	}
	return out
}

// mountType finds the filesystem type of the mount that holds path: the
// longest mount point that is a prefix of it, and the last such line, since a
// later mount on the same point hides the earlier one.
func mountType(mounts, path string) string {
	best, kind := -1, ""
	for _, line := range strings.Split(mounts, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		point := f[1]
		if point != "/" && path != point && !strings.HasPrefix(path, point+"/") {
			continue
		}
		if len(point) >= best && len(f[2]) <= 32 {
			best, kind = len(point), f[2]
		}
	}
	return kind
}

func (c *Collector) sampleEMMC() *proto.EMMCHealth {
	const dir = "/sys/block/mmcblk0/device/"
	s, ok := c.text(dir+"life_time", smallFile)
	if !ok {
		return nil
	}
	f := strings.Fields(s)
	if len(f) != 2 {
		return nil
	}
	a, okA := parseHexByte(f[0])
	b, okB := parseHexByte(f[1])
	if !okA || !okB {
		return nil
	}
	out := &proto.EMMCHealth{Device: "mmcblk0", LifeTimeEstA: &a, LifeTimeEstB: &b}
	if s, ok := c.text(dir+"pre_eol_info", smallFile); ok {
		if v, ok := parseHexByte(s); ok {
			out.PreEOL = &v
		}
	}
	return out
}

func parseHexByte(s string) (uint8, bool) {
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(s), "0x"), 16, 8)
	return uint8(v), err == nil
}

func (c *Collector) sampleInterfaces(elapsed time.Duration, comparable bool) []proto.InterfaceResource {
	data, ok := c.text("/proc/net/dev", textFile)
	if !ok {
		c.net = nil
		return nil
	}
	var out []proto.InterfaceResource
	current := map[string]netCounters{}
	for _, line := range strings.Split(data, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue // The two header lines have no colon.
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if name == "" || name == "lo" || len(name) > 32 || len(f) < 11 || len(out) >= maxInterfaces {
			continue
		}
		var v [11]uint64
		valid := true
		for _, i := range []int{0, 1, 2, 8, 9, 10} {
			n, err := strconv.ParseUint(f[i], 10, 64)
			if err != nil {
				valid = false
				break
			}
			v[i] = n
		}
		if !valid {
			continue
		}
		iface := proto.InterfaceResource{Name: name, RxBytes: v[0], RxPackets: v[1], RxErrors: v[2], TxBytes: v[8], TxPackets: v[9], TxErrors: v[10]}
		// A counter that went backwards was reset (interface re-created, modem
		// restart) or wrapped. Either way the difference is not traffic, so
		// this interval has no rate; the next one starts from the new value.
		if before, ok := c.net[name]; ok && comparable && iface.RxBytes >= before.rx && iface.TxBytes >= before.tx {
			seconds := elapsed.Seconds()
			rx, tx := float64(iface.RxBytes-before.rx)/seconds, float64(iface.TxBytes-before.tx)/seconds
			iface.RxBytesPerSecond, iface.TxBytesPerSecond = &rx, &tx
		}
		current[name] = netCounters{iface.RxBytes, iface.TxBytes}
		out = append(out, iface)
	}
	c.net = current
	return out
}

func (c *Collector) sampleProcesses(r *proto.SystemResources) {
	entries, err := c.src.ReadDir("/proc", maxProcEntries)
	if err != nil {
		return
	}
	r.ProcessScanTruncated = len(entries) >= maxProcEntries
	threads, scanned := 0, 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil || pid <= 0 {
			continue
		}
		r.ProcessCount++
		if scanned >= maxProcessScan {
			r.ProcessScanTruncated = true
			continue
		}
		scanned++
		data, ok := c.text("/proc/"+entry+"/status", textFile)
		if !ok {
			continue
		} // Processes can exit while collecting.
		p, n := parseProcessStatus(data)
		p.PID = pid
		threads += n
		r.Processes = append(r.Processes, p)
	}
	sort.Slice(r.Processes, func(i, j int) bool {
		if r.Processes[i].RSSBytes == r.Processes[j].RSSBytes {
			return r.Processes[i].PID < r.Processes[j].PID
		}
		return r.Processes[i].RSSBytes > r.Processes[j].RSSBytes
	})
	if len(r.Processes) > topProcesses {
		r.Processes = r.Processes[:topProcesses]
	}
	// A truncated scan would give a thread count that is too low and looks exact.
	if !r.ProcessScanTruncated {
		r.ThreadCount = &threads
	}
}

func parseProcessStatus(data string) (proto.ProcessResource, int) {
	var p proto.ProcessResource
	threads := 0
	for _, line := range strings.Split(data, "\n") {
		if name, ok := strings.CutPrefix(line, "Name:"); ok {
			p.Name = strings.TrimSpace(name)
		}
		if rss, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			var kb uint64
			fmt.Sscanf(rss, "%d kB", &kb)
			p.RSSBytes = kb * 1024
		}
		if n, ok := strings.CutPrefix(line, "Threads:"); ok {
			threads, _ = strconv.Atoi(strings.TrimSpace(n))
		}
	}
	if len(p.Name) > 64 {
		p.Name = p.Name[:64]
	}
	return p, threads
}

// sampleAgent reports this process. Its CPU share is its own tick delta over
// the machine's, which needs no assumption about the kernel's tick rate and
// puts it on the same scale as the overall cpu_percent.
func (c *Collector) sampleAgent(cpu ticks, comparable bool) *proto.AgentResource {
	stat, ok := c.text("/proc/self/stat", 1024)
	if !ok {
		c.haveSelf = false
		return nil
	}
	pid, used, ok := parseSelfStat(stat)
	if !ok {
		c.haveSelf = false
		return nil
	}
	out := &proto.AgentResource{PID: pid}
	if comparable && c.haveSelf && used >= c.self && cpu.total > c.cpu.total {
		if p := 100 * float64(used-c.self) / float64(cpu.total-c.cpu.total); p >= 0 && p <= 100 {
			out.CPUPercent = &p
		}
	}
	c.self, c.haveSelf = used, true
	if status, ok := c.text("/proc/self/status", textFile); ok && strings.Contains(status, "VmRSS:") {
		p, _ := parseProcessStatus(status)
		out.RSSBytes = &p.RSSBytes
	}
	return out
}

// parseSelfStat returns the pid and utime+stime in clock ticks. The command
// name is in parentheses and may itself contain spaces or parentheses, so the
// numbered fields are counted from the last ")".
func parseSelfStat(data string) (int, uint64, bool) {
	end := strings.LastIndex(data, ")")
	open := strings.Index(data, "(")
	if open < 0 || end < open {
		return 0, 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(data[:open]))
	f := strings.Fields(data[end+1:])
	if err != nil || len(f) < 13 {
		return 0, 0, false
	}
	user, eu := strconv.ParseUint(f[11], 10, 64)
	system, es := strconv.ParseUint(f[12], 10, 64)
	if eu != nil || es != nil {
		return 0, 0, false
	}
	return pid, user + system, true
}

// legacyMetrics fills the older free-form map from the same sample. The
// standalone admin page and the NAS web UI were written against these keys;
// each is present only when the typed value it is derived from is.
func legacyMetrics(r *proto.SystemResources) map[string]any {
	m := map[string]any{}
	if cpu := r.CPU; cpu != nil {
		if cpu.CoreCount != nil {
			m["cores"] = *cpu.CoreCount
		}
		if cpu.Model != "" {
			m["cpu_model_name"] = cpu.Model
		}
		if cpu.Load1 != nil {
			m["load_raw_1"], m["load_raw_5"], m["load_raw_15"] = *cpu.Load1, *cpu.Load5, *cpu.Load15
		}
		// These two keys always described a single core; keep them the
		// lowest-numbered core that reports a frequency.
		for _, core := range cpu.Cores {
			if core.CurrentKHz != nil {
				m["cpu_current_mhz"] = float64(*core.CurrentKHz) / 1000
				if core.MaxKHz != nil {
					m["cpu_max_mhz"] = float64(*core.MaxKHz) / 1000
				}
				break
			}
		}
	}
	if mem := r.Memory; mem != nil {
		if mem.CachedBytes != nil {
			m["memory_cached_bytes"] = *mem.CachedBytes
		}
		if mem.BuffersBytes != nil {
			m["memory_buffers_bytes"] = *mem.BuffersBytes
		}
	}
	// A zone is called the CPU's or the modem's only when the kernel's own
	// type says so. With several CPU zones the hottest is the one that
	// matters for throttling.
	for _, zone := range r.ThermalZones {
		kind := strings.ToLower(zone.Type)
		for key, word := range map[string]string{"cpu_temp_celsius": "cpu", "modem_temp_celsius": "modem"} {
			if strings.Contains(kind, word) {
				if old, ok := m[key].(float64); !ok || zone.Celsius > old {
					m[key] = zone.Celsius
				}
			}
		}
	}
	if r.ThreadCount != nil {
		m["thread_count"] = *r.ThreadCount
	}
	for _, s := range r.Storage {
		if s.Role != proto.StorageRoleState {
			continue
		}
		m["flash_total_bytes"], m["flash_free_bytes"], m["flash_path"] = s.TotalBytes, s.AvailableBytes, s.Path
		m["flash_used_percent"] = 100 * float64(s.TotalBytes-s.AvailableBytes) / float64(s.TotalBytes)
		if s.FSType != "" {
			m["flash_fs_type"] = s.FSType
		}
	}
	interfaces := []map[string]any{}
	for _, i := range r.Interfaces {
		interfaces = append(interfaces, map[string]any{"name": i.Name, "rx_bytes": i.RxBytes, "tx_bytes": i.TxBytes})
	}
	m["interfaces"] = interfaces
	if r.Cell != nil {
		m["cellular_radio"] = cellMetrics(r.Cell)
	}
	return m
}
