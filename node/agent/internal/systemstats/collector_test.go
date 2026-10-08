package systemstats

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// fakeSource is a device made of fixture text. Every call is counted, so a
// test can state how much one tick is allowed to read.
type fakeSource struct {
	files map[string]string
	dirs  map[string][]string
	fs    map[string]FSStat
	times map[string]time.Time
	reads int
}

func (f *fakeSource) ReadFile(name string, limit int) ([]byte, error) {
	f.reads++
	data, ok := f.files[name]
	if !ok {
		return nil, errors.New("no such file")
	}
	if len(data) > limit {
		data = data[:limit]
	}
	return []byte(data), nil
}

func (f *fakeSource) ReadDir(name string, limit int) ([]string, error) {
	f.reads++
	names, ok := f.dirs[name]
	if !ok {
		return nil, errors.New("no such directory")
	}
	if len(names) > limit {
		names = names[:limit]
	}
	return names, nil
}

func (f *fakeSource) Statfs(path string) (FSStat, error) {
	f.reads++
	stat, ok := f.fs[path]
	if !ok {
		return FSStat{}, errors.New("no such path")
	}
	return stat, nil
}

func (f *fakeSource) ModTime(name string) (time.Time, error) {
	f.reads++
	at, ok := f.times[name]
	if !ok {
		return time.Time{}, errors.New("no such file")
	}
	return at, nil
}

type fakeClock struct{ at time.Time }

func (c *fakeClock) now() time.Time { return c.at }

var epoch = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

const fixtureStat = `cpu  1000 0 500 8000 100 0 20 0 0 0
cpu0 250 0 125 2000 25 0 5 0 0 0
cpu1 250 0 125 2000 25 0 5 0 0 0
cpu2 250 0 125 2000 25 0 5 0 0 0
intr 123456 0 0 0
ctxt 987654
btime 1767323045
`

const fixtureMeminfo = `MemTotal:         388896 kB
MemFree:           41200 kB
MemAvailable:     196608 kB
Buffers:           12288 kB
Cached:           150528 kB
SwapCached:            0 kB
SwapTotal:        194444 kB
SwapFree:         194444 kB
`

const fixtureNetDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:   90000     900    0    0    0     0          0         0    90000     900    0    0    0     0       0          0
 wwan0: 5000000    4000    2    0    0     0          0         0  1000000    3000    1    0    0     0       0          0
 wlan0:    2048      16    0    0    0     0          0         0     4096      32    0    0    0     0       0          0
`

func status(name string, rssKB, threads int) string {
	return fmt.Sprintf("Name:\t%s\nUmask:\t0022\nState:\tS (sleeping)\nVmRSS:\t%8d kB\nThreads:\t%d\n", name, rssKB, threads)
}

// device is a UFI003-shaped fixture: four cores with one offline, the
// MSM8916 thermal zone names, an ext4 root that also holds the state
// directory, and three processes.
func device() *fakeSource {
	f := &fakeSource{
		files: map[string]string{
			"/proc/stat":                      fixtureStat,
			"/proc/meminfo":                   fixtureMeminfo,
			"/proc/uptime":                    "86400.25 300000.00\n",
			"/proc/loadavg":                   "0.42 0.31 0.25 1/118 4242\n",
			"/proc/sys/kernel/random/boot_id": "00000000-0000-4000-8000-000000000001\n",
			"/proc/cpuinfo":                   "processor\t: 0\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd\nCPU implementer\t: 0x41\nCPU part\t: 0xd03\n",
			"/proc/net/dev":                   fixtureNetDev,
			"/proc/self/mounts":               "rootfs / rootfs rw 0 0\n/dev/mmcblk0p14 / ext4 rw,noatime 0 0\ntmpfs /run tmpfs rw 0 0\n",
			"/proc/self/stat":                 "300 (nassimhub-agent) S 1 300 300 0 -1 4194560 900 0 0 0 40 20 0 0 20 0 9 0 5000 20000000 3000\n",
			"/proc/self/status":               status("nassimhub-agent", 12288, 9),
			"/proc/1/status":                  status("init", 4096, 1),
			"/proc/2/status":                  "Name:\tkthreadd\nThreads:\t1\n",
			"/proc/300/status":                status("nassimhub-agent", 12288, 9),

			"/sys/devices/system/cpu/present": "0-3\n",
			"/sys/devices/system/cpu/online":  "0-2\n",

			"/sys/class/thermal/thermal_zone0/type": "cpu0-1-thermal\n",
			"/sys/class/thermal/thermal_zone0/temp": "41500\n",
			"/sys/class/thermal/thermal_zone1/type": "cpu2-3-thermal\n",
			"/sys/class/thermal/thermal_zone1/temp": "43250\n",
			"/sys/class/thermal/thermal_zone2/type": "gpu-thermal\n",
			"/sys/class/thermal/thermal_zone2/temp": "39000\n",
			"/sys/class/thermal/thermal_zone3/type": "camera-thermal\n",
			// thermal_zone3 has no temp file: the sensor does not answer.
			"/sys/class/thermal/thermal_zone4/type": "modem-thermal\n",
			"/sys/class/thermal/thermal_zone4/temp": "44000\n",

			"/sys/block/mmcblk0/device/life_time":    "0x02 0x01\n",
			"/sys/block/mmcblk0/device/pre_eol_info": "0x01\n",
		},
		dirs: map[string][]string{
			"/proc":              {"cpuinfo", "self", "1", "2", "300", "sys"},
			"/sys/class/thermal": {"cooling_device0", "thermal_zone4", "thermal_zone0", "thermal_zone1", "thermal_zone2", "thermal_zone3"},
		},
		fs: map[string]FSStat{
			"/":                  {BlockSize: 4096, Blocks: 800000, Free: 300000, Available: 250000},
			"/var/lib/nassimhub": {BlockSize: 4096, Blocks: 800000, Free: 300000, Available: 250000},
		},
		times: map[string]time.Time{},
	}
	for i := 0; i < 3; i++ {
		dir := fmt.Sprintf("/sys/devices/system/cpu/cpu%d/cpufreq/", i)
		f.files[dir+"scaling_cur_freq"] = "800000\n"
		f.files[dir+"cpuinfo_min_freq"] = "200000\n"
		f.files[dir+"cpuinfo_max_freq"] = "1209600\n"
	}
	return f
}

func setCell(f *fakeSource, at time.Time) {
	// Obviously artificial identifiers: TAC 1, cell 0x101.
	f.files[radioMetricsFile] = "band=3\nearfcn=1300\npci=101\ntac=1\ncell_id=257\n"
	f.times[radioMetricsFile] = at
}

func TestFirstSampleHasNoDeltasAndSecondDoes(t *testing.T) {
	f, clock := device(), &fakeClock{at: epoch}
	c := NewCollector(f, clock.now)
	first := c.Sample()
	if first == nil {
		t.Fatal("no sample")
	}
	if first.CPUPercent != nil || first.Agent.CPUPercent != nil {
		t.Fatalf("utilisation invented from a single reading: %v %v", first.CPUPercent, first.Agent.CPUPercent)
	}
	for _, core := range first.CPU.Cores {
		if core.Percent != nil {
			t.Fatalf("core %d has utilisation on the first sample", core.Index)
		}
	}
	for _, i := range first.Interfaces {
		if i.RxBytesPerSecond != nil || i.TxBytesPerSecond != nil {
			t.Fatalf("%s has a rate on the first sample", i.Name)
		}
	}

	// Two seconds later: 100 more busy ticks and 300 idle overall, core 0 all
	// busy, 10 ticks of that in the agent, and traffic on wwan0 only.
	clock.at = epoch.Add(2 * time.Second)
	f.files["/proc/stat"] = "cpu  1080 0 520 8300 100 0 20 0 0 0\ncpu0 350 0 125 2000 25 0 5 0 0 0\ncpu1 250 0 125 2100 25 0 5 0 0 0\ncpu2 250 0 125 2100 25 0 5 0 0 0\n"
	f.files["/proc/self/stat"] = "300 (nassimhub-agent) S 1 300 300 0 -1 4194560 900 0 0 0 46 24 0 0 20 0 9 0 5000 20000000 3000\n"
	f.files["/proc/net/dev"] = strings.Replace(strings.Replace(fixtureNetDev, "5000000", "5300000", 1), "1000000", "1001000", 1)
	second := c.Sample()
	if second.CPUPercent == nil || *second.CPUPercent != 25 {
		t.Fatalf("cpu percent = %v, want 25", second.CPUPercent)
	}
	if p := second.CPU.Cores[0].Percent; p == nil || *p != 100 {
		t.Fatalf("core 0 = %v, want 100", p)
	}
	if p := second.CPU.Cores[1].Percent; p == nil || *p != 0 {
		t.Fatalf("core 1 = %v, want a measured 0", p)
	}
	if p := second.CPU.Cores[3].Percent; p != nil {
		t.Fatalf("offline core 3 has utilisation %v", *p)
	}
	if p := second.Agent.CPUPercent; p == nil || *p != 2.5 {
		t.Fatalf("agent cpu = %v, want 2.5", p)
	}
	rates := map[string][2]*float64{}
	for _, i := range second.Interfaces {
		rates[i.Name] = [2]*float64{i.RxBytesPerSecond, i.TxBytesPerSecond}
	}
	if r := rates["wwan0"]; r[0] == nil || *r[0] != 150000 || r[1] == nil || *r[1] != 500 {
		t.Fatalf("wwan0 rates = %v", r)
	}
	// No traffic is a measurement: 0 B/s, present.
	if r := rates["wlan0"]; r[0] == nil || *r[0] != 0 || r[1] == nil || *r[1] != 0 {
		t.Fatalf("idle wlan0 must report a known 0 B/s, got %v", r)
	}
}

func TestCounterResetGivesUnknownRateNotASpike(t *testing.T) {
	f, clock := device(), &fakeClock{at: epoch}
	c := NewCollector(f, clock.now)
	c.Sample()
	rate := func() *proto.InterfaceResource {
		clock.at = clock.at.Add(2 * time.Second)
		for _, i := range c.Sample().Interfaces {
			if i.Name == "wwan0" {
				return &i
			}
		}
		t.Fatal("wwan0 missing")
		return nil
	}
	// The modem restarted: rx starts again from a small number while tx kept
	// counting. Neither direction has a trustworthy difference.
	f.files["/proc/net/dev"] = strings.Replace(strings.Replace(fixtureNetDev, "5000000", "700", 1), "1000000", "1000900", 1)
	if i := rate(); i.RxBytesPerSecond != nil || i.TxBytesPerSecond != nil || i.RxBytes != 700 {
		t.Fatalf("reset interval reported a rate: %+v", i)
	}
	f.files["/proc/net/dev"] = strings.Replace(strings.Replace(fixtureNetDev, "5000000", "2700", 1), "1000000", "1000900", 1)
	if i := rate(); i.RxBytesPerSecond == nil || *i.RxBytesPerSecond != 1000 || *i.TxBytesPerSecond != 0 {
		t.Fatalf("rate did not resume from the new baseline: %+v", i)
	}
	// An interface that disappears and comes back starts over as well.
	f.files["/proc/net/dev"] = strings.Replace(fixtureNetDev, " wwan0:", " wwan9:", 1)
	clock.at = clock.at.Add(2 * time.Second)
	c.Sample()
	f.files["/proc/net/dev"] = strings.Replace(fixtureNetDev, "5000000", "9000000", 1)
	if i := rate(); i.RxBytesPerSecond != nil {
		t.Fatalf("re-created interface compared against counters from before it vanished: %v", *i.RxBytesPerSecond)
	}
}

func TestCPUCountersGoingBackwardsGiveUnknown(t *testing.T) {
	f, clock := device(), &fakeClock{at: epoch}
	c := NewCollector(f, clock.now)
	c.Sample()
	clock.at = epoch.Add(2 * time.Second)
	f.files["/proc/stat"] = "cpu  10 0 5 80 1 0 0 0 0 0\ncpu0 10 0 5 80 1 0 0 0 0 0\n"
	f.files["/proc/self/stat"] = "300 (a b) c) S 1 300 300 0 -1 0 0 0 0 0 1 1 0 0 20 0 9 0 5000 0 0\n"
	r := c.Sample()
	if r.CPUPercent != nil || r.CPU.Cores[0].Percent != nil || r.Agent.CPUPercent != nil {
		t.Fatalf("backwards counters produced utilisation: %+v %+v", r.CPUPercent, r.Agent)
	}
	if r.Agent.PID != 300 {
		t.Fatalf("command name with parentheses broke the stat parse: %+v", r.Agent)
	}
}

func TestLongGapBetweenSamplesGivesUnknown(t *testing.T) {
	f, clock := device(), &fakeClock{at: epoch}
	c := NewCollector(f, clock.now)
	c.Sample()
	clock.at = epoch.Add(5 * time.Minute)
	f.files["/proc/stat"] = strings.Replace(fixtureStat, "cpu  1000", "cpu  9000", 1)
	f.files["/proc/net/dev"] = strings.Replace(fixtureNetDev, "5000000", "5300000", 1)
	r := c.Sample()
	if r.CPUPercent != nil || r.Interfaces[0].RxBytesPerSecond != nil {
		t.Fatal("a five-minute average was reported as the current figure")
	}
	clock.at = clock.at.Add(2 * time.Second)
	if r := c.Sample(); r.Interfaces[0].RxBytesPerSecond == nil || *r.Interfaces[0].RxBytesPerSecond != 0 {
		t.Fatal("the sample after the gap did not measure again")
	}
}

func TestCPUTopologyFrequencyAndLoad(t *testing.T) {
	r := NewCollector(device(), (&fakeClock{at: epoch}).now).Sample()
	cpu := r.CPU
	if cpu.CoreCount == nil || *cpu.CoreCount != 4 || len(cpu.Cores) != 4 {
		t.Fatalf("cores: %+v", cpu)
	}
	for i, core := range cpu.Cores {
		wantOnline := i < 3
		if core.Index != i || core.Online == nil || *core.Online != wantOnline {
			t.Fatalf("core %d online = %v", i, core.Online)
		}
		if wantOnline && (core.CurrentKHz == nil || *core.CurrentKHz != 800000 || *core.MinKHz != 200000 || *core.MaxKHz != 1209600) {
			t.Fatalf("core %d frequency: %+v", i, core)
		}
		if !wantOnline && (core.CurrentKHz != nil || core.MinKHz != nil || core.MaxKHz != nil) {
			t.Fatalf("offline core %d has a frequency", i)
		}
	}
	if *cpu.Load1 != 0.42 || *cpu.Load5 != 0.31 || *cpu.Load15 != 0.25 {
		t.Fatalf("load: %v %v %v", *cpu.Load1, *cpu.Load5, *cpu.Load15)
	}
	// This kernel's cpuinfo names no model, so none is reported - in
	// particular not one assumed from the board the agent expects to run on.
	if cpu.Model != "" {
		t.Fatalf("model %q was not in cpuinfo", cpu.Model)
	}
	if _, ok := r.Metrics["cpu_model_name"]; ok {
		t.Fatal("legacy cpu_model_name invented")
	}
	if r.Metrics["cores"] != 4 || r.Metrics["cpu_current_mhz"] != float64(800) || r.Metrics["cpu_max_mhz"] != 1209.6 || r.Metrics["load_raw_1"] != 0.42 {
		t.Fatalf("legacy cpu keys: %v", r.Metrics)
	}
}

func TestCPUModelOnlyFromCPUInfo(t *testing.T) {
	f := device()
	f.files["/proc/cpuinfo"] = "processor\t: 0\nmodel name\t: Example Core v1\nHardware\t: Example Board\n"
	r := NewCollector(f, (&fakeClock{at: epoch}).now).Sample()
	if r.CPU.Model != "Example Core v1" || r.Metrics["cpu_model_name"] != "Example Core v1" {
		t.Fatalf("model = %q", r.CPU.Model)
	}
}

func TestMissingCPUSysfsLeavesFieldsUnknown(t *testing.T) {
	f := device()
	for name := range f.files {
		if strings.HasPrefix(name, "/sys/devices/system/cpu/") {
			delete(f.files, name)
		}
	}
	delete(f.files, "/proc/loadavg")
	r := NewCollector(f, (&fakeClock{at: epoch}).now).Sample()
	if r.CPU.CoreCount != nil || r.CPU.Load1 != nil {
		t.Fatalf("unknown reported as known: %+v", r.CPU)
	}
	// The cores that have counters are still listed, without claims about them.
	if len(r.CPU.Cores) != 3 || r.CPU.Cores[0].Online != nil || r.CPU.Cores[0].CurrentKHz != nil {
		t.Fatalf("cores: %+v", r.CPU.Cores)
	}
	for _, key := range []string{"cores", "cpu_current_mhz", "cpu_max_mhz", "load_raw_1"} {
		if _, ok := r.Metrics[key]; ok {
			t.Fatalf("legacy %s present without a source", key)
		}
	}
}

func TestThermalZonesReportedByTypeAndFailuresOmitted(t *testing.T) {
	f := device()
	r := NewCollector(f, (&fakeClock{at: epoch}).now).Sample()
	var got []string
	for _, z := range r.ThermalZones {
		got = append(got, fmt.Sprintf("%s/%s/%.2f", z.Zone, z.Type, z.Celsius))
	}
	want := "thermal_zone0/cpu0-1-thermal/41.50 thermal_zone1/cpu2-3-thermal/43.25 thermal_zone2/gpu-thermal/39.00 thermal_zone4/modem-thermal/44.00"
	if strings.Join(got, " ") != want {
		t.Fatalf("zones:\n got %s\nwant %s", strings.Join(got, " "), want)
	}
	if r.Metrics["cpu_temp_celsius"] != 43.25 || r.Metrics["modem_temp_celsius"] != float64(44) {
		t.Fatalf("legacy temperatures: %v %v", r.Metrics["cpu_temp_celsius"], r.Metrics["modem_temp_celsius"])
	}

	// A board whose only sensors are not CPU sensors has no CPU temperature,
	// and a sentinel reading is not a temperature at all.
	f.files["/sys/class/thermal/thermal_zone0/type"] = "tsens_tz_sensor0\n"
	f.files["/sys/class/thermal/thermal_zone1/type"] = "battery\n"
	f.files["/sys/class/thermal/thermal_zone2/temp"] = "-274000\n"
	delete(f.files, "/sys/class/thermal/thermal_zone4/temp")
	r = NewCollector(f, (&fakeClock{at: epoch}).now).Sample()
	if len(r.ThermalZones) != 2 || r.ThermalZones[0].Type != "tsens_tz_sensor0" {
		t.Fatalf("zones: %+v", r.ThermalZones)
	}
	for _, key := range []string{"cpu_temp_celsius", "modem_temp_celsius"} {
		if v, ok := r.Metrics[key]; ok {
			t.Fatalf("%s = %v although no zone of that type answered", key, v)
		}
	}
}

func TestMemoryClasses(t *testing.T) {
	f := device()
	r := NewCollector(f, (&fakeClock{at: epoch}).now).Sample()
	m := r.Memory
	if *m.TotalBytes != 388896<<10 || *m.AvailableBytes != 196608<<10 || *m.FreeBytes != 41200<<10 || *m.BuffersBytes != 12288<<10 || *m.CachedBytes != 150528<<10 || *m.SwapTotalBytes != 194444<<10 || *m.SwapFreeBytes != 194444<<10 {
		t.Fatalf("memory: %+v", m)
	}
	if r.MemoryTotal != 388896<<10 || r.MemoryAvailable != 196608<<10 || r.Metrics["memory_cached_bytes"] != uint64(150528<<10) {
		t.Fatalf("legacy memory fields changed: %d %d %v", r.MemoryTotal, r.MemoryAvailable, r.Metrics["memory_cached_bytes"])
	}

	// A kernel without swap accounting, and with swap present but empty.
	f.files["/proc/meminfo"] = "MemTotal: 1024 kB\nMemFree: 512 kB\nSwapCached: 7 kB\n"
	m = NewCollector(f, (&fakeClock{at: epoch}).now).Sample().Memory
	if m.SwapTotalBytes != nil || m.CachedBytes != nil || m.AvailableBytes != nil || *m.FreeBytes != 512<<10 {
		t.Fatalf("absent lines became values: %+v", m)
	}
	f.files["/proc/meminfo"] = "MemTotal: 1024 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
	m = NewCollector(f, (&fakeClock{at: epoch}).now).Sample().Memory
	if m.SwapTotalBytes == nil || *m.SwapTotalBytes != 0 {
		t.Fatal("a reported zero swap must stay a known zero")
	}
	delete(f.files, "/proc/meminfo")
	if r := NewCollector(f, (&fakeClock{at: epoch}).now).Sample(); r.Memory != nil {
		t.Fatalf("memory without meminfo: %+v", r.Memory)
	}
}

func TestStorageAndEMMC(t *testing.T) {
	f := device()
	f.files["/proc/self/mounts"] += "/dev/mmcblk0p15 /var/lib/nassimhub f2fs rw 0 0\n"
	f.fs["/var/lib/nassimhub"] = FSStat{BlockSize: 4096, Blocks: 1000, Free: 400, Available: 250}
	r := NewCollector(f, (&fakeClock{at: epoch}).now).Sample()
	if len(r.Storage) != 2 {
		t.Fatalf("storage: %+v", r.Storage)
	}
	state, root := r.Storage[0], r.Storage[1]
	if state.Role != "state" || state.TotalBytes != 4096000 || state.FreeBytes != 1638400 || state.AvailableBytes != 1024000 || state.UsedBytes != 2457600 || state.FSType != "f2fs" {
		t.Fatalf("state: %+v", state)
	}
	if root.Role != "root" || root.Path != "/" || root.FSType != "ext4" {
		t.Fatalf("root: %+v", root)
	}
	if r.Metrics["flash_fs_type"] != "f2fs" || r.Metrics["flash_free_bytes"] != uint64(1024000) || r.Metrics["flash_used_percent"] != float64(75) {
		t.Fatalf("legacy flash keys: %v", r.Metrics)
	}
	if e := r.EMMC; e == nil || e.Device != "mmcblk0" || *e.LifeTimeEstA != 2 || *e.LifeTimeEstB != 1 || *e.PreEOL != 1 {
		t.Fatalf("emmc: %+v", e)
	}

	// No mount table: the sizes are still real, the type is not known. No
	// state directory: only the root is reported. No life_time: no eMMC
	// section, whatever else is in that directory.
	delete(f.files, "/proc/self/mounts")
	delete(f.fs, "/var/lib/nassimhub")
	delete(f.files, "/sys/block/mmcblk0/device/life_time")
	r = NewCollector(f, (&fakeClock{at: epoch}).now).Sample()
	if len(r.Storage) != 1 || r.Storage[0].Role != "root" || r.Storage[0].FSType != "" {
		t.Fatalf("storage: %+v", r.Storage)
	}
	if r.EMMC != nil {
		t.Fatalf("emmc without life_time: %+v", r.EMMC)
	}
	for _, key := range []string{"flash_total_bytes", "flash_fs_type", "flash_used_percent"} {
		if _, ok := r.Metrics[key]; ok {
			t.Fatalf("legacy %s present without a state filesystem", key)
		}
	}
	f.files["/sys/block/mmcblk0/device/life_time"] = "garbage\n"
	if r := NewCollector(f, (&fakeClock{at: epoch}).now).Sample(); r.EMMC != nil {
		t.Fatal("unparseable life_time accepted")
	}
}

func TestInterfaceCounters(t *testing.T) {
	r := NewCollector(device(), (&fakeClock{at: epoch}).now).Sample()
	if len(r.Interfaces) != 2 {
		t.Fatalf("interfaces: %+v", r.Interfaces)
	}
	w := r.Interfaces[0]
	if w.Name != "wwan0" || w.RxBytes != 5000000 || w.RxPackets != 4000 || w.RxErrors != 2 || w.TxBytes != 1000000 || w.TxPackets != 3000 || w.TxErrors != 1 {
		t.Fatalf("wwan0: %+v", w)
	}
	legacy := r.Metrics["interfaces"].([]map[string]any)
	if len(legacy) != 2 || legacy[0]["name"] != "wwan0" || legacy[0]["rx_bytes"] != uint64(5000000) {
		t.Fatalf("legacy interfaces: %v", legacy)
	}
}

func TestProcessesAgentUptimeAndBootID(t *testing.T) {
	r := NewCollector(device(), (&fakeClock{at: epoch}).now).Sample()
	if r.ProcessCount != 3 || len(r.Processes) != 3 || r.Processes[0].Name != "nassimhub-agent" || r.Processes[0].RSSBytes != 12288<<10 || r.Processes[2].Name != "kthreadd" {
		t.Fatalf("processes: %d %+v", r.ProcessCount, r.Processes)
	}
	if r.ThreadCount == nil || *r.ThreadCount != 11 || r.Metrics["thread_count"] != 11 || r.ProcessScanTruncated {
		t.Fatalf("threads: %v", r.ThreadCount)
	}
	if r.Agent == nil || r.Agent.PID != 300 || *r.Agent.RSSBytes != 12288<<10 {
		t.Fatalf("agent: %+v", r.Agent)
	}
	if r.UptimeSeconds != 86400.25 || r.BootID != "00000000-0000-4000-8000-000000000001" {
		t.Fatalf("uptime %v boot id %q", r.UptimeSeconds, r.BootID)
	}
}

func TestServingCellFromRadioFile(t *testing.T) {
	f, clock := device(), &fakeClock{at: epoch}
	c := NewCollector(f, clock.now)
	if r := c.Sample(); r.Cell != nil || r.Metrics["cellular_radio"] != nil {
		t.Fatalf("cell without a radio report: %+v", r.Cell)
	}
	setCell(f, epoch.Add(-30*time.Second))
	r := c.Sample()
	cell := r.Cell
	if cell == nil || cell.Band != "B3" || *cell.EARFCN != 1300 || *cell.PCI != 101 || *cell.TAC != 1 || *cell.CellID != 257 || !cell.ObservedAt.Equal(epoch.Add(-30*time.Second)) {
		t.Fatalf("cell: %+v", cell)
	}
	legacy := r.Metrics["cellular_radio"].(map[string]any)
	if legacy["band"] != "B3" || legacy["tac_hex"] != "1" || legacy["cell_id_hex"] != "101" || legacy["frequency_mhz"] != float64(1815) {
		t.Fatalf("legacy cell: %v", legacy)
	}
	// Nothing reported a bandwidth, so no form of the document has one.
	if data, _ := json.Marshal(r); strings.Contains(string(data), "bandwidth") {
		t.Fatalf("bandwidth invented: %s", data)
	}
	// A report the timer stopped refreshing is not the serving cell any more.
	clock.at = epoch.Add(2 * time.Minute)
	if r := c.Sample(); r.Cell != nil || r.Metrics["cellular_radio"] != nil {
		t.Fatal("stale radio report presented as current")
	}
	// Nor is one dated far in the future: the clock moved, so its age is unknown.
	f.times[radioMetricsFile] = clock.at.Add(time.Hour)
	if r := c.Sample(); r.Cell != nil {
		t.Fatal("radio report from the future presented as current")
	}
	f.times[radioMetricsFile] = clock.at
	if r := c.Sample(); r.Cell == nil {
		t.Fatal("fresh radio report dropped")
	}
	f.files[radioMetricsFile] = strings.Repeat("pci=1\n", 2000)
	if r := c.Sample(); r.Cell != nil {
		t.Fatal("oversized radio file accepted")
	}
	f.files[radioMetricsFile] = "pci=999\nband=invalid\nearfcn=bad\n"
	if r := c.Sample(); r.Cell != nil {
		t.Fatalf("out-of-range fields made a cell: %+v", r.Cell)
	}
}

func TestSampleNeedsCPUCounters(t *testing.T) {
	f := device()
	delete(f.files, "/proc/stat")
	if NewCollector(f, (&fakeClock{at: epoch}).now).Sample() != nil {
		t.Fatal("a sample without procfs")
	}
}

// expectedReads is the cost of one steady-state tick on the fixture device,
// spelled out so that adding a read is a visible decision:
//
//	7  /proc: stat, meminfo, uptime, loadavg, net/dev, self/mounts, readdir
//	2  /proc/self: stat, status
//	3  one status per process
//	2  cpu present, online
//	3  scaling_cur_freq per online core
//	5  thermal readdir + temp of four answering zones
//	1  temp of the zone that does not answer
//	2  statfs: state, root
//	2  eMMC life_time, pre_eol_info
//	2  radio file mtime + contents
const expectedReads = 7 + 2 + 3 + 2 + 3 + 5 + 1 + 2 + 2 + 2

func TestReadsPerTickAreBounded(t *testing.T) {
	f, clock := device(), &fakeClock{at: epoch}
	setCell(f, epoch)
	c := NewCollector(f, clock.now)
	c.Sample() // The first tick also reads what is cached: boot id, cpuinfo, zone types, frequency limits.
	first := f.reads
	for tick := 0; tick < 3; tick++ {
		before := f.reads
		clock.at = clock.at.Add(2 * time.Second)
		c.Sample()
		if got := f.reads - before; got != expectedReads {
			t.Fatalf("tick %d made %d reads, want %d", tick, got, expectedReads)
		}
	}
	if first <= expectedReads || first > expectedReads+16 {
		t.Fatalf("first tick made %d reads", first)
	}

	// A hostile or broken system: thousands of processes, zones, cores and
	// interfaces. The tick still costs a fixed amount.
	var pids, zones []string
	var net strings.Builder
	stat := "cpu  1 0 1 1 0 0 0 0 0 0\n"
	for i := 1; i <= 6000; i++ {
		pids = append(pids, fmt.Sprint(i))
		f.files[fmt.Sprintf("/proc/%d/status", i)] = status("p", i, 1)
		zones = append(zones, fmt.Sprintf("thermal_zone%d", i))
		fmt.Fprintf(&net, " eth%d: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n", i)
		if i < 200 {
			stat += fmt.Sprintf("cpu%d 1 0 1 1 0 0 0 0 0 0\n", i)
		}
	}
	f.dirs["/proc"], f.dirs["/sys/class/thermal"] = pids, zones
	f.files["/proc/net/dev"], f.files["/proc/stat"] = net.String(), stat
	f.files["/sys/devices/system/cpu/present"], f.files["/sys/devices/system/cpu/online"] = "0-4095\n", "0-4095\n"
	limit := 16 + maxProcessScan + 4*maxCores + 2*maxZones
	before := f.reads
	r := c.Sample()
	if got := f.reads - before; got > limit {
		t.Fatalf("%d reads in one tick, limit %d", got, limit)
	}
	if !r.ProcessScanTruncated || r.ThreadCount != nil || len(r.Processes) != topProcesses {
		t.Fatalf("truncated scan not marked: truncated=%v threads=%v processes=%d", r.ProcessScanTruncated, r.ThreadCount, len(r.Processes))
	}
	if len(r.CPU.Cores) > maxCores || len(r.Interfaces) > maxInterfaces || len(r.ThermalZones) > maxZones {
		t.Fatalf("unbounded lists: %d cores %d interfaces %d zones", len(r.CPU.Cores), len(r.Interfaces), len(r.ThermalZones))
	}
}

func TestSamplerServesFromMemoryAndIdles(t *testing.T) {
	f, clock := device(), &fakeClock{at: epoch}
	s := NewSampler(NewCollector(f, clock.now))
	s.wait = 0 // No goroutine in this test; steps are driven by hand.

	// Nobody has asked yet: the tick reads nothing.
	if s.step(false) || f.reads != 0 {
		t.Fatalf("sampled with no reader (%d reads)", f.reads)
	}
	if s.Snapshot() != nil {
		t.Fatal("snapshot before any sample")
	}
	if !s.step(false) {
		t.Fatal("did not sample after a reader asked")
	}
	reads := f.reads
	first := s.Snapshot()
	for i := 0; i < 100; i++ {
		if s.Snapshot() != first {
			t.Fatal("snapshot changed between ticks")
		}
	}
	if first == nil || f.reads != reads {
		t.Fatalf("requests read the filesystem: %d reads for 100 requests", f.reads-reads)
	}

	// A snapshot the sampler stopped refreshing is not served as current.
	clock.at = epoch.Add(staleAfter + time.Second)
	if s.Snapshot() != nil {
		t.Fatal("stale snapshot served")
	}
	// That request counts as demand, so the next tick samples again...
	if !s.step(false) || s.Snapshot() == nil {
		t.Fatal("did not resume after a reader came back")
	}
	// ...and once readers have been gone long enough, ticks cost nothing.
	clock.at = clock.at.Add(idleAfter + time.Second)
	reads = f.reads
	if s.step(false) || f.reads != reads {
		t.Fatal("kept sampling with no reader")
	}
}

func TestSamplerWakesForAWaitingReader(t *testing.T) {
	f := device()
	s := NewSampler(NewCollector(f, nil))
	s.interval, s.wait = time.Hour, 5*time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	// With an hour between ticks only the wake can have produced this.
	if r := s.Snapshot(); r == nil || r.ProcessCount != 3 {
		t.Fatalf("first reader got %+v", r)
	}
}

func TestUnsupportedPlatformHasNoSnapshot(t *testing.T) {
	ok, reason := Supported()
	if src, _ := platformSource(); (src != nil) != ok || (!ok && reason == "") {
		t.Fatalf("supported=%v reason=%q", ok, reason)
	}
}

func TestSnapshotJSONKeysAreStable(t *testing.T) {
	f := device()
	setCell(f, epoch)
	data, err := json.Marshal(NewCollector(f, (&fakeClock{at: epoch}).now).Sample())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for key := range doc {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	want := "agent boot_id cell cpu cpu_percent emmc interfaces memory memory_available_bytes memory_total_bytes metrics observed_at process_count processes storage thermal_zones thread_count uptime_seconds"
	if strings.Join(keys, " ") != want {
		t.Fatalf("keys:\n got %s\nwant %s", strings.Join(keys, " "), want)
	}
}

func BenchmarkSample(b *testing.B) {
	f, clock := device(), &fakeClock{at: epoch}
	for i := 4; i < 120; i++ {
		f.dirs["/proc"] = append(f.dirs["/proc"], fmt.Sprint(i))
		f.files[fmt.Sprintf("/proc/%d/status", i)] = status("worker", 1024+i, 2)
	}
	c := NewCollector(f, clock.now)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		clock.at = clock.at.Add(2 * time.Second)
		c.Sample()
	}
	b.ReportMetric(float64(f.reads)/float64(b.N), "reads/op")
}
