package systemstats

import "testing"

func TestCPUDoesNotDoubleCountGuest(t *testing.T) {
	total, idle, err := cpuTicks("cpu 100 10 20 200 30 4 5 6 70 8\n")
	if err != nil || total != 375 || idle != 230 {
		t.Fatalf("total=%d idle=%d err=%v", total, idle, err)
	}
	if _, _, err := cpuTicks("cpu 1 broken 3 4"); err == nil {
		t.Fatal("invalid counter accepted")
	}
}
func TestMemoryUsesAvailable(t *testing.T) {
	total, available := memory("MemTotal: 1024 kB\nMemFree: 10 kB\nMemAvailable: 256 kB\n")
	if total != 1048576 || available != 262144 {
		t.Fatalf("%d %d", total, available)
	}
}
