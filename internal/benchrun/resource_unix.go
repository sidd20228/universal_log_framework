//go:build darwin || linux

package benchrun

import (
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type processResources struct {
	user   time.Duration
	system time.Duration
	maxRSS uint64
}

func readProcessResources() processResources {
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil {
		return processResources{}
	}
	rss := uint64(usage.Maxrss)
	if runtime.GOOS == "linux" {
		rss *= 1024
	}
	return processResources{user: timevalDuration(usage.Utime), system: timevalDuration(usage.Stime), maxRSS: rss}
}

func timevalDuration(value syscall.Timeval) time.Duration {
	return time.Duration(value.Sec)*time.Second + time.Duration(value.Usec)*time.Microsecond
}

func resourceDelta(before, after processResources, wall time.Duration) Resources {
	user := after.user - before.user
	system := after.system - before.system
	total := user + system
	result := Resources{UserCPUSeconds: user.Seconds(), SystemCPUSeconds: system.Seconds(), TotalCPUSeconds: total.Seconds(), PeakRSSBytes: after.maxRSS}
	if wall > 0 {
		result.ProcessCPUPercent = total.Seconds() / wall.Seconds() * 100
	}
	return result
}

func hardwareInfo() (string, uint64) {
	if runtime.GOOS == "darwin" {
		model := commandOutput(".", "sysctl", "-n", "machdep.cpu.brand_string")
		memory, _ := strconv.ParseUint(commandOutput(".", "sysctl", "-n", "hw.memsize"), 10, 64)
		return model, memory
	}
	model := "unknown"
	if contents, err := osReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(contents), "\n") {
			if key, value, found := strings.Cut(line, ":"); found && strings.TrimSpace(key) == "model name" {
				model = strings.TrimSpace(value)
				break
			}
		}
	}
	var memory uint64
	if contents, err := osReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(contents), "\n") {
			var kib uint64
			if _, err := fmtSscanf(line, "MemTotal: %d kB", &kib); err == nil {
				memory = kib * 1024
				break
			}
		}
	}
	return model, memory
}
