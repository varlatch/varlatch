// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Disk is the record G9a keeps of the disk it ran on: the verdict holds for
// that class of disk only. Fields the system does not expose are empty.
type Disk struct {
	Dir        string `json:"dir"`
	MountPoint string `json:"mountPoint,omitempty"`
	Source     string `json:"source,omitempty"`
	FSType     string `json:"fsType,omitempty"`
	Options    string `json:"options,omitempty"`
	// Device is the block device (major:minor) and what sysfs says of it;
	// for a device mapper (encryption, LVM) the devices under it.
	Device     string   `json:"device,omitempty"`
	DevName    string   `json:"devName,omitempty"`
	DMName     string   `json:"dmName,omitempty"`
	Slaves     []string `json:"slaves,omitempty"`
	Model      string   `json:"model,omitempty"`
	Rotational string   `json:"rotational,omitempty"`
	Note       string   `json:"note,omitempty"`
}

// MemoryEvents are the cgroup's memory.events counters G9 requires to stay
// at zero, and memory.current (page cache included; reported only).
type MemoryEvents struct {
	High    int64 `json:"high,omitempty"`
	Max     int64 `json:"max,omitempty"`
	OOM     int64 `json:"oom,omitempty"`
	OOMKill int64 `json:"oomKill,omitempty"`
	Current int64 `json:"currentBytes,omitempty"`
}

// Cgroup is the memory limits the run was under, as G9 requires them
// (memory.max 1 GiB, memory.swap.max 0), and its CPU limit (cpu.max, read
// once; reported only, ADR-0059 amendment 4).
type Cgroup struct {
	Path        string `json:"path,omitempty"`
	MemoryMax   string `json:"memoryMax,omitempty"`
	SwapMax     string `json:"swapMax,omitempty"`
	Note        string `json:"note,omitempty"`
	CPUMax      string `json:"cpuMax,omitempty"`
	CPUNote     string `json:"cpuNote,omitempty"`
	statPath    string
	usablePath  bool
	cpuStatPath string
}

// CPUStat is the part of the cgroup's cpu.stat G9a records. Throttling is
// false when the file has no throttling counters (the cpu controller is not
// enabled for the cgroup); the counters are then 0.
type CPUStat struct {
	UsageUs     int64 `json:"usageUs"`
	NrPeriods   int64 `json:"nrPeriods"`
	NrThrottled int64 `json:"nrThrottled"`
	ThrottledUs int64 `json:"throttledUs"`
	Throttling  bool  `json:"throttling"`
}

// parseCPUStat reads cpu.stat's "key value" lines.
func parseCPUStat(text string) (CPUStat, error) {
	var c CPUStat
	seen, usage := 0, false
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		var dst *int64
		switch k {
		case "usage_usec":
			dst = &c.UsageUs
		case "nr_periods":
			dst = &c.NrPeriods
		case "nr_throttled":
			dst = &c.NrThrottled
		case "throttled_usec":
			dst = &c.ThrottledUs
		default:
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return CPUStat{}, fmt.Errorf("cpu.stat %s: %w", k, err)
		}
		*dst = n
		if k == "usage_usec" {
			usage = true
		} else {
			seen++
		}
	}
	if seen == 0 && !usage {
		return CPUStat{}, errors.New("cpu.stat has none of usage_usec, nr_periods, nr_throttled, throttled_usec")
	}
	c.Throttling = seen == 3
	return c, nil
}

// cpuLimit describes cpu.max ("$MAX $PERIOD", or "max $PERIOD" for none).
func cpuLimit(cpuMax string) string {
	f := strings.Fields(cpuMax)
	switch {
	case cpuMax == "":
		return "not recorded"
	case len(f) >= 1 && f[0] == "max":
		return "no limit (cpu.max " + strconv.Quote(cpuMax) + ")"
	case len(f) == 2:
		quota, err1 := strconv.ParseFloat(f[0], 64)
		period, err2 := strconv.ParseFloat(f[1], 64)
		if err1 == nil && err2 == nil && period > 0 {
			return fmt.Sprintf("%.2f CPU (cpu.max %q)", quota/period, cpuMax)
		}
	}
	return "cpu.max " + strconv.Quote(cpuMax)
}
