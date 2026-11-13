// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// describeDisk finds the mount holding dir in /proc/self/mountinfo and the
// block device under it in /sys/dev/block.
func describeDisk(dir string) Disk {
	d := Disk{Dir: dir}
	abs, err := filepath.Abs(dir)
	if err == nil {
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			abs = real
		}
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		d.Note = err.Error()
		return d
	}
	defer f.Close()
	best := -1
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// id parent major:minor root mountpoint options ... - fstype source superoptions
		pre, post, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		a, b := strings.Fields(pre), strings.Fields(post)
		if len(a) < 6 || len(b) < 2 {
			continue
		}
		mp := unescapeMount(a[4])
		if !within(abs, mp) || len(mp) <= best {
			continue
		}
		best = len(mp)
		d.MountPoint, d.Device, d.Options = mp, a[2], a[5]
		d.FSType, d.Source = b[0], unescapeMount(b[1])
		if len(b) > 2 {
			d.Options += " " + b[2]
		}
	}
	if d.Device == "" {
		d.Note = "no mount found for " + abs
		return d
	}
	sys := "/sys/dev/block/" + d.Device
	d.DevName = ueventValue(sys+"/uevent", "DEVNAME")
	d.DMName = readTrim(sys + "/dm/name")
	if entries, err := os.ReadDir(sys + "/slaves"); err == nil {
		for _, e := range entries {
			d.Slaves = append(d.Slaves, e.Name())
		}
	}
	// A partition's queue and model belong to its disk.
	disk := sys
	if _, err := os.Stat(sys + "/partition"); err == nil {
		disk = sys + "/.."
	}
	d.Rotational = readTrim(disk + "/queue/rotational")
	d.Model = readTrim(disk + "/device/model")
	return d
}

func within(path, mount string) bool {
	return mount == "/" || path == mount || strings.HasPrefix(path, strings.TrimSuffix(mount, "/")+"/")
}

// unescapeMount undoes mountinfo's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func ueventValue(path, key string) string {
	for _, line := range strings.Split(readTrim(path), "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return v
		}
	}
	return ""
}

// ownCgroup finds this process's cgroup v2 directory and its limits.
func ownCgroup() Cgroup {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return Cgroup{Note: err.Error()}
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if rel, ok := strings.CutPrefix(line, "0::"); ok {
			dir := filepath.Join("/sys/fs/cgroup", rel)
			c := Cgroup{Path: rel, MemoryMax: readTrim(dir + "/memory.max"), SwapMax: readTrim(dir + "/memory.swap.max"), statPath: dir + "/memory.stat"}
			if _, err := os.Stat(c.statPath); err != nil {
				c.Note = "no memory.stat (memory controller not enabled here)"
			} else {
				c.usablePath = true
			}
			return c
		}
	}
	return Cgroup{Note: "not in a cgroup v2 hierarchy"}
}

// anonBytes is the cgroup's anon memory (memory.stat), the measure G9 uses.
func (c Cgroup) anonBytes() (int64, error) {
	if !c.usablePath {
		return 0, fmt.Errorf("no cgroup memory: %s", c.Note)
	}
	f, err := os.Open(c.statPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "anon "); ok {
			return strconv.ParseInt(v, 10, 64)
		}
	}
	return 0, fmt.Errorf("%s has no anon line", c.statPath)
}

// memoryEvents reads the cgroup's memory.events counters that G9 requires
// to stay at zero (high, max, oom, oom_kill), and memory.current.
func (c Cgroup) memoryEvents() (MemoryEvents, error) {
	if !c.usablePath {
		return MemoryEvents{}, fmt.Errorf("no cgroup memory: %s", c.Note)
	}
	dir := filepath.Dir(c.statPath)
	var m MemoryEvents
	b, err := os.ReadFile(dir + "/memory.events")
	if err != nil {
		return m, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, _ := strings.Cut(line, " ")
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "high":
			m.High = n
		case "max":
			m.Max = n
		case "oom":
			m.OOM = n
		case "oom_kill":
			m.OOMKill = n
		}
	}
	m.Current, err = strconv.ParseInt(readTrim(dir+"/memory.current"), 10, 64)
	return m, err
}

// rssBytes is this process's resident set (VmRSS), reported alongside.
func rssBytes() int64 {
	for _, line := range strings.Split(readTrim("/proc/self/status"), "\n") {
		if v, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			kb, _ := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "kB")), 10, 64)
			return kb << 10
		}
	}
	return 0
}
