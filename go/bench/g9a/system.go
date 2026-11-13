// SPDX-License-Identifier: Apache-2.0

package g9a

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
// (memory.max 1 GiB, memory.swap.max 0).
type Cgroup struct {
	Path       string `json:"path,omitempty"`
	MemoryMax  string `json:"memoryMax,omitempty"`
	SwapMax    string `json:"swapMax,omitempty"`
	Note       string `json:"note,omitempty"`
	statPath   string
	usablePath bool
}
