// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package g9a

import "errors"

func describeDisk(dir string) Disk {
	return Disk{Dir: dir, Note: "disk details are read on Linux only"}
}

func ownCgroup() Cgroup { return Cgroup{Note: "cgroups are Linux only"} }

func (c Cgroup) anonBytes() (int64, error) { return 0, errors.New("no cgroup memory: " + c.Note) }

func (c Cgroup) memoryEvents() (MemoryEvents, error) {
	return MemoryEvents{}, errors.New("no cgroup memory: " + c.Note)
}

func rssBytes() int64 { return 0 }
