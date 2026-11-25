// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMountOf(t *testing.T) {
	const info = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 0:40 / /srv/vl-rh/b6 rw,nosuid,nodev - tmpfs vl-rh-b6 rw\n" +
		"3 2 252:0 / /srv/vl-rh/b6 rw,nosuid,nodev,noatime shared:395 - ext4 /dev/mapper/x rw\n4 1 0:50 / /srv/a\\040b rw - tmpfs t rw\nnot one\n"
	for path, want := range map[string]string{"/srv/vl-rh/b6/runs": "252:0", "/srv/vl-rh/b6": "252:0", "/srv/vl-rh/b6x": "8:1", "/": "8:1", "/srv/a b/c": "0:50"} {
		if m, err := mountOf(info, path); err != nil || m.device != want {
			t.Errorf("%s: %+v, %v; want %s", path, m, err, want)
		}
	}
	if _, err := mountOf("", "/x"); err == nil {
		t.Error("no mounts")
	}
}

func TestOnCryptDisk(t *testing.T) {
	const line = "109 33 252:0 / /BASE rw,nosuid,nodev,noatime shared:395 - ext4 /dev/mapper/vl-rh-b6-crypt rw\n"
	table := "0 131072 crypt aes-xts-plain64 " + strings.Repeat("0", 128) + " 0 7:0 0\n"
	base := t.TempDir()
	type world struct {
		line, name, uuid, slaves, file, table string
		err                                   error
	}
	good := world{line, "vl-rh-b6-crypt", "CRYPT-PLAIN-vl-rh-b6-crypt", "loop0", "/srv/vl-rh-b6-crypt.img", table, nil}
	for what, c := range map[string]struct {
		change func(*world)
		want   string
	}{
		"as the box says it":      {func(*world) {}, ""},
		"a disk":                  {func(w *world) { w.line = strings.Replace(line, "252:0", "8:1", 1) }, "not the mapping"},
		"a tmpfs":                 {func(w *world) { w.line = strings.Replace(line, "ext4", "tmpfs", 1) }, "(tmpfs)"},
		"devices":                 {func(w *world) { w.line = strings.Replace(line, ",nodev", "", 1) }, "nodev"},
		"discard":                 {func(w *world) { w.line = strings.Replace(line, "noatime", "noatime,discard", 1) }, "discard"},
		"another mapping":         {func(w *world) { w.name = "other" }, "not the mapping"},
		"LUKS":                    {func(w *world) { w.uuid = "CRYPT-LUKS2-1-vl-rh-b6-crypt" }, "not the mapping"},
		"not crypt":               {func(w *world) { w.uuid = "LVM-x" }, "not the mapping"},
		"over a disk":             {func(w *world) { w.slaves = "sda2" }, "one loop device"},
		"over two":                {func(w *world) { w.slaves = "loop0 loop1" }, "one loop device"},
		"over another file":       {func(w *world) { w.file = "/home/x.img" }, "/home/x.img"},
		"over a removed file":     {func(w *world) { w.file += " (deleted)" }, "deleted"},
		"another cipher":          {func(w *world) { w.table = strings.Replace(table, "aes-xts-plain64", "aes-cbc-plain64", 1) }, "aes-xts"},
		"a shorter key":           {func(w *world) { w.table = strings.Replace(table, strings.Repeat("0", 128), strings.Repeat("0", 64), 1) }, "512 bit"},
		"two targets":             {func(w *world) { w.table = table + table }, "one target"},
		"discards let through":    {func(w *world) { w.table = strings.TrimSpace(table) + " 1 allow_discards\n" }, "discards"},
		"dmsetup does not answer": {func(w *world) { w.err = errors.New("no") }, "dmsetup"},
	} {
		w := good
		c.change(&w)
		root := t.TempDir()
		write := func(p, text string) {
			t.Helper()
			p = filepath.Join(root, p)
			if err := errors.Join(os.MkdirAll(filepath.Dir(p), 0o700), os.WriteFile(p, []byte(text+"\n"), 0o600)); err != nil {
				t.Fatal(err)
			}
		}
		write("proc/self/mountinfo", "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"+strings.Replace(w.line, "/BASE", base, 1))
		write("sys/dev/block/252:0/dm/name", w.name)
		write("sys/dev/block/252:0/dm/uuid", w.uuid)
		for _, s := range strings.Fields(w.slaves) {
			write("sys/dev/block/252:0/slaves/"+s, "")
			write("sys/block/"+s+"/loop/backing_file", w.file)
		}
		err := onCryptDisk(root, filepath.Join(base, "not", "yet"), func(string) (string, error) { return w.table, w.err })
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v, want %q", what, err, c.want)
		}
	}
	// The box never takes it unchecked.
	t.Setenv("VL_RH_MEMORY_DISK", "unchecked")
	if place, err := memoryPlace("/proc", true); err == nil {
		t.Errorf("unchecked on the box: %s", place)
	}
	if place, err := memoryPlace("/proc", false); err != nil || place != "crypt" {
		t.Errorf("unchecked on a workstation: %s, %v", place, err)
	}
}
