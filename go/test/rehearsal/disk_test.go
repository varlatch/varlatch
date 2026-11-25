// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// A copy too large for the host's memory: the same run (VL_RH_MEMORY=1) on a
// throwaway encrypted disk of the operator's, ext4 on dm-crypt plain over a loop
// file, whose key was never anywhere but in the kernel (the B6 kit's b6-env.sh).
// What this checks is what the kernel says of the mount a path is on, never a
// setting: the mapping by its name and its kind (a uuid cryptsetup gives a plain
// mapping), the one loop device under it and that one's file, the cipher, and that
// no discard goes through. Whether the key is anywhere else, the kernel does not
// know: that is b6-env.sh's to keep.
const (
	cryptName  = "vl-rh-b6-crypt"
	cryptImage = "/srv/vl-rh-b6-crypt.img"
)

// mount is one of /proc/self/mountinfo's.
type mount struct {
	device, point, fstype, source string
	options                       []string
}

// mountOf is the mount a path is on: of those it is below, the last one made
// with the longest place. The path is one without links.
func mountOf(mountinfo, path string) (mount, error) {
	var on mount
	for _, l := range strings.Split(mountinfo, "\n") {
		left, right, ok := strings.Cut(l, " - ")
		f, g := strings.Fields(left), strings.Fields(right)
		if !ok || len(f) < 6 || len(g) < 3 {
			continue
		}
		point := unescapeMount.Replace(f[4])
		if path != point && !strings.HasPrefix(path, strings.TrimSuffix(point, "/")+"/") || len(point) < len(on.point) {
			continue
		}
		on = mount{device: f[2], point: point, fstype: g[0], source: g[1], options: append(strings.Split(f[5], ","), strings.Split(g[2], ",")...)}
	}
	if on.point == "" {
		return on, fmt.Errorf("no mount holds %s", path)
	}
	return on, nil
}

var unescapeMount = strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)

// onCryptDisk is nil when path (or the nearest directory above it) is on the
// crypt disk. root is "/" (a test's own tree), table what `dmsetup table` says.
func onCryptDisk(root, path string, table func(name string) (string, error)) error {
	for {
		p, err := filepath.EvalSymlinks(path)
		if err == nil {
			path = p
			break
		}
		if !errors.Is(err, os.ErrNotExist) || path == "/" {
			return err
		}
		path = filepath.Dir(path)
	}
	info, err := os.ReadFile(filepath.Join(root, "proc/self/mountinfo"))
	if err != nil {
		return err
	}
	m, err := mountOf(string(info), path)
	if err != nil {
		return err
	}
	switch {
	case m.fstype != "ext4":
		return fmt.Errorf("it is on %s (%s)", m.source, m.fstype)
	case !slices.Contains(m.options, "nodev") || !slices.Contains(m.options, "nosuid") || slices.Contains(m.options, "discard"):
		return fmt.Errorf("%s is mounted %s, not nodev, nosuid and without discard", m.point, strings.Join(m.options, ","))
	}
	read := func(p string) string {
		b, _ := os.ReadFile(filepath.Join(root, p))
		return strings.TrimSpace(string(b))
	}
	dev := "sys/dev/block/" + m.device
	if name, id := read(dev+"/dm/name"), read(dev+"/dm/uuid"); name != cryptName || id != "CRYPT-PLAIN-"+cryptName {
		return fmt.Errorf("%s is on the device %s (%q, %q), not the mapping %s", m.point, m.device, name, id, cryptName)
	}
	under, err := os.ReadDir(filepath.Join(root, dev, "slaves"))
	if err != nil || len(under) != 1 || !strings.HasPrefix(under[0].Name(), "loop") {
		return fmt.Errorf("the mapping %s is not over one loop device (%v)", cryptName, err)
	}
	if file := read("sys/block/" + under[0].Name() + "/loop/backing_file"); file != cryptImage {
		return fmt.Errorf("the mapping %s is over %q, not %s", cryptName, file, cryptImage)
	}
	said, err := table(cryptName)
	f := strings.Fields(said)
	switch {
	case err != nil:
		return fmt.Errorf("dmsetup table: %w", err)
	case strings.Count(strings.TrimSpace(said), "\n") != 0 || len(f) < 8 || f[2] != "crypt" || f[3] != "aes-xts-plain64" || len(f[4]) != 128:
		return errors.New("the mapping is not one target, crypt aes-xts-plain64 with a key of 512 bit")
	case slices.Contains(f[8:], "allow_discards"):
		return errors.New("the mapping lets discards through")
	}
	return nil
}

// dmsetupTable never shows the key: without --showkeys it is zeros.
func dmsetupTable(name string) (string, error) {
	b, err := exec.Command("dmsetup", "table", name).Output()
	return string(b), err
}

// memoryPlace says how a path of a run in memory is kept off the host's disks:
// "tmpfs" or "crypt". On a workstation, whose data is synthetic and which has no
// such disk, VL_RH_MEMORY_DISK=unchecked takes any path as the crypt disk.
func memoryPlace(path string, box bool) (string, error) {
	ok, err := onTmpfs(path)
	switch {
	case err != nil:
		return "", err
	case ok:
		return "tmpfs", nil
	case !box && os.Getenv("VL_RH_MEMORY_DISK") == "unchecked":
		return "crypt", nil
	}
	if err := onCryptDisk("/", path, dmsetupTable); err != nil {
		return "", err
	}
	return "crypt", nil
}
