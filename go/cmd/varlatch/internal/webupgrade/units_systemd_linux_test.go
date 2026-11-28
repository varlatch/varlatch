// SPDX-License-Identifier: Apache-2.0

package webupgrade

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// serviceProperties are the [Service] settings of a unit's file but its
// ExecStart, as systemd-run takes them.
func serviceProperties(t *testing.T, unit string) []string {
	t.Helper()
	f := UnitFile(unit, paths)
	_, service, ok := strings.Cut(f, "\n[Service]\n")
	if !ok {
		t.Fatalf("%s has no [Service]:\n%s", unit, f)
	}
	service, _, _ = strings.Cut(service, "\n\n")
	var props []string
	for _, line := range strings.Split(strings.TrimSpace(service), "\n") {
		if !strings.HasPrefix(line, "ExecStart=") {
			props = append(props, line)
		}
	}
	return props
}

// The helper's units let varlatchd admin, run as root, become the data
// directory's owner: each unit's [Service] settings, as the file has them,
// on this machine's systemd (systemd-run), run `varlatchd admin schema status`
// (the helper's first call, which becomes the owner), several times. A
// sandbox varlatchd cannot drop privileges in (on Ubuntu 26.04,
// NoNewPrivileges with the system call filters) records nothing and takes no
// request, and TestUnitFiles, which reads the text, cannot see it. The
// fixture is in a temporary directory below /var/lib, not /tmp, which the
// unit's PrivateTmp hides. A disposable runner's only: the transient units
// run on this machine's systemd, and CacheDirectory makes
// /var/cache/varlatch-upgrade (go.yml's root tests run it on the
// GitHub-hosted runner).
func TestUnitSandboxLetsVarlatchdDrop(t *testing.T) {
	if os.Getenv("VARLATCH_TEST_DISPOSABLE_ROOT") != "1" || os.Geteuid() != 0 {
		t.Skip("runs units on this machine's systemd as root: a disposable runner's only (VARLATCH_TEST_DISPOSABLE_ROOT=1, root)")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Fatalf("no systemd here (VARLATCH_TEST_DISPOSABLE_ROOT=1 says this is a disposable runner with one): %v", err)
	}
	const owner = 65534
	dir, err := os.MkdirTemp("/var/lib", "varlatch-unit-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// The way in is open to the owner, as /var/lib/varlatch's is.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	varlatchd := filepath.Join(dir, "varlatchd")
	build := exec.Command("go", "build", "-trimpath", "-o", varlatchd, "github.com/varlatch/varlatch/go/cmd/varlatchd")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build varlatchd: %v\n%s", err, out)
	}
	data, keys := filepath.Join(dir, "data"), filepath.Join(dir, "keys")
	for _, d := range []string{data, keys} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(data, owner, owner); err != nil {
		t.Fatal(err)
	}
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	if err := os.WriteFile(filepath.Join(keys, "root-kek"), []byte(hex.EncodeToString(kek)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "varlatchd.conf")
	if err := os.WriteFile(conf, []byte(fmt.Sprintf("listen = 127.0.0.1:0\ndata_dir = %s\nroot_kek_file = %s\nbackup_interval = off\n", data, filepath.Join(keys, "root-kek"))), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, unit := range []string{CheckServiceUnit, ServiceUnit, RecoverUnit} {
		args := []string{"--wait", "--pipe", "--quiet", "--collect"}
		for _, p := range serviceProperties(t, unit) {
			args = append(args, "--property="+p)
		}
		args = append(args, varlatchd, "admin", "schema", "status", "--json", "--config", conf)
		// The failure it guards against may depend on timing: more than once.
		for i := range 5 {
			cmd := exec.Command("systemd-run", args...)
			var stderr strings.Builder
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil || !strings.Contains(string(out), `"dataDir":"`+data+`"`) {
				t.Fatalf("%s's sandbox, run %d: varlatchd admin schema status as root: %v\nstdout: %s\nstderr: %s\nproperties: %q", unit, i+1, err, out, stderr.String(), serviceProperties(t, unit))
			}
		}
	}
	// It did become the owner: what it made in the data directory, if
	// anything, is the owner's.
	entries, err := os.ReadDir(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != owner {
			t.Errorf("%s in the data directory is not the owner's: %+v", e.Name(), info.Sys())
		}
	}
}
