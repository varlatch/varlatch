// SPDX-License-Identifier: Apache-2.0

//go:build linux

package setup

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// TestPrepareTargetOnThisHost makes a migration's target on this host's
// systemd for real, then undoes it: the varlatch user (useradd, no
// supplementary group), /etc/varlatch root:varlatch 0750, the data
// directory varlatch's 0700, the configuration root:varlatch 0640 that
// varlatchd checked, the unit enabled and not started, no key; undone, all
// of it gone and the unit disabled. It changes the machine's users, /etc
// and systemd, so it runs only where go.yml runs it, on a disposable
// GitHub-hosted runner (VARLATCH_TEST_DISPOSABLE_ROOT=1, as root, with
// VARLATCH_TEST_VARLATCHD built), and refuses a host that has any of it.
func TestPrepareTargetOnThisHost(t *testing.T) {
	varlatchd := os.Getenv("VARLATCH_TEST_VARLATCHD")
	if os.Getenv("VARLATCH_TEST_DISPOSABLE_ROOT") != "1" || os.Geteuid() != 0 || varlatchd == "" {
		t.Skip("changes this machine's users, /etc and systemd: a disposable runner's only (VARLATCH_TEST_DISPOSABLE_ROOT=1, root, VARLATCH_TEST_VARLATCHD)")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("no systemd")
	}
	h := SystemHost{Varlatchd: varlatchd, Env: os.Environ()}
	if _, _, found, _ := h.LookupUser(User); found {
		t.Fatal("refusing: the varlatch user exists on this host")
	}
	for _, p := range []string{EtcDir, DataDir} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("refusing: %s exists on this host", p)
		}
	}
	// The unit, as install.sh --server installs it, when it is not there.
	if _, err := os.Stat(UnitFile); err != nil {
		_, file, _, _ := runtime.Caller(0)
		unit, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "install", "varlatchd.service"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(UnitFile, unit, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = os.Remove(UnitFile)
			_ = exec.Command("systemctl", "daemon-reload").Run()
		})
	}
	var made []string
	t.Cleanup(func() { _ = UndoTarget(h, made, nil) })
	_, err := PrepareTarget(context.Background(), Options{Host: h, Given: proxyAnswers()}, func(item string) error {
		made = append(made, item)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, found, err := h.LookupUser(User)
	if err != nil || !found {
		t.Fatalf("the user: %v %v", found, err)
	}
	if g, err := h.SupplementaryGroups(User); err != nil || len(g) != 0 {
		t.Errorf("the user's groups: %v %v", g, err)
	}
	owner := func(p string) (int, int, os.FileMode) {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		s := st.Sys().(*syscall.Stat_t)
		return int(s.Uid), int(s.Gid), st.Mode().Perm()
	}
	for _, c := range []struct {
		path     string
		uid, gid int
		mode     os.FileMode
	}{{EtcDir, 0, gid, 0o750}, {ConfigFile, 0, gid, 0o640}, {DataDir, uid, gid, 0o700}} {
		if u, g, m := owner(c.path); u != c.uid || g != c.gid || m != c.mode {
			t.Errorf("%s: %d:%d %o, want %d:%d %o", c.path, u, g, m, c.uid, c.gid, c.mode)
		}
	}
	for _, k := range []string{RootKEK, BackupKey} {
		if _, err := os.Stat(k); !os.IsNotExist(err) {
			t.Errorf("%s: %v; the keys are the source's, installed later", k, err)
		}
	}
	if out, _ := h.Systemctl("is-enabled", Unit); strings.TrimSpace(out) != "enabled" {
		t.Errorf("the unit is %q, want enabled", strings.TrimSpace(out))
	}
	if out, _ := h.Systemctl("is-active", Unit); strings.TrimSpace(out) == "active" {
		t.Error("the unit was started")
	}
	if err := UndoTarget(h, made, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, found, _ := h.LookupUser(User); found {
		t.Error("the user is left")
	}
	for _, p := range []string{EtcDir, DataDir} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s is left: %v", p, err)
		}
	}
	if out, _ := h.Systemctl("is-enabled", Unit); strings.TrimSpace(out) == "enabled" {
		t.Error("the unit is left enabled")
	}
	if _, err := user.LookupGroup(User); err == nil {
		t.Error("the varlatch group is left")
	}
	made = nil

	// login.defs' USERGROUPS_ENAB no: userdel leaves the user's own group,
	// which the undo removes too (useradd --user-group made it with the
	// user), so the target made again finds no group in its way.
	const defs = "/etc/login.defs"
	st, err := os.Stat(defs)
	if err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(defs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(defs, orig, st.Mode().Perm()) })
	edited := regexp.MustCompile(`(?m)^\s*USERGROUPS_ENAB\b.*$`).ReplaceAllString(string(orig), "")
	if err := os.WriteFile(defs, []byte(edited+"\nUSERGROUPS_ENAB no\n"), st.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	for round := 1; round <= 2; round++ {
		if _, err := PrepareTarget(context.Background(), Options{Host: h, Given: proxyAnswers()}, func(item string) error {
			made = append(made, item)
			return nil
		}); err != nil {
			t.Fatalf("USERGROUPS_ENAB no, round %d: %v", round, err)
		}
		if err := UndoTarget(h, made, nil); err != nil {
			t.Fatalf("USERGROUPS_ENAB no, round %d, the undo: %v", round, err)
		}
		made = nil
		if _, err := user.LookupGroup(User); err == nil {
			t.Errorf("USERGROUPS_ENAB no, round %d: the varlatch group is left", round)
		}
	}
}
