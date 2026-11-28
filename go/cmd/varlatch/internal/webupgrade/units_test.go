// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// The units and their paths are a systemd host's: the helper never runs on
// Windows, whose file paths these are not.

package webupgrade

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/upgraderequest"
)

var paths = UnitPaths{Varlatch: "/usr/local/bin/varlatch", Config: "/etc/varlatch/varlatchd.conf", DataDir: "/var/lib/varlatch"}

// Every root unit is hardened, with the system call filters and without
// NoNewPrivileges (hardening says why; TestUnitSandboxLetsVarlatchdDrop
// runs it); each runs the CLI with the configuration; the path unit watches
// the request file in the data directory; the recovery comes after
// varlatchd (it starts it); the timer is Decision 1's cadence.
func TestUnitFiles(t *testing.T) {
	for _, u := range []string{CheckServiceUnit, ServiceUnit, RecoverUnit} {
		f := UnitFile(u, paths)
		for _, want := range []string{"Type=oneshot", "User=root", "PrivateTmp=yes", "ProtectHome=yes", "LimitCORE=0", "CacheDirectory=varlatch-upgrade",
			"ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectKernelTunables=yes", "ProtectClock=yes", "ProtectHostname=yes",
			"RestrictRealtime=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes", "KeyringMode=private",
			"ExecStart=/usr/local/bin/varlatch upgrade --"} {
			if !strings.Contains(f, want) {
				t.Errorf("%s has no %q:\n%s", u, want, f)
			}
		}
		if strings.Contains(f, "NoNewPrivileges") {
			t.Errorf("%s sets NoNewPrivileges, with which varlatchd admin cannot become the data directory's owner on some hosts:\n%s", u, f)
		}
		if !strings.Contains(f, " --config /etc/varlatch/varlatchd.conf\n") {
			t.Errorf("%s names no configuration", u)
		}
	}
	for u, want := range map[string]string{
		CheckServiceUnit: "upgrade --check --config",
		ServiceUnit:      "upgrade --from-request --config",
		RecoverUnit:      "upgrade --recover --config",
		PathUnit:         "PathExists=/var/lib/varlatch/upgrade-request/request.json\nUnit=varlatch-upgrade.service",
		CheckTimerUnit:   "OnCalendar=daily\nRandomizedDelaySec=1h\nPersistent=true",
	} {
		if !strings.Contains(UnitFile(u, paths), want) {
			t.Errorf("%s has no %q", u, want)
		}
	}
	if f := UnitFile(RecoverUnit, paths); !strings.Contains(f, "After=network-online.target varlatchd.service") || strings.Contains(f, "Before=") || !strings.Contains(f, "WantedBy=multi-user.target") {
		t.Errorf("the recovery's order:\n%s", f)
	}
	// The request's service sets its own start limit, which a run that
	// waits RetryDelay each time stays under, in [Unit] where systemd reads
	// it.
	f := UnitFile(ServiceUnit, paths)
	if !strings.Contains(f, "StartLimitIntervalSec=10min\nStartLimitBurst=20\n\n[Service]") {
		t.Errorf("the service's start limit:\n%s", f)
	}
	if RetryDelay*20 <= 10*time.Minute {
		t.Errorf("a run every %s would reach the start limit", RetryDelay)
	}
}

type fakeHost struct {
	files   map[string]string
	dirs    []string
	calls   []string
	same    bool
	locked  bool
	held    int
	failing string
	// writeFailing is a path whose write fails.
	writeFailing string
	states       map[string][2]string
}

func (h *fakeHost) WriteFile(path string, data []byte, _ fs.FileMode) error {
	if path == h.writeFailing {
		return errors.New("disk full")
	}
	h.calls = append(h.calls, "write "+filepath.Base(path))
	h.files[path] = string(data)
	return nil
}
func (h *fakeHost) Remove(path string) error {
	if _, ok := h.files[path]; !ok {
		return fs.ErrNotExist
	}
	delete(h.files, path)
	return nil
}
func (h *fakeHost) MkdirRoot(path string, _ fs.FileMode) error {
	h.dirs = append(h.dirs, path)
	return nil
}
func (h *fakeHost) SameFileSystem(string, string) (bool, error) { return h.same, nil }
func (h *fakeHost) Systemctl(_ context.Context, args ...string) error {
	call := strings.Join(args, " ")
	h.calls = append(h.calls, call)
	if call == h.failing {
		return errors.New("failed")
	}
	return nil
}
func (h *fakeHost) State(_ context.Context, unit string) (string, string, error) {
	s, ok := h.states[unit]
	if !ok {
		return "inactive", "success", nil
	}
	return s[0], s[1], nil
}
func (h *fakeHost) Lock(string) (func(), bool, error) {
	if h.locked {
		return nil, false, nil
	}
	h.held++
	return func() { h.held-- }, true, nil
}

var (
	conf      = "/etc/varlatch/web-upgrade.conf"
	unitFiles = func() []string {
		var out []string
		for _, u := range Units {
			out = append(out, "write "+u)
		}
		return out
	}()
	undo = []string{"disable --now " + PathUnit + " " + CheckTimerUnit, "disable " + RecoverUnit, "daemon-reload"}
)

func TestEnableAndDisable(t *testing.T) {
	ctx, said := context.Background(), func(string) {}
	// Not on the data directory's file system: nothing is installed.
	h := &fakeHost{files: map[string]string{}}
	if err := Enable(ctx, h, paths, "/etc/varlatch", TakenDir, said); err == nil || !strings.Contains(err.Error(), "different file systems") || len(h.files) != 0 || len(h.calls) != 0 {
		t.Fatalf("another file system: %v %v %v", err, h.files, h.calls)
	}
	// While a run of the helper holds its lock, nothing is enabled.
	h.same, h.locked = true, true
	if err := Enable(ctx, h, paths, "/etc/varlatch", TakenDir, said); !errors.Is(err, ErrRunning) || len(h.files) != 0 || len(h.calls) != 0 {
		t.Fatalf("while a run holds the lock: %v %v %v", err, h.files, h.calls)
	}
	h.locked, h.failing, h.dirs = false, "start "+CheckServiceUnit, nil
	if err := Enable(ctx, h, paths, "/etc/varlatch", TakenDir, said); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.dirs, []string{"/var/lib/varlatch-upgrade", TakenDir}) || h.held != 0 {
		t.Fatalf("the directories: %v (lock held %d)", h.dirs, h.held)
	}
	for _, u := range Units {
		if h.files[filepath.Join(UnitDir, u)] != UnitFile(u, paths) {
			t.Errorf("%s not installed", u)
		}
	}
	if on, err := upgraderequest.ParseConf([]byte(h.files[conf])); err != nil || !on {
		t.Fatalf("web-upgrade.conf: %v %v", on, err)
	}
	// web-upgrade.conf only once the units are enabled.
	want := append(slices.Clone(unitFiles), "daemon-reload", "enable "+RecoverUnit, "enable --now "+CheckTimerUnit+" "+PathUnit, "write web-upgrade.conf", "start "+CheckServiceUnit)
	if !slices.Equal(h.calls, want) {
		t.Fatalf("the steps: %v", h.calls)
	}
	// While a run holds the lock, nothing is disabled.
	h.locked, h.calls = true, nil
	if err := Disable(ctx, h, "/etc/varlatch", TakenDir, said); !errors.Is(err, ErrRunning) || len(h.calls) != 0 {
		t.Fatalf("while running: %v %v", err, h.calls)
	}
	h.locked = false
	if err := Disable(ctx, h, "/etc/varlatch", TakenDir, said); err != nil {
		t.Fatal(err)
	}
	// The recovery is disabled without --now: one that runs is not stopped.
	if len(h.files) != 0 || !slices.Equal(h.calls, undo) || h.held != 0 {
		t.Fatalf("after disable: %v %v", h.files, h.calls)
	}
	// Twice is no error.
	if err := Disable(ctx, h, "/etc/varlatch", TakenDir, said); err != nil {
		t.Fatal(err)
	}
}

// An enable that fails part way removes what it installed, web-upgrade.conf
// first: the host never says it accepts requests that no unit takes.
func TestEnableRollsBack(t *testing.T) {
	ctx, said := context.Background(), func(string) {}
	for _, c := range []struct {
		name, failing, writeFailing string
	}{
		{"daemon-reload", "daemon-reload", ""},
		{"the recovery", "enable " + RecoverUnit, ""},
		{"the path unit", "enable --now " + CheckTimerUnit + " " + PathUnit, ""},
		{"web-upgrade.conf", "", conf},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Enabled before: what failed now leaves it off, not half on.
			h := &fakeHost{files: map[string]string{conf: string(upgraderequest.EncodeConf(true))}, same: true, failing: c.failing, writeFailing: c.writeFailing}
			err := Enable(ctx, h, paths, "/etc/varlatch", TakenDir, said)
			if !errors.Is(err, ErrLeftOff) || len(h.files) != 0 || h.held != 0 {
				t.Fatalf("%v; left %v (lock held %d)", err, h.files, h.held)
			}
			if !slices.Equal(h.calls[len(h.calls)-len(undo):], undo) {
				t.Fatalf("no undo: %v", h.calls)
			}
		})
	}
}

// Failed counts units that systemd failed for good, not a request's run
// that failed.
func TestFailed(t *testing.T) {
	ctx := context.Background()
	h := &fakeHost{states: map[string][2]string{ServiceUnit: {"failed", "exit-code"}}}
	if f := Failed(ctx, h); len(f) != 0 {
		t.Fatalf("a run that failed: %v", f)
	}
	h.states[ServiceUnit] = [2]string{"failed", "start-limit-hit"}
	h.states[PathUnit] = [2]string{"failed", "unit-start-limit-hit"}
	if f := Failed(ctx, h); !slices.Equal(f, []string{PathUnit, ServiceUnit}) {
		t.Fatalf("the start limit: %v", f)
	}
}
