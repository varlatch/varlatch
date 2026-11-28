// SPDX-License-Identifier: Apache-2.0

package webupgrade

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/upgraderequest"
)

var paths = UnitPaths{Varlatch: "/usr/local/bin/varlatch", Config: "/etc/varlatch/varlatchd.conf", DataDir: "/var/lib/varlatch"}

// Every root unit is hardened as the release check's documented unit is,
// and more; each runs the CLI with the configuration; the path unit watches
// the request file in the data directory; the recovery comes after
// varlatchd (it starts it); the timer is Decision 1's cadence.
func TestUnitFiles(t *testing.T) {
	for _, u := range []string{CheckServiceUnit, ServiceUnit, RecoverUnit} {
		f := UnitFile(u, paths)
		for _, want := range []string{"Type=oneshot", "User=root", "NoNewPrivileges=yes", "PrivateTmp=yes", "ProtectHome=yes", "LimitCORE=0", "CacheDirectory=varlatch-upgrade",
			"ExecStart=/usr/local/bin/varlatch upgrade --"} {
			if !strings.Contains(f, want) {
				t.Errorf("%s has no %q:\n%s", u, want, f)
			}
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
}

type fakeHost struct {
	files   map[string]string
	dirs    []string
	calls   []string
	same    bool
	active  bool
	failing string
}

func (h *fakeHost) WriteFile(path string, data []byte, _ fs.FileMode) error {
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
func (h *fakeHost) Active(context.Context, string) bool { return h.active }

func TestEnableAndDisable(t *testing.T) {
	ctx, said := context.Background(), func(string) {}
	// Not on the data directory's file system: nothing is installed.
	h := &fakeHost{files: map[string]string{}}
	if err := Enable(ctx, h, paths, "/etc/varlatch", TakenDir, said); err == nil || !strings.Contains(err.Error(), "different file systems") || len(h.files) != 0 || len(h.calls) != 0 {
		t.Fatalf("another file system: %v %v %v", err, h.files, h.calls)
	}
	h.same, h.failing = true, "start "+CheckServiceUnit
	if err := Enable(ctx, h, paths, "/etc/varlatch", TakenDir, said); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.dirs, []string{"/var/lib/varlatch-upgrade", TakenDir, "/var/lib/varlatch-upgrade", TakenDir}) {
		t.Fatalf("the directories: %v", h.dirs)
	}
	for _, u := range Units {
		if h.files[filepath.Join(UnitDir, u)] != UnitFile(u, paths) {
			t.Errorf("%s not installed", u)
		}
	}
	if on, err := upgraderequest.ParseConf([]byte(h.files["/etc/varlatch/web-upgrade.conf"])); err != nil || !on {
		t.Fatalf("web-upgrade.conf: %v %v", on, err)
	}
	want := []string{"daemon-reload", "enable " + RecoverUnit, "enable --now " + CheckTimerUnit + " " + PathUnit, "start " + CheckServiceUnit}
	if !slices.Equal(h.calls, want) {
		t.Fatalf("systemctl: %v", h.calls)
	}
	// While an upgrade from a request runs, nothing is disabled.
	h.active, h.calls = true, nil
	if err := Disable(ctx, h, "/etc/varlatch", said); !errors.Is(err, ErrRunning) || len(h.calls) != 0 {
		t.Fatalf("while running: %v %v", err, h.calls)
	}
	h.active = false
	if err := Disable(ctx, h, "/etc/varlatch", said); err != nil {
		t.Fatal(err)
	}
	if len(h.files) != 0 || !slices.Equal(h.calls, []string{"disable --now " + PathUnit + " " + CheckTimerUnit + " " + RecoverUnit, "daemon-reload"}) {
		t.Fatalf("after disable: %v %v", h.files, h.calls)
	}
	// Twice is no error.
	if err := Disable(ctx, h, "/etc/varlatch", said); err != nil {
		t.Fatal(err)
	}
}
