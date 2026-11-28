// SPDX-License-Identifier: Apache-2.0

package webupgrade

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/varlatch/varlatch/go/lib/upgraderequest"
)

// The units `--enable-web` installs, in /etc/systemd/system (Decisions 1
// and 6).
const (
	PathUnit         = "varlatch-upgrade.path"
	ServiceUnit      = "varlatch-upgrade.service"
	RecoverUnit      = "varlatch-upgrade-recover.service"
	CheckServiceUnit = "varlatch-release-check.service"
	CheckTimerUnit   = "varlatch-release-check.timer"
	UnitDir          = "/etc/systemd/system"
)

// Units are the unit files, in the order they are installed.
var Units = []string{CheckServiceUnit, CheckTimerUnit, ServiceUnit, PathUnit, RecoverUnit}

// UnitPaths says where the units point: the CLI, varlatchd's configuration
// and its data directory.
type UnitPaths struct {
	Varlatch, Config, DataDir string
}

// hardening is the sandbox of every root unit here, as far as it leaves
// an upgrade possible: it replaces binaries in /usr/local, writes
// /etc/varlatch and the data directory, and stops and starts varlatchd
// through systemd. No new privileges, its own /tmp, no home directories (the
// Sigstore cache is the unit's cache directory), no kernel or clock changes,
// no core dump (the commands it runs load the keys).
const hardening = `User=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectKernelTunables=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
KeyringMode=private
LimitCORE=0
Environment=XDG_CACHE_HOME=/var/cache/varlatch-upgrade
CacheDirectory=varlatch-upgrade
CacheDirectoryMode=0700
`

const docs = "Documentation=https://docs.varlatch.com/operations/upgrade/\n"

// UnitFile is one unit's file.
func UnitFile(name string, p UnitPaths) string {
	head := "# Installed by sudo varlatch upgrade --enable-web; removed by --disable-web.\n"
	switch name {
	case CheckServiceUnit:
		return head + "[Unit]\nDescription=Varlatch release check (varlatch upgrade --check)\n" + docs +
			"Wants=network-online.target\nAfter=network-online.target varlatchd.service\n\n" +
			"[Service]\nType=oneshot\n" + hardening +
			"ExecStart=" + p.Varlatch + " upgrade --check --config " + p.Config + "\n"
	case CheckTimerUnit:
		return head + "[Unit]\nDescription=Daily Varlatch release check\n" + docs + "\n" +
			"[Timer]\nOnCalendar=daily\nRandomizedDelaySec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
	case ServiceUnit:
		// The start limit is set here, not left to the host's defaults: a
		// run that cannot take a request waits RetryDelay before it fails,
		// about ten starts in ten minutes, which this allows; a run that
		// fails at once, again and again (the binary gone), hits it, and
		// the units fail, which `varlatch doctor` reports
		// (docs/operations/upgrade.md: systemctl reset-failed).
		return head + "[Unit]\nDescription=Varlatch upgrade asked for in the web app (varlatch upgrade --from-request)\n" + docs +
			"Wants=network-online.target\nAfter=network-online.target\n" +
			"StartLimitIntervalSec=10min\nStartLimitBurst=20\n\n" +
			"[Service]\nType=oneshot\n" + hardening +
			"TimeoutStartSec=45min\n" +
			"ExecStart=" + p.Varlatch + " upgrade --from-request --config " + p.Config + "\n"
	case PathUnit:
		return head + "[Unit]\nDescription=Varlatch upgrade requests from the web app\n" + docs + "\n" +
			"[Path]\nPathExists=" + filepath.Join(p.DataDir, upgraderequest.Dir, upgraderequest.RequestFile) + "\nUnit=" + ServiceUnit + "\n\n" +
			"[Install]\nWantedBy=paths.target\n"
	case RecoverUnit:
		// After varlatchd, not before it: the recovery starts varlatchd
		// itself (the previous release, or the new one) and waits for its
		// health checks, which a unit ordered before varlatchd.service
		// would wait for forever. A varlatchd that an unfinished upgrade
		// keeps from starting at boot fails first; this then finishes or
		// undoes the upgrade.
		return head + "[Unit]\nDescription=Varlatch: finish or undo an interrupted upgrade at boot (varlatch upgrade --recover)\n" + docs +
			"Wants=network-online.target\nAfter=network-online.target varlatchd.service\n" +
			"ConditionPathExists=" + filepath.Join(filepath.Dir(p.Config), "upgrade.json") + "\n\n" +
			"[Service]\nType=oneshot\n" + hardening +
			"TimeoutStartSec=45min\n" +
			"ExecStart=" + p.Varlatch + " upgrade --recover --config " + p.Config + "\n\n" +
			"[Install]\nWantedBy=multi-user.target\n"
	}
	return ""
}

// Host is what enabling and disabling change: files as root, and systemd.
type Host interface {
	// WriteFile replaces path with data, root's, mode, durably.
	WriteFile(path string, data []byte, mode fs.FileMode) error
	Remove(path string) error
	// MkdirRoot makes path, root's, mode, or checks that it is that.
	MkdirRoot(path string, mode fs.FileMode) error
	SameFileSystem(a, b string) (bool, error)
	Systemctl(ctx context.Context, args ...string) error
	// State is a unit's ActiveState (active, activating for a oneshot that
	// runs, failed, inactive, ...) and Result (success, exit-code,
	// start-limit-hit, ...).
	State(ctx context.Context, unit string) (active, result string, err error)
	// Lock takes the helper's run lock on dir without waiting: ok false
	// when a run of the helper holds it; an error wrapping fs.ErrNotExist
	// when dir is not there.
	Lock(dir string) (unlock func(), ok bool, err error)
}

// Enable installs the units and the root-only directory, enables them (the
// path unit and the timer at once, with a release check now, the recovery
// for the next boot), and only then writes web-upgrade.conf: a host never
// says it accepts requests that no unit takes. When a step fails, what it
// installed is removed again, web-upgrade.conf with it. It holds the
// helper's run lock throughout, so a run the path unit starts meanwhile
// waits and then reads web-upgrade.conf as Enable left it; ErrRunning while
// a run holds it.
func Enable(ctx context.Context, h Host, p UnitPaths, configDir, takenDir string, say func(string)) error {
	parent := filepath.Dir(takenDir)
	for _, d := range []string{parent, takenDir} {
		if err := h.MkdirRoot(d, 0o700); err != nil {
			return fmt.Errorf("the helper's directory %s: %w", d, err)
		}
	}
	same, err := h.SameFileSystem(takenDir, p.DataDir)
	if err != nil {
		return err
	}
	if !same {
		return fmt.Errorf("%s and varlatchd's data directory %s are on different file systems: taking a request is a rename, which needs one. Nothing was enabled (move %s onto the data directory's file system, or bind-mount it there)", takenDir, p.DataDir, parent)
	}
	unlock, ok, err := h.Lock(parent)
	switch {
	case err != nil:
		return fmt.Errorf("the helper's lock: %w", err)
	case !ok:
		return ErrRunning
	}
	// Released before the release check below, which may take a while.
	unlock = sync.OnceFunc(unlock)
	defer unlock()
	conf := filepath.Join(configDir, upgraderequest.ConfFile)
	install := func() error {
		for _, u := range Units {
			if err := h.WriteFile(filepath.Join(UnitDir, u), []byte(UnitFile(u, p)), 0o644); err != nil {
				return err
			}
		}
		for _, args := range [][]string{{"daemon-reload"}, {"enable", RecoverUnit}, {"enable", "--now", CheckTimerUnit, PathUnit}} {
			if err := h.Systemctl(ctx, args...); err != nil {
				return err
			}
		}
		return h.WriteFile(conf, upgraderequest.EncodeConf(true), 0o644)
	}
	if err := install(); err != nil {
		if undo := disable(ctx, h, configDir); undo != nil {
			return fmt.Errorf("%w; %w, but not all of it was removed again (%v): run sudo varlatch upgrade --disable-web, put that right, then --enable-web again", err, ErrLeftOff, undo)
		}
		return fmt.Errorf("%w; %w: its units and %s were removed again (put that right, then run sudo varlatch upgrade --enable-web again)", err, ErrLeftOff, conf)
	}
	unlock()
	say("Installed and enabled " + strings.Join(Units, ", ") + " in " + UnitDir + ", and wrote " + conf + ".")
	say("Checking for a newer release now (" + CheckServiceUnit + ")...")
	if err := h.Systemctl(ctx, "start", CheckServiceUnit); err != nil {
		say("The release check did not succeed now (journalctl -u " + CheckServiceUnit + " says why); the timer runs it again daily.")
	}
	return nil
}

// ErrLeftOff is an Enable that failed part way and removed what it had
// installed: the host does not accept requests.
var ErrLeftOff = errors.New("the web upgrade was left off")

// ErrRunning refuses to enable or disable while a run of the helper holds
// its lock: an upgrade asked for in the web app is being taken or run.
var ErrRunning = errors.New("an upgrade asked for in the web app is running (" + ServiceUnit + "): wait until it is over, then run this again")

// Disable stops and removes the units and web-upgrade.conf, holding the
// helper's run lock (ErrRunning while a run holds it). The helper's
// directory, with the requests it took, stays.
func Disable(ctx context.Context, h Host, configDir, takenDir string, say func(string)) error {
	unlock, ok, err := h.Lock(filepath.Dir(takenDir))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Never enabled here, or its directory removed: no run to wait for.
		unlock = func() {}
	case err != nil:
		return fmt.Errorf("the helper's lock: %w", err)
	case !ok:
		return ErrRunning
	}
	defer unlock()
	if err := disable(ctx, h, configDir); err != nil {
		return err
	}
	say("Removed " + strings.Join(Units, ", ") + " and " + filepath.Join(configDir, upgraderequest.ConfFile) + ": the web app shows upgrade commands only.")
	say("Nothing schedules the release check now; docs.varlatch.com/operations/upgrade/#scheduling-the-release-check gives a timer to install by hand.")
	return nil
}

// disable is Disable's change, and Enable's undo: web-upgrade.conf first,
// so no run reads yes while the rest goes. The recovery's unit is disabled
// without --now: a recovery that runs (at boot) is finishing or undoing an
// upgrade and must not be stopped half way; systemd keeps a running unit
// loaded when its file goes. A run of the helper waiting RetryDelay holds
// no lock and changes nothing, and fails when it ends.
func disable(ctx context.Context, h Host, configDir string) error {
	var first error
	keep := func(err error) {
		if first == nil && err != nil && !errors.Is(err, fs.ErrNotExist) {
			first = err
		}
	}
	keep(h.Remove(filepath.Join(configDir, upgraderequest.ConfFile)))
	// Errors from units that are not there are not errors here.
	_ = h.Systemctl(ctx, "disable", "--now", PathUnit, CheckTimerUnit)
	_ = h.Systemctl(ctx, "disable", RecoverUnit)
	for _, p := range unitPaths() {
		keep(h.Remove(p))
	}
	keep(h.Systemctl(ctx, "daemon-reload"))
	return first
}

func unitPaths() []string {
	var out []string
	for _, u := range Units {
		out = append(out, filepath.Join(UnitDir, u))
	}
	return out
}

// SystemHost is the real host.
type SystemHost struct{}

func (SystemHost) WriteFile(path string, data []byte, mode fs.FileMode) error {
	return writeRootFile(path, data, mode)
}

func (SystemHost) Remove(path string) error { return os.Remove(path) }

func (SystemHost) MkdirRoot(path string, mode fs.FileMode) error { return mkdirRoot(path, mode) }

func (SystemHost) SameFileSystem(a, b string) (bool, error) { return sameFileSystem(a, b) }

func (SystemHost) Systemctl(ctx context.Context, args ...string) error {
	return systemctl(ctx, args...)
}

func (SystemHost) State(ctx context.Context, unit string) (string, string, error) {
	return unitState(ctx, unit)
}

func (SystemHost) Lock(dir string) (func(), bool, error) { return lockDir(dir, false) }

// LockRun is the helper's run lock on takenDir's parent, waiting for it
// (Helper.Lock).
func LockRun(takenDir string) (func(), error) {
	unlock, _, err := lockDir(filepath.Dir(takenDir), true)
	return unlock, err
}

// Failed are the helper's units that systemd failed for good: the path
// unit, the timer or the recovery failed, or the request's service hit its
// start limit (which fails the path unit too). Then no request is taken
// until `systemctl reset-failed`. A request's run that failed (an upgrade
// that failed, a request not taken) leaves the service failed until the
// next request, and is not counted: the dashboard shows it. A state that
// cannot be read is not counted.
func Failed(ctx context.Context, h Host) []string {
	var out []string
	for _, u := range []string{PathUnit, ServiceUnit, RecoverUnit, CheckTimerUnit} {
		active, result, err := h.State(ctx, u)
		if err == nil && (u != ServiceUnit && active == "failed" || u == ServiceUnit && result == "start-limit-hit") {
			out = append(out, u)
		}
	}
	return out
}
