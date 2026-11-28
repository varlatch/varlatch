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
		return head + "[Unit]\nDescription=Varlatch upgrade asked for in the web app (varlatch upgrade --from-request)\n" + docs +
			"Wants=network-online.target\nAfter=network-online.target\n\n" +
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
	// Active is whether a unit is active (running).
	Active(ctx context.Context, unit string) bool
}

// Enable installs the units and the root-only directory, writes
// web-upgrade.conf and enables them: the path unit and the timer at once
// (with a release check now), the recovery for the next boot.
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
	for _, u := range Units {
		if err := h.WriteFile(filepath.Join(UnitDir, u), []byte(UnitFile(u, p)), 0o644); err != nil {
			return err
		}
	}
	if err := h.WriteFile(filepath.Join(configDir, upgraderequest.ConfFile), upgraderequest.EncodeConf(true), 0o644); err != nil {
		return err
	}
	if err := h.Systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	if err := h.Systemctl(ctx, "enable", RecoverUnit); err != nil {
		return err
	}
	if err := h.Systemctl(ctx, "enable", "--now", CheckTimerUnit, PathUnit); err != nil {
		return err
	}
	say("Installed and enabled " + strings.Join(Units, ", ") + " in " + UnitDir + ", and wrote " + filepath.Join(configDir, upgraderequest.ConfFile) + ".")
	say("Checking for a newer release now (" + CheckServiceUnit + ")...")
	if err := h.Systemctl(ctx, "start", CheckServiceUnit); err != nil {
		say("The release check did not succeed now (journalctl -u " + CheckServiceUnit + " says why); the timer runs it again daily.")
	}
	return nil
}

// ErrRunning refuses to disable while an upgrade from a request runs.
var ErrRunning = errors.New("an upgrade asked for in the web app is running (" + ServiceUnit + "): wait until it is over, then disable")

// Disable stops and removes the units and web-upgrade.conf. The helper's
// directory, with the requests it took, stays.
func Disable(ctx context.Context, h Host, configDir string, say func(string)) error {
	if h.Active(ctx, ServiceUnit) {
		return ErrRunning
	}
	// Errors from units that are not there are not errors here.
	_ = h.Systemctl(ctx, "disable", "--now", PathUnit, CheckTimerUnit, RecoverUnit)
	for _, p := range append([]string{filepath.Join(configDir, upgraderequest.ConfFile)}, unitPaths()...) {
		if err := h.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := h.Systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	say("Removed " + strings.Join(Units, ", ") + " and " + filepath.Join(configDir, upgraderequest.ConfFile) + ": the web app shows upgrade commands only.")
	say("Nothing schedules the release check now; docs.varlatch.com/operations/upgrade/#scheduling-the-release-check gives a timer to install by hand.")
	return nil
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

func (SystemHost) Active(ctx context.Context, unit string) bool {
	return systemctl(ctx, "is-active", "--quiet", unit) == nil
}
