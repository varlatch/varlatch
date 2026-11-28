// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/upgrade"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/webupgrade"
	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/keyenv"
	journal "github.com/varlatch/varlatch/go/lib/upgradejournal"
	"github.com/varlatch/varlatch/go/lib/upgraderequest"
)

// The web upgrade's host forms (ADR-0065 phase 2): `varlatch upgrade
// --enable-web` and `--disable-web`, which the operator runs, and
// `--from-request` and `--recover`, which its units run.

// webForms are the forms, each alone with --config.
var webForms = []string{"--enable-web", "--disable-web", "--from-request", "--recover"}

// webHost is the host --enable-web and --disable-web change; only the tests
// replace it.
var webHost = func() webupgrade.Host { return webupgrade.SystemHost{} }

// webTakenDir is the helper's directory; only the tests replace it, and
// webRetryDelay.
var (
	webTakenDir, webTakenOwner = webupgrade.TakenDir, uint32(0)
	webRetryDelay              = webupgrade.RetryDelay
)

// noticeWait is how long the helper waits before the stop once the
// dashboards are told varlatchd restarts (varlatchd looks every second).
const noticeWait = 3 * time.Second

// webForm is the one web form among the options given, or "".
func webForm(parsed *ParsedOptions) (string, bool) {
	form, n := "", 0
	for _, f := range webForms {
		if parsed.Has(f) {
			form, n = f, n+1
		}
	}
	if n == 0 {
		return "", true
	}
	others := len(parsed.Positionals) > 0
	for _, o := range []string{"--check", "--json", "--yes", "--prerelease", "--accept-not-rollback-safe", "--end-rollback-window", "--rollback", "--accept-data-loss"} {
		others = others || parsed.Has(o)
	}
	return form, n == 1 && !others
}

// upgradeWeb runs one web form, as root, on a Go installation's host.
func (r *Run) upgradeWeb(ctx context.Context, form string, u *upgrade.Upgrader, varlatchd, config string) error {
	if r.Getenv(keyenv.ImageMarker) != "" {
		return Fail("varlatch upgrade "+form+": this is the container image, which is upgraded by deploying another image by digest; the web upgrade's helper runs on a systemd host. Nothing was changed.", ExitUsage)
	}
	record := func(ctx context.Context, args ...string) error {
		return runQuiet(ctx, varlatchd, append(append([]string{"admin", "upgrade-request"}, args...), "--config", config)...)
	}
	heartbeat := func(ctx context.Context, enabled bool) error {
		on := "false"
		if enabled {
			on = "true"
		}
		return record(ctx, "heartbeat", "--helper-version", buildinfo.Version, "--enabled", on)
	}
	say := func(line string) { _ = r.println(line) }
	switch form {
	case "--recover":
		return r.upgradeRecover(ctx, u, config)
	case "--disable-web":
		err := webupgrade.Disable(ctx, webHost(), filepath.Dir(config), webTakenDir, say)
		if errors.Is(err, webupgrade.ErrRunning) {
			return Fail("varlatch upgrade --disable-web: "+err.Error()+". Nothing was changed.", ExitFailure)
		}
		if err != nil {
			return Fail("varlatch upgrade --disable-web: "+err.Error(), ExitFailure)
		}
		if err := heartbeat(ctx, false); err != nil {
			return r.warn("varlatch upgrade --disable-web: the dashboard was not told (it shows the helper until its heartbeat is old): " + err.Error())
		}
		return nil
	case "--enable-web":
		inst, err := u.Inspect(ctx)
		if err != nil {
			return Fail("varlatch upgrade --enable-web: "+err.Error()+". Nothing was changed.", ExitFailure)
		}
		abs, err := filepath.Abs(config)
		if err != nil {
			return Fail("varlatch upgrade --enable-web: "+err.Error(), ExitFailure)
		}
		p := webupgrade.UnitPaths{Varlatch: filepath.Join(u.BinDir, "varlatch"), Config: abs, DataDir: inst.DataDir}
		if err := webupgrade.Enable(ctx, webHost(), p, filepath.Dir(config), webTakenDir, say); err != nil {
			if errors.Is(err, webupgrade.ErrLeftOff) {
				// Left off: a heartbeat from before must not say otherwise.
				_ = heartbeat(ctx, false)
			}
			return Fail("varlatch upgrade --enable-web: "+err.Error(), ExitFailure)
		}
		if err := heartbeat(ctx, true); err != nil {
			return r.warn("varlatch upgrade --enable-web: the helper's heartbeat was not recorded; the next release check records it: " + err.Error())
		}
		return r.println("Installation Admins can now ask for an upgrade to the next release in the web app (Installation settings, Release), when every line of its pre-flight passes. This host checks, verifies, backs up and upgrades; sudo varlatch upgrade --disable-web turns it off.")
	}
	// --from-request: the path unit's service.
	src := selfUpdateSource(r)
	h := &webupgrade.Helper{
		ConfigDir: filepath.Dir(config), TakenDir: webTakenDir, TakenOwner: webTakenOwner, Now: time.Now,
		DataDir: func(ctx context.Context) (string, error) { return dataDirOf(ctx, varlatchd, config) },
		Inspect: u.Inspect,
		Newest: func(ctx context.Context) (string, error) {
			v, _, err := selfupdate.Newest(ctx, src, false)
			return v, err
		},
		Fetch: func(ctx context.Context, v string) (upgrade.Release, error) {
			return upgrade.Fetch(ctx, src, v, runtime.GOARCH)
		},
		WindowEnds: func(dataDir, v string, ends bool) (bool, error) {
			return windowEnding(dataDir, v, ends, time.Now())
		},
		Run: func(ctx context.Context, inst upgrade.Installed, rel upgrade.Release, onStep func(*journal.Journal, journal.Step)) (*journal.Journal, error) {
			// The engine as `sudo varlatch upgrade <version> --yes` runs it,
			// with no override, and its snapshot checked off the host first.
			u.VerifyRemote, u.OnStep = true, onStep
			return u.Run(ctx, inst, rel)
		},
		Record:     record,
		NoticeWait: noticeWait,
		Log:        say,
		Version:    buildinfo.Version,
		Lock:       func(context.Context) (func(), error) { return webupgrade.LockRun(webTakenDir) },
		RetryDelay: webRetryDelay,
	}
	o, err := h.FromRequest(ctx)
	switch {
	case errors.Is(err, webupgrade.ErrNoRequest):
		return r.println("There is no upgrade request (it was cancelled, or already taken).")
	case errors.Is(err, webupgrade.ErrNotTaken):
		return Fail("varlatch upgrade --from-request: "+err.Error()+". The request stays; this service runs again for it until varlatchd removes it at its expiry (docs: Upgrading from the web app, when the helper cannot take a request).", ExitFailure)
	case err != nil:
		return Fail("varlatch upgrade --from-request: "+err.Error(), ExitFailure)
	case o.Phase == upgraderequest.Done:
		return r.println("Upgraded to " + o.Request.Version + " for the request " + o.Request.ID + ".")
	case o.Phase == upgraderequest.Refused:
		return r.println("The request " + o.Request.ID + " for " + o.Request.Version + " was refused (" + o.Reason + "). Nothing was changed.")
	}
	return Fail("varlatch upgrade --from-request: the request "+o.Request.ID+" for "+o.Request.Version+" ended "+string(o.Phase)+" ("+o.Reason+")", ExitFailure)
}

// dataDirOf is the data directory varlatchd's configuration names, as
// `admin schema status` says it.
func dataDirOf(ctx context.Context, varlatchd, config string) (string, error) {
	out, err := exec.CommandContext(ctx, varlatchd, "admin", "schema", "status", "--json", "--config", config).Output()
	if err != nil {
		return "", err
	}
	var st struct {
		DataDir string `json:"dataDir"`
	}
	if err := json.Unmarshal(out, &st); err != nil || st.DataDir == "" || !filepath.IsAbs(st.DataDir) {
		return "", errors.New("varlatchd admin schema status named no data directory")
	}
	return st.DataDir, nil
}

// upgradeRecover is `upgrade --recover`: an upgrade or rollback left
// pending is finished or undone, as the next `varlatch upgrade` would, and
// nothing else (the boot recovery's unit). A restored installation that is
// held is left to its operator.
func (r *Run) upgradeRecover(ctx context.Context, u *upgrade.Upgrader, config string) error {
	j, err := u.Pending()
	if err != nil {
		return Fail("varlatch upgrade --recover: "+err.Error(), ExitFailure)
	}
	if j == nil {
		return r.println("No upgrade or rollback is pending.")
	}
	if h, err := backup.ReadHold(j.DataDir); err != nil || h != nil && !(j.Kind == journal.Rollback && h.ArchiveID == j.SnapshotArchive && j.SnapshotArchive != "") {
		return Fail("varlatch upgrade --recover: this installation was restored from an archive and is held, and an upgrade from "+j.From+" to "+j.To+" is still pending: sudo varlatch upgrade says what to do. Nothing was changed.", ExitFailure)
	}
	// At boot varlatchd may have failed to start (the journal keeps it
	// from it) before this ran: it is started again.
	u.Service = resetFailed{u.Service}
	done, err := u.Recover(ctx)
	if err != nil {
		return upgradeFailure(err)
	}
	if done == nil {
		return r.println("No upgrade or rollback is pending.")
	}
	return r.println(recoveredMessage(done))
}

// resetFailed is a service whose start first clears systemd's record of
// its failed starts.
type resetFailed struct{ upgrade.Service }

func (s resetFailed) Start(ctx context.Context) error {
	if sd, ok := s.Service.(upgrade.Systemd); ok {
		_ = exec.CommandContext(ctx, "systemctl", "reset-failed", sd.Unit).Run()
	}
	return s.Service.Start(ctx)
}

// heartbeatAfterCheck records the helper's heartbeat after a release check
// run as root on a host that accepts requests (Decision 1: at each run of
// the check); without the helper, nothing.
func (r *Run) heartbeatAfterCheck(ctx context.Context, u *upgrade.Upgrader) error {
	if !asRoot() {
		return nil
	}
	if on, err := upgraderequest.Accepting(filepath.Dir(u.ConfigPath)); err != nil || !on {
		return nil
	}
	err := runQuiet(ctx, filepath.Join(u.BinDir, "varlatchd"), "admin", "upgrade-request", "heartbeat", "--helper-version", buildinfo.Version, "--enabled", "true", "--config", u.ConfigPath)
	if err != nil {
		return r.warn("varlatch upgrade --check: the web upgrade helper's heartbeat was not recorded: " + err.Error())
	}
	return nil
}

// setupWebUpgrade is setup's last question (ADR-0065, owner decision 2):
// whether Installation Admins may ask for an upgrade from the web app,
// default no. Without a terminal it is not asked, and the answer is no.
func (r *Run) setupWebUpgrade(ask interface {
	Confirm(q string, defaultYes bool) (bool, error)
}, varlatchd string) error {
	later := "To let Installation Admins upgrade to the next release from the web app later: sudo varlatch upgrade --enable-web."
	if ask == nil {
		return r.println(later)
	}
	yes, err := ask.Confirm("Let Installation Admins upgrade Varlatch to the next release from the web app? This host then verifies, backs up off the host and upgrades when one asks, with a passkey.", false)
	if err != nil || !yes {
		if err == nil {
			err = r.println(later)
		}
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), upgradeTimeout)
	defer cancel()
	u := &upgrade.Upgrader{BinDir: filepath.Dir(varlatchd), ConfigPath: DefaultVarlatchdConfig, Service: upgradeService(), Log: func(line string) { _ = r.println(line) }}
	if err := u.Trusted(); err != nil {
		return Fail("varlatch setup: the web upgrade was not enabled: "+err.Error(), ExitFailure)
	}
	return r.upgradeWeb(ctx, "--enable-web", u, varlatchd, DefaultVarlatchdConfig)
}
