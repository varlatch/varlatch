// SPDX-License-Identifier: Apache-2.0

// Package upgrade is `varlatch upgrade`'s engine for a Go installation
// (ADR-0059 Decision 8; internal docs/design/go-step6.md, decision 6, slice
// 6.6b). It runs decision 6's steps, each recorded in the journal
// (go/lib/upgradejournal) before the next begins, and undoes what a failed
// step leaves, so an upgrade ends in a stated state: the previous release
// serving on its database as it was, or the new release serving after its
// health checks.
//
//	verified   the release's varlatch, varlatchd and release.json, verified
//	           against its signed SHA256SUMS (by the caller, with
//	           selfupdate.FetchAssets), are staged; the installed release's
//	           binaries are kept beside them
//	snapshot   `varlatchd admin backup run`: the pre-upgrade snapshot, an
//	           archive encrypted with the Backup Encryption Key, kept with the
//	           upgrade for 30 days (backup_keep's pruning never reaches it)
//	stopping   recorded before the stop: from here on the service may be
//	           down, whatever happens next
//	stopped    varlatchd is stopped
//	prepared   a copy of the database gets the new release's schema
//	           (`varlatchd admin schema upgrade --database`, the new
//	           varlatchd): the schema update runs on a copy first
//	swapped    the original database is moved aside and the upgraded copy
//	           takes its place; the new binaries replace the old ones
//	started    varlatchd is started
//	checked    the new varlatchd answers `admin status` as the new release,
//	           serving, its schema, Root KEK and installation ready; nothing
//	           else counts as healthy (unknown blocks like a failure)
//
// Before anything is written, the disks must hold the upgrade (a copy of
// the database, a snapshot, the binaries, a margin) and <data>/upgrades
// must be a real directory of the data directory's owner. A failure before
// stopping changes nothing on the host. A failure from stopping on stops
// varlatchd, puts the original database files and the previous binaries
// back. Either way the undo ends by starting the previous release and
// checking it: it never takes the service to be running. An interrupted upgrade (a kill, a power cut) is
// finished or undone by the next run (Recover) from the journal: after
// checked it is finished, before it undone. An undo that cannot complete is
// recorded as failed, with what is left and the snapshot to restore from.
//
// The database is never changed in place: the schema update writes the
// copy, and an undo puts back the files the original release last wrote.
package upgrade

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/release"
	journal "github.com/varlatch/varlatch/go/lib/upgradejournal"
)

// databaseFiles are the database's files in the data directory (the
// server's config.DatabaseFile and SQLite's write-ahead log and index).
var databaseFiles = []string{"varlatch.db", "varlatch.db-wal", "varlatch.db-shm"}

// keepSnapshots is how long an upgrade's directory (its snapshot) is kept.
const keepSnapshots = 30 * 24 * time.Hour

// Service is varlatchd's service on the host.
type Service interface {
	Stop(ctx context.Context) error
	Start(ctx context.Context) error
}

// Systemd is the varlatchd unit, through systemctl.
type Systemd struct{ Unit string }

func (s Systemd) Stop(ctx context.Context) error  { return systemctl(ctx, "stop", s.Unit) }
func (s Systemd) Start(ctx context.Context) error { return systemctl(ctx, "start", s.Unit) }

func systemctl(ctx context.Context, verb, unit string) error {
	out, err := exec.CommandContext(ctx, "systemctl", verb, unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %v: %s", verb, unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Release is the release to install, verified.
type Release struct {
	Version             string
	Varlatch, Varlatchd []byte
	Manifest            release.Manifest
}

// Installed is the release the host runs.
type Installed struct {
	// Version is varlatchd's release, Schema its schema version, DataDir
	// its data directory. Database is the database's schema version: newer
	// than Schema once a rollback-safe release wrote it and this one is
	// back, Schema otherwise.
	Version          string
	Schema, Database int64
	DataDir          string
}

// RollbackSafe is whether the installed release's varlatchd may open a
// database the release upgraded: its manifest lets that schema version in.
func RollbackSafe(m release.Manifest, installed Installed) bool {
	return m.CompatibleFrom <= installed.Schema
}

// Error is an upgrade that did not happen, or did not end as asked:
// Journal says where it stands.
type Error struct {
	Message string
	Journal *journal.Journal
}

func (e *Error) Error() string { return e.Message }

// errKilled is a run stopped at a crash point (the tests' kill).
var errKilled = errors.New("upgrade: stopped at a crash point")

// Upgrader upgrades one host.
type Upgrader struct {
	// BinDir holds varlatch and varlatchd; ConfigPath is varlatchd.conf,
	// whose directory holds the journal.
	BinDir, ConfigPath string
	Service            Service
	// Log gets a line for each step; nil discards them. The CLI shows them
	// through its fail-safe.
	Log func(line string)
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// HealthTimeout bounds the wait for a started varlatchd's checks;
	// zero is a minute.
	HealthTimeout time.Duration
	// Crash and Fault are the tests' seams: Crash stops the run at a named
	// point as a kill would (nothing undone); Fault fails a write to a
	// path as a full disk would.
	Crash func(point string) bool
	Fault func(path string) error
}

func (u *Upgrader) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *Upgrader) logf(format string, a ...any) {
	if u.Log != nil {
		u.Log(fmt.Sprintf(format, a...))
	}
}

func (u *Upgrader) configDir() string { return filepath.Dir(u.ConfigPath) }
func (u *Upgrader) varlatchd() string { return filepath.Join(u.BinDir, "varlatchd") }

// Releases is where each release's binaries are kept: beside BinDir, in
// lib/varlatch/releases (/usr/local/lib/varlatch/releases), root's.
func (u *Upgrader) Releases() string {
	return filepath.Join(filepath.Dir(u.BinDir), "lib", "varlatch", "releases")
}

// admin runs a varlatchd with args and the configuration, and returns
// what it printed on its standard output; a failure carries its message.
func (u *Upgrader) admin(ctx context.Context, binary string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, append(args, "--config", u.ConfigPath)...)
	// Both pipes read whole, at once: what varlatchd answers, and what it
	// says when it refuses, which a failure carries.
	answerPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	saidPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	saidCh := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(saidPipe); saidCh <- b }()
	answer, _ := io.ReadAll(answerPipe)
	said := <-saidCh
	if err := cmd.Wait(); err != nil {
		msg := strings.TrimSpace(string(said))
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}
	return answer, nil
}

// Inspect reads the installed release: varlatchd's version, and its
// schema and data directory (`admin schema status`). The database must be
// one it serves.
func (u *Upgrader) Inspect(ctx context.Context) (Installed, error) {
	out, err := exec.CommandContext(ctx, u.varlatchd(), "--version").Output()
	if err != nil {
		return Installed{}, fmt.Errorf("%s --version: %v", u.varlatchd(), err)
	}
	version, ok := strings.CutPrefix(strings.TrimSpace(string(out)), "varlatchd ")
	if !ok || !release.ValidVersion(version) {
		return Installed{}, fmt.Errorf("%s is not a release's varlatchd (it says %q): upgrade replaces an installed release", u.varlatchd(), strings.TrimSpace(string(out)))
	}
	raw, err := u.admin(ctx, u.varlatchd(), "admin", "schema", "status", "--json")
	if err != nil {
		return Installed{}, fmt.Errorf("varlatchd admin schema status: %v", err)
	}
	var st struct {
		Binary struct {
			SchemaVersion int64 `json:"schemaVersion"`
		} `json:"binary"`
		Database *struct {
			SchemaVersion int64 `json:"schemaVersion"`
		} `json:"database"`
		Opens   bool   `json:"opens"`
		DataDir string `json:"dataDir"`
	}
	if err := json.Unmarshal(raw, &st); err != nil || st.DataDir == "" || st.Binary.SchemaVersion < 1 {
		return Installed{}, errors.New("varlatchd admin schema status gave no schema or data directory")
	}
	if st.Database == nil {
		return Installed{}, fmt.Errorf("there is no database in %s yet: set the installation up (varlatch setup) before an upgrade", st.DataDir)
	}
	if !st.Opens || st.Database.SchemaVersion < st.Binary.SchemaVersion {
		return Installed{}, fmt.Errorf("the database's schema (version %d) is not the installed varlatchd's (%d): check the installation (varlatch doctor) before an upgrade", st.Database.SchemaVersion, st.Binary.SchemaVersion)
	}
	return Installed{Version: version, Schema: st.Binary.SchemaVersion, Database: st.Database.SchemaVersion, DataDir: st.DataDir}, nil
}

// write records j at its step.
func (u *Upgrader) write(j *journal.Journal) error {
	if err := u.fault(filepath.Join(u.configDir(), journal.File)); err != nil {
		return err
	}
	j.UpdatedAt = u.now().UTC().Format(time.RFC3339)
	return journal.Write(u.configDir(), j)
}

// reach records step s, then stops there if a test kills the run.
func (u *Upgrader) reach(j *journal.Journal, s journal.Step) error {
	j.Step = s
	if err := u.write(j); err != nil {
		return err
	}
	return u.point(string(s))
}

func (u *Upgrader) point(name string) error {
	if u.Crash != nil && u.Crash(name) {
		return errKilled
	}
	return nil
}

// Run upgrades the installed release to rel. Its error is an *Error unless
// a crash point stopped it.
func (u *Upgrader) Run(ctx context.Context, inst Installed, rel Release) (*journal.Journal, error) {
	unlock, err := lock(u.configDir())
	if err != nil {
		return nil, &Error{Message: err.Error()}
	}
	defer unlock()
	if prev, err := journal.Read(u.configDir()); err != nil {
		return nil, &Error{Message: err.Error()}
	} else if prev.Pending() {
		return prev, &Error{Message: fmt.Sprintf("an upgrade from %s to %s is not over (%s at step %q): run varlatch upgrade again to finish or undo it first", prev.From, prev.To, prev.State, prev.Step), Journal: prev}
	}
	m := rel.Manifest
	if m.Version != rel.Version {
		return nil, &Error{Message: fmt.Sprintf("the release's manifest is for %s, not %s; nothing was changed", m.Version, rel.Version)}
	}
	if m.SchemaVersion < inst.Database {
		return nil, &Error{Message: fmt.Sprintf("the database's schema is version %d (a release later than %s wrote it), and %s's is %d: upgrade to a release of schema %d or later; nothing was changed", inst.Database, inst.Version, rel.Version, m.SchemaVersion, inst.Database)}
	}
	// <data>/upgrades is checked before anything reads or removes there:
	// prune must never follow a link out of the data directory.
	if err := upgradesDir(inst.DataDir); err != nil {
		return nil, &Error{Message: err.Error() + "; nothing was changed"}
	}
	u.prune(inst.DataDir)
	if err := u.enoughSpace(inst, rel); err != nil {
		return nil, &Error{Message: err.Error() + "; nothing was changed"}
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, &Error{Message: err.Error()}
	}
	start := u.now().UTC().Format(time.RFC3339)
	j := &journal.Journal{
		ID: hex.EncodeToString(id), From: inst.Version, To: rel.Version, FromSchema: inst.Schema, ToSchema: m.SchemaVersion,
		RollbackSafe: RollbackSafe(m, inst), State: journal.InProgress, StartedAt: start,
		BinDir: u.BinDir, Releases: u.Releases(), DataDir: inst.DataDir,
	}
	j.Work = filepath.Join(inst.DataDir, "upgrades", j.ID)
	if err := u.write(j); err != nil {
		return nil, &Error{Message: fmt.Sprintf("cannot write the upgrade journal in %s: %v; nothing was changed", u.configDir(), err)}
	}
	err = u.steps(ctx, j, rel)
	if errors.Is(err, errKilled) {
		return j, err
	}
	if err != nil {
		reason := err.Error()
		if uerr := u.undo(ctx, j, reason); uerr != nil {
			if errors.Is(uerr, errKilled) {
				return j, uerr
			}
			return j, &Error{Message: uerr.Error(), Journal: j}
		}
		return j, &Error{Message: fmt.Sprintf("the upgrade to %s did not complete (%s); it was undone: %s serves, on its database as it was", rel.Version, reason, inst.Version), Journal: j}
	}
	return j, nil
}

// steps runs decision 6's steps from j's.
func (u *Upgrader) steps(ctx context.Context, j *journal.Journal, rel Release) error {
	if err := u.stage(j, rel); err != nil {
		return err
	}
	if err := u.reach(j, journal.Verified); err != nil {
		return err
	}
	u.logf("Verified %s and staged it; %s's binaries are kept in %s.", j.To, j.From, filepath.Join(j.Releases, j.From))

	if err := u.snapshot(ctx, j); err != nil {
		return fmt.Errorf("the pre-upgrade snapshot: %w", err)
	}
	if err := u.reach(j, journal.Snapshot); err != nil {
		return err
	}
	u.logf("Took the pre-upgrade snapshot: %s (kept 30 days).", j.Snapshot)

	// Recorded before the stop: a run that ends between the stop and its
	// record (a kill, a power cut, a journal it cannot write) leaves a
	// journal that says the service may be down.
	if err := u.reach(j, journal.Stopping); err != nil {
		return err
	}
	if err := u.Service.Stop(ctx); err != nil {
		return fmt.Errorf("stopping varlatchd: %w", err)
	}
	if err := u.point("stop:done"); err != nil {
		return err
	}
	if err := u.reach(j, journal.Stopped); err != nil {
		return err
	}
	u.logf("Stopped varlatchd %s.", j.From)

	if err := u.prepare(ctx, j); err != nil {
		return fmt.Errorf("the schema update on a copy of the database: %w", err)
	}
	if err := u.reach(j, journal.Prepared); err != nil {
		return err
	}
	u.logf("Updated a copy of the database to schema version %d with %s.", j.ToSchema, j.To)

	if err := u.swap(j); err != nil {
		return fmt.Errorf("putting %s in place: %w", j.To, err)
	}
	if err := u.reach(j, journal.Swapped); err != nil {
		return err
	}

	if err := u.Service.Start(ctx); err != nil {
		return fmt.Errorf("starting varlatchd %s: %w", j.To, err)
	}
	if err := u.reach(j, journal.Started); err != nil {
		return err
	}
	if err := u.check(ctx, j.To, j.ToSchema); err != nil {
		return fmt.Errorf("the health checks of %s: %w", j.To, err)
	}
	if err := u.reach(j, journal.Checked); err != nil {
		return err
	}
	return u.promote(j)
}

// stage writes the new release's binaries into Releases/<to>, and keeps
// the installed ones in Releases/<from> (once).
func (u *Upgrader) stage(j *journal.Journal, rel Release) error {
	to := filepath.Join(j.Releases, j.To)
	from := filepath.Join(j.Releases, j.From)
	for _, dir := range []string{to, from} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("staging: %w", err)
		}
	}
	for name, data := range map[string][]byte{"varlatch": rel.Varlatch, "varlatchd": rel.Varlatchd} {
		if err := u.writeFile(filepath.Join(to, name), data, 0o755); err != nil {
			return fmt.Errorf("staging %s: %w", name, err)
		}
	}
	for _, name := range []string{"varlatch", "varlatchd"} {
		kept := filepath.Join(from, name)
		if _, err := os.Stat(kept); err == nil {
			continue
		}
		if err := u.copyFile(filepath.Join(u.BinDir, name), kept, 0o755); err != nil {
			return fmt.Errorf("keeping %s's %s: %w", j.From, name, err)
		}
	}
	return nil
}

// snapshot takes the pre-upgrade archive with the installed varlatchd and
// keeps it (a hard link, else a copy) in the upgrade's directory, where
// backup_keep's pruning never reaches it.
func (u *Upgrader) snapshot(ctx context.Context, j *journal.Journal) error {
	if err := u.workDir(j, j.Work); err != nil {
		return err
	}
	out, err := u.admin(ctx, u.varlatchd(), "admin", "backup", "run", "--json")
	if err != nil {
		return err
	}
	var res struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(out, &res); err != nil || res.Path == "" {
		return errors.New("varlatchd admin backup run named no archive")
	}
	kept := filepath.Join(j.Work, "snapshot"+filepath.Ext(res.Path))
	if err := os.Link(res.Path, kept); err != nil {
		if err := u.copyFile(res.Path, kept, 0o600); err != nil {
			return err
		}
	}
	owned(kept, j.DataDir)
	// The link and the upgrade's directory are on disk before the journal
	// says the snapshot is taken.
	syncDir(j.Work)
	syncDir(filepath.Dir(j.Work))
	j.Snapshot = kept
	return nil
}

// prepare copies the stopped varlatchd's database files into the upgrade's
// directory and runs the new varlatchd's schema update on the copy.
func (u *Upgrader) prepare(ctx context.Context, j *journal.Journal) error {
	copyDir := filepath.Join(j.Work, "db")
	if err := os.RemoveAll(copyDir); err != nil {
		return err
	}
	if err := u.workDir(j, copyDir); err != nil {
		return err
	}
	for _, name := range databaseFiles {
		src := filepath.Join(j.DataDir, name)
		if _, err := os.Stat(src); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := u.copyFile(src, filepath.Join(copyDir, name), 0o600); err != nil {
			return err
		}
	}
	newd := filepath.Join(j.Releases, j.To, "varlatchd")
	out, err := u.admin(ctx, newd, "admin", "schema", "upgrade", "--json", "--database", filepath.Join(copyDir, databaseFiles[0]))
	if err != nil {
		return err
	}
	var up struct {
		To int64 `json:"to"`
	}
	if err := json.Unmarshal(out, &up); err != nil {
		return errors.New("the new varlatchd's schema update gave no version")
	}
	if up.To != j.ToSchema {
		return fmt.Errorf("the copy's schema is version %d, not the manifest's %d", up.To, j.ToSchema)
	}
	return ownAll(copyDir, j.DataDir)
}

// swap moves the original database files aside and the upgraded copy in,
// then installs the new binaries (each written beside its place, synced,
// renamed over it).
func (u *Upgrader) swap(j *journal.Journal) error {
	original := filepath.Join(j.Work, "original")
	if err := u.workDir(j, original); err != nil {
		return err
	}
	for _, name := range databaseFiles {
		if err := os.Rename(filepath.Join(j.DataDir, name), filepath.Join(original, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	syncDir(j.DataDir)
	syncDir(original)
	if err := u.point("swap:original-aside"); err != nil {
		return err
	}
	for _, name := range databaseFiles {
		if err := os.Rename(filepath.Join(j.Work, "db", name), filepath.Join(j.DataDir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	syncDir(j.DataDir)
	syncDir(filepath.Join(j.Work, "db"))
	if err := u.point("swap:database-in"); err != nil {
		return err
	}
	return u.install(j, j.To)
}

// install puts version's kept binaries in BinDir.
func (u *Upgrader) install(j *journal.Journal, version string) error {
	for _, name := range []string{"varlatchd", "varlatch"} {
		place := filepath.Join(u.BinDir, name)
		temp := filepath.Join(u.BinDir, "."+name+"."+j.ID+".new")
		if err := u.copyFile(filepath.Join(j.Releases, version, name), temp, 0o755); err != nil {
			os.Remove(temp)
			return err
		}
		if err := os.Rename(temp, place); err != nil {
			os.Remove(temp)
			return err
		}
		if err := u.point("install:" + version + ":" + name); err != nil {
			return err
		}
	}
	syncDir(u.BinDir)
	return nil
}

// check waits for the running varlatchd to answer `admin status` as
// version, serving its database: schema, Root KEK and installation ready.
func (u *Upgrader) check(ctx context.Context, version string, schema int64) error {
	timeout := u.HealthTimeout
	if timeout == 0 {
		timeout = time.Minute
	}
	deadline := time.Now().Add(timeout)
	last := "it did not answer"
	for {
		out, err := u.admin(ctx, u.varlatchd(), "admin", "status", "--json")
		if err == nil {
			var st struct {
				Version       string `json:"version"`
				SchemaVersion int64  `json:"schemaVersion"`
				Serving       bool   `json:"serving"`
				Ready         struct {
					Schema       bool `json:"schema"`
					RootKEK      bool `json:"rootKek"`
					Installation bool `json:"installation"`
				} `json:"ready"`
			}
			switch {
			case json.Unmarshal(out, &st) != nil:
				last = "its status is not one varlatchd gives"
			case st.Version != version:
				last = fmt.Sprintf("it runs %s, not %s", st.Version, version)
			case st.SchemaVersion != schema:
				last = fmt.Sprintf("its schema is version %d, not %d", st.SchemaVersion, schema)
			case !st.Serving:
				last = "it does not serve yet"
			case !st.Ready.Schema || !st.Ready.RootKEK || !st.Ready.Installation:
				last = fmt.Sprintf("it is not ready (schema %v, Root KEK %v, installation %v)", st.Ready.Schema, st.Ready.RootKEK, st.Ready.Installation)
			default:
				return nil
			}
		} else {
			last = err.Error()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("after %s: %s", timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// promote ends a checked upgrade: the copy's and the original's leftovers
// go, the snapshot and the kept binaries stay.
func (u *Upgrader) promote(j *journal.Journal) error {
	for _, dir := range []string{filepath.Join(j.Work, "db"), filepath.Join(j.Work, "original")} {
		if err := os.RemoveAll(dir); err != nil {
			u.logf("Could not remove %s: %v", dir, err)
		}
	}
	j.State, j.Reason = journal.Done, ""
	if err := u.write(j); err != nil {
		return err
	}
	u.logf("varlatchd %s serves, after its health checks.", j.To)
	return nil
}

// undo brings the host back to the previous release on its database as it
// was, from wherever j stands; it records undone, or failed with what is
// left. It never takes the service to be running: whatever happened, it
// ends by starting the previous release (nothing to do for one that runs)
// and checking it.
func (u *Upgrader) undo(ctx context.Context, j *journal.Journal, why string) error {
	j.Reason = why
	var left []string
	if j.Reached(journal.Stopping) {
		// The service may be down, and from Prepared on the database and
		// the binaries may be the new release's.
		if err := u.Service.Stop(ctx); err != nil {
			left = append(left, err.Error())
		}
		if err := u.point("undo:stopped"); err != nil {
			return err
		}
		original := filepath.Join(j.Work, "original")
		for _, name := range databaseFiles {
			from := filepath.Join(original, name)
			if _, err := os.Stat(from); err != nil {
				continue
			}
			to := filepath.Join(j.DataDir, name)
			if err := os.Remove(to); err != nil && !errors.Is(err, fs.ErrNotExist) {
				left = append(left, err.Error())
				continue
			}
			if err := os.Rename(from, to); err != nil {
				left = append(left, err.Error())
			}
		}
		if j.Reached(journal.Prepared) {
			if err := u.install(j, j.From); errors.Is(err, errKilled) {
				return err
			} else if err != nil {
				left = append(left, "the previous binaries: "+err.Error())
			}
		}
		// The restored names are on disk before the journal records the undo.
		syncDir(j.DataDir)
		syncDir(original)
		os.RemoveAll(filepath.Join(j.Work, "db"))
		if err := u.point("undo:restored"); err != nil {
			return err
		}
	} else {
		// The service was never stopped: the staged release goes, the
		// snapshot stays with the upgrade.
		os.RemoveAll(filepath.Join(j.Releases, j.To))
	}
	if len(left) == 0 {
		if err := u.Service.Start(ctx); err != nil {
			left = append(left, "starting varlatchd "+j.From+": "+err.Error())
		} else if err := u.check(ctx, j.From, j.FromSchema); err != nil {
			left = append(left, fmt.Sprintf("the health checks of %s: %v", j.From, err))
		}
	}
	if len(left) > 0 {
		j.State = journal.Failed
		j.Reason = fmt.Sprintf("%s; the undo did not complete: %s. The pre-upgrade snapshot is %s (varlatchd admin backup restore --in <it>, varlatchd stopped)", why, strings.Join(left, "; "), j.Snapshot)
		if err := u.write(j); err != nil {
			return fmt.Errorf("the upgrade to %s failed, its undo did not complete (%s), and the journal could not record it: %v", j.To, j.Reason, err)
		}
		return fmt.Errorf("the upgrade to %s failed and its undo did not complete: %s", j.To, j.Reason)
	}
	j.State = journal.Undone
	if err := u.write(j); err != nil {
		return fmt.Errorf("the upgrade to %s was undone (%s serves, after its checks), but the journal could not record it: %v", j.To, j.From, err)
	}
	if j.Reached(journal.Stopping) {
		u.logf("Undone: %s serves again, on its database as it was, after its health checks.", j.From)
	} else {
		u.logf("Undone: nothing was changed; %s serves, after its health checks.", j.From)
	}
	return nil
}

// Recover finishes or undoes an upgrade the journal says is not over: one
// interrupted after its checks is finished, any other undone (a failed
// undo is tried again). It returns the journal, nil when nothing was
// pending.
func (u *Upgrader) Recover(ctx context.Context) (*journal.Journal, error) {
	unlock, err := lock(u.configDir())
	if err != nil {
		return nil, &Error{Message: err.Error()}
	}
	defer unlock()
	j, err := journal.Read(u.configDir())
	if err != nil {
		return nil, &Error{Message: err.Error()}
	}
	if !j.Pending() {
		return nil, nil
	}
	if j.State == journal.InProgress && j.Reached(journal.Checked) {
		if err := u.promote(j); err != nil {
			return j, &Error{Message: err.Error(), Journal: j}
		}
		return j, nil
	}
	why := j.Reason
	if j.State == journal.InProgress {
		why = fmt.Sprintf("interrupted after step %q", j.Step)
		if j.Step == journal.None {
			why = "interrupted before its first step"
		}
	}
	j.State = journal.InProgress
	if err := u.undo(ctx, j, why); err != nil {
		if errors.Is(err, errKilled) {
			return j, err
		}
		return j, &Error{Message: err.Error(), Journal: j}
	}
	return j, nil
}

// prune removes upgrades' directories older than keepSnapshots, but never
// the journal's own.
func (u *Upgrader) prune(dataDir string) {
	current := ""
	if j, err := journal.Read(u.configDir()); err == nil && j != nil {
		current = j.ID
	}
	entries, err := os.ReadDir(filepath.Join(dataDir, "upgrades"))
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !e.IsDir() || e.Name() == current || u.now().Sub(info.ModTime()) < keepSnapshots {
			continue
		}
		os.RemoveAll(filepath.Join(dataDir, "upgrades", e.Name()))
	}
}

// workDir makes dir (and its parents in the data directory) the data
// directory owner's, private.
func (u *Upgrader) workDir(j *journal.Journal, dir string) error {
	if err := upgradesDir(j.DataDir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for d := dir; d != j.DataDir && strings.HasPrefix(d, j.DataDir); d = filepath.Dir(d) {
		owned(d, j.DataDir)
	}
	return nil
}

func (u *Upgrader) fault(path string) error {
	if u.Fault != nil {
		return u.Fault(path)
	}
	return nil
}

// writeFile writes data to path whole and synced.
func (u *Upgrader) writeFile(path string, data []byte, mode os.FileMode) error {
	if err := u.fault(path); err != nil {
		return err
	}
	return release.WriteDurably(path, data, mode)
}

// copyFile copies src to dst, synced, with mode.
func (u *Upgrader) copyFile(src, dst string, mode os.FileMode) error {
	if err := u.fault(dst); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Chmod(mode); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// ownAll gives every file in dir the data directory owner's ownership.
func ownAll(dir, dataDir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		owned(filepath.Join(dir, e.Name()), dataDir)
	}
	return nil
}

// spaceMargin is kept free beyond what an upgrade writes.
const spaceMargin = 64 << 20

// FreeSpace is the space free to root on path's filesystem and that
// filesystem's identity; a variable so the tests can run a full disk.
var FreeSpace = freeSpace

// enoughSpace refuses an upgrade the disks cannot hold, before anything is
// written: on the data directory's filesystem, a copy of the database (and
// its log) and a snapshot of about its size; on the binaries' filesystem,
// the new binaries staged and written beside their places, and the
// installed ones kept; each with spaceMargin to spare.
func (u *Upgrader) enoughSpace(inst Installed, rel Release) error {
	var db int64
	for _, name := range databaseFiles {
		if info, err := os.Stat(filepath.Join(inst.DataDir, name)); err == nil {
			db += info.Size()
		}
	}
	var installed int64
	for _, name := range []string{"varlatch", "varlatchd"} {
		if info, err := os.Stat(filepath.Join(u.BinDir, name)); err == nil {
			installed += info.Size()
		}
	}
	binaries := 2*int64(len(rel.Varlatch)+len(rel.Varlatchd)) + installed
	// What each filesystem must hold: one sum when both are on one.
	type fsNeed struct {
		path        string
		bytes, free int64
		what        []string
	}
	var needs []*fsNeed
	byFS := map[uint64]*fsNeed{}
	for _, n := range []struct {
		path  string
		bytes int64
		what  string
	}{{inst.DataDir, 2 * db, "a copy of the database and a snapshot"}, {u.BinDir, binaries, "the new binaries and the kept ones"}} {
		free, fsid, err := FreeSpace(n.path)
		if err != nil {
			// Unknown: the writes themselves still fail cleanly.
			continue
		}
		if byFS[fsid] == nil {
			byFS[fsid] = &fsNeed{path: n.path, free: int64(free)}
			needs = append(needs, byFS[fsid])
		}
		byFS[fsid].bytes += n.bytes
		byFS[fsid].what = append(byFS[fsid].what, n.what)
	}
	for _, n := range needs {
		if want := n.bytes + spaceMargin; n.free < want {
			return fmt.Errorf("not enough space on the filesystem of %s: the upgrade needs %d MiB free there (%s, and %d MiB to spare), it has %d MiB",
				n.path, want>>20, strings.Join(n.what, ", "), spaceMargin>>20, n.free>>20)
		}
	}
	return nil
}
