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
//	           binaries are kept beside them; the SHA-256 of all four is in
//	           the journal, and nothing else is put in place or run
//	snapshot   `varlatchd admin backup run`: the pre-upgrade snapshot, an
//	           archive encrypted with the Backup Encryption Key, kept with the
//	           upgrade for 30 days (backup_keep's pruning never reaches it)
//	stopping   recorded before the stop: from here until checked, varlatchd
//	           starts only as the journal allows (its Start)
//	stopped    varlatchd is stopped
//	prepared   a copy of the database gets the new release's schema
//	           (`varlatchd admin schema upgrade --database`, the new
//	           varlatchd), and is one file
//	kept       the original database's files have second names, a set that
//	           stays whole until the upgrade is over
//	installed  the new binaries replace the old ones: from here the varlatchd
//	           in place is one that reads the journal
//	swapped    the copy takes the database's place, by one rename
//	started    varlatchd is started
//	checked    the new varlatchd answers `admin status` as the new release,
//	           serving, its schema, Root KEK and installation ready; nothing
//	           else counts as healthy (unknown blocks like a failure). From
//	           here on the upgrade is only ever finished
//
// Before anything is written, the disks must hold the upgrade (a copy of
// the database, a snapshot, the binaries, a margin). A failure before the
// stop changes nothing; a failure after it, or failed checks, stops
// varlatchd, puts the original database back from its set, then the
// previous binaries, each recorded, and ends by starting the previous
// release and checking it: it never takes the service to be running. An
// interrupted upgrade (a kill, a power cut) is finished or undone by the
// next run (Recover) from the journal: after checked it is finished, before
// it undone, the undo going on from where it got. An undo that cannot
// complete is recorded as failed, with what is left and the snapshot to
// restore from.
//
// The database is never changed in place: the schema update writes the
// copy, and an undo puts back the files the original release last wrote.
// What is done in the data directory is done as its owner (datadir.go).
package upgrade

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/release"
	journal "github.com/varlatch/varlatch/go/lib/upgradejournal"
)

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
	// its data directory.
	Version string
	Schema  int64
	DataDir string
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
	// ChildProgram is the program that runs the data directory's work as
	// its owner; "" is this one.
	ChildProgram string
	// Crash, ChildCrash, Fault and trace are the tests' seams: Crash stops
	// the run at a named point as a kill would (nothing undone), ChildCrash
	// names the one at which the owner's child is killed; Fault fails a
	// write to a path as a full disk would; trace is told each change of
	// the data directory made in this process.
	Crash      func(point string) bool
	ChildCrash string
	Fault      func(path string) error
	trace      func(fsEvent)
	boot       func() string
	// run stands in for running a varlatchd (the tests').
	run func(binary string, args ...string) ([]byte, error)
}

func (u *Upgrader) bootID() string {
	if u.boot != nil {
		return u.boot()
	}
	return bootID()
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
	if u.run != nil {
		return u.run(binary, args...)
	}
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
	if !st.Opens || st.Database.SchemaVersion != st.Binary.SchemaVersion {
		return Installed{}, fmt.Errorf("the database's schema (version %d) is not the installed varlatchd's (%d): check the installation (varlatch doctor) before an upgrade", st.Database.SchemaVersion, st.Binary.SchemaVersion)
	}
	return Installed{Version: version, Schema: st.Binary.SchemaVersion, DataDir: st.DataDir}, nil
}

// write records j.
func (u *Upgrader) write(j *journal.Journal) error {
	if err := u.fault(filepath.Join(u.configDir(), journal.File)); err != nil {
		return err
	}
	j.UpdatedAt = u.now().UTC().Format(time.RFC3339)
	return journal.Write(u.configDir(), j)
}

// reach records step s, the start allowed before it gone, then stops there
// if a test kills the run.
func (u *Upgrader) reach(j *journal.Journal, s journal.Step) error {
	was, start := j.Step, j.Start
	j.Step, j.Start = s, nil
	if err := u.write(j); err != nil {
		if !errors.Is(err, release.ErrNotDurable) {
			// The journal on disk is the one before.
			j.Step, j.Start = was, start
		}
		return err
	}
	return u.point(string(s))
}

// undone records how far an undo got.
func (u *Upgrader) undone(j *journal.Journal, s journal.UndoStep) error {
	j.Undo, j.Start = s, nil
	if err := u.write(j); err != nil {
		return err
	}
	return u.point("undo:" + string(s))
}

func (u *Upgrader) point(name string) error {
	if u.Crash != nil && u.Crash(name) {
		return errKilled
	}
	return nil
}

func (u *Upgrader) fault(path string) error {
	if u.Fault != nil {
		return u.Fault(path)
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
	prev, err := journal.Read(u.configDir())
	if err != nil {
		return nil, &Error{Message: err.Error()}
	} else if prev.Pending() {
		return prev, &Error{Message: fmt.Sprintf("an upgrade from %s to %s is not over (%s at step %q): run varlatch upgrade again to finish or undo it first", prev.From, prev.To, prev.State, prev.Step), Journal: prev}
	}
	m := rel.Manifest
	if m.Version != rel.Version {
		return nil, &Error{Message: fmt.Sprintf("the release's manifest is for %s, not %s; nothing was changed", m.Version, rel.Version)}
	}
	if err := u.trusted(); err != nil {
		return nil, &Error{Message: err.Error() + "; nothing was changed"}
	}
	// <data>/upgrades is checked before anything reads or removes there.
	if _, err := u.data(ctx, dataOp{Op: "begin", DataDir: inst.DataDir}); err != nil {
		return nil, &Error{Message: err.Error() + "; nothing was changed"}
	}
	keep := []string{}
	if prev != nil {
		keep = append(keep, prev.ID)
	}
	if _, err := u.data(ctx, dataOp{Op: "prune", DataDir: inst.DataDir, Keep: keep, Before: u.now().Add(-keepSnapshots)}); err != nil {
		u.logf("Could not remove what earlier upgrades left: %v", err)
	}
	if err := u.enoughSpace(ctx, inst, rel); err != nil {
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
	switch {
	case err == nil:
		return j, nil
	case errors.Is(err, errKilled):
		return j, err
	case j.Reached(journal.Checked):
		// Its checks passed, and the journal says so: never undone.
		return j, &Error{Message: u.unfinished(j, err), Journal: j}
	}
	reason := err.Error()
	if uerr := u.undo(ctx, j, reason); uerr != nil {
		if errors.Is(uerr, errKilled) {
			return j, uerr
		}
		return j, &Error{Message: uerr.Error(), Journal: j}
	}
	return j, &Error{Message: fmt.Sprintf("the upgrade to %s did not complete (%s); it was undone: %s serves, on its database as it was", rel.Version, reason, inst.Version), Journal: j}
}

// unfinished says that a checked upgrade's end could not be recorded.
func (u *Upgrader) unfinished(j *journal.Journal, err error) string {
	return fmt.Sprintf("%s serves, after its health checks, but the upgrade's end could not be recorded: %v. Run sudo varlatch upgrade to finish it", j.To, err)
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
	// journal that says the service may be down, and that it may not start.
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

	if _, err := u.data(ctx, dataOp{Op: "keep-original", DataDir: j.DataDir, ID: j.ID}); err != nil {
		return fmt.Errorf("keeping the original database: %w", err)
	}
	if err := u.reach(j, journal.Kept); err != nil {
		return err
	}
	// The binaries before the database: whatever is started from here on is
	// a varlatchd that reads the journal.
	if err := u.install(j, j.To, j.Binaries.To, binaryNames...); err != nil {
		return fmt.Errorf("putting %s's binaries in place: %w", j.To, err)
	}
	if err := u.reach(j, journal.Installed); err != nil {
		return err
	}
	if _, err := u.data(ctx, dataOp{Op: "swap", DataDir: j.DataDir, ID: j.ID}); err != nil {
		return fmt.Errorf("putting the updated database in place: %w", err)
	}
	if err := u.reach(j, journal.Swapped); err != nil {
		return err
	}

	if err := u.start(ctx, j, j.To); err != nil {
		return err
	}
	if err := u.reachStarted(j); err != nil {
		return err
	}
	if err := u.check(ctx, j.To, j.ToSchema); err != nil {
		return fmt.Errorf("the health checks of %s: %w", j.To, err)
	}
	if err := u.reach(j, journal.Checked); err != nil {
		return err
	}
	return u.promote(ctx, j)
}

// start records that version may start, now, and starts varlatchd.
func (u *Upgrader) start(ctx context.Context, j *journal.Journal, version string) error {
	if j.Format != journal.FormatOne {
		j.Start = &journal.Start{Version: version, BootID: u.bootID(), At: u.now().UTC().Format(time.RFC3339)}
		if err := u.write(j); err != nil {
			return err
		}
	}
	if err := u.point("start:" + version); err != nil {
		return err
	}
	if err := u.Service.Start(ctx); err != nil {
		return fmt.Errorf("starting varlatchd %s: %w", version, err)
	}
	return nil
}

// reachStarted records Started, the start it allowed still allowed: the
// unit may start varlatchd again (Restart=) while it is checked.
func (u *Upgrader) reachStarted(j *journal.Journal) error {
	j.Step = journal.Started
	if err := u.write(j); err != nil {
		return err
	}
	return u.point(string(journal.Started))
}

// trusted checks that the binaries' directories are root's, so what is kept
// there, and checked, is what runs.
func (u *Upgrader) trusted() error {
	if err := os.MkdirAll(u.Releases(), 0o755); err != nil {
		return err
	}
	for _, dir := range []string{u.BinDir, u.Releases()} {
		if err := rootOwned(dir); err != nil {
			return err
		}
	}
	return nil
}

var binaryNames = []string{"varlatchd", "varlatch"}

func sumOf(b journal.BinarySums, name string) string {
	if name == "varlatch" {
		return b.Varlatch
	}
	return b.Varlatchd
}

// stage writes the new release's binaries into Releases/<to>, and keeps
// the installed ones in Releases/<from>, replacing what is there under
// those names that is not them; and records the SHA-256 of each: the new
// ones' as downloaded and verified, the installed ones' as installed.
func (u *Upgrader) stage(j *journal.Journal, rel Release) error {
	sums := &journal.Binaries{}
	for _, v := range []struct {
		version string
		sums    *journal.BinarySums
		open    func(name string) (io.ReadCloser, error)
	}{
		{j.To, &sums.To, func(name string) (io.ReadCloser, error) {
			if name == "varlatch" {
				return io.NopCloser(bytes.NewReader(rel.Varlatch)), nil
			}
			return io.NopCloser(bytes.NewReader(rel.Varlatchd)), nil
		}},
		{j.From, &sums.From, func(name string) (io.ReadCloser, error) { return os.Open(filepath.Join(u.BinDir, name)) }},
	} {
		dir := filepath.Join(j.Releases, v.version)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("staging: %w", err)
		}
		if err := rootOwned(dir); err != nil {
			return fmt.Errorf("staging: %w", err)
		}
		for _, name := range binaryNames {
			r, err := v.open(name)
			if err != nil {
				return fmt.Errorf("staging %s's %s: %w", v.version, name, err)
			}
			sum, err := u.putBinary(filepath.Join(dir, name), r, "")
			r.Close()
			if err != nil {
				return fmt.Errorf("staging %s's %s: %w", v.version, name, err)
			}
			if name == "varlatch" {
				v.sums.Varlatch = sum
			} else {
				v.sums.Varlatchd = sum
			}
		}
		if err := u.rootFS().syncDir(dir); err != nil {
			return fmt.Errorf("staging: %w", err)
		}
	}
	if err := u.rootFS().syncDir(j.Releases); err != nil {
		return fmt.Errorf("staging: %w", err)
	}
	j.Binaries = sums
	return nil
}

// rootFS is the file system for root's own directories.
func (u *Upgrader) rootFS() fsys { return fsys{fault: u.Fault} }

// putBinary puts r's content at path, whole, through a temporary name, when
// its SHA-256 is want ("" for any), and returns it.
func (u *Upgrader) putBinary(path string, r io.Reader, want string) (string, error) {
	if err := u.fault(path); err != nil {
		return "", err
	}
	temp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".new")
	f := u.rootFS()
	if err := f.remove(temp); err != nil {
		return "", err
	}
	sum, err := f.create(temp, 0o755, r)
	if err != nil {
		return "", err
	}
	if want != "" && sum != want {
		_ = os.Remove(temp)
		return "", fmt.Errorf("it is not the one the upgrade recorded (SHA-256 %s, not %s)", sum, want)
	}
	if err := f.rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return "", err
	}
	return sum, nil
}

// snapshot takes the pre-upgrade archive with the installed varlatchd and
// keeps it in the upgrade's directory.
func (u *Upgrader) snapshot(ctx context.Context, j *journal.Journal) error {
	if _, err := u.data(ctx, dataOp{Op: "begin", DataDir: j.DataDir, ID: j.ID}); err != nil {
		return err
	}
	out, err := u.admin(ctx, u.varlatchd(), "admin", "backup", "run", "--json")
	if err != nil {
		return err
	}
	var res struct {
		Path      string `json:"path"`
		CreatedAt string `json:"createdAt"`
	}
	if err := json.Unmarshal(out, &res); err != nil || res.Path == "" {
		return errors.New("varlatchd admin backup run named no archive")
	}
	kept, err := u.data(ctx, dataOp{Op: "keep-snapshot", DataDir: j.DataDir, ID: j.ID, Archive: res.Path})
	if err != nil {
		return err
	}
	j.Snapshot, j.SnapshotSHA256, j.SnapshotAt = kept.Path, kept.SHA256, res.CreatedAt
	return nil
}

// prepare copies the stopped varlatchd's database files into the upgrade's
// directory and runs the new varlatchd's schema update on the copy.
func (u *Upgrader) prepare(ctx context.Context, j *journal.Journal) error {
	if _, err := u.data(ctx, dataOp{Op: "copy-database", DataDir: j.DataDir, ID: j.ID}); err != nil {
		return err
	}
	newd, err := u.kept(j, j.To, "varlatchd")
	if err != nil {
		return err
	}
	out, err := u.admin(ctx, newd, "admin", "schema", "upgrade", "--json", "--database", filepath.Join(j.Work, copyDir, databaseFile))
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
	_, err = u.data(ctx, dataOp{Op: "settle", DataDir: j.DataDir, ID: j.ID})
	return err
}

// kept is a kept release's binary, once it is the one the journal records
// and nobody but root can change it.
func (u *Upgrader) kept(j *journal.Journal, version, name string) (string, error) {
	path := filepath.Join(j.Releases, version, name)
	if err := rootOwned(path); err != nil {
		return "", err
	}
	if j.Binaries == nil {
		return path, nil // format 1 records none
	}
	want := j.Binaries.To
	if version == j.From {
		want = j.Binaries.From
	}
	sum, err := fileSum(path)
	if err != nil {
		return "", err
	}
	if sum != sumOf(want, name) {
		return "", fmt.Errorf("%s is not the one the upgrade recorded (SHA-256 %s, not %s): it is not run", path, sum, sumOf(want, name))
	}
	return path, nil
}

// install puts version's kept binaries of these names, of these SHA-256s, in
// BinDir.
func (u *Upgrader) install(j *journal.Journal, version string, sums journal.BinarySums, names ...string) error {
	for _, name := range names {
		if _, err := u.kept(j, version, name); err != nil {
			return err
		}
	}
	for _, name := range names {
		r, err := os.Open(filepath.Join(j.Releases, version, name))
		if err != nil {
			return err
		}
		_, err = u.putBinary(filepath.Join(u.BinDir, name), r, sumOf(sums, name))
		r.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := u.point("install:" + version + ":" + name); err != nil {
			return err
		}
	}
	return u.rootFS().syncDir(u.BinDir)
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

// promote ends a checked upgrade: recorded first, durably, then the copy's
// and the original's leftovers go; the snapshot and the kept binaries stay.
func (u *Upgrader) promote(ctx context.Context, j *journal.Journal) error {
	j.State, j.Reason, j.Start = journal.Done, "", nil
	if err := u.write(j); err != nil {
		j.State = journal.InProgress
		return err
	}
	if err := u.point("done"); err != nil {
		return err
	}
	if err := u.tidy(ctx, j); err != nil {
		return err
	}
	u.logf("varlatchd %s serves, after its health checks.", j.To)
	return nil
}

// tidy removes what an ended upgrade left in the data directory; what it
// cannot remove, the next run, or the next upgrade's prune, does. Its error
// is a test's kill.
func (u *Upgrader) tidy(ctx context.Context, j *journal.Journal) error {
	_, err := u.data(ctx, dataOp{Op: "clean", DataDir: j.DataDir, ID: j.ID})
	if errors.Is(err, errKilled) {
		return err
	}
	if err != nil {
		u.logf("Could not remove what the upgrade left in %s: %v", j.Work, err)
	}
	return nil
}

// undo brings the host back to the previous release on its database as it
// was, from wherever j stands, and from wherever an undo before got (Undo):
// varlatchd stopped, the original database back from its set, then the
// previous binaries, each recorded before the next; then the previous
// release started and checked, and the undo recorded. It records failed,
// with what is left, when one of them fails. It never takes the service to
// be running. It has no deadline but its checks': the one the upgrade ran
// under may be what stopped it.
func (u *Upgrader) undo(ctx context.Context, j *journal.Journal, why string) error {
	ctx = context.WithoutCancel(ctx)
	j.Reason = why
	if j.Reached(journal.Stopping) {
		if err := u.restore(ctx, j); errors.Is(err, errKilled) {
			return err
		} else if err != nil {
			return u.failed(j, why, err)
		}
	} else {
		// The service was never stopped: the staged release goes, the
		// snapshot stays with the upgrade.
		_ = os.RemoveAll(filepath.Join(j.Releases, j.To))
	}
	if err := u.start(ctx, j, j.From); errors.Is(err, errKilled) {
		return err
	} else if err != nil {
		return u.failed(j, why, err)
	}
	if err := u.check(ctx, j.From, j.FromSchema); err != nil {
		return u.failed(j, why, fmt.Errorf("the health checks of %s: %w", j.From, err))
	}
	if err := u.point("undo:checked"); err != nil {
		return err
	}
	j.State, j.Start = journal.Undone, nil
	err := u.write(j)
	if err == nil && older(j) {
		err = u.leave(j)
	}
	if errors.Is(err, errKilled) {
		return err
	}
	if err != nil {
		j.State = journal.InProgress
		return fmt.Errorf("the upgrade to %s was undone (%s serves, after its checks), but the journal could not record it: %v", j.To, j.From, err)
	}
	if err := u.point("undone"); err != nil {
		return err
	}
	if err := u.tidy(ctx, j); err != nil {
		return err
	}
	if j.Reached(journal.Stopping) {
		u.logf("Undone: %s serves again, on its database as it was, after its health checks.", j.From)
	} else {
		u.logf("Undone: nothing was changed; %s serves, after its health checks.", j.From)
	}
	return nil
}

// older is whether the release an upgrade came from reads no journal of this
// format: its varlatch would refuse it, so it is put back only once the
// journal is away (leave), and until then the new one, which can go on.
func older(j *journal.Journal) bool {
	order, ok := release.CompareVersions(j.From, journal.FormatSince)
	return j.Format != journal.FormatOne && ok && order < 0
}

// leave moves an undone upgrade's journal aside, then puts the older
// release's varlatch back.
func (u *Upgrader) leave(j *journal.Journal) error {
	if err := os.Rename(filepath.Join(u.configDir(), journal.File), filepath.Join(u.configDir(), "upgrade-"+j.ID+".json")); err != nil {
		return err
	}
	if err := u.rootFS().syncDir(u.configDir()); err != nil {
		return err
	}
	if err := u.point("journal-aside"); err != nil {
		return err
	}
	if !j.Reached(journal.Kept) {
		return nil
	}
	if err := u.install(j, j.From, j.Binaries.From, "varlatch"); err != nil {
		if errors.Is(err, errKilled) {
			return err
		}
		u.logf("%s's varlatch is not back in %s (%v): install it, or go on with %s's.", j.From, u.BinDir, err, j.To)
	}
	return nil
}

// restore stops varlatchd and puts the original database and the previous
// binaries back, as far as they were replaced and are not back yet.
func (u *Upgrader) restore(ctx context.Context, j *journal.Journal) error {
	if j.Start != nil {
		// Whatever start was allowed is not any more.
		j.Start = nil
		if err := u.write(j); err != nil {
			return err
		}
	}
	if err := u.Service.Stop(ctx); err != nil {
		return fmt.Errorf("stopping varlatchd: %w", err)
	}
	if err := u.point("undo:stopped"); err != nil {
		return err
	}
	if j.Format == journal.FormatOne {
		return u.restoreFormatOne(ctx, j)
	}
	// Until the new binaries are in place nothing was swapped: the database
	// is the previous release's, and what it may have written since (one
	// that does not read the journal, started by a reboot) stays.
	if j.Undo == journal.UndoNone && j.Reached(journal.Installed) {
		if _, err := u.data(ctx, dataOp{Op: "put-back", DataDir: j.DataDir, ID: j.ID}); err != nil {
			return fmt.Errorf("the original database: %w", err)
		}
		if err := u.undone(j, journal.FilesBack); err != nil {
			return err
		}
	}
	if j.Undo != journal.BinariesBack && j.Reached(journal.Kept) {
		names := binaryNames
		if older(j) {
			names = []string{"varlatchd"}
		}
		if err := u.install(j, j.From, j.Binaries.From, names...); err != nil {
			if errors.Is(err, errKilled) {
				return err
			}
			return fmt.Errorf("%s's binaries: %w", j.From, err)
		}
		if err := u.undone(j, journal.BinariesBack); err != nil {
			return err
		}
	}
	return nil
}

// restoreFormatOne undoes an upgrade an earlier release's varlatch (0.50.0
// before rc.4) left pending: its database files moved aside one by one, no
// set of them, and no SHA-256 of its binaries.
func (u *Upgrader) restoreFormatOne(ctx context.Context, j *journal.Journal) error {
	if _, err := u.data(ctx, dataOp{Op: "put-back-1", DataDir: j.DataDir, ID: j.ID}); err != nil {
		return fmt.Errorf("the original database: %w", err)
	}
	if err := u.point("undo:" + string(journal.FilesBack)); err != nil {
		return err
	}
	if !j.Reached(journal.Prepared) {
		return nil
	}
	for _, name := range binaryNames {
		path, err := u.kept(j, j.From, name)
		if err != nil {
			return fmt.Errorf("%s's binaries: %w", j.From, err)
		}
		r, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = u.putBinary(filepath.Join(u.BinDir, name), r, "")
		r.Close()
		if err != nil {
			return fmt.Errorf("%s's %s: %w", j.From, name, err)
		}
	}
	return u.rootFS().syncDir(u.BinDir)
}

// failed records an undo that did not complete, with what is left.
func (u *Upgrader) failed(j *journal.Journal, why string, left error) error {
	j.State, j.Start = journal.Failed, nil
	j.Reason = fmt.Sprintf("%s; the undo did not complete: %v. varlatchd does not start until it does: put right what it says, then run sudo varlatch upgrade. The pre-upgrade snapshot is %s", why, left, j.Snapshot)
	if errors.Is(left, errNoOriginal) {
		j.Reason = fmt.Sprintf("%s; the undo did not complete: %v. Put the original database's files back into %s, then run sudo varlatch upgrade; or restore the pre-upgrade snapshot %s (varlatchd admin backup restore --in <it>)",
			why, left, filepath.Join(j.Work, originalDir), j.Snapshot)
	}
	if err := u.write(j); err != nil {
		return fmt.Errorf("the upgrade to %s failed, its undo did not complete (%s), and the journal could not record it: %v", j.To, j.Reason, err)
	}
	return fmt.Errorf("the upgrade to %s failed and its undo did not complete: %s", j.To, j.Reason)
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
		// One that is over, and was stopped before it had tidied up.
		if j != nil && (exists(filepath.Join(j.Work, originalDir)) || exists(filepath.Join(j.Work, copyDir))) {
			if err := u.tidy(ctx, j); err != nil {
				return j, err
			}
		}
		return nil, nil
	}
	if j.State == journal.InProgress && j.Reached(journal.Checked) {
		if err := u.promote(ctx, j); errors.Is(err, errKilled) {
			return j, err
		} else if err != nil {
			return j, &Error{Message: u.unfinished(j, err), Journal: j}
		}
		return j, nil
	}
	why := j.Reason
	if j.State == journal.InProgress && why == "" {
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
func (u *Upgrader) enoughSpace(ctx context.Context, inst Installed, rel Release) error {
	size, err := u.data(ctx, dataOp{Op: "size", DataDir: inst.DataDir})
	if err != nil {
		return err
	}
	db := size.Bytes
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
