// SPDX-License-Identifier: Apache-2.0

package upgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
)

// What an upgrade does in the data directory, each piece of it one op
// (dataOp): as the directory's owner, the user varlatchd runs as. That user
// may write there, so root, working by name, could be led elsewhere by a
// link, and what it made would be root's. Run as root, an op runs in a
// child process of this program that is the owner (ChildCommand); as anyone
// else, in this process.
//
// Every op can be run again after it was stopped at any point of itself.

// databaseFile is the database's name in the data directory; its
// write-ahead log belongs to it and to no other, and its index (-shm) is
// made again.
const (
	databaseFile = "varlatch.db"
	walSuffix    = "-wal"
	shmSuffix    = "-shm"
	lockFile     = "varlatchd.lock"
)

// An upgrade's directory is <data>/upgrades/<id>. In it: db, the copy that
// gets the new schema, and original, the database's files as the stopped
// release left them, under the names they had: whole from the moment it has
// its name, and never taken apart until the upgrade's end is recorded.
const (
	copyDir     = "db"
	originalDir = "original"
	makingDir   = ".making"
)

// workDirs are what an upgrade's directory holds while it runs; its snapshot
// stays.
var workDirs = []string{copyDir, copyDir + makingDir, originalDir, originalDir + makingDir}

// dataOp is one op and what it needs.
type dataOp struct {
	Op      string `json:"op"`
	DataDir string `json:"dataDir"`
	ID      string `json:"id,omitempty"`
	// Rollback is put-back's and clean's: the upgrade's directory is a
	// rollback's. Archive is the archive a rollback restores, whose hold is
	// its own.
	Rollback bool   `json:"rollback,omitempty"`
	Archive  string `json:"archive,omitempty"`
	// Keep is prune's: the upgrades' directories that stay.
	Keep []string `json:"keep,omitempty"`
	// Before is prune's: directories last changed before it go.
	Before time.Time `json:"before,omitzero"`
	// Crash is the tests': the child kills itself after this change.
	Crash string `json:"crash,omitempty"`
}

// dataResult is an op's answer.
type dataResult struct {
	// Bytes is size's: the database's files.
	Bytes int64 `json:"bytes,omitempty"`
}

func (o dataOp) work() string { return filepath.Join(o.DataDir, "upgrades", o.ID) }

// run runs the op with f, as this process's user.
func (o dataOp) run(f fsys) (dataResult, error) {
	switch o.Op {
	case "size":
		return o.size()
	case "begin":
		return dataResult{}, o.begin(f)
	case "probe":
		return dataResult{}, f.syncDir(o.DataDir)
	case "copy-database":
		return dataResult{}, o.locked(func() error { return o.copyDatabase(f) })
	case "settle":
		return dataResult{}, o.settle(f)
	case "keep-original":
		return dataResult{}, o.locked(func() error { return o.keepOriginal(f) })
	case "swap":
		return dataResult{}, o.locked(func() error { return o.swap(f) })
	case "put-back":
		return dataResult{}, o.locked(func() error { return o.putBack(f) })
	case "put-back-1":
		return dataResult{}, o.locked(func() error { return o.putBackFormatOne(f) })
	case "clean":
		return dataResult{}, o.clean(f)
	case "prune":
		return dataResult{}, o.prune(f)
	}
	return dataResult{}, fmt.Errorf("no such work: %q", o.Op)
}

// locked runs fn under the data directory's lock, which a varlatchd and its
// offline commands hold while they use the database. A directory without
// the lock file has had no varlatchd.
func (o dataOp) locked(fn func() error) error {
	unlock, err := lockData(filepath.Join(o.DataDir, lockFile))
	if errors.Is(err, errBusy) {
		return fmt.Errorf("a varlatchd, or a varlatchd command, still uses %s: wait until it has ended, then run sudo varlatch upgrade", o.DataDir)
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("the data directory's lock: %w", err)
	}
	if unlock != nil {
		defer unlock()
	}
	// A restore made since (it took the same lock) is not undone over, nor
	// copied as if it were the database the upgrade began on.
	if o.heldByAnother() {
		return fmt.Errorf("%w (%s, %s)", errHeld, filepath.Join(o.DataDir, backup.HoldFile), backup.GateFile)
	}
	return fn()
}

// heldByAnother is whether the installation is held after a restore that is
// not this rollback's own, or such a restore stopped in the middle of itself.
func (o dataOp) heldByAnother() bool {
	own := func(archive string) bool { return o.Rollback && o.Archive != "" && archive == o.Archive }
	if h, err := backup.ReadHold(o.DataDir); err != nil || h != nil && !own(h.ArchiveID) {
		return true
	}
	g, err := backup.ReadGate(o.DataDir)
	return err != nil || g != nil && g.Kind == "restore" && (g.ArchiveID == nil || !own(*g.ArchiveID))
}

// errHeld is an installation restored from an archive since the upgrade
// began.
var errHeld = errors.New("this installation was restored from an archive since the upgrade began, and is held: finishing or undoing the upgrade would replace the restored database")

func (o dataOp) size() (dataResult, error) {
	var r dataResult
	for _, name := range []string{databaseFile, databaseFile + walSuffix} {
		info, err := os.Lstat(filepath.Join(o.DataDir, name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return r, err
		}
		r.Bytes += info.Size()
	}
	return r, nil
}

// begin makes the upgrade's directory, and its name durable up to the data
// directory.
func (o dataOp) begin(f fsys) error {
	upgrades := filepath.Join(o.DataDir, "upgrades")
	info, err := os.Lstat(upgrades)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := f.mkdir(upgrades, 0o700); err != nil {
			return err
		}
	case err != nil:
		return err
	case !info.IsDir():
		return fmt.Errorf("%s is not a directory (a link or another file): an upgrade works only in a real directory there", upgrades)
	}
	if o.ID == "" {
		return nil
	}
	if err := f.mkdir(o.work(), 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := f.syncDir(upgrades); err != nil {
		return err
	}
	return f.syncDir(o.DataDir)
}

// set makes dir, a directory of the upgrade's, with fill's files in it: it
// has its name only once they are all there and durable.
func (o dataOp) set(f fsys, name string, fill func(dir string) error) error {
	dir, making := filepath.Join(o.work(), name), filepath.Join(o.work(), name+makingDir)
	for _, d := range []string{making, dir} {
		if err := f.removeAll(d); err != nil {
			return err
		}
	}
	if err := f.mkdir(making, 0o700); err != nil {
		return err
	}
	if err := fill(making); err != nil {
		return err
	}
	if err := f.syncDir(making); err != nil {
		return err
	}
	if err := f.rename(making, dir); err != nil {
		return err
	}
	return f.syncDir(o.work())
}

// copyDatabase copies the stopped varlatchd's database and its log.
func (o dataOp) copyDatabase(f fsys) error {
	return o.set(f, copyDir, func(dir string) error {
		return o.eachFile(func(name string) error {
			_, err := f.copy(filepath.Join(o.DataDir, name), filepath.Join(dir, name), 0o600)
			return err
		})
	})
}

// eachFile calls fn with the database's name, then its log's when there is
// one. A database that is not there is an error.
func (o dataOp) eachFile(fn func(name string) error) error {
	info, err := os.Lstat(filepath.Join(o.DataDir, databaseFile))
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a file", filepath.Join(o.DataDir, databaseFile))
	}
	if err := fn(databaseFile); err != nil {
		return err
	}
	if exists(filepath.Join(o.DataDir, databaseFile+walSuffix)) {
		return fn(databaseFile + walSuffix)
	}
	return nil
}

// settle checks that the copy, once the new release updated it, is one
// file: its log empty or gone (the update's last connection wrote it back),
// so one rename puts it in place.
func (o dataOp) settle(f fsys) error {
	dir := filepath.Join(o.work(), copyDir)
	if info, err := os.Lstat(filepath.Join(dir, databaseFile+walSuffix)); err == nil && info.Size() > 0 {
		return errors.New("the updated copy's write-ahead log is not written back into it")
	}
	for _, suffix := range []string{walSuffix, shmSuffix} {
		if err := f.remove(filepath.Join(dir, databaseFile+suffix)); err != nil {
			return err
		}
	}
	if err := f.sync(filepath.Join(dir, databaseFile)); err != nil {
		return err
	}
	return f.syncDir(dir)
}

// keepOriginal makes the set of the database's files as they are, under
// second names (hard links; copies where the file system has none). The
// data directory is as it was.
func (o dataOp) keepOriginal(f fsys) error {
	return o.set(f, originalDir, func(dir string) error {
		return o.eachFile(func(name string) error { return keepFile(f, filepath.Join(o.DataDir, name), filepath.Join(dir, name)) })
	})
}

// linkFile is os.Link, or a copy that fails as one does (the tests').
var linkFile = fsys.link

// keepFile gives from a second name to, else copies it.
func keepFile(f fsys, from, to string) error {
	// Durable as it is before anything else has its content.
	if err := f.sync(from); err != nil {
		return err
	}
	err := linkFile(f, from, to)
	if err == nil || errors.Is(err, errKilled) {
		return err
	}
	_, err = f.copy(from, to, 0o600)
	return err
}

// swap puts the updated copy in the database's place. The original's log,
// which is not the copy's, goes first; its set holds it.
func (o dataOp) swap(f fsys) error {
	if !exists(filepath.Join(o.work(), originalDir, databaseFile)) {
		return fmt.Errorf("the original database is not in %s", filepath.Join(o.work(), originalDir))
	}
	if err := o.dropLog(f); err != nil {
		return err
	}
	if err := f.rename(filepath.Join(o.work(), copyDir, databaseFile), filepath.Join(o.DataDir, databaseFile)); err != nil {
		return err
	}
	return f.syncDir(o.DataDir)
}

// dropLog removes the log and index beside the database, durably: SQLite
// would apply a log to whatever database has its name.
func (o dataOp) dropLog(f fsys) error {
	for _, suffix := range []string{walSuffix, shmSuffix} {
		if err := f.remove(filepath.Join(o.DataDir, databaseFile+suffix)); err != nil {
			return err
		}
	}
	return f.syncDir(o.DataDir)
}

// errNoOriginal is an original that must be there and is not: nothing is
// put in its place, and nothing is started.
var errNoOriginal = errors.New("the original database is gone")

// putBack puts the original database and its log back, from their set,
// which stays. Whatever is beside the database there is not the
// original's: its log goes first, and the original's comes after it.
func (o dataOp) putBack(f fsys) error {
	original := filepath.Join(o.work(), originalDir)
	if !exists(filepath.Join(original, databaseFile)) {
		return fmt.Errorf("%w: %s must hold it and does not. Nothing was put in its place", errNoOriginal, original)
	}
	if err := o.dropLog(f); err != nil {
		return err
	}
	back := func(name string) error {
		tmp := filepath.Join(o.DataDir, "."+name+".back")
		if err := f.remove(tmp); err != nil {
			return err
		}
		if err := keepFile(f, filepath.Join(original, name), tmp); err != nil {
			return err
		}
		// Two names of one file: rename does nothing, and leaves both.
		if sameFile(tmp, filepath.Join(o.DataDir, name)) {
			return f.remove(tmp)
		}
		return f.rename(tmp, filepath.Join(o.DataDir, name))
	}
	if err := back(databaseFile); err != nil {
		return err
	}
	if err := f.syncDir(o.DataDir); err != nil {
		return err
	}
	if exists(filepath.Join(original, databaseFile+walSuffix)) {
		if err := back(databaseFile + walSuffix); err != nil {
			return err
		}
	}
	if err := f.syncDir(o.DataDir); err != nil {
		return err
	}
	if !o.Rollback {
		return nil
	}
	// The restore this rollback ran, complete or not: its gate, its hold,
	// and what it left. The database they are of is gone.
	// (Another's gate or hold is refused before: heldByAnother.)
	if g, err := backup.ReadGate(o.DataDir); err == nil && g != nil && g.Kind == "restore" {
		if err := f.remove(filepath.Join(o.DataDir, backup.GateFile)); err != nil {
			return err
		}
	}
	for _, name := range restoreLeftovers {
		if err := f.removeAll(filepath.Join(o.DataDir, name)); err != nil {
			return err
		}
	}
	return f.syncDir(o.DataDir)
}

// restoreLeftovers are what a restore leaves besides the database and its
// gate: the hold a complete one leaves, the archive a stopped one had opened
// and the database it had not put in place.
var restoreLeftovers = []string{backup.HoldFile, ".restore-work", databaseFile + ".restore"}

// putBackFormatOne puts back what an upgrade of an earlier release moved
// aside, one file at a time, into original. A log beside a database that
// stands there is that database's and goes first; with none there (its
// swap stopped between the original's files) it is the original's own. It
// stops at the first file it cannot move: a log never goes back without its
// database.
func (o dataOp) putBackFormatOne(f fsys) error {
	original := filepath.Join(o.work(), originalDir)
	if o.another() {
		if err := o.dropLog(f); err != nil {
			return err
		}
	}
	for _, name := range []string{databaseFile, databaseFile + walSuffix} {
		if !exists(filepath.Join(original, name)) {
			continue
		}
		from, to := filepath.Join(original, name), filepath.Join(o.DataDir, name)
		// A move a power cut left with both names is done.
		move := f.rename
		if sameFile(from, to) {
			move = func(from, _ string) error { return f.remove(from) }
		}
		if err := move(from, to); err != nil {
			return err
		}
		for _, dir := range []string{o.DataDir, original} {
			if err := f.syncDir(dir); err != nil {
				return err
			}
		}
	}
	return f.remove(filepath.Join(o.DataDir, databaseFile+shmSuffix))
}

// another is whether a database that is not the original stands in its
// place, which is aside.
func (o dataOp) another() bool {
	original, inPlace := filepath.Join(o.work(), originalDir, databaseFile), filepath.Join(o.DataDir, databaseFile)
	return exists(original) && exists(inPlace) && !sameFile(original, inPlace)
}

func sameFile(a, b string) bool {
	ai, aerr := os.Lstat(a)
	bi, berr := os.Lstat(b)
	return aerr == nil && berr == nil && os.SameFile(ai, bi)
}

// clean removes what an ended upgrade leaves; its snapshot stays.
func (o dataOp) clean(f fsys) error {
	for _, name := range workDirs {
		if o.Rollback && name == originalDir {
			continue // what the rollback lost
		}
		if err := f.removeAll(filepath.Join(o.work(), name)); err != nil {
			return err
		}
	}
	if !exists(o.work()) {
		return nil
	}
	return f.syncDir(o.work())
}

// prune removes upgrades' directories last changed before o.Before, but
// those of o.Keep.
func (o dataOp) prune(f fsys) error {
	entries, err := os.ReadDir(filepath.Join(o.DataDir, "upgrades"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !e.IsDir() || !info.ModTime().Before(o.Before) {
			continue
		}
		kept := false
		for _, id := range o.Keep {
			kept = kept || id == e.Name()
		}
		if !kept {
			if err := f.removeAll(filepath.Join(o.DataDir, "upgrades", e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// ChildCommand is the argument this program runs itself with, as the data
// directory's owner, for one op (its JSON on standard input, its answer on
// standard output). It is not a command of the CLI's: it does nothing its
// caller's own user could not.
const ChildCommand = "__upgrade-data"

// Child is the child's main: its exit status.
func Child(in io.Reader, out, errs io.Writer) int {
	var o dataOp
	if err := json.NewDecoder(io.LimitReader(in, 1<<16)).Decode(&o); err != nil {
		fmt.Fprintln(errs, "not an upgrade's work")
		return 64
	}
	f := fsys{}
	if o.Crash != "" {
		f.after = func(point string) error {
			if "data:"+o.Op+":"+point == o.Crash {
				killSelf()
			}
			return nil
		}
	}
	r, err := o.run(f)
	if err != nil {
		fmt.Fprintln(errs, err)
		for status, known := range childErrors {
			if errors.Is(err, known) {
				return status
			}
		}
		return 1
	}
	if err := json.NewEncoder(out).Encode(r); err != nil {
		return 1
	}
	return 0
}

// childErrors are the errors the child's exit status tells its parent.
var childErrors = map[int]error{3: errNoOriginal, 4: errHeld}

// data runs an op as the data directory's owner.
func (u *Upgrader) data(ctx context.Context, o dataOp) (dataResult, error) {
	uid, gid, child, err := ownerToBe(o.DataDir)
	if err != nil {
		return dataResult{}, err
	}
	if !child {
		return o.run(u.fsys("data:" + o.Op + ":"))
	}
	exe := u.ChildProgram
	if exe == "" {
		exe = "/proc/self/exe"
	}
	if u.Crash != nil {
		o.Crash = u.ChildCrash
	}
	b, err := json.Marshal(o)
	if err != nil {
		return dataResult{}, err
	}
	cmd := exec.CommandContext(ctx, exe, ChildCommand)
	cmd.Stdin = bytes.NewReader(b)
	cmd.Env, cmd.Dir = []string{"PATH=/usr/bin:/bin"}, "/"
	asOwner(cmd, uid, gid)
	u.bind(cmd)
	var out, errs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errs
	if err := cmd.Run(); err != nil {
		if o.Crash != "" && cmd.ProcessState != nil && !cmd.ProcessState.Exited() {
			return dataResult{}, errKilled
		}
		msg := strings.TrimSpace(errs.String())
		if msg == "" {
			msg = err.Error()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if known := childErrors[exit.ExitCode()]; known != nil {
				return dataResult{}, fmt.Errorf("%w%s", known, strings.TrimPrefix(msg, known.Error()))
			}
		}
		return dataResult{}, errors.New(msg)
	}
	var r dataResult
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		return dataResult{}, fmt.Errorf("the upgrade's work %s gave no answer", o.Op)
	}
	return r, nil
}

// fsys is the file system with the tests' seams, its points named with
// prefix.
func (u *Upgrader) fsys(prefix string) fsys {
	return fsys{after: func(point string) error { return u.point(prefix + point) }, trace: u.trace, fault: u.Fault}
}

var errBusy = syscall.EWOULDBLOCK
