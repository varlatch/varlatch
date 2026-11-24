// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Kind is who installed the running binary: "release" (a release's
// binary, which self-update replaces), "homebrew" or "winget" (that
// package manager updates it).
type Kind string

const (
	KindRelease  Kind = "release"
	KindHomebrew Kind = "homebrew"
	KindWinget   Kind = "winget"
)

// Target is the file self-update replaces and who installed it.
type Target struct {
	// Path is the running binary's file, symbolic links resolved: a link on
	// PATH keeps pointing at it.
	Path string
	Kind Kind
}

// Locate is the running binary's file, given os.Executable's answer.
func Locate(executable string) (Target, error) {
	path, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return Target{}, err
	}
	if path, err = filepath.Abs(path); err != nil {
		return Target{}, err
	}
	kind := KindRelease
	for _, p := range []string{executable, path} {
		switch slashed := strings.ToLower(filepath.ToSlash(p)); {
		case strings.Contains(slashed, "/cellar/"), strings.HasPrefix(slashed, "/opt/homebrew/"), strings.HasPrefix(slashed, "/home/linuxbrew/.linuxbrew/"):
			kind = KindHomebrew
		case strings.Contains(slashed, "/winget/packages/"), strings.Contains(slashed, "/winget/links/"):
			kind = KindWinget
		}
	}
	return Target{Path: path, Kind: kind}, nil
}

// PackageManaged is the refusal for a binary a package manager installed,
// "" for a release's binary.
func (t Target) PackageManaged() string {
	switch t.Kind {
	case KindHomebrew:
		return "varlatch is installed with Homebrew at " + t.Path + "; update it with: brew upgrade varlatch"
	case KindWinget:
		return "varlatch is installed with winget at " + t.Path + "; update it with: winget upgrade varlatch"
	}
	return ""
}

// stagePattern names the new binary while it is checked, beside the
// target; on Windows it must end in .exe to run.
func stagePattern() string {
	if runtime.GOOS == "windows" {
		return ".varlatch-self-update-*.exe"
	}
	return ".varlatch-self-update-*"
}

// Install puts d's binary in place of target: written to a new file in
// target's directory, made executable, run once (it must report d's
// version), then renamed over target. Nothing changes at target until the
// rename. On Windows target is renamed aside first (a running file cannot
// be replaced, only renamed); CleanUp removes it on the next run. A rename
// there that another process's hold on a file stops is tried again for a
// few seconds.
func Install(ctx context.Context, d *Download, target string) error {
	dir := filepath.Dir(target)
	f, err := os.CreateTemp(dir, stagePattern())
	if err != nil {
		return writeError(err, target, d.Version)
	}
	staged := f.Name()
	done := false
	defer func() {
		if !done {
			_ = os.Remove(staged)
		}
	}()
	_, err = f.Write(d.Binary)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(staged, 0o755)
	}
	if err != nil {
		return writeError(err, target, d.Version)
	}
	if err := reports(ctx, staged, d.Version); err != nil {
		return err
	}
	if err := replace(ctx, staged, target); err != nil {
		return writeError(err, target, d.Version)
	}
	done = true
	return nil
}

// reports runs the staged binary's --version: it must run on this machine
// and be the version verified.
func reports(ctx context.Context, path, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	out, err := cmd.Output()
	if err != nil {
		return fail("the downloaded varlatch does not run on this machine (%v); nothing was installed", err)
	}
	first, _, _ := bytes.Cut(out, []byte("\n"))
	if got := strings.TrimSpace(string(first)); got != "varlatch "+version && !strings.HasPrefix(got, "varlatch "+version+" ") {
		return fail("the downloaded varlatch reports %q, not %s; nothing was installed", got, version)
	}
	return nil
}

// replace renames staged over target. Windows cannot replace a running
// file, but can rename it: target goes aside first, and comes back if the
// new file cannot take its place.
func replace(ctx context.Context, staged, target string) error {
	if runtime.GOOS != "windows" {
		return os.Rename(staged, target)
	}
	aside := target + ".old"
	if err := os.Remove(aside); err != nil && !errors.Is(err, fs.ErrNotExist) {
		// An earlier aside still running: another name.
		aside = target + ".old-" + filepath.Base(staged)
	}
	m := mover{rename: os.Rename, held: isHeld, sleep: sleep}
	if err := m.swap(ctx, staged, target, aside); err != nil {
		return err
	}
	_ = os.Remove(aside) // fails while it runs; CleanUp removes it later
	return nil
}

// How long a rename is tried again while another process (a virus scanner
// or an indexer reading the new file, say) holds one of the files: the
// waits are firstWait, doubled up to longestWait, and maxWait in all.
const (
	firstWait   = 25 * time.Millisecond
	longestWait = 500 * time.Millisecond
	maxWait     = 5 * time.Second
)

// mover renames files that another process may hold for a moment.
type mover struct {
	rename func(from, to string) error
	// held reports whether a rename failed for what another process may
	// soon let go of.
	held func(error) bool
	// sleep waits, and reports whether to go on.
	sleep func(context.Context, time.Duration) bool
}

// retry runs do again while it fails because a file is held and there is
// waiting left.
func (m mover) retry(ctx context.Context, left *time.Duration, do func() error) error {
	for wait := firstWait; ; wait = min(2*wait, longestWait) {
		err := do()
		d := min(wait, *left)
		if err == nil || d <= 0 || !m.held(err) || !m.sleep(ctx, d) {
			return err
		}
		*left -= d
	}
}

// swap puts staged in target's place, target at aside. A held file is
// tried again from the start with target back in its place, so target is
// there during those waits. Putting target back is tried again the same
// way, with a maxWait of its own (one for all the times) and even when ctx
// is done: only that leaves target as it was.
func (m mover) swap(ctx context.Context, staged, target, aside string) error {
	forward, back := maxWait, maxWait
	return m.retry(ctx, &forward, func() error {
		if err := m.rename(target, aside); err != nil {
			return err
		}
		err := m.rename(staged, target)
		if err == nil {
			return nil
		}
		undo := m.retry(context.WithoutCancel(ctx), &back, func() error { return m.rename(aside, target) })
		if undo != nil {
			return fail("could not replace %s: %v; the binary that was there is at %s and could not be put back: %v. Rename it to %s", target, err, aside, undo, filepath.Base(target))
		}
		return err
	})
}

// sleep waits d, or until ctx is done, which it reports as false.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// CleanUp removes what an update on Windows left beside the running
// binary: the old binary it renamed aside, once nothing runs it. Elsewhere
// it does nothing. Errors are ignored: a file still in use stays for the
// next run.
func CleanUp() {
	if runtime.GOOS != "windows" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	old, _ := filepath.Glob(exe + ".old*")
	for _, f := range old {
		_ = os.Remove(f)
	}
}

// writeError explains a failure to write beside the target or rename over
// it.
func writeError(err error, target, version string) error {
	var e *Error
	if errors.As(err, &e) {
		return err
	}
	denied := errors.Is(err, fs.ErrPermission) || isReadOnly(err)
	if runtime.GOOS != "windows" {
		if denied {
			return fail("cannot write %s. Rerun with the rights to replace %s, for example:\n  sudo %s self-update %s", filepath.Dir(target), target, target, version)
		}
		return fail("could not replace %s: %v; it was left as it was", target, err)
	}
	if denied {
		return fail("cannot replace %s. Rerun from a terminal with the rights to replace it, such as one run as administrator:\n  \"%s\" self-update %s\nOr install varlatch in a directory you own, as install.ps1 does (%%LOCALAPPDATA%%\\Programs\\Varlatch)", target, target, version)
	}
	return fail("could not replace %s: %v; it was left as it was", target, err)
}
