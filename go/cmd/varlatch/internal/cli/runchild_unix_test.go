// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLookCommandAsLibuv: a command is found as libuv's execvp finds it, in
// the command's own PATH (a delivered PATH changes the search), skipping a
// file that is not executable; a name with a slash is used as it is.
func TestLookCommandAsLibuv(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	write := func(dir, name string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(first, "tool", 0o644) // not executable: skipped
	write(second, "tool", 0o755)
	write(first, "only-first", 0o755)
	path := first + string(os.PathListSeparator) + second
	if got, err := lookCommand("tool", path); err != nil || got != filepath.Join(second, "tool") {
		t.Errorf("tool: %q, %v", got, err)
	}
	if got, err := lookCommand("only-first", second); !errors.Is(err, errNotFound) {
		t.Errorf("a PATH without it: %q, %v", got, err)
	}
	if got, err := lookCommand("./relative/tool", path); err != nil || got != "./relative/tool" {
		t.Errorf("a name with a slash: %q, %v", got, err)
	}
	if err := spawnError("nosuch", errNotFound); err.Error() != "spawn nosuch ENOENT" {
		t.Errorf("%v", err)
	}
}

// TestLookCommandAsksTheSystem: a file earlier on PATH that this process
// may not execute (only its group may, here) is skipped for a later one it
// may, as execve would; the mode bits alone would take the first.
func TestLookCommandAsksTheSystem(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may execute any file with an execute bit")
	}
	first, second := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(first, "tool"), []byte("#!/bin/sh\n"), 0o070); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, "tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := lookCommand("tool", first+string(os.PathListSeparator)+second); err != nil || got != filepath.Join(second, "tool") {
		t.Errorf("tool: %q, %v", got, err)
	}
}

// TestLookCommandRemembersEACCES: as libuv's execvp, a candidate on PATH
// that exists but may not be executed makes the search end with EACCES
// when no later directory has the command (ENOENT only when none had it).
func TestLookCommandRemembersEACCES(t *testing.T) {
	dir, empty := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tool"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "adir"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := empty + string(os.PathListSeparator) + dir
	for _, name := range []string{"tool", "adir"} {
		_, err := lookCommand(name, path)
		if got := spawnError(name, err); got.Error() != "spawn "+name+" EACCES" {
			t.Errorf("%s: %v", name, got)
		}
	}
	_, err := lookCommand("nosuch", path)
	if got := spawnError("nosuch", err); got.Error() != "spawn nosuch ENOENT" {
		t.Errorf("nosuch: %v", got)
	}
}

// TestSpawnExecFormatError: an executable file the system cannot execute
// (no #! line) fails to start as Node's spawn does: spawn tool ENOEXEC,
// not Go's fork/exec message.
func TestSpawnExecFormatError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tool"), []byte{0x7f, 'n', 'o', 't', 0, 1, 2, 3}, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &Run{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard}
	_, err := r.runChild("tool", nil, []string{"PATH=" + dir}, nil)
	if err == nil || err.Error() != "spawn tool ENOEXEC" {
		t.Fatalf("%v", err)
	}
}

// TestParentLookupIsExact: off Windows, process.env's names are exact.
func TestParentLookupIsExact(t *testing.T) {
	p := parentVars{names: []string{"Path", "PATH"}, values: map[string]string{"Path": "first", "PATH": "second"}}
	if v, ok := p.lookup("PATH"); !ok || v != "second" {
		t.Fatalf("%q, %v", v, ok)
	}
	if _, ok := p.lookup("path"); ok {
		t.Fatal("found by another case")
	}
}
