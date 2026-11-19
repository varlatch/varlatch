// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// forwardedSignals are inject.ts's FORWARDED_SIGNALS. Job-control and
// terminal signals (SIGTSTP, SIGCONT, SIGWINCH) are left alone: they reach
// the command through the terminal.
var forwardedSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2}

// interruptingSignals are INTERRUPTING: forwarded signals that usually end
// a run, after which a stream's held bytes are discarded at its end. SIGHUP
// is here even though a service may take it as "reload": discarding is the
// conservative choice.
var interruptingSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

func forwardSignal(p *os.Process, sig os.Signal) { _ = p.Signal(sig) }

// exitStatus is the command's status, or signalExitCode's: 128 plus the
// number of the signal that ended it, as a shell reports it.
func exitStatus(state *os.ProcessState) int {
	if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return state.ExitCode()
}

// ignoreBrokenPipe turns a write to a closed stdout or stderr into an
// EPIPE error instead of the end of the process (Go's runtime raises
// SIGPIPE for fd 1 and 2 unless the program handles it), until the
// returned function is called.
func ignoreBrokenPipe() func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGPIPE)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
			case <-done:
				return
			}
		}
	}()
	return func() { signal.Stop(ch); close(done) }
}

// envNameEqual compares variable names as the system does: exactly.
func envNameEqual(a, b string) bool { return a == b }

// lookCommand finds the command as libuv's execvp does: a name with a
// slash as it is; otherwise each directory of the command's own PATH in
// order (an empty entry is the working directory), the first regular file
// this process may execute.
func lookCommand(name, path string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	if path == "" {
		path = "/usr/local/bin:/bin:/usr/bin" // libuv's default when PATH is unset or empty
	}
	for _, dir := range strings.Split(path, ":") {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, name)
		// Executable for this process, as execve would judge it (access(2)
		// with X_OK), not by the mode bits: a file only its owner may run
		// is skipped by anyone else.
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && unix.Access(candidate, unix.X_OK) == nil {
			if dir == "." {
				return "./" + name, nil
			}
			return candidate, nil
		}
	}
	return "", errNotFound
}
