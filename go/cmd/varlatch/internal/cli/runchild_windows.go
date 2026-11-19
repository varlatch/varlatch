// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// forwardedSignals are what Windows has of inject.ts's FORWARDED_SIGNALS:
// Ctrl-C (os.Interrupt) and a stop.
var forwardedSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

var interruptingSignals = forwardedSignals

// forwardSignal ends the command, as Node's child.kill does on Windows for
// either signal (TerminateProcess).
func forwardSignal(p *os.Process, _ os.Signal) { _ = p.Kill() }

func exitStatus(state *os.ProcessState) int { return state.ExitCode() }

func ignoreBrokenPipe() func() { return func() {} }

// envNameEqual compares variable names as Windows does: without case.
func envNameEqual(a, b string) bool { return strings.EqualFold(a, b) }

// lookCommand finds the command as libuv does without a shell (decision
// 4): in the working directory, then each directory of PATH, the name as
// it is when it has an extension, then with .com, then with .exe; a .bat or
// .cmd file is refused (Node's EINVAL since CVE-2024-27980). Go's
// exec.LookPath would also find .bat and .cmd through PATHEXT and run
// them through cmd.exe.
func lookCommand(name, path string) (string, error) {
	var dirs []string
	if strings.ContainsAny(name, `/\:`) {
		dirs = []string{""}
	} else {
		dirs = append([]string{"."}, filepath.SplitList(path)...)
	}
	hasExt := filepath.Ext(name) != ""
	for _, dir := range dirs {
		var tries []string
		if hasExt {
			tries = append(tries, name)
		}
		tries = append(tries, name+".com", name+".exe")
		for _, t := range tries {
			candidate := t
			if dir != "" {
				candidate = filepath.Join(dir, t)
			}
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				switch strings.ToLower(filepath.Ext(candidate)) {
				case ".bat", ".cmd":
					return "", errBatchFile
				}
				return candidate, nil
			}
		}
	}
	return "", errNotFound
}

// errnoName is the error's name as libuv gives it on Windows, for the
// errors starting a command can end with; "" for another (its message is
// then kept).
func errnoName(errno syscall.Errno) string {
	switch errno {
	case syscall.ERROR_FILE_NOT_FOUND, syscall.ERROR_PATH_NOT_FOUND:
		return "ENOENT"
	case syscall.ERROR_ACCESS_DENIED:
		return "EACCES"
	}
	return ""
}
