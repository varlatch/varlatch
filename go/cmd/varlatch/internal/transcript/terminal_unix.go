// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package transcript

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// onTerminal runs cmd with a new pseudo-terminal as its controlling
// terminal and stdin, and as its stdout, its stderr or both (which: the
// case's Terminal); the other stream is captured as usual. shown is what
// the terminal displayed, with the terminal's "\r\n" as "\n", as goKit.ts
// records it from util-linux script(1).
func onTerminal(cmd *exec.Cmd, which string) (status int, stdout, stderr, shown string, err error) {
	master, tty, err := pty.Open()
	if err != nil {
		return 0, "", "", "", fmt.Errorf("%w: no pseudo-terminal: %v", ErrUnsupported, err)
	}
	defer func() { _ = master.Close() }()
	var out, errOut bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	switch which {
	case "both":
	case "stdout":
		cmd.Stderr = &errOut
	case "stderr":
		cmd.Stdout = &out
	default:
		_ = tty.Close()
		return 0, "", "", "", fmt.Errorf("no terminal %q (stdout, stderr or both)", which)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if err := cmd.Start(); err != nil {
		_ = tty.Close()
		return 0, "", "", "", err
	}
	var screen bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(&screen, master)
	}()
	timer := time.AfterFunc(60*time.Second, func() { _ = cmd.Process.Kill() })
	waited := cmd.Wait()
	timer.Stop()
	_ = tty.Close()
	// Linux ends the master's reads once no terminal side is open; where
	// it does not, what was displayed is read by then, and closing the
	// master ends the copy.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = master.Close()
		<-done
	}
	if waited != nil {
		var exit *exec.ExitError
		if !asExit(waited, &exit) {
			return 0, "", "", "", waited
		}
		status = exitStatus(exit)
	}
	return status, out.String(), errOut.String(), strings.ReplaceAll(screen.String(), "\r\n", "\n"), nil
}
