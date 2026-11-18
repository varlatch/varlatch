// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package secretinput

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

// fatalSignals end the prompt with the terminal restored: those after which
// Node.js restores its standard streams before it ends (SignalExit), and
// the terminal closing (SIGHUP) and SIGQUIT, whose default actions would
// otherwise leave it raw.
var fatalSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

// reraise ends the process by the signal's default action. SIGQUIT's in
// Go is a dump of every goroutine's stack and status 2, so for it the
// process exits 131 (128 + 3) itself, saying nothing.
func reraise(sig os.Signal) {
	if sig == syscall.SIGQUIT {
		os.Exit(128 + int(syscall.SIGQUIT))
	}
	signal.Reset(sig)
	if s, ok := sig.(syscall.Signal); ok {
		_ = syscall.Kill(syscall.Getpid(), s)
		time.Sleep(time.Second)
	}
	os.Exit(128 + int(sig.(syscall.Signal)))
}
