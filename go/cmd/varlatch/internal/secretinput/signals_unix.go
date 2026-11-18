// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package secretinput

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

// fatalSignals are those after which Node.js restores its standard
// streams before it ends (SignalExit).
var fatalSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM}

// reraise ends the process by the signal's default action.
func reraise(sig os.Signal) {
	signal.Reset(sig)
	if s, ok := sig.(syscall.Signal); ok {
		_ = syscall.Kill(syscall.Getpid(), s)
		time.Sleep(time.Second)
	}
	os.Exit(128 + int(sig.(syscall.Signal)))
}
