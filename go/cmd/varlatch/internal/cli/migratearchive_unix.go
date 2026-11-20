// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"os"
	"syscall"
)

// conversionSignals end a backup conversion with its cleanup.
var conversionSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}
