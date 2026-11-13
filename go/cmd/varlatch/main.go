// SPDX-License-Identifier: Apache-2.0

// Command varlatch is the Varlatch CLI of the Go rewrite (ADR-0059). It is a
// skeleton: only the version and verify-release (used by the installers)
// work so far.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintln(stdout, "varlatch", buildinfo.Version)
		return 0
	}
	if len(args) > 0 && args[0] == "verify-release" {
		return verifyRelease(args[1:], stdout, stderr)
	}
	fmt.Fprintln(stderr, "varlatch: this Go build is not usable yet; only --version and verify-release work")
	return 2
}
