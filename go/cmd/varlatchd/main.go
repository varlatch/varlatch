// SPDX-License-Identifier: AGPL-3.0-or-later

// Command varlatchd is the Varlatch server of the Go rewrite (ADR-0059). It
// is a skeleton: only the version works so far.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/server"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintln(stdout, server.Name, buildinfo.Version)
		return 0
	}
	fmt.Fprintln(stderr, server.Name+": this Go build is not usable yet; only --version works")
	return 2
}
