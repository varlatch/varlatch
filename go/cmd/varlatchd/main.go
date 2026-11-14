// SPDX-License-Identifier: AGPL-3.0-or-later

// Command varlatchd is the Varlatch server of the Go rewrite (ADR-0059).
//
//	varlatchd serve [--config <file>]   serve (default /etc/varlatch/varlatchd.conf)
//	varlatchd --version                 print the version
//	varlatchd admin bootstrap|recover   not built yet (ADR-0059 step 3.4)
//
// Exit statuses of serve: 0 after a clean stop, 1 for a failure a restart
// may fix, 78 for a configuration error no restart can fix (the unit's
// RestartPreventExitStatus). 64 is a usage error; 69 an admin command that
// is not built yet.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/server"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/daemon"
)

const (
	exitUsage = 64
	// exitNotBuilt is EX_UNAVAILABLE: an admin command this build does not
	// have yet. Its message starts with NOT_IMPLEMENTED_YET, the code the
	// HTTP stub answers with, which the conformance harness's go-binary
	// adapter recognizes.
	exitNotBuilt = 69
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(stderr io.Writer, msg string) int {
	fmt.Fprintf(stderr, "%s: %s\nUsage: varlatchd serve [--config <file>] | varlatchd --version\n", server.Name, msg)
	return exitUsage
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr, "no command")
	}
	switch args[0] {
	case "--version", "version":
		if len(args) != 1 {
			return usage(stderr, "--version takes no arguments")
		}
		fmt.Fprintln(stdout, server.Name, buildinfo.Version)
		return 0
	case "serve":
		path := config.DefaultPath
		rest := args[1:]
		for len(rest) > 0 {
			switch {
			case rest[0] == "--config" && len(rest) > 1:
				path, rest = rest[1], rest[2:]
			default:
				return usage(stderr, "serve: unknown argument "+rest[0])
			}
		}
		return daemon.Serve(daemon.Options{ConfigPath: path, Stderr: stderr})
	case "admin":
		if len(args) > 1 && (args[1] == "bootstrap" || args[1] == "recover") {
			fmt.Fprintf(stderr, "NOT_IMPLEMENTED_YET: varlatchd admin %s is not built yet (ADR-0059 step 3.4)\n", args[1])
			return exitNotBuilt
		}
		return usage(stderr, "admin: unknown command")
	default:
		return usage(stderr, "unknown command "+args[0])
	}
}
