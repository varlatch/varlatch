// SPDX-License-Identifier: AGPL-3.0-or-later

// Command varlatchd is the Varlatch server of the Go rewrite (ADR-0059).
//
//	varlatchd serve [--config <file>]   serve (default /etc/varlatch/varlatchd.conf)
//	varlatchd --version                 print the version
//	varlatchd admin bootstrap|recover   one-time enrollment URLs or CLI credentials (daemon.Admin)
//
// Exit statuses of serve: 0 after a clean stop, 1 for a failure a restart
// may fix, 78 for a configuration error no restart can fix, a wrong Root KEK
// included (the unit's RestartPreventExitStatus). 64 is a usage error.
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

const exitUsage = 64

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
		return daemon.Admin(args[1:], stdout, stderr)
	default:
		return usage(stderr, "unknown command "+args[0])
	}
}
