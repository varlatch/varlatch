// SPDX-License-Identifier: Apache-2.0

// Command varlatch is the Varlatch CLI of the Go rewrite (ADR-0059 step 5).
// It is being ported from the TypeScript CLI (apps/cli) slice by slice
// (internal docs/design/go-cli.md); a command not ported yet says so and
// exits 64. verify-release, which the installers run, is Go's own.
package main

import (
	"io"
	"os"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/cli"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate"
)

func main() {
	// What a self-update on Windows left beside this binary (the old one,
	// renamed aside while it ran) goes now that it no longer runs.
	selfupdate.CleanUp()
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// osEnv is the process environment.
type osEnv struct{}

func (osEnv) LookupEnv(key string) (string, bool) { return os.LookupEnv(key) }

// Environ lists the process environment, as process.env's keys.
func (osEnv) Environ() map[string]string {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
			if _, seen := env[k]; !seen {
				env[k] = v
			}
		}
	}
	return env
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "verify-release" {
		return verifyRelease(args[1:], stdout, stderr)
	}
	return cli.Main(args, osEnv{}, cli.IO{Stdin: stdin, Stdout: stdout, Stderr: stderr})
}
