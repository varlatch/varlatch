// SPDX-License-Identifier: Apache-2.0

// Command varlatch is the Varlatch CLI of the Go rewrite (ADR-0059 step 5).
// It is being ported from the TypeScript CLI (apps/cli) slice by slice
// (internal docs/design/go-cli.md); a command not ported yet says so and
// exits 64. verify-release, which the installers run, is Go's own.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/cli"
	"github.com/varlatch/varlatch/go/lib/keyenv"
)

func main() {
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

// EnvironNames lists the process environment's names in the order the
// process got them, the first of names that repeat.
func (osEnv) EnvironNames() []string {
	var names []string
	seen := map[string]bool{}
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok && k != "" && !seen[k] {
			seen[k] = true
			names = append(names, k)
		}
	}
	return names
}

// In the single-container image (go/image/Dockerfile sets
// keyenv.ImageMarker), the CLI runs beside varlatchd and refuses, as
// varlatchd does, an environment that holds the Root KEK or the Backup
// Encryption Key that imageConfig names, or a key or passphrase variable
// name (lib/keyenv): exit 78, the variable named, never its value. It
// needs no key itself; keys reach varlatchd only as mounted files.
var imageConfig = "/etc/varlatch/varlatchd.conf"

// exitConfig is the exit status of a refused environment (EX_CONFIG, as
// varlatchd's).
const exitConfig = 78

func imageRefusal() string {
	if os.Getenv(keyenv.ImageMarker) == "" {
		return ""
	}
	keys := keyenv.Configured(imageConfig)
	why := keyenv.Refusal(os.Environ(), keys...)
	for _, k := range keys {
		clear(k.Bytes)
	}
	return why
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if why := imageRefusal(); why != "" {
		fmt.Fprintln(stderr, "varlatch: "+why)
		return exitConfig
	}
	if len(args) > 0 && args[0] == "verify-release" {
		return verifyRelease(args[1:], stdout, stderr)
	}
	return cli.Main(args, osEnv{}, cli.IO{Stdin: stdin, Stdout: stdout, Stderr: stderr})
}
