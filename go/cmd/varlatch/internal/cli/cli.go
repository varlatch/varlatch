// SPDX-License-Identifier: Apache-2.0

// Package cli is the Go CLI's command framework (ADR-0059 step 5; internal
// docs/design/go-cli.md, slice 5.1a): the global options, help, the command
// table, exit statuses and the shared helpers every command uses. It is a
// port of apps/cli/src/main.ts's entry point and of options.ts, usage.ts,
// exitCodes.ts, safeText.ts, assisted.ts and userAgent.ts, and it behaves as
// the TypeScript CLI does, observed from outside (decision 2): the same
// bytes on stdout and stderr and the same exit status.
package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
)

// Env is the environment a run sees.
type Env interface {
	LookupEnv(key string) (string, bool)
}

// MapEnv is an Env from a map, for tests.
type MapEnv map[string]string

// LookupEnv implements Env.
func (m MapEnv) LookupEnv(key string) (string, bool) {
	v, ok := m[key]
	return v, ok
}

// Environ implements Lister.
func (m MapEnv) Environ() map[string]string { return m }

// Lister is an Env that can list its variables (process.env's keys).
type Lister interface {
	Environ() map[string]string
}

// IO is where a run reads and writes.
type IO struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Run is one invocation: its arguments after the global options, its
// environment and streams, and the global options themselves.
type Run struct {
	IO
	Env      Env
	Assisted AssistedMode
	// Approval is the global --approval <id>, or "" (ADR-0054 Decision 3).
	Approval string
	// Secrets is what the run masks in a server's free text.
	Secrets *Secrets
	// Command is the command's name, Args what follows it.
	Command string
	Args    []string
	// clients is what main.ts keeps per process for its API clients.
	clients clientState
	// everyFailureIsOne: `varlatch scan` documents 1 for every failure, finding
	// or not (usage, authentication, permission, server), and that meaning is
	// frozen (ADR-0043 Decision 10); every other command distinguishes them.
	everyFailureIsOne bool
}

// Environ is every variable of the run's environment, when its Env can
// list them (Lister); none otherwise.
func (r *Run) Environ() map[string]string {
	if l, ok := r.Env.(Lister); ok {
		return l.Environ()
	}
	return map[string]string{}
}

// Getenv is the variable's value, "" when unset.
func (r *Run) Getenv(key string) string {
	v, _ := r.Env.LookupEnv(key)
	return v
}

// exitError ends a command: its message goes to stderr, and the run exits
// with its status.
type exitError struct {
	message string
	// usage is the usage text printed after message: a constant of this
	// binary, holding nothing the person gave, so the fail-safe that masks
	// message (which echoes what they gave) leaves it as it is.
	usage string
	code  int
}

func (e *exitError) Error() string { return e.message + e.usage }

// Fail is the error that prints message on stderr and exits with code
// (apps/cli/src/main.ts fail()).
func Fail(message string, code int) error { return &exitError{message: message, code: code} }

// UsageError is a usage error: message on stderr, exit 64 (main.ts usageError()).
func UsageError(message string) error { return Fail(message, ExitUsage) }

// UsageErrorWithUsage is UsageError(message + usage), usage being one of
// this binary's usage texts: it is printed after message, outside the
// fail-safe, so a usage text's own "@<file>" never makes the fail-safe
// mask the message.
func UsageErrorWithUsage(message, usage string) error {
	return &exitError{message: message, usage: usage, code: ExitUsage}
}

// Main runs the CLI with args (the process's arguments without the program
// name) and returns the exit status, as apps/cli/src/main.ts main() does.
func Main(args []string, env Env, streams IO) int {
	taken, given := TakeAssistedOption(args)
	run := &Run{IO: streams, Env: env, Assisted: ResolveAssisted(given, env)}
	run.Secrets = &Secrets{Token: run.Getenv("VARLATCH_TOKEN"), Stored: func() []string { return storedTokens(env) }}
	resumed, approval, problem := TakeApprovalOption(taken)
	if problem != "" {
		return run.finish(UsageError("varlatch: " + problem))
	}
	run.Approval = approval
	if len(resumed) > 0 {
		run.Command, run.Args = resumed[0], resumed[1:]
	}
	run.everyFailureIsOne = run.Command == "scan"
	return run.finish(run.dispatch(len(resumed) > 0))
}

// dispatch runs the command, or help (ADR-0043 Decision 10: on stdout,
// status 0; only the CLI's own arguments count, so a --help after `--`
// belongs to the command `run` starts).
func (r *Run) dispatch(hasCommand bool) error {
	if r.Command == "--help" || r.Command == "-h" || r.Command == "help" {
		topic := ""
		if r.Command == "help" && len(r.Args) > 0 {
			topic = r.Args[0]
		}
		if topic != "" {
			help, ok := CommandHelp(topic)
			if !ok {
				return UsageErrorWithUsage("varlatch: no help for "+clientctx.MaskURLInValue(topic)+": not a command", "\n\n"+Usage)
			}
			return r.println(help)
		}
		return r.println(Usage)
	}
	if hasCommand {
		own := r.Args
		for i, a := range r.Args {
			if a == "--" {
				own = r.Args[:i]
				break
			}
		}
		for _, a := range own {
			if a == "--help" || a == "-h" {
				if help, ok := CommandHelp(r.Command); ok {
					return r.println(help)
				}
				break
			}
		}
	}
	if !hasCommand {
		// No command prints the usage (0).
		return r.println(Usage)
	}
	c := lookup(r.Command)
	if c == nil {
		return UsageErrorWithUsage("varlatch: unknown command "+clientctx.MaskURLInValue(r.Command), "\n\n"+Usage)
	}
	if c.run == nil {
		return notBuilt(c)
	}
	return c.run(r)
}

// finish prints a command's error and gives the exit status.
func (r *Run) finish(err error) int {
	if err == nil {
		return ExitOK
	}
	err = r.mapClientError(err)
	var e *exitError
	if !errors.As(err, &e) {
		// An error no command turned into a message: TypeScript lets it
		// escape, and Node prints its stack and exits 1. Go says what it
		// was instead (go/README.md, the Go CLI's accepted differences).
		e = &exitError{message: "varlatch: " + err.Error(), code: ExitFailure}
	}
	// The fail-safe on every failure, whatever it echoes: no URL's user name
	// and password reaches stderr even where an echo site did not mask its
	// value (go/README.md, "Diagnostics never print credential values"). A
	// line with no ":"...at-sign pair keeps its bytes.
	fmt.Fprintln(r.Stderr, jsval.NodeText(clientctx.MaskUserinfoInText(e.message)+e.usage))
	if r.everyFailureIsOne {
		return ExitFailure
	}
	return e.code
}

// storedTokens is safeText.ts's heldCredentials' stored half: every stored
// credential's token that is a string; an unreadable store adds nothing.
func storedTokens(env Env) []string {
	list, err := clientctx.ListCredentials(env)
	if err != nil {
		return nil
	}
	var tokens []string
	for _, e := range list {
		if e.Credential == nil {
			continue
		}
		if token, ok := jsval.Get(e.Credential, "token"); ok {
			if s, isString := token.(string); isString {
				tokens = append(tokens, s)
			}
		}
	}
	return tokens
}

// println writes one line on stdout, as console.log does (a lone
// surrogate as U+FFFD, as Node.js writes it).
func (r *Run) println(text string) error {
	_, err := io.WriteString(r.Stdout, jsval.NodeText(text)+"\n")
	return err
}

// versionCommand is `varlatch --version` and `varlatch version`: `varlatch
// <version>`. The TypeScript CLI adds `(migration <n>)` from its release
// manifest; the Go CLI has no migrations (internal docs/design/go-cli.md,
// decision 6), and every consumer reads the first two words.
func versionCommand(r *Run) error {
	return r.println("varlatch " + buildinfo.Version)
}
