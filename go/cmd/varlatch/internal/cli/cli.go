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
	"github.com/varlatch/varlatch/go/lib/jsjson"
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
	// silent: the command printed what it had to say (process.exitCode).
	silent bool
}

func (e *exitError) Error() string { return e.message + e.usage }

// Fail is the error that prints message on stderr and exits with code
// (apps/cli/src/main.ts fail()).
func Fail(message string, code int) error { return &exitError{message: message, code: code} }

// ExitWith ends a command that has printed its output with code, as
// setting process.exitCode does: nothing more is printed.
func ExitWith(code int) error { return &exitError{code: code, silent: true} }

// UsageError is a usage error: message on stderr, exit 64 (main.ts usageError()).
func UsageError(message string) error { return Fail(message, ExitUsage) }

// UsageErrorWithUsage is UsageError(message + usage), usage being one of
// this binary's usage texts: it is printed after message, outside the
// fail-safe, so a usage text's own "@<file>" never makes the fail-safe
// mask the message.
func UsageErrorWithUsage(message, usage string) error {
	return &exitError{message: message, usage: usage, code: ExitUsage}
}

// UsageOnly is UsageError(usage), usage being one of this binary's usage
// texts and the whole message: printed outside the fail-safe, byte for
// byte as TypeScript prints it, never masked.
func UsageOnly(usage string) error { return UsageErrorWithUsage("", usage) }

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
				return UsageErrorWithUsage("varlatch: no help for "+shownArgument(topic)+": not a command", "\n\n"+Usage)
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
		shown := shownArgument(r.Command)
		if clientctx.HasAtSign(shown) {
			return UsageErrorWithUsage("varlatch: "+shown+": unknown command", "\n\n"+Usage) // the explanation follows the URL
		}
		return UsageErrorWithUsage("varlatch: unknown command "+shown, "\n\n"+Usage)
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
	// No home directory to find the configuration in: the command line (or
	// the environment) must give one, as in main.ts's catch.
	var noHome *clientctx.HomeDirectoryError
	if errors.As(err, &noHome) {
		err = Fail(noHome.Error(), ExitUsage)
	}
	var e *exitError
	if !errors.As(err, &e) {
		// An error no command turned into a message: TypeScript lets it
		// escape, and Node prints its stack and exits 1. Go says what it
		// was instead (go/README.md, the Go CLI's accepted differences).
		e = &exitError{message: "varlatch: " + err.Error(), code: ExitFailure}
	}
	// The fail-safe on every failure, whatever it echoes and whichever path
	// made it (RedactDiagnostic): no URL's user name and password and no
	// Varlatch token reaches stderr (go/README.md, "Diagnostics never print
	// credential values").
	if !e.silent {
		fmt.Fprintln(r.Stderr, jsval.NodeText(RedactDiagnostic(e.message)+e.usage))
	}
	if r.everyFailureIsOne {
		return ExitFailure
	}
	return e.code
}

// RedactDiagnostic is the fail-safe every diagnostic goes through before it
// is written, failures (Run.finish) and warnings (Run.warn) alike: a URL's
// user name and password (clientctx.MaskUserinfoInText, from the first
// scheme colon to the last at-sign), then every text in Varlatch's token
// format, as [redacted]. Text with neither keeps its bytes.
func RedactDiagnostic(text string) string {
	return varlatchToken.ReplaceAllLiteralString(clientctx.MaskUserinfoInText(text), Redacted)
}

// warn writes one diagnostic line on stderr through the fail-safe
// (RedactDiagnostic). Every line the CLI writes on stderr outside
// Run.finish goes through it.
func (r *Run) warn(text string) error {
	_, err := fmt.Fprintln(r.Stderr, jsval.NodeText(RedactDiagnostic(text)))
	return err
}

// RedactOutput is the fail-safe on everything the CLI writes on stdout:
// every text in Varlatch's token format as [redacted]. The values that hold
// a URL are masked where they are shown (and, in a --json document, by
// RedactValue), so ordinary output keeps its bytes.
func RedactOutput(text string) string {
	return varlatchToken.ReplaceAllLiteralString(text, Redacted)
}

// RedactValue is a JSON value with the fail-safe applied to every string
// in it, keys untouched: a URL's user name and password masked (precisely,
// clientctx.MaskURLInValue, so a value without them keeps its bytes) and
// every text in Varlatch's token format as [redacted]. printJSON applies it
// to every --json document.
func RedactValue(v any) any {
	switch x := v.(type) {
	case string:
		return RedactOutput(clientctx.MaskURLInValue(x))
	case jsjson.Object:
		out := make(jsjson.Object, len(x))
		for i, m := range x {
			out[i] = jsjson.Member{Key: m.Key, Value: RedactValue(m.Value)}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = RedactValue(e)
		}
		return out
	case []string:
		out := make([]string, len(x))
		for i, e := range x {
			out[i] = RedactOutput(clientctx.MaskURLInValue(e))
		}
		return out
	}
	return v // nil, bool, float64, int: nothing to redact
}

// scalar is v when it is a JSON scalar (null, a boolean, a number or a
// string), and false for an object or an array: a field a document defines
// as a scalar never passes a server's nested value through.
func scalar(v any) (any, bool) {
	switch v.(type) {
	case nil, bool, float64, string:
		return v, true
	}
	return nil, false
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
	return r.out(text + "\n")
}

// out is the one place the CLI writes stdout: through the fail-safe
// (RedactOutput). TestEveryWriteGoesThroughTheFailSafe fails on any other.
func (r *Run) out(text string) error {
	_, err := io.WriteString(r.Stdout, jsval.NodeText(RedactOutput(text)))
	return err
}

// redactedJSON is a --json document serialised after every string value in
// it went through RedactValue. Only redactJSON makes one (its field is
// unexported, and TestEveryWriteGoesThroughTheFailSafe fails on any other
// composite literal of it), so outJSON can never print arbitrary text.
type redactedJSON struct{ document string }

// redactJSON is JSON.stringify(doc, null, 2) of doc with RedactValue
// applied: keys are left alone (they come from the API's schema and the
// CLI's own documents), so no two keys are ever made the same.
func redactJSON(doc jsjson.Object) redactedJSON {
	return redactedJSON{document: string(jsjson.StringifyIndent(RedactValue(doc), 2))}
}

// outJSON writes a redacted --json document and a newline, as it is: the
// text redactor never touches it.
func (r *Run) outJSON(doc redactedJSON) error {
	_, err := io.WriteString(r.Stdout, jsval.NodeText(doc.document)+"\n")
	return err
}

// versionCommand is `varlatch --version` and `varlatch version`: `varlatch
// <version>`. The TypeScript CLI adds `(migration <n>)` from its release
// manifest; the Go CLI has no migrations (internal docs/design/go-cli.md,
// decision 6), and every consumer reads the first two words.
func versionCommand(r *Run) error {
	return r.println("varlatch " + buildinfo.Version)
}
