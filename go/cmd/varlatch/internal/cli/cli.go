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
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
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
	// argv is the command and its arguments, the global options taken out:
	// the command an approval's rerun line repeats.
	argv []string
	// Secrets is what the run masks in a server's free text.
	Secrets *Secrets
	// Command is the command's name, Args what follows it.
	Command string
	Args    []string
	// clients is what main.ts keeps per process for its API clients.
	clients clientState
	// inFlight are the secret values this run handles (the value `values
	// set` or `values rotate` sends, the Secrets `import` reads, a
	// credential given or issued, a device code, an OIDC token, a sign-in
	// hand-off bearer): every output and diagnostic has each exact
	// occurrence of them redacted, whatever their length (holdValue).
	inFlight []string
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
	// VARLATCH_TOKEN is a bearer the person gave: held from the start,
	// whatever its length, also by commands that never send it (an offline
	// status printing a tier a server once answered).
	run.holdCredential(run.Getenv("VARLATCH_TOKEN"), true)
	resumed, approval, problem := TakeApprovalOption(taken)
	if problem != "" {
		return run.finish(UsageError("varlatch: " + problem))
	}
	run.Approval = approval
	run.argv = resumed
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
			help, ok := commandHelp(topic)
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
				if help, ok := commandHelp(r.Command); ok {
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
		if c.partial != nil {
			if handled, err := c.partial(r); handled {
				return err
			}
		}
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
		fmt.Fprintln(r.Stderr, jsval.NodeText(RedactDiagnostic(e.message, r.inFlight...)+e.usage))
	}
	// A failure of scan is 1 (main.ts's fail()); a status scan sets itself
	// (process.exitCode: ExitWith, silent), such as --find-files' 2, is
	// kept.
	if r.everyFailureIsOne && !e.silent {
		return ExitFailure
	}
	return e.code
}

// RedactDiagnostic is the fail-safe every diagnostic goes through before it
// is written, failures (Run.finish) and warnings (Run.warn) alike. Every
// sensitive span is found in the original text first and their union is
// replaced once: clientctx's fail-safe spans (MaskUserinfoInText's: a URL's
// user name and password, each up to its at-sign), every text in
// Varlatch's token format, and each exact occurrence of a secret value in
// flight (values), whatever its length. A merged region reads
// "[redacted]@" when it ends with a fail-safe span's at-sign that no value
// in flight covers, "[redacted]" otherwise. So no detection depends on
// another's replacement (a value "@" never hides the at-sign that marks a
// password), and with no values in flight the bytes are the fail-safe's
// and the token redaction's, as before. Text with none keeps its bytes.
func RedactDiagnostic(text string, values ...string) string {
	spans := atSignSpans(clientctx.FailSafeSpans(text))
	return redactSpans(text, append(append(spans, tokenSpans(text)...), valueSpans(text, values)...))
}

// warn writes one diagnostic line on stderr through the fail-safe
// (RedactDiagnostic). Every line the CLI writes on stderr outside
// Run.finish goes through it.
func (r *Run) warn(text string) error {
	_, err := fmt.Fprintln(r.Stderr, jsval.NodeText(RedactDiagnostic(text, r.inFlight...)))
	return err
}

// ask writes a prompt on stderr, without a line break, through the
// fail-safe (RedactDiagnostic): the hidden prompt's question and what it
// says when it ends.
func (r *Run) ask(text string) error {
	_, err := io.WriteString(r.Stderr, jsval.NodeText(RedactDiagnostic(text, r.inFlight...)))
	return err
}

// RedactOutput is the fail-safe on everything the CLI writes on stdout:
// every text in Varlatch's token format and each exact occurrence of a
// secret value in flight (values), whatever its length, found in the
// original text and replaced once, as [redacted]. The values that hold a
// URL are masked where they are shown (and, in a --json document, by
// RedactValue), so ordinary output keeps its bytes.
func RedactOutput(text string, values ...string) string {
	return redactSpans(text, append(tokenSpans(text), valueSpans(text, values)...))
}

// RedactValue is a JSON value with the fail-safe applied to every string
// in it, keys untouched: clientctx's composed masker's spans (MaskURLInValue's,
// so a value without a user name and password keeps its bytes), every text
// in Varlatch's token format, and each exact occurrence of a secret value
// in flight (values), all found in the original string and their union
// replaced once (RedactDiagnostic's rule). redactJSON applies it to every
// --json document, so a value is matched in the string that holds it,
// never in the serialised text (a short value never touches a number or an
// escape).
func RedactValue(v any, values ...string) (any, error) {
	switch x := v.(type) {
	case nil, bool, float64, int:
		return v, nil // nothing to redact
	case string:
		return redactString(x, values), nil
	case jsjson.Object:
		out := make(jsjson.Object, len(x))
		for i, m := range x {
			value, err := RedactValue(m.Value, values...)
			if err != nil {
				return nil, err
			}
			out[i] = jsjson.Member{Key: m.Key, Value: value}
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			value, err := RedactValue(e, values...)
			if err != nil {
				return nil, err
			}
			out[i] = value
		}
		return out, nil
	case []string:
		out := make([]string, len(x))
		for i, e := range x {
			out[i] = redactString(e, values)
		}
		return out, nil
	}
	// Any other type would reach the serialiser unredacted: refused, so a
	// --json document holds only what the fail-safe walks.
	return nil, errNotRedactable{v}
}

// errNotRedactable is a value of a type RedactValue does not walk: an
// error of the CLI's own, never printed with the value.
type errNotRedactable struct{ v any }

func (e errNotRedactable) Error() string {
	return fmt.Sprintf("internal error: a JSON document holds a %T, which the fail-safe does not redact; nothing was printed", e.v)
}

// redactString is RedactValue for one string.
func redactString(s string, values []string) string {
	spans := atSignSpans(clientctx.ValueSpans(s))
	return redactSpans(s, append(append(spans, tokenSpans(s)...), valueSpans(s, values)...))
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

// span is a part of a text, [a, b), to be redacted: one of clientctx's
// fail-safe spans (atSign: it ends just after an at-sign, replaced alone
// by "[redacted]@"), a token, or a value in flight (value).
type span struct {
	a, b   int
	atSign bool
	value  bool
}

// atSignSpans are clientctx's spans, each ending just after an at-sign.
func atSignSpans(spans [][2]int) []span {
	out := make([]span, len(spans))
	for i, s := range spans {
		out[i] = span{a: s[0], b: s[1], atSign: true}
	}
	return out
}

// tokenSpans are the texts in Varlatch's token format.
func tokenSpans(text string) []span {
	var out []span
	for _, m := range varlatchToken.FindAllStringIndex(text, -1) {
		out = append(out, span{a: m[0], b: m[1]})
	}
	return out
}

// valueSpans are every occurrence, overlapping ones included, of each
// value and of each as Printable shows it.
func valueSpans(text string, values []string) []span {
	var out []span
	for _, v := range values {
		forms := []string{v}
		if p := Printable(v); p != v {
			forms = append(forms, p)
		}
		for _, form := range forms {
			if form == "" {
				continue
			}
			for from := 0; from < len(text); {
				i := strings.Index(text[from:], form)
				if i < 0 {
					break
				}
				out = append(out, span{a: from + i, b: from + i + len(form), value: true})
				from += i + 1
			}
		}
	}
	return out
}

// redactSpans replaces the union of spans in text, in one pass over the
// original: spans that overlap or touch are one region (as clientctx's
// replaceSpans merges its own). A region reads "[redacted]@" when it ends
// with an at-sign span's end that no value span reaches, "[redacted]"
// otherwise, so a value in flight that is (or ends with) the at-sign is
// never written back.
func redactSpans(text string, spans []span) string {
	if len(spans) == 0 {
		return text
	}
	slices.SortStableFunc(spans, func(x, y span) int {
		if x.a != y.a {
			return x.a - y.a
		}
		return y.b - x.b
	})
	type region struct {
		a, b               int
		atSignEnd, valueAt bool
	}
	var merged []region
	for _, s := range spans {
		if n := len(merged); n > 0 && s.a <= merged[n-1].b {
			last := &merged[n-1]
			switch {
			case s.b > last.b:
				last.b, last.atSignEnd, last.valueAt = s.b, s.atSign, s.value
			case s.b == last.b:
				last.atSignEnd = last.atSignEnd || s.atSign
				last.valueAt = last.valueAt || s.value
			}
			continue
		}
		merged = append(merged, region{a: s.a, b: s.b, atSignEnd: s.atSign, valueAt: s.value})
	}
	var b strings.Builder
	at := 0
	for _, m := range merged {
		b.WriteString(text[at:m.a])
		b.WriteString(Redacted)
		if m.atSignEnd && !m.valueAt {
			b.WriteString("@")
		}
		at = m.b
	}
	b.WriteString(text[at:])
	return b.String()
}

// holdCredential registers a bearer this run sends: masked in a server's
// free text (Secrets.Remember) and, whatever its shape (not only
// Varlatch's vlt_ format), in everything the run writes on stdout and
// stderr (holdValue), so a server that echoes it back in an answer the run
// prints never gets it shown. A bearer the person gave (given: --token or
// --token-stdin; or VARLATCH_TOKEN's value) is held whatever its length;
// any other only from MinMaskedLength on, since a shorter one would match
// ordinary words.
func (r *Run) holdCredential(token string, given bool) {
	if token == "" {
		return
	}
	r.Secrets.Remember(token)
	if given || token == r.Getenv("VARLATCH_TOKEN") || utf16Len(token) >= MinMaskedLength {
		r.holdValue(token)
	}
}

// newClient is the one way the CLI makes an API client: the bearer it
// sends is held first (holdCredential), so no command that prints a
// server's answer can show it, whichever it is.
// TestEveryClientHoldsItsBearer fails on any other apiclient.New.
func (r *Run) newClient(opts apiclient.Options) *apiclient.Client {
	r.holdCredential(opts.Token, false)
	return apiclient.New(opts)
}

// holdValue registers a secret value this run handles, so no output or
// diagnostic shows it (RedactDiagnostic, RedactOutput, RedactValue).
func (r *Run) holdValue(value string) {
	if value != "" && !slices.Contains(r.inFlight, value) {
		r.inFlight = append(r.inFlight, value)
	}
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
	_, err := io.WriteString(r.Stdout, jsval.NodeText(RedactOutput(text, r.inFlight...)))
	return err
}

// redactedJSON is a --json document serialised after every string value in
// it went through RedactValue. Only redactJSON makes one (its field is
// unexported, and TestEveryWriteGoesThroughTheFailSafe fails on any other
// composite literal of it), so outJSON can never print arbitrary text.
type redactedJSON struct{ document string }

// redactJSON is JSON.stringify(doc, null, 2) of doc with RedactValue
// applied, the values in flight included: keys are left alone (they come
// from the API's schema and the CLI's own documents), so no two keys are
// ever made the same.
func redactJSON(doc any, values ...string) (redactedJSON, error) {
	redacted, err := RedactValue(doc, values...)
	if err != nil {
		return redactedJSON{}, err
	}
	return redactedJSON{document: string(jsjson.StringifyIndent(redacted, 2))}, nil
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
