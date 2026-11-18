// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/secretinput"
	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch values set/list/delete/rotate/rotate-complete` (slice 5.3a of
// internal docs/design/go-cli.md), main.ts's "values" case and the helpers
// it calls (valuePresence, rotationHintOf, sensitiveItem, valueSource,
// refuseValueSource, obtainValue), with secretInput.ts in
// internal/secretinput. Values are secrets: no path here prints one, in a
// message, a document or an error (go/README.md, "No message holds a
// value").

const (
	valuesSetUsage    = "Usage: varlatch values set <ITEM> [-e <environment>] [--server <url>] [--replace <ITEM>] [<value> | --stdin | --from-file <path> | --generate <spec>]"
	valuesRotateUsage = "Usage: varlatch values rotate <ITEM> [-e <environment>] [--server <url>] [--replace <ITEM>] [<new-value> | --stdin | --from-file <path> | --generate <spec>] [--grace <seconds>]"
	valuesDeleteUsage = "Usage: varlatch values delete <ITEM> [-e <environment>] [--server <url>] [--confirm <ITEM>]"
)

// lazyClient is main.ts's client(ctx): the API client of the context's
// server, connected on its first request, so the command's own checks of
// its command line come first.
type lazyClient struct {
	r      *Run
	server any
	api    *apiclient.Client
}

func (r *Run) client(ctx *clientctx.Context) *lazyClient {
	return &lazyClient{r: r, server: ctx.Server}
}

func (l *lazyClient) get() (*apiclient.Client, error) {
	if l.api != nil {
		return l.api, nil
	}
	server, err := serverString(l.server)
	if err != nil {
		return nil, err
	}
	api, err := l.r.connectClient(server)
	if err != nil {
		return nil, err
	}
	l.api = api
	return api, nil
}

// environmentOf is `${ctx.environment}`.
func environmentOf(ctx *clientctx.Context) string { return jsjson.String(ctx.Environment) }

// contextOptions is main.ts's contextOptions: the options a suggested
// command needs to reach the same environment and server from a new shell.
func (r *Run) contextOptions(args []string, environment string, server any) string {
	_, flagged := flagArg(args, "--server")
	out := "-e " + environment
	if flagged || r.Getenv("VARLATCH_SERVER") != "" {
		out += " --server " + jsjson.String(clientctx.MaskServer(server))
	}
	return out
}

func valuesCommand(r *Run) error {
	sub := ""
	if len(r.Args) > 0 {
		sub = r.Args[0]
	}
	if len(r.Args) > 0 && (sub == "set" || sub == "rotate") {
		return r.valuesSetOrRotate(sub)
	}
	if len(r.Args) > 0 && sub == "delete" {
		return r.valuesDelete()
	}
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	ctx, err := r.resolveFromArgs(cwd)
	if err != nil {
		return contextError(err)
	}
	api := r.client(ctx)
	switch {
	case len(r.Args) > 0 && sub == "list":
		return r.valuesList(ctx, api)
	case len(r.Args) > 0 && sub == "rotate-complete":
		if len(r.Args) < 2 {
			return UsageError("Usage: varlatch values rotate-complete <ITEM>")
		}
		item := r.Args[1]
		c, err := api.get()
		if err != nil {
			return err
		}
		if _, err := c.CompleteRotation(context.Background(), ctx.Organization, ctx.Project, environmentOf(ctx), item); err != nil {
			return err
		}
		return r.println(item + " rotation complete — previous value retired.")
	}
	return UsageError("Usage: varlatch values <set|list|delete|rotate|rotate-complete>")
}

// valueFreeOptions is strictOptions for a command whose arguments may hold
// a Secret (values set, values rotate): an argument the parser refuses is
// never repeated, whatever its spelling, since it may be the value or part
// of it; the message names its place among the command's arguments. The
// status is 64, as for any wrong command line (go/README.md, "No message
// holds a value").
func valueFreeOptions(command string, args []string, spec OptionSpec, usage string) (*ParsedOptions, error) {
	parsed, err := ParseOptions(args, spec)
	if err == nil {
		return parsed, nil
	}
	var o *OptionsError
	if !errors.As(err, &o) {
		return nil, err
	}
	message := o.Message
	switch o.Rejected {
	case "unexpected":
		message = "unexpected argument " + strconv.Itoa(o.Index) + ", not shown since it may be part of a value (a value with spaces goes in quotes)"
	case "unknown":
		message = "unknown option at argument " + strconv.Itoa(o.Index) + `, not shown since it may be a value (a value that begins with "-" goes after --)`
	}
	return nil, UsageErrorWithUsage("varlatch "+command+": "+message, "\n"+usage)
}

var wholeSeconds = regexp.MustCompile(`^[0-9]+$`)

func (r *Run) valuesSetOrRotate(sub string) error {
	usage := valuesSetUsage
	values := []string{"--environment", "--server", "--from-file", "--generate", "--replace"}
	if sub == "rotate" {
		usage = valuesRotateUsage
		values = append(values, "--grace")
	}
	// Strict (ADR-0043 Decision 10), before anything is read, prompted or
	// written: an option typo such as `--env production` must never become
	// the stored value. A value that begins with "-" goes after `--`.
	parsed, err := valueFreeOptions("values "+sub, r.Args, OptionSpec{
		Values:       values,
		Booleans:     []string{"--stdin"},
		Aliases:      []Alias{{"-e", "--environment"}},
		Positionals:  3,
		EndOfOptions: true,
	}, usage)
	if err != nil {
		return err
	}
	if len(parsed.Positionals) < 2 || strings.HasPrefix(parsed.Positionals[1], "-") {
		return UsageError(usage)
	}
	item := parsed.Positionals[1]
	grace, hasGrace := parsed.Value("--grace")
	if hasGrace && !wholeSeconds.MatchString(grace) {
		// The value is not repeated: a refused argument may be a Secret.
		return UsageError("varlatch values rotate: --grace needs a whole number of seconds\n" + usage)
	}
	// --replace names the one item this command replaces: approval for one item never covers another.
	replace, hasReplace := parsed.Value("--replace")
	if hasReplace && replace != item {
		verb := "sets"
		if sub == "rotate" {
			verb = "rotates"
		}
		return UsageError("varlatch values " + sub + ": --replace names " + replace + ", but this command " + verb + " " + item + "; approval for one item never covers another.\n" + usage)
	}
	// The value source and the generator are part of the command line: checked before any request.
	options := secretinput.Options{Stdin: parsed.Has("--stdin")}
	if len(parsed.Positionals) > 2 {
		// Node reads the command line as UTF-8, each ill-formed sequence as U+FFFD.
		options.Value, options.HasValue = jsval.DecodeUTF8([]byte(parsed.Positionals[2])), true
		// No output or diagnostic shows it from here on, whatever its length.
		r.holdValue(options.Value)
	}
	options.File, options.HasFile = parsed.Value("--from-file")
	options.Generate, options.HasGen = parsed.Value("--generate")
	source, err := secretinput.SourceOf(options)
	if err != nil {
		return secretInputFailure(err)
	}
	// The context from the parsed options only: nothing after `--` is read as an option.
	var where []string
	if env, ok := parsed.Value("--environment"); ok {
		where = append(where, "--environment", env)
	}
	if server, ok := parsed.Value("--server"); ok {
		where = append(where, "--server", server)
	}
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	ctx, err := r.resolveArgs(cwd, where)
	if err != nil {
		return contextError(err)
	}
	api := r.client(ctx)
	environment := environmentOf(ctx)
	// Refusals that need no value (a Secret on the command line, a prompt in assisted mode) come first.
	if err := r.refuseValueSource(sub, item, r.contextOptions(where, environment, ctx.Server), source, func() (bool, error) {
		return sensitiveItem(api, ctx, item)
	}); err != nil {
		return err
	}
	// Assisted mode: replacing an existing value needs --replace <ITEM>, checked before any value is
	// read, prompted for, generated, or written. --replace records the override's intent; it does not
	// prove that a human approved it.
	if r.Assisted.On && replace != item {
		presence, unknown, err := valuePresence(api, ctx, item)
		if err != nil {
			return err
		}
		if presence != "absent" {
			verb := "setting"
			if sub == "rotate" {
				verb = "rotating"
			}
			var said string
			switch presence {
			case "present":
				said = "varlatch values " + sub + ": " + item + " already has a value in " + environment + "; " + verb + " it replaces that value. "
			case "inherited":
				said = "varlatch values " + sub + ": " + environment + " inherits a value for " + item + " from its parent environment; " + verb + " it here overrides that value in " + environment + ". "
			default:
				said = "varlatch values " + sub + ": whether " + item + " already has a value in " + environment + " cannot be checked (" + unknown + "), so it counts as existing. "
			}
			return Fail(said+"Replacing it is the human's decision, for this item only: ask them, and with their approval add --replace "+item+". Nothing was stored.", ExitConfig)
		}
	}
	// How to rotate this credential, from the Contract: before the value is asked for or sent and again after.
	hint, hasHint := "", false
	if sub == "rotate" {
		hint, hasHint = rotationHintOf(api, ctx, item)
	}
	if hasHint {
		r.eprintln("How to rotate " + item + " (from the Contract): " + r.Secrets.ServerMessage(hint))
	}
	value, generated, err := r.obtainValue(source, item)
	if err != nil {
		return err
	}
	// An unpaired UTF-16 surrogate (possible in a Windows command line) has no exact UTF-8 form.
	if !secretinput.IsWellFormed(value) {
		return Fail("varlatch: the value is not well-formed Unicode text; nothing was stored.", ExitFailure)
	}
	// No output or diagnostic shows the value, a server's echo of it
	// included, whatever its length (issue #119).
	r.holdValue(value)
	how := ""
	if generated != nil {
		how = " to a generated value (" + secretinput.DescribeGenerated(*generated) + "; not shown)"
	}
	c, err := api.get()
	if err != nil {
		return err
	}
	if sub == "set" {
		version, err := c.SetValue(context.Background(), ctx.Organization, ctx.Project, environment, item, value)
		if err != nil {
			return err
		}
		id, ok, err := read(version, true, "versionId")
		if err != nil {
			return err
		}
		shown, err := shownID(id, ok, "ver")
		if err != nil {
			return err
		}
		return r.println(item + " set (version " + shown + ")" + how + ".")
	}
	var graceSeconds *float64
	if hasGrace {
		n, _ := strconv.ParseFloat(grace, 64) // Number(digits)
		graceSeconds = &n
	}
	rot, err := c.BeginRotation(context.Background(), ctx.Organization, ctx.Project, environment, item, value, graceSeconds)
	if err != nil {
		return err
	}
	primary, pOK, err := read(rot, true, "primaryVersionId")
	if err != nil {
		return err
	}
	shown, err := shownID(primary, pOK, "ver")
	if err != nil {
		return err
	}
	deadline, _, _ := read(rot, true, "rotationDeadline")
	if err := r.println(item + " rotating" + how + " — new primary " + shown + ", previous value valid until " + templateTime(deadline) +
		". Run \"varlatch values rotate-complete " + item + "\" once consumers have migrated."); err != nil {
		return err
	}
	if hasHint {
		r.eprintln("Remaining steps for " + item + " (from the Contract): " + r.Secrets.ServerMessage(hint))
	}
	return nil
}

// UnrecognizedID is said in place of a server's identifier that does not
// have the server's shape.
const UnrecognizedID = "an unrecognized id"

// shownID is printable(value) for an identifier read from an answer: one of
// the server's own (`<prefix>_` and 26 characters of lower-case base32) as
// it is, any other text as UnrecognizedID, so a server never puts a value
// (or anything else) where the CLI shows an id. printable() takes a
// string, and TypeScript throws a TypeError for anything else, as here.
func shownID(v any, present bool, prefix string) (string, error) {
	if s, ok := v.(string); ok {
		if serverID(prefix).MatchString(s) {
			return s, nil
		}
		return UnrecognizedID, nil
	}
	if !present || v == nil {
		return "", typeErrorRead(v, present, "replace")
	}
	return "", &clientctx.TypeError{Message: "text.replace is not a function"}
}

// serverID is the shape of the server's identifiers of a kind
// (services/varlatchd/src/db/ids.ts: a prefix and 128 random bits in
// lower-case base32).
func serverID(prefix string) *regexp.Regexp {
	return regexp.MustCompile(`^` + prefix + `_[a-z2-7]{26}$`)
}

// eprintln writes one line on stderr, as console.error does, through the
// fail-safe (Run.warn).
func (r *Run) eprintln(text string) { _ = r.warn(text) }

// secretInputFailure is a SecretInputError as main.ts fails with it: 64
// for a wrong command line, 1 for the input it names.
func secretInputFailure(err error) error {
	var s *secretinput.Error
	if errors.As(err, &s) {
		code := ExitFailure
		if s.Usage {
			code = ExitUsage
		}
		return Fail("varlatch: "+s.Message, code)
	}
	return err
}

// refuseValueSource is main.ts's refuseValueSource: the refusals that need
// no value. In assisted mode a Secret's value is never taken from the
// command line, and there is no prompt: a coding agent cannot type into
// one, and the human uses their own terminal instead. A prompt or --stdin
// that cannot work here is refused too. Nothing is read, prompted for, or
// generated.
func (r *Run) refuseValueSource(sub, item, where string, source secretinput.Source, sensitive func() (bool, error)) error {
	// Every command names the environment (and an overridden server): a handoff without -e would target
	// the default one. The human's command has no --assisted, so it prompts.
	target := item + " " + where
	safeForms := strings.Join([]string{
		"  A value from elsewhere (a provider's key, a password) is the human's to enter. Ask them to run this",
		"  in their own terminal, where it prompts without showing the value, or to use the dashboard:",
		"    varlatch values " + sub + " " + target,
		"  Or store it without putting the value in a command:",
		"    varlatch --assisted values " + sub + " " + target + " --generate hex:32       a new random value, for a value nothing else holds",
		"    varlatch --assisted values " + sub + " " + target + " --from-file <path>      from a file",
		"    <command> | varlatch --assisted values " + sub + " " + target + " --stdin     from another command's output",
	}, "\n")
	switch source.Kind {
	case secretinput.Argument:
		if r.Assisted.On {
			isSecret, err := sensitive()
			if err != nil {
				return err
			}
			if isSecret {
				return UsageError("varlatch: " + item + " is a Secret, and in assisted mode a Secret's value is never taken from the command line. " +
					"Nothing was stored.\n" + safeForms)
			}
		}
	case secretinput.Stdin:
		if secretinput.IsTerminal(r.Stdin) {
			return UsageError("varlatch: --stdin reads a pipe or a file, and standard input is a terminal. For a hidden prompt, leave the value out: varlatch values " + sub + " " + item)
		}
	case secretinput.Prompt:
		if r.Assisted.On {
			return UsageError("varlatch: no value given for " + item + ", and assisted mode never prompts. Nothing was stored.\n" + safeForms)
		}
		if !secretinput.IsTerminal(r.Stdin) {
			return UsageError("varlatch: no value given for " + item + ". Pass --stdin, --from-file <path>, or --generate <spec>, " +
				"or run the command in a terminal for a hidden prompt.")
		}
	}
	return nil
}

// obtainValue is main.ts's obtainValue: the value itself, once every check
// has passed: read, generated, or prompted for.
func (r *Run) obtainValue(source secretinput.Source, item string) (string, *secretinput.GenerateSpec, error) {
	var value string
	var err error
	switch source.Kind {
	case secretinput.Argument:
		return source.Value, nil, nil
	case secretinput.Stdin:
		var b []byte
		if b, err = readAllStdin(r.Stdin); err == nil {
			value, err = secretinput.FromBytes(b, "standard input")
		}
	case secretinput.File:
		value, err = secretinput.ReadFile(source.Path)
	case secretinput.Generate:
		spec := source.Spec
		if value, err = secretinput.GenerateValue(spec); err == nil {
			return value, &spec, nil
		}
	case secretinput.Prompt:
		value, err = r.promptHidden("Value for " + item + " (input hidden): ")
	}
	if err != nil {
		if _, cancelled := err.(secretinput.Cancelled); cancelled {
			return "", nil, ExitWith(ExitInterrupted)
		}
		return "", nil, secretInputFailure(err)
	}
	return value, nil, nil
}

// readAllStdin is secretInput.ts's readAll(process.stdin).
func readAllStdin(stdin io.Reader) ([]byte, error) {
	if stdin == nil {
		return nil, nil
	}
	return io.ReadAll(stdin)
}

// promptHidden is secretInput.ts's promptHidden on the run's standard
// input (a terminal: refuseValueSource checked) and standard error.
func (r *Run) promptHidden(question string) (string, error) {
	f, ok := r.Stdin.(*os.File)
	if !ok {
		return "", &secretinput.Error{Message: "no value entered; nothing was stored"}
	}
	return secretinput.PromptHidden(f, func(text string) { _ = r.ask(text) }, question)
}

// valuePresence is main.ts's valuePresence: whether the environment
// already has a value for item, from its effective configuration's
// metadata (names only). A value inherited from a parent environment
// counts. When the server cannot say (denied, missing), the answer is
// unknown ("unknown", with the status and code), never "absent"; an
// unreachable server fails as usual (69).
func valuePresence(api *lazyClient, ctx *clientctx.Context, item string) (string, string, error) {
	c, err := api.get()
	if err != nil {
		return "", "", err
	}
	effective, err := c.EffectiveConfiguration(context.Background(), ctx.Organization, ctx.Project, environmentOf(ctx), false)
	if err != nil {
		var a *apiclient.APIError
		if errors.As(err, &a) {
			return "unknown", strconv.Itoa(a.Status) + " " + safeCode(a.Code), nil
		}
		return "", "", err
	}
	items, err := itemsOf(effective)
	if err != nil {
		return "", "", err
	}
	for _, i := range items {
		name, _ := jsval.Get(i, "name")
		if s, ok := name.(string); ok && s == item {
			if source, _ := jsval.Get(i, "source"); source == "parent" {
				return "inherited", "", nil
			}
			return "present", "", nil
		}
	}
	return "absent", "", nil
}

// itemsOf is `effective.items ?? []` for an answer that is an object.
func itemsOf(answer any) ([]any, error) {
	items, ok, err := read(answer, true, "items")
	if err != nil {
		return nil, err
	}
	if !ok || items == nil {
		return nil, nil
	}
	list, isList := items.([]any)
	if !isList {
		return nil, &clientctx.TypeError{Message: "(effective.items ?? []).find is not a function"}
	}
	return list, nil
}

// contractItems is `revision.contract.items` of an active Contract answer,
// nil when it has none.
func contractItems(revision any) ([]any, error) {
	c, ok, err := read(revision, true, "contract")
	if err != nil {
		return nil, err
	}
	items, ok, err := read(c, ok, "items")
	if err != nil || !ok {
		return nil, err
	}
	list, _ := items.([]any)
	return list, nil
}

// findItem is `items?.find((i) => i.name === name)`.
func findItem(items []any, name string) (any, error) {
	for _, i := range items {
		n, ok, err := read(i, true, "name")
		if err != nil {
			return nil, err
		}
		if s, isString := n.(string); ok && isString && s == name {
			return i, nil
		}
	}
	return nil, nil
}

// rotationHintOf is main.ts's rotationHintOf: the item's rotation hint
// from the active Contract (ADR-0053). Any failure, a refused Contract
// read included, only means no hint; a hint that would not pass
// validation is not printed.
func rotationHintOf(api *lazyClient, ctx *clientctx.Context, item string) (string, bool) {
	c, err := api.get()
	if err != nil {
		return "", false
	}
	revision, err := c.GetActiveContract(context.Background(), ctx.Organization, ctx.Project)
	if err != nil {
		return "", false
	}
	items, err := contractItems(revision)
	if err != nil {
		return "", false
	}
	found, err := findItem(items, item)
	if err != nil || found == nil {
		return "", false
	}
	hint, _ := jsval.Get(found, "rotationHint")
	s, ok := hint.(string)
	if !ok || contract.RotationHintProblem(s) != "" {
		return "", false
	}
	return s, true
}

// sensitiveItem is main.ts's sensitiveItem: whether item is a Secret by
// the active Contract. Items outside it, and every item of a project
// without one, are (ADR-0012); a Contract this caller cannot read (403) or
// that is missing (404) leaves the item a Secret, the safe classification.
func sensitiveItem(api *lazyClient, ctx *clientctx.Context, item string) (bool, error) {
	c, err := api.get()
	if err != nil {
		return false, err
	}
	revision, err := c.GetActiveContract(context.Background(), ctx.Organization, ctx.Project)
	if err != nil {
		var a *apiclient.APIError
		if errors.As(err, &a) && (a.Status == 404 || a.Status == 403) {
			return true, nil
		}
		return false, err
	}
	items, err := contractItems(revision)
	if err != nil {
		return false, err
	}
	found, err := findItem(items, item)
	if err != nil {
		return false, err
	}
	if found == nil {
		return true, nil
	}
	sensitive, ok := jsval.Get(found, "sensitive")
	if !ok || sensitive == nil {
		return true, nil // `?? true`
	}
	return jsjson.Truthy(sensitive), nil
}

func (r *Run) valuesDelete() error {
	// Strict, in every mode, before any request (ADR-0043 Decision 10): a typo such as `--env production`
	// must not delete the default environment's value.
	parsed, err := strictOptions("values delete", r.Args, OptionSpec{
		Values:      []string{"--environment", "--server", "--confirm"},
		Aliases:     []Alias{{"-e", "--environment"}},
		Positionals: 2,
	}, valuesDeleteUsage)
	if err != nil {
		return err
	}
	if len(parsed.Positionals) < 2 {
		return UsageError(valuesDeleteUsage)
	}
	item := parsed.Positionals[1]
	confirm, hasConfirm := parsed.Value("--confirm")
	if hasConfirm && confirm != item {
		return UsageError("varlatch values delete: --confirm names " + confirm + ", but this command deletes " + item + "; approval for one item never covers another.\n" + valuesDeleteUsage)
	}
	var where []string
	if env, ok := parsed.Value("--environment"); ok {
		where = append(where, "--environment", env)
	}
	if server, ok := parsed.Value("--server"); ok {
		where = append(where, "--server", server)
	}
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	ctx, err := r.resolveArgs(cwd, where)
	if err != nil {
		return contextError(err)
	}
	environment := environmentOf(ctx)
	// Assisted mode: every deletion, of a plain value or a Secret, needs the item named with --confirm,
	// checked before any request. --confirm records the deletion's intent; it does not prove that a human
	// approved it.
	if r.Assisted.On && !hasConfirm {
		return Fail("varlatch values delete: deleting "+item+" from "+environment+" is the human's decision, for this item in this environment. "+
			"Ask them, and with their approval for "+item+" in "+environment+", add --confirm "+item+". "+
			"Or the human runs, in their own terminal:\n  varlatch values delete "+item+" "+r.contextOptions(where, environment, ctx.Server)+"\nNothing was deleted.", ExitConfig)
	}
	c, err := r.client(ctx).get()
	if err != nil {
		return err
	}
	if _, err := c.DeleteValue(context.Background(), ctx.Organization, ctx.Project, environment, item); err != nil {
		return err
	}
	return r.println(item + " deleted from " + environment + ".")
}

// valuesList is `varlatch values list [--json]`: names and classification
// only; this command never fetches values.
func (r *Run) valuesList(ctx *clientctx.Context, api *lazyClient) error {
	c, err := api.get()
	if err != nil {
		return err
	}
	effective, err := c.EffectiveConfiguration(context.Background(), ctx.Organization, ctx.Project, environmentOf(ctx), false)
	if err != nil {
		return err
	}
	items, err := itemsOf(effective)
	if err != nil {
		return err
	}
	if hasArg(r.Args, "--json") {
		list := make([]any, len(items))
		for i, item := range items {
			o := jsjson.Object{}
			for _, key := range []string{"name", "sensitive", "source"} {
				// JSON.stringify leaves out a property that is undefined.
				if v, ok, err := read(item, true, key); err != nil {
					return err
				} else if ok {
					o = append(o, jsjson.Member{Key: key, Value: v})
				}
			}
			rotating, _ := jsval.Get(item, "rotating")
			list[i] = append(o, jsjson.Member{Key: "rotating", Value: rotating == true})
		}
		return r.printJSON(jsjson.Object{{Key: "version", Value: statusSchemaVersion}, {Key: "environment", Value: ctx.Environment}, {Key: "items", Value: list}})
	}
	for _, i := range items {
		name, nOK, err := read(i, true, "name")
		if err != nil {
			return err
		}
		sensitive, _ := jsval.Get(i, "sensitive")
		source, sOK := jsval.Get(i, "source")
		kind := "plain"
		if jsjson.Truthy(sensitive) {
			kind = "secret"
		}
		if err := r.println(Printable(jsTemplate(name, nOK)) + "  (" + kind + ", " + Printable(jsTemplate(source, sOK)) + ")"); err != nil {
			return err
		}
	}
	// The human format stays as it is; an active rotation is a note on stderr, with the command that
	// completes it where it lives. An inherited item rotates in the parent (inheritance is one level).
	var rotating []any
	inherited := false
	for _, i := range items {
		if v, _ := jsval.Get(i, "rotating"); jsjson.Truthy(v) {
			rotating = append(rotating, i)
			if source, _ := jsval.Get(i, "source"); source == "parent" {
				inherited = true
			}
		}
	}
	var parent any
	parentOK := false
	if inherited {
		parent, parentOK = r.parentEnvironment(c, ctx)
	}
	for _, i := range rotating {
		name, nOK, _ := read(i, true, "name")
		shown := jsTemplate(name, nOK)
		source, _ := jsval.Get(i, "source")
		owner, ownerOK := any(ctx.Environment), true
		parentName := "the parent environment"
		if parentOK && parent != nil {
			parentName = jsjson.String(parent)
		}
		subject := shown + " is rotating"
		if source == "parent" {
			owner, ownerOK = parent, parentOK
			subject = shown + " is inherited from " + parentName + ", where it is rotating"
		}
		command := ""
		if ownerOK && jsjson.Truthy(owner) {
			command = " (varlatch values rotate-complete " + shown + " " + r.contextOptions(r.Args, jsjson.String(owner), ctx.Server) + ")"
		}
		// One line of names from the server and the CLI's own words: escaped as a whole.
		r.eprintln(Printable(subject + ": its previous value still works until the rotation completes" + command + "."))
	}
	return nil
}

// parentEnvironment is the name of the environment's parent, from the
// project's environments; nothing when it cannot be found (the note then
// names no environment and offers no command).
func (r *Run) parentEnvironment(c *apiclient.Client, ctx *clientctx.Context) (any, bool) {
	answer, err := c.ListEnvironments(context.Background(), ctx.Organization, ctx.Project)
	if err != nil {
		return nil, false
	}
	envs, ok, err := read(answer, true, "items")
	if err != nil || !ok {
		return nil, false
	}
	list, isList := envs.([]any)
	if !isList {
		return nil, false
	}
	// envs.find((e) => e.name === ctx.environment): undefined matches a missing name.
	var self any
	selfOK := false
	for _, e := range list {
		if e == nil {
			return nil, false // reading a property of null throws, and the note names no environment
		}
		name, nameOK := jsval.Get(e, "name")
		if strictEqualPresent(name, nameOK, ctx.Environment, true) {
			self, selfOK = e, true
			break
		}
	}
	var parentID any
	parentIDOK := false
	if selfOK {
		parentID, parentIDOK = jsval.Get(self, "parentEnvironmentId")
	}
	for _, e := range list {
		id, idOK := jsval.Get(e, "id")
		if strictEqualPresent(id, idOK, parentID, parentIDOK) {
			return jsval.Get(e, "name")
		}
	}
	return nil, false
}

// strictEqualPresent is === between two values read as properties, an
// absent one being undefined.
func strictEqualPresent(a any, aOK bool, b any, bOK bool) bool {
	if !aOK || !bOK {
		return !aOK && !bOK
	}
	return jsval.StrictEqual(a, b)
}
