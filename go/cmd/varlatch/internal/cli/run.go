// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/matcher"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch run` (slice 5.4b of internal docs/design/go-cli.md): main.ts's
// "run" case for a default run and its assisted form, inject.ts and
// exportContext.ts. The command gets this process's environment with every
// delivered value over it (inject.ts's buildEnv); --export-context adds
// VARLATCH_RUN_CONTEXT; --omit leaves named items out; in assisted mode the
// output is masked by internal/matcher and a Secret too short to mask stops
// the run (78) unless the human allowed it (--allow-unmasked, outside
// assisted mode); --redact (5.4c, redact.ts, ADR-0038 Decision 10) masks
// the delivered Secrets outside assisted mode too, and refuses when stdout
// or stderr is a terminal or the run is agent-safe; --strict (5.4f,
// strictrun.go) validates the whole environment against the Contract
// first; --agent-safe (with or without --strict, agentrun.go) and a run
// inside an agent-safe run (nestedrun.go) are slice 5.5b's.

const runUsage = "Usage: varlatch run [-e <environment>] [--server <url>] [--export-context | --strict [--allow-inherited <NAME>]...] [--redact | --no-redact] [--allow-unmasked <NAME>]... [--omit <NAME>]... " +
	"[--agent-safe --agent <identity> --allow-host <host[:port]>... --target <NAME=kind:location>... [--broker-credential-file <path>] [--agent-network strict] [--ttl <s>] [--agent-metadata]] -- <command> [args...]"

// runOptions is RUN_OPTIONS: every option `varlatch run` takes before `--`.
var runOptions = OptionSpec{
	Values:       []string{"--environment", "--server", "--agent", "--broker-credential-file", "--agent-network", "--ttl"},
	Lists:        []string{"--allow-unmasked", "--allow-inherited", "--allow-host", "--target", "--omit"},
	Booleans:     []string{"--export-context", "--strict", "--redact", "--no-redact", "--agent-safe", "--agent-metadata"},
	OnceBooleans: true,
	Aliases:      []Alias{{"-e", "--environment"}},
}

// strictExit is STRICT_EXIT (EX_CONFIG).
const strictExit = 78

// flagValues is main.ts's flags(): every value given after name.
func flagValues(args []string, name string) []string {
	var out []string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			out = append(out, args[i+1])
		}
	}
	return out
}

// allowUnmaskedNames is allowUnmaskedNames: the items named with
// --allow-unmasked, checked strictly before anything is fetched or
// started. A malformed form must not leave the list empty (that would
// select a run in which no Secret is masked).
func allowUnmaskedNames(args []string) ([]string, error) {
	var names []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		for _, option := range []string{"--allow-unmasked", "--no-redact"} {
			if strings.HasPrefix(arg, option+"=") {
				write := "--no-redact"
				if option == "--allow-unmasked" {
					write = "--allow-unmasked <NAME>"
				}
				return nil, UsageError("varlatch: " + option + "=... is not supported; write " + write + ". Nothing was started.")
			}
		}
		if arg != "--allow-unmasked" {
			continue
		}
		if i+1 >= len(args) {
			return nil, UsageError("varlatch: --allow-unmasked needs an item's name: --allow-unmasked <NAME>, before `--`. Nothing was started.")
		}
		if !configItemName.MatchString(args[i+1]) {
			return nil, UsageError("varlatch: --allow-unmasked needs an item's name, not " + args[i+1] + ": --allow-unmasked <NAME>, before `--`. Nothing was started.")
		}
		names = append(names, args[i+1])
		i++
	}
	return names, nil
}

// omitNames is omitNames: the items named with --omit, each an item's
// name, none also allowed unmasked or inherited.
func omitNames(args []string) ([]string, error) {
	names := flagValues(args, "--omit")
	for _, name := range names {
		if !configItemName.MatchString(name) {
			return nil, UsageError("varlatch: --omit needs an item's name, not " + name + ": --omit <NAME>, before `--`. Nothing was started.")
		}
	}
	for _, option := range []string{"--allow-unmasked", "--allow-inherited"} {
		var both []string
		for _, n := range flagValues(args, option) {
			if slices.Contains(names, n) && !slices.Contains(both, n) {
				both = append(both, n)
			}
		}
		if len(both) > 0 {
			slices.SortFunc(both, jsval.CompareUTF16)
			return nil, UsageError("varlatch: --omit and " + option + " cannot name the same item: " + strings.Join(both, ", ") + ". Nothing was started.")
		}
	}
	var unique []string
	for _, n := range names {
		if !slices.Contains(unique, n) {
			unique = append(unique, n)
		}
	}
	return unique, nil
}

// runPolicyOptions is runPolicyOptions: the run's options a remedy repeats.
func runPolicyOptions(args []string) []string {
	var out []string
	if hasArg(args, "--strict") {
		out = append(out, "--strict")
	}
	for _, n := range flagValues(args, "--allow-inherited") {
		out = append(out, "--allow-inherited "+n)
	}
	if hasArg(args, "--export-context") {
		out = append(out, "--export-context")
	}
	seen := map[string]bool{}
	for _, n := range flagValues(args, "--omit") {
		if !seen[n] {
			out = append(out, "--omit "+n)
		}
		seen[n] = true
	}
	return out
}

// omittedNotice is omittedNotice: what --omit left out, said before the
// command starts.
func omittedNotice(omitted []string, masking, agent bool) string {
	if len(omitted) == 0 {
		return ""
	}
	them := "them"
	if len(omitted) == 1 {
		them = "it"
	}
	sorted := slices.Clone(omitted)
	slices.SortFunc(sorted, jsval.CompareUTF16)
	notice := "varlatch: left out of this run (--omit), so the command does not get " + them
	if masking {
		notice += ", and not masked if the command obtains " + them + " another way"
	}
	notice += ": " + strings.Join(sorted, ", ")
	if agent {
		notice += "\nvarlatch: name " + them + " in your answer; the command starting does not show that the task was done"
	}
	return notice
}

func runCommand(r *Run) error {
	sep := slices.Index(r.Args, "--")
	if sep < 0 || sep == len(r.Args)-1 {
		return UsageOnly(runUsage)
	}
	pre := r.Args[:sep]
	command, commandArgs := r.Args[sep+1], r.Args[sep+2:]
	// Strict (ADR-0043 Decision 10), in every mode and before anything is
	// fetched or started: an unknown or misspelled option must never select
	// a run in which no Secret is masked. The command's own arguments are
	// never read.
	if _, err := allowUnmaskedNames(pre); err != nil {
		return err
	}
	if _, err := strictOptions("run", pre, runOptions, runUsage); err != nil {
		return err
	}
	omit, err := omitNames(pre)
	if err != nil {
		return err
	}
	if agentRun := clientctx.AgentRunOf(r.Env); agentRun != "" {
		return r.nestedRun(agentRun, pre, command, commandArgs, omit)
	}
	agentSafe, noRedact, redact := hasArg(pre, "--agent-safe"), hasArg(pre, "--no-redact"), hasArg(pre, "--redact")
	allowUnmasked, _ := allowUnmaskedNames(pre)
	switch {
	case agentSafe && (noRedact || len(allowUnmasked) > 0):
		return UsageError("--no-redact and --allow-unmasked do not apply to --agent-safe runs: the Agent receives Placeholders, not Secrets.")
	case noRedact && redact:
		return UsageError("--redact and --no-redact cannot be combined.")
	case !agentSafe && hasArg(pre, "--target"):
		return UsageError("--target applies only to --agent-safe runs.")
	case hasArg(pre, "--export-context") && (hasArg(pre, "--strict") || agentSafe):
		return UsageError("--export-context applies only to default runs; a --strict run always gives the command its run context.")
	case hasArg(pre, "--allow-inherited") && !hasArg(pre, "--strict"):
		return UsageError("--allow-inherited applies only to --strict runs.")
	}
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	// Assisted mode refuses both ways of showing a Secret: the choice is
	// the human's, for a named item, in their own terminal.
	if r.Assisted.On && (noRedact || len(allowUnmasked) > 0) {
		shown := allowUnmasked
		if len(shown) == 0 {
			shown = []string{"<NAME>"}
		}
		which := "--allow-unmasked"
		if noRedact {
			which = "--no-redact"
		}
		target := "-e <environment>"
		if ctx, err := r.resolveArgs(cwd, pre); err == nil {
			target = r.contextOptions(pre, environmentOf(ctx), ctx.Server)
		}
		parts := append([]string{target}, runPolicyOptions(pre)...)
		for _, n := range shown {
			parts = append(parts, "--allow-unmasked "+n)
		}
		return UsageError("varlatch: " + which + " is refused in assisted mode: showing a Secret unmasked is the human's decision, " +
			"for a named item, made in their own terminal. Report the item and wait. The human runs, outside assisted mode (every other Secret stays masked):\n" +
			"  varlatch run " + strings.Join(parts, " ") + " -- <command>\n" +
			"Nothing was started.")
	}
	if !r.Assisted.On && len(allowUnmasked) > 0 && noRedact {
		return UsageError("--allow-unmasked shows only the named items and keeps every other Secret masked; it cannot be combined with --no-redact.")
	}
	humanOverride := !r.Assisted.On && !agentSafe && len(allowUnmasked) > 0
	assistedRedaction := (r.Assisted.On && !agentSafe) || humanOverride
	// Output redaction (ADR-0038 Decision 10): refused before anything is
	// fetched. Assisted mode gives the command pipes, so a terminal does not
	// matter there.
	if redact {
		if refusal := redactRefusal(agentSafe, !r.Assisted.On && isTerminal(r.Stdout), !r.Assisted.On && isTerminal(r.Stderr)); refusal != "" {
			return UsageError("varlatch: " + refusal + ". Nothing was started.")
		}
	}
	if humanOverride {
		r.eprintln("varlatch: showing " + strings.Join(allowUnmasked, ", ") + " unmasked in this run only, if too short to mask; every other known Secret stays masked.")
	}
	ctx, err := r.resolveArgs(cwd, pre)
	if err != nil {
		return contextError(err)
	}
	api := r.client(ctx)
	if hasArg(pre, "--strict") && agentSafe {
		opts, err := agentRunFlags(pre)
		if err != nil {
			return err
		}
		return agentSafeFailure(r.runAgentSafeStrict(ctx, api, opts, flagValues(pre, "--allow-inherited"), command, commandArgs))
	}
	if agentSafe {
		// ADR-0022: Placeholders and a local Broker; the Agent gets no bearer.
		opts, err := agentRunFlags(pre)
		if err != nil {
			return err
		}
		return agentSafeFailure(r.runAgentSafe(ctx, api, opts, command, commandArgs))
	}
	c, err := api.get()
	if err != nil {
		return err
	}
	if hasArg(pre, "--strict") {
		return r.strictRun(ctx, c, pre, command, commandArgs, omit, allowUnmasked, assistedRedaction, redact)
	}
	return r.defaultRun(ctx, c, cwd, pre, command, commandArgs, omit, allowUnmasked, assistedRedaction, redact)
}

// defaultRun is the default run: read, inject, start.
func (r *Run) defaultRun(ctx *clientctx.Context, c *apiclient.Client, cwd string, pre []string, command string, commandArgs, omit, allowUnmasked []string, assistedRedaction, redact bool) error {
	omitted := map[string]bool{}
	for _, n := range omit {
		omitted[n] = true
	}
	exporting := hasArg(pre, "--export-context")
	environment := environmentOf(ctx)
	read := func() (configurationRead, error) {
		effective, err := c.EffectiveConfiguration(context.Background(), ctx.Organization, ctx.Project, environment, true)
		if err != nil {
			return configurationRead{}, err
		}
		got := configurationRead{configurationDigest: digestOf(effective), disclosureDigest: nil, effective: effective}
		// Before any Secret is disclosed: a misspelled --omit discloses nothing.
		if len(omit) > 0 {
			known, err := r.namesForOmit(ctx, c, effective, omit)
			if err != nil {
				return got, err
			}
			var unknown []string
			for _, n := range omit {
				if !known[n] {
					unknown = append(unknown, n)
				}
			}
			if len(unknown) > 0 {
				slices.SortFunc(unknown, jsval.CompareUTF16)
				return got, UsageError("varlatch: --omit must name an item stored in this environment or in its Contract; not found: " + Printable(strings.Join(unknown, ", ")) + ". Nothing was started.")
			}
		}
		// Before any Secret is disclosed: a run that cannot export its context discloses nothing.
		if exporting {
			if got.encode, err = r.prepareExportedContext(c, ctx.Organization, ctx.Project, effective); err != nil {
				return got, err
			}
		}
		// An omitted Secret is never asked for.
		var wanted []any
		for _, item := range listOf(effective, "items") {
			if name, ok := stringField(item, "name"); ok && jsjson.Truthy(fieldOf(item, "sensitive")) && !omitted[name] {
				wanted = append(wanted, name)
			}
		}
		if len(omit) > 0 && len(wanted) == 0 {
			return got, nil
		}
		body := jsjson.Object{{Key: "scope", Value: "all-authorized-secrets"}}
		if len(omit) > 0 {
			body = jsjson.Object{{Key: "items", Value: wanted}}
		}
		disclosed, err := c.DiscloseSecrets(context.Background(), ctx.Organization, ctx.Project, environment, body)
		var apiErr *apiclient.APIError
		if errors.As(err, &apiErr) {
			code, _ := apiErr.Code.(string)
			if code == "PERMISSION_DENIED" || strings.HasPrefix(code, "TAILNET_") {
				r.eprintln("varlatch: secrets not disclosed (" + SafeAPICode(code) + "); continuing with non-sensitive values")
				return got, nil
			}
		}
		if err != nil {
			return got, err
		}
		got.disclosureDigest = digestOf(disclosed)
		values := map[string]any{}
		for _, item := range listOf(disclosed, "items") {
			if name, ok := stringField(item, "name"); ok {
				values[name] = fieldOf(item, "value")
			}
		}
		for _, item := range listOf(effective, "items") {
			name, _ := stringField(item, "name")
			if v, ok := values[name]; ok && jsjson.Truthy(fieldOf(item, "sensitive")) {
				if o, ok := item.(jsjson.Object); ok {
					setInPlace(o, "value", v)
				}
			}
		}
		return got, nil
	}
	var got configurationRead
	var err error
	if exporting {
		got, err = r.readConsistently(read)
	} else {
		got, err = read()
	}
	if err != nil {
		return err
	}
	effective := got.effective
	var withheld, codes, connections []string
	for _, item := range listOf(effective, "items") {
		name := jsjson.String(fieldOf(item, "name"))
		if v := fieldOf(item, "value"); v == nil && !omitted[name] {
			if fieldOf(item, "oauth") != nil {
				connections = append(connections, name)
				continue
			}
			if fieldOf(item, "totp") != nil {
				codes = append(codes, name)
				continue
			}
			withheld = append(withheld, name)
		}
	}
	if len(connections) > 0 {
		// Always: its access token ends, and nothing in a process's environment
		// can refresh it (ADR-0062).
		r.eprintln("varlatch: " + itoa(len(connections)) + " OAuth connection(s) not delivered (an agent-safe run's Broker gets the access token when it is used): " + Printable(strings.Join(connections, ", ")))
	}
	if len(codes) > 0 {
		// Always: the seed is delivered to nobody, and a code would be stale
		// in an environment variable (ADR-0061).
		r.eprintln("varlatch: " + itoa(len(codes)) + " one-time code(s) not delivered, since a seed never is (an agent-safe run's Broker gets the code when it is used): " + Printable(strings.Join(codes, ", ")))
	}
	if len(withheld) > 0 {
		r.eprintln("varlatch: " + itoa(len(withheld)) + " value(s) withheld by policy: " + Printable(strings.Join(withheld, ", ")))
	}
	parent := r.parentVars()
	env := buildEnv(r.parentEnv(), effective, omitted)
	if got.encode != nil {
		encoded, err := got.encode(effective, parent, omitted)
		if err != nil {
			return err
		}
		env.Set(runContextName, encoded)
	}
	where := r.contextOptions(pre, environment, ctx.Server)
	if r.Assisted.On {
		for _, line := range assistedRunNotices(ctx, effective, command, where, cwd) {
			r.eprintln(line)
		}
	}
	notice := omittedNotice(omit, assistedRedaction || redact, r.Assisted.On)
	if assistedRedaction {
		names, err := r.knownSecretNames(ctx, c, effective)
		if err != nil {
			return err
		}
		set := assistedRedactionSet(deliveredSecrets(effective, env), env, parent, names)
		plan := planAssistedRedaction(set, allowUnmasked)
		if !r.assistedGate(plan, remedyContext{target: where, runOptions: runPolicyOptions(pre), assisted: r.Assisted.On}) {
			return ExitWith(strictExit)
		}
		if notice != "" {
			r.eprintln(notice)
		}
		code, err := r.runChild(command, commandArgs, env.Lines(), matcher.NewOutputRedaction(plan.entries, matcher.ModeAssisted))
		if err != nil {
			return err
		}
		return ExitWith(code)
	}
	if notice != "" {
		r.eprintln(notice)
	}
	var redaction *matcher.OutputRedaction
	if redact {
		redaction = matcher.NewOutputRedaction(deliveredSecrets(effective, env), matcher.ModeRedact)
	}
	code, err := r.runChild(command, commandArgs, env.Lines(), redaction)
	if err != nil {
		return err
	}
	return ExitWith(code)
}

// digestOf is the answer's stateDigest, apiclient.Undefined when it has
// none.
func digestOf(answer any) any {
	if v, ok := jsval.Get(answer, "stateDigest"); ok {
		return v
	}
	return apiclient.Undefined
}

// setInPlace sets an object member's value where it is, or adds it.
func setInPlace(o jsjson.Object, key string, value any) {
	for i := range o {
		if o[i].Key == key {
			o[i].Value = value
			return
		}
	}
}

func itoa(n int) string { return jsjson.String(float64(n)) }

// namesForOmit is namesForOmit: the names --omit may use, every item
// stored in the environment (withheld ones included) and every item of the
// active Contract, read only when a name is not stored.
func (r *Run) namesForOmit(ctx *clientctx.Context, c *apiclient.Client, effective any, omit []string) (map[string]bool, error) {
	names := map[string]bool{}
	manifest := fieldOf(effective, "manifest")
	for _, item := range append(listOf(effective, "items"), listOf(manifest, "items")...) {
		names[jsjson.String(fieldOf(item, "name"))] = true
	}
	all := true
	for _, n := range omit {
		all = all && names[n]
	}
	if all || jsjson.Truthy(manifest) && !jsjson.Truthy(fieldOf(manifest, "contract")) {
		return names, nil
	}
	revision, err := c.GetActiveContract(context.Background(), ctx.Organization, ctx.Project)
	var apiErr *apiclient.APIError
	if errors.As(err, &apiErr) && (apiErr.Status == 404 || apiErr.Status == 403) {
		return names, nil
	} else if err != nil {
		return nil, err
	}
	for _, item := range listOf(fieldOf(revision, "contract"), "items") {
		names[jsjson.String(fieldOf(item, "name"))] = true
	}
	return names, nil
}

// parentEnv is this process's environment, in the order the system gives
// it where it can.
func (r *Run) parentEnv() *orderedEnv {
	env := newOrderedEnv()
	values := r.Environ()
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		env.Set(n, values[n])
	}
	return env
}

// buildEnv is inject.ts's buildEnv: base with every delivered value over
// it; an omitted item is not delivered and an inherited copy is removed; an
// inherited VARLATCH_RUN_CONTEXT is removed and none is injected.
func buildEnv(base *orderedEnv, effective any, omitted map[string]bool) *orderedEnv {
	base.Delete(runContextName)
	for n := range omitted {
		base.Delete(n)
	}
	for _, item := range listOf(effective, "items") {
		name := jsjson.String(fieldOf(item, "name"))
		if name == runContextName || omitted[name] {
			continue
		}
		if v := fieldOf(item, "value"); v != nil {
			base.Set(name, jsjson.String(v))
		}
	}
	return base
}

// redactRefusal is redact.ts's redactRefusal: why --redact refuses to
// start, or "".
func redactRefusal(agentSafe, stdoutIsTTY, stderrIsTTY bool) string {
	if agentSafe {
		return "--redact does not apply to --agent-safe runs: the Agent receives Placeholders, not Secrets, " +
			"so no Secret is delivered to it to mask, and an agent-safe run never fetches Secrets to build a filter"
	}
	var terminals []string
	if stdoutIsTTY {
		terminals = append(terminals, "stdout")
	}
	if stderrIsTTY {
		terminals = append(terminals, "stderr")
	}
	if len(terminals) == 0 {
		return ""
	}
	verb := "is a terminal"
	if len(terminals) == 2 {
		verb = "are terminals"
	}
	return "--redact works only when stdout and stderr are pipes or files, and " + strings.Join(terminals, " and ") + " " + verb +
		". Redirect both, for example: varlatch run --redact -- <command> 2>&1 | tee run.log"
}

// deliveredSecrets is redact.ts's deliveredSecrets: the sensitive values
// delivered in env, and nothing else.
func deliveredSecrets(effective any, env *orderedEnv) []matcher.SecretEntry {
	var out []matcher.SecretEntry
	for _, item := range listOf(effective, "items") {
		name, _ := stringField(item, "name")
		value, ok := fieldOf(item, "value").(string)
		if !jsjson.Truthy(fieldOf(item, "sensitive")) || !ok {
			continue
		}
		if v, set := env.Get(name); !set || v != value {
			continue
		}
		out = append(out, matcher.SecretEntry{Item: name, Value: value})
	}
	return out
}
