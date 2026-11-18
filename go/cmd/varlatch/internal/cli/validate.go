// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"slices"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch validate [--json]` (slice 5.3a of internal docs/design/go-cli.md),
// main.ts's "validate" case and validation.ts. A partial evaluation (items
// this identity may not read) is never presented as valid; it gets its own
// exit status so CI can tell "invalid" from "could not check everything".

// validate's exit statuses (frozen).
const (
	validateValid      = 0
	validateInvalid    = 1
	validateIncomplete = 2
)

var requiresHint = map[string]string{
	"config.metadata.read": "needs config.metadata.read",
	"config.value.read":    "needs config.value.read",
	"secret.reveal":        "needs secret.reveal",
}

// ValidationOutcome is validation.ts's ValidationOutcome.
type ValidationOutcome struct {
	Stdout   []string
	Stderr   []string
	ExitCode int
}

// listOr is `report[key] ?? []`: absent and null are an empty list.
func listOr(report any, key string) (any, error) {
	v, ok, err := read(report, true, key)
	if err != nil {
		return nil, err
	}
	if !ok || v == nil {
		return []any{}, nil
	}
	return v, nil
}

// lengthOf is `v.length` for a list or a string (UTF-16 units), 0 for
// anything without one (undefined > 0 is false).
func lengthOf(v any) int {
	switch x := v.(type) {
	case []any:
		return len(x)
	case string:
		return utf16Len(x)
	}
	return 0
}

// complete is `report.complete ?? notEvaluated.length === 0`.
func completeOf(report, notEvaluated any) any {
	if c, ok := jsval.Get(report, "complete"); ok && c != nil {
		return c
	}
	return lengthOf(notEvaluated) == 0
}

// prop is `item.<key>` as a template literal shows it.
func prop(item any, key string) (string, error) {
	v, ok, err := read(item, true, key)
	if err != nil {
		return "", err
	}
	return jsTemplate(v, ok), nil
}

// The words said in place of a report's field that is not one the protocol
// defines.
const (
	UnrecognizedReason      = "an unrecognized reason"
	UnrecognizedRequirement = "an unrecognized requirement"
)

var (
	notEvaluatedReasons = []string{"permission", "requirement"}
	unresolvedReasons   = []string{"authority", "reference"}
	requirements        = []string{"config.metadata.read", "config.value.read", "secret.reveal"}
)

// ProjectReport is the validation report as the CLI reads and shows it:
// the documented fields only (ValidationReport in
// packages/protocol/openapi.yaml), a field of an enumeration in it when
// the protocol defines it and a placeholder otherwise, so a server never
// puts anything else (an extra field, a value) into what validate prints,
// in --json or not. Names and an invalid item's reason (free text, which
// the protocol says never holds the value) are kept, as text. A report
// that is not an object, or a list that cannot be read, stays as it is,
// for the TypeError TypeScript throws.
func ProjectReport(report any) (any, error) {
	if _, ok := report.(jsjson.Object); !ok {
		return report, nil
	}
	out := jsjson.Object{}
	for _, key := range []string{"valid", "complete"} {
		if v, ok := jsval.Get(report, key); ok {
			if v != nil {
				v = jsjson.Truthy(v)
			}
			out = append(out, jsjson.Member{Key: key, Value: v})
		}
	}
	text := func(v any) any {
		if s, ok := v.(string); ok {
			return s
		}
		return jsjson.String(v)
	}
	enum := func(v any, allowed []string, placeholder string) any {
		if s, ok := v.(string); ok && slices.Contains(allowed, s) {
			return s
		}
		return placeholder
	}
	project := func(key string, fields func(item any) jsjson.Object) {
		v, ok := jsval.Get(report, key)
		if !ok {
			return
		}
		list, isList := v.([]any)
		if !isList {
			if s, isString := v.(string); isString {
				chars, _ := iterate(s, key)
				list = chars
			} else {
				out = append(out, jsjson.Member{Key: key, Value: v})
				return
			}
		}
		items := make([]any, len(list))
		for i, item := range list {
			if fields == nil || item == nil {
				items[i] = item
				if fields == nil && item != nil {
					items[i] = text(item)
				}
				continue
			}
			items[i] = fields(item)
		}
		out = append(out, jsjson.Member{Key: key, Value: items})
	}
	// fields keeps an item's documented members, in the item's own order,
	// each as shown gives it; an item that is not an object has none.
	fields := func(shown map[string]func(any) any) func(item any) jsjson.Object {
		return func(item any) jsjson.Object {
			o, ok := item.(jsjson.Object)
			if !ok {
				return jsjson.Object{}
			}
			kept := jsjson.Object{}
			for _, m := range o {
				if f, known := shown[m.Key]; known {
					kept = append(kept, jsjson.Member{Key: m.Key, Value: f(m.Value)})
				}
			}
			return kept
		}
	}
	reason := func(allowed []string) func(any) any {
		return func(v any) any { return enum(v, allowed, UnrecognizedReason) }
	}
	project("missing", nil)
	project("invalid", fields(map[string]func(any) any{"name": text, "reason": text}))
	project("unresolved", fields(map[string]func(any) any{"name": text, "reason": reason(unresolvedReasons)}))
	project("notEvaluated", fields(map[string]func(any) any{
		"name": text, "reason": reason(notEvaluatedReasons),
		"requires": func(v any) any { return enum(v, requirements, UnrecognizedRequirement) },
	}))
	if out == nil {
		out = jsjson.Object{}
	}
	return out, nil
}

// ValidationOutcomeOf is validation.ts's validationOutcome for a report
// the server sent, as ProjectReport shows it.
func ValidationOutcomeOf(environment string, report any) (ValidationOutcome, error) {
	report, err := ProjectReport(report)
	if err != nil {
		return ValidationOutcome{}, err
	}
	notEvaluated, err := listOr(report, "notEvaluated")
	if err != nil {
		return ValidationOutcome{}, err
	}
	complete := jsjson.Truthy(completeOf(report, notEvaluated))
	missing, _ := listOr(report, "missing")
	invalid, _ := listOr(report, "invalid")
	unresolved, _ := listOr(report, "unresolved")
	if valid, _ := jsval.Get(report, "valid"); jsjson.Truthy(valid) && complete {
		return ValidationOutcome{Stdout: []string{environment + ": valid"}, ExitCode: validateValid}, nil
	}
	unresolvedList, err := iterate(unresolved, "unresolved")
	if err != nil {
		return ValidationOutcome{}, err
	}
	failed := lengthOf(missing) > 0 || lengthOf(invalid) > 0
	if !failed {
		for _, u := range unresolvedList {
			reason, _, err := read(u, true, "reason")
			if err != nil {
				return ValidationOutcome{}, err
			}
			if reason == "reference" {
				failed = true
				break
			}
		}
	}
	var stderr []string
	switch {
	case failed && complete:
		stderr = append(stderr, environment+": INVALID")
	case failed:
		stderr = append(stderr, environment+": INVALID (some items not evaluated)")
	default:
		stderr = append(stderr, environment+": INCOMPLETE: not every item could be evaluated with this identity's access")
	}
	missingList, err := iterate(missing, "missing")
	if err != nil {
		return ValidationOutcome{}, err
	}
	for _, name := range missingList {
		stderr = append(stderr, "  missing: "+jsjson.String(name))
	}
	invalidList, err := iterate(invalid, "invalid")
	if err != nil {
		return ValidationOutcome{}, err
	}
	for _, item := range invalidList {
		name, err := prop(item, "name")
		if err != nil {
			return ValidationOutcome{}, err
		}
		reason, _ := prop(item, "reason")
		stderr = append(stderr, "  invalid: "+name+" — "+reason)
	}
	for _, item := range unresolvedList {
		name, err := prop(item, "name")
		if err != nil {
			return ValidationOutcome{}, err
		}
		if reason, _ := jsval.Get(item, "reason"); reason == "authority" {
			stderr = append(stderr, "  unresolved: "+name+" (references non-sensitive values; needs config.value.read)")
		} else {
			stderr = append(stderr, "  unresolved: "+name+" (a reference stays literal when delivered)")
		}
	}
	notEvaluatedList, err := iterate(notEvaluated, "notEvaluated")
	if err != nil {
		return ValidationOutcome{}, err
	}
	for _, item := range notEvaluatedList {
		name, err := prop(item, "name")
		if err != nil {
			return ValidationOutcome{}, err
		}
		requires, _ := prop(item, "requires")
		if s, ok := jsval.Get(item, "requires"); ok {
			if hint, known := requiresHint[jsjson.String(s)]; known {
				if _, isString := s.(string); isString {
					requires = hint
				}
			}
		}
		why := requires
		if reason, _ := jsval.Get(item, "reason"); reason == "requirement" {
			why = requires + "; a Requirement (e.g. Tailnet Constraint) is not met"
		}
		stderr = append(stderr, "  not evaluated: "+name+" ("+why+")")
	}
	code := validateIncomplete
	if failed {
		code = validateInvalid
	}
	return ValidationOutcome{Stderr: stderr, ExitCode: code}, nil
}

// ValidationDocument is validation.ts's validationDocument: the report's
// names and reasons, never a value, with the result and the exit status
// the human form would give.
func ValidationDocument(environment any, report any, exitCode int) (jsjson.Object, error) {
	report, err := ProjectReport(report)
	if err != nil {
		return nil, err
	}
	result := "incomplete"
	switch exitCode {
	case validateValid:
		result = "valid"
	case validateInvalid:
		result = "invalid"
	}
	notEvaluated, err := listOr(report, "notEvaluated")
	if err != nil {
		return nil, err
	}
	missing, _ := listOr(report, "missing")
	invalid, _ := listOr(report, "invalid")
	unresolved, _ := listOr(report, "unresolved")
	return jsjson.Object{
		{Key: "environment", Value: environment},
		{Key: "result", Value: result},
		{Key: "complete", Value: completeOf(report, notEvaluated)},
		{Key: "missing", Value: missing},
		{Key: "invalid", Value: invalid},
		{Key: "unresolved", Value: unresolved},
		{Key: "notEvaluated", Value: notEvaluated},
		{Key: "exitCode", Value: float64(exitCode)},
	}, nil
}

func validateCommand(r *Run) error {
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	ctx, err := r.resolveFromArgs(cwd)
	if err != nil {
		return contextError(err)
	}
	c, err := r.client(ctx).get()
	if err != nil {
		return err
	}
	report, err := c.ValidateEnvironment(context.Background(), ctx.Organization, ctx.Project, environmentOf(ctx))
	if err != nil {
		return err
	}
	outcome, err := ValidationOutcomeOf(environmentOf(ctx), report)
	if err != nil {
		return err
	}
	if hasArg(r.Args, "--json") {
		// The same exit status as the human form: 0 valid, 1 invalid, 2 incomplete.
		doc, err := ValidationDocument(ctx.Environment, report, outcome.ExitCode)
		if err != nil {
			return err
		}
		if err := r.printJSON(append(jsjson.Object{{Key: "version", Value: statusSchemaVersion}}, doc...)); err != nil {
			return err
		}
		if outcome.ExitCode != 0 {
			return ExitWith(outcome.ExitCode)
		}
		return nil
	}
	// Item names and reasons from the server, one line each: escaped (issue #119).
	for _, line := range outcome.Stdout {
		if err := r.println(Printable(line)); err != nil {
			return err
		}
	}
	for _, line := range outcome.Stderr {
		r.eprintln(Printable(line))
	}
	if outcome.ExitCode != 0 {
		return ExitWith(outcome.ExitCode)
	}
	return nil
}
