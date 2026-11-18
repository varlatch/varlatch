// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"

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

// ValidationOutcomeOf is validation.ts's validationOutcome for a report
// the server sent.
func ValidationOutcomeOf(environment string, report any) (ValidationOutcome, error) {
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
