// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/matcher"
	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch run --strict` (slice 5.4f), apps/cli/src/strictRun.ts: one
// strict retrieval gives the values, the manifest and the Contract
// Revision; the exact environment the command would receive is resolved
// and validated against that revision, and the command starts only if
// nothing is wrong. Every violation is reported at once, names, classes and
// reasons, never a value, and the run ends with 78 before the command
// starts.
//
// For each Contract item the source is decided in this order, first match
// wins:
//
//	server status             parent environment   outcome
//	delivered, expanded       any                  the delivered value
//	delivered, unexpanded ref any                  violation: unresolved reference
//	withheld                  set, allowed         the inherited value
//	withheld                  set, not allowed     violation: withheld
//	withheld                  unset                violation if required, else absent
//	not stored                set, allowed         the inherited value
//	not stored                set, not allowed     violation: inherited
//	not stored                unset, default       the Contract default
//	not stored                unset, no default    violation if required, else absent
//
// An item named with --omit comes before every row: absent whatever the
// server or the parent holds, and a violation where it is required. A
// default never stands in for a withheld value, and every value the
// command will receive is validated as it will be received. Items outside
// the Contract are delivered as a default run delivers them.
//
// The agent-safe form (--strict --agent-safe) is slice 5.5b.

// violation is a Violation: name is the Contract item, or "(contract)" /
// "(run context)"; reason never holds a value.
type violation struct{ name, kind, reason string }

// strictPlan is StrictPlan.
type strictPlan struct {
	env             *orderedEnv
	mediated        []string
	violations      []violation
	outsideContract int
}

// agentFact is one item's Broker issuance preflight fact.
type agentFact struct {
	present    bool
	authorized bool
	reason     string
}

// agentSafeFacts is AgentSafeFacts: non-nil for an agent-safe strict run;
// agent is nil during preliminary planning before Capability issuance.
type agentSafeFacts struct {
	agent map[string]agentFact
}

// contractItemOf is one item of a Contract a server sent, read as
// strictRun.ts reads it: the server's form, never normalized again.
func contractItemOf(v any) contract.Item {
	var it contract.Item
	it.Name, _ = stringField(v, "name")
	it.Sensitive = jsjson.Truthy(fieldOf(v, "sensitive"))
	it.Type, _ = stringField(v, "type")
	required := fieldOf(v, "required")
	it.Required.Kind, _ = stringField(required, "kind")
	if selector, ok := fieldOf(required, "selector").(jsjson.Object); ok {
		s := &contract.Selector{}
		s.Kind, _ = stringField(selector, "kind")
		s.Tier, _ = stringField(selector, "tier")
		for _, id := range listOf(selector, "environmentIds") {
			if id, ok := id.(string); ok {
				s.EnvironmentIDs = append(s.EnvironmentIDs, id)
			}
		}
		it.Required.Selector = s
	}
	for _, e := range listOf(v, "enumValues") {
		if e, ok := e.(string); ok {
			it.EnumValues = append(it.EnumValues, e)
		}
	}
	if d, ok := fieldOf(v, "defaultValue").(string); ok {
		it.DefaultValue = &d
	}
	return it
}

// templateText is a value as a JavaScript template literal shows it:
// String(v), "undefined" when the member is absent.
func templateText(v any, key string) string {
	if f, ok := jsval.Get(v, key); ok {
		return jsjson.String(f)
	}
	return "undefined"
}

// checkAllowances is checkAllowances: --allow-inherited names must be
// Contract items; a typo is an error, never ignored. In an agent-safe run
// it may not name a Secret, which would put plaintext into the Agent's
// environment.
func checkAllowances(contractDoc any, allowInherited []string, agentSafe bool) error {
	byName := map[string]bool{}
	sensitive := map[string]bool{}
	for _, item := range listOf(contractDoc, "items") {
		if name, ok := stringField(item, "name"); ok {
			byName[name] = true
			if jsjson.Truthy(fieldOf(item, "sensitive")) {
				sensitive[name] = true
			}
		}
	}
	var unknown []string
	for _, n := range allowInherited {
		if !byName[n] && !slices.Contains(unknown, n) {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		slices.SortFunc(unknown, jsval.CompareUTF16)
		return UsageError("varlatch: --allow-inherited names must be Contract items; not in the Contract: " + Printable(strings.Join(unknown, ", ")) + ". Nothing was started.")
	}
	if agentSafe {
		var secrets []string
		for _, n := range allowInherited {
			if sensitive[n] && !slices.Contains(secrets, n) {
				secrets = append(secrets, n)
			}
		}
		if len(secrets) > 0 {
			slices.SortFunc(secrets, jsval.CompareUTF16)
			return UsageError("varlatch: --allow-inherited cannot name a Secret in an agent-safe run, which would put plaintext into the Agent's environment: " + Printable(strings.Join(secrets, ", ")) + ". Nothing was started.")
		}
	}
	return nil
}

// withheldReason is withheldReason.
func withheldReason(withheld any) string {
	if jsjson.String(fieldOf(withheld, "reason")) == "requirement" {
		return "withheld by the server: a Requirement (such as a Tailnet Constraint) for " + templateText(withheld, "requires") + " is not met"
	}
	return "withheld by the server: this identity needs " + templateText(withheld, "requires")
}

// joinedReferences is references.join(", ").
func joinedReferences(references any) string {
	list, ok := references.([]any)
	if !ok {
		return jsjson.String(references)
	}
	parts := make([]string, len(list))
	for i, r := range list {
		if r != nil {
			parts[i] = jsjson.String(r)
		}
	}
	return strings.Join(parts, ", ")
}

// planStrictRun is planStrictRun: env starts as the parent's environment
// (parent, read as process.env reads it), without an inherited run context
// or an omitted item. agentSafe is non-nil for `--agent-safe --strict`.
func planStrictRun(retrieval any, env *orderedEnv, parent parentVars, allowInherited, omitted map[string]bool, agentSafe *agentSafeFacts) strictPlan {
	plan := strictPlan{env: env}
	env.Delete(runContextName)
	for name := range omitted {
		env.Delete(name)
	}
	add := func(name, kind, reason string) {
		plan.violations = append(plan.violations, violation{name, kind, reason})
	}
	manifest := fieldOf(retrieval, "manifest")
	revision := fieldOf(manifest, "contract")
	if !jsjson.Truthy(revision) {
		add("(contract)", "contract", "no active Contract: strict startup needs one")
		return plan
	}
	contractDoc := fieldOf(retrieval, "contract")
	if !jsjson.Truthy(contractDoc) {
		add("(contract)", "contract", "the active Contract is not readable by this identity: it needs contract.read")
		return plan
	}
	version, _ := fieldOf(revision, "semanticsVersion").(float64)
	semantics, err := contract.SemanticsFor(int(version))
	if version != math.Trunc(version) || err != nil {
		supported := make([]string, len(contract.SemanticsVersions))
		for i, v := range contract.SemanticsVersions {
			supported[i] = strconv.Itoa(v)
		}
		add("(contract)", "semantics", "Contract semantics version "+templateText(revision, "semanticsVersion")+" is not supported by this CLI (supported: "+strings.Join(supported, ", ")+"); upgrade the CLI")
		return plan
	}
	named := func(list []any, name string) bool {
		return slices.ContainsFunc(list, func(i any) bool { n, ok := stringField(i, "name"); return ok && n == name })
	}
	for _, reserved := range contract.ReservedItemNames {
		if named(listOf(manifest, "items"), reserved) || named(listOf(contractDoc, "items"), reserved) {
			add(reserved, "reserved", "this name is reserved for launcher metadata; rename the stored item")
		}
	}

	environment := fieldOf(manifest, "environment")
	envCtx := contract.Environment{}
	envCtx.RootID, _ = stringField(environment, "rootId")
	envCtx.Tier, _ = stringField(environment, "tier")
	items := map[string]any{}
	for _, item := range listOf(retrieval, "items") {
		if name, ok := stringField(item, "name"); ok {
			items[name] = item
		}
	}
	callerView := fieldOf(retrieval, "callerView")
	withheld := map[string]any{}
	for _, w := range listOf(callerView, "withheld") {
		if name, ok := stringField(w, "name"); ok {
			withheld[name] = w
		}
	}
	unexpanded := map[string]any{}
	for _, u := range listOf(callerView, "unexpanded") {
		if name, ok := stringField(u, "name"); ok {
			unexpanded[name] = fieldOf(u, "references")
		}
	}
	contracted := map[string]bool{}
	for _, item := range listOf(contractDoc, "items") {
		if name, ok := stringField(item, "name"); ok {
			contracted[name] = true
		}
	}

	// Items outside the Contract are delivered as a default run delivers them
	// (in an agent-safe run, a stored Secret as a Placeholder).
	for _, item := range listOf(retrieval, "items") {
		name, _ := stringField(item, "name")
		if contracted[name] || slices.Contains(contract.ReservedItemNames, name) || omitted[name] {
			continue
		}
		if agentSafe != nil && jsjson.Truthy(fieldOf(item, "sensitive")) {
			plan.mediated = append(plan.mediated, name)
			plan.outsideContract++
		} else if value, ok := fieldOf(item, "value").(string); ok {
			env.Set(name, value)
			plan.outsideContract++
		}
	}

	// Server verdicts for Secrets in an agent-safe strict run.
	validation := fieldOf(retrieval, "validation")
	invalidVerdicts := map[string]string{}
	for _, v := range listOf(validation, "invalid") {
		if name, ok := stringField(v, "name"); ok {
			invalidVerdicts[name] = jsjson.String(fieldOf(v, "reason"))
		}
	}
	unresolvedVerdicts := map[string]bool{}
	for _, v := range listOf(validation, "unresolved") {
		if name, ok := stringField(v, "name"); ok {
			unresolvedVerdicts[name] = true
		}
	}
	notEvaluatedVerdicts := map[string]string{}
	for _, v := range listOf(validation, "notEvaluated") {
		if name, ok := stringField(v, "name"); ok {
			notEvaluatedVerdicts[name] = jsjson.String(fieldOf(v, "reason"))
		}
	}

	contextItems := jsjson.Object{}
	validate := func(it contract.Item, value, source string) {
		if problem := semantics.Validate(it, value); problem != "" {
			add(it.Name, "invalid", source+" "+problem)
		}
	}
	planAgentSecret := func(it contract.Item, required bool) jsjson.Object {
		_, stored := items[it.Name]
		if stored && omitted[it.Name] {
			env.Delete(it.Name)
			if required {
				add(it.Name, "omitted", "required in this environment, and --omit leaves it out of the run")
			}
			return jsjson.Object{{Key: "server", Value: "delivered"}, {Key: "delivery", Value: "absent"}}
		}
		if !stored {
			if _, isSet := parent.lookup(it.Name); isSet {
				add(it.Name, "inherited", "a Secret set only in the parent environment would reach the Agent as plaintext; store it in Varlatch")
				return jsjson.Object{{Key: "server", Value: "notStored"}, {Key: "delivery", Value: "absent"}}
			}
			if it.DefaultValue != nil {
				env.Set(it.Name, *it.DefaultValue)
				validate(it, *it.DefaultValue, "the Contract default")
				return jsjson.Object{{Key: "server", Value: "notStored"}, {Key: "delivery", Value: "default"}}
			}
			if required {
				add(it.Name, "missing", "required in this environment and not stored")
			}
			return jsjson.Object{{Key: "server", Value: "notStored"}, {Key: "delivery", Value: "absent"}}
		}
		if reason, ok := notEvaluatedVerdicts[it.Name]; ok {
			if reason == "requirement" {
				add(it.Name, "not-evaluated", "validating Secrets needs secret.reveal, and a Requirement (such as a Tailnet Constraint) is not met")
			} else {
				add(it.Name, "not-evaluated", "validating Secrets in an agent-safe strict run needs secret.reveal for the operator")
			}
		} else if reason, ok := invalidVerdicts[it.Name]; ok && reason != "" {
			add(it.Name, "invalid", "the stored value "+reason)
		} else if unresolvedVerdicts[it.Name] {
			add(it.Name, "unresolved-reference", "a reference stays literal for the operator")
		}
		if agentSafe.agent != nil {
			if fact, ok := agentSafe.agent[it.Name]; ok {
				if !fact.present {
					add(it.Name, "missing", "no longer stored when the Capability was issued")
				} else if !fact.authorized {
					if fact.reason == "requirement" {
						add(it.Name, "agent-unauthorized", "the Agent's secret.use Requirement (such as a Tailnet Constraint) is not met at issuance")
					} else {
						add(it.Name, "agent-unauthorized", "the Agent lacks secret.use here")
					}
				}
			}
		}
		plan.mediated = append(plan.mediated, it.Name)
		return jsjson.Object{{Key: "server", Value: "delivered"}, {Key: "delivery", Value: "varlatch"}}
	}
	for _, raw := range listOf(contractDoc, "items") {
		it := contractItemOf(raw)
		if slices.Contains(contract.ReservedItemNames, it.Name) {
			continue
		}
		if agentSafe != nil && it.Sensitive {
			contextItems = contextItems.Set(it.Name, planAgentSecret(it, semantics.RequiredApplies(it, envCtx)))
			continue
		}
		got, stored := items[it.Name]
		denied, isDenied := withheld[it.Name]
		value, delivered := fieldOf(got, "value").(string)
		server := "delivered"
		switch {
		case !stored:
			server = "notStored"
		case isDenied || !delivered:
			server = "withheld"
		}
		inherited, isSet := parent.lookup(it.Name)
		required := semantics.RequiredApplies(it, envCtx)
		if !isDenied {
			requires := "config.value.read"
			if it.Sensitive {
				requires = "secret.reveal"
			}
			denied = jsjson.Object{{Key: "name", Value: it.Name}, {Key: "reason", Value: "permission"}, {Key: "requires", Value: requires}}
		}
		delivery := "absent"
		switch {
		case omitted[it.Name]:
			// Left out: the server's status is recorded as it was, and nothing replaces the value.
			if required {
				add(it.Name, "omitted", "required in this environment, and --omit leaves it out of the run")
			}
		case server == "delivered":
			if references, ok := unexpanded[it.Name]; ok && jsjson.Truthy(references) {
				add(it.Name, "unresolved-reference", "a reference stays literal when delivered to this identity: "+joinedReferences(references))
			} else {
				env.Set(it.Name, value)
				delivery = "varlatch"
				validate(it, value, "the delivered value")
			}
		case isSet:
			switch {
			case allowInherited[it.Name]:
				delivery = "inherited"
				validate(it, inherited, "the inherited value")
			case server == "withheld":
				add(it.Name, "withheld", withheldReason(denied)+"; the parent environment sets it, which --allow-inherited "+it.Name+" would accept")
			default:
				add(it.Name, "inherited", "not stored in Varlatch and set only in the parent environment; accept it with --allow-inherited "+it.Name)
			}
		case server == "withheld":
			// A default never replaces a withheld value: the real value exists.
			if required {
				add(it.Name, "withheld", withheldReason(denied))
			}
		case it.DefaultValue != nil:
			env.Set(it.Name, *it.DefaultValue)
			delivery = "default"
			validate(it, *it.DefaultValue, "the Contract default")
		case required:
			add(it.Name, "missing", "required in this environment and not stored")
		}
		contextItems = contextItems.Set(it.Name, jsjson.Object{{Key: "server", Value: server}, {Key: "delivery", Value: delivery}})
	}

	runContext := jsjson.Object{
		{Key: "v", Value: float64(1)},
		{Key: "mode", Value: "strict"},
		{Key: "contractRevisionId", Value: fieldOf(revision, "revisionId")},
		{Key: "contractHash", Value: fieldOf(revision, "contentHash")},
		{Key: "semanticsVersion", Value: fieldOf(revision, "semanticsVersion")},
		{Key: "environment", Value: jsjson.Object{{Key: "rootId", Value: fieldOf(environment, "rootId")}, {Key: "tier", Value: fieldOf(environment, "tier")}}},
		{Key: "items", Value: contextItems},
	}
	if encoded, ok := encodeRunContext(runContext); ok {
		env.Set(runContextName, encoded)
	} else {
		add("(run context)", "context", "the run context would exceed "+strconv.Itoa(runContextMaxBytes)+" bytes; it is never truncated")
	}
	return plan
}

// formatViolations is formatViolations: every violation at once, names,
// classes and reasons, never values; names and reasons from the server
// escaped.
func formatViolations(violations []violation) []string {
	lines := []string{"varlatch: strict startup found " + strconv.Itoa(len(violations)) + " violation(s); the command was not started:"}
	for _, v := range violations {
		lines = append(lines, Printable("  "+v.name+": "+v.kind+": "+v.reason))
	}
	return lines
}

// retryable is retryable: a server-side failure (an audit commit or a
// decryption) or a lost connection, where nothing was returned.
func retryable(err error) bool {
	var apiErr *apiclient.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status >= 500
	}
	var fetch *apiclient.FetchError
	var body *apiclient.BodyError
	return errors.As(err, &fetch) || errors.As(err, &body)
}

// retryOnce is retryOnce: the request again, once, after a retryable
// failure.
func retryOnce(request func() (any, error)) (any, error) {
	answer, err := request()
	if err != nil && retryable(err) {
		return request()
	}
	return answer, err
}

// secretNamesOf is secretNamesOf: every name the retrieval knows as a
// Secret, stored as one or sensitive in the Contract.
func secretNamesOf(retrieval any) []string {
	var names []string
	for _, list := range [][]any{listOf(retrieval, "items"), listOf(fieldOf(retrieval, "contract"), "items")} {
		for _, item := range list {
			if name, ok := stringField(item, "name"); ok && jsjson.Truthy(fieldOf(item, "sensitive")) && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	slices.SortFunc(names, jsval.CompareUTF16)
	return names
}

// strictRun is runStrict and main.ts's start for a run that is not
// agent-safe: nothing starts, and nothing reaches the command, until the
// whole environment is resolved and every violation is found.
func (r *Run) strictRun(ctx *clientctx.Context, c *apiclient.Client, pre []string, command string, commandArgs, omit, allowUnmasked []string, assistedRedaction, redact bool) error {
	meta, err := c.Meta(context.Background())
	if err != nil {
		return err
	}
	capabilities, present := getOptional(meta, "capabilities")
	strict, err := includes(capabilities, present, "retrieval.strict", "meta.capabilities.includes")
	if err != nil {
		return err
	}
	if !strict {
		version, ok := r.Secrets.SafeVersion(fieldOf(meta, "serverVersion"))
		if !ok {
			version = "an older release"
		}
		r.eprintln("varlatch: --strict needs strict retrieval, which this server (" + version + ") does not offer; it needs Varlatch 0.11.0 or later. Strict startup never falls back to a default run.")
		return ExitWith(strictExit)
	}
	environment := environmentOf(ctx)
	retrieval, err := retryOnce(func() (any, error) {
		return c.StrictRetrieval(context.Background(), ctx.Organization, ctx.Project, environment, "strict")
	})
	if err != nil {
		return err
	}
	contractDoc := fieldOf(retrieval, "contract")
	allowInherited := flagValues(pre, "--allow-inherited")
	if jsjson.Truthy(contractDoc) {
		if err := checkAllowances(contractDoc, allowInherited, false); err != nil {
			return err
		}
	}
	omitted := map[string]bool{}
	for _, n := range omit {
		omitted[n] = true
	}
	// Stored: every resolved item the manifest lists, withheld ones included.
	known := map[string]bool{}
	for _, list := range [][]any{listOf(fieldOf(retrieval, "manifest"), "items"), listOf(retrieval, "items"), listOf(fieldOf(retrieval, "callerView"), "withheld"), listOf(contractDoc, "items")} {
		for _, item := range list {
			if name, ok := stringField(item, "name"); ok {
				known[name] = true
			}
		}
	}
	var unknown []string
	for _, n := range omit {
		if !known[n] && !slices.Contains(unknown, n) {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		slices.SortFunc(unknown, jsval.CompareUTF16)
		return UsageError("varlatch: --omit must name an item stored in this environment or in its Contract; not found: " + Printable(strings.Join(unknown, ", ")) + ". Nothing was started.")
	}
	allowed := map[string]bool{}
	for _, n := range allowInherited {
		allowed[n] = true
	}
	parent := r.parentVars()
	plan := planStrictRun(retrieval, r.parentEnv(), parent, allowed, omitted, nil)
	if len(plan.violations) > 0 {
		for _, line := range formatViolations(plan.violations) {
			r.eprintln(line)
		}
		return ExitWith(strictExit)
	}
	if plan.outsideContract > 0 {
		r.eprintln("varlatch: " + strconv.Itoa(plan.outsideContract) + " delivered item(s) are not in the Contract; delivered as usual")
	}
	env := plan.env
	secrets := deliveredSecrets(retrieval, env)
	notice := omittedNotice(omit, assistedRedaction || redact, r.Assisted.On)
	var redaction *matcher.OutputRedaction
	if assistedRedaction {
		assisted := planAssistedRedaction(assistedRedactionSet(secrets, env, parent, secretNamesOf(retrieval)), allowUnmasked)
		where := r.contextOptions(pre, environment, ctx.Server)
		if !r.assistedGate(assisted, remedyContext{target: where, runOptions: runPolicyOptions(pre), assisted: r.Assisted.On}) {
			return ExitWith(strictExit)
		}
		redaction = matcher.NewOutputRedaction(assisted.entries, matcher.ModeAssisted)
	} else if redact {
		redaction = matcher.NewOutputRedaction(secrets, matcher.ModeRedact)
	}
	if notice != "" {
		r.eprintln(notice)
	}
	code, err := r.runChild(command, commandArgs, env.Lines(), redaction)
	if err != nil {
		return err
	}
	return ExitWith(code)
}
