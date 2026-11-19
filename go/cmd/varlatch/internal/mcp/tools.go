// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The tools of packages/mcp-server/src/server.ts (ADR-0043 Decision 9):
// eight reads, and with --allow-writes varlatch_set_value, which refuses a
// Secret's value, and varlatch_delete_value. No tool returns a Secret's
// value: none asks for one (effective configuration's values are the
// server's non-secret ones), and every answer goes through the CLI's
// fail-safe on its way out.

// Client is the API client the tools call (apiclient's, the SDK's
// VarlatchClient).
type Client interface {
	Server() string
	Meta(ctx context.Context) (any, error)
	WhoAmI(ctx context.Context) (any, error)
	ListOrganizations(ctx context.Context) (any, error)
	ListProjects(ctx context.Context, org string) (any, error)
	ListEnvironments(ctx context.Context, org, project string) (any, error)
	EffectiveConfiguration(ctx context.Context, org, project, environment string, includeValues bool) (any, error)
	ValidateEnvironment(ctx context.Context, org, project, environment string) (any, error)
	GetActiveContract(ctx context.Context, org, project string) (any, error)
	ListAuditEvents(ctx context.Context, org string, limit float64, cursor string) (any, error)
	SetValueWith(ctx context.Context, org, project, environment, item string, body jsjson.Object) (any, error)
	DeleteValue(ctx context.Context, org, project, environment, item string) (any, error)
}

// Defaults are the organization, project and environment a tool uses when
// its arguments name none, from the repository's context and the flags, as
// TypeScript's McpDefaults holds them: the keys assigned a value, in order
// (organization, project, environment), each value as it came (a
// .varlatch/local.json selection can be any JSON).
type Defaults = jsjson.Object

// tool is one registered tool.
type tool struct {
	name, title, description string
	shape                    []argument
	run                      func(s *Server, ctx context.Context, args jsjson.Object) jsjson.Object
}

var (
	orgArg  = argument{name: "organization", kind: "string", description: "Organization slug (defaults to the resolved repo context)"}
	projArg = argument{name: "project", kind: "string", description: "Project slug (defaults to the resolved repo context)"}
	envArg  = argument{name: "environment", kind: "string", description: "Environment name (defaults to the resolved repo context)"}
)

func toolsFor(allowWrites bool) []tool {
	list := []tool{
		{name: "varlatch_whoami", title: "Caller, server, and context info",
			description: "Show who this MCP server acts as (the identity, its organization, and the credential, a person's or a machine's), the varlatch server, the resolved default organization/project/environment, and whether this MCP server was started with writes enabled. No tool ever returns a Secret's value.",
			run:         (*Server).whoami},
		{name: "varlatch_list_organizations", title: "List organizations", description: "List organizations the current credential can see.",
			run: func(s *Server, ctx context.Context, _ jsjson.Object) jsjson.Object {
				return run(func() (any, error) { return s.client(ctx).ListOrganizations(ctx) })
			}},
		{name: "varlatch_list_projects", title: "List projects", description: "List projects in an organization.", shape: []argument{orgArg},
			run: func(s *Server, ctx context.Context, args jsjson.Object) jsjson.Object {
				return run(func() (any, error) {
					org, err := s.required("organization", args)
					if err != nil {
						return nil, err
					}
					return s.client(ctx).ListProjects(ctx, org)
				})
			}},
		{name: "varlatch_list_environments", title: "List environments", description: "List environments in a project.", shape: []argument{orgArg, projArg},
			run: func(s *Server, ctx context.Context, args jsjson.Object) jsjson.Object {
				return run(func() (any, error) {
					names, err := s.requiredAll(args, "organization", "project")
					if err != nil {
						return nil, err
					}
					return s.client(ctx).ListEnvironments(ctx, names[0], names[1])
				})
			}},
		{name: "varlatch_effective_configuration", title: "Effective configuration",
			description: "Get the effective configuration of an environment (contract items, provenance, versions). With includeValues, non-secret values are included; secrets are never returned by this tool.",
			shape:       []argument{orgArg, projArg, envArg, {name: "includeValues", kind: "boolean", description: "Include non-secret plaintext values"}},
			run: func(s *Server, ctx context.Context, args jsjson.Object) jsjson.Object {
				return run(func() (any, error) {
					names, err := s.requiredAll(args, "organization", "project", "environment")
					if err != nil {
						return nil, err
					}
					include, _ := args.Value("includeValues").(bool)
					return s.client(ctx).EffectiveConfiguration(ctx, names[0], names[1], names[2], include)
				})
			}},
		{name: "varlatch_validate_environment", title: "Validate environment",
			description: "Validate an environment against its active contract and return the validation report. " +
				"Items this credential may not read (Secrets need secret.reveal) are listed in notEvaluated; " +
				"valid is true only when every item was evaluated.",
			shape: []argument{orgArg, projArg, envArg},
			run: func(s *Server, ctx context.Context, args jsjson.Object) jsjson.Object {
				return run(func() (any, error) {
					names, err := s.requiredAll(args, "organization", "project", "environment")
					if err != nil {
						return nil, err
					}
					return s.client(ctx).ValidateEnvironment(ctx, names[0], names[1], names[2])
				})
			}},
		{name: "varlatch_get_active_contract", title: "Get active contract", description: "Get the active configuration-contract revision for a project.",
			shape: []argument{orgArg, projArg},
			run: func(s *Server, ctx context.Context, args jsjson.Object) jsjson.Object {
				return run(func() (any, error) {
					names, err := s.requiredAll(args, "organization", "project")
					if err != nil {
						return nil, err
					}
					return s.client(ctx).GetActiveContract(ctx, names[0], names[1])
				})
			}},
		{name: "varlatch_list_audit_events", title: "List audit events", description: "List recent audit events for an organization (paged).",
			shape: []argument{orgArg, {name: "limit", kind: "limit"}, {name: "cursor", kind: "string"}},
			run: func(s *Server, ctx context.Context, args jsjson.Object) jsjson.Object {
				return run(func() (any, error) {
					org, err := s.required("organization", args)
					if err != nil {
						return nil, err
					}
					limit, _ := args.Value("limit").(float64)
					cursor, _ := args.Value("cursor").(string)
					return s.client(ctx).ListAuditEvents(ctx, org, limit, cursor)
				})
			}},
	}
	if allowWrites {
		list = append(list,
			tool{name: "varlatch_set_value", title: "Set value",
				description: "Set a non-secret configuration value in an environment. A Secret's value is refused (Secrets, and items " +
					"outside the Contract, never pass through MCP), with or without replace. Replacing a value the environment " +
					"already has, or inherits from its parent, is the human's decision: ask them first, and with their approval " +
					"pass the item's name again as replace. Pass expectedVersionId for optimistic concurrency; it does not stand " +
					"in for replace.",
				shape: []argument{orgArg, projArg, envArg,
					{name: "item", kind: "string", required: true, description: "Item name from the contract, e.g. DATABASE_URL"},
					{name: "value", kind: "string", required: true},
					{name: "expectedVersionId", kind: "string"},
					{name: "replace", kind: "string", description: "Required to replace an existing value: the item's name again, given only after the human approved replacing it"},
				},
				run: (*Server).setValue},
			tool{name: "varlatch_delete_value", title: "Delete value",
				description: "Delete a configuration value from an environment. Deleting is the human's decision, for that item in that " +
					"environment: ask them first, and with their approval pass the item's name again as confirm. Without it, " +
					"nothing is deleted.",
				shape: []argument{orgArg, projArg, envArg,
					{name: "item", kind: "string", required: true},
					{name: "confirm", kind: "string", description: "Required: the item's name again, given only after the human approved deleting it in this environment"},
				},
				run: (*Server).deleteValue},
		)
	}
	return list
}

// definition is the tool as tools/list shows it: its input schema as the
// SDK converts the zod shape (draft-07; a described optional property
// leads with its description, a described required one with its type).
func (t tool) definition() jsjson.Object {
	properties := jsjson.Object{}
	var required []any
	for _, a := range t.shape {
		var p jsjson.Object
		typ := a.kind
		switch a.kind {
		case "limit":
			p = jsjson.Object{{Key: "type", Value: "integer"}, {Key: "minimum", Value: 1.0}, {Key: "maximum", Value: 200.0}}
		default:
			switch {
			case a.description == "":
				p = jsjson.Object{{Key: "type", Value: typ}}
			case a.required:
				p = jsjson.Object{{Key: "type", Value: typ}, {Key: "description", Value: a.description}}
			default:
				p = jsjson.Object{{Key: "description", Value: a.description}, {Key: "type", Value: typ}}
			}
		}
		properties = append(properties, jsjson.Member{Key: a.name, Value: p})
		if a.required {
			required = append(required, a.name)
		}
	}
	schema := jsjson.Object{
		{Key: "$schema", Value: "http://json-schema.org/draft-07/schema#"},
		{Key: "type", Value: "object"},
		{Key: "properties", Value: properties},
	}
	if required != nil {
		schema = append(schema, jsjson.Member{Key: "required", Value: required})
	}
	return jsjson.Object{
		{Key: "name", Value: t.name},
		{Key: "title", Value: t.title},
		{Key: "description", Value: t.description},
		{Key: "inputSchema", Value: schema},
		{Key: "execution", Value: jsjson.Object{{Key: "taskSupport", Value: "forbidden"}}},
	}
}

// objectPrototype are the properties every JavaScript object has: the SDK
// looks a tool up in a plain object, finds one of these for its name, and
// answers that the tool is disabled.
var objectPrototype = map[string]bool{
	"constructor": true, "__defineGetter__": true, "__defineSetter__": true, "hasOwnProperty": true,
	"__lookupGetter__": true, "__lookupSetter__": true, "isPrototypeOf": true, "propertyIsEnumerable": true,
	"toString": true, "valueOf": true, "__proto__": true, "toLocaleString": true,
}

// emptyResultError is the SDK's answer when a tool's text is undefined
// (JSON.stringify of an answer with no body): CallToolResultSchema refuses
// the result, and the request gets the error, not a result.
const emptyResultError = "MCP error -32602: Invalid tools/call result: " + emptyResultIssues

// callTool is McpServer's tools/call handler, with the Server's checks of
// the request around it.
func (s *Server) callTool(ctx context.Context, params any) (any, error) {
	if issues := callToolIssues(params); len(issues) > 0 {
		return nil, &zodError{issues}
	}
	p := params.(jsjson.Object)
	name := p.Value("name").(string)
	var found *tool
	for i := range s.tools {
		if s.tools[i].name == name {
			found = &s.tools[i]
		}
	}
	if found == nil {
		if objectPrototype[name] {
			return toolError(mcpError(codeInvalidParams, "Tool "+name+" disabled").Error()), nil
		}
		return toolError(mcpError(codeInvalidParams, "Tool "+name+" not found").Error()), nil
	}
	args, _ := p.Value("arguments").(jsjson.Object) // `args ?? {}`
	if issues := argumentIssues(args, found.shape); len(issues) > 0 {
		return toolError(mcpError(codeInvalidParams, "Input validation error: Invalid arguments for tool "+name+": "+parseErrorMessage(issues)).Error()), nil
	}
	r := found.run(s, ctx, args)
	if r == nil {
		return nil, &rpcErr{code: codeInvalidParams, message: emptyResultError}
	}
	return r, nil
}

// ok is a tool's answer: the payload as JSON, indented by two; nil when the
// payload is undefined (an answer with no body), which the SDK refuses.
func ok(payload any) jsjson.Object {
	if payload == apiclient.Undefined {
		return nil
	}
	return jsjson.Object{{Key: "content", Value: []any{text(string(jsjson.StringifyIndent(payload, 2)))}}}
}

func text(t string) jsjson.Object {
	return jsjson.Object{{Key: "type", Value: "text"}, {Key: "text", Value: t}}
}

func toolError(message string) jsjson.Object {
	return jsjson.Object{{Key: "content", Value: []any{text(message)}}, {Key: "isError", Value: true}}
}

// errorResult is a failure as a tool's error: an API error with its status,
// code and request, anything else by its message.
func errorResult(err error) jsjson.Object {
	if api, ok := errors.AsType[*apiclient.APIError](err); ok {
		return toolError(apiErrorText(api))
	}
	return toolError(err.Error())
}

func apiErrorText(e *apiclient.APIError) string {
	return "varlatch API error " + strconv.Itoa(e.Status) + " (" + jsString(e.Code) + ", request " + jsString(e.RequestID) + "): " + e.Message
}

// jsString is String(v) for a value an answer held, undefined included.
func jsString(v any) string {
	if v == apiclient.Undefined {
		return "undefined"
	}
	return jsjson.String(v)
}

func run(fn func() (any, error)) jsjson.Object {
	v, err := fn()
	if err != nil {
		return errorResult(err)
	}
	return ok(v)
}

// client is the API client for a call: first telling the server's loop
// that the handler now waits on the server.
func (s *Server) client(ctx context.Context) Client {
	calling(ctx)
	return s.opts.Client
}

// required is a tool's organization, project or environment: its argument,
// else the default; none (or an empty one) is an error.
func (s *Server) required(name string, args jsjson.Object) (string, error) {
	// `override ?? defaults[name]`, then `if (!value)`.
	value, present := s.opts.Defaults.Get(name)
	if v, given := args.Value(name).(string); given {
		value, present = v, true
	}
	if !present || !jsjson.Truthy(value) {
		flag := name
		if name == "organization" {
			flag = "org"
		}
		return "", errors.New(`No ` + name + ` given and none resolved from context; pass the "` + name +
			`" argument or run varlatch mcp inside a varlatch repo / with --` + flag + `.`)
	}
	return jsjson.String(value), nil
}

func (s *Server) requiredAll(args jsjson.Object, names ...string) ([]string, error) {
	out := make([]string, len(names))
	for i, n := range names {
		v, err := s.required(n, args)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

// defaultsValue is the defaults as whoami shows them: an object, empty for
// none.
func defaultsValue(d Defaults) jsjson.Object {
	if d == nil {
		return jsjson.Object{}
	}
	return d
}

// ---- whoami ---------------------------------------------------------------------

func (s *Server) whoami(ctx context.Context, _ jsjson.Object) jsjson.Object {
	return run(func() (any, error) {
		meta, err := s.client(ctx).Meta(ctx)
		if err != nil {
			return nil, err
		}
		capabilities, err := property(meta, "capabilities")
		if err != nil {
			return nil, err
		}
		serverVersion, _ := property(meta, "serverVersion")
		caller, err := s.caller(ctx, capabilities, serverVersion)
		if err != nil {
			return nil, err
		}
		out := jsjson.Object{{Key: "server", Value: s.opts.Client.Server()}}
		out = append(out, caller...)
		return append(out,
			jsjson.Member{Key: "meta", Value: meta},
			jsjson.Member{Key: "defaults", Value: defaultsValue(s.opts.Defaults)},
			jsjson.Member{Key: "allowWrites", Value: s.opts.AllowWrites},
			jsjson.Member{Key: "secretValues", Value: "never returned or written through MCP"},
		), nil
	})
}

// caller is the caller from GET /v1/me, or why there is none.
func (s *Server) caller(ctx context.Context, capabilities, serverVersion any) (jsjson.Object, error) {
	has, err := includes("capabilities", capabilities, "identity.whoami")
	if err != nil {
		return nil, err
	}
	if !has {
		return jsjson.Object{{Key: "caller", Value: nil}, {Key: "callerUnavailable",
			Value: "this server (" + jsString(serverVersion) + ") cannot say who a credential belongs to (no identity.whoami capability)"}}, nil
	}
	me, err := s.client(ctx).WhoAmI(ctx)
	if err != nil {
		api, isAPI := errors.AsType[*apiclient.APIError](err)
		if !isAPI {
			return nil, err
		}
		return jsjson.Object{{Key: "caller", Value: nil}, {Key: "callerUnavailable", Value: apiErrorText(api)}}, nil
	}
	return jsjson.Object{{Key: "caller", Value: me}}, nil
}

// ---- JavaScript's reads of an answer --------------------------------------------

// typeError is the TypeError JavaScript throws reading an answer of a
// shape the code does not expect; its message is V8's.
type typeError struct{ message string }

func (e *typeError) Error() string { return e.message }

func nullishName(v any) (string, bool) {
	switch v {
	case nil:
		return "null", true
	case apiclient.Undefined, absent:
		return "undefined", true
	}
	return "", false
}

// property is v.key: undefined for a primitive or an array (none of the
// keys read here is one of theirs), a TypeError for null or undefined.
func property(v any, key string) (any, error) {
	if name, nullish := nullishName(v); nullish {
		return nil, &typeError{"Cannot read properties of " + name + " (reading '" + key + "')"}
	}
	if o, ok := v.(jsjson.Object); ok {
		if x, present := o.Get(key); present {
			return x, nil
		}
	}
	return apiclient.Undefined, nil
}

// optional is v?.key.
func optional(v any, key string) any {
	if _, nullish := nullishName(v); nullish {
		return apiclient.Undefined
	}
	x, _ := property(v, key)
	return x
}

// includes is expr.includes(want): an array's element or a string's part.
func includes(expr string, v any, want string) (bool, error) {
	if name, nullish := nullishName(v); nullish {
		return false, &typeError{"Cannot read properties of " + name + " (reading 'includes')"}
	}
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if e == want {
				return true, nil
			}
		}
		return false, nil
	case string:
		return strings.Contains(x, want), nil
	}
	return false, &typeError{expr + ".includes is not a function"}
}

// findByName is list.find((i) => i.name === item), list being expr's
// value: undefined when none matches.
func findByName(expr string, list any, item string) (any, error) {
	a, isArray := list.([]any)
	if !isArray {
		return nil, &typeError{expr + ".find is not a function"}
	}
	for _, e := range a {
		name, err := property(e, "name")
		if err != nil {
			return nil, err
		}
		if name == item {
			return e, nil
		}
	}
	return apiclient.Undefined, nil
}

// ---- Writes -----------------------------------------------------------------------

// isSecretItem is whether item is a Secret by the active Contract: items
// outside it, and every item of a project without one (or whose Contract
// this credential may not read), are.
func (s *Server) isSecretItem(ctx context.Context, org, project, item string) (bool, error) {
	revision, err := s.client(ctx).GetActiveContract(ctx, org, project)
	if err != nil {
		if api, ok := errors.AsType[*apiclient.APIError](err); ok && (api.Status == 404 || api.Status == 403) {
			return true, nil
		}
		return false, err
	}
	contract, err := property(revision, "contract")
	if err != nil {
		return false, err
	}
	items := optional(contract, "items")
	if _, nullish := nullishName(items); nullish {
		return true, nil
	}
	found, err := findByName("contract?.items?", items, item)
	if err != nil {
		return false, err
	}
	sensitive := optional(found, "sensitive")
	if _, nullish := nullishName(sensitive); nullish {
		return true, nil
	}
	return jsjson.Truthy(sensitive), nil
}

// presence is whether the environment already has a value for item:
// "present", "inherited", "absent", or unknown with why.
type presence struct {
	state   string
	unknown string
}

func (s *Server) valuePresence(ctx context.Context, org, project, environment, item string) (presence, error) {
	effective, err := s.client(ctx).EffectiveConfiguration(ctx, org, project, environment, false)
	if err != nil {
		if api, ok := errors.AsType[*apiclient.APIError](err); ok {
			return presence{unknown: strconv.Itoa(api.Status) + " " + jsString(api.Code)}, nil
		}
		return presence{}, err
	}
	items, err := property(effective, "items")
	if err != nil {
		return presence{}, err
	}
	if _, nullish := nullishName(items); nullish {
		items = []any{}
	}
	found, err := findByName("(effective.items ?? [])", items, item)
	if err != nil {
		return presence{}, err
	}
	if found == apiclient.Undefined {
		return presence{state: "absent"}, nil
	}
	if source, _ := property(found, "source"); source == "parent" {
		return presence{state: "inherited"}, nil
	}
	return presence{state: "present"}, nil
}

func secretWriteRefusal(item string) string {
	return item + " is a Secret, and its value is never written through MCP: the value would be in the model's context. " +
		"Store it with `varlatch --assisted values set " + item + " --generate hex:32` (a new random value), " +
		"`--from-file <path>`, `--stdin`, or `varlatch --assisted import <file>`; or ask the human to run " +
		"`varlatch values set " + item + "` in their own terminal. Nothing was stored."
}

func replaceRefusal(item, environment string, p presence) string {
	var why string
	switch p.state {
	case "present":
		why = item + " already has a value in " + environment + "; setting it replaces that value"
	case "inherited":
		why = environment + " inherits a value for " + item + " from its parent environment; setting it here overrides that value in " + environment
	default:
		why = "whether " + item + " already has a value in " + environment + " cannot be checked (" + p.unknown + "), so it counts as existing"
	}
	return why + ". Replacing it is the human's decision, for this item only: ask them, and with their approval pass replace: \"" + item + "\". Nothing was stored."
}

func deleteConfirmationRefusal(item, environment string, confirm any) string {
	if confirm == item {
		return ""
	}
	var why string
	if confirm == absent {
		why = "deleting " + item + " from " + environment + " is the human's decision, for this item in this environment"
	} else {
		why = "confirm names " + confirm.(string) + ", but this call deletes " + item + "; approval for one item never covers another"
	}
	return why + ". Ask the human, and with their approval for " + item + " in " + environment + ", pass confirm: \"" + item + "\". Nothing was deleted."
}

func (s *Server) setValue(ctx context.Context, args jsjson.Object) jsjson.Object {
	names, err := s.requiredAll(args, "organization", "project", "environment")
	if err != nil {
		return errorResult(err)
	}
	org, project, environment := names[0], names[1], names[2]
	item := args.Value("item").(string)
	replace := field(args, "replace")
	// replace names the one item this call replaces, checked before any request.
	if replace != absent && replace != item {
		return toolError("replace names " + replace.(string) + ", but this call sets " + item + "; approval for one item never covers another. Nothing was stored.")
	}
	// Checked before anything is written; an unreadable Contract counts as a Secret.
	secret, err := s.isSecretItem(ctx, org, project, item)
	if err != nil {
		return errorResult(err)
	}
	if secret {
		return toolError(secretWriteRefusal(item))
	}
	if replace != item {
		p, err := s.valuePresence(ctx, org, project, environment, item)
		if err != nil {
			return errorResult(err)
		}
		if p.state != "absent" {
			return toolError(replaceRefusal(item, environment, p))
		}
	}
	body := jsjson.Object{{Key: "value", Value: args.Value("value")}}
	if v := field(args, "expectedVersionId"); v != absent {
		body = append(body, jsjson.Member{Key: "expectedVersionId", Value: v})
	}
	answer, err := s.client(ctx).SetValueWith(ctx, org, project, environment, item, body)
	if err != nil {
		return errorResult(err)
	}
	return ok(answer)
}

func (s *Server) deleteValue(ctx context.Context, args jsjson.Object) jsjson.Object {
	names, err := s.requiredAll(args, "organization", "project", "environment")
	if err != nil {
		return errorResult(err)
	}
	org, project, environment := names[0], names[1], names[2]
	item := args.Value("item").(string)
	// Checked before any request: --allow-writes enables the tool, it does not record the intent to delete.
	if refusal := deleteConfirmationRefusal(item, environment, field(args, "confirm")); refusal != "" {
		return toolError(refusal)
	}
	if _, err := s.client(ctx).DeleteValue(ctx, org, project, environment, item); err != nil {
		return errorResult(err)
	}
	return ok(jsjson.Object{{Key: "deleted", Value: item}, {Key: "environment", Value: environment}})
}
