// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"math"
	"strings"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The request schemas of @modelcontextprotocol/sdk 1.32.2 (types.js) that a
// method checks its request against, and the tools' input schemas, with the
// issues zod 4 reports, in its order and words: a failed request answers
// with zod's error message (the issues as JSON, indented by two), a failed
// tool input with each issue's message and place (getParseErrorMessage).
// Only the schemas `varlatch mcp` meets are here; the vectors
// (testdata/vectors/mcp.json) hold them to the TypeScript server.

// issue is one zod issue.
type issue struct {
	code     string // invalid_type, invalid_value, custom, too_big, too_small
	expected string // invalid_type
	values   []string
	path     []any // strings and indexes (float64)
	message  string
}

// absent stands for a property the input does not have (JavaScript's
// undefined).
type absentT struct{}

var absent any = absentT{}

// typeName is zod's name for what it received.
func typeName(v any) string {
	switch v.(type) {
	case absentT:
		return "undefined"
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case jsjson.Object:
		return "object"
	}
	return "object"
}

// checker collects issues for one parse.
type checker struct{ issues []issue }

func at(path []any, key any) []any {
	out := make([]any, len(path), len(path)+1)
	copy(out, path)
	return append(out, key)
}

func (c *checker) invalidType(path []any, expected string, v any) {
	c.issues = append(c.issues, issue{code: "invalid_type", expected: expected, path: path,
		message: "Invalid input: expected " + expected + ", received " + typeName(v)})
}

// field is an object's property, absent when it has none.
func field(o jsjson.Object, key string) any {
	if v, ok := o.Get(key); ok {
		return v
	}
	return absent
}

func (c *checker) str(path []any, v any, optional bool) {
	if v == absent && optional {
		return
	}
	if _, ok := v.(string); !ok {
		c.invalidType(path, "string", v)
	}
}

func (c *checker) boolean(path []any, v any, optional bool) {
	if v == absent && optional {
		return
	}
	if _, ok := v.(bool); !ok {
		c.invalidType(path, "boolean", v)
	}
}

func (c *checker) number(path []any, v any, optional bool) {
	if v == absent && optional {
		return
	}
	if _, ok := v.(float64); !ok {
		c.invalidType(path, "number", v)
	}
}

// object checks that v is a plain object (not an array or null); fields
// checks its properties when it is.
func (c *checker) object(path []any, v any, optional bool, fields func(jsjson.Object)) {
	if v == absent && optional {
		return
	}
	o, ok := v.(jsjson.Object)
	if !ok {
		c.invalidType(path, "object", v)
		return
	}
	if fields != nil {
		fields(o)
	}
}

// record is z.record(z.string(), value): an object whose every value
// passes value (nil: any value).
func (c *checker) record(path []any, v any, optional bool, value func([]any, any)) {
	if v == absent && optional {
		return
	}
	o, ok := v.(jsjson.Object)
	if !ok {
		c.invalidType(path, "record", v)
		return
	}
	if value != nil {
		for _, m := range o {
			value(at(path, m.Key), m.Value)
		}
	}
}

// assertObject is the SDK's AssertObjectSchema: any object, arrays
// included.
func (c *checker) assertObject(path []any, v any, optional bool) {
	if v == absent && optional {
		return
	}
	switch v.(type) {
	case jsjson.Object, []any:
		return
	}
	c.issues = append(c.issues, issue{code: "custom", path: path, message: "Invalid input"})
}

func (c *checker) array(path []any, v any, optional bool, element func([]any, any)) {
	if v == absent && optional {
		return
	}
	a, ok := v.([]any)
	if !ok {
		c.invalidType(path, "array", v)
		return
	}
	for i, e := range a {
		element(at(path, float64(i)), e)
	}
}

func (c *checker) enum(path []any, v any, optional bool, values ...string) {
	if v == absent && optional {
		return
	}
	if s, ok := v.(string); ok {
		for _, want := range values {
			if s == want {
				return
			}
		}
	}
	quoted := make([]string, len(values))
	for i, s := range values {
		quoted[i] = string(jsjson.Stringify(s))
	}
	c.issues = append(c.issues, issue{code: "invalid_value", values: values, path: path,
		message: "Invalid option: expected one of " + strings.Join(quoted, "|")})
}

// ---- The request schemas ----------------------------------------------------------

// initializeIssues is InitializeRequestSchema's issues for params.
func initializeIssues(params any) []issue {
	var c checker
	c.object([]any{"params"}, params, false, func(p jsjson.Object) {
		base := []any{"params"}
		c.str(at(base, "protocolVersion"), field(p, "protocolVersion"), false)
		c.clientCapabilities(at(base, "capabilities"), field(p, "capabilities"))
		c.implementation(at(base, "clientInfo"), field(p, "clientInfo"))
	})
	return c.issues
}

// clientCapabilities is ClientCapabilitiesSchema.
func (c *checker) clientCapabilities(path []any, v any) {
	c.object(path, v, false, func(o jsjson.Object) {
		c.record(at(path, "experimental"), field(o, "experimental"), true, func(p []any, v any) { c.assertObject(p, v, false) })
		c.object(at(path, "sampling"), field(o, "sampling"), true, func(s jsjson.Object) {
			c.assertObject(at(at(path, "sampling"), "context"), field(s, "context"), true)
			c.assertObject(at(at(path, "sampling"), "tools"), field(s, "tools"), true)
		})
		c.elicitation(at(path, "elicitation"), field(o, "elicitation"))
		c.object(at(path, "roots"), field(o, "roots"), true, func(r jsjson.Object) {
			c.boolean(at(at(path, "roots"), "listChanged"), field(r, "listChanged"), true)
		})
		tasks := at(path, "tasks")
		c.object(tasks, field(o, "tasks"), true, func(t jsjson.Object) {
			c.assertObject(at(tasks, "list"), field(t, "list"), true)
			c.assertObject(at(tasks, "cancel"), field(t, "cancel"), true)
			requests := at(tasks, "requests")
			c.object(requests, field(t, "requests"), true, func(r jsjson.Object) {
				sampling := at(requests, "sampling")
				c.object(sampling, field(r, "sampling"), true, func(s jsjson.Object) {
					c.assertObject(at(sampling, "createMessage"), field(s, "createMessage"), true)
				})
				elicitation := at(requests, "elicitation")
				c.object(elicitation, field(r, "elicitation"), true, func(e jsjson.Object) {
					c.assertObject(at(elicitation, "create"), field(e, "create"), true)
				})
			})
		})
		c.record(at(path, "extensions"), field(o, "extensions"), true, func(p []any, v any) { c.assertObject(p, v, false) })
	})
}

// elicitation is ElicitationCapabilitySchema: an empty object reads as
// {form: {}}; then an intersection of {form?, url?} and a record, whose
// issues come left side first.
func (c *checker) elicitation(path []any, v any) {
	if v == absent {
		return
	}
	c.intersection(path, v, func(o jsjson.Object) {
		form := at(path, "form")
		if f := field(o, "form"); f != absent {
			c.intersection(form, f, func(fo jsjson.Object) {
				c.boolean(at(form, "applyDefaults"), field(fo, "applyDefaults"), true)
			})
		}
		c.assertObject(at(path, "url"), field(o, "url"), true)
	})
}

// intersection is z.intersection(z.object(...), z.record(z.string(),
// z.unknown())): for anything but an object, the object's issue and the
// record's.
func (c *checker) intersection(path []any, v any, fields func(jsjson.Object)) {
	if o, ok := v.(jsjson.Object); ok {
		fields(o)
		return
	}
	c.invalidType(path, "object", v)
	c.invalidType(path, "record", v)
}

// implementation is ImplementationSchema.
func (c *checker) implementation(path []any, v any) {
	c.object(path, v, false, func(o jsjson.Object) {
		c.str(at(path, "name"), field(o, "name"), false)
		c.str(at(path, "title"), field(o, "title"), true)
		c.array(at(path, "icons"), field(o, "icons"), true, func(p []any, icon any) {
			c.object(p, icon, false, func(i jsjson.Object) {
				c.str(at(p, "src"), field(i, "src"), false)
				c.str(at(p, "mimeType"), field(i, "mimeType"), true)
				c.array(at(p, "sizes"), field(i, "sizes"), true, func(sp []any, s any) { c.str(sp, s, false) })
				c.enum(at(p, "theme"), field(i, "theme"), true, "light", "dark")
			})
		})
		c.str(at(path, "version"), field(o, "version"), false)
		c.str(at(path, "websiteUrl"), field(o, "websiteUrl"), true)
		c.str(at(path, "description"), field(o, "description"), true)
	})
}

// listToolsIssues is ListToolsRequestSchema's issues for params.
func listToolsIssues(params any) []issue {
	var c checker
	c.object([]any{"params"}, params, true, func(p jsjson.Object) {
		c.str([]any{"params", "cursor"}, field(p, "cursor"), true)
	})
	return c.issues
}

// callToolIssues is CallToolRequestSchema's issues for params, in its
// shape's order: _meta, task, name, arguments.
func callToolIssues(params any) []issue {
	var c checker
	c.object([]any{"params"}, params, false, func(p jsjson.Object) {
		c.taskMetadata([]any{"params", "task"}, field(p, "task"))
		c.str([]any{"params", "name"}, field(p, "name"), false)
		c.record([]any{"params", "arguments"}, field(p, "arguments"), true, nil)
	})
	return c.issues
}

func (c *checker) taskMetadata(path []any, v any) {
	c.object(path, v, true, func(t jsjson.Object) {
		c.number(at(path, "ttl"), field(t, "ttl"), true)
	})
}

// taskAugmented is isTaskAugmentedRequestParams(params) with a task: the
// request asks for task creation.
func taskAugmented(params any) bool {
	p, ok := params.(jsjson.Object)
	if !ok {
		return false
	}
	task := field(p, "task")
	if task == absent {
		return false
	}
	var c checker
	c.taskMetadata(nil, task)
	return len(c.issues) == 0
}

// zodMessage is a ZodError's message: its issues as JSON, indented by two.
func zodMessage(issues []issue) string {
	list := make([]any, len(issues))
	for i, is := range issues {
		var o jsjson.Object
		if is.code == "invalid_type" {
			o = append(o, jsjson.Member{Key: "expected", Value: is.expected})
		}
		o = append(o, jsjson.Member{Key: "code", Value: is.code})
		if is.values != nil {
			values := make([]any, len(is.values))
			for j, v := range is.values {
				values[j] = v
			}
			o = append(o, jsjson.Member{Key: "values", Value: values})
		}
		o = append(o, jsjson.Member{Key: "path", Value: append([]any{}, is.path...)}, jsjson.Member{Key: "message", Value: is.message})
		list[i] = o
	}
	return string(jsjson.StringifyIndent(list, 2))
}

// ---- The tools' input schemas ---------------------------------------------------------

// argument is one property of a tool's input schema.
type argument struct {
	name        string
	kind        string // string, boolean, limit
	required    bool
	description string
}

// argumentIssues is the tool's z.object(shape) parse of args, in the
// shape's order.
func argumentIssues(args jsjson.Object, shape []argument) []issue {
	var c checker
	for _, a := range shape {
		v := field(args, a.name)
		path := []any{a.name}
		switch a.kind {
		case "string":
			c.str(path, v, !a.required)
		case "boolean":
			c.boolean(path, v, !a.required)
		case "limit":
			c.limit(path, v)
		}
	}
	return c.issues
}

// limit is z.number().int().min(1).max(200).optional(): an integer that is
// not safe gets its bound's issue and the checks go on; a number that is no
// integer gets one issue and they stop.
func (c *checker) limit(path []any, v any) {
	if v == absent {
		return
	}
	n, ok := v.(float64)
	if !ok {
		c.invalidType(path, "number", v)
		return
	}
	if n != math.Trunc(n) {
		c.issues = append(c.issues, issue{code: "invalid_type", expected: "int", path: path, message: "Invalid input: expected int, received number"})
		return
	}
	const maxSafe = 1<<53 - 1
	if n > maxSafe {
		c.issues = append(c.issues, issue{code: "too_big", path: path, message: "Too big: expected int to be <=9007199254740991"})
	}
	if n < -maxSafe {
		c.issues = append(c.issues, issue{code: "too_small", path: path, message: "Too small: expected int to be >=-9007199254740991"})
	}
	if n < 1 {
		c.issues = append(c.issues, issue{code: "too_small", path: path, message: "Too small: expected number to be >=1"})
	}
	if n > 200 {
		c.issues = append(c.issues, issue{code: "too_big", path: path, message: "Too big: expected number to be <=200"})
	}
}

// parseErrorMessage is getParseErrorMessage: each issue's message, and its
// place when it has one, one per line.
func parseErrorMessage(issues []issue) string {
	lines := make([]string, len(issues))
	for i, is := range issues {
		if len(is.path) == 0 {
			lines[i] = is.message
			continue
		}
		var b strings.Builder
		for j, seg := range is.path {
			switch s := seg.(type) {
			case float64:
				if j == 0 {
					b.WriteString(jsjson.Number(s))
				} else {
					b.WriteString("[" + jsjson.Number(s) + "]")
				}
			case string:
				if j > 0 {
					b.WriteByte('.')
				}
				b.WriteString(s)
			}
		}
		lines[i] = is.message + " at " + b.String()
	}
	return strings.Join(lines, "\n")
}
