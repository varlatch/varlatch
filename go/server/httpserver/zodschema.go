// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// A small zod 4 for the bodies with nested objects, arrays and unions (the
// Grant declaration, a role's actions), as safeParse reads them and
// parseBody reports them: each issue "<path>: <message>", in the schema's
// order. An issue either aborts its value (a wrong type, literal or
// option, a missing field, a union no option took) or lets it go on (a
// size check): an array whose elements failed skips its own size check,
// and a union whose options all failed surfaces the issues of the one
// option that failed without aborting, or else reports "Invalid input" at
// its own path. The output keeps the schema's members, in its order.

type zIssue struct {
	path  []string
	msg   string
	abort bool
}

type zSchema interface {
	parse(v any, present bool, path []string) (any, []zIssue)
}

func zPath(path []string, more ...string) []string {
	return append(append([]string{}, path...), more...)
}

func aborted(issues []zIssue) bool {
	for _, i := range issues {
		if i.abort {
			return true
		}
	}
	return false
}

func received(v any, present bool) string {
	if !present {
		return "undefined"
	}
	return zodReceived(v)
}

// zString is z.string(), with .min and .max when set (code points).
type zString struct{ min, max int }

func (s zString) parse(v any, present bool, path []string) (any, []zIssue) {
	str, ok := v.(string)
	if !present || !ok {
		return nil, []zIssue{{path, "Invalid input: expected string, received " + received(v, present), true}}
	}
	n := codePoints(str)
	switch {
	case s.min > 0 && n < s.min:
		return str, []zIssue{{path, "Too small: expected string to have >=" + strconv.Itoa(s.min) + " characters", false}}
	case s.max > 0 && n > s.max:
		return str, []zIssue{{path, "Too big: expected string to have <=" + strconv.Itoa(s.max) + " characters", false}}
	}
	return str, nil
}

// zLiteral is z.literal(value).
type zLiteral string

func (l zLiteral) parse(v any, present bool, path []string) (any, []zIssue) {
	if s, ok := v.(string); present && ok && s == string(l) {
		return s, nil
	}
	return nil, []zIssue{{path, `Invalid input: expected "` + string(l) + `"`, true}}
}

// zEnum is z.enum(options).
type zEnum []string

func (e zEnum) parse(v any, present bool, path []string) (any, []zIssue) {
	if s, ok := v.(string); present && ok && containsString(e, s) {
		return s, nil
	}
	return nil, []zIssue{{path, "Invalid option: expected one of " + quoteOptions(e), true}}
}

// zArray is z.array(element), with .min and .max when set.
type zArray struct {
	element  zSchema
	min, max int
}

func (a zArray) parse(v any, present bool, path []string) (any, []zIssue) {
	list, ok := v.([]any)
	if !present || !ok {
		return nil, []zIssue{{path, "Invalid input: expected array, received " + received(v, present), true}}
	}
	out := make([]any, len(list))
	var issues []zIssue
	for i, e := range list {
		var is []zIssue
		out[i], is = a.element.parse(e, true, zPath(path, strconv.Itoa(i)))
		issues = append(issues, is...)
	}
	if !aborted(issues) && len(list) < a.min {
		issues = append(issues, zIssue{path, "Too small: expected array to have >=" + strconv.Itoa(a.min) + " items", false})
	}
	if !aborted(issues) && a.max > 0 && len(list) > a.max {
		issues = append(issues, zIssue{path, "Too big: expected array to have <=" + strconv.Itoa(a.max) + " items", false})
	}
	return out, issues
}

// zNullable is schema.nullable(): null passes as null.
type zNullable struct{ schema zSchema }

func (n zNullable) parse(v any, present bool, path []string) (any, []zIssue) {
	if present && v == nil {
		return nil, nil
	}
	return n.schema.parse(v, present, path)
}

// zField is one member of a z.object.
type zField struct {
	name     string
	schema   zSchema
	optional bool
}

// zObject is z.object(shape), not strict: unknown members are dropped.
type zObject []zField

func (o zObject) parse(v any, present bool, path []string) (any, []zIssue) {
	obj, ok := v.(jsvalue.Object)
	if !present || !ok {
		return nil, []zIssue{{path, "Invalid input: expected object, received " + received(v, present), true}}
	}
	out := jsvalue.Object{}
	var issues []zIssue
	for _, f := range o {
		fv, has := obj.Get(f.name)
		if !has && f.optional {
			continue
		}
		val, is := f.schema.parse(fv, has, zPath(path, f.name))
		issues = append(issues, is...)
		if len(is) == 0 || !aborted(is) {
			out = append(out, jsvalue.Member{Key: f.name, Value: val})
		}
	}
	return out, issues
}

// zStrict is z.object(shape).strict(): its members, then one issue at its
// own path naming every key the shape does not know.
type zStrict zObject

func (o zStrict) parse(v any, present bool, path []string) (any, []zIssue) {
	out, issues := zObject(o).parse(v, present, path)
	obj, ok := v.(jsvalue.Object)
	if !present || !ok {
		return out, issues
	}
	var extra []string
	for _, m := range obj {
		known := false
		for _, f := range o {
			known = known || f.name == m.Key
		}
		if !known {
			extra = append(extra, `"`+m.Key+`"`)
		}
	}
	switch len(extra) {
	case 0:
	case 1:
		issues = append(issues, zIssue{path, "Unrecognized key: " + extra[0], false})
	default:
		issues = append(issues, zIssue{path, "Unrecognized keys: " + strings.Join(extra, ", "), false})
	}
	return out, issues
}

// zDefault is schema.default(value): undefined becomes value.
type zDefault struct {
	schema zSchema
	value  any
}

func (d zDefault) parse(v any, present bool, path []string) (any, []zIssue) {
	if !present {
		return d.value, nil
	}
	return d.schema.parse(v, present, path)
}

// zBool is z.boolean().
type zBool struct{}

func (zBool) parse(v any, present bool, path []string) (any, []zIssue) {
	if b, ok := v.(bool); present && ok {
		return b, nil
	}
	return nil, []zIssue{{path, "Invalid input: expected boolean, received " + received(v, present), true}}
}

// zUnion is z.union(options).
type zUnion []zSchema

func (u zUnion) parse(v any, present bool, path []string) (any, []zIssue) {
	type result struct {
		value  any
		issues []zIssue
	}
	results := make([]result, len(u))
	for i, option := range u {
		val, is := option.parse(v, present, path)
		if len(is) == 0 {
			return val, nil
		}
		results[i] = result{val, is}
	}
	var live []result
	for _, r := range results {
		if !aborted(r.issues) {
			live = append(live, r)
		}
	}
	if len(live) == 1 {
		return live[0].value, live[0].issues
	}
	return nil, []zIssue{{path, "Invalid input", true}}
}

// zParse is parseBody for a schema: its output, or VALIDATION_FAILED with
// every issue.
func zParse(schema zSchema, body any) (any, error) {
	_, undefined := body.(undefinedBody)
	out, issues := schema.parse(body, !undefined, nil)
	if len(issues) == 0 {
		return out, nil
	}
	parts := make([]string, len(issues))
	for i, is := range issues {
		p := strings.Join(is.path, ".")
		if p == "" {
			p = "(root)"
		}
		parts[i] = p + ": " + is.msg
	}
	return nil, domainerr.New("VALIDATION_FAILED", strings.Join(parts, "; "))
}
