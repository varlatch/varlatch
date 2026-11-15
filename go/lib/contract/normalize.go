// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// ValidationError is ContractValidationError: the Contract is not valid,
// for the reasons in Issues, each "<path>: <message>" as zod and the
// TypeScript rules word them.
type ValidationError struct{ Issues []string }

func (e *ValidationError) Error() string {
	return "Invalid Configuration Contract: " + strings.Join(e.Issues, "; ")
}

// Options are normalizeContract's NormalizeOptions.
type Options struct {
	// VersionUndecided: the Contract names no semantics version and the
	// server decides it; the check that each item type exists at the
	// revision's version waits for that decision.
	VersionUndecided bool
}

var namePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// The structural checks are zod's, as packages/contract declares them
// (normalize.ts), with zod 4's messages and order: an object's fields in
// the schema's order, each field's checks in order, then the object's
// unrecognized keys; every issue is collected.

type checker struct{ issues []string }

func pathOf(path []string) string {
	if len(path) == 0 {
		return "(root)"
	}
	return strings.Join(path, ".")
}

func (c *checker) add(path []string, format string, args ...any) {
	c.issues = append(c.issues, pathOf(path)+": "+fmt.Sprintf(format, args...))
}

func at(path []string, part string) []string { return append(slices.Clone(path), part) }

// object checks an object and its unrecognized keys around fields, which
// checks the known ones; it reports whether v is an object.
func (c *checker) object(path []string, v any, present bool, known []string, fields func(o Object)) bool {
	o, ok := v.(Object)
	if !ok || !present {
		c.add(path, "Invalid input: expected object, received %s", jsType(v, present))
		return false
	}
	fields(o)
	var unknown []string
	for _, k := range o.keys() {
		if !slices.Contains(known, k) {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		var b bytes.Buffer
		for i, k := range unknown {
			if i > 0 {
				b.WriteString(", ")
			}
			quote(&b, k)
		}
		word := "key"
		if len(unknown) > 1 {
			word = "keys"
		}
		c.add(path, "Unrecognized %s: %s", word, b.String())
	}
	return true
}

// str is z.string() with min and max (code points, as zod 4 counts) and an
// optional pattern; it reports whether v is a string.
func (c *checker) str(path []string, v any, present bool, minLen, maxLen int, pattern *regexp.Regexp, patternMessage string) (string, bool) {
	s, ok := v.(string)
	if !ok || !present {
		c.add(path, "Invalid input: expected string, received %s", jsType(v, present))
		return "", false
	}
	n := codePoints(s)
	if minLen > 0 && n < minLen {
		c.add(path, "Too small: expected string to have >=%d characters", minLen)
	}
	if maxLen > 0 && n > maxLen {
		c.add(path, "Too big: expected string to have <=%d characters", maxLen)
	}
	if pattern != nil && !pattern.MatchString(s) {
		c.add(path, "%s", patternMessage)
	}
	return s, true
}

const maxSafe = 9007199254740991

// integer is z.number().int() with min and max; it reports whether v is
// an integer within the bounds zod checks.
func (c *checker) integer(path []string, v any, present bool, minV, maxV *float64) (int64, bool) {
	f, ok := v.(float64)
	if !ok || !present || math.IsNaN(f) || math.IsInf(f, 0) {
		c.add(path, "Invalid input: expected number, received %s", jsType(v, present))
		return 0, false
	}
	if f != math.Trunc(f) {
		c.add(path, "Invalid input: expected int, received number")
		return 0, false
	}
	good := true
	if f > maxSafe {
		c.add(path, "Too big: expected int to be <=%d", maxSafe)
		good = false
	}
	if f < -maxSafe {
		c.add(path, "Too small: expected int to be >=-%d", maxSafe)
		good = false
	}
	if minV != nil && f < *minV {
		c.add(path, "Too small: expected number to be >=%s", strconv.FormatFloat(*minV, 'f', -1, 64))
		good = false
	}
	if maxV != nil && f > *maxV {
		c.add(path, "Too big: expected number to be <=%s", strconv.FormatFloat(*maxV, 'f', -1, 64))
		good = false
	}
	return int64(f), good
}

func (c *checker) boolean(path []string, v any, present bool) bool {
	b, ok := v.(bool)
	if !ok || !present {
		c.add(path, "Invalid input: expected boolean, received %s", jsType(v, present))
	}
	return b
}

func optionsText(options []string) string {
	q := make([]string, len(options))
	for i, o := range options {
		var b bytes.Buffer
		quote(&b, o)
		q[i] = b.String()
	}
	return strings.Join(q, "|")
}

// enum is z.enum(options).
func (c *checker) enum(path []string, v any, present bool, options []string) string {
	s, ok := v.(string)
	if !ok || !present || !slices.Contains(options, s) {
		c.add(path, "Invalid option: expected one of %s", optionsText(options))
		return ""
	}
	return s
}

// discriminator is a discriminated union's kind; ok false when it matches
// no option (the union reports it at the key's path).
func (c *checker) discriminator(path []string, o Object, options []string) (string, bool) {
	v, present := o.get("kind")
	s, ok := v.(string)
	if !present || !ok || !slices.Contains(options, s) {
		q := make([]string, len(options))
		for i, opt := range options {
			q[i] = "'" + opt + "'"
		}
		c.add(at(path, "kind"), "Invalid discriminator value. Expected %s", strings.Join(q, " | "))
		return "", false
	}
	return s, true
}

func (c *checker) array(path []string, v any, present bool, minLen int, each func(path []string, v any)) bool {
	a, ok := v.([]any)
	if !ok || !present {
		c.add(path, "Invalid input: expected array, received %s", jsType(v, present))
		return false
	}
	if minLen > 0 && len(a) < minLen {
		c.add(path, "Too small: expected array to have >=%d items", minLen)
	}
	for i, e := range a {
		each(at(path, strconv.Itoa(i)), e)
	}
	return true
}

func ptr[T any](v T) *T { return &v }

func (c *checker) selector(path []string, v any, present bool) *Selector {
	var sel Selector
	if _, ok := v.(Object); !ok || !present {
		c.add(path, "Invalid input: expected object, received %s", jsType(v, present))
		return nil
	}
	kind, ok := c.discriminator(path, v.(Object), []string{"environments", "tier"})
	if !ok {
		return nil
	}
	sel.Kind = kind
	if kind == "environments" {
		c.object(path, v, true, []string{"kind", "environmentIds"}, func(o Object) {
			ids, present := o.get("environmentIds")
			c.array(at(path, "environmentIds"), ids, present, 1, func(p []string, e any) {
				if s, ok := c.str(p, e, true, 1, 0, nil, ""); ok {
					sel.EnvironmentIDs = append(sel.EnvironmentIDs, s)
				}
			})
		})
	} else {
		c.object(path, v, true, []string{"kind", "tier"}, func(o Object) {
			t, present := o.get("tier")
			sel.Tier = c.enum(at(path, "tier"), t, present, Tiers)
		})
	}
	return &sel
}

func (c *checker) requiredness(path []string, v any, present bool) Requiredness {
	var r Requiredness
	if _, ok := v.(Object); !ok || !present {
		c.add(path, "Invalid input: expected object, received %s", jsType(v, present))
		return r
	}
	kind, ok := c.discriminator(path, v.(Object), []string{"always", "never", "selector"})
	if !ok {
		return r
	}
	r.Kind = kind
	known := []string{"kind"}
	if kind == "selector" {
		known = append(known, "selector")
	}
	c.object(path, v, true, known, func(o Object) {
		if kind == "selector" {
			s, present := o.get("selector")
			r.Selector = c.selector(at(path, "selector"), s, present)
		}
	})
	return r
}

var itemFields = []string{"name", "required", "sensitive", "type", "enumValues", "defaultValue", "description", "example", "rotationGraceSeconds", "rotationHint"}

func (c *checker) item(path []string, v any) Item {
	var it Item
	c.object(path, v, true, itemFields, func(o Object) {
		get := func(k string) (any, bool) { return o.get(k) }
		val, present := get("name")
		it.Name, _ = c.str(at(path, "name"), val, present, 1, 256, namePattern, "Config Item names must match ^[A-Z][A-Z0-9_]*$")
		val, present = get("required")
		it.Required = c.requiredness(at(path, "required"), val, present)
		val, present = get("sensitive")
		it.Sensitive = c.boolean(at(path, "sensitive"), val, present)
		val, present = get("type")
		it.Type = c.enum(at(path, "type"), val, present, ItemTypes)
		if val, present = get("enumValues"); present {
			it.EnumValues = []string{}
			c.array(at(path, "enumValues"), val, true, 1, func(p []string, e any) {
				if s, ok := c.str(p, e, true, 1, 0, nil, ""); ok {
					it.EnumValues = append(it.EnumValues, s)
				}
			})
		}
		optional := func(key string, maxLen int) *string {
			val, present := get(key)
			if !present {
				return nil
			}
			s, ok := c.str(at(path, key), val, true, 0, maxLen, nil, "")
			if !ok {
				return nil
			}
			return &s
		}
		it.DefaultValue = optional("defaultValue", 0)
		it.Description = optional("description", 4096)
		it.Example = optional("example", 4096)
		if val, present = get("rotationGraceSeconds"); present {
			if n, ok := c.integer(at(path, "rotationGraceSeconds"), val, true, ptr(1.0), ptr(2_592_000.0)); ok {
				it.RotationGraceSeconds = &n
			}
		}
		if val, present = get("rotationHint"); present {
			if s, ok := c.str(at(path, "rotationHint"), val, true, 0, 0, nil, ""); ok {
				if problem := RotationHintProblem(s); problem != "" {
					c.add(at(path, "rotationHint"), "%s", problem)
				}
				it.RotationHint = &s
			}
		}
	})
	return it
}

// RotationHintMax is the most code points a rotation hint may hold
// (ADR-0053).
const RotationHintMax = 1024

// RotationHintProblem is rotationHintProblem: why a hint is not
// acceptable, or "". A hint is one plain paragraph.
func RotationHintProblem(hint string) string {
	n := codePoints(hint)
	if n == 0 {
		return "a rotation hint cannot be empty; leave it out instead"
	}
	if n > RotationHintMax {
		return fmt.Sprintf("a rotation hint holds at most %d characters", RotationHintMax)
	}
	for _, r := range hint {
		if r <= 0x1f || (r >= 0x7f && r <= 0x9f) || r == 0x061c || r == 0x200e || r == 0x200f || r == 0x2028 || r == 0x2029 ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return "a rotation hint is one paragraph: no tabs, line breaks, control or bidirectional formatting characters"
		}
	}
	return ""
}

// SemanticsVersions are the Contract Semantics versions this code knows.
var SemanticsVersions = []int{1, 2, 3}

// LatestSemanticsVersion is what a project's first revision gets.
const LatestSemanticsVersion = 3

// Normalize is normalizeContract: input validated and put in canonical
// form (items sorted by name, enum values and selector environment IDs
// sorted and unique, absent optional fields omitted). A *ValidationError
// says why it is not a Contract.
func Normalize(input any, opts Options) (Contract, error) {
	c := &checker{}
	var version *int64
	var items []Item
	c.object(nil, input, true, []string{"schemaVersion", "semanticsVersion", "items"}, func(o Object) {
		if v, present := o.get("schemaVersion"); !present || v != any(float64(SchemaVersion)) {
			c.add([]string{"schemaVersion"}, "Invalid input: expected %d", SchemaVersion)
		}
		if v, present := o.get("semanticsVersion"); present {
			if n, ok := c.integer([]string{"semanticsVersion"}, v, true, nil, nil); ok {
				version = &n
			}
		}
		v, present := o.get("items")
		c.array([]string{"items"}, v, present, 0, func(p []string, e any) {
			items = append(items, c.item(p, e))
		})
	})
	if len(c.issues) > 0 {
		return Contract{}, &ValidationError{Issues: c.issues}
	}

	var issues []string
	if version != nil && !slices.Contains(SemanticsVersions, int(*version)) {
		issues = append(issues, fmt.Sprintf("semanticsVersion: version %d is not supported (supported: 1, 2, 3)", *version))
	}
	typesVersion := int64(1)
	decided := true
	switch {
	case version != nil:
		typesVersion = *version
	case opts.VersionUndecided:
		decided = false
	}
	seen := map[string]bool{}
	for _, it := range items {
		if since := TypeSince[it.Type]; decided && typesVersion < int64(since) {
			issues = append(issues, fmt.Sprintf("%s: type %s needs Contract Semantics version %d or later, and this Contract uses version %d; "+
				"move it to the newest rules (varlatch contract push --semantics latest, or the dashboard's Contract page)", it.Name, it.Type, since, typesVersion))
		}
		if slices.Contains(ReservedItemNames, it.Name) {
			issues = append(issues, it.Name+" is reserved for launcher metadata and cannot be a Config Item")
		}
		if seen[it.Name] {
			issues = append(issues, "duplicate Config Item name "+it.Name)
		}
		seen[it.Name] = true
		if it.Type == "enum" && it.EnumValues == nil {
			issues = append(issues, it.Name+": enum type requires enumValues")
		}
		if it.Type != "enum" && it.EnumValues != nil {
			issues = append(issues, it.Name+": enumValues is only valid for enum type")
		}
		if it.Type == "enum" && it.EnumValues != nil && it.DefaultValue != nil && !slices.Contains(it.EnumValues, *it.DefaultValue) {
			issues = append(issues, it.Name+": defaultValue is not one of enumValues")
		}
	}
	if len(issues) > 0 {
		return Contract{}, &ValidationError{Issues: issues}
	}

	for i := range items {
		it := &items[i]
		if s := it.Required.Selector; s != nil && s.Kind == "environments" {
			s.EnvironmentIDs = sortedUnique(s.EnvironmentIDs)
		}
		if it.EnumValues != nil {
			it.EnumValues = sortedUnique(it.EnumValues)
		}
	}
	slices.SortStableFunc(items, func(a, b Item) int { return compare(a.Name, b.Name) })
	out := Contract{Items: items}
	if version != nil && *version != 1 {
		out.SemanticsVersion = int(*version)
	}
	if out.Items == nil {
		out.Items = []Item{}
	}
	return out, nil
}

func compare(a, b string) int {
	switch {
	case less(a, b):
		return -1
	case less(b, a):
		return 1
	}
	return 0
}

func sortedUnique(s []string) []string {
	out := slices.Clone(s)
	slices.SortStableFunc(out, compare)
	return slices.Compact(out)
}
