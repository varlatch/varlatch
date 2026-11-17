// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"math"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// JSON settings files as the TypeScript code handles them: values from
// JSON.parse (lib/jsjson), objects built with spreads, and
// util.isDeepStrictEqual.

// isObject is a non-null, non-array object.
func isObject(v any) bool {
	_, ok := v.(jsjson.Object)
	return ok
}

// get is o[k] for a value that may not be an object.
func get(v any, k string) (any, bool) {
	if o, ok := v.(jsjson.Object); ok {
		return o.Get(k)
	}
	return nil, false
}

// with is {...o, [k]: v}: k keeps its place when o has it, else comes last.
func with(o jsjson.Object, k string, v any) jsjson.Object {
	return append(jsjson.Object(nil), o...).Set(k, v)
}

// without is the rest of `const {[k]: _, ...rest} = o`.
func without(o jsjson.Object, k string) jsjson.Object {
	out := jsjson.Object{}
	for _, m := range o {
		if m.Key != k {
			out = append(out, m)
		}
	}
	return out
}

// spread is {...v} for any value an object literal may spread: an object's
// own properties, an array's indexes, nothing for null or a boolean or
// number (the callers spread only objects and arrays).
func spread(v any) jsjson.Object {
	switch x := v.(type) {
	case jsjson.Object:
		return append(jsjson.Object(nil), x...)
	case []any:
		out := jsjson.Object{}
		for i, item := range x {
			out = out.Set(jsjson.Number(float64(i)), item)
		}
		return out
	}
	return jsjson.Object{}
}

// deepEqual is util.isDeepStrictEqual for JSON values: numbers by
// Object.is, objects whatever their key order.
func deepEqual(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y && math.Signbit(x) == math.Signbit(y)
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !deepEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case jsjson.Object:
		y, ok := b.(jsjson.Object)
		if !ok || len(x) != len(y) {
			return false
		}
		for _, m := range x {
			other, ok := y.Get(m.Key)
			if !ok || !deepEqual(m.Value, other) {
				return false
			}
		}
		return true
	}
	return false
}

// includes is Array.prototype.includes for a string.
func includes(list []any, s string) bool {
	for _, v := range list {
		if v == any(s) {
			return true
		}
	}
	return false
}
