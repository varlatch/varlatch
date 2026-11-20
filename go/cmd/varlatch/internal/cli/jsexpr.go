// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"math"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The expression layer of the security commands (slice 5.7b): TypeScript
// that reads a server's answer as `x.a.b`, `${x}`, `x ?? y` and `x > 0`,
// ported as it reads. A value is a parsed JSON value, or undef for a
// property that is not there. A read the TypeScript CLI would throw on
// (a property of null or undefined, a method of a value that has none)
// panics with jsThrown, and catchJS turns it back into the error: the
// whole builder fails before anything is printed, as the TypeScript one
// throws before its console.log.

// undef is JavaScript's undefined.
var undef = apiclient.Undefined

// jsThrown carries a TypeError out of a builder to catchJS.
type jsThrown struct{ err error }

func throwJS(err error) { panic(jsThrown{err}) }

func throwType(message string) { throwJS(&clientctx.TypeError{Message: message}) }

// catchJS runs f and returns what it threw (jsThrown), nil when nothing.
func catchJS(f func()) (err error) {
	defer func() {
		if v := recover(); v != nil {
			if t, ok := v.(jsThrown); ok {
				err = t.err
				return
			}
			panic(v)
		}
	}()
	f()
	return nil
}

// must is a (value, error) pair inside a builder: the error is thrown.
func must[T any](v T, err error) T {
	if err != nil {
		throwJS(err)
	}
	return v
}

// isNullish is `x == null`.
func isNullish(x any) bool { return x == nil || x == undef }

// at is `x.key`: V8's TypeError when x is null or undefined, undefined for
// a key x does not have.
func at(x any, key string) any {
	if isNullish(x) {
		throwJS(typeErrorRead(x, x != undef, key))
	}
	v, ok := jsval.Get(x, key)
	if !ok {
		return undef
	}
	return v
}

// optAt is `x?.key`.
func optAt(x any, key string) any {
	if isNullish(x) {
		return undef
	}
	return at(x, key)
}

// js is `${x}`: String(x), "undefined" for undefined.
func js(x any) string {
	if x == undef {
		return "undefined"
	}
	return jsjson.String(x)
}

// sval is `${x}` of a server's value through the URL fail-safe every
// printed server value goes through (shownValue); the line it goes into
// is escaped as a whole (printable) at the end.
func sval(x any) string { return shownValue(js(x)) }

// truthy is ToBoolean.
func truthy(x any) bool { return x != undef && jsjson.Truthy(x) }

// coalesce is `x ?? y`.
func coalesce(x, y any) any {
	if isNullish(x) {
		return y
	}
	return x
}

// strictEq is `a === b`.
func strictEq(a, b any) bool {
	if a == undef || b == undef {
		return a == b
	}
	return jsval.StrictEqual(a, b)
}

// num is Number(x).
func num(x any) float64 {
	switch v := x.(type) {
	case float64:
		return v
	case string:
		n, ok := jsval.ToNumber(jsval.UTF16(v))
		if !ok {
			return math.NaN()
		}
		return n
	case bool:
		if v {
			return 1
		}
		return 0
	case nil:
		return 0
	case []any:
		switch len(v) {
		case 0:
			return 0
		case 1:
			return num(js(v[0]))
		}
	}
	return math.NaN()
}

// gt is `a > b`: two strings compare as strings, anything else as numbers.
func gt(a, b any) bool {
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		return jsval.CompareUTF16(as, bs) > 0
	}
	return num(a) > num(b)
}

// length is `x.length`: a string's UTF-16 length, an array's; undefined
// (NaN in arithmetic) for anything else.
func length(x any) any {
	switch v := x.(type) {
	case string:
		return float64(utf16Len(v))
	case []any:
		return float64(len(v))
	}
	return at(x, "length")
}

// jsPadEnd is `x.padEnd(width)` for a string; anything else has no padEnd.
func jsPadEnd(x any, width float64, expr string) string {
	s, ok := x.(string)
	if !ok {
		if isNullish(x) {
			throwJS(typeErrorRead(x, x != undef, "padEnd"))
		}
		throwType(expr + ".padEnd is not a function")
	}
	n := utf16Len(s)
	if math.IsNaN(width) || width <= float64(n) {
		return s
	}
	return s + strings.Repeat(" ", int(width)-n)
}

// maxLength is `Math.max(...xs.map((x) => x.length))`: -Infinity for none,
// NaN when one is not a number.
func maxLength(lengths []any) float64 {
	out := math.Inf(-1)
	for _, l := range lengths {
		n, ok := l.(float64)
		if !ok {
			return math.NaN()
		}
		out = math.Max(out, n)
	}
	return out
}

// array is x for `x.map(...)`, `x.filter(...)`, `x.find(...)`, `x.join(...)`
// and the like: an array, or V8's TypeError.
func array(x any, expr, method string) []any {
	if l, ok := x.([]any); ok {
		return l
	}
	if isNullish(x) {
		throwJS(typeErrorRead(x, x != undef, method))
	}
	throwType(expr + "." + method + " is not a function")
	return nil
}

// join is `x.join(sep)`: each element as String(), null and undefined as "".
func join(x any, sep, expr string) string {
	parts := []string{}
	for _, e := range array(x, expr, "join") {
		if isNullish(e) {
			parts = append(parts, "")
			continue
		}
		parts = append(parts, sval(e))
	}
	return strings.Join(parts, sep)
}

// has is `x.includes(value)` for a string value.
func has(x any, value, expr string) bool {
	return must(includes(x, x != undef, value, expr))
}

// pl is `${n} ${n === 1 ? one : many}`.
func pl(n any, one, many string) string {
	if strictEq(n, 1.0) {
		return sval(n) + " " + one
	}
	return sval(n) + " " + many
}

// jsNum is a number as `${n}` writes it.
func jsNum(n float64) string { return jsjson.Number(n) }
