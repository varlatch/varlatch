// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jsvalue is JSON as the TypeScript server reads and writes it, so
// that what varlatchd stores and answers matches it byte for byte (ADR-0059
// step 3.3):
//
//   - Stringify is JSON.stringify: object members in insertion order, no
//     HTML escaping, U+2028 and U+2029 left as they are, numbers in
//     ECMAScript's Number.prototype.toString form, lone surrogates escaped.
//   - Parse is JSON.parse with JavaScript's property order: numbers become
//     float64 (as JavaScript's numbers), a repeated key keeps its first
//     position and its last value, and keys that are array indexes ("0",
//     "17") come first, in numeric order (JSOrder).
//   - Jsonb reorders a value as PostgreSQL's jsonb stores it: within each
//     object, shorter keys first, keys of one length by their UTF-8 bytes,
//     and a repeated key's last value. The TypeScript server's audit
//     columns are jsonb, so every nested object it reads back (and answers
//     with) is in that order, whatever order it was written in.
//
// A value is nil (null), bool, float64 (or any Go integer, when building
// one), string, Object, []any, []string, or a type with a JSValue method.
package jsvalue

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Member is one member of an Object.
type Member struct {
	Key   string
	Value any
}

// Object is a JSON object with its members in order. Keys are unique in an
// Object built by Parse, Jsonb or Set.
type Object []Member

// Get returns the value of key.
func (o Object) Get(key string) (any, bool) {
	for _, m := range o {
		if m.Key == key {
			return m.Value, true
		}
	}
	return nil, false
}

// Set replaces key's value in place, or appends the member: JavaScript's
// assignment to an object property.
func (o Object) Set(key string, value any) Object {
	for i := range o {
		if o[i].Key == key {
			o[i].Value = value
			return o
		}
	}
	return append(o, Member{key, value})
}

// Valuer is a type with a JSON form of its own.
type Valuer interface {
	JSValue() any
}

// Stringify is JSON.stringify(v).
func Stringify(v any) []byte {
	var b bytes.Buffer
	write(&b, v)
	return b.Bytes()
}

func write(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		Quote(b, x)
	case float64:
		b.WriteString(Number(x))
	case int:
		b.WriteString(Number(float64(x)))
	case int32:
		b.WriteString(Number(float64(x)))
	case int64:
		b.WriteString(Number(float64(x)))
	case Object:
		b.WriteByte('{')
		for i, m := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			Quote(b, m.Key)
			b.WriteByte(':')
			write(b, m.Value)
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			write(b, e)
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			Quote(b, e)
		}
		b.WriteByte(']')
	case Valuer:
		write(b, x.JSValue())
	default:
		panic(fmt.Sprintf("jsvalue: %T is not a JSON value", v))
	}
}

const hex = "0123456789abcdef"

// Quote writes s as JSON.stringify quotes a string. Bytes that are not
// UTF-8 count as U+FFFD, as decoding them into a JavaScript string would.
func Quote(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte(hex[r>>4])
			b.WriteByte(hex[r&0xf])
		case r >= 0xd800 && r <= 0xdfff:
			// Not reachable from a Go string (utf8 decodes surrogates as
			// U+FFFD); kept for what JSON.stringify does with one.
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// Number is ECMAScript's Number::toString(x) in radix 10, which
// JSON.stringify uses; NaN and the infinities are null.
func Number(x float64) string {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return "null"
	}
	if x == 0 {
		return "0" // -0 too
	}
	sign := ""
	if x < 0 {
		sign, x = "-", -x
	}
	// The shortest digits that round-trip, as ECMAScript requires: d.ddde+x.
	e := strconv.FormatFloat(x, 'e', -1, 64)
	mant, exp, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	p, _ := strconv.Atoi(exp)
	k, n := len(digits), p+1 // x = 0.digits * 10^n
	var s string
	switch {
	case k <= n && n <= 21:
		s = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		s = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		s = "0." + strings.Repeat("0", -n) + digits
	default:
		es := "+"
		if n-1 < 0 {
			es = "-"
		}
		ev := strconv.Itoa(abs(n - 1))
		if k == 1 {
			s = digits + "e" + es + ev
		} else {
			s = digits[:1] + "." + digits[1:] + "e" + es + ev
		}
	}
	return sign + s
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// Parse is JSON.parse(text), keeping objects' order (see the package
// comment).
func Parse(text []byte) (any, error) {
	if !utf8.Valid(text) {
		return nil, errors.New("jsvalue: the text is not UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(text))
	d.UseNumber()
	v, err := parseValue(d)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("jsvalue: text after the value")
	}
	return JSOrder(v), nil
}

// arrayIndex reports whether k is an array index, which a JavaScript
// object orders before its other keys: "0", or a decimal without leading
// zeros below 2^32 - 1.
func arrayIndex(k string) (uint64, bool) {
	if k == "" || len(k) > 10 || (len(k) > 1 && k[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseUint(k, 10, 64)
	if err != nil || n >= 1<<32-1 {
		return 0, false
	}
	return n, true
}

// JSOrder returns v with every object's members in the order a JavaScript
// object built from it enumerates them: array indexes first, ascending,
// then the other keys in their order.
func JSOrder(v any) any {
	switch x := v.(type) {
	case Object:
		o := make(Object, len(x))
		for i, m := range x {
			o[i] = Member{m.Key, JSOrder(m.Value)}
		}
		slices.SortStableFunc(o, func(a, b Member) int {
			na, ia := arrayIndex(a.Key)
			nb, ib := arrayIndex(b.Key)
			switch {
			case ia && ib:
				return cmp.Compare(na, nb)
			case ia:
				return -1
			case ib:
				return 1
			}
			return 0
		})
		return o
	case []any:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = JSOrder(e)
		}
		return a
	}
	return v
}

func parseValue(d *json.Decoder) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			o := Object{}
			for d.More() {
				kt, err := d.Token()
				if err != nil {
					return nil, err
				}
				v, err := parseValue(d)
				if err != nil {
					return nil, err
				}
				o = o.Set(kt.(string), v)
			}
			_, err := d.Token()
			return o, err
		case '[':
			a := []any{}
			for d.More() {
				v, err := parseValue(d)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := d.Token()
			return a, err
		}
		return nil, fmt.Errorf("jsvalue: unexpected %v", x)
	case json.Number:
		// JSON.parse: the nearest double; beyond its range, an infinity.
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return nil, err
		}
		return f, nil
	default:
		return x, nil // nil, bool, string
	}
}

// Jsonb returns v as PostgreSQL's jsonb holds it (see the package comment).
func Jsonb(v any) any {
	switch x := v.(type) {
	case Object:
		o := make(Object, 0, len(x))
		for _, m := range x {
			o = o.Set(m.Key, Jsonb(m.Value))
		}
		slices.SortStableFunc(o, func(a, b Member) int {
			if len(a.Key) != len(b.Key) {
				return len(a.Key) - len(b.Key)
			}
			return strings.Compare(a.Key, b.Key)
		})
		return o
	case []any:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = Jsonb(e)
		}
		return a
	case []string:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = e
		}
		return a
	case Valuer:
		return Jsonb(x.JSValue())
	case int:
		return float64(x)
	case int32:
		return float64(x)
	case int64:
		return float64(x)
	default:
		return v
	}
}

// Canonical is Stringify(Jsonb(Parse(text))): two texts with the same
// canonical form hold the same jsonb value. For tests and comparisons.
func Canonical(text []byte) (string, error) {
	v, err := Parse(text)
	if err != nil {
		return "", err
	}
	return string(Stringify(Jsonb(v))), nil
}
