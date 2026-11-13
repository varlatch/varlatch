// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var errNoPurpose = errors.New("envelope: context has no purpose")

// maxSafeInteger is JavaScript's Number.MAX_SAFE_INTEGER: beyond it,
// String(n) in JavaScript stops writing plain digits.
const maxSafeInteger = 1<<53 - 1

// CanonicalJSON encodes v exactly as the TypeScript canonicalJson
// (packages/contract/src/canonical.ts): object keys sorted by UTF-16 code
// units, recursively; no whitespace; strings escaped as JSON.stringify does
// (only '"', '\' and control characters; not HTML characters, not
// U+2028/U+2029); integers only. It accepts nil, bool, string, integers,
// json.Number and float64 holding a safe integer, map[string]any,
// map[string]string, Context, []any and []string.
func CanonicalJSON(v any) (string, error) {
	var b strings.Builder
	if err := canonical(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func canonical(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		return jsString(b, x)
	case int:
		return integer(b, int64(x))
	case int32:
		return integer(b, int64(x))
	case int64:
		return integer(b, x)
	case uint32:
		return integer(b, int64(x))
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			f, ferr := x.Float64()
			if ferr != nil || f != math.Trunc(f) || math.Abs(f) > maxSafeInteger {
				return fmt.Errorf("envelope: %s is not a safe integer", x)
			}
			n = int64(f)
		}
		return integer(b, n)
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || x != math.Trunc(x) || math.Abs(x) > maxSafeInteger {
			return errors.New("envelope: only safe integers are canonicalizable")
		}
		return integer(b, int64(x))
	case Context:
		return object(b, x)
	case map[string]any:
		return object(b, x)
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, v := range x {
			m[k] = v
		}
		return object(b, m)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []string:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = e
		}
		return canonical(b, a)
	default:
		return fmt.Errorf("envelope: a %T is not canonicalizable", v)
	}
	return nil
}

func integer(b *strings.Builder, n int64) error {
	if n > maxSafeInteger || n < -maxSafeInteger {
		return fmt.Errorf("envelope: %d is not a safe integer", n)
	}
	b.WriteString(strconv.FormatInt(n, 10))
	return nil
}

func object(b *strings.Builder, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// JavaScript compares strings by UTF-16 code units.
	slices.SortFunc(keys, func(a, c string) int {
		return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(c)))
	})
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := jsString(b, k); err != nil {
			return err
		}
		b.WriteByte(':')
		if err := canonical(b, m[k]); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

// jsString writes s as JSON.stringify does. A JavaScript string cannot hold
// invalid UTF-8, so neither may s.
func jsString(b *strings.Builder, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("envelope: a string is not valid UTF-8")
	}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return nil
}
