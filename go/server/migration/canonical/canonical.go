// SPDX-License-Identifier: AGPL-3.0-or-later

// Package canonical is the migration's canonical encoding, canonical-v1
// (ADR-0059 Decision 9; docs/design/go-step7.md decision 3; CANONICAL.md):
// how a row of the migration manifest is written, byte for byte, so that the
// TypeScript export and varlatchd write the same bytes for the same value,
// and how decision 7's digest input is built. The TypeScript server's
// encoder (services/varlatchd/src/migration/canonical.ts on the 0.22 line)
// reproduces testdata/vectors.json, as this package does.
package canonical

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Type is a column's PostgreSQL type, as the manifest names it.
type Type string

// The types of the TypeScript server's schema (testdata/pg-v0.22.0.json).
// A type outside this list is refused until the encoding defines it.
const (
	Text        Type = "text"
	Timestamptz Type = "timestamp with time zone"
	Integer     Type = "integer"
	Bigint      Type = "bigint"
	Boolean     Type = "boolean"
	Jsonb       Type = "jsonb"
	TextArray   Type = "text[]"
	Bytea       Type = "bytea"
)

// Types lists every type the encoding defines.
var Types = []Type{Text, Timestamptz, Integer, Bigint, Boolean, Jsonb, TextArray, Bytea}

// Known reports whether the encoding defines t.
func Known(t Type) bool {
	for _, k := range Types {
		if k == t {
			return true
		}
	}
	return false
}

// AppendValue appends v, a value of a column of type t, in canonical form.
//
// The Go forms it takes, as varlatchd reads them from SQLite:
//   - any type: nil for SQL NULL;
//   - text: a string;
//   - timestamp with time zone: int64 microseconds since the Unix epoch, UTC;
//   - integer, bigint: int64 (an integer must be within PostgreSQL's 32 bits);
//   - boolean: bool, or int64 0 or 1;
//   - jsonb: the JSON text, as a string or []byte;
//   - text[]: the JSON array text SQLite holds, or []any of strings and nils;
//   - bytea: []byte.
func AppendValue(b []byte, t Type, v any) ([]byte, error) {
	if v == nil {
		return append(b, "null"...), nil
	}
	switch t {
	case Text:
		s, ok := v.(string)
		if !ok {
			return nil, typeErr(t, v)
		}
		if err := checkText(s); err != nil {
			return nil, err
		}
		return quote(b, s), nil
	case Timestamptz, Bigint, Integer:
		n, ok := asInt64(v)
		if !ok {
			return nil, typeErr(t, v)
		}
		if t == Integer && (n < math.MinInt32 || n > math.MaxInt32) {
			return nil, fmt.Errorf("canonical: %d is outside an integer's 32 bits", n)
		}
		return strconv.AppendInt(b, n, 10), nil
	case Boolean:
		switch x := v.(type) {
		case bool:
			if x {
				return append(b, '1'), nil
			}
			return append(b, '0'), nil
		case int64:
			if x == 0 || x == 1 {
				return strconv.AppendInt(b, x, 10), nil
			}
			return nil, fmt.Errorf("canonical: boolean %d is neither 0 nor 1", x)
		}
		return nil, typeErr(t, v)
	case Jsonb:
		var text []byte
		switch x := v.(type) {
		case string:
			text = []byte(x)
		case []byte:
			text = x
		default:
			return nil, typeErr(t, v)
		}
		c, err := JsonbText(text)
		if err != nil {
			return nil, err
		}
		return quote(b, c), nil
	case TextArray:
		elems, err := textArray(v)
		if err != nil {
			return nil, err
		}
		b = append(b, '[')
		for i, e := range elems {
			if i > 0 {
				b = append(b, ',')
			}
			if e == nil {
				b = append(b, "null"...)
				continue
			}
			if err := checkText(*e); err != nil {
				return nil, err
			}
			b = quote(b, *e)
		}
		return append(b, ']'), nil
	case Bytea:
		x, ok := v.([]byte)
		if !ok {
			return nil, typeErr(t, v)
		}
		return quote(b, base64.StdEncoding.EncodeToString(x)), nil
	}
	return nil, fmt.Errorf("canonical: the encoding does not define type %q", t)
}

// AppendRow appends a row: its values in the manifest's column order, as a
// JSON array with no space.
func AppendRow(b []byte, types []Type, values []any) ([]byte, error) {
	if len(types) != len(values) {
		return nil, fmt.Errorf("canonical: %d types for %d values", len(types), len(values))
	}
	b = append(b, '[')
	for i, t := range types {
		if i > 0 {
			b = append(b, ',')
		}
		var err error
		if b, err = AppendValue(b, t, values[i]); err != nil {
			return nil, fmt.Errorf("column %d: %w", i+1, err)
		}
	}
	return append(b, ']'), nil
}

// JsonbText is a jsonb value's canonical text: the text parsed as
// JSON.parse parses it (numbers as ECMAScript numbers, a repeated key's
// last value), every object's members in jsonb's order (shorter keys first,
// keys of one length by their UTF-8 bytes), written as JSON.stringify
// writes it. Text jsonb would refuse (a lone surrogate, U+0000) is refused.
func JsonbText(text []byte) (string, error) {
	v, err := jsvalue.Parse(text)
	if err != nil {
		return "", fmt.Errorf("canonical: jsonb: %w", err)
	}
	if err := jsvalue.JsonbRefuses(v); err != nil {
		return "", fmt.Errorf("canonical: %w", err)
	}
	return string(jsvalue.Stringify(jsvalue.Jsonb(v))), nil
}

// DigestInput is what decision 7's keyed digest is computed over for one
// decrypted item: the canonical JSON of {class, ids, plaintext}, members in
// jsonb's order (so "ids", "class", "plaintext"), the ids' members in
// jsonb's order too, and the plaintext's bytes in base64.
func DigestInput(class string, ids map[string]string, plaintext []byte) ([]byte, error) {
	if err := checkText(class); err != nil {
		return nil, err
	}
	var idObj jsvalue.Object
	for k, v := range ids {
		if err := checkText(k); err != nil {
			return nil, err
		}
		if err := checkText(v); err != nil {
			return nil, err
		}
		idObj = append(idObj, jsvalue.Member{Key: k, Value: v})
	}
	o := jsvalue.Object{
		{Key: "class", Value: class},
		{Key: "ids", Value: idObj},
		{Key: "plaintext", Value: base64.StdEncoding.EncodeToString(plaintext)},
	}
	return jsvalue.Stringify(jsvalue.Jsonb(o)), nil
}

// checkText refuses what PostgreSQL's text cannot hold: bytes that are not
// UTF-8, and U+0000.
func checkText(s string) error {
	if !utf8.ValidString(s) {
		return errors.New("canonical: text that is not UTF-8")
	}
	if strings.IndexByte(s, 0) >= 0 {
		return errors.New("canonical: text holding U+0000")
	}
	return nil
}

func quote(b []byte, s string) []byte {
	var buf bytes.Buffer
	jsvalue.Quote(&buf, s)
	return append(b, buf.Bytes()...)
}

func asInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case int32:
		return int64(x), true
	}
	return 0, false
}

// textArray reads a text[] value: the JSON array text SQLite holds, or the
// elements. A nested array or any element but a string or null is refused,
// as PostgreSQL's one-dimensional text[] holds neither.
func textArray(v any) ([]*string, error) {
	var raw []any
	switch x := v.(type) {
	case string:
		// Parsed as JSON.parse would: an escaped lone surrogate stays one,
		// and is then refused as text that is not UTF-8.
		p, err := jsvalue.Parse([]byte(x))
		if err != nil {
			return nil, fmt.Errorf("canonical: text[]: %w", err)
		}
		a, ok := p.([]any)
		if !ok {
			return nil, errors.New("canonical: text[] is not a JSON array")
		}
		raw = a
	case []any:
		raw = x
	default:
		return nil, typeErr(TextArray, v)
	}
	out := make([]*string, len(raw))
	for i, e := range raw {
		switch y := e.(type) {
		case nil:
		case string:
			out[i] = &y
		default:
			return nil, fmt.Errorf("canonical: text[] element %d is not a string or null", i+1)
		}
	}
	return out, nil
}

func typeErr(t Type, v any) error {
	return fmt.Errorf("canonical: a %T for a %s column", v, t)
}
