// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// The decoder: a canonical row read back into the Go forms AppendValue
// takes, as varlatchd writes them to SQLite. A row is accepted only when it
// is canonical: re-encoded, its values give back exactly its bytes, so a
// value written any other way (a jsonb text out of jsonb's order, a
// base64 without padding, an integer with a leading zero, an escape
// JSON.stringify would not write) is refused, never normalized. Whatever
// JsonbText refuses (jsonb's own refusals, and any number rule canonical-v1
// holds) is refused here too, through that re-encoding.

// DecodeRow reads one canonical row of the given column types: a JSON
// array of as many values. The values are the Go forms AppendValue takes:
// nil, string (text, jsonb, text[]'s JSON array text), int64 (timestamps,
// integers, booleans as 0 or 1) and []byte (bytea).
func DecodeRow(types []Type, row []byte) ([]any, error) {
	var raw []json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(row))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("canonical: a row that is not a JSON array: %w", err)
	}
	if dec.More() {
		return nil, errors.New("canonical: text after the row")
	}
	if raw == nil {
		return nil, errors.New("canonical: a row that is not a JSON array")
	}
	if len(raw) != len(types) {
		return nil, fmt.Errorf("canonical: %d values for %d columns", len(raw), len(types))
	}
	values := make([]any, len(types))
	for i, t := range types {
		v, err := decodeValue(t, raw[i])
		if err != nil {
			return nil, fmt.Errorf("column %d: %w", i+1, err)
		}
		values[i] = v
	}
	again, err := AppendRow(nil, types, values)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, row) {
		return nil, errors.New("canonical: the row is not in canonical form (its values written again differ from it)")
	}
	return values, nil
}

func decodeValue(t Type, raw json.RawMessage) (any, error) {
	if !Known(t) {
		return nil, fmt.Errorf("canonical: the encoding does not define type %q", t)
	}
	if string(raw) == "null" {
		return nil, nil
	}
	str := func() (string, error) {
		if len(raw) == 0 || raw[0] != '"' {
			return "", fmt.Errorf("canonical: a %s value that is not a JSON string", t)
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", fmt.Errorf("canonical: %w", err)
		}
		return s, nil
	}
	switch t {
	case Text:
		return str()
	case Timestamptz, Integer, Bigint, Boolean:
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("canonical: a %s value that is not a decimal integer", t)
		}
		return n, nil
	case Jsonb:
		s, err := str()
		if err != nil {
			return nil, err
		}
		// JsonbText's refusals (and the canonical form) are checked when
		// the row is written again below.
		return s, nil
	case TextArray:
		if len(raw) == 0 || raw[0] != '[' {
			return nil, errors.New("canonical: a text[] value that is not a JSON array")
		}
		return string(raw), nil
	case Bytea:
		s, err := str()
		if err != nil {
			return nil, err
		}
		b, err := base64.StdEncoding.Strict().DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("canonical: bytea that is not standard padded base64: %w", err)
		}
		return b, nil
	}
	panic("canonical: a known type without its case: " + string(t))
}
