// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

type vectors struct {
	Comment string `json:"comment"`
	Values  []struct {
		Name   string          `json:"name"`
		Type   Type            `json:"type"`
		Input  json.RawMessage `json:"input"`
		Output string          `json:"output"`
	} `json:"values"`
	Refused []struct {
		Name  string          `json:"name"`
		Type  Type            `json:"type"`
		Input json.RawMessage `json:"input"`
		Why   string          `json:"why"`
	} `json:"refused"`
	Rows []struct {
		Name   string            `json:"name"`
		Types  []Type            `json:"types"`
		Inputs []json.RawMessage `json:"inputs"`
		Output string            `json:"output"`
	} `json:"rows"`
	Digests []struct {
		Name      string            `json:"name"`
		Class     string            `json:"class"`
		IDs       map[string]string `json:"ids"`
		Plaintext string            `json:"plaintext"`
		Output    string            `json:"output"`
	} `json:"digests"`
}

func readVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// native turns a vector's neutral input into the Go form AppendValue takes,
// as varlatchd reads it from SQLite.
func native(t *testing.T, typ Type, in json.RawMessage) any {
	t.Helper()
	if string(in) == "null" {
		return nil
	}
	var s string
	switch typ {
	case Boolean:
		var b bool
		if err := json.Unmarshal(in, &b); err != nil {
			t.Fatal(err)
		}
		return b
	case TextArray:
		// SQLite holds the array's JSON text.
		return string(in)
	}
	if err := json.Unmarshal(in, &s); err != nil {
		t.Fatalf("%s input %s: %v", typ, in, err)
	}
	switch typ {
	case Timestamptz, Integer, Bigint:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return n
	case Bytea:
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return s
}

func TestVectors(t *testing.T) {
	v := readVectors(t)
	if len(v.Values) == 0 || len(v.Refused) == 0 || len(v.Rows) == 0 || len(v.Digests) == 0 {
		t.Fatal("a section of the vectors is empty")
	}
	covered := map[Type]bool{}
	for _, c := range v.Values {
		covered[c.Type] = true
		got, err := AppendValue(nil, c.Type, native(t, c.Type, c.Input))
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		if string(got) != c.Output {
			t.Errorf("%s: %s, want %s", c.Name, got, c.Output)
		}
	}
	for _, typ := range Types {
		if !covered[typ] {
			t.Errorf("no vector for %s", typ)
		}
	}
	for _, c := range v.Refused {
		if _, err := AppendValue(nil, c.Type, native(t, c.Type, c.Input)); err == nil {
			t.Errorf("%s: accepted", c.Name)
		}
	}
	for _, c := range v.Rows {
		values := make([]any, len(c.Inputs))
		for i, in := range c.Inputs {
			values[i] = native(t, c.Types[i], in)
		}
		got, err := AppendRow(nil, c.Types, values)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
		} else if string(got) != c.Output {
			t.Errorf("%s: %s, want %s", c.Name, got, c.Output)
		}
	}
	for _, c := range v.Digests {
		p, err := hex.DecodeString(c.Plaintext)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DigestInput(c.Class, c.IDs, p)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
		} else if string(got) != c.Output {
			t.Errorf("%s: %s, want %s", c.Name, got, c.Output)
		}
	}
}

// The cases only Go's input can hold: bytes that are not UTF-8, and the
// SQLite forms of booleans and text[].
func TestGoOnlyInputs(t *testing.T) {
	for _, c := range []struct {
		name string
		typ  Type
		v    any
	}{
		{"text, not UTF-8", Text, "a\xffb"},
		{"text, a lone surrogate in WTF-8", Text, "a\xed\xa0\x80"},
		{"text[], an escaped lone surrogate", TextArray, `["\ud800"]`},
		{"text[], not an array", TextArray, `{"a":"b"}`},
		{"boolean 2", Boolean, int64(2)},
		{"text given an int", Text, int64(1)},
		{"bytea given a string", Bytea, "00"},
		{"digest class not UTF-8", Text, "\xff"},
	} {
		if _, err := AppendValue(nil, c.typ, c.v); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	if _, err := AppendValue(nil, Type("smallint"), nil); err == nil {
		t.Error("SQL NULL of a type the encoding does not define was accepted")
	}
	if _, err := DigestInput("value", map[string]string{"id": "\xff"}, nil); err == nil {
		t.Error("a digest id that is not UTF-8 was accepted")
	}
	got, err := AppendValue(nil, Boolean, int64(1))
	if err != nil || string(got) != "1" {
		t.Errorf("SQLite's boolean 1: %s %v", got, err)
	}
	got, err = AppendValue(nil, TextArray, []any{"a", nil})
	if err != nil || string(got) != `["a",null]` {
		t.Errorf("text[] as elements: %s %v", got, err)
	}
	got, err = AppendRow(nil, []Type{Text}, []any{"a", "b"})
	if err == nil {
		t.Errorf("a row with more values than types: %s", got)
	}
}
