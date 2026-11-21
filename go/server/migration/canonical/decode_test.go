// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every value and row the shared vectors write decodes, and is written
// again to the same bytes: the decoder is the encoder's inverse on
// canonical input.
func TestDecodeReadsBackEveryVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Values []struct {
			Name   string `json:"name"`
			Type   Type   `json:"type"`
			Output string `json:"output"`
		} `json:"values"`
		Rows []struct {
			Name   string `json:"name"`
			Types  []Type `json:"types"`
			Output string `json:"output"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Values {
		row := "[" + c.Output + "]"
		if _, err := DecodeRow([]Type{c.Type}, []byte(row)); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
	}
	for _, c := range v.Rows {
		values, err := DecodeRow(c.Types, []byte(c.Output))
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		again, err := AppendRow(nil, c.Types, values)
		if err != nil || string(again) != c.Output {
			t.Errorf("%s: written again %s, %v", c.Name, again, err)
		}
	}
	if len(v.Values) == 0 || len(v.Rows) == 0 {
		t.Fatal("no vectors")
	}
}

// The forms the decoder gives are the ones varlatchd writes to SQLite.
func TestDecodeForms(t *testing.T) {
	types := []Type{Text, Bigint, Boolean, Jsonb, Bytea, Timestamptz, TextArray, Integer}
	values, err := DecodeRow(types, []byte(`["id_1",42,1,"{\"k\":[1,2]}","AA==",1700000000000001,["x",null],-7]`))
	if err != nil {
		t.Fatal(err)
	}
	if values[0] != "id_1" || values[1] != int64(42) || values[2] != int64(1) || values[3] != `{"k":[1,2]}` ||
		string(values[4].([]byte)) != "\x00" || values[5] != int64(1700000000000001) || values[6] != `["x",null]` || values[7] != int64(-7) {
		t.Fatalf("%#v", values)
	}
	if values, err := DecodeRow([]Type{Text, Bytea}, []byte(`[null,null]`)); err != nil || values[0] != nil || values[1] != nil {
		t.Fatalf("nulls: %#v %v", values, err)
	}
}

// What is not canonical is refused, never normalized.
func TestDecodeRefusesWhatIsNotCanonical(t *testing.T) {
	for _, c := range []struct {
		name  string
		types []Type
		row   string
		why   string
	}{
		{"a space between values", []Type{Text, Bigint}, `["a", 1]`, "not in canonical form"},
		{"jsonb with PostgreSQL's spaces", []Type{Jsonb}, `["{\"a\": 1}"]`, "not in canonical form"},
		{"jsonb out of jsonb's key order", []Type{Jsonb}, `["{\"bb\":1,\"a\":2}"]`, "not in canonical form"},
		{"jsonb that is not JSON", []Type{Jsonb}, `["{"]`, "jsonb"},
		{"base64 without padding", []Type{Bytea}, `["AA"]`, "base64"},
		{"base64 of another alphabet", []Type{Bytea}, `["-_8="]`, "base64"},
		{"an integer with a leading zero", []Type{Bigint}, `[042]`, "row that is not a JSON array"},
		{"an integer as a string", []Type{Bigint}, `["42"]`, "not a decimal integer"},
		{"an integer past 32 bits", []Type{Integer}, `[2147483648]`, "32 bits"},
		{"a boolean as true", []Type{Boolean}, `[true]`, "not a decimal integer"},
		{"a boolean of 2", []Type{Boolean}, `[2]`, "neither 0 nor 1"},
		{"a text as a number", []Type{Text}, `[1]`, "not a JSON string"},
		{"an escape JSON.stringify does not write", []Type{Text}, `["\u0041"]`, "not in canonical form"},
		{"a nested text[]", []Type{TextArray}, `[["a",["b"]]]`, "not a string or null"},
		{"too few values", []Type{Text, Text}, `["a"]`, "1 values for 2 columns"},
		{"not an array", []Type{Text}, `{"a":1}`, "not a JSON array"},
		{"text after the row", []Type{Text}, `["a"] ["b"]`, "text after the row"},
		{"a type the encoding does not define", []Type{"numeric"}, `[1]`, "does not define"},
	} {
		if _, err := DecodeRow(c.types, []byte(c.row)); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v, want %q", c.name, err, c.why)
		}
	}
}
