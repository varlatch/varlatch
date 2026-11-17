// SPDX-License-Identifier: Apache-2.0

package jsjson

import (
	"encoding/json"
	"os"
	"testing"
)

// TestTypeScriptVectors holds Parse, Stringify and StringifyIndent to what
// Node.js's JSON.parse and JSON.stringify make of each text
// (testdata/ts-vectors.json, written by apps/cli/test/go-vectors-framework.test.ts).
func TestTypeScriptVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			Text, Compact, Indented, Indented4 string
		}
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range file.Cases {
		v, err := Parse([]byte(c.Text))
		if err != nil {
			t.Errorf("%s: %v", c.Text, err)
			continue
		}
		if got := string(Stringify(v)); got != c.Compact {
			t.Errorf("%s: Stringify %q, want %q", c.Text, got, c.Compact)
		}
		if got := string(StringifyIndent(v, 2)); got != c.Indented {
			t.Errorf("%s: StringifyIndent(2) %q, want %q", c.Text, got, c.Indented)
		}
		if got := string(StringifyIndent(v, 4)); got != c.Indented4 {
			t.Errorf("%s: StringifyIndent(4) %q, want %q", c.Text, got, c.Indented4)
		}
	}
}

func TestStringifyIndentClamps(t *testing.T) {
	v := Object{{"a", []any{1.0}}}
	if got, want := string(StringifyIndent(v, 0)), `{"a":[1]}`; got != want {
		t.Fatalf("0: %q", got)
	}
	if got, want := string(StringifyIndent(v, 20)), string(StringifyIndent(v, 10)); got != want {
		t.Fatalf("20: %q, want %q", got, want)
	}
}
