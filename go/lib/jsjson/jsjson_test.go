// SPDX-License-Identifier: Apache-2.0

package jsjson

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
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

func nested(depth int, inner string) []byte {
	return []byte(strings.Repeat(`{"a":[`, depth/2) + inner + strings.Repeat(`]}`, depth/2))
}

// TestDepth: Parse refuses nesting past MaxDepth; ParseDeep reads any
// depth, without recursion, and refuses the same malformed text.
func TestDepth(t *testing.T) {
	if _, err := Parse(nested(MaxDepth, "1")); err != nil {
		t.Fatalf("Parse at MaxDepth: %v", err)
	}
	if _, err := Parse(nested(MaxDepth+2, "1")); err == nil {
		t.Fatal("Parse past MaxDepth: no error")
	}
	for _, depth := range []int{10_002, 100_000, 1_000_000} {
		v, err := ParseDeep(nested(depth, `"x"`))
		if err != nil {
			t.Fatalf("ParseDeep %d: %v", depth, err)
		}
		for range depth / 2 {
			v = v.(Object).Value("a").([]any)[0]
		}
		if v != "x" {
			t.Fatalf("ParseDeep %d: innermost %v", depth, v)
		}
	}
	for _, bad := range []string{`[`, `[1,]`, `{"a":1,}`, `{"a"}`, `[1 2]`, `{"a":[1}`, `[{"a":1]`, `[1]]`, `{,}`, `[,1]`} {
		if _, err := ParseDeep([]byte(bad)); err == nil {
			t.Errorf("ParseDeep(%s): no error", bad)
		}
	}
}

// TestManyKeys: reading an object with many keys takes linear time, and
// keeps JavaScript's order: array indexes first, a repeated key in its
// first place with its last value.
func TestManyKeys(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"z":0`)
	for i := range 200_000 {
		fmt.Fprintf(&b, `,"k%d":%d,"%d":%d`, i, i, 200_000-i, i)
	}
	b.WriteString(`,"z":1}`)
	start := time.Now()
	v, err := Parse([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 2*time.Second*raceSlowdown {
		t.Fatalf("400k keys took %v", took)
	}
	o := v.(Object)
	if len(o) != 400_001 || o[0].Key != "1" || o[199_999].Key != "200000" || o[200_000].Key != "z" || o[200_000].Value != 1.0 || o[200_001].Key != "k0" {
		t.Fatalf("order: %d members, %v %v %v %v", len(o), o[0], o[199_999], o[200_000], o[200_001])
	}
	small, _ := Parse([]byte(`{"b":1,"2":2,"a":3,"1":4,"b":5}`))
	if got := string(Stringify(small)); got != `{"1":4,"2":2,"b":5,"a":3}` {
		t.Fatalf("small: %s", got)
	}
}
