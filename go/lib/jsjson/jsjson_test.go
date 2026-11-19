// SPDX-License-Identifier: Apache-2.0

package jsjson

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
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

// bestOf3 is the fastest of three runs of f, each after a garbage
// collection: noise only ever adds time.
func bestOf3(f func()) time.Duration {
	var fastest time.Duration
	for i := range 3 {
		runtime.GC()
		start := time.Now()
		f()
		if took := time.Since(start); i == 0 || took < fastest {
			fastest = took
		}
	}
	return fastest
}

// growsLinearly: for an input four times as large, at most tenfold the
// time (linear is about fourfold, quadratic sixteenfold), with 20 ms of
// slack for jitter; never an absolute bound.
func growsLinearly(small, large time.Duration) bool {
	return large <= 10*small+20*time.Millisecond
}

func manyKeys(n int) []byte {
	var b strings.Builder
	b.WriteString(`{"z":0`)
	for i := range n {
		fmt.Fprintf(&b, `,"k%d":%d,"%d":%d`, i, i, n-i, i)
	}
	b.WriteString(`,"z":1}`)
	return []byte(b.String())
}

// TestManyKeys: reading an object with many keys keeps JavaScript's order
// (array indexes first, a repeated key in its first place with its last
// value), and takes time linear in the keys (growsLinearly, each size the
// best of three runs; no absolute time bound); the criterion fails a
// deliberately quadratic merge.
func TestManyKeys(t *testing.T) {
	v, err := Parse(manyKeys(200_000))
	if err != nil {
		t.Fatal(err)
	}
	o := v.(Object)
	if len(o) != 400_001 || o[0].Key != "1" || o[199_999].Key != "200000" || o[200_000].Key != "z" || o[200_000].Value != 1.0 || o[200_001].Key != "k0" {
		t.Fatalf("order: %d members, %v %v %v %v", len(o), o[0], o[199_999], o[200_000], o[200_001])
	}
	small, _ := Parse([]byte(`{"b":1,"2":2,"a":3,"1":4,"b":5}`))
	if got := string(Stringify(small)); got != `{"1":4,"2":2,"b":5,"a":3}` {
		t.Fatalf("small: %s", got)
	}

	n := 50_000
	if raceSlowdown > 1 {
		n /= 4
	}
	parse := func(text []byte) func() {
		return func() {
			if _, err := Parse(text); err != nil {
				t.Fatal(err)
			}
		}
	}
	a, b := manyKeys(n), manyKeys(4*n)
	parse(manyKeys(n / 4))() // warm up
	fast, slow := bestOf3(parse(a)), bestOf3(parse(b))
	t.Logf("%d keys %v, %d keys %v (%.1fx)", 2*n, fast, 8*n, slow, float64(slow)/float64(fast))
	if !growsLinearly(fast, slow) {
		t.Errorf("%d keys %v, %d keys %v: not linear", 2*n, fast, 8*n, slow)
	}
	// A merge that walks everything it holds for each new item: quadratic
	// work with no constant cost to blur its growth.
	quadratic := func(n int) func() {
		return func() {
			var held []int
			sum := 0
			for i := range n {
				for _, h := range held {
					sum += h
				}
				held = append(held, i)
			}
			if sum < 0 {
				t.Log(sum)
			}
		}
	}
	// Large enough that its growth, not the 20 ms slack, decides (the race
	// detector only makes it slower, which helps).
	n = 10_000
	qSmall, qLarge := bestOf3(quadratic(n)), bestOf3(quadratic(4*n))
	t.Logf("a quadratic merge: %d items %v, %d items %v (%.1fx)", n, qSmall, 4*n, qLarge, float64(qLarge)/float64(qSmall))
	if growsLinearly(qSmall, qLarge) {
		t.Errorf("a quadratic merge (%v then %v) was judged linear", qSmall, qLarge)
	}
}
