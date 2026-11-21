// SPDX-License-Identifier: Apache-2.0

package jsjson

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
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

// growsLinearly is the timing tests' criterion: for an input eight times
// as large, the time may grow at most 24-fold. Linear work grows about
// eightfold and quadratic about 64-fold (on shared CI runners, which blur
// the growth, about 38-fold), and 24 sits near their geometric middle, so
// the limit separates them with room for noise on either side; it judges
// growth only, never a machine's absolute speed. 20 ms of slack keeps a
// shape that takes a few milliseconds from failing on jitter.
func growsLinearly(small, large time.Duration) bool {
	return large <= 24*small+20*time.Millisecond
}

// minSmall is how long a real shape's smaller run must take before its
// growth is judged, so that the 20 ms of slack never decides.
const minSmall = 50 * time.Millisecond

// minControl is the same for the quadratic control: its larger run takes
// about 64 times its smaller (38 on a blurring CI runner), far past
// 24 times plus the slack even from a few milliseconds, and a short
// smaller run keeps the larger one to a fraction of a second.
const minControl = 7 * time.Millisecond

// timed is one run of f, after a garbage collection and with the
// collector off while it runs: a collection's pause landing in one run and
// not the other is the noise that made a linear shape look 26 times slower
// at eight times the size once (macOS CI, 2026-11-20).
func timed(f func()) time.Duration {
	runtime.GC()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	began := time.Now()
	f()
	return time.Since(began)
}

// interleaved times small and large five times each, alternately (small,
// large, small, large, ...), each by timed, and gives the fastest of each,
// after one untimed run of small: noise only ever adds time, and a
// runner's CPU that is still cold or clocking up slows the first runs, so
// neither size's runs all come before the other's.
func interleaved(small, large func()) (time.Duration, time.Duration) {
	small() // warm up
	var s, l time.Duration
	for i := range 5 {
		ts := timed(small)
		tl := timed(large)
		if i == 0 || ts < s {
			s = ts
		}
		if i == 0 || tl < l {
			l = tl
		}
	}
	return s, l
}

// growth sizes n and times run(n) and run(8n) by interleaved. n starts at
// an eighth of startLarge and grows by half again until run(n) takes at
// least floor, measured, or 8n would pass limitLarge (which the log
// says): small
// steps keep the larger run, which for quadratic work is 64 times the
// smaller, from overshooting. The log gives the n chosen, each time, and
// the time per operation (ops(n) of them; n when ops is nil) for each
// size: equal for linear work, so a size measured slower per operation
// shows a bias in the measurement.
func growth(t *testing.T, name string, floor time.Duration, startLarge, limitLarge int, ops func(n int) float64, run func(n int) func()) (small, large time.Duration) {
	t.Helper()
	// Under the race detector the work is about raceSlowdown times slower,
	// so the sizing starts that much smaller and reaches the floor sooner.
	n := max(startLarge/8/raceSlowdown, 1)
	capped := false
	for {
		next := n + max(n/2, 1)
		capped = 8*next > limitLarge
		if !capped {
			f := run(n)
			f() // warm up
			// The faster of two probes: one stalled probe never stops the
			// sizing early.
			if min(timed(f), timed(f)) < floor {
				n = next
				continue
			}
		}
		small, large = interleaved(run(n), run(8*n))
		// The measured smaller run decides: a single run before it can be
		// slower than the work (a cold CPU).
		if small >= floor || capped {
			break
		}
		n = next
	}
	note := ""
	if capped && small < floor {
		note = " (at its size limit)"
	}
	if ops == nil {
		ops = func(n int) float64 { return float64(n) }
	}
	perOp := func(d time.Duration, n int) float64 { return float64(d.Nanoseconds()) / ops(n) }
	t.Logf("%s: n=%d %v (%.3g ns/op), n=%d %v (%.3g ns/op): %.1fx%s",
		name, n, small, perOp(small, n), 8*n, large, perOp(large, 8*n), float64(large)/float64(small), note)
	return small, large
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
// value), and takes time linear in the keys (growsLinearly, timed by
// growth: a warm-up, then five runs of each size, interleaved; no
// absolute time bound); the criterion fails a deliberately quadratic merge.
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

	parse := func(n int) func() {
		text := manyKeys(n)
		return func() {
			if _, err := Parse(text); err != nil {
				t.Fatal(err)
			}
		}
	}
	fast, slow := growth(t, "keys (two per n)", minSmall, 200_000, 4<<20, nil, parse)
	if !growsLinearly(fast, slow) {
		t.Errorf("keys: %v, then %v at eight times as many: not linear", fast, slow)
	}
	// A merge that walks everything it holds for each new item: quadratic
	// work with no constant cost to blur its growth; it must fail.
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
	qSmall, qLarge := growth(t, "a quadratic merge", minControl, 8_000, 320_000, func(n int) float64 { return float64(n) * float64(n-1) / 2 }, quadratic)
	if growsLinearly(qSmall, qLarge) {
		t.Errorf("a quadratic merge (%v then %v) was judged linear", qSmall, qLarge)
	}
}
