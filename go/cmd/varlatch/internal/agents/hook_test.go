// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// TestHookReadsEveryCommandAlike: a command named like a property every
// JavaScript object has (toString, constructor, valueOf, __proto__), or a
// glob with a class that is no regular expression, is read like any other
// word: the rest of the command line is still checked, so `cat .env`
// after it is denied (go/README.md, "The guardrail hook reads every
// command alike").
func TestHookReadsEveryCommandAlike(t *testing.T) {
	env := envMap{"HOME": "/home/dev", "XDG_CONFIG_HOME": "/home/dev/.xdg"}
	for _, command := range []string{
		"toString x; cat .env",
		"constructor x && cat .env",
		"valueOf -e x; cat .env",
		"__proto__ x; cat .env",
		"hasOwnProperty -c x | cat .env",
		"cat '[z-a]' .env",
		"cat [z-a]; cat .env",
	} {
		event := `{"cwd":"/work/app","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":` + quote(command) + `}}`
		got, err := RunHook("claude", event, env, "/")
		if err != nil || !strings.Contains(got, ".env files are off limits") {
			t.Errorf("%q: %q, %v; want the .env denial", command, got, err)
		}
	}
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func TestLexShell(t *testing.T) {
	l := lexShell(`A=1 cat 'my file' "x y" < in.txt > out.txt 2>&1 && echo $(date) | tee -a log; ls`)
	var words []string
	for _, s := range l.segments {
		words = append(words, strings.Join(s.words, ","))
	}
	if got := strings.Join(words, " | "); got != "A=1,cat,my file,x y | echo,$SUBST | tee,-a,log | ls" {
		t.Errorf("words %q", got)
	}
	if got := l.segments[0]; strings.Join(got.inputs, ",") != "in.txt" || strings.Join(got.outputs, ",") != "out.txt" {
		t.Errorf("inputs %q, outputs %q", got.inputs, got.outputs)
	}
	if strings.Join(l.nested, ",") != "date" {
		t.Errorf("nested %q", l.nested)
	}
	if got := lexShell("cat <<EOF >x\ncat .env\nEOF\nls # cat .env").segments; len(got) != 2 || got[0].words[0] != "cat" || got[1].words[0] != "ls" {
		t.Errorf("heredoc and comment: %+v", got)
	}
	if got := lexShell(`grep "\.env" "a\$b" "c\"d"`).segments[0].words; strings.Join(got, "|") != `grep|\.env|a$b|c"d` {
		t.Errorf("double quotes: %q", got)
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

// minSmall is how long the smaller size must take before growth is
// judged, so that the 20 ms of slack never decides.
const minSmall = 50 * time.Millisecond

// timed is one run of f, after a garbage collection.
func timed(f func()) time.Duration {
	runtime.GC()
	began := time.Now()
	f()
	return time.Since(began)
}

// interleaved times small and large three times each, alternately (small,
// large, small, large, ...), each after a garbage collection, and gives the
// fastest of each, after one untimed run of small: noise only ever adds
// time, and a runner's CPU that is still cold or clocking up slows the
// first runs, so neither size's runs all come before the other's.
func interleaved(small, large func()) (time.Duration, time.Duration) {
	small() // warm up
	var s, l time.Duration
	for i := range 3 {
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
// least minSmall, measured, or 8n would pass limitLarge (which the log
// says): small
// steps keep the larger run, which for quadratic work is 64 times the
// smaller, from overshooting. The log gives the n chosen, each time, and
// the time per operation (ops(n) of them; n when ops is nil) for each
// size: equal for linear work, so a size measured slower per operation
// shows a bias in the measurement.
func growth(t *testing.T, name string, startLarge, limitLarge int, ops func(n int) float64, run func(n int) func()) (small, large time.Duration) {
	t.Helper()
	n := max(startLarge/8, 1)
	capped := false
	for {
		next := n + max(n/2, 1)
		capped = 8*next > limitLarge
		if !capped {
			f := run(n)
			f() // warm up
			if timed(f) < minSmall {
				n = next
				continue
			}
		}
		small, large = interleaved(run(n), run(8*n))
		// The measured smaller run decides: a single run before it can be
		// slower than the work (a cold CPU).
		if small >= minSmall || capped {
			break
		}
		n = next
	}
	note := ""
	if capped && small < minSmall {
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

// TestTheLinearityCriterion: linear growth with noise passes
// growsLinearly, quadratic growth fails it, and so does a deliberately
// quadratic implementation timed the way TestHookLinearTime times the
// hook. The figures are measured (a busy 2026 workstation; eight times the
// input): the linear shapes of TestHookLinearTime grew 4.9 to 13.4 times,
// the quadratic merge 77 to 91 times. CI's runners blur quadratic growth:
// on Windows the merge grew 10.0 times for four times the input (110 ms to
// 1.10 s), about 32 times for eight at that rate.
func TestTheLinearityCriterion(t *testing.T) {
	ms := time.Millisecond
	for _, c := range []struct {
		small, large time.Duration
		linear       bool
	}{
		{84 * ms, 883 * ms, true},   // keys, 10.5x
		{54 * ms, 720 * ms, true},   // a walk past a long --exclude-dir, 13.4x
		{105 * ms, 762 * ms, true},  // nesting, 7.2x
		{100 * ms, 2400 * ms, true}, // 24x, the limit
		{100 * ms, 2500 * ms, false},
		{110 * ms, 3480 * ms, false}, // Windows CI's quadratic rate, 32x
		{96 * ms, 7398 * ms, false},  // the quadratic merge, 77x
		{85 * ms, 7695 * ms, false},  // 91x
	} {
		if growsLinearly(c.small, c.large) != c.linear {
			t.Errorf("%v then %v: judged linear %v", c.small, c.large, !c.linear)
		}
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
	// Sized until its smaller run takes minSmall, so its growth, not the
	// 20 ms slack, decides; the larger run is capped at 320,000 items.
	small, large := growth(t, "a quadratic merge", 40_000, 320_000, func(n int) float64 { return float64(n) * float64(n-1) / 2 }, quadratic)
	if growsLinearly(small, large) {
		t.Errorf("a quadratic merge (%v then %v) was judged linear", small, large)
	}
}

// TestHookLinearTime: the hook reads a long word in every shape, an
// object with many keys, a deeply nested event and a search past a long
// filter in time linear in the input, by growsLinearly: each size timed as
// the fastest of three, interleaved with the other size's after a warm-up
// run (growth), the smaller sized until it takes minSmall, the larger
// eight times its size. No absolute time bound: a slow runner is not a
// failure. Every run still decides: `cat .env` after a long word is
// denied, and so is a search past a long filter. Globs are compiled afresh
// in each run, as each run of the hook is a process of its own.
func TestHookLinearTime(t *testing.T) {
	env := envMap{"HOME": "/home/dev", "XDG_CONFIG_HOME": "/home/dev/.xdg"}
	event := func(command, padding string) string {
		return `{"cwd":"/work/app","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{` + padding + `"command":` + quote(command) + `}}`
	}
	keys := func(n int) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, `"k%d":%d,`, i, i)
		}
		return b.String()
	}
	// A search's filters are tried on every entry of its walk.
	dir := t.TempDir()
	for i := range 3000 {
		sub := filepath.Join(dir, fmt.Sprintf("d%d", i%30))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "d29", ".env.local"), []byte("KEY=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	walk := func(options string) string {
		return `{"cwd":` + quote(dir) + `,"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":` + quote("grep -r "+options+" KEY .") + `}}`
	}
	a := func(n int) string { return strings.Repeat("a", n) }
	cases := []struct {
		name       string
		event      func(n int) string // an event whose size grows with n
		start, max int                // the larger size to start from, and its limit
	}{
		{"plain word", func(n int) string { return event("cat "+a(n)+" .env", "") }, 1600 * 1024, 32 << 20},
		{"single-quoted word", func(n int) string { return event("cat '"+a(n)+"' .env", "") }, 1600 * 1024, 32 << 20},
		{"double-quoted word", func(n int) string { return event(`cat "`+a(n)+`" .env`, "") }, 1600 * 1024, 32 << 20},
		{"escaped word", func(n int) string { return event("cat "+strings.Repeat(`\a`, n/2)+" .env", "") }, 1600 * 1024, 32 << 20},
		{"non-ASCII word", func(n int) string { return event("cat "+strings.Repeat("é", n/2)+" .env", "") }, 1600 * 1024, 32 << 20},
		{"option cluster", func(n int) string { return event("grep -"+a(n)+" x .env", "") }, 1600 * 1024, 32 << 20},
		{"glob", func(n int) string { return event("cat "+a(n)+"* .env", "") }, 1600 * 1024, 32 << 20},
		{"dot-leading glob", func(n int) string { return event("cat ."+a(n)+"* .env", "") }, 1600 * 1024, 32 << 20},
		{"keys", func(n int) string { return event("cat .env", keys(n)) }, 200_000, 4 << 20},
		{"keys at the top", func(n int) string { return `{` + keys(n) + event("cat .env", "")[1:] }, 200_000, 4 << 20},
		{"nesting", func(n int) string {
			return event("cat .env", `"p":`+strings.Repeat("[", n)+strings.Repeat("]", n)+`,`)
		}, 100_000, 4 << 20},
		{"walk, long --exclude-dir", func(n int) string { return walk("--exclude-dir=." + a(n) + "*") }, 1600 * 1024, 32 << 20},
		{"walk, long --exclude", func(n int) string { return walk("--exclude=." + a(n) + "*") }, 1600 * 1024, 32 << 20},
		{"walk, long --include", func(n int) string { return walk("--include=." + a(n) + "* --include=.env*") }, 1600 * 1024, 32 << 20},
	}
	for _, c := range cases {
		run := func(n int) func() {
			e := c.event(n)
			return func() {
				globCache.Lock() // each run of the hook is a process of its own
				clear(globCache.m)
				globCache.Unlock()
				got, err := RunHook("claude", e, env, "/")
				if err != nil || !strings.Contains(got, `"permissionDecision":"deny"`) {
					t.Fatalf("%s: %.200q, %v; want a denial", c.name, got, err)
				}
			}
		}
		small, large := growth(t, c.name, c.start, c.max, nil, run)
		if !growsLinearly(small, large) {
			t.Errorf("%s: %v, then %v at eight times the size: not linear", c.name, small, large)
		}
	}
}

// TestHookNonASCIIWords: a word's bytes are kept whole, so a path with an
// accented or CJK name is the path on disk.
func TestHookNonASCIIWords(t *testing.T) {
	l := lexShell(`cat café/.env-old "日本/x" '日本' \é "a\é" ${HOME}é`)
	want := []string{"cat", "café/.env-old", "日本/x", "日本", "é", `a\é`, "${HOME}é"}
	if got := l.segments[0].words; !slices.Equal(got, want) {
		t.Fatalf("words %q, want %q", got, want)
	}
	options, operands := parseArgs([]string{"-éA3", "-日n", "x"}, setOf("-A"))
	if len(options) != 4 || options[0].name != "-é" || options[1].name != "-A" || *options[1].value != "3" || options[2].name != "-日" || len(operands) != 1 {
		t.Fatalf("parseArgs: %v %v", options, operands)
	}
}

// TestHookStricterReadings: where RE2 reads a glob or a name more widely
// than a JavaScript regular expression would, the hook denies (go/README.md,
// "Hook globs are RE2 classes" and "A name ending in a line break after
// `.env.`").
func TestHookStricterReadings(t *testing.T) {
	env := envMap{"HOME": "/home/dev", "XDG_CONFIG_HOME": "/home/dev/.xdg"}
	for _, command := range []string{"cat .e[[:alpha:]]v", "cat '.env.\r'", "cat '.env. '", "cat '.env. '"} {
		event := `{"cwd":"/work/app","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":` + string(jsjson.Stringify(command)) + `}}`
		got, err := RunHook("claude", event, env, "/")
		if err != nil || !strings.Contains(got, ".env files are off limits") {
			t.Errorf("%q: %q, %v; want the .env denial", command, got, err)
		}
	}
}
