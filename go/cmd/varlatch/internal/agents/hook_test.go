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

// bestOf3 is the fastest of three runs of f, each after a garbage
// collection: noise (a shared runner's pauses, another job's load) only
// ever adds time, so the minimum is the closest to the work itself.
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

// growsLinearly is the timing tests' criterion: for an input four times as
// large, the time may grow at most tenfold. Linear work grows about
// fourfold and quadratic about sixteenfold, so the limit separates them
// with room for noise on either side; it judges growth only, never a
// machine's absolute speed. 20 ms of slack keeps a shape that takes a few
// milliseconds from failing on jitter.
func growsLinearly(small, large time.Duration) bool {
	return large <= 10*small+20*time.Millisecond
}

// TestTheLinearityCriterion: linear growth with noise passes
// growsLinearly, quadratic growth fails it, and so does a deliberately
// quadratic implementation timed the way TestHookLinearTime times the
// hook.
func TestTheLinearityCriterion(t *testing.T) {
	ms := time.Millisecond
	for _, c := range []struct {
		small, large time.Duration
		linear       bool
	}{
		{630 * ms, 4190 * ms, true},
		{200 * ms, 900 * ms, true},
		{1060 * ms, 3310 * ms, true},
		{250 * ms, 4000 * ms, false},
		{1000 * ms, 16000 * ms, false},
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
	// Large enough that its growth, not the 20 ms slack, decides (the race
	// detector only makes it slower, which helps).
	n := 10_000
	small, large := bestOf3(quadratic(n)), bestOf3(quadratic(4*n))
	t.Logf("a quadratic merge: %d items %v, %d items %v (%.1fx)", n, small, 4*n, large, float64(large)/float64(small))
	if growsLinearly(small, large) {
		t.Errorf("a quadratic merge (%v then %v) was judged linear", small, large)
	}
}

// TestHookLinearTime: the hook reads a long word in every shape, an
// object with many keys, a deeply nested event and a search past a long
// filter in time linear in the input, by growsLinearly: each size timed as
// the best of three runs (bestOf3), the largest 1.6 MB. No absolute time
// bound: a slow runner is not a failure. Every run still decides: `cat
// .env` after a long word is denied, and so is a search past a long
// filter. Globs are compiled afresh in each run, as each run of the hook
// is a process of its own. Under the race detector the inputs are a
// quarter the size.
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
		name  string
		event func(n int) string // an event whose size grows with n
		unit  int                // n for the smaller size
	}{
		{"plain word", func(n int) string { return event("cat "+a(n)+" .env", "") }, 400 * 1024},
		{"single-quoted word", func(n int) string { return event("cat '"+a(n)+"' .env", "") }, 400 * 1024},
		{"double-quoted word", func(n int) string { return event(`cat "`+a(n)+`" .env`, "") }, 400 * 1024},
		{"escaped word", func(n int) string { return event("cat "+strings.Repeat(`\a`, n/2)+" .env", "") }, 400 * 1024},
		{"non-ASCII word", func(n int) string { return event("cat "+strings.Repeat("é", n/2)+" .env", "") }, 400 * 1024},
		{"option cluster", func(n int) string { return event("grep -"+a(n)+" x .env", "") }, 400 * 1024},
		{"glob", func(n int) string { return event("cat "+a(n)+"* .env", "") }, 400 * 1024},
		{"dot-leading glob", func(n int) string { return event("cat ."+a(n)+"* .env", "") }, 400 * 1024},
		{"keys", func(n int) string { return event("cat .env", keys(n)) }, 50_000},
		{"keys at the top", func(n int) string { return `{` + keys(n) + event("cat .env", "")[1:] }, 50_000},
		{"nesting", func(n int) string {
			return event("cat .env", `"p":`+strings.Repeat("[", n)+strings.Repeat("]", n)+`,`)
		}, 25_000},
		{"walk, long --exclude-dir", func(n int) string { return walk("--exclude-dir=." + a(n) + "*") }, 400 * 1024},
		{"walk, long --exclude", func(n int) string { return walk("--exclude=." + a(n) + "*") }, 400 * 1024},
		{"walk, long --include", func(n int) string { return walk("--include=." + a(n) + "* --include=.env*") }, 400 * 1024},
	}
	for _, c := range cases {
		unit := c.unit
		if raceSlowdown > 1 {
			unit /= 4
		}
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
		run(unit / 4)() // warm up
		small, large := bestOf3(run(unit)), bestOf3(run(4*unit))
		t.Logf("%s: %v, then %v at four times the size (%.1fx)", c.name, small, large, float64(large)/float64(small))
		if !growsLinearly(small, large) {
			t.Errorf("%s: %v, then %v at four times the size: not linear", c.name, small, large)
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
