// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"fmt"
	"os"
	"path/filepath"
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

// TestHookLinearTime: the hook reads a long word, an object with many
// keys and a deeply nested event in linear time, well inside the 30
// seconds a coding agent gives it, and still decides: `cat .env` after a
// 1.6 MB word is denied.
func TestHookLinearTime(t *testing.T) {
	env := envMap{"HOME": "/home/dev", "XDG_CONFIG_HOME": "/home/dev/.xdg"}
	const size = 1600 * 1024
	long := strings.Repeat("a", size)
	event := func(command, padding string) string {
		return `{"cwd":"/work/app","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{` + padding + `"command":` + quote(command) + `}}`
	}
	var keys strings.Builder
	for i := range 200_000 {
		fmt.Fprintf(&keys, `"k%d":%d,`, i, i)
	}
	cases := []struct{ name, event string }{
		{"plain word", event("cat "+long+" .env", "")},
		{"single-quoted word", event("cat '"+long+"' .env", "")},
		{"double-quoted word", event(`cat "`+long+`" .env`, "")},
		{"escaped word", event("cat "+strings.Repeat(`\a`, size/2)+" .env", "")},
		{"non-ASCII word", event("cat "+strings.Repeat("é", size/2)+" .env", "")},
		{"option cluster", event("grep -"+long+" x .env", "")},
		{"glob", event("cat "+long+"* .env", "")},
		{"dot-leading glob", event("cat ."+long+"* .env", "")},
		{"dot-leading glob in a search", event("grep -r --include=."+long+"* x . ; cat .env", "")},
		{"200k keys", event("cat .env", keys.String())},
		{"200k keys at the top", `{` + keys.String() + event("cat .env", "")[1:]},
		{"nested 100k deep", event("cat .env", `"p":`+strings.Repeat("[", 100_000)+strings.Repeat("]", 100_000)+`,`)},
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
	cases = append(cases,
		struct{ name, event string }{"walk, long --exclude-dir", walk("--exclude-dir=." + long + "*")},
		struct{ name, event string }{"walk, long --exclude", walk("--exclude=." + long + "*")},
		struct{ name, event string }{"walk, long --include", walk("--include=." + long + "* --include=.env*")},
	)
	for _, c := range cases {
		start := time.Now()
		got, err := RunHook("claude", c.event, env, "/")
		took := time.Since(start)
		if err != nil || !strings.Contains(got, `"permissionDecision":"deny"`) {
			t.Errorf("%s: %q, %v; want a denial", c.name, got, err)
		}
		if took > 2*time.Second*raceSlowdown {
			t.Errorf("%s: took %v", c.name, took)
		}
		t.Logf("%s: %v", c.name, took)
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
