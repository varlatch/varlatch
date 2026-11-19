// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"strings"
	"testing"
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
