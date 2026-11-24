// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/agents"
)

// hostCommand is a varlatch command in the skill's self-hosting reference,
// in a block or a code span, however it is run on the host.
var hostCommand = regexp.MustCompile("(?m)(?:^(?:sudo )?|^docker exec <container> |`)varlatch( [^`\n]*)")

// unknownHostCommands are the commands of text whose command, words or
// options the Go CLI's own help does not have.
func unknownHostCommands(text string) (n int, problems []string) {
	for _, m := range hostCommand.FindAllStringSubmatch(text, -1) {
		n++
		words := strings.Fields(m[1])
		if words[0] == "--assisted" {
			words = words[1:]
		}
		// The command's entries in the whole usage, which is this CLI's: each
		// form with its options, without the explanation after it.
		var entries []string
		in := false
		for _, l := range strings.Split(Usage, "\n") {
			f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(l), "sudo "))
			switch {
			case len(f) > 1 && f[0] == "varlatch" && strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "   "):
				if in = f[1] == words[0]; in {
					entries = append(entries, strings.Join(f, " "))
				}
			case len(f) == 0 || strings.HasPrefix(f[0], "("):
				in = false
			case in:
				entries[len(entries)-1] += " " + strings.Join(f, " ")
			}
		}
		if len(entries) == 0 {
			problems = append(problems, fmt.Sprintf("varlatch%s: no command %s", m[1], words[0]))
			continue
		}
		// One entry with its words together and every option it names.
		form, options := []string{"varlatch", words[0]}, []string{}
		for _, w := range words[1:] {
			if strings.HasPrefix(w, "-") {
				options = append(options, w)
			} else {
				form = append(form, w)
			}
		}
		if !slices.ContainsFunc(entries, func(e string) bool {
			f := strings.Fields(e)
			if len(f) < len(form) {
				return false
			}
			for i, w := range form {
				if !slices.Contains(strings.Split(f[i], "|"), w) {
					return false
				}
			}
			for _, o := range options {
				if !regexp.MustCompile(`(^|[\s\[(|])` + regexp.QuoteMeta(o) + `([\s\]|)<=]|$)`).MatchString(e) {
					return false
				}
			}
			return true
		}) {
			problems = append(problems, fmt.Sprintf("varlatch%s: the usage of %s has no such form", m[1], words[0]))
		}
	}
	return n, problems
}

// The skill's self-hosting reference is for a Go installation's host, so
// its commands are checked against this CLI's help (the other references'
// against the TypeScript usage, apps/cli/test/skill.test.ts).
func TestTheSkillsHostCommandsAreThisCLIs(t *testing.T) {
	text, err := agents.Guide("self-hosting", true)
	if err != nil {
		t.Fatal(err)
	}
	n, problems := unknownHostCommands(text)
	if n < 8 {
		t.Errorf("%d commands found", n)
	}
	for _, p := range problems {
		t.Error(p)
	}
	// Controls: each is reported.
	for _, broken := range []string{"varlatch adopt\n", "sudo varlatch setup --dir /srv\n", "varlatch admin backup create\n", "docker exec <container> varlatch doctor --nosuch\n", "see `varlatch migrate --nosuch`", "varlatch admin backup status --json\n"} {
		if n, problems := unknownHostCommands(broken); n != 1 || len(problems) == 0 {
			t.Errorf("%q: %d commands, %v", broken, n, problems)
		}
	}
}
