// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

// TestAgentsEchoesMaskTheirValue: a guide topic or a coding agent name the
// CLI echoes in a usage error is masked as one value, and one that holds
// an at-sign comes before its explanation, so the fail-safe keeps the
// explanation; a plain value keeps the TypeScript CLI's wording.
func TestAgentsEchoesMaskTheirValue(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"agents", "guide", "https://u:PW@host.example"}, "varlatch agents guide:[redacted]@host.example: no such guide topic; topics: setup, run, agent-run, self-hosting, contract\n"},
		{[]string{"agents", "guide", "nosuch"}, "varlatch agents guide: no guide topic nosuch; topics: setup, run, agent-run, self-hosting, contract\n"},
		{[]string{"agents", "install", "--check", "--agent", "https://u:PW@host.example"}, "varlatch agents install:[redacted]@host.example: unknown coding agent; known: "},
		{[]string{"agents", "install", "--check", "--agent", "nosuch"}, "varlatch agents install: unknown coding agent nosuch; known: "},
	} {
		var stdout, stderr strings.Builder
		code := Main(c.args, MapEnv{"HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir()}, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
		if code != ExitUsage || stdout.String() != "" || !strings.HasPrefix(stderr.String(), c.want) || strings.Contains(stderr.String(), "PW") {
			t.Errorf("%v: exit %d, stderr %q; want 64 and %q", c.args, code, stderr.String(), c.want)
		}
	}
}
