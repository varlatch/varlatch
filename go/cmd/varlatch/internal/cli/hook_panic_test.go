// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
)

// TestHookPanicIsNoDecision: a panic inside the hook is no decision, with
// status 0 and a warning, as hook.ts's caller treats a throw.
func TestHookPanicIsNoDecision(t *testing.T) {
	saved := hookRunner
	t.Cleanup(func() { hookRunner = saved })
	hookRunner = func(string, string, clientctx.Env, string) (string, error) {
		var m map[string]int
		m["x"]++ // a runtime panic
		return "never", nil
	}
	var stdout, stderr bytes.Buffer
	event := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat .env"}}`
	code := Main([]string{"agents", "hook", "--format", "claude"}, MapEnv{"HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir()},
		IO{Stdin: strings.NewReader(event), Stdout: &stdout, Stderr: &stderr})
	if code != 0 || stdout.Len() != 0 {
		t.Fatalf("status %d, stdout %q", code, stdout.String())
	}
	if got := stderr.String(); !strings.HasPrefix(got, "varlatch agents hook: ") || !strings.HasSuffix(got, "; no decision\n") {
		t.Fatalf("stderr %q", got)
	}
}
