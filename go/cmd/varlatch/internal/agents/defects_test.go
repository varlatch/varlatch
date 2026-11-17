// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"errors"
	"os"
	"testing"
)

// TestPrototypeNamesAreUnknown: the TypeScript CLI looks coding agents and
// guide topics up in plain objects (install.ts's AGENTS, skill.ts's
// GUIDE_TOPICS), so a name of an Object.prototype member passes as known:
// `agents install --agent constructor` installs and prints "constructor
// reads undefined", `--agent toString --mcp` and `agents guide constructor`
// throw a TypeError (go/README.md, "Known TypeScript defects"). The Go CLI
// refuses them as unknown, as any other name it does not have.
func TestPrototypeNamesAreUnknown(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"constructor", "toString", "__proto__", "hasOwnProperty", "valueOf", "isPrototypeOf"} {
		_, err := RunInstall(Options{Scope: "project", Root: root, Version: "1", Agents: []string{name}, Mode: "install", MCP: true, Guardrails: true})
		var e *Error
		if !errors.As(err, &e) || !e.Usage || e.Message[:len("unknown coding agent "+name)] != "unknown coding agent "+name {
			t.Errorf("--agent %s: %v, want unknown coding agent", name, err)
		}
		_, err = Guide(name, true)
		var g *GuideTopicError
		if !errors.As(err, &g) {
			t.Errorf("guide %s: %v, want no guide topic", name, err)
		}
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Errorf("a refused run wrote %d entries", len(entries))
	}
}
