// SPDX-License-Identifier: Apache-2.0

package transcript

import (
	"slices"
	"testing"
)

// TestSkillOrderFree: only runs of skill-file entries are reordered, as a
// multiset; every other line, entry and byte keeps its place, and a JSON
// document in another form is compared as text.
func TestSkillOrderFree(t *testing.T) {
	a := "created AGENTS.md\ncreated .agents/skills/varlatch/references/run.md\ncreated .agents/skills/varlatch/SKILL.md\nNote: x\n"
	b := "created AGENTS.md\ncreated .agents/skills/varlatch/SKILL.md\ncreated .agents/skills/varlatch/references/run.md\nNote: x\n"
	if SkillOrderFree(a) != SkillOrderFree(b) {
		t.Fatal("text runs not compared as a multiset")
	}
	for _, other := range []string{
		"created .agents/skills/varlatch/SKILL.md\ncreated AGENTS.md\ncreated .agents/skills/varlatch/references/run.md\nNote: x\n", // a line moved out of its run
		"created AGENTS.md\ncreated .agents/skills/varlatch/SKILL.md\nNote: x\n",                                                    // a line dropped
		"created AGENTS.md\ncreated .agents/skills/varlatch/SKILL.md\ncreated .agents/skills/varlatch/references/run.md\nNote: y\n", // another line
	} {
		if SkillOrderFree(a) == SkillOrderFree(other) {
			t.Errorf("accepted %q", other)
		}
	}
	j := "{\n  \"changes\": [\n    {\n      \"path\": \".claude/skills/varlatch/references/run.md\",\n      \"action\": \"remove\"\n    },\n    {\n      \"path\": \".claude/skills/varlatch/SKILL.md\",\n      \"action\": \"remove\"\n    },\n    {\n      \"path\": \"AGENTS.md\",\n      \"action\": \"update\"\n    }\n  ]\n}\n"
	k := "{\n  \"changes\": [\n    {\n      \"path\": \".claude/skills/varlatch/SKILL.md\",\n      \"action\": \"remove\"\n    },\n    {\n      \"path\": \".claude/skills/varlatch/references/run.md\",\n      \"action\": \"remove\"\n    },\n    {\n      \"path\": \"AGENTS.md\",\n      \"action\": \"update\"\n    }\n  ]\n}\n"
	if SkillOrderFree(j) != SkillOrderFree(k) || SkillOrderFree(j) != k {
		t.Fatalf("JSON runs: %q", SkillOrderFree(j))
	}
	// Compact JSON is not JSON.stringify(doc, null, 2)'s form: compared as text.
	if compact := `{"changes":[{"path":".agents/skills/varlatch/references/run.md"},{"path":".agents/skills/varlatch/SKILL.md"}]}`; SkillOrderFree(compact) != compact {
		t.Fatal("rewrote JSON of another form")
	}
	if got := SortSkillRuns([]string{"x", ".agents/skills/varlatch/b", ".agents/skills/varlatch/a", "y", ".claude/skills/varlatch/d", ".claude/skills/varlatch/c"}, NamesSkillFile, func(s string) string { return s }); !slices.Equal(got, []string{"x", ".agents/skills/varlatch/a", ".agents/skills/varlatch/b", "y", ".claude/skills/varlatch/c", ".claude/skills/varlatch/d"}) {
		t.Fatalf("runs %q", got)
	}
}
