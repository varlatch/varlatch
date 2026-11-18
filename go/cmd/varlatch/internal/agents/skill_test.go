// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// TestSkillFilesCurrent is the staleness check of the embedded skill:
// skillfiles.gen.go holds apps/cli/skill/varlatch exactly, in the order of
// the TypeScript CLI's own embedded copy (skillFiles.generated.ts), which
// its own test holds to the same source. After editing the skill, run
// `go generate ./cmd/varlatch/internal/agents` in go/.
func TestSkillFilesCurrent(t *testing.T) {
	const source = "../../../../../apps/cli/skill/varlatch"
	onDisk := map[string]string{}
	err := filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(source, path)
		onDisk[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(onDisk) != len(skillFiles) {
		t.Fatalf("stale: the source has %d files, skillfiles.gen.go %d; run go generate", len(onDisk), len(skillFiles))
	}
	for _, f := range skillFiles {
		if onDisk[f.path] != f.content {
			t.Errorf("stale: %s differs from its source; run go generate", f.path)
		}
	}

	ts, err := os.ReadFile("../../../../../apps/cli/src/agents/skillFiles.generated.ts")
	if err != nil {
		t.Fatal(err)
	}
	text := string(ts)
	start := strings.Index(text, "= {") + 2
	end := strings.LastIndex(text, "};")
	module, err := jsjson.Parse([]byte(text[start : end+1]))
	if err != nil {
		t.Fatal(err)
	}
	embedded := module.(jsjson.Object)
	if len(embedded) != len(skillFiles) {
		t.Fatalf("the TypeScript CLI embeds %d files, the Go CLI %d", len(embedded), len(skillFiles))
	}
	for i, m := range embedded {
		if skillFiles[i].path != m.Key || skillFiles[i].content != m.Value {
			t.Errorf("file %d: the TypeScript CLI has %s, the Go CLI %s (or their contents differ)", i, m.Key, skillFiles[i].path)
		}
	}
}
