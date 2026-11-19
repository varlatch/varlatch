// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The hook vectors (../../testdata/vectors/hook.json), written by
// apps/cli/test/go-vectors-hook.test.ts from hook.ts itself: every event of
// agents-hook.test.ts and agents-guardrails.test.ts, and a command for each
// option of another program the hook reads, with the answer's exact bytes.
const hookVectors = "../../testdata/vectors/hook.json"

type envMap map[string]string

func (m envMap) LookupEnv(key string) (string, bool) { v, ok := m[key]; return v, ok }

// TestHookVectors: RunHook gives every recorded event the same answer, byte
// for byte: the same denial, or none.
func TestHookVectors(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("the project cases need git")
	}
	data, err := os.ReadFile(hookVectors)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	cases, _ := parsed.(jsjson.Object).Value("cases").([]any)
	if len(cases) < 1000 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, raw := range cases {
		c := raw.(jsjson.Object)
		id := jsjson.String(c.Value("id"))
		env := envMap{}
		for _, m := range c.Value("env").(jsjson.Object) {
			env[m.Key] = jsjson.String(m.Value)
		}
		stdin, cwd := jsjson.String(c.Value("stdin")), jsjson.String(c.Value("cwd"))
		if nest, ok := c.Value("nest").(float64); ok {
			stdin = strings.ReplaceAll(stdin, `"{{nest}}"`, strings.Repeat("[", int(nest))+strings.Repeat("]", int(nest)))
		}
		dir := ""
		if cwd == "{{dir}}" {
			dir = project(t, c)
			stdin, cwd = strings.ReplaceAll(stdin, "{{dir}}", dir), dir
		}
		got, err := RunHook(jsjson.String(c.Value("format")), stdin, env, cwd)
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		if dir != "" {
			got = strings.ReplaceAll(got, dir, "{{dir}}")
		}
		if want := jsjson.String(c.Value("expect")); got != want {
			t.Errorf("%s: stdin %q\n got %q\nwant %q", id, jsjson.String(c.Value("stdin")), got, want)
		}
	}
}

// project makes a case's project: its directories, its files, and git.
func project(t *testing.T, c jsjson.Object) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if dirs, ok := c.Value("dirs").([]any); ok {
		for _, d := range dirs {
			if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(d.(string))), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	if files, ok := c.Value("files").(jsjson.Object); ok {
		for _, f := range files {
			p := filepath.Join(dir, filepath.FromSlash(f.Key))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(jsjson.String(f.Value)), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if c.Value("git") == true {
		run := func(args ...string) {
			cmd := exec.Command("git", args...)
			cmd.Dir = dir
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v\n%s", args, err, out)
			}
		}
		run("init", "-q")
		if add, ok := c.Value("gitAdd").([]any); ok {
			for _, f := range add {
				run("add", "-f", f.(string))
			}
		}
	}
	return dir
}
