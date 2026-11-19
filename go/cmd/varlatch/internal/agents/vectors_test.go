// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/transcript"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The agent-file vectors (../../testdata/vectors/agents.json), written by
// apps/cli/test/go-vectors-agents.test.ts from apps/cli/src/agents itself:
// the pure edits, and projects taken through runs of install, check and
// remove for every coding agent, scope and option. The Go port must give
// the same results, lines and trees.

const agentVectors = "../../testdata/vectors/agents.json"

func loadAgentVectors(t *testing.T) jsjson.Object {
	t.Helper()
	data, err := os.ReadFile(agentVectors)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return v.(jsjson.Object)
}

func js(v any) string { return string(jsjson.Stringify(v)) }

// pathBelowDir matches a path below the scenario's directory placeholder:
// a scenario whose recorded steps hold one has a Windows expectation
// (apps/cli/test/goWindows.ts's PATH_BELOW_DIR).
var pathBelowDir = regexp.MustCompile(`\{\{(dir|home)\}\}[/\\]`)

// windowsAgentVectors holds the install scenarios as TypeScript recorded
// them on Windows: those whose Linux recording names a path below the
// directory, which both CLIs join with backslashes there.
const windowsAgentVectors = "../../testdata/vectors/windows/agents.json"

// windowsScenarios is the Windows recording's scenarios by name.
func windowsScenarios(t *testing.T) map[string]jsjson.Object {
	t.Helper()
	data, err := os.ReadFile(windowsAgentVectors)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]jsjson.Object{}
	for _, s := range cases(t, v.(jsjson.Object), "install", 0) {
		out[s.Value("name").(string)] = s
	}
	return out
}

// TestWindowsAgentVectorsComplete: the Windows recording holds exactly the
// scenarios whose Linux recording names a path below the directory, with
// the same setup and steps; checked on every platform, so a scenario that
// needs a Windows expectation and has none fails before Windows runs.
func TestWindowsAgentVectorsComplete(t *testing.T) {
	linux := cases(t, loadAgentVectors(t), "install", 250)
	windows := windowsScenarios(t)
	if v, _ := jsjson.Parse(must(os.ReadFile(windowsAgentVectors))); v.(jsjson.Object).Value("version") != loadAgentVectors(t).Value("version") {
		t.Error("windows/agents.json was recorded from another version: record it again (apps/cli/test/goWindows.ts)")
	}
	seen := map[string]bool{}
	for _, s := range linux {
		name := s.Value("name").(string)
		seen[name] = true
		w, ok := windows[name]
		switch {
		case !pathBelowDir.MatchString(js(s.Value("steps"))):
			if ok {
				t.Errorf("%s: a Windows expectation for a scenario that names no path: record again (apps/cli/test/goWindows.ts)", name)
			}
			continue
		case !ok:
			t.Errorf("%s: names a path and has no Windows expectation: record one (apps/cli/test/goWindows.ts)", name)
		case js(w.Value("setup")) != js(s.Value("setup")) || len(asList(w.Value("steps"))) != len(asList(s.Value("steps"))):
			t.Errorf("%s: the Windows recording has another setup or other steps: record again", name)
		default:
			for i, step := range asList(s.Value("steps")) {
				if js(step.(jsjson.Object).Value("step")) != js(asList(w.Value("steps"))[i].(jsjson.Object).Value("step")) {
					t.Errorf("%s: step %d differs from the Linux recording's: record again", name, i)
				}
			}
		}
	}
	for name := range windows {
		if !seen[name] {
			t.Errorf("windows/agents.json holds %s, a scenario the recording does not have: record again", name)
		}
	}
}

func must(data []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return data
}

func optional(v any) desired {
	if s, ok := v.(string); ok {
		return ptr(s)
	}
	return nil
}

func desiredJSON(d desired) any {
	if d == nil {
		return nil
	}
	return *d
}

func cases(t *testing.T, vectors jsjson.Object, name string, min int) []jsjson.Object {
	t.Helper()
	list, _ := vectors.Value(name).([]any)
	if len(list) < min {
		t.Fatalf("%s: only %d vectors", name, len(list))
	}
	out := make([]jsjson.Object, len(list))
	for i, c := range list {
		out[i] = c.(jsjson.Object)
	}
	return out
}

func TestPureEditVectors(t *testing.T) {
	v := loadAgentVectors(t)
	if v.Value("block") != AgentsBlock() {
		t.Errorf("the AGENTS.md block differs")
	}
	for _, c := range cases(t, v, "withBlock", 40) {
		got, err := withBlock(optional(c.Value("current")), c.Value("remove").(bool))
		if message, ok := c.Get("error"); ok {
			var e *Error
			if !errors.As(err, &e) || e.Message != message || e.Usage != c.Value("usage") {
				t.Errorf("withBlock(%q): %v, want %q", c.Value("current"), err, message)
			}
			continue
		}
		if err != nil || js(desiredJSON(got)) != js(c.Value("result")) {
			t.Errorf("withBlock(%q, %v) = %q, %v; want %q", c.Value("current"), c.Value("remove"), desiredJSON(got), err, c.Value("result"))
		}
	}
	for _, c := range cases(t, v, "withClaudeImport", 80) {
		got := withClaudeImport(optional(c.Value("current")), c.Value("remove").(bool), c.Value("importPath").(string))
		if js(desiredJSON(got)) != js(c.Value("result")) {
			t.Errorf("withClaudeImport(%q, %v, %v) = %q, want %q", c.Value("current"), c.Value("remove"), c.Value("importPath"), desiredJSON(got), c.Value("result"))
		}
	}
	for _, c := range cases(t, v, "withGeminiContext", 10) {
		settings, _ := jsjson.Parse([]byte(c.Value("settings").(string)))
		var got any
		if next := withGeminiContext(settings.(jsjson.Object)); next != nil {
			got = stringify2(next)
		}
		if js(got) != js(c.Value("result")) {
			t.Errorf("withGeminiContext(%s) = %v, want %v", c.Value("settings"), got, c.Value("result"))
		}
	}
	for _, c := range cases(t, v, "aiderLayout", 40) {
		if got := aiderLayout(c.Value("text").(string)); got != c.Value("result") {
			t.Errorf("aiderLayout(%q) = %s, want %s", c.Value("text"), got, c.Value("result"))
		}
	}
	for _, c := range cases(t, v, "withAiderRead", 100) {
		got := withAiderRead(optional(c.Value("current")), c.Value("remove").(bool))
		if js(desiredJSON(got)) != js(c.Value("result")) {
			t.Errorf("withAiderRead(%q, %v) = %q, want %q", c.Value("current"), c.Value("remove"), desiredJSON(got), c.Value("result"))
		}
	}
	for _, c := range cases(t, v, "toml", 100) {
		current := optional(c.Value("current"))
		var edit tomlEdit
		switch c.Value("edit") {
		case "withCodexEnv":
			edit = withCodexEnv(current)
		case "withoutCodexEnv":
			edit = withoutTOMLPart(*current, partEnv, codexEnvBody)
		case "withMcpPart":
			edit = withTOMLPart(current, partMCP, codexMCPBody, expectMCP)
		case "withoutMcpPart":
			edit = withoutTOMLPart(*current, partMCP, codexMCPBody)
		default:
			t.Fatalf("edit %v", c.Value("edit"))
		}
		got := jsjson.Object{{Key: "next", Value: desiredJSON(edit.next)}}
		if edit.refused != "" {
			got = jsjson.Object{{Key: "refused", Value: edit.refused}}
		}
		if js(got) != js(c.Value("result")) {
			t.Errorf("%s(%q) = %s, want %s", c.Value("edit"), c.Value("current"), js(got), js(c.Value("result")))
		}
	}
	for _, c := range cases(t, v, "guide", 8) {
		topic, given := c.Value("topic").(string)
		got, err := Guide(topic, given)
		if message, ok := c.Get("error"); ok {
			var e *GuideTopicError
			if !errors.As(err, &e) || e.Error() != message {
				t.Errorf("guide(%q): %v, want %q", topic, err, message)
			}
			continue
		}
		if err != nil || got != c.Value("result") {
			t.Errorf("guide(%q) differs", topic)
		}
	}
	want := v.Value("skillFiles").(jsjson.Object)
	files := SkillFiles(v.Value("version").(string))
	if len(files) != len(want) {
		t.Fatalf("%d skill files, want %d", len(files), len(want))
	}
	for i, f := range files {
		if want[i].Key != f.path || want[i].Value != f.content {
			t.Errorf("skill file %d: %s differs from %s", i, f.path, want[i].Key)
		}
	}
}

func TestInstallVectors(t *testing.T) {
	v := loadAgentVectors(t)
	version := v.Value("version").(string)
	scenarios := cases(t, v, "install", 250)
	var windows map[string]jsjson.Object
	if runtime.GOOS == "windows" {
		windows = windowsScenarios(t)
	}
	syncWrites = false
	defer func() { syncWrites = true }()
	scratch, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range scenarios {
		name := s.Value("name").(string)
		t.Run(name, func(t *testing.T) {
			// The recorded outcomes name paths as TypeScript printed them on
			// Linux; on Windows both CLIs join them with backslashes, so a
			// scenario whose outcomes name a path below its directory is
			// compared there with TypeScript's Windows recording.
			windowsRecorded := false
			if runtime.GOOS == "windows" && pathBelowDir.MatchString(js(s.Value("steps"))) {
				w, ok := windows[name]
				if !ok {
					t.Fatal("no Windows expectation: record one (apps/cli/test/goWindows.ts)")
				}
				s, windowsRecorded = w, true
			}
			dir := filepath.Join(scratch, "s"+jsjson.Number(float64(i)))
			for _, sub := range []string{"project", "home"} {
				if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			buildSetup(t, dir, s.Value("setup").(jsjson.Object))
			before := js(treeOf(t, dir, version))
			for n, raw := range s.Value("steps").([]any) {
				step := raw.(jsjson.Object)
				got := runVectorStep(dir, version, step.Value("step").(jsjson.Object), !strings.HasPrefix(name, "matrix."))
				want := step.Value("outcome")
				if _, uncaught := get(want, "uncaught"); uncaught {
					// An error TypeScript lets escape: Go fails too, in its own words.
					if _, ok := get(got, "uncaught"); ok {
						got = want
					}
				}
				if runtime.GOOS == "windows" && !windowsRecorded {
					// go/README.md, `skill-order`: against a Linux recording,
					// the skill's files as a multiset in each run.
					got, want = skillOrderFree(got), skillOrderFree(want)
				}
				if js(got) != js(want) {
					t.Fatalf("step %d %s:\n got %s\nwant %s", n, js(step.Value("step")), js(got), js(step.Value("outcome")))
				}
				tree := treeOf(t, dir, version)
				var gotTree any = tree
				if js(tree) == before {
					gotTree = "unchanged"
				}
				before = js(tree)
				if js(gotTree) != js(step.Value("tree")) {
					t.Fatalf("step %d %s: tree\n got %s\nwant %s", n, js(step.Value("step")), js(gotTree), js(step.Value("tree")))
				}
			}
		})
	}
}

func buildSetup(t *testing.T, dir string, setup jsjson.Object) {
	t.Helper()
	for _, m := range setup {
		at := filepath.Join(dir, m.Key)
		if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
			t.Fatal(err)
		}
		entry := m.Value.(jsjson.Object)
		var err error
		switch {
		case entry.Value("text") != nil:
			err = os.WriteFile(at, []byte(entry.Value("text").(string)), 0o644)
		case entry.Value("base64") != nil:
			data, _ := base64.StdEncoding.DecodeString(entry.Value("base64").(string))
			err = os.WriteFile(at, data, 0o644)
		case entry.Value("link") != nil:
			err = os.Symlink(strings.ReplaceAll(entry.Value("link").(string), "{{dir}}", dir), at)
		case entry.Value("hardlink") != nil:
			err = os.Link(filepath.Join(dir, entry.Value("hardlink").(string)), at)
		default:
			err = os.MkdirAll(at, 0o755)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func runVectorStep(dir, version string, step jsjson.Object, withLines bool) any {
	opts := Options{Scope: "project", Root: filepath.Join(dir, "project"), Version: version, Mode: "install"}
	if s, ok := step.Value("scope").(string); ok {
		opts.Scope = s
		if s == "user" {
			opts.Root = filepath.Join(dir, "home")
		}
	}
	if m, ok := step.Value("mode").(string); ok {
		opts.Mode = m
	}
	for _, a := range asList(step.Value("agents")) {
		opts.Agents = append(opts.Agents, a.(string))
	}
	opts.Guardrails = step.Value("guardrails") == true
	opts.MCP = step.Value("mcp") == true
	sub := func(s string) string { return transcript.UnfillDir(s, dir) }
	result, err := RunInstall(opts)
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			return jsjson.Object{{Key: "error", Value: sub(e.Message)}, {Key: "usage", Value: e.Usage}}
		}
		return jsjson.Object{{Key: "uncaught", Value: "(Go: " + err.Error() + ")"}}
	}
	out := jsjson.Object{{Key: "result", Value: result.JSON()}}
	if withLines {
		out = append(out, jsjson.Member{Key: "lines", Value: strs(Describe(result, opts.Mode))})
	}
	if step.Value("init") == true {
		out = append(out, jsjson.Member{Key: "changedTargets", Value: strs(ChangedTargets(result))})
	}
	text := sub(js(out))
	parsed, _ := jsjson.Parse([]byte(text))
	return parsed
}

func asList(v any) []any {
	list, _ := v.([]any)
	return list
}

// treeOf is the vectors' tree: every entry under dir, with the skill files
// and the AGENTS.md block replaced by their markers.
func treeOf(t *testing.T, dir, version string) jsjson.Object {
	t.Helper()
	skill := map[string]string{}
	for _, f := range SkillFiles(version) {
		skill[f.path] = f.content
	}
	block := AgentsBlock()
	out := jsjson.Object{}
	var walk func(rel string)
	walk = func(rel string) {
		entries, err := os.ReadDir(filepath.Join(dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		sort.Strings(names)
		for _, name := range names {
			path := name
			if rel != "" {
				path = rel + "/" + name
			}
			at := filepath.Join(dir, path)
			info, err := os.Lstat(at)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case info.Mode()&os.ModeSymlink != 0:
				target, _ := os.Readlink(at)
				out = append(out, jsjson.Member{Key: path, Value: jsjson.Object{{Key: "link", Value: strings.ReplaceAll(target, dir, "{{dir}}")}}})
			case info.IsDir():
				out = append(out, jsjson.Member{Key: path + "/", Value: jsjson.Object{}})
				walk(path)
			default:
				data, err := os.ReadFile(at)
				if err != nil {
					t.Fatal(err)
				}
				if !utf8.Valid(data) {
					out = append(out, jsjson.Member{Key: path, Value: jsjson.Object{{Key: "base64", Value: base64.StdEncoding.EncodeToString(data)}}})
					continue
				}
				text := string(data)
				for _, prefix := range []string{"project/.agents/skills/varlatch/", "project/.claude/skills/varlatch/", "home/.agents/skills/varlatch/", "home/.claude/skills/varlatch/"} {
					if p, ok := strings.CutPrefix(path, prefix); ok {
						if content, ok := skill[p]; ok && content == text {
							text = "{{skill}}"
						}
					}
				}
				if text != "{{skill}}" {
					text = strings.ReplaceAll(text, block, "{{block}}")
					text = strings.ReplaceAll(text, strings.ReplaceAll(block, "\n", "\r\n"), "{{block-crlf}}")
				}
				out = append(out, jsjson.Member{Key: path, Value: jsjson.Object{{Key: "text", Value: text}}})
			}
		}
	}
	walk("")
	return out
}

// skillOrderFree is a step's outcome with the skill's files in sorted runs,
// for a scenario replayed on Windows against its Linux recording
// (go/README.md, `skill-order`): its result's changes, by path, and its
// lines (transcript.SkillOrderFree's rule).
func skillOrderFree(v any) any {
	o, ok := v.(jsjson.Object)
	if !ok {
		return v
	}
	out := make(jsjson.Object, len(o))
	for i, m := range o {
		value := m.Value
		switch m.Key {
		case "result":
			if r, ok := value.(jsjson.Object); ok {
				result := make(jsjson.Object, len(r))
				for j, rm := range r {
					if list, ok := rm.Value.([]any); ok && rm.Key == "changes" {
						rm.Value = transcript.SortSkillChanges(list)
					}
					result[j] = rm
				}
				value = result
			}
		case "lines":
			if list, ok := value.([]any); ok {
				line := func(e any) string { s, _ := e.(string); return s }
				value = transcript.SortSkillRuns(list, func(e any) bool { return transcript.NamesSkillFile(line(e)) }, line)
			}
		}
		out[i] = jsjson.Member{Key: m.Key, Value: value}
	}
	return out
}
