// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// snapshot is every entry under dir: each file's mode and content, each
// directory, each link's target.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			target, _ := os.Readlink(path)
			out[rel] = "link " + target
		case info.IsDir():
			out[rel+"/"] = info.Mode().Perm().String()
		default:
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out[rel] = info.Mode().Perm().String() + " " + string(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameSnapshot(t *testing.T, what string, before, after map[string]string) {
	t.Helper()
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s: %s changed or went away: %q, now %q", what, k, v, after[k])
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			t.Errorf("%s: %s appeared", what, k)
		}
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links: %v", err)
	}
}

func writeAt(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestNothingThroughALinkBelowTheRoot: a directory below the scope's root
// that is a symbolic link (a cloned repository can hold one) refuses the
// whole run, install, check or remove, before anything is read through it,
// written or removed, inside the root or outside it.
func TestNothingThroughALinkBelowTheRoot(t *testing.T) {
	cases := []struct {
		name  string
		scope string
		mode  string
		opts  func(*Options)
		// link is the path below the root that is a link to outside/.
		link string
		// outside's files, as a person left them.
		outside map[string]string
		refused string
	}{
		{name: ".claude, --guardrails", mode: "install", opts: func(o *Options) { o.Guardrails = true }, link: ".claude",
			outside: map[string]string{"settings.json": "{}\n", "skills/varlatch/personal.txt": "mine\n"}, refused: ".claude"},
		{name: ".claude, plain install", mode: "install", link: ".claude",
			outside: map[string]string{"skills/varlatch/personal.txt": "mine\n"}, refused: ".claude"},
		{name: "skills", mode: "install", link: ".claude/skills",
			outside: map[string]string{"varlatch/personal.txt": "mine\n"}, refused: ".claude/skills"},
		{name: "skills/varlatch", mode: "install", link: ".agents/skills/varlatch",
			outside: map[string]string{"personal.txt": "mine\n", "sub/notes.md": "mine\n"}, refused: ".agents/skills/varlatch"},
		{name: "a directory inside the skill", mode: "install", link: ".agents/skills/varlatch/references",
			outside: map[string]string{"run.md": "mine\n"}, refused: ".agents/skills/varlatch/references"},
		{name: "--remove through a linked parent", mode: "remove", link: ".agents",
			outside: map[string]string{"skills/varlatch/SKILL.md": "mine\n", "skills/varlatch/references/run.md": "mine\n"}, refused: ".agents"},
		{name: "--remove, a linked directory it only prunes", mode: "remove", link: ".vscode",
			outside: map[string]string{}, refused: ".vscode"},
		{name: "--check does not read through it either", mode: "check", link: ".agents/skills",
			outside: map[string]string{"varlatch/SKILL.md": "mine\n"}, refused: ".agents/skills"},
		{name: ".codex, --mcp", mode: "install", opts: func(o *Options) { o.MCP = true; o.Agents = []string{"codex"} }, link: ".codex",
			outside: map[string]string{"config.toml": "model = \"o3\"\n"}, refused: ".codex"},
		{name: ".gemini, read by every project install", mode: "install", link: ".gemini",
			outside: map[string]string{"settings.json": "{}\n"}, refused: ".gemini"},
		{name: "user scope, a linked skill directory", scope: "user", mode: "install", link: ".claude",
			outside: map[string]string{"skills/varlatch/personal.txt": "mine\n"}, refused: ".claude"},
		{name: "user scope --remove, a linked ~/.codex", scope: "user", mode: "remove", link: ".codex",
			outside: map[string]string{"config.toml": "x = 1\n", "empty/.keep": ""}, refused: ".codex"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			root, outside := filepath.Join(dir, "root"), filepath.Join(dir, "outside")
			if err := os.MkdirAll(outside, 0o755); err != nil {
				t.Fatal(err)
			}
			for path, content := range c.outside {
				writeAt(t, filepath.Join(outside, path), content)
			}
			writeAt(t, filepath.Join(root, "AGENTS.md"), "# Rules\n")
			symlink(t, outside, filepath.Join(root, c.link))
			beforeRoot, beforeOutside := snapshot(t, root), snapshot(t, outside)
			scope := c.scope
			if scope == "" {
				scope = "project"
			}
			opts := Options{Scope: scope, Root: root, Version: "1", Mode: c.mode}
			if c.opts != nil {
				c.opts(&opts)
			}
			_, err := RunInstall(opts)
			var e *Error
			if !errors.As(err, &e) || e.Usage || !strings.HasPrefix(e.Message, c.refused+" is a symbolic link, so the CLI does not read, write or remove anything through it") {
				t.Fatalf("%v, want the refusal naming %s", err, c.refused)
			}
			sameSnapshot(t, "outside", beforeOutside, snapshot(t, outside))
			sameSnapshot(t, "the root", beforeRoot, snapshot(t, root))
		})
	}
}

// TestUserScopeIgnoresLinksItDoesNotUse: a linked ~/.codex is no concern
// of a user-scope install, which writes only the skill.
func TestUserScopeIgnoresLinksItDoesNotUse(t *testing.T) {
	dir := t.TempDir()
	home, outside := filepath.Join(dir, "home"), filepath.Join(dir, "outside")
	writeAt(t, filepath.Join(outside, "config.toml"), "x = 1\n")
	symlink(t, outside, filepath.Join(home, ".codex"))
	before := snapshot(t, outside)
	if _, err := RunInstall(Options{Scope: "user", Root: home, Version: "1", Mode: "install"}); err != nil {
		t.Fatal(err)
	}
	sameSnapshot(t, "outside", before, snapshot(t, outside))
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills", "varlatch", "SKILL.md")); err != nil {
		t.Fatal(err)
	}
}

// TestReplacementsAreAtomic: a file is replaced by a synced temporary file
// renamed over it, keeping the mode the person gave it; a new file gets the
// default mode less the umask; no temporary file stays; a file with
// another name (a hard link) is written in place, so both names see it.
func TestReplacementsAreAtomic(t *testing.T) {
	root := t.TempDir()
	writeAt(t, filepath.Join(root, "AGENTS.md"), "# Rules\n")
	if err := os.Chmod(filepath.Join(root, "AGENTS.md"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeAt(t, filepath.Join(root, ".claude", "settings.json"), "{}\n")
	if err := os.Chmod(filepath.Join(root, ".claude", "settings.json"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := RunInstall(Options{Scope: "project", Root: root, Version: "1", Mode: "install", Guardrails: true}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]fs.FileMode{"AGENTS.md": 0o600, ".claude/settings.json": 0o640} {
		info, err := os.Stat(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %v kept", path, info.Mode().Perm(), want)
		}
	}
	data, _ := os.ReadFile(filepath.Join(root, "AGENTS.md"))
	if !strings.HasPrefix(string(data), "# Rules\n\n<!-- varlatch:begin -->") {
		t.Errorf("AGENTS.md: %q", data)
	}
	for path := range snapshot(t, root) {
		if strings.Contains(path, ".varlatch-") {
			t.Errorf("a temporary file stayed: %s", path)
		}
	}

	if runtime.GOOS == "windows" {
		return
	}
	shared := t.TempDir()
	writeAt(t, filepath.Join(shared, "AGENTS.md"), "# Rules\n")
	if err := os.Link(filepath.Join(shared, "AGENTS.md"), filepath.Join(shared, "CLAUDE.md")); err != nil {
		t.Skip(err)
	}
	if _, err := RunInstall(Options{Scope: "project", Root: shared, Version: "1", Mode: "install"}); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(filepath.Join(shared, "AGENTS.md"))
	c, _ := os.ReadFile(filepath.Join(shared, "CLAUDE.md"))
	if string(a) != string(c) || !strings.Contains(string(c), "<!-- varlatch:begin -->") {
		t.Errorf("the hard link no longer shares AGENTS.md: %q / %q", a, c)
	}
}
