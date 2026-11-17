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
			if !strings.Contains(e.Message, "; nothing was changed. Replace it with a directory, then run this again") {
				t.Errorf("the refusal does not say nothing changed: %q", e.Message)
			}
			sameSnapshot(t, "outside", beforeOutside, snapshot(t, outside))
			sameSnapshot(t, "the root", beforeRoot, snapshot(t, root))
		})
	}
}

// TestRemoveRefusalListsTheFiles: a --remove refused for a linked
// directory it would prune (a dotfiles ~/.codex) names the link, says
// nothing changed, and lists the skill files it would have removed, none
// of them behind a link.
func TestRemoveRefusalListsTheFiles(t *testing.T) {
	dir := t.TempDir()
	home, outside := filepath.Join(dir, "home"), filepath.Join(dir, "outside")
	if _, err := RunInstall(Options{Scope: "user", Root: home, Version: "1", Mode: "install"}); err != nil {
		t.Fatal(err)
	}
	writeAt(t, filepath.Join(outside, "config.toml"), "x = 1\n")
	symlink(t, outside, filepath.Join(home, ".codex"))
	before := snapshot(t, dir)
	_, err := RunInstall(Options{Scope: "user", Root: home, Version: "1", Mode: "remove"})
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("%v, want a refusal", err)
	}
	want := ".codex is a symbolic link, so the CLI does not read, write or remove anything through it; nothing was changed. " +
		"Replace it with a directory, then run this again, or remove these files by hand:\n"
	if !strings.HasPrefix(e.Message, want) {
		t.Fatalf("%q, want it to begin %q", e.Message, want)
	}
	var listed []string
	for _, f := range SkillFiles("1") {
		for _, base := range skillBases {
			listed = append(listed, filepath.Join(home, base, filepath.FromSlash(f.path)))
		}
	}
	for _, path := range listed {
		if !strings.Contains(e.Message, "\n  "+path) {
			t.Errorf("the refusal does not list %s", path)
		}
	}
	if got := strings.Count(e.Message, "\n  "); got != len(listed) {
		t.Errorf("%d files listed, want %d", got, len(listed))
	}
	sameSnapshot(t, "everything", before, snapshot(t, dir))
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
		t.Errorf("CLAUDE.md no longer shows AGENTS.md: %q / %q", a, c)
	}
	ai, _ := os.Stat(filepath.Join(shared, "AGENTS.md"))
	ci, _ := os.Stat(filepath.Join(shared, "CLAUDE.md"))
	if !os.SameFile(ai, ci) {
		t.Errorf("AGENTS.md and CLAUDE.md are no longer one file")
	}
	for path := range snapshot(t, shared) {
		if strings.Contains(path, ".varlatch-") {
			t.Errorf("a temporary file stayed: %s", path)
		}
	}
}

// TestHardLinkWithAnUnseenName: a file install would change that has a
// name the CLI cannot see (here, outside the root) is refused before
// anything changes, so the other name's file is never written: in place
// it would change, and renamed over it would split from it.
func TestHardLinkWithAnUnseenName(t *testing.T) {
	for _, alsoClaude := range []bool{false, true} {
		dir := t.TempDir()
		root, outside := filepath.Join(dir, "root"), filepath.Join(dir, "outside")
		writeAt(t, filepath.Join(outside, "notes.md"), "# Mine\n")
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(outside, "notes.md"), filepath.Join(root, "AGENTS.md")); err != nil {
			t.Skip(err)
		}
		if alsoClaude {
			// The CLAUDE.md alias is install's own, but a third name is not.
			if err := os.Link(filepath.Join(root, "AGENTS.md"), filepath.Join(root, "CLAUDE.md")); err != nil {
				t.Fatal(err)
			}
		}
		before := snapshot(t, dir)
		for _, mode := range []string{"install", "remove"} {
			_, err := RunInstall(Options{Scope: "project", Root: root, Version: "1", Mode: mode})
			if mode == "remove" {
				// Nothing to change: AGENTS.md holds no block.
				if err != nil {
					t.Fatalf("remove: %v", err)
				}
				continue
			}
			var e *Error
			want := "AGENTS.md has another name (a hard link) the CLI cannot see, so nothing was changed; replace it with a plain copy of itself, then run this again"
			if !errors.As(err, &e) || e.Usage || e.Message != want {
				t.Fatalf("CLAUDE.md alias %v: %v, want %q", alsoClaude, err, want)
			}
		}
		sameSnapshot(t, "everything", before, snapshot(t, dir))
	}
}

// TestTemporaryFilesArePrivate: while a temporary file holds the new
// content, only its owner can read it, whatever mode the file ends with.
func TestTemporaryFilesArePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	root := t.TempDir()
	writeAt(t, filepath.Join(root, ".claude", "settings.json"), "{}\n")
	if err := os.Chmod(filepath.Join(root, ".claude", "settings.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	seen := 0
	tempWritten = func(r *os.Root, tmp string) {
		seen++
		info, err := r.Lstat(tmp)
		if err != nil {
			t.Errorf("%s: %v", tmp, err)
			return
		}
		if info.Size() == 0 || info.Mode().Perm()&^0o600 != 0 {
			t.Errorf("%s holds %d bytes with mode %v", tmp, info.Size(), info.Mode().Perm())
		}
	}
	defer func() { tempWritten = nil }()
	if _, err := RunInstall(Options{Scope: "project", Root: root, Version: "1", Mode: "install", Guardrails: true}); err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Fatal("no temporary file was written")
	}
	for path, want := range map[string]fs.FileMode{".claude/settings.json": 0o600, "AGENTS.md": newFileMode()} {
		info, err := os.Stat(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %v", path, info.Mode().Perm(), want)
		}
	}
}
