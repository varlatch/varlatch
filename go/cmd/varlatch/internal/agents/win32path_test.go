// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// TestWin32Paths holds win32path.go to Node.js's path.win32 (v26):
// path.win32.resolve("D:\\wd", cwd, p), isAbsolute and normalize.
func TestWin32Paths(t *testing.T) {
	for _, c := range [][3]string{
		{"/work/app", ".env", `D:\work\app\.env`},
		{"/work/app", "/home/dev/.xdg/varlatch/credentials.json", `D:\home\dev\.xdg\varlatch\credentials.json`},
		{`C:\proj`, ".env", `C:\proj\.env`},
		{`C:\proj`, "sub/../.env", `C:\proj\.env`},
		{`C:\proj`, "/home/x", `C:\home\x`},
		{`C:\proj`, `D:\y\z`, `D:\y\z`},
		{`C:\proj`, `..\..\..`, `C:\`},
		{"C:/proj/", "./a//b/", `C:\proj\a\b`},
		{`\\srv\share\dir`, ".env", `\\srv\share\dir\.env`},
		{`\\srv\share\dir`, `\top`, `\\srv\share\top`},
		{`C:\proj`, "C:rel", `C:\proj\rel`},
		{`C:\proj`, "D:rel", `D:\wd\rel`},
		{"relative", "x", `D:\wd\relative\x`},
		{"/work/app", "../../home/dev/.config/varlatch/credentials.json", `D:\home\dev\.config\varlatch\credentials.json`},
		{`C:\proj`, "é/.env", `C:\proj\é\.env`},
	} {
		if got := win32Resolve(`D:\wd`, c[0], c[1]); got != c[2] {
			t.Errorf("resolve(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
	for _, c := range []struct {
		p        string
		absolute bool
		normal   string
	}{
		{"/a", true, `\a`}, {`\a`, true, `\a`}, {`C:\a`, true, `C:\a`}, {"C:/a", true, `C:\a`},
		{"C:a", false, "C:a"}, {"a", false, "a"}, {"", false, "."}, {`\\srv\share`, true, `\\srv\share\`},
	} {
		if got := win32IsAbsolute(c.p); got != c.absolute {
			t.Errorf("isAbsolute(%q) = %v", c.p, got)
		}
		if got := win32Normalize(c.p); got != c.normal {
			t.Errorf("normalize(%q) = %q, want %q", c.p, got, c.normal)
		}
	}
}

// TestHookDeniesWithThisPlatformsPaths: with the directories and paths of
// the platform the hook runs on (a drive and backslashes on Windows), a
// `.env` read and the credential store are denied: the hook never fails
// open on a path's form.
func TestHookDeniesWithThisPlatformsPaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	home, xdg := t.TempDir(), t.TempDir()
	env := envMap{"HOME": home, "XDG_CONFIG_HOME": xdg}
	q := func(s string) string { return string(jsjson.Stringify(s)) }
	event := func(tool, input string) string {
		return `{"cwd":` + q(dir) + `,"hook_event_name":"PreToolUse","tool_name":"` + tool + `","tool_input":` + input + `}`
	}
	for _, c := range []struct{ name, event, reason string }{
		{"cat .env", event("Bash", `{"command":"cat .env"}`), ".env files are off limits"},
		{"cat <dir>/.env", event("Bash", `{"command":`+q("cat "+q(filepath.Join(dir, ".env")))+`}`), ".env files are off limits"},
		{"Read .env", event("Read", `{"file_path":".env"}`), ".env files are off limits"},
		{"Read <dir>/.env", event("Read", `{"file_path":`+q(filepath.Join(dir, ".env"))+`}`), ".env files are off limits"},
		{"grep -r", event("Bash", `{"command":"grep -r KEY ."}`), "this search would print"},
		{"Read the default store", event("Read", `{"file_path":`+q(filepath.Join(home, ".config", "varlatch", "credentials.json"))+`}`), "credential store is off limits"},
		{"Read the XDG store", event("Read", `{"file_path":`+q(filepath.Join(xdg, "varlatch", "credentials.json"))+`}`), "credential store is off limits"},
		{"cat the XDG store", event("Bash", `{"command":"cat $XDG_CONFIG_HOME/varlatch/credentials.json"}`), "credential store is off limits"},
	} {
		got, err := RunHook("claude", c.event, env, dir)
		if err != nil || !strings.Contains(got, c.reason) {
			t.Errorf("%s: %q, %v; want %q", c.name, got, err, c.reason)
		}
	}
}
