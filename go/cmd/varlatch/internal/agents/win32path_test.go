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
		// UNC paths: after the server, any run of separators.
		{`\\srv\share\cfg`, `\\srv\\share\cfg\credentials.json`, `\\srv\share\cfg\credentials.json`},
		{`\\srv\share\dir`, "//srv//share/x", `\\srv\share\x`},
		{"/work", "//srv//share/x", `\\srv\share\x`},
		{`C:\proj`, `\\srv\\share`, `\\srv\share\`},
		{`C:\proj`, `\\srv\\`, `C:\srv`},
		{`C:\proj`, `\\\srv\share\x`, `C:\srv\share\x`},
		{`C:\proj`, `\\?\C:\cfg\x`, `\\?\C:\cfg\x`},
		{`C:\proj`, `\\.\C:\cfg`, `\\.\C:\cfg`},
	} {
		if got := win32Resolve(`D:\wd`, c[0], c[1]); got != c[2] {
			t.Errorf("resolve(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
	// A drive-relative path on another drive than the working directory's:
	// Node.js, with no `=D:` variable, resolves it against `D:\` (its
	// win32.resolve's fallback; on Windows only, so not from a recording).
	for _, c := range [][3]string{
		{`C:\proj`, "D:rel", `D:\rel`},
		{"relative", "D:rel", `D:\relative\rel`},
	} {
		if got := win32Resolve(`E:\wd`, c[0], c[1]); got != c[2] {
			t.Errorf("resolve from E:\\wd (%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
	for _, c := range []struct {
		p        string
		absolute bool
		normal   string
	}{
		{"/a", true, `\a`}, {`\a`, true, `\a`}, {`C:\a`, true, `C:\a`}, {"C:/a", true, `C:\a`},
		{"C:a", false, "C:a"}, {"a", false, "a"}, {"", false, "."}, {`\\srv\share`, true, `\\srv\share\`},
		{"C:", false, "C:."}, {`\\srv\\share\cfg`, true, `\\srv\share\cfg`}, {"//srv//share/x", true, `\\srv\share\x`},
		{`\\?\C:\a`, true, `\\?\C:\a`}, {`\\?\UNC\srv\share\a`, true, `\\?\UNC\srv\share\a`},
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

// windowsPaths runs f with the hook reading paths as on Windows, as it does
// there natively.
func windowsPaths(t *testing.T, f func()) {
	t.Helper()
	saved := onWindows
	onWindows = true
	defer func() { onWindows = saved }()
	f()
}

// TestHookStoreWindowsForms: on Windows the credential store is denied in
// each form a Windows path can name it: a UNC path with a run of
// separators after the server, letters in another case, a `\\?\` or
// `\\.\` prefix, and the `.config/varlatch` backstop in any case; a
// directory that only begins like the store's is not it. Natively on
// Windows, and with Windows paths switched on elsewhere.
func TestHookStoreWindowsForms(t *testing.T) {
	read := func(env envMap, path string) string {
		event := `{"cwd":"C:\\work","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":` + string(jsjson.Stringify(path)) + `}}`
		got, err := RunHook("claude", event, env, `C:\work`)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return got
	}
	windowsPaths(t, func() {
		unc := envMap{"HOME": `C:\Users\dev`, "XDG_CONFIG_HOME": `\\srv\share\cfg`}
		drive := envMap{"HOME": `C:\Users\dev`, "XDG_CONFIG_HOME": `C:\cfg`}
		for _, c := range []struct {
			env    envMap
			path   string
			denied bool
		}{
			{unc, `\\srv\share\cfg\varlatch\credentials.json`, true},
			{unc, `\\srv\\share\cfg\varlatch\credentials.json`, true},
			{unc, `//srv//share/cfg/varlatch/credentials.json`, true},
			{unc, `\\?\UNC\srv\share\cfg\varlatch\credentials.json`, true},
			{drive, `C:\cfg\varlatch\credentials.json`, true},
			{drive, `c:\Cfg\Varlatch\credentials.json`, true},
			{drive, `\\?\C:\cfg\varlatch\credentials.json`, true},
			{drive, `\\.\C:\cfg\varlatch\credentials.json`, true},
			{drive, `C:\cfg\VARLATCH`, true},
			{drive, `C:\Users\dev\.Config\Varlatch\credentials.json`, true},
			{drive, `C:\cfg\varlatch2\credentials.json`, false},
			{drive, `C:\cfg2\varlatch\credentials.json`, false},
		} {
			if got := read(c.env, c.path); strings.Contains(got, "credential store is off limits") != c.denied {
				t.Errorf("%s: %q, denied %v", c.path, got, c.denied)
			}
		}
	})
}

// TestHookStoreCaseOffWindows: elsewhere names are compared byte for byte,
// as hook.ts compares them.
func TestHookStoreCaseOffWindows(t *testing.T) {
	if onWindows {
		t.Skip("Windows compares names without regard to case")
	}
	env := envMap{"HOME": "/home/dev", "XDG_CONFIG_HOME": "/home/dev/.xdg"}
	for path, denied := range map[string]bool{
		"/home/dev/.xdg/varlatch/credentials.json":    true,
		"/home/dev/.XDG/varlatch/credentials.json":    false,
		"/home/dev/.config/varlatch/credentials.json": true,
		"/home/dev/.Config/Varlatch/credentials.json": false,
	} {
		event := `{"cwd":"/work/app","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":` + string(jsjson.Stringify(path)) + `}}`
		got, err := RunHook("claude", event, env, "/")
		if err != nil || strings.Contains(got, "credential store is off limits") != denied {
			t.Errorf("%s: %q, %v; denied %v", path, got, err, denied)
		}
	}
}
