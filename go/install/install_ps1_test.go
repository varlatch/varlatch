// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

func ps1Script(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ps1Bounds checks install.ps1's shape: comments and blank lines, a line
// holding only "& {", the script, a line holding only "}", and after it
// nothing but comments and blank lines. It returns the byte offset of
// that line's closing brace.
func ps1Bounds(src []byte) (int, error) {
	// A lone CR ends a line for PowerShell but not for this check, so code
	// could hide behind one inside a comment.
	if i := bytes.IndexByte(src, '\r'); i >= 0 {
		return 0, fmt.Errorf("a carriage return at byte %d", i)
	}
	lines := strings.SplitAfter(string(src), "\n")
	isNothing := func(l string) bool {
		t := strings.TrimSpace(l)
		return t == "" || strings.HasPrefix(t, "#")
	}
	open := -1
	for i, l := range lines {
		if strings.TrimRight(l, "\r\n") == "& {" {
			open = i
			break
		}
		if !isNothing(l) {
			return 0, fmt.Errorf("line %d runs before the group opens: %q", i+1, strings.TrimSpace(l))
		}
	}
	if open < 0 {
		return 0, errors.New("no line holding only & { opens the group")
	}
	closeLine := -1
	for i := len(lines) - 1; i > open; i-- {
		if strings.TrimRight(lines[i], "\r\n") == "}" {
			closeLine = i
			break
		}
		if !isNothing(lines[i]) {
			return 0, fmt.Errorf("line %d runs after the group closes: %q", i+1, strings.TrimSpace(lines[i]))
		}
	}
	if closeLine < 0 {
		return 0, errors.New("no line holding only } closes the group")
	}
	offset := 0
	for _, l := range lines[:closeLine] {
		offset += len(l)
	}
	return offset, nil
}

func TestPS1GroupBoundsRejectsCodeOutside(t *testing.T) {
	src := string(ps1Script(t))
	if _, err := ps1Bounds([]byte(src)); err != nil {
		t.Fatal(err)
	}
	for i, c := range src {
		if c > 0x7f {
			t.Fatalf("install.ps1 is not ASCII at byte %d: prefixes are cut by byte", i)
		}
	}
	opening := "\n& {\n"
	for name, bad := range map[string]string{
		"a cmdlet before":      strings.Replace(src, opening, "\nRemove-Item x\n& {\n", 1),
		"an assignment before": strings.Replace(src, opening, "\n$x = 1\n& {\n", 1),
		"a block comment":      strings.Replace(src, opening, "\n<# hidden #> Set-Location /\n& {\n", 1),
		"a command after":      src + "exit 1\n",
		"code behind a CR":     strings.Replace(src, "\n& {\n", "\n# c\rWrite-Output X\n& {\n", 1),
		"no group":             strings.Replace(src, opening, "\n{\n", 1),
	} {
		if bad == src {
			t.Fatalf("%s: the edit did not apply", name)
		}
		if _, err := ps1Bounds([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// psHosts are the PowerShell versions G8 names, as far as this machine
// has them: pwsh (7) everywhere, powershell (5.1) on Windows.
func psHosts(t *testing.T) map[string]string {
	t.Helper()
	found := map[string]string{}
	if p, err := exec.LookPath("pwsh"); err == nil {
		found["pwsh"] = p
	}
	if runtime.GOOS == "windows" {
		if p, err := exec.LookPath("powershell"); err == nil {
			found["powershell"] = p
		}
	}
	if len(found) == 0 {
		t.Skip("no PowerShell")
	}
	return found
}

func psArgs(file string, args ...string) []string {
	a := []string{"-NoProfile", "-NonInteractive"}
	if runtime.GOOS == "windows" {
		a = append(a, "-ExecutionPolicy", "Bypass")
	}
	return append(append(a, "-File", file), args...)
}

// psMessages are the script's own messages; each starts a line.
var psMessages = regexp.MustCompile(`(?m)^(varlatch install:|usage:|Installed|Next:|Added )`)

// G8: every prefix of install.ps1, under PowerShell 7 and (on Windows)
// 5.1, runs nothing or runs the whole script.
func TestPS1EveryPrefix(t *testing.T) {
	src := ps1Script(t)
	closing, err := ps1Bounds(src)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := filepath.Abs("testdata/ps1prefix.ps1")
	if err != nil {
		t.Fatal(err)
	}
	for name, host := range psHosts(t) {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "install.ps1")
			if err := os.WriteFile(file, src, 0o644); err != nil {
				t.Fatal(err)
			}
			// Prefixes that end before the closing brace: nothing may run.
			work := t.TempDir()
			out, err := exec.Command(host, psArgs(runner, "-Script", file, "-Closing", fmt.Sprint(closing), "-Work", work)...).CombinedOutput()
			if err != nil {
				t.Fatalf("the prefix runner failed: %v\n%s", err, out)
			}
			// The script's failure line goes to the process's stderr, past
			// PowerShell's streams: look for it in the runner's own output.
			if psMessages.Match(out) {
				t.Fatalf("a prefix printed one of the script's messages:\n%s", out)
			}
			if strings.Contains(string(out), "BADSETUP") {
				t.Fatalf("the sentinels did not load:\n%s", out)
			}
			bad := 0
			for _, line := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(line, "BAD") {
					if bad++; bad <= 5 {
						t.Errorf("%s", line)
					}
				}
			}
			if want := fmt.Sprintf("CHECKED %d", 2*(closing+1)); !strings.Contains(string(out), want) {
				t.Fatalf("the runner did not check every prefix (want %q):\n%s", want, out)
			}
			if bad > 0 {
				t.Fatalf("%d prefixes ran something", bad)
			}

			// A sample of the same prefixes run as the installer runs them,
			// powershell -File, with the command sentinels on PATH: every
			// third line boundary and some cuts inside lines.
			bin := filepath.Join(work, "bin")
			commandLog := filepath.Join(work, "commands.log")
			var cuts []int
			for i, line := 0, 0; i < closing; i++ {
				if src[i] == '\n' {
					if line%3 == 0 {
						cuts = append(cuts, i+1)
					}
					line++
				}
			}
			for i := 1; i <= 12; i++ {
				cuts = append(cuts, closing*i/13)
			}
			for _, n := range cuts {
				f := filepath.Join(dir, fmt.Sprintf("file%d.ps1", n))
				if err := os.WriteFile(f, src[:n], 0o644); err != nil {
					t.Fatal(err)
				}
				_ = os.Remove(commandLog)
				cmd := exec.Command(host, psArgs(f)...)
				cmd.Dir = t.TempDir()
				cmd.Env = append(os.Environ(), "PATH="+bin)
				got, _ := cmd.CombinedOutput()
				logged, _ := os.ReadFile(commandLog)
				if psMessages.Match(got) || len(logged) > 0 {
					t.Errorf("-File run of a %d-byte prefix ran something: %q %q", n, got, logged)
				}
			}

			// The rest: either nothing runs, or the whole script does.
			run := func(f string) (string, int) {
				cmd := exec.Command(host, psArgs(f)...)
				cmd.Dir = t.TempDir()
				out, _ := cmd.CombinedOutput()
				return strings.ReplaceAll(string(out), f, "SCRIPT"), cmd.ProcessState.ExitCode()
			}
			wantOut, wantCode := run(file)
			if !psMessages.MatchString(wantOut) {
				t.Fatalf("the whole script did not run as expected: %q", wantOut)
			}
			for n := closing + 1; n < len(src); n++ {
				f := filepath.Join(dir, fmt.Sprintf("p%d.ps1", n))
				if err := os.WriteFile(f, src[:n], 0o644); err != nil {
					t.Fatal(err)
				}
				got, code := run(f)
				if psMessages.MatchString(got) && (got != wantOut || code != wantCode) {
					t.Errorf("a prefix of %d bytes ran part of the script: %q (exit %d)", n, got, code)
				}
			}
		})
	}
}

// The runner catches what it is for: a command before the group, as an
// alias, a function and a command on PATH, and the script's shape.
func TestPS1PrefixRunnerCatches(t *testing.T) {
	runner, err := filepath.Abs("testdata/ps1prefix.ps1")
	if err != nil {
		t.Fatal(err)
	}
	src := []byte("# a script with a command before its group\nGet-Date\n& {\n  Write-Output inside\n}\n")
	closing := bytes.LastIndex(src, []byte("\n}\n")) + 1
	for name, host := range psHosts(t) {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "bad.ps1")
			if err := os.WriteFile(file, src, 0o644); err != nil {
				t.Fatal(err)
			}
			work := t.TempDir()
			out, err := exec.Command(host, psArgs(runner, "-Script", file, "-Closing", fmt.Sprint(closing), "-Work", work)...).CombinedOutput()
			if err != nil {
				t.Fatalf("the runner failed: %v\n%s", err, out)
			}
			for _, want := range []string{"BADSHAPE the script is not exactly one statement", "alias sentinel: ALIAS G", "function sentinel: FUNCTION Ge", "parse the prefix parses"} {
				if !strings.Contains(string(out), want) {
					t.Errorf("the runner did not report %q:\n%s", want, out)
				}
			}
			// An alias or function hides a command of the same name, so
			// the command sentinels the runner leaves on PATH are what the
			// -File runs rely on: one must catch a prefix ending in "Ge".
			cut := filepath.Join(t.TempDir(), "cut.ps1")
			if err := os.WriteFile(cut, src[:bytes.Index(src, []byte("Get-Date"))+2], 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(host, psArgs(cut)...)
			cmd.Env = append(os.Environ(), "PATH="+filepath.Join(work, "bin"))
			_, _ = cmd.CombinedOutput()
			logged, _ := os.ReadFile(filepath.Join(work, "commands.log"))
			if !strings.Contains(string(logged), "COMMAND Ge") {
				t.Errorf("the command sentinel did not catch a -File run of %q: %q", "...Ge", logged)
			}
		})
	}
}

// --- end to end: Windows, against a local HTTPS server ---

const ps1BaseLine = "  $Base = 'https://github.com/varlatch/varlatch/releases/download/v'"

// psRelease is a release as GitHub serves it: /v<version>/<name> answers
// with a relative redirect to /dl/<name>, which serves the file. Fields
// change that for the refusal cases.
type psRelease struct {
	files    map[string][]byte
	sums     string
	hits     atomic.Int32
	requests []string

	absolute     bool   // redirect with an absolute https: Location
	hops         int    // redirects in a row before the file (default 1)
	cutOff       string // served without its last bytes and without a length
	cutLength    string // served with a Content-Length larger than what follows
	redirectHTTP string // redirected to http:
	noLocation   string // a 302 without a Location
}

func (r *psRelease) body(name string) ([]byte, bool) {
	if name == "SHA256SUMS" {
		return []byte(r.sums), true
	}
	b, ok := r.files[name]
	return b, ok
}

func (r *psRelease) serve(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		r.requests = append(r.requests, req.URL.Path)
		path := req.URL.Path
		if name, ok := strings.CutPrefix(path, "/v"+version+"/"); ok {
			if _, exists := r.body(name); !exists {
				http.NotFound(w, req)
				return
			}
			switch {
			case name == r.redirectHTTP:
				http.Redirect(w, req, "http://"+req.Host+"/dl/"+name, http.StatusFound)
			case name == r.noLocation:
				w.WriteHeader(http.StatusFound)
			case r.hops > 1:
				http.Redirect(w, req, fmt.Sprintf("/hop/%d/%s", r.hops-1, name), http.StatusFound)
			case r.absolute:
				http.Redirect(w, req, srv.URL+"/dl/"+name, http.StatusFound)
			default:
				http.Redirect(w, req, "/dl/"+name, http.StatusFound)
			}
			return
		}
		if rest, ok := strings.CutPrefix(path, "/hop/"); ok {
			left, name, _ := strings.Cut(rest, "/")
			if left == "1" {
				http.Redirect(w, req, "/dl/"+name, http.StatusFound)
			} else {
				var n int
				fmt.Sscan(left, &n)
				http.Redirect(w, req, fmt.Sprintf("/hop/%d/%s", n-1, name), http.StatusFound)
			}
			return
		}
		name, ok := strings.CutPrefix(path, "/dl/")
		data, exists := r.body(name)
		if !ok || !exists {
			http.NotFound(w, req)
			return
		}
		switch name {
		case r.cutOff, r.cutLength:
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			if name == r.cutLength {
				fmt.Fprintf(buf, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(data))
			} else {
				_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
			}
			_, _ = buf.Write(data[:len(data)/2])
			_ = buf.Flush()
			_ = conn.Close()
		default:
			_, _ = w.Write(data)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sha256Line(data []byte, name string) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// psRun runs a Windows PowerShell snippet and returns its output.
func psRun(t *testing.T, script string, env ...string) string {
	t.Helper()
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("powershell: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestPS1EndToEnd installs with install.ps1 under every PowerShell found,
// against a local HTTPS server standing in for GitHub. It changes the
// current user's PATH in the registry (restored, value and kind,
// afterwards), so it runs only on a disposable Windows machine:
// VARLATCH_TEST_DISPOSABLE=1 (CI).
func TestPS1EndToEnd(t *testing.T) {
	if runtime.GOOS != "windows" || os.Getenv("VARLATCH_TEST_DISPOSABLE") != "1" {
		t.Skip("needs a disposable Windows machine: VARLATCH_TEST_DISPOSABLE=1")
	}
	hosts := psHosts(t)
	stub := filepath.Join(t.TempDir(), "stub.exe")
	if out, err := exec.Command("go", "build", "-o", stub, "./testdata/stubcli").CombinedOutput(); err != nil {
		t.Fatalf("building the stub: %v\n%s", err, out)
	}
	stubBytes, err := os.ReadFile(stub)
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte(`{"stub":true}`)
	exe := "varlatch-" + version + "-windows-" + runtime.GOARCH + ".exe"

	// The user PATH, raw and with its kind, saved and restored; a %VAR%
	// entry is added first, which the installer must keep unexpanded.
	const readPath = `$k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment'); ` +
		`if ($k.GetValueNames() -contains 'Path') { '{0}|{1}' -f $k.GetValueKind('Path'), $k.GetValue('Path', '', 'DoNotExpandEnvironmentNames') } else { 'None|' }`
	const writePath = `$k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment'); ` +
		`if ($env:VARLATCH_PATH_KIND -eq 'None') { $k.DeleteValue('Path', $false) } else { $k.SetValue('Path', $env:VARLATCH_PATH_VALUE, $env:VARLATCH_PATH_KIND) }`
	saved := psRun(t, readPath)
	savedKind, savedValue, _ := strings.Cut(saved, "|")
	t.Cleanup(func() {
		psRun(t, writePath, "VARLATCH_PATH_KIND="+savedKind, "VARLATCH_PATH_VALUE="+savedValue)
	})
	const varEntry = `%VARLATCH_TEST_UNSET_VARIABLE%\bin`
	withVar := varEntry
	if savedValue != "" {
		withVar = savedValue + ";" + varEntry
	}
	psRun(t, writePath, "VARLATCH_PATH_KIND=ExpandString", "VARLATCH_PATH_VALUE="+withVar)

	newRelease := func() *psRelease {
		r := &psRelease{files: map[string][]byte{exe: stubBytes, "SHA256SUMS.sigstore.json": bundle}}
		r.sums = sha256Line(stubBytes, exe)
		return r
	}

	type result struct {
		code       int
		out        string
		local, tmp string
		calls      [][]string
	}
	spaced := func(t *testing.T) string {
		d := filepath.Join(t.TempDir(), "with space")
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		return d
	}
	// install runs a copy of install.ps1: stamped unless told otherwise,
	// downloading from the test server and trusting its certificate only
	// (or, with wrongPin, another one).
	install := func(t *testing.T, host string, r *psRelease, stamped, wrongPin bool, args []string, env ...string) result {
		t.Helper()
		srv := r.serve(t)
		thumb := sha1.Sum(srv.Certificate().Raw)
		if wrongPin {
			thumb[0] ^= 1
		}
		src := ps1Script(t)
		if stamped {
			src = edit(t, src, "'@VARLATCH_VERSION@'", "'"+version+"'")
		}
		src = edit(t, src, ps1BaseLine, "  $Base = '"+srv.URL+"/v'")
		// The test server's certificate, pinned by thumbprint, on each
		// request (a compiled callback: a script block would run on a
		// thread without a runspace).
		trust := "  $ErrorActionPreference = 'Stop'\n" +
			"Add-Type -TypeDefinition @'\n" +
			"public static class VarlatchTestTrust {\n" +
			"  public static string Thumbprint;\n" +
			"  public static System.Net.Security.RemoteCertificateValidationCallback Callback =\n" +
			"    (s, c, chain, e) => c != null && c.GetCertHashString() == Thumbprint;\n" +
			"}\n" +
			"'@\n" +
			"  [VarlatchTestTrust]::Thumbprint = '" + strings.ToUpper(hex.EncodeToString(thumb[:])) + "'\n"
		src = edit(t, src, "  $ErrorActionPreference = 'Stop'\n", trust)
		src = edit(t, src, "      $Request.AllowAutoRedirect = $false\n",
			"      $Request.AllowAutoRedirect = $false\n      $Request.ServerCertificateValidationCallback = [VarlatchTestTrust]::Callback\n")
		file := filepath.Join(spaced(t), "install.ps1")
		if err := os.WriteFile(file, src, 0o644); err != nil {
			t.Fatal(err)
		}
		local, tmp := spaced(t), spaced(t)
		log := filepath.Join(t.TempDir(), "stub.log")
		cmd := exec.Command(host, psArgs(file, args...)...)
		// PROCESSOR_ARCHITEW6432 is left out rather than set empty: an
		// empty entry garbles the environment block on Windows.
		for _, e := range os.Environ() {
			if !strings.HasPrefix(strings.ToUpper(e), "PROCESSOR_ARCHITEW6432=") {
				cmd.Env = append(cmd.Env, e)
			}
		}
		cmd.Env = append(cmd.Env, "LOCALAPPDATA="+local, "TEMP="+tmp, "TMP="+tmp, "STUB_LOG="+log,
			"STUB_WANT_SUMS="+sha256Hex([]byte(r.sums)), "STUB_WANT_BUNDLE="+sha256Hex(bundle),
			"STUB_WANT_FILE="+sha256Hex(stubBytes), "STUB_WANT_NAME="+exe)
		cmd.Env = append(cmd.Env, env...)
		out, _ := cmd.CombinedOutput()
		var calls [][]string
		if b, err := os.ReadFile(log); err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				var call []string
				if json.Unmarshal([]byte(line), &call) == nil {
					calls = append(calls, call)
				}
			}
		}
		return result{cmd.ProcessState.ExitCode(), string(out), local, tmp, calls}
	}
	target := func(r result) string { return filepath.Join(r.local, "Programs", "Varlatch", "varlatch.exe") }
	emptyDir := func(t *testing.T, dir string) {
		t.Helper()
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			names := []string{}
			for _, e := range entries {
				names = append(names, e.Name())
			}
			sort.Strings(names)
			t.Fatalf("%s holds %v", dir, names)
		}
	}
	pathCount := func(t *testing.T, dir string) int {
		t.Helper()
		raw := psRun(t, readPath)
		kind, value, _ := strings.Cut(raw, "|")
		if kind != "ExpandString" || !strings.Contains(value, varEntry) {
			t.Fatalf("the user PATH lost its kind or its %%VAR%% entry: %s", raw)
		}
		n := 0
		for _, e := range strings.Split(value, ";") {
			if strings.EqualFold(strings.TrimRight(e, `\`), dir) {
				n++
			}
		}
		return n
	}
	verifiedStaged := func(t *testing.T, res result) {
		t.Helper()
		for _, c := range res.calls {
			if len(c) == 9 && c[0] == "verify-release" && c[1] == "--version" && c[2] == version &&
				c[3] == "--sums" && strings.HasSuffix(c[4], `\SHA256SUMS`) &&
				c[5] == "--bundle" && strings.HasSuffix(c[6], `\SHA256SUMS.sigstore.json`) &&
				c[7] == "--file" && strings.HasSuffix(c[8], `\`+exe+"="+exe) {
				return
			}
		}
		t.Fatalf("verify-release was not called on the staged files: %q", res.calls)
	}

	for name, host := range hosts {
		t.Run(name, func(t *testing.T) {
			r := newRelease()
			res := install(t, host, r, true, false, nil)
			got, _ := os.ReadFile(target(res))
			if res.code != 0 || !bytes.Equal(got, stubBytes) || !strings.Contains(res.out, "Installed varlatch "+version) || !strings.Contains(res.out, "Added ") {
				t.Fatalf("install: exit %d\n%s", res.code, res.out)
			}
			verifiedStaged(t, res)
			emptyDir(t, res.tmp)
			dir := filepath.Dir(target(res))
			if n := pathCount(t, dir); n != 1 {
				t.Fatalf("the user PATH holds %s %d times", dir, n)
			}

			// A rerun into the same place changes nothing, PATH included.
			again := install(t, host, r, true, false, nil, "LOCALAPPDATA="+res.local)
			if again.code != 0 || !strings.Contains(again.out, "already installed") || strings.Contains(again.out, "Added ") {
				t.Fatalf("rerun: exit %d\n%s", again.code, again.out)
			}
			if n := pathCount(t, dir); n != 1 {
				t.Fatalf("after the rerun the user PATH holds %s %d times", dir, n)
			}

			// An older varlatch already in place is replaced, leaving only
			// the new one; a locked one (a running varlatch) is kept as it
			// was, and nothing staged is left beside it.
			seed := func(t *testing.T) (string, string) {
				t.Helper()
				local := spaced(t)
				dir := filepath.Join(local, "Programs", "Varlatch")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "varlatch.exe"), []byte("older varlatch"), 0o755); err != nil {
					t.Fatal(err)
				}
				return local, dir
			}
			only := func(t *testing.T, dir string, want []byte) {
				t.Helper()
				entries, _ := os.ReadDir(dir)
				if len(entries) != 1 || entries[0].Name() != "varlatch.exe" {
					names := []string{}
					for _, e := range entries {
						names = append(names, e.Name())
					}
					t.Fatalf("%s holds %v", dir, names)
				}
				if got, _ := os.ReadFile(filepath.Join(dir, "varlatch.exe")); !bytes.Equal(got, want) {
					t.Fatalf("varlatch.exe holds %d bytes, not the expected %d", len(got), len(want))
				}
			}
			t.Run("replaces an older varlatch", func(t *testing.T) {
				local, dir := seed(t)
				res := install(t, host, newRelease(), true, false, nil, "LOCALAPPDATA="+local)
				if res.code != 0 || !strings.Contains(res.out, "Installed varlatch "+version) {
					t.Fatalf("exit %d\n%s", res.code, res.out)
				}
				only(t, dir, stubBytes)
				emptyDir(t, res.tmp)
			})
			t.Run("keeps a locked varlatch", func(t *testing.T) {
				local, dir := seed(t)
				lockFile(t, filepath.Join(dir, "varlatch.exe"))
				res := install(t, host, newRelease(), true, false, nil, "LOCALAPPDATA="+local)
				if res.code == 0 || !strings.Contains(res.out, "could not replace") {
					t.Fatalf("exit %d\n%s", res.code, res.out)
				}
				only(t, dir, []byte("older varlatch"))
				emptyDir(t, res.tmp)
			})

			// Successes other than the default.
			for caseName, tc := range map[string]struct {
				edit    func(*psRelease)
				stamped bool
				args    []string
			}{
				"absolute redirect":        {edit: func(r *psRelease) { r.absolute = true }, stamped: true},
				"five redirects":           {edit: func(r *psRelease) { r.hops = 5 }, stamped: true},
				"unstamped with --version": {args: []string{"--version", version}},
			} {
				t.Run(caseName, func(t *testing.T) {
					r := newRelease()
					if tc.edit != nil {
						tc.edit(r)
					}
					res := install(t, host, r, tc.stamped, false, tc.args)
					if res.code != 0 || !strings.Contains(res.out, "Installed varlatch "+version) {
						t.Fatalf("exit %d\n%s", res.code, res.out)
					}
					verifiedStaged(t, res)
					emptyDir(t, res.tmp)
				})
			}

			for caseName, tc := range map[string]struct {
				edit       func(*psRelease)
				stamped    bool
				wrongPin   bool
				args, env  []string
				want       string
				noDownload bool
			}{
				"changed binary":             {edit: func(r *psRelease) { r.files[exe] = append(bytes.Clone(stubBytes), 'x') }, stamped: true, want: "does not match SHA256SUMS"},
				"not listed":                 {edit: func(r *psRelease) { r.sums = sha256Line(stubBytes, "other.exe") }, stamped: true, want: "does not list " + exe},
				"listed twice":               {edit: func(r *psRelease) { r.sums += r.sums }, stamped: true, want: "does not list " + exe},
				"cut-off binary":             {edit: func(r *psRelease) { r.cutOff = exe }, stamped: true, want: "does not match SHA256SUMS"},
				"cut-off binary, length":     {edit: func(r *psRelease) { r.cutLength = exe }, stamped: true, want: "varlatch install:"},
				"cut-off SHA256SUMS":         {edit: func(r *psRelease) { r.cutOff = "SHA256SUMS" }, stamped: true, want: "varlatch install:"},
				"cut-off SHA256SUMS, length": {edit: func(r *psRelease) { r.cutLength = "SHA256SUMS" }, stamped: true, want: "varlatch install:"},
				"cut-off bundle":             {edit: func(r *psRelease) { r.cutOff = "SHA256SUMS.sigstore.json" }, stamped: true, want: "release signature does not verify"},
				"cut-off bundle, length":     {edit: func(r *psRelease) { r.cutLength = "SHA256SUMS.sigstore.json" }, stamped: true, want: "varlatch install:"},
				"redirect to http":           {edit: func(r *psRelease) { r.redirectHTTP = exe }, stamped: true, want: "not HTTPS"},
				"six redirects":              {edit: func(r *psRelease) { r.hops = 6 }, stamped: true, want: "too many redirects"},
				"redirect without location":  {edit: func(r *psRelease) { r.noLocation = exe }, stamped: true, want: "without a location"},
				"another certificate":        {stamped: true, wrongPin: true, want: "could not download"},
				"signature fails":            {stamped: true, env: []string{"STUB_VERIFY=fail"}, want: "release signature does not verify"},
				"wrong version":              {stamped: true, env: []string{"STUB_REPORTS=0.49.0"}, want: "reports 'varlatch 0.49.0'"},
				"unstamped":                  {want: "not from a release", noDownload: true},
				"bad version":                {stamped: true, args: []string{"--version", "0.50.0/../x"}, want: "not a release version", noDownload: true},
				"unknown option":             {stamped: true, args: []string{"--force"}, want: "unknown option", noDownload: true},
				"other processor":            {stamped: true, env: []string{"PROCESSOR_ARCHITECTURE=x86"}, want: "no varlatch for x86", noDownload: true},
				"not Windows":                {stamped: true, env: []string{"OS=Linux"}, want: "elsewhere use install.sh", noDownload: true},
			} {
				t.Run(caseName, func(t *testing.T) {
					r := newRelease()
					if tc.edit != nil {
						tc.edit(r)
					}
					res := install(t, host, r, tc.stamped, tc.wrongPin, tc.args, tc.env...)
					if res.code == 0 || !strings.Contains(res.out, tc.want) {
						t.Fatalf("exit %d, want %q in:\n%s", res.code, tc.want, res.out)
					}
					if _, err := os.Stat(target(res)); err == nil {
						t.Fatal("something was installed")
					}
					emptyDir(t, res.tmp)
					if tc.noDownload && r.hits.Load() != 0 {
						t.Fatalf("%d requests before refusing", r.hits.Load())
					}
				})
			}

			// A 32-bit PowerShell on 64-bit ARM Windows asks for the arm64
			// build (absent here, so the download fails).
			t.Run("ARM64 machine", func(t *testing.T) {
				r := newRelease()
				res := install(t, host, r, true, false, nil, "PROCESSOR_ARCHITECTURE=x86", "PROCESSOR_ARCHITEW6432=ARM64")
				if res.code == 0 || !strings.Contains(res.out, "does not list varlatch-"+version+"-windows-arm64.exe") {
					t.Fatalf("exit %d:\n%s", res.code, res.out)
				}
			})
		})
	}
}
