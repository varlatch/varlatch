// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
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
			out, err := exec.Command(host, psArgs(runner, "-Script", file, "-Closing", fmt.Sprint(closing), "-Work", t.TempDir())...).CombinedOutput()
			if err != nil {
				t.Fatalf("the prefix runner failed: %v\n%s", err, out)
			}
			bad := 0
			for _, line := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(line, "BAD ") {
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

// --- end to end: Windows, against a local HTTPS server ---

const ps1BaseLine = "  $Base = 'https://github.com/varlatch/varlatch/releases/download/v'"

type psRelease struct {
	files        map[string][]byte
	sums         string
	hits         atomic.Int32
	cutOff       string
	redirectHTTP string
}

func (r *psRelease) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		name := strings.TrimPrefix(req.URL.Path, "/v"+version+"/")
		if name == "SHA256SUMS" {
			_, _ = w.Write([]byte(r.sums))
			return
		}
		data, ok := r.files[name]
		if !ok {
			http.NotFound(w, req)
			return
		}
		switch name {
		case r.redirectHTTP:
			http.Redirect(w, req, "http://"+req.Host+req.URL.Path, http.StatusFound)
		case r.cutOff:
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
			_, _ = buf.Write(data[:len(data)-10])
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

// TestPS1EndToEnd installs with install.ps1 under every PowerShell found,
// against a local HTTPS server standing in for GitHub. It changes the
// current user's PATH (restored afterwards), so it runs only on a
// disposable Windows machine: VARLATCH_TEST_DISPOSABLE=1 (CI).
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
	exe := "varlatch-" + version + "-windows-" + runtime.GOARCH + ".exe"

	userPath := func() string {
		out, err := exec.Command("powershell", "-NoProfile", "-Command", "[Environment]::GetEnvironmentVariable('Path', 'User')").Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	saved := userPath()
	t.Cleanup(func() {
		cmd := exec.Command("powershell", "-NoProfile", "-Command", "[Environment]::SetEnvironmentVariable('Path', $env:VARLATCH_SAVED_PATH, 'User')")
		cmd.Env = append(os.Environ(), "VARLATCH_SAVED_PATH="+saved)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("restoring the user PATH: %v\n%s", err, out)
		}
	})

	newRelease := func() *psRelease {
		r := &psRelease{files: map[string][]byte{exe: stubBytes, "SHA256SUMS.sigstore.json": []byte(`{"stub":true}`)}}
		r.sums = sha256Line(stubBytes, exe)
		return r
	}

	type result struct {
		code       int
		out        string
		local, tmp string
		log        string
	}
	// install runs a copy of install.ps1: stamped unless told otherwise,
	// downloading from the test server and trusting its certificate only.
	install := func(t *testing.T, host string, r *psRelease, stamped bool, args []string, env ...string) result {
		t.Helper()
		srv := r.serve(t)
		thumb := sha1.Sum(srv.Certificate().Raw)
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
		file := filepath.Join(t.TempDir(), "install.ps1")
		if err := os.WriteFile(file, src, 0o644); err != nil {
			t.Fatal(err)
		}
		local, tmp := t.TempDir(), t.TempDir()
		log := filepath.Join(t.TempDir(), "stub.log")
		cmd := exec.Command(host, psArgs(file, args...)...)
		// PROCESSOR_ARCHITEW6432 is left out rather than set empty: an
		// empty entry garbles the environment block on Windows.
		for _, e := range os.Environ() {
			if !strings.HasPrefix(strings.ToUpper(e), "PROCESSOR_ARCHITEW6432=") {
				cmd.Env = append(cmd.Env, e)
			}
		}
		cmd.Env = append(cmd.Env, "LOCALAPPDATA="+local, "TEMP="+tmp, "TMP="+tmp, "STUB_LOG="+log)
		cmd.Env = append(cmd.Env, env...)
		out, _ := cmd.CombinedOutput()
		stubLog, _ := os.ReadFile(log)
		return result{cmd.ProcessState.ExitCode(), string(out), local, tmp, string(stubLog)}
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

	for name, host := range hosts {
		t.Run(name, func(t *testing.T) {
			r := newRelease()
			res := install(t, host, r, true, nil)
			got, _ := os.ReadFile(target(res))
			if res.code != 0 || !bytes.Equal(got, stubBytes) || !strings.Contains(res.out, "Installed varlatch "+version) {
				t.Fatalf("install: exit %d\n%s", res.code, res.out)
			}
			if !regexp.MustCompile(`verify-release --version 0\.50\.0 --sums \S+ --bundle \S+ --file \S+=` + regexp.QuoteMeta(exe)).MatchString(res.log) {
				t.Fatalf("verify-release was not called as expected:\n%s", res.log)
			}
			emptyDir(t, res.tmp)
			dir := filepath.Dir(target(res))
			count := 0
			for _, e := range strings.Split(userPath(), ";") {
				if strings.EqualFold(strings.TrimRight(e, `\`), dir) {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("the user PATH holds %s %d times", dir, count)
			}

			// A rerun into the same place changes nothing.
			again := install(t, host, r, true, nil, "LOCALAPPDATA="+res.local)
			if again.code != 0 || !strings.Contains(again.out, "already installed") {
				t.Fatalf("rerun: exit %d\n%s", again.code, again.out)
			}

			for caseName, tc := range map[string]struct {
				edit       func(*psRelease)
				stamped    bool
				args, env  []string
				want       string
				noDownload bool
			}{
				"changed binary":   {edit: func(r *psRelease) { r.files[exe] = append(bytes.Clone(stubBytes), 'x') }, stamped: true, want: "does not match SHA256SUMS"},
				"not listed":       {edit: func(r *psRelease) { r.sums = sha256Line(stubBytes, "other.exe") }, stamped: true, want: "does not list " + exe},
				"listed twice":     {edit: func(r *psRelease) { r.sums += r.sums }, stamped: true, want: "does not list " + exe},
				"cut-off binary":   {edit: func(r *psRelease) { r.cutOff = exe }, stamped: true, want: "varlatch install:"},
				"redirect to http": {edit: func(r *psRelease) { r.redirectHTTP = exe }, stamped: true, want: "not HTTPS"},
				"signature fails":  {stamped: true, env: []string{"STUB_VERIFY=fail"}, want: "release signature does not verify"},
				"wrong version":    {stamped: true, env: []string{"STUB_REPORTS=0.49.0"}, want: "reports 'varlatch 0.49.0'"},
				"unstamped":        {want: "not from a release", noDownload: true},
				"bad version":      {stamped: true, args: []string{"--version", "0.50.0/../x"}, want: "not a release version", noDownload: true},
				"unknown option":   {stamped: true, args: []string{"--force"}, want: "unknown option", noDownload: true},
				"other processor":  {stamped: true, env: []string{"PROCESSOR_ARCHITECTURE=x86"}, want: "no varlatch for x86", noDownload: true},
			} {
				t.Run(caseName, func(t *testing.T) {
					r := newRelease()
					if tc.edit != nil {
						tc.edit(r)
					}
					res := install(t, host, r, tc.stamped, tc.args, tc.env...)
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
		})
	}
}
