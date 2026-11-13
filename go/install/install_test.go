// SPDX-License-Identifier: Apache-2.0

// Package install tests install.sh (ADR-0059 Decision 8, gate G8).
package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
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
	"sync"
	"sync/atomic"
	"testing"
)

func script(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// shells are the ones G8 names; each found on this machine is used.
func shells(t *testing.T) map[string]string {
	t.Helper()
	found := map[string]string{}
	for _, name := range []string{"sh", "dash", "bash"} {
		if p, err := exec.LookPath(name); err == nil {
			found[name] = p
		}
	}
	if len(found) == 0 {
		t.Skip("no POSIX shell")
	}
	return found
}

var (
	wordRE     = regexp.MustCompile(`[A-Za-z0-9_.-]+`)
	identRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	funcDefRE  = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\(\)`)
	reserved   = map[string]bool{"if": true, "then": true, "else": true, "elif": true, "fi": true, "do": true, "done": true, "case": true, "esac": true, "while": true, "until": true, "for": true, "in": true, "function": true, "select": true, "time": true, "coproc": true}
	scriptMsgs = []string{"varlatch install:", "usage:", "Installed", "Next:"}
)

// sentinels makes, for every word of the script and every prefix of every
// word (a cut-off script can end in any of them), an executable on PATH
// and, for bash, a function and an alias, each recording that it ran.
func sentinels(t *testing.T, src []byte) (binDir, bashEnv string) {
	t.Helper()
	names := map[string]bool{}
	for _, w := range wordRE.FindAllString(string(src), -1) {
		for i := 1; i <= len(w); i++ {
			names[w[:i]] = true
		}
	}
	defined := map[string]bool{}
	for _, m := range funcDefRE.FindAllStringSubmatch(string(src), -1) {
		defined[m[1]] = true
	}
	dir := t.TempDir()
	binDir = filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := []byte("#!/bin/sh\nprintf 'COMMAND %s\\n' \"${0##*/}\" >> \"$SENTINEL_LOG\"\n")
	var env bytes.Buffer
	env.WriteString("shopt -s expand_aliases 2>/dev/null\n")
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	for _, n := range sorted {
		if n == "." || n == ".." {
			continue
		}
		if err := os.WriteFile(filepath.Join(binDir, n), stub, 0o755); err != nil {
			t.Fatal(err)
		}
		// The sentinels themselves call "builtin printf".
		if identRE.MatchString(n) && !reserved[n] && n != "builtin" {
			fmt.Fprintf(&env, "eval '%s() { builtin printf \"FUNCTION %%s\\\\n\" %s >> \"$SENTINEL_LOG\"; }' 2>/dev/null\n", n, n)
			// An alias for a name the script defines as a function would
			// rewrite the definition itself and break the whole script, so
			// those names keep their command and function sentinels only.
			if !defined[n] {
				fmt.Fprintf(&env, "alias %s='builtin printf \"ALIAS %%s\\\\n\" %s >> \"$SENTINEL_LOG\"' 2>/dev/null\n", n, n)
			}
		}
	}
	bashEnv = filepath.Join(dir, "bashenv")
	if err := os.WriteFile(bashEnv, env.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return binDir, bashEnv
}

type result struct {
	code     int
	out, log string
	files    string // what the run left in its working directory
}

// runFile runs a script file as the installer is run: <shell> install.sh,
// in work, a fresh empty directory that is also HOME; anything the run
// leaves there is reported in result.files.
func runFile(shell, file, binDir, bashEnv, work string) result {
	logFile := file + ".log"
	cmd := exec.Command(shell, file)
	cmd.Dir = work
	cmd.Env = []string{"PATH=" + binDir, "HOME=" + work, "SENTINEL_LOG=" + logFile}
	if bashEnv != "" {
		cmd.Env = append(cmd.Env, "BASH_ENV="+bashEnv)
	}
	out, _ := cmd.CombinedOutput()
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	log, _ := os.ReadFile(logFile)
	// Messages name the script file; runs are compared without it.
	norm := func(b []byte) string {
		return strings.ReplaceAll(strings.ReplaceAll(string(b), logFile, "LOG"), file, "SCRIPT")
	}
	var files []string
	entries, _ := os.ReadDir(work)
	for _, e := range entries {
		files = append(files, e.Name())
	}
	return result{code, norm(out), norm(log), strings.Join(files, ",")}
}

// groupBounds checks the shape that makes the guarantee hold: the shebang,
// comments and blank lines, then a line holding only "{", then the script,
// then a line holding only "}" and after it nothing but comments and blank
// lines. Code outside the group, such as a silent builtin or redirection,
// would run from a cut-off copy without calling anything a sentinel can
// see. It returns the byte offset of the closing brace.
func groupBounds(src []byte) (int, error) {
	lines := strings.SplitAfter(string(src), "\n")
	isNothing := func(l string) bool {
		t := strings.TrimSpace(l)
		return t == "" || strings.HasPrefix(t, "#")
	}
	open := -1
	for i, l := range lines {
		if strings.TrimRight(l, "\n") == "{" {
			open = i
			break
		}
		if !isNothing(l) {
			return 0, fmt.Errorf("line %d runs before the group opens: %q", i+1, strings.TrimSpace(l))
		}
	}
	if open < 0 {
		return 0, errors.New("no line holding only { opens the group")
	}
	closeLine := -1
	for i := len(lines) - 1; i > open; i-- {
		if strings.TrimRight(lines[i], "\n") == "}" {
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

// The structure check rejects code outside the group, including what a
// dynamic run cannot see (a silent builtin or redirection).
func TestGroupBoundsRejectsCodeOutside(t *testing.T) {
	src := string(script(t))
	if _, err := groupBounds([]byte(src)); err != nil {
		t.Fatal(err)
	}
	opening := "\n{\nset -eu\n"
	for name, bad := range map[string]string{
		"silent redirection before": strings.Replace(src, opening, "\n: > partial-ran\n{\nset -eu\n", 1),
		"assignment before":         strings.Replace(src, opening, "\nx=1\n{\nset -eu\n", 1),
		"builtin before":            strings.Replace(src, opening, "\ncd /\n{\nset -eu\n", 1),
		"command after":             src + "true\n",
		"redirection after":         src + "exec 3>file\n",
		"no group":                  strings.Replace(src, "\n{\n", "\n", 1),
	} {
		if bad == src {
			t.Fatalf("%s: the edit did not apply", name)
		}
		if _, err := groupBounds([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The sentinels are live: an external command reaches its executable under
// every shell, and under bash a bare word reaches its function or alias.
// dash reads no startup file when it runs a script, so it gets no function
// or alias sentinels, and builtins such as ':' cannot be replaced in any
// shell; the structure check above is what covers those.
func TestSentinelsLoad(t *testing.T) {
	binDir, bashEnv := sentinels(t, []byte("say uname"))
	for name, shell := range shells(t) {
		f := filepath.Join(t.TempDir(), "probe.sh")
		if err := os.WriteFile(f, []byte("uname\nsay\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		got := runFile(shell, f, binDir, bashEnv, t.TempDir())
		if name == "bash" {
			// bash looks up an alias before a function before a command.
			for _, word := range []string{"uname", "say"} {
				if !strings.Contains(got.log, "ALIAS "+word) && !strings.Contains(got.log, "FUNCTION "+word) {
					t.Errorf("bash: no function or alias sentinel ran for %s: %+v", word, got)
				}
			}
			continue
		}
		if !strings.Contains(got.log, "COMMAND uname") {
			t.Errorf("%s: the command sentinel did not run: %+v", name, got)
		}
	}
}

// G8: every prefix of install.sh, under every shell, runs nothing or runs
// the whole script.
func TestEveryPrefixRunsNothingOrEverything(t *testing.T) {
	src := script(t)
	closing, err := groupBounds(src)
	if err != nil {
		t.Fatal(err)
	}
	binDir, bashEnv := sentinels(t, src)
	for name, shell := range shells(t) {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			full := filepath.Join(dir, "full.sh")
			if err := os.WriteFile(full, src, 0o644); err != nil {
				t.Fatal(err)
			}
			// Complete prefixes are compared with the whole script with the
			// sentinel commands on PATH but without bash's sentinel
			// functions and aliases: those replace exit and set, so a
			// complete run would never stop where the script does and would
			// differ from run to run. The sentinels exist for cut-off
			// prefixes, which always get all of them.
			want := runFile(shell, full, binDir, "", t.TempDir())
			if !strings.Contains(want.out, "varlatch install:") {
				t.Fatalf("the whole script did not run as expected: %+v", want)
			}
			var bad atomic.Int32
			var wg sync.WaitGroup
			lengths := make(chan int)
			for range max(2, runtime.NumCPU()) {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for n := range lengths {
						f := filepath.Join(dir, fmt.Sprintf("p%d.sh", n))
						if err := os.WriteFile(f, src[:n], 0o644); err != nil {
							t.Error(err)
							return
						}
						work := filepath.Join(dir, fmt.Sprintf("w%d", n))
						if err := os.Mkdir(work, 0o755); err != nil {
							t.Error(err)
							return
						}
						if n > closing {
							got := runFile(shell, f, binDir, "", work)
							_ = os.RemoveAll(work)
							_ = os.Remove(f)
							_ = os.Remove(f + ".log")
							if got.code != want.code || got.out != want.out || got.log != want.log {
								if bad.Add(1) <= 5 {
									t.Errorf("complete prefix of %d bytes ran differently:\ngot  %#v\nwant %#v", n, got, want)
								}
							}
							continue
						}
						got := runFile(shell, f, binDir, bashEnv, work)
						_ = os.Remove(f)
						_ = os.Remove(f + ".log")
						_ = os.RemoveAll(work)
						// The script's own messages start a line; a shell's
						// syntax error may quote the script's text inside one.
						// A file left in the working directory means something
						// ran, sentinel or not.
						ran := got.log != "" || got.files != ""
						for _, line := range strings.Split(got.out, "\n") {
							for _, m := range scriptMsgs {
								ran = ran || strings.HasPrefix(line, m)
							}
						}
						if ran {
							if bad.Add(1) <= 5 {
								t.Errorf("a prefix of %d bytes (ending %q) ran something: %+v", n, tail(src[:n]), got)
							}
						}
					}
				}()
			}
			for n := 0; n <= len(src); n++ {
				lengths <- n
			}
			close(lengths)
			wg.Wait()
			if bad.Load() > 0 {
				t.Fatalf("%d prefixes misbehaved", bad.Load())
			}
		})
	}
}

func tail(b []byte) string {
	if len(b) > 30 {
		b = b[len(b)-30:]
	}
	return string(b)
}

// --- end to end, against a local HTTPS server standing in for GitHub ---

const version = "0.50.0"

// stubCLI stands in for the varlatch binary: it reports its version, and
// its verify-release succeeds unless STUB_VERIFY=fail (the real command is
// tested in cmd/varlatch); it logs how it was called.
const stubCLI = `#!/bin/sh
printf '%s\n' "$*" >> "${STUB_LOG:-/dev/null}"
case "$1" in
  --version) echo "varlatch ${STUB_REPORTS:-0.50.0}" ;;
  verify-release) [ "${STUB_VERIFY:-}" != fail ] || { echo "signature does not verify" >&2; exit 1; } ;;
  setup) echo "setup ran" ;;
esac
`

type release struct {
	files map[string][]byte
	sums  string // overrides the computed SHA256SUMS when set
	hits  atomic.Int32
	// cutOff names a file served without its last bytes and without a
	// length, the way a dropped close-delimited response looks complete.
	cutOff string
	// redirectHTTP names a file whose request is redirected to plain HTTP.
	redirectHTTP string
}

func goArch() string { return runtime.GOARCH }

func newRelease() *release {
	r := &release{files: map[string][]byte{}}
	r.files["varlatch-"+version+"-linux-"+goArch()] = []byte(stubCLI)
	r.files["varlatchd-"+version+"-linux-"+goArch()] = []byte("#!/bin/sh\necho varlatchd\n")
	r.files["varlatchd.service"] = []byte("[Unit]\nDescription=Varlatch\n")
	r.files["SHA256SUMS.sigstore.json"] = []byte(`{"stub":true}`)
	return r
}

func (r *release) sha256sums() string {
	if r.sums != "" {
		return r.sums
	}
	var b strings.Builder
	names := make([]string, 0, len(r.files))
	for n := range r.files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if n == "SHA256SUMS.sigstore.json" {
			continue
		}
		sum := sha256.Sum256(r.files[n])
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), n)
	}
	return b.String()
}

func (r *release) serve(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		name := strings.TrimPrefix(req.URL.Path, "/")
		if name == "SHA256SUMS" {
			_, _ = w.Write([]byte(r.sha256sums()))
			return
		}
		data, ok := r.files[name]
		if !ok {
			http.NotFound(w, req)
			return
		}
		if name == r.redirectHTTP {
			http.Redirect(w, req, "http://"+req.Host+"/"+name, http.StatusFound)
			return
		}
		if name == r.cutOff {
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
			_, _ = buf.Write(data[:len(data)-10])
			_ = buf.Flush()
			_ = conn.Close()
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	return srv, ca
}

type run struct {
	code      int
	out       string
	home, dir string
	stubLog   string
	tmpdir    string // TMPDIR of the run: must be empty afterwards
}

// The production script has no way to change where files come from or
// where a server's files go; the tests run a copy with these lines edited.
const (
	baseLine = "base=https://github.com/$REPOSITORY/releases/download/v$version"
	rootLine = "root=''"
)

// edit replaces exactly one occurrence of old in src, or fails the test.
func edit(t *testing.T, src []byte, old, new string) []byte {
	t.Helper()
	if bytes.Count(src, []byte(old)) != 1 {
		t.Fatalf("install.sh no longer has exactly one %q", old)
	}
	return bytes.Replace(src, []byte(old), []byte(new), 1)
}

// install runs a copy of install.sh (stamped with version unless stamped is
// false; downloading from the test server, or from baseURL if one is given
// in env as "BASE_URL=..."; with "ROOT=..." in env, a directory standing in
// for / in --server) with the given arguments and extra environment.
func install(t *testing.T, r *release, stamped bool, args []string, env ...string) run {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the end-to-end runs serve Linux binaries")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	srv, ca := r.serve(t)
	home := t.TempDir()
	src := script(t)
	if stamped {
		src = edit(t, src, "'@VARLATCH_VERSION@'", "'"+version+"'")
	}
	base := srv.URL
	var extra []string
	for _, e := range env {
		switch {
		case strings.HasPrefix(e, "BASE_URL="):
			base = strings.TrimPrefix(e, "BASE_URL=")
		case strings.HasPrefix(e, "ROOT="):
			src = edit(t, src, rootLine, "root='"+strings.TrimPrefix(e, "ROOT=")+"'")
		default:
			extra = append(extra, e)
		}
	}
	src = edit(t, src, baseLine, "base='"+base+"'")
	file := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}
	stubLog := filepath.Join(home, "stub.log")
	tmpdir := t.TempDir()
	cmd := exec.Command("sh", append([]string{file}, args...)...)
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TMPDIR=" + tmpdir,
		"CURL_CA_BUNDLE=" + ca, "STUB_LOG=" + stubLog,
	}, extra...)
	out, _ := cmd.CombinedOutput()
	return run{cmd.ProcessState.ExitCode(), string(out), home, filepath.Join(home, ".local", "bin"), stubLog, tmpdir}
}

// emptyTmp checks a run left nothing in its TMPDIR.
func emptyTmp(t *testing.T, res run) {
	t.Helper()
	if entries, _ := os.ReadDir(res.tmpdir); len(entries) != 0 {
		t.Fatalf("the run left %d entries in TMPDIR", len(entries))
	}
}

// The production script reads nothing from the environment that changes
// where release files come from or go.
func TestNoOverridesInTheScript(t *testing.T) {
	src := string(script(t))
	for _, line := range []string{baseLine, rootLine} {
		if strings.Count(src, line) != 1 {
			t.Fatalf("expected exactly one %q", line)
		}
	}
	if regexp.MustCompile(`VARLATCH_[A-Z_]*(BASE|URL|ROOT|MIRROR)`).MatchString(src) {
		t.Fatal("install.sh reads a variable that could change where files come from or go")
	}
}

func installed(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

func TestInstallCLI(t *testing.T) {
	r := newRelease()
	res := install(t, r, true, nil)
	target := filepath.Join(res.dir, "varlatch")
	if res.code != 0 || !bytes.Equal(installed(t, target), []byte(stubCLI)) {
		t.Fatalf("exit %d: %s", res.code, res.out)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", fi.Mode())
	}
	for _, want := range []string{"Installed varlatch " + version, "Next: varlatch login"} {
		if !strings.Contains(res.out, want) {
			t.Fatalf("no %q in %s", want, res.out)
		}
	}
	// The downloaded CLI verified the signature and the file before it was
	// put in place.
	log, _ := os.ReadFile(res.stubLog)
	if !regexp.MustCompile(`verify-release --version 0\.50\.0 --sums \S+/SHA256SUMS --bundle \S+/SHA256SUMS\.sigstore\.json --file \S+=varlatch-0\.50\.0-linux-`).Match(log) {
		t.Fatalf("verify-release was not called as expected:\n%s", log)
	}
	entries, _ := os.ReadDir(res.dir)
	if len(entries) != 1 {
		t.Fatalf("left %d files in %s", len(entries), res.dir)
	}
	emptyTmp(t, res)
}

func TestInstallCLIRerun(t *testing.T) {
	r := newRelease()
	srvDir := t.TempDir()
	first := install(t, r, true, []string{"--dir", srvDir})
	second := install(t, r, true, []string{"--dir", srvDir})
	if first.code != 0 || second.code != 0 || !strings.Contains(second.out, "already installed") {
		t.Fatalf("first: %s\nsecond: %s", first.out, second.out)
	}
}

// Every failed check installs nothing.
func TestInstallRefuses(t *testing.T) {
	cli := "varlatch-" + version + "-linux-" + goArch()
	cases := map[string]struct {
		edit       func(r *release)
		args       []string
		env        []string
		unstamped  bool
		want       string
		noDownload bool
	}{
		"changed binary":        {edit: func(r *release) { r.files[cli] = append([]byte(stubCLI), '#'); r.sums = sumsFor(stubCLI, cli) }, want: "does not match SHA256SUMS"},
		"not listed":            {edit: func(r *release) { r.sums = "0000000000000000000000000000000000000000000000000000000000000000  other\n" }, want: "does not list " + cli},
		"listed twice":          {edit: func(r *release) { r.sums = sumsFor(stubCLI, cli) + sumsFor(stubCLI, cli) }, want: "does not list " + cli},
		"cut-off binary":        {edit: func(r *release) { r.cutOff = cli }, want: "varlatch install:"},
		"redirect to http":      {edit: func(r *release) { r.redirectHTTP = cli }, want: "could not download"},
		"signature fails":       {env: []string{"STUB_VERIFY=fail"}, want: "release signature does not verify"},
		"wrong version inside":  {env: []string{"STUB_REPORTS=0.49.0"}, want: "reports 'varlatch 0.49.0'"},
		"unstamped script":      {unstamped: true, want: "not from a release", noDownload: true},
		"bad version":           {args: []string{"--version", "0.50.0/../../x"}, want: "not a release version", noDownload: true},
		"version with a ref":    {args: []string{"--version", "0.50.0@main"}, want: "not a release version", noDownload: true},
		"setup flags for a CLI": {args: []string{"--", "--domain", "x"}, want: "for --server", noDownload: true},
		"unknown option":        {args: []string{"--force"}, want: "unknown option", noDownload: true},
	}
	if os.Geteuid() != 0 {
		cases["server without root"] = struct {
			edit       func(r *release)
			args       []string
			env        []string
			unstamped  bool
			want       string
			noDownload bool
		}{args: []string{"--server"}, want: "needs root", noDownload: true}
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRelease()
			if tc.edit != nil {
				tc.edit(r)
			}
			res := install(t, r, !tc.unstamped, tc.args, tc.env...)
			if res.code == 0 || !strings.Contains(res.out, tc.want) {
				t.Fatalf("exit %d, want %q in:\n%s", res.code, tc.want, res.out)
			}
			if installed(t, filepath.Join(res.dir, "varlatch")) != nil {
				t.Fatal("something was installed")
			}
			emptyTmp(t, res)
			if tc.noDownload && r.hits.Load() != 0 {
				t.Fatalf("%d requests before refusing", r.hits.Load())
			}
		})
	}
}

func sumsFor(content, name string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

// An unsupported platform is refused before anything is downloaded.
func TestInstallRefusesOtherPlatforms(t *testing.T) {
	for _, tc := range []struct{ s, m, want string }{
		{"SunOS", "x86_64", "no varlatch for SunOS"},
		{"Linux", "riscv64", "no varlatch for riscv64"},
		{"MINGW64_NT-10.0", "x86_64", "use install.ps1"},
	} {
		bin := t.TempDir()
		stub := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in -s) echo %s ;; -m) echo %s ;; esac\n", tc.s, tc.m)
		if err := os.WriteFile(filepath.Join(bin, "uname"), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
		r := newRelease()
		res := install(t, r, true, nil, "PATH="+bin+":"+os.Getenv("PATH"))
		if res.code == 0 || !strings.Contains(res.out, tc.want) || r.hits.Load() != 0 {
			t.Fatalf("%s/%s: exit %d, %d requests: %s", tc.s, tc.m, res.code, r.hits.Load(), res.out)
		}
	}
}

// Plain HTTP is refused, even if a test points the script at it.
func TestInstallRefusesHTTP(t *testing.T) {
	r := newRelease()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { r.hits.Add(1) }))
	defer srv.Close()
	res := install(t, newRelease(), true, nil, "BASE_URL="+srv.URL)
	if res.code == 0 || !strings.Contains(res.out, "could not download") || r.hits.Load() != 0 {
		t.Fatalf("exit %d, %d requests: %s", res.code, r.hits.Load(), res.out)
	}
}

// As root, a server install puts both binaries and the unit in place
// (under a test directory standing in for / here), and a rerun changes
// nothing.
func TestInstallServerAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (run the tests in a container as root to cover it)")
	}
	r := newRelease()
	root := t.TempDir()
	res := install(t, r, true, []string{"--server"}, "ROOT="+root)
	if res.code != 0 || !strings.Contains(res.out, "Next: varlatch setup") {
		t.Fatalf("exit %d: %s", res.code, res.out)
	}
	for path, mode := range map[string]os.FileMode{
		"usr/local/bin/varlatch": 0o755, "usr/local/bin/varlatchd": 0o755, "etc/systemd/system/varlatchd.service": 0o644,
	} {
		fi, err := os.Stat(filepath.Join(root, path))
		if err != nil || fi.Mode().Perm() != mode {
			t.Fatalf("%s: %v %v", path, fi, err)
		}
	}
	log, _ := os.ReadFile(res.stubLog)
	if !bytes.Contains(log, []byte("=varlatchd-"+version+"-linux-")) || !bytes.Contains(log, []byte("=varlatchd.service")) {
		t.Fatalf("the server files were not verified:\n%s", log)
	}
	again := install(t, r, true, []string{"--server"}, "ROOT="+root)
	if again.code != 0 || !strings.Contains(again.out, "already installed") {
		t.Fatalf("rerun: %s", again.out)
	}
}

// The production server path, unedited but for the download address: as
// root it writes /usr/local/bin and /etc/systemd/system, runs systemctl and
// execs varlatch setup, so it runs only in a disposable container
// (VARLATCH_TEST_DISPOSABLE_ROOT=1). exec skips the EXIT trap; the staging
// directory must be gone anyway.
func TestInstallServerProductionPath(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("VARLATCH_TEST_DISPOSABLE_ROOT") != "1" {
		t.Skip("needs root in a disposable container: VARLATCH_TEST_DISPOSABLE_ROOT=1")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\necho \"systemctl $*\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := newRelease()
	res := install(t, r, true, []string{"--server", "--", "--non-interactive"}, "PATH="+bin+":"+os.Getenv("PATH"))
	if res.code != 0 || !strings.Contains(res.out, "systemctl daemon-reload") || !strings.Contains(res.out, "setup ran") {
		t.Fatalf("exit %d: %s", res.code, res.out)
	}
	log, _ := os.ReadFile(res.stubLog)
	if !bytes.Contains(log, []byte("setup --non-interactive")) {
		t.Fatalf("setup was not started with the flags after --:\n%s", log)
	}
	for _, p := range []string{"/usr/local/bin/varlatch", "/usr/local/bin/varlatchd", "/etc/systemd/system/varlatchd.service"} {
		if _, err := os.Stat(p); err != nil {
			t.Fatal(err)
		}
	}
	emptyTmp(t, res)
}
