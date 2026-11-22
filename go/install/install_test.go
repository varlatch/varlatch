// SPDX-License-Identifier: Apache-2.0

// Package install tests install.sh (ADR-0059 Decision 8, gate G8).
package install

import (
	"bytes"
	"context"
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
	"time"
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, file)
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

func hasScriptMessage(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		for _, m := range scriptMsgs {
			if strings.HasPrefix(line, m) {
				return true
			}
		}
	}
	return false
}

func prefixRan(got result) bool {
	// The script's own messages start a line; a shell's syntax error may
	// quote the script's text inside one. A file left in the working
	// directory means something ran, sentinel or not.
	return got.log != "" || got.files != "" || hasScriptMessage(got.out)
}

// runBashSpan sources bashEnv once in a single bash process and evaluates
// every prefix src[:n] for n in [lo, hi) inside an isolated subshell, with no
// per-prefix process startup or per-prefix temp file.
func runBashSpan(shell, srcFile string, srcLen, lo, hi int, binDir, bashEnv, work, logFile, outFile string) (ran bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// Define _run before sourcing bashEnv so sentinel aliases never rewrite
	// the driver, and invoke builtins via "builtin" (which sentinels never
	// shadow). LC_ALL=C makes ${var:0:n} slice by byte. Each prefix runs in a
	// subshell with stdin closed so syntax errors, set -eu, exit, or traps
	// stay isolated.
	const driver = `
LC_ALL=C
builtin export LC_ALL
_run() {
	(
		builtin cd "$2" || builtin exit 99
		HOME=$2
		SENTINEL_LOG=$3
		builtin export HOME SENTINEL_LOG
		builtin eval -- "${_SRC:0:$1}" </dev/null >>"$4" 2>&1
	)
}
IFS= builtin read -r -d '' _SRC < "$1"
if (( ${#_SRC} != $8 )); then
	builtin exit 97
fi
builtin source "$2" || builtin exit 98
_N=$3
_END=$4
while (( _N < _END )); do
	_run "$_N" "$5" "$6" "$7"
	(( _N += 1 ))
done
builtin exit 0
`
	cmd := exec.CommandContext(ctx, shell, "-c", driver, "_",
		srcFile, bashEnv,
		fmt.Sprint(lo), fmt.Sprint(hi),
		work, logFile, outFile,
		fmt.Sprint(srcLen),
	)
	cmd.Env = []string{"PATH=" + binDir, "HOME=" + work, "SENTINEL_LOG=" + logFile}
	if out, err := cmd.CombinedOutput(); err != nil {
		return true, fmt.Errorf("bash prefix worker [%d,%d) failed: %w: %s", lo, hi, err, out)
	}
	if b, _ := os.ReadFile(logFile); len(b) > 0 {
		return true, nil
	}
	if entries, _ := os.ReadDir(work); len(entries) > 0 {
		return true, nil
	}
	if out, _ := os.ReadFile(outFile); hasScriptMessage(string(out)) {
		return true, nil
	}
	return false, nil
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
	binDir, bashEnv := sentinels(t, []byte("say() { :; }\nsay uname\n"))
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
		} else if !strings.Contains(got.log, "COMMAND uname") {
			t.Errorf("%s: the command sentinel did not run: %+v", name, got)
		}
		if name == "bash" {
			// The batched bash runner must catch the same sentinels, file
			// creation, early group closes, and script messages.
			cases := map[string]string{
				"command":     "uname\n{\n",
				"function":    "say\n{\n",
				"redirect":    ": > leaked\n{\n",
				"message":     "printf 'varlatch install: leaked\\n'\n{\n",
				"early-close": "{\n:\n}\nuname\n{\n",
			}
			for label, body := range cases {
				d := t.TempDir()
				p := filepath.Join(d, "bad.sh")
				work := filepath.Join(d, "work")
				if err := os.Mkdir(work, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
				ran, err := runBashSpan(shell, p, len(body), len(body), len(body)+1, binDir, bashEnv, work, filepath.Join(d, "log"), filepath.Join(d, "out"))
				if err != nil {
					t.Errorf("bash batch %s: %v", label, err)
				} else if !ran {
					t.Errorf("bash batch %s: did not detect execution", label)
				}
			}
		}
	}
}

// G8: every prefix of install.sh, under every shell, runs nothing or runs
// the whole script.
func TestEveryPrefixRunsNothingOrEverything(t *testing.T) {
	src := script(t)
	if bytes.IndexByte(src, 0) >= 0 {
		t.Fatal("install.sh contains a NUL byte")
	}
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
			if name == "bash" {
				// Sourcing bashEnv per prefix is O(n^2) in script length:
				// batch cut-off prefixes in bash workers that source bashEnv
				// once and slice the script in memory, falling back to
				// runFile to pinpoint any failing prefix.
				type span struct{ lo, hi int }
				const batchSize = 512
				batches := make(chan span)
				var wg sync.WaitGroup
				for range max(2, runtime.NumCPU()) {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for sp := range batches {
							bdir := filepath.Join(dir, fmt.Sprintf("b%d", sp.lo))
							work := filepath.Join(bdir, "work")
							if err := os.MkdirAll(work, 0o755); err != nil {
								t.Error(err)
								return
							}
							logFile := filepath.Join(bdir, "sentinel.log")
							outFile := filepath.Join(bdir, "out.log")
							ran, err := runBashSpan(shell, full, len(src), sp.lo, sp.hi, binDir, bashEnv, work, logFile, outFile)
							if ran || err != nil {
								foundHit := false
								for n := sp.lo; n < sp.hi; n++ {
									f := filepath.Join(bdir, fmt.Sprintf("p%d.sh", n))
									if wErr := os.WriteFile(f, src[:n], 0o644); wErr != nil {
										t.Error(wErr)
										break
									}
									pw := filepath.Join(bdir, fmt.Sprintf("w%d", n))
									if mkErr := os.Mkdir(pw, 0o755); mkErr != nil {
										t.Error(mkErr)
										break
									}
									got := runFile(shell, f, binDir, bashEnv, pw)
									if prefixRan(got) {
										foundHit = true
										if bad.Add(1) <= 5 {
											t.Errorf("a prefix of %d bytes (ending %q) ran something: %+v", n, tail(src[:n]), got)
										}
									}
								}
								if !foundHit {
									if bad.Add(1) <= 5 {
										t.Errorf("batch [%d,%d) reported execution (err=%v) without an individual hit", sp.lo, sp.hi, err)
									}
								}
							}
							_ = os.RemoveAll(bdir)
						}
					}()
				}
				for lo := 0; lo <= closing; lo += batchSize {
					batches <- span{lo, min(lo+batchSize, closing+1)}
				}
				close(batches)
				wg.Wait()

				// Also verify a sample of cut-off prefixes via direct
				// bash <file> invocation with BASH_ENV.
				sample := []int{0, closing}
				for i := 1; i <= 12; i++ {
					sample = append(sample, closing*i/13)
				}
				for _, n := range sample {
					f := filepath.Join(dir, fmt.Sprintf("s%d.sh", n))
					work := filepath.Join(dir, fmt.Sprintf("sw%d", n))
					if err := os.Mkdir(work, 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(f, src[:n], 0o644); err != nil {
						t.Fatal(err)
					}
					got := runFile(shell, f, binDir, bashEnv, work)
					_ = os.RemoveAll(work)
					_ = os.Remove(f)
					_ = os.Remove(f + ".log")
					if prefixRan(got) {
						if bad.Add(1) <= 5 {
							t.Errorf("direct run of a %d-byte prefix (ending %q) ran something: %+v", n, tail(src[:n]), got)
						}
					}
				}

				for n := closing + 1; n <= len(src); n++ {
					f := filepath.Join(dir, fmt.Sprintf("c%d.sh", n))
					work := filepath.Join(dir, fmt.Sprintf("cw%d", n))
					if err := os.Mkdir(work, 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(f, src[:n], 0o644); err != nil {
						t.Fatal(err)
					}
					got := runFile(shell, f, binDir, "", work)
					_ = os.RemoveAll(work)
					_ = os.Remove(f)
					_ = os.Remove(f + ".log")
					if got.code != want.code || got.out != want.out || got.log != want.log {
						if bad.Add(1) <= 5 {
							t.Errorf("complete prefix of %d bytes ran differently:\ngot  %#v\nwant %#v", n, got, want)
						}
					}
				}
			} else {
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
							if prefixRan(got) {
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
			}
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
	// servedOnly answers only a serving installation's paths.
	servedOnly bool
	// redirect names a file whose request is redirected to the same file
	// at the server's root.
	redirect string
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
		// A serving installation's layout (/cli/v<version>/<file>) too.
		name := strings.TrimPrefix(strings.TrimPrefix(req.URL.Path, "/cli/v"+version), "/")
		if r.servedOnly && !strings.HasPrefix(req.URL.Path, "/cli/v"+version+"/") {
			http.NotFound(w, req)
			return
		}
		if name == "SHA256SUMS" {
			_, _ = w.Write([]byte(r.sha256sums()))
			return
		}
		data, ok := r.files[name]
		if !ok {
			http.NotFound(w, req)
			return
		}
		if name == r.redirect && strings.HasPrefix(req.URL.Path, "/cli/") {
			http.Redirect(w, req, "/"+name, http.StatusFound)
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
		t.Fatalf("the script no longer has exactly one %q", old)
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
		case strings.HasPrefix(e, "ORIGIN="):
			// As a serving installation stamps it; "server" is the test's.
			origin := strings.TrimPrefix(e, "ORIGIN=")
			if origin == "server" {
				origin = srv.URL
			}
			src = edit(t, src, "ORIGIN=''", "ORIGIN='"+origin+"'")
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

// --- the TypeScript CLI already on PATH (decision 11) ---

// tsCLI stands in for the TypeScript CLI's single-file build, with its
// banner as esbuild writes it.
const tsCLI = "#!/usr/bin/env node\n/*! Varlatch CLI. Copyright 2026 Robotsson. SPDX-License-Identifier: Apache-2.0. */\nconsole.log('varlatch 0.22.4');\n"

// overTypeScript puts tsCLI at dir/varlatch, and a stand-in for the store
// both CLIs share under home, then installs into dir.
func overTypeScript(t *testing.T, r *release, env ...string) (res run, dir, home string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "bin")
	home = t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "varlatch"), []byte(tsCLI), 0o755); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(home, ".config", "varlatch")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "config.json"), []byte(`{"server":"https://vault.example.invalid"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res = install(t, r, true, []string{"--dir", dir}, append([]string{"HOME=" + home}, env...)...)
	return res, dir, home
}

// files lists dir's entries with their content.
func files(t *testing.T, dir string) map[string]string {
	t.Helper()
	got := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		got[e.Name()] = string(b)
	}
	return got
}

func storeUnchanged(t *testing.T, home string) {
	t.Helper()
	if b, _ := os.ReadFile(filepath.Join(home, ".config", "varlatch", "config.json")); string(b) != `{"server":"https://vault.example.invalid"}`+"\n" {
		t.Fatalf("the store changed: %q", b)
	}
}

func TestInstallReplacesTheTypeScriptCLI(t *testing.T) {
	res, dir, home := overTypeScript(t, newRelease())
	if res.code != 0 || !strings.Contains(res.out, "Replaced the TypeScript CLI at "+filepath.Join(dir, "varlatch")) {
		t.Fatalf("exit %d: %s", res.code, res.out)
	}
	if got := files(t, dir); len(got) != 1 || got["varlatch"] != stubCLI {
		t.Fatalf("left %q", got)
	}
	storeUnchanged(t, home)
	emptyTmp(t, res)
}

// On a host with a Compose installation the TypeScript CLI stays, as
// varlatch-ts, for that installation's host commands.
func TestInstallKeepsTheTypeScriptCLIForCompose(t *testing.T) {
	for _, marker := range []string{"varlatch-install.json", "docker-compose.yml"} {
		t.Run(marker, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "srv", "varlatch"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "srv", "varlatch", marker), []byte("{}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			res, dir, home := overTypeScript(t, newRelease(), "ROOT="+root)
			if res.code != 0 || !strings.Contains(res.out, "Kept the TypeScript CLI as "+filepath.Join(dir, "varlatch-ts")) {
				t.Fatalf("exit %d: %s", res.code, res.out)
			}
			if got := files(t, dir); len(got) != 2 || got["varlatch"] != stubCLI || got["varlatch-ts"] != tsCLI {
				t.Fatalf("left %q", got)
			}
			if fi, _ := os.Stat(filepath.Join(dir, "varlatch-ts")); fi.Mode().Perm() != 0o755 {
				t.Fatalf("varlatch-ts mode %v", fi.Mode())
			}
			storeUnchanged(t, home)
			emptyTmp(t, res)
		})
	}
}

// Nothing changes when the TypeScript CLI cannot be kept, or when the new
// varlatch does not run where it was put.
func TestInstallLeavesTheTypeScriptCLI(t *testing.T) {
	t.Run("another varlatch-ts", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "srv", "varlatch"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "srv", "varlatch", "docker-compose.yml"), []byte("services: {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		r := newRelease()
		dir := filepath.Join(t.TempDir(), "bin")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range map[string]string{"varlatch": tsCLI, "varlatch-ts": "#!/bin/sh\necho mine\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		res := install(t, r, true, []string{"--dir", dir}, "ROOT="+root)
		if res.code == 0 || !strings.Contains(res.out, "varlatch-ts exists and is not the TypeScript CLI") {
			t.Fatalf("exit %d: %s", res.code, res.out)
		}
		if got := files(t, dir); len(got) != 2 || got["varlatch"] != tsCLI || got["varlatch-ts"] != "#!/bin/sh\necho mine\n" {
			t.Fatalf("left %q", got)
		}
	})
	t.Run("the new varlatch does not run there", func(t *testing.T) {
		r := newRelease()
		// Runs from the staging directory, fails from the target's.
		r.files["varlatch-"+version+"-linux-"+goArch()] = []byte("#!/bin/sh\ncase \"$0\" in */bin/varlatch) exit 1 ;; esac\n" + strings.TrimPrefix(stubCLI, "#!/bin/sh\n"))
		res, dir, home := overTypeScript(t, r)
		if res.code == 0 || !strings.Contains(res.out, "the TypeScript CLI was put back") {
			t.Fatalf("exit %d: %s", res.code, res.out)
		}
		if got := files(t, dir); len(got) != 1 || got["varlatch"] != tsCLI {
			t.Fatalf("left %q", got)
		}
		storeUnchanged(t, home)
		emptyTmp(t, res)
	})
}

// --- from a serving installation (varlatchd's serve_cli; decision 12) ---

func TestInstallFromAnInstallation(t *testing.T) {
	r := newRelease()
	r.servedOnly = true
	res := install(t, r, true, nil, "ORIGIN=server")
	target := filepath.Join(res.dir, "varlatch")
	if res.code != 0 || !bytes.Equal(installed(t, target), []byte(stubCLI)) {
		t.Fatalf("exit %d: %s", res.code, res.out)
	}
	if !regexp.MustCompile(`Next: varlatch login --server https://127\.0\.0\.1:[0-9]+\n`).MatchString(res.out) {
		t.Fatalf("no next step naming the installation in:\n%s", res.out)
	}
	// The downloaded CLI still checks the signature, as from github.com.
	log, _ := os.ReadFile(res.stubLog)
	if !regexp.MustCompile(`verify-release --version 0\.50\.0 --sums \S+/SHA256SUMS --bundle \S+/SHA256SUMS\.sigstore\.json --file \S+=varlatch-0\.50\.0-linux-`).Match(log) {
		t.Fatalf("verify-release was not called as expected:\n%s", log)
	}
	emptyTmp(t, res)
}

// Plain http only to this machine, as the installation serves it there.
func TestInstallFromALoopbackInstallation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the end-to-end runs serve Linux binaries")
	}
	r := newRelease()
	r.servedOnly = true
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		name := strings.TrimPrefix(req.URL.Path, "/cli/v"+version+"/")
		if name == "SHA256SUMS" {
			_, _ = w.Write([]byte(r.sha256sums()))
			return
		}
		if b, ok := r.files[name]; ok && strings.HasPrefix(req.URL.Path, "/cli/") {
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, req)
	}))
	defer plain.Close()
	res := install(t, r, true, nil, "ORIGIN="+plain.URL)
	if res.code != 0 || !strings.Contains(res.out, "Next: varlatch login --server "+plain.URL+"\n") {
		t.Fatalf("exit %d: %s", res.code, res.out)
	}
}

func TestInstallFromAnInstallationRefuses(t *testing.T) {
	for name, c := range map[string]struct {
		origin, want string
		args         []string
		edit         func(*release)
		noDownload   bool
	}{
		"plain http elsewhere":   {origin: "http://vault.example.invalid", want: "neither https: nor http: on this machine", noDownload: true},
		"an address with a user": {origin: "https://user@vault.example.invalid", want: "not an address to install from", noDownload: true},
		"a server":               {origin: "server", args: []string{"--server"}, want: "a server installs from github.com", noDownload: true},
		"a redirect":             {origin: "server", edit: func(r *release) { r.redirect = "varlatch-" + version + "-linux-" + goArch() }, want: "a redirect is never followed"},
		"a signature that fails": {origin: "server", want: "release signature does not verify"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRelease()
			r.servedOnly = true
			if c.edit != nil {
				c.edit(r)
			}
			env := []string{"ORIGIN=" + c.origin}
			if name == "a signature that fails" {
				env = append(env, "STUB_VERIFY=fail")
			}
			res := install(t, r, true, c.args, env...)
			if res.code == 0 || !strings.Contains(res.out, c.want) {
				t.Fatalf("exit %d, want %q in:\n%s", res.code, c.want, res.out)
			}
			if installed(t, filepath.Join(res.dir, "varlatch")) != nil {
				t.Fatal("something was installed")
			}
			if c.noDownload && r.hits.Load() != 0 {
				t.Fatalf("%d requests before refusing", r.hits.Load())
			}
			emptyTmp(t, res)
		})
	}
}
