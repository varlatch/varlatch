// SPDX-License-Identifier: Apache-2.0

package install

// G8's published-asset half (ADR-0059; internal docs/design/go-step6.md,
// slice 6.1b), against a release published on GitHub: the installers
// install it from github.com and a rerun changes nothing, and they fail
// closed on a bad signature, a cut-off asset and a wrong platform with
// that release's real files, tampered copies served from a local server
// (a copy of the script pointed at it, as the other end-to-end tests do).
// The identity check is verify-release's, which the installers run: the
// release's real binary refuses its real SHA256SUMS and signature as any
// other version's. Every check runs the real binary and Sigstore's live
// trusted root.
//
// It runs only when asked: VARLATCH_TEST_PUBLISHED=<version>, as the
// published-release workflow sets it (and Windows also needs
// VARLATCH_TEST_DISPOSABLE=1: the install changes the user PATH).

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var versionRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)

// published is a release on GitHub, its files downloaded once and checked
// against its SHA256SUMS.
type published struct {
	version string
	mu      sync.Mutex
	files   map[string][]byte
	sums    map[string]string // name -> SHA-256, from SHA256SUMS
}

var (
	publishedOnce sync.Once
	publishedRel  *published
)

func publishedRelease(t *testing.T) *published {
	t.Helper()
	v := os.Getenv("VARLATCH_TEST_PUBLISHED")
	if v == "" {
		t.Skip("set VARLATCH_TEST_PUBLISHED=<version> to test a published release (the published-release workflow does)")
	}
	if !versionRE.MatchString(v) {
		t.Fatalf("VARLATCH_TEST_PUBLISHED=%q is not a release version", v)
	}
	publishedOnce.Do(func() { publishedRel = &published{version: v, files: map[string][]byte{}} })
	p := publishedRel
	if p.sums == nil {
		sums := p.get(t, "SHA256SUMS")
		p.sums = map[string]string{}
		sc := bufio.NewScanner(bytes.NewReader(sums))
		for sc.Scan() {
			line := strings.TrimSuffix(sc.Text(), "\r")
			if len(line) > 66 {
				p.sums[strings.TrimPrefix(line[66:], "*")] = line[:64]
			}
		}
	}
	return p
}

// get downloads a release file from github.com once; anything but
// SHA256SUMS and its signature must match its line.
func (p *published) get(t *testing.T, name string) []byte {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if b, ok := p.files[name]; ok {
		return b
	}
	url := "https://github.com/varlatch/varlatch/releases/download/v" + p.version + "/" + name
	client := &http.Client{Timeout: 5 * time.Minute}
	res, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("%s: %s", url, res.Status)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if name != "SHA256SUMS" && name != "SHA256SUMS.sigstore.json" {
		sum := sha256.Sum256(b)
		if want := p.sums[name]; hex.EncodeToString(sum[:]) != want {
			t.Fatalf("%s as downloaded does not match SHA256SUMS", name)
		}
	}
	p.files[name] = b
	return b
}

func (p *published) cli(goos, goarch string) string {
	name := "varlatch-" + p.version + "-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// tampered serves the release's files at /v<version>/<file> over HTTPS:
// each as published, or as changed for the case.
type tampered struct {
	p      *published
	t      *testing.T
	change map[string][]byte // served instead
	cutOff string            // served without its last bytes and its length
}

func (tp *tampered) serve() *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, ok := strings.CutPrefix(r.URL.Path, "/v"+tp.p.version+"/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		if _, listed := tp.p.sums[name]; !listed && name != "SHA256SUMS" && name != "SHA256SUMS.sigstore.json" {
			http.NotFound(w, r)
			return
		}
		body, changed := tp.change[name]
		if !changed {
			body = tp.p.get(tp.t, name)
		}
		if name == tp.cutOff {
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
			_, _ = buf.Write(body[:len(body)/2])
			_ = buf.Flush()
			_ = conn.Close()
			return
		}
		_, _ = w.Write(body)
	}))
	tp.t.Cleanup(srv.Close)
	return srv
}

// badSums is SHA256SUMS with one more line: every asset still listed as
// published, the signature no longer over it.
func (p *published) badSums(t *testing.T) []byte {
	return append(bytes.Clone(p.get(t, "SHA256SUMS")), []byte(strings.Repeat("0", 64)+"  extra.txt\n")...)
}

// runSh runs a copy of install.sh (stamped with the version; pointed at
// base unless it is "") with env, in a fresh HOME; it answers the exit
// status, the output and the installed file's path.
func runSh(t *testing.T, p *published, base, ca string, env ...string) (int, string, string) {
	t.Helper()
	src := edit(t, script(t), "'@VARLATCH_VERSION@'", "'"+p.version+"'")
	if base != "" {
		src = edit(t, src, baseLine, "base='"+base+"'")
	}
	file := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	return runShIn(t, file, home, ca, env...)
}

func runShIn(t *testing.T, file, home, ca string, env ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command("sh", file)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TMPDIR=" + t.TempDir()}, env...)
	if ca != "" {
		cmd.Env = append(cmd.Env, "CURL_CA_BUNDLE="+ca)
	}
	out, _ := cmd.CombinedOutput()
	return cmd.ProcessState.ExitCode(), string(out), filepath.Join(home, ".local", "bin", "varlatch")
}

func caFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	return ca
}

// unameArch is uname -m's word for GOARCH.
func unameArch(goarch string) string {
	if goarch == "amd64" {
		return "x86_64"
	}
	return "arm64"
}

func TestPublishedInstallSh(t *testing.T) {
	p := publishedRelease(t)
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("install.sh is for Linux and macOS")
	}
	cli := p.cli(runtime.GOOS, runtime.GOARCH)

	t.Run("from github.com, then again", func(t *testing.T) {
		src := edit(t, script(t), "'@VARLATCH_VERSION@'", "'"+p.version+"'")
		file := filepath.Join(t.TempDir(), "install.sh")
		if err := os.WriteFile(file, src, 0o644); err != nil {
			t.Fatal(err)
		}
		home := t.TempDir()
		code, out, target := runShIn(t, file, home, "")
		if got, _ := os.ReadFile(target); code != 0 || !bytes.Equal(got, p.get(t, cli)) {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		if v, err := exec.Command(target, "--version").Output(); err != nil || !strings.HasPrefix(string(v), "varlatch "+p.version) {
			t.Fatalf("--version: %q %v", v, err)
		}
		code, out, _ = runShIn(t, file, home, "")
		if code != 0 || !strings.Contains(out, "already installed") {
			t.Fatalf("rerun: exit %d:\n%s", code, out)
		}
	})

	for name, c := range map[string]struct {
		tp   func(*tampered)
		path func(t *testing.T) string // a directory put first on PATH
		want string
	}{
		"a bad signature": {tp: func(tp *tampered) { tp.change = map[string][]byte{"SHA256SUMS": p.badSums(t)} }, want: "release signature does not verify"},
		"a cut-off asset": {tp: func(tp *tampered) { tp.cutOff = cli }, want: "does not match SHA256SUMS"},
		"a wrong platform": {path: func(t *testing.T) string {
			// The other system's binary for this processor: listed, so it
			// matches its line, and it cannot run here.
			other := "Darwin"
			if runtime.GOOS == "darwin" {
				other = "Linux"
			}
			bin := t.TempDir()
			stub := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in -s) echo %s ;; -m) echo %s ;; esac\n", other, unameArch(runtime.GOARCH))
			if err := os.WriteFile(filepath.Join(bin, "uname"), []byte(stub), 0o755); err != nil {
				t.Fatal(err)
			}
			return bin
		}, want: "does not run on this machine"},
	} {
		t.Run(name, func(t *testing.T) {
			tp := &tampered{p: p, t: t}
			if c.tp != nil {
				c.tp(tp)
			}
			srv := tp.serve()
			var env []string
			if c.path != nil {
				env = append(env, "PATH="+c.path(t)+":"+os.Getenv("PATH"))
			}
			code, out, target := runSh(t, p, srv.URL+"/v"+p.version, caFile(t, srv), env...)
			if code == 0 || !strings.Contains(out, c.want) || !strings.Contains(out, "nothing was installed") && !strings.Contains(out, "does not verify") {
				t.Fatalf("exit %d, want %q:\n%s", code, c.want, out)
			}
			if _, err := os.Stat(target); err == nil {
				t.Fatal("something was installed")
			}
		})
	}
}

// The identity the release was signed for is its own version's tag: the
// release's binary verifies its real SHA256SUMS for that version, and
// refuses the same files as another version's.
func TestPublishedIdentity(t *testing.T) {
	p := publishedRelease(t)
	cli := p.cli(runtime.GOOS, runtime.GOARCH)
	dir := t.TempDir()
	write := func(name string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, p.get(t, name), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	bin, sums, bundle := write(cli), write("SHA256SUMS"), write("SHA256SUMS.sigstore.json")
	verify := func(version string) (string, error) {
		out, err := exec.Command(bin, "verify-release", "--version", version, "--sums", sums, "--bundle", bundle, "--file", bin+"="+cli).CombinedOutput()
		return string(out), err
	}
	if out, err := verify(p.version); err != nil {
		t.Fatalf("its own version: %v\n%s", err, out)
	}
	// Refused: exit 1 and no line saying it is signed. (Its message names
	// the identity, a URL with "@refs/tags/", which the CLI's fail-safe on
	// stderr masks: the status is what is checked.)
	if out, err := verify(p.version + ".another"); err == nil || strings.Contains(out, "is signed by") || strings.Contains(out, "matches SHA256SUMS") {
		t.Fatalf("another version's identity: %v\n%s", err, out)
	}
}

func TestPublishedInstallPS1(t *testing.T) {
	p := publishedRelease(t)
	if runtime.GOOS != "windows" || os.Getenv("VARLATCH_TEST_DISPOSABLE") != "1" {
		t.Skip("needs a disposable Windows machine: VARLATCH_TEST_DISPOSABLE=1")
	}
	cli := p.cli("windows", runtime.GOARCH)
	spaced := func(t *testing.T) string {
		d := filepath.Join(t.TempDir(), "with space")
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		return d
	}
	run := func(t *testing.T, host string, src []byte, local string, env ...string) (int, string, string) {
		t.Helper()
		file := filepath.Join(spaced(t), "install.ps1")
		if err := os.WriteFile(file, src, 0o644); err != nil {
			t.Fatal(err)
		}
		tmp := spaced(t)
		cmd := exec.Command(host, psArgs(file)...)
		for _, e := range os.Environ() {
			if !strings.HasPrefix(strings.ToUpper(e), "PROCESSOR_ARCHITEW6432=") {
				cmd.Env = append(cmd.Env, e)
			}
		}
		cmd.Env = append(cmd.Env, append([]string{"LOCALAPPDATA=" + local, "TEMP=" + tmp, "TMP=" + tmp}, env...)...)
		out, _ := cmd.CombinedOutput()
		return cmd.ProcessState.ExitCode(), string(out), filepath.Join(local, "Programs", "Varlatch", "varlatch.exe")
	}
	stamped := func(t *testing.T) []byte { return edit(t, ps1Script(t), "'@VARLATCH_VERSION@'", "'"+p.version+"'") }

	for name, host := range psHosts(t) {
		t.Run(name, func(t *testing.T) {
			t.Run("from github.com, then again", func(t *testing.T) {
				local := spaced(t)
				code, out, target := run(t, host, stamped(t), local)
				if got, _ := os.ReadFile(target); code != 0 || !bytes.Equal(got, p.get(t, cli)) {
					t.Fatalf("exit %d:\n%s", code, out)
				}
				if v, err := exec.Command(target, "--version").Output(); err != nil || !strings.HasPrefix(string(v), "varlatch "+p.version) {
					t.Fatalf("--version: %q %v", v, err)
				}
				code, out, _ = run(t, host, stamped(t), local)
				if code != 0 || !strings.Contains(out, "already installed") {
					t.Fatalf("rerun: exit %d:\n%s", code, out)
				}
			})
			cases := map[string]struct {
				tp   func(*tampered)
				env  []string
				want string
			}{
				"a bad signature": {tp: func(tp *tampered) { tp.change = map[string][]byte{"SHA256SUMS": p.badSums(t)} }, want: "release signature does not verify"},
				"a cut-off asset": {tp: func(tp *tampered) { tp.cutOff = cli }, want: "varlatch install:"},
			}
			if runtime.GOARCH == "amd64" {
				// The arm64 build, listed, matching its line: an x64 Windows
				// cannot run it.
				cases["a wrong platform"] = struct {
					tp   func(*tampered)
					env  []string
					want string
				}{env: []string{"PROCESSOR_ARCHITECTURE=ARM64"}, want: "does not run on this machine"}
			}
			for caseName, c := range cases {
				t.Run(caseName, func(t *testing.T) {
					tp := &tampered{p: p, t: t}
					if c.tp != nil {
						c.tp(tp)
					}
					srv := tp.serve()
					src := ps1Trusting(t, stamped(t), srv.URL+"/v", sha1.Sum(srv.Certificate().Raw))
					code, out, target := run(t, host, src, spaced(t), c.env...)
					if code == 0 || !strings.Contains(out, c.want) {
						t.Fatalf("exit %d, want %q:\n%s", code, c.want, out)
					}
					if _, err := os.Stat(target); err == nil {
						t.Fatal("something was installed")
					}
				})
			}
		})
	}
}
