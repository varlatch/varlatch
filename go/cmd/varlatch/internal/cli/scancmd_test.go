// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/scan"
)

const (
	scanAPIKey = "scan-key-aaaabbbbccccdddd"
	scanOldKey = "scan-key-oldoldoldoldold1"
	scanDBPass = "hunter2-hunter2-hunter2"
)

type scanServer struct {
	mu       sync.Mutex
	requests []string
	bodies   []string
}

// newScanServer answers /v1/meta and the disclosure with items, and
// records every request.
func newScanServer(t *testing.T, items string) (*scanServer, string) {
	s := &scanServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.requests = append(s.requests, r.Method+" "+r.URL.Path)
		s.bodies = append(s.bodies, string(body))
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/meta":
			_, _ = io.WriteString(w, `{"serverVersion":"0.22.0","apiMajor":1,"capabilities":["secrets.disclosure-purpose"]}`)
		case strings.HasSuffix(r.URL.Path, "/disclosures"):
			_, _ = io.WriteString(w, `{"items":`+items+`,"withheld":[]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return s, srv.URL
}

const scanItems = `[{"name":"API_KEY","versionId":"ver_api2","value":"` + scanAPIKey + `","retiring":{"versionId":"ver_api1","value":"` + scanOldKey + `"}},` +
	`{"name":"DB_PASS","versionId":"ver_db","value":"` + scanDBPass + `"},{"name":"PIN","versionId":"ver_pin","value":"1234567"}]`

// scanRepo is a project directory for server, the working directory from
// here on.
func scanRepo(t *testing.T, server string, files map[string]string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files["varlatch.toml"] = "server = \"" + server + "\"\norganization = \"acme\"\nproject = \"web\"\ndefault_environment = \"dev\"\n"
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, path)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, path), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	return dir
}

func runScan(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Main(append([]string{"scan"}, args...), MapEnv{"VARLATCH_TOKEN": "vlt_svc_scanAAAAAA", "HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir()},
		IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
	return code, stdout.String(), stderr.String()
}

// TestScanNeverShowsAValue: findings name the path, line, column, item and
// version; no output, diagnostic or file the scan writes holds a value,
// whatever form the file holds it in. A value the scan holds is a value in
// flight: a path that holds one is shown with it redacted (go/README.md,
// `scan-values-in-flight`).
func TestScanNeverShowsAValue(t *testing.T) {
	_, server := newScanServer(t, scanItems)
	dir := scanRepo(t, server, map[string]string{
		"dist/app.js":              "var k=\"" + scanAPIKey + "\";\nvar b=\"" + base64.StdEncoding.EncodeToString([]byte("user:"+scanOldKey)) + "\";\n",
		"named/leak-" + scanDBPass: scanDBPass + "\n",
		"dist/two.txt":             "CANARY " + scanAPIKey + " CANARY " + scanDBPass + " CANARY\n",
		"dist/pin.txt":             "pin=1234567\n",
	})
	var seen strings.Builder
	// The baseline holds paths as they are (it must match them again), so
	// the file named after a value stays out of --write-baseline's run.
	for _, args := range [][]string{{"dist", "named"}, {"dist", "named", "--json"}, {"dist", "--write-baseline"}, {"dist", "named"}} {
		code, out, errText := runScan(t, args...)
		if code != 1 && code != 0 {
			t.Fatalf("%v: status %d\n%s%s", args, code, out, errText)
		}
		seen.WriteString(out + errText)
	}
	baseline, err := os.ReadFile(filepath.Join(dir, "varlatch-scan-baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	seen.Write(baseline)
	for _, value := range []string{scanAPIKey, scanOldKey, scanDBPass, "CANARY"} {
		if strings.Contains(seen.String(), value) {
			t.Fatalf("%q shown:\n%s", value, seen.String())
		}
	}
	if !strings.Contains(seen.String(), "named/leak-[redacted]:1:1: DB_PASS (version ver_db), as written") {
		t.Fatalf("the finding in the file named after a value:\n%s", seen.String())
	}
}

// TestScanDisclosesOnce: a scan that reads files makes one disclosure,
// declared as a scan, of every Secret the identity may retrieve; one with
// nothing to read asks the server for nothing.
func TestScanDisclosesOnce(t *testing.T) {
	s, server := newScanServer(t, scanItems)
	scanRepo(t, server, map[string]string{"a.txt": scanAPIKey})
	if code, out, errText := runScan(t, "a.txt"); code != 1 {
		t.Fatalf("status %d\n%s%s", code, out, errText)
	}
	if got := strings.Join(s.requests, ", "); got != "GET /v1/meta, POST /v1/organizations/acme/projects/web/environments/dev/disclosures" {
		t.Fatalf("requests %s", got)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(s.bodies[1]), &body); err != nil || len(body) != 2 || body["scope"] != "all-authorized-secrets" || body["purpose"] != "scan" {
		t.Fatalf("disclosure %s", s.bodies[1])
	}
	s.requests = nil
	if code, _, _ := runScan(t, "missing"); code != 2 || len(s.requests) != 0 {
		t.Fatalf("status %d, requests %v", code, s.requests)
	}
}

// TestScanNoFilesToScan: a directory with no file says so, discloses
// nothing and exits 0.
func TestScanNoFilesToScan(t *testing.T) {
	s, server := newScanServer(t, scanItems)
	dir := scanRepo(t, server, map[string]string{})
	if err := os.Mkdir(filepath.Join(dir, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, errText := runScan(t, "empty")
	if code != 0 || out != "varlatch scan: no files to scan.\n" || errText != "" || len(s.requests) != 0 {
		t.Fatalf("status %d\n%q %q, requests %v", code, out, errText, s.requests)
	}
}

// TestScanRefusesADisclosureOfAnotherShape: a disclosed item whose name,
// version id or value is not a string ends the scan (1) before any file is
// read, and nothing of the answer is shown (go/README.md,
// `scan-disclosure-shape`).
func TestScanRefusesADisclosureOfAnotherShape(t *testing.T) {
	for _, items := range []string{
		`[{"name":"A","versionId":"v","value":5}]`,
		`[{"name":"A","versionId":"v","value":"` + scanAPIKey + `","retiring":{"versionId":"w"}}]`,
		`[null]`,
		`{"a":1}`,
	} {
		_, server := newScanServer(t, items)
		scanRepo(t, server, map[string]string{"a.txt": scanAPIKey})
		code, out, errText := runScan(t, "a.txt")
		if code != 1 || out != "" || !strings.HasPrefix(errText, "varlatch: ") || strings.Contains(errText, scanAPIKey) {
			t.Errorf("%s: status %d\n%q %q", items, code, out, errText)
		}
	}
}

// TestInstallHookRefusesALink: a pre-commit hook that is a symbolic link,
// to a file outside the hooks directory or dangling, is refused (1) and
// never written through: the file it points to is unchanged and a dangling
// target is not created, and the message never names the target
// (go/README.md, `scan-hook-link`). core.hooksPath is still honoured.
func TestInstallHookRefusesALink(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	_, server := newScanServer(t, scanItems)
	outside := t.TempDir()
	foreign := filepath.Join(outside, "foreign-hook")
	if err := os.WriteFile(foreign, []byte("#!/bin/sh\necho foreign\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{foreign, filepath.Join(outside, "nowhere", "hook")} {
		dir := scanRepo(t, server, map[string]string{})
		gitInit(t, dir)
		hook := filepath.Join(dir, ".git", "hooks", "pre-commit")
		if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, hook); err != nil {
			t.Skipf("no symbolic links here: %v", err)
		}
		code, out, errText := runScan(t, "--install-hook")
		if code != 1 || out != "" || !strings.Contains(errText, "is a symbolic link; it was left unchanged") || strings.Contains(errText, outside) {
			t.Fatalf("%s: status %d\n%q\n%q", target, code, out, errText)
		}
		if info, err := os.Lstat(hook); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%s: the link was replaced", target)
		}
	}
	if data, err := os.ReadFile(foreign); err != nil || string(data) != "#!/bin/sh\necho foreign\n" {
		t.Fatalf("the linked hook was written: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "nowhere")); !os.IsNotExist(err) {
		t.Fatalf("the dangling link's target was created: %v", err)
	}

	// core.hooksPath: the hook goes where git runs it from.
	dir := scanRepo(t, server, map[string]string{})
	gitInit(t, dir, "config", "core.hooksPath", "githooks")
	if code, out, errText := runScan(t, "--install-hook"); code != 0 || !strings.Contains(out, filepath.Join("githooks", "pre-commit")) {
		t.Fatalf("core.hooksPath: status %d\n%s%s", code, out, errText)
	}
	info, err := os.Lstat(filepath.Join(dir, "githooks", "pre-commit"))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("core.hooksPath: %v %v", info, err)
	}
}

// TestWriteHookNeverFollowsALink: a link put in place after installHook's
// check is refused by the write itself (O_NOFOLLOW, or the reparse point
// opened and seen on Windows), and nothing is written through it.
func TestWriteHookNeverFollowsALink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("kept\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "pre-commit")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	err := writeHook(link, "#!/bin/sh\n")
	var refused *scan.SourceError
	if !errors.As(err, &refused) || !strings.Contains(refused.Message, "is a symbolic link") {
		t.Fatalf("writeHook through a link: %v", err)
	}
	if data, _ := os.ReadFile(target); string(data) != "kept\n" {
		t.Fatalf("written through the link: %q", data)
	}
	// A regular file is written, 0755.
	plain := filepath.Join(dir, "plain")
	if err := writeHook(plain, "#!/bin/sh\necho ok\n"); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(plain); string(data) != "#!/bin/sh\necho ok\n" {
		t.Fatalf("plain hook %q", data)
	}
	if info, _ := os.Stat(plain); runtime.GOOS != "windows" && info.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", info.Mode())
	}
}

// gitInit makes dir a Git repository with no configuration of the machine,
// then runs git with extra, when given.
func gitInit(t *testing.T, dir string, extra ...string) {
	t.Helper()
	for _, args := range [][]string{{"init", "-q"}, extra} {
		if len(args) == 0 {
			continue
		}
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}
