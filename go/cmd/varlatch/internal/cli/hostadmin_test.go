// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestMain: run as `varlatchd` (a copy of this test binary under that
// name, fakeVarlatchd), the binary is a fake varlatchd: it records its
// arguments in its directory's args.json and answers with the stdout,
// stderr and status files there.
func TestMain(m *testing.M) {
	if strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe") == "varlatchd" {
		dir := filepath.Dir(os.Args[0])
		args, _ := json.Marshal(os.Args[1:])
		_ = os.WriteFile(filepath.Join(dir, "args.json"), args, 0o644)
		out, _ := os.ReadFile(filepath.Join(dir, "stdout"))
		errText, _ := os.ReadFile(filepath.Join(dir, "stderr"))
		_, _ = os.Stdout.Write(out)
		_, _ = os.Stderr.Write(errText)
		status, _ := os.ReadFile(filepath.Join(dir, "status"))
		code, _ := strconv.Atoi(strings.TrimSpace(string(status)))
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// fakeVarlatchd puts a fake varlatchd in a directory of its own and
// returns the directory, for PATH.
func fakeVarlatchd(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	name := "varlatchd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// answer sets what the fake varlatchd in dir answers.
func answer(t *testing.T, dir, stdout, stderr string, status int) {
	t.Helper()
	for name, content := range map[string]string{"stdout": stdout, "stderr": stderr, "status": strconv.Itoa(status)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Remove(filepath.Join(dir, "args.json"))
}

// called is what the fake varlatchd in dir was run with, nil if it was not.
func called(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "args.json"))
	if err != nil {
		return nil
	}
	var args []string
	if err := json.Unmarshal(data, &args); err != nil {
		t.Fatal(err)
	}
	return args
}

func runAdmin(t *testing.T, path string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Main(append([]string{"admin"}, args...), MapEnv{"PATH": path, "HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir()},
		IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
	return code, stdout.String(), stderr.String()
}

// TestAdminFrontsRunVarlatchd: each form runs `varlatchd admin <the same
// words and options> [--config <file>]`, shows a JSON answer as
// JSON.stringify(doc, null, 2) and any other answer as it is, every line
// on stderr after it, all through the fail-safe, and exits with
// varlatchd's status.
func TestAdminFrontsRunVarlatchd(t *testing.T) {
	dir := fakeVarlatchd(t)
	for _, c := range []struct {
		args           []string
		stdout, stderr string
		status         int
		want           []string
		out, errText   string
	}{
		{[]string{"backup", "run", "--json", "--config", "/etc/x.conf"}, `{"archiveId":"arc_1","bytes":3,"removed":[]}`, "", 0,
			[]string{"admin", "backup", "run", "--json", "--config", "/etc/x.conf"}, "{\n  \"archiveId\": \"arc_1\",\n  \"bytes\": 3,\n  \"removed\": []\n}\n", ""},
		{[]string{"backup", "run"}, "Archive created: /var/lib/varlatch/backups/a (arc_1)\n", "", 0,
			[]string{"admin", "backup", "run"}, "Archive created: /var/lib/varlatch/backups/a (arc_1)\n", ""},
		{[]string{"backup", "status"}, `{"archives":[],"warnings":[]}` + "\n", "", 0,
			[]string{"admin", "backup", "status"}, "{\n  \"archives\": [],\n  \"warnings\": []\n}\n", ""},
		{[]string{"backup", "test-bucket"}, "Bucket test with k:\n  delivery: FAILED\n", "varlatchd admin backup test-bucket: the bucket refused\n", 1,
			[]string{"admin", "backup", "test-bucket"}, "Bucket test with k:\n  delivery: FAILED\n", "varlatchd admin backup test-bucket: the bucket refused\n"},
		{[]string{"backup", "restore", "--in", "/tmp/a.tar", "--backup-key-file", "/k"}, "Restore completed for arc_1.\n", "", 0,
			[]string{"admin", "backup", "restore", "--in", "/tmp/a.tar", "--backup-key-file", "/k"}, "Restore completed for arc_1.\n", ""},
		{[]string{"security", "reset", "--org", "acme", "--all", "--json"}, `{"organization":{"id":"org_1","slug":"acme"},"reset":[]}`, "", 0,
			[]string{"admin", "security", "reset", "--org", "acme", "--all", "--json"}, "{\n  \"organization\": {\n    \"id\": \"org_1\",\n    \"slug\": \"acme\"\n  },\n  \"reset\": []\n}\n", ""},
		{[]string{"unfreeze", "--org", "acme", "--confirm", "acme"}, "Unfrozen acme.\n", "", 0,
			[]string{"admin", "unfreeze", "--org", "acme", "--confirm", "acme"}, "Unfrozen acme.\n", ""},
		{[]string{"outbound", "check", "--org", "acme"}, "unresolved: api.example\n", "", 2,
			[]string{"admin", "outbound", "check", "--org", "acme"}, "unresolved: api.example\n", ""},
		{[]string{"maintenance", "begin", "--ttl", "10m", "--config", "/c"}, `{"id":"gate_1","kind":"capture"}`, "", 0,
			[]string{"admin", "maintenance", "begin", "--ttl", "10m", "--config", "/c"}, "{\n  \"id\": \"gate_1\",\n  \"kind\": \"capture\"\n}\n", ""},
		{[]string{"maintenance", "end", "gate_1"}, "Maintenance ended.\n", "", 0,
			[]string{"admin", "maintenance", "end", "gate_1"}, "Maintenance ended.\n", ""},
		{[]string{"maintenance", "status"}, "null\n", "", 0,
			[]string{"admin", "maintenance", "status"}, "null\n", ""},
		// A token varlatchd ever printed is redacted, in text and JSON alike.
		{[]string{"backup", "run"}, "token vlt_cli_AAAAAAAAAAAAAAAAAAAAAAAA\n", "saw vlt_cli_AAAAAAAAAAAAAAAAAAAAAAAA\n", 0,
			[]string{"admin", "backup", "run"}, "token [redacted]\n", "saw [redacted]\n"},
		{[]string{"backup", "run", "--json"}, `{"note":"vlt_cli_AAAAAAAAAAAAAAAAAAAAAAAA"}`, "", 0,
			[]string{"admin", "backup", "run", "--json"}, "{\n  \"note\": \"[redacted]\"\n}\n", ""},
		// varlatchd's own usage error stands.
		{[]string{"security", "reset", "--org", "acme"}, "", "Usage: varlatchd admin security reset ...\n", 64,
			[]string{"admin", "security", "reset", "--org", "acme"}, "", "Usage: varlatchd admin security reset ...\n"},
	} {
		answer(t, dir, c.stdout, c.stderr, c.status)
		code, out, errText := runAdmin(t, dir, c.args...)
		if got := called(t, dir); !slices.Equal(got, c.want) {
			t.Errorf("%v: varlatchd ran with %q, want %q", c.args, got, c.want)
		}
		if code != c.status || out != c.out || errText != c.errText {
			t.Errorf("%v: status %d\nstdout %q\nstderr %q\nwant %d %q %q", c.args, code, out, errText, c.status, c.out, c.errText)
		}
	}
	// 78 (the installation's files are not this user's): a hint to run it
	// as root, when not root.
	answer(t, dir, "", "varlatchd admin backup status: the data directory /var/lib/varlatch is owned by uid 990, not by you\n", 78)
	code, _, errText := runAdmin(t, dir, "backup", "status")
	if code != 78 || !strings.Contains(errText, "owned by uid 990") {
		t.Fatalf("78: %d %q", code, errText)
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 && !strings.Contains(errText, "run this as root (sudo varlatch admin ...)") {
		t.Fatalf("78: no hint: %q", errText)
	}
}

// TestAdminRefusals: what the front refuses before running anything.
func TestAdminRefusals(t *testing.T) {
	dir := fakeVarlatchd(t)
	answer(t, dir, "", "", 0)
	for _, c := range []struct {
		args []string
		code int
		has  string
	}{
		{nil, 64, "Usage: varlatch admin backup run [--json]"},
		{[]string{"backup"}, 64, "Usage: varlatch admin backup run"},
		{[]string{"backup", "run", "--dir", "/srv/varlatch"}, 64, "--dir names a Compose installation"},
		{[]string{"security", "reset", "--org", "acme", "--all", "--dir", "."}, 64, "varlatch-ts"},
		{[]string{"backup", "create"}, 64, "`varlatch admin backup run`"},
		{[]string{"backup", "verify"}, 64, "`varlatch admin backup run`"},
		{[]string{"backup", "run", "--nope"}, 64, "varlatch admin backup run: unknown option --nope"},
		{[]string{"backup", "status", "extra"}, 64, "unexpected argument extra"},
		{[]string{"maintenance", "end"}, 64, "needs the lease id"},
		{[]string{"maintenance", "begin", "--ttl"}, 64, "--ttl needs a value"},
		{[]string{"backup", "run", "--config"}, 64, "--config needs a file"},
		{[]string{"reenroll", "--all"}, 64, "not in this build of the Go CLI yet (ADR-0059 step 6)"},
	} {
		code, out, errText := runAdmin(t, dir, c.args...)
		if code != c.code || out != "" || !strings.Contains(errText, c.has) {
			t.Errorf("%v: %d %q %q, want %d and %q", c.args, code, out, errText, c.code, c.has)
		}
		if got := called(t, dir); got != nil {
			t.Errorf("%v: varlatchd ran (%q)", c.args, got)
		}
	}
	// A varlatch-ts on PATH is named by its path.
	ts := t.TempDir()
	if err := os.WriteFile(filepath.Join(ts, "varlatch-ts"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, errText := runAdmin(t, dir+string(os.PathListSeparator)+ts, "backup", "run", "--dir", "/srv"); !strings.Contains(errText, filepath.Join(ts, "varlatch-ts")) {
		t.Errorf("varlatch-ts not named by its path: %q", errText)
	}
	// No varlatchd: 69, saying where it looked.
	if code, _, errText := runAdmin(t, t.TempDir(), "backup", "status"); code != 69 || !strings.Contains(errText, "no varlatchd beside this varlatch or on PATH") {
		t.Errorf("no varlatchd: %d %q", code, errText)
	}
}

// TestAdminWithTheRealVarlatchd runs the offline forms against the real
// varlatchd, built from this checkout, in a temporary installation (no
// root: --config points at it): `maintenance status` and `backup status`
// read the data directory's files under its lock.
func TestAdminWithTheRealVarlatchd(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("builds varlatchd (Linux)")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("needs the go tool")
	}
	bin := t.TempDir()
	build := exec.Command(goTool, "build", "-o", filepath.Join(bin, "varlatchd"), "github.com/varlatch/varlatch/go/cmd/varlatchd")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build varlatchd: %v\n%s", err, out)
	}
	install := t.TempDir()
	data := filepath.Join(install, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	kek := filepath.Join(install, "root-kek")
	if err := os.WriteFile(kek, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(install, "varlatchd.conf")
	if err := os.WriteFile(conf, []byte("listen = 127.0.0.1:0\ndata_dir = "+data+"\nroot_kek_file = "+kek+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		out  string
	}{
		{[]string{"maintenance", "status", "--config", conf}, "null\n"},
		{[]string{"backup", "status", "--config", conf}, "{\n  \"archives\": [],\n  \"warnings\": [\n    \"No archive created within the last 48 hours\"\n  ]\n}\n"},
	} {
		code, out, errText := runAdmin(t, bin, c.args...)
		if code != 0 || out != c.out || errText != "" {
			t.Errorf("%v: %d %q %q, want %q", c.args, code, out, errText, c.out)
		}
	}
	// A configuration that is not valid: varlatchd's 78, its message shown.
	bad := filepath.Join(install, "bad.conf")
	if err := os.WriteFile(bad, []byte("nonsense\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errText := runAdmin(t, bin, "maintenance", "status", "--config", bad); code != 78 || !strings.Contains(errText, "is not valid") {
		t.Errorf("bad configuration: %d %q", code, errText)
	}
}
