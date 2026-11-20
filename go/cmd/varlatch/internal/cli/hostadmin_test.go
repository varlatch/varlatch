// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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
		// The names of the VARLATCH_* variables it was given, never a value.
		var names []string
		for _, kv := range os.Environ() {
			if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(strings.ToUpper(name), "VARLATCH_") {
				names = append(names, name)
			}
		}
		slices.Sort(names)
		envNames, _ := json.Marshal(names)
		_ = os.WriteFile(filepath.Join(dir, "env.json"), envNames, 0o644)
		// Where it was told the credentials are (a directory's name).
		_ = os.WriteFile(filepath.Join(dir, "credentials-directory"), []byte(os.Getenv("CREDENTIALS_DIRECTORY")), 0o644)
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
	return runAdminWith(t, MapEnv{"PATH": path}, args...)
}

// runAdminWith runs `varlatch admin args...` with env (PATH among it), a
// HOME and a configuration directory of its own.
func runAdminWith(t *testing.T, env MapEnv, args ...string) (int, string, string) {
	t.Helper()
	full := MapEnv{"HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir()}
	for k, v := range env {
		full[k] = v
	}
	var stdout, stderr bytes.Buffer
	code := Main(append([]string{"admin"}, args...), full, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
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
		{nil, 64, "Usage:\n  varlatch admin backup run [--json]\n"},
		{[]string{"backup"}, 64, "  varlatch admin backup run [--json]\n"},
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

// TestFindVarlatchdBesideFirst: the varlatchd beside this varlatch wins
// over one on PATH, also when varlatch is reached through a symbolic link
// (the link's target's directory counts, not the link's); one without an
// execute bit is not run (Unix); without a self, PATH decides.
func TestFindVarlatchdBesideFirst(t *testing.T) {
	name := "varlatchd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	install, links, decoy := t.TempDir(), t.TempDir(), t.TempDir()
	self := filepath.Join(install, "varlatch")
	for _, f := range []string{self, filepath.Join(install, name), filepath.Join(decoy, name)} {
		if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The beside one is found through the resolved executable, so it is
	// named by its resolved path (macOS's /var is /private/var; Windows's
	// TEMP may hold an 8.3 short name); one on PATH is named as PATH gives it.
	beside, onPath := filepath.Join(resolved(t, install), name), filepath.Join(decoy, name)
	check := func(what, self, want string) {
		t.Helper()
		got, err := findVarlatchd(self, decoy, false)
		if err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", what, got, err, want)
		}
	}
	check("beside", self, beside)
	check("no self", "", onPath)
	link := filepath.Join(links, "varlatch")
	if err := os.Symlink(self, link); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
		t.Logf("no symbolic link on this system (%v); the link case is checked on Unix", err)
	} else {
		check("through a symbolic link", link, beside)
		// A varlatchd beside the link, not the target, is not the one.
		if err := os.WriteFile(filepath.Join(links, name), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		check("beside the link only", link, beside)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(beside, 0o644); err != nil {
			t.Fatal(err)
		}
		check("beside without an execute bit", self, onPath)
	}
	if err := os.Remove(beside); err != nil {
		t.Fatal(err)
	}
	check("nothing beside", self, onPath)
	if _, err := findVarlatchd(self, t.TempDir(), false); err == nil {
		t.Error("found a varlatchd where there is none")
	}
}

// TestFindVarlatchdAsRoot: as root, a varlatchd on PATH is run only when
// root alone can change it, the directory it is in and the PATH entry;
// otherwise the run refuses it (78), naming the path, and runs nothing.
// The beside one is not checked: it is the installation's own.
func TestFindVarlatchdAsRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no root on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("the temporary files are root's own here")
	}
	dir := fakeVarlatchd(t)
	// As root, the program checked and run is the resolved one, and a
	// refusal names it (macOS's /var is /private/var).
	path := filepath.Join(resolved(t, dir), "varlatchd")
	if _, err := findVarlatchd("", dir, true); !isUnsafe(err, path, "is not owned by root") {
		t.Errorf("not root's: %v", err)
	}
	if err := os.Chmod(path, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := findVarlatchd("", dir, true); !isUnsafe(err, path, "is writable by its group or by others") {
		t.Errorf("group-writable: %v", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	// The beside one is run as it is.
	self := filepath.Join(t.TempDir(), "varlatch")
	if err := os.WriteFile(self, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(self), "varlatchd"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := findVarlatchd(self, dir, true); err != nil || got != filepath.Join(resolved(t, filepath.Dir(self)), "varlatchd") {
		t.Errorf("beside, as root: %q %v", got, err)
	}
	// What root may run: a system program, root's, in root's directory.
	for _, p := range []string{"/bin/sh", "/usr/bin/env"} {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if uid, ok := fileOwner(info); !ok || uid != 0 || info.Mode().Perm()&0o022 != 0 {
			continue
		}
		if why := onlyRootCanChange(p); why != "" {
			t.Errorf("%s: %s", p, why)
		}
	}

	// Through the command: 78, the path named, varlatchd never run.
	answer(t, dir, "", "", 0)
	defer func(was func() bool) { asRoot = was }(asRoot)
	asRoot = func() bool { return true }
	code, out, errText := runAdmin(t, dir, "backup", "status")
	if code != ExitConfig || out != "" || errText != "varlatch admin: not running the varlatchd on PATH as root: "+path+" is not owned by root; as root, the host commands run the varlatchd installed beside this varlatch, or one on PATH that only root can change\n" {
		t.Errorf("as root: %d %q %q", code, out, errText)
	}
	if got := called(t, dir); got != nil {
		t.Errorf("varlatchd ran: %q", got)
	}
}

// resolved is path with every symbolic link (and, on Windows, every short
// name) resolved, as findVarlatchd resolves the executable.
func resolved(t *testing.T, path string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func isUnsafe(err error, path, why string) bool {
	var u *unsafeVarlatchd
	return errors.As(err, &u) && u.path == path && u.why == why
}

// TestAdminLeavesCredentialsOut: varlatchd gets the run's environment
// without its credential VARLATCH_* variables (no fronted form reads
// them); the others reach it.
func TestAdminLeavesCredentialsOut(t *testing.T) {
	dir := fakeVarlatchd(t)
	answer(t, dir, "", "", 0)
	env := MapEnv{"PATH": dir,
		"VARLATCH_TOKEN": "vlt_cli_fakeAAAAAAAAAAAAAAAAAAAAAAAA", "VARLATCH_OIDC_TOKEN": "x.y.z", "VARLATCH_KEK_PASSPHRASE": "p",
		"Varlatch_Api_Key": "k", "VARLATCH_SOME_SECRET": "s", "VARLATCH_OUTBOUND_ALLOW": "10.0.0.0/8", "VARLATCH_ASSISTED": "0"}
	if code, _, errText := runAdminWith(t, env, "backup", "status"); code != 0 {
		t.Fatalf("%d %q", code, errText)
	}
	data, err := os.ReadFile(filepath.Join(dir, "env.json"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		t.Fatal(err)
	}
	if want := []string{"VARLATCH_ASSISTED", "VARLATCH_CONFIG_DIR", "VARLATCH_OUTBOUND_ALLOW"}; !slices.Equal(names, want) {
		t.Errorf("varlatchd got %q, want %q", names, want)
	}
	for name, want := range map[string]bool{"VARLATCH_TOKEN": true, "varlatch_token": true, "VARLATCH_BACKUP_KEY": true, "VARLATCH_PASSWORD": true,
		"VARLATCH_CREDENTIALS_FILE": true, "VARLATCH_CONFIG_DIR": false, "VARLATCH_KEYRING_DIR": false, "TOKEN": false, "GITHUB_TOKEN": false} {
		if isCredentialVariable(name) != want {
			t.Errorf("isCredentialVariable(%q) = %v", name, !want)
		}
	}
}

// TestHelpAdminIsTheGoUsage: `help admin`, `admin --help` and `admin -h`
// print the Go installation's admin usage (the accepted difference
// admin-usage), on stdout, status 0.
func TestHelpAdminIsTheGoUsage(t *testing.T) {
	for _, args := range [][]string{{"help", "admin"}, {"admin", "--help"}, {"admin", "-h"}, {"admin", "backup", "run", "--help"}} {
		var stdout, stderr bytes.Buffer
		code := Main(args, MapEnv{"HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir(), "PATH": t.TempDir()},
			IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
		if code != 0 || stdout.String() != adminUsage+"\n" || stderr.String() != "" {
			t.Errorf("%v: %d %q %q", args, code, stdout.String(), stderr.String())
		}
	}
}

// TestAdminFindsTheUnitsCredentials: outside the unit, a host command's
// varlatchd gets CREDENTIALS_DIRECTORY = the configuration's directory
// when the Root KEK is there (as setup writes it), so the configuration
// loads as under the unit; not when it is not there, nor over one the run
// set.
func TestAdminFindsTheUnitsCredentials(t *testing.T) {
	dir := fakeVarlatchd(t)
	answer(t, dir, "", "", 0)
	etc := t.TempDir()
	conf := filepath.Join(etc, "varlatchd.conf")
	got := func(env MapEnv) string {
		t.Helper()
		if code, _, errText := runAdminWith(t, env, "backup", "status", "--config", conf); code != 0 {
			t.Fatalf("%d %q", code, errText)
		}
		b, _ := os.ReadFile(filepath.Join(dir, "credentials-directory"))
		return string(b)
	}
	if c := got(MapEnv{"PATH": dir}); c != "" {
		t.Errorf("without a Root KEK there: %q", c)
	}
	if err := os.WriteFile(filepath.Join(etc, "root-kek"), []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := got(MapEnv{"PATH": dir}); c != etc {
		t.Errorf("with the Root KEK beside the configuration: %q, want %q", c, etc)
	}
	if c := got(MapEnv{"PATH": dir, "CREDENTIALS_DIRECTORY": "/run/credentials/varlatchd.service"}); c != "/run/credentials/varlatchd.service" {
		t.Errorf("the run's own: %q", c)
	}
}
