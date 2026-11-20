// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
)

func runDoctor(t *testing.T, path string, env MapEnv, args ...string) (int, string, string) {
	t.Helper()
	full := MapEnv{"PATH": path, "HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir()}
	for k, v := range env {
		full[k] = v
	}
	var stdout, stderr bytes.Buffer
	code := Main(append([]string{"doctor"}, args...), full, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
	return code, stdout.String(), stderr.String()
}

// doctorAnswer is a varlatchd doctor report, via daemon or offline, with
// one check.
func doctorAnswer(via, version string, check string) string {
	return `{"via":"` + via + `","facts":{"serverVersion":"` + version + `","schemaVersion":1,"dataDir":"/var/lib/varlatch","publicUrl":"https://vault.example.com",` +
		`"installationId":"inst_1","listeners":{"plain":"127.0.0.1:8686","https":null,"httpRedirect":null,"tailnetPort":null,"tailnetBrowserPort":null}},"checks":[` + check + `]}` + "\n"
}

const passingCheck = `{"id":"secret-plane.ready","title":"Server readiness","status":"pass","class":"mandatory","detail":"ready"}`

// TestDoctorFrontsVarlatchd: `varlatch doctor` runs `varlatchd admin
// doctor --json [--config file]`, adds its own checks (services.running
// from whether varlatchd answered, release.pending-upgrade from the two
// versions), and shows the report as text, or
// with --json as JSON; exit 1 only on a mandatory failure.
func TestDoctorFrontsVarlatchd(t *testing.T) {
	dir := fakeVarlatchd(t)
	answer(t, dir, doctorAnswer("daemon", buildinfo.Version, passingCheck), "", 0)
	code, out, errText := runDoctor(t, dir, nil, "--json", "--config", "/etc/v.conf")
	if code != 0 || errText != "" {
		t.Fatalf("--json: %d %q %q", code, out, errText)
	}
	if got := called(t, dir); !slices.Equal(got, []string{"admin", "doctor", "--json", "--config", "/etc/v.conf"}) {
		t.Errorf("ran %q", got)
	}
	var r doctorReport
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.Via != "daemon" {
		t.Fatalf("report %q: %v", out, err)
	}
	status := map[string]string{}
	for _, c := range r.Checks {
		status[c.ID] = c.Status
	}
	if status["secret-plane.ready"] != "pass" || status["services.running"] != "pass" || status["release.pending-upgrade"] != "pass" {
		t.Errorf("checks %v", status)
	}
	// Text: one line a check, what was seen, what to do.
	code, out, _ = runDoctor(t, dir, nil)
	if code != 0 || !strings.Contains(out, "PASS    secret-plane.ready: Server readiness\n        ready\n") || !strings.Contains(out, "PASS    services.running") {
		t.Errorf("text: %d %q", code, out)
	}
	if got := called(t, dir); !slices.Equal(got, []string{"admin", "doctor", "--json"}) {
		t.Errorf("text ran %q", got)
	}
	// Offline (varlatchd did not answer): services.running fails, exit 1.
	answer(t, dir, doctorAnswer("offline", buildinfo.Version, `{"id":"storage.wal","title":"WAL","status":"unknown","class":"mandatory","detail":"varlatchd did not answer"}`), "", 0)
	code, out, _ = runDoctor(t, dir, nil)
	if code != 1 || !strings.Contains(out, "FAIL    services.running: varlatchd is running\n        varlatchd did not answer on its control socket\n        to do: Start varlatchd") {
		t.Errorf("offline: %d %q", code, out)
	}
	// Another release's varlatchd: release.pending-upgrade fails.
	answer(t, dir, doctorAnswer("daemon", "0.49.0", passingCheck), "", 0)
	if code, out, _ := runDoctor(t, dir, nil); code != 1 || !strings.Contains(out, "FAIL    release.pending-upgrade") || !strings.Contains(out, "varlatchd is 0.49.0") {
		t.Errorf("another release: %d %q", code, out)
	}
	// varlatchd's mandatory failure (its status 1, with the report).
	answer(t, dir, doctorAnswer("daemon", buildinfo.Version, `{"id":"disk.free","title":"Free space","status":"fail","class":"mandatory","detail":"10 MiB free","remedy":"Free space"}`), "", 1)
	if code, out, _ := runDoctor(t, dir, nil); code != 1 || !strings.Contains(out, "FAIL    disk.free: Free space\n        10 MiB free\n        to do: Free space\n") {
		t.Errorf("a mandatory failure: %d %q", code, out)
	}
	// An advisory failure does not fail doctor.
	answer(t, dir, doctorAnswer("daemon", buildinfo.Version, `{"id":"disk.fsync","title":"fsync","status":"fail","class":"advisory","detail":"slow"}`), "", 0)
	if code, out, _ := runDoctor(t, dir, nil); code != 0 || !strings.Contains(out, "FAIL    disk.fsync: fsync (advisory)") {
		t.Errorf("an advisory failure: %d %q", code, out)
	}
}

// TestDoctorRefusals: --dir names a Compose installation (the TypeScript
// CLI's doctor); unknown options and arguments are usage errors; none
// runs varlatchd. varlatchd's own refusal is shown with its status, and
// its 78 says to run doctor as root.
func TestDoctorRefusals(t *testing.T) {
	dir := fakeVarlatchd(t)
	answer(t, dir, "", "", 0)
	for _, c := range []struct {
		args []string
		has  string
	}{
		{[]string{"--dir", "/srv/varlatch"}, "varlatch-ts doctor --dir"},
		{[]string{"--wait", "30"}, "unknown option --wait"},
		{[]string{"--gate"}, "unknown option --gate"},
		{[]string{"extra"}, "unexpected argument extra"},
		{[]string{"--config"}, "--config needs a file"},
	} {
		code, out, errText := runDoctor(t, dir, nil, c.args...)
		if code != 64 || out != "" || !strings.Contains(errText, c.has) {
			t.Errorf("%v: %d %q %q", c.args, code, out, errText)
		}
		if got := called(t, dir); got != nil {
			t.Errorf("%v ran varlatchd: %q", c.args, got)
		}
	}
	answer(t, dir, "", "varlatchd admin doctor: the configuration file /etc/v.conf is not valid\n", 78)
	code, _, errText := runDoctor(t, dir, nil)
	if code != 78 || !strings.Contains(errText, "is not valid") {
		t.Errorf("78: %d %q", code, errText)
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 && !strings.Contains(errText, "run this as root (sudo varlatch doctor)") {
		t.Errorf("78 without the root advice: %q", errText)
	}
}

// TestDoctorShowsNoCredential: whatever varlatchd's report carries (a
// URL with a user name and password in an error, a token), the output
// shows none of it; a credential in the environment never reaches
// varlatchd.
func TestDoctorShowsNoCredential(t *testing.T) {
	dir := fakeVarlatchd(t)
	token := "vlt_cli_" + strings.Repeat("Z", 40)
	answer(t, dir, doctorAnswer("daemon", buildinfo.Version,
		`{"id":"public.certificate","title":"cert","status":"fail","class":"mandatory","detail":"fetching https://ops:hunter2@ca.example/directory failed with `+token+`"}`), "", 0)
	for _, args := range [][]string{nil, {"--json"}} {
		_, out, errText := runDoctor(t, dir, MapEnv{"VARLATCH_TOKEN": token}, args...)
		if strings.Contains(out+errText, "hunter2") || strings.Contains(out+errText, token) {
			t.Errorf("%v shows a credential: %q %q", args, out, errText)
		}
	}
	env, _ := os.ReadFile(filepath.Join(dir, "env.json"))
	if strings.Contains(string(env), "VARLATCH_TOKEN") {
		t.Errorf("varlatchd got %s", env)
	}
}

// TestDoctorWithTheRealVarlatchd: the real varlatchd, built from this
// checkout, on a temporary installation that is not running: the report
// says so (services.running fails, the server's checks are unknown), and
// the host's checks are made.
func TestDoctorWithTheRealVarlatchd(t *testing.T) {
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
	if err := os.WriteFile(conf, []byte("listen = 127.0.0.1:0\npublic_url = https://vault.example.com\ndata_dir = "+data+"\nroot_kek_file = "+kek+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errText := runDoctor(t, bin, nil, "--json", "--config", conf)
	var r doctorReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%d %q %q: %v", code, out, errText, err)
	}
	status := map[string]string{}
	for _, c := range r.Checks {
		status[c.ID] = c.Status
	}
	want := map[string]string{"services.running": "fail", "secret-plane.ready": "unknown", "storage.wal": "unknown", "config.public-url": "pass", "files.data-dir": "pass", "files.keys": "pass", "release.pending-upgrade": "pass"}
	for id, s := range want {
		if status[id] != s {
			t.Errorf("%s: %s, want %s", id, status[id], s)
		}
	}
	if code != 1 || r.Via != "offline" || strings.Contains(out, hex.EncodeToString(key)) {
		t.Errorf("exit %d, via %s", code, r.Via)
	}
	if entries, _ := os.ReadDir(data); len(entries) != 0 {
		t.Errorf("doctor wrote in the data directory: %v", entries)
	}
}
