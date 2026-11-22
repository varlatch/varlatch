// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The harness's inputs (run.sh sets them).
var (
	runID      = os.Getenv("VL_RH_RUN")         // the run's name: vl-rh-<run>-...
	releaseDir = os.Getenv("VL_RH_RELEASE_DIR") // images.sh's output
	binDir     = os.Getenv("VL_RH_BIN")         // varlatch (-tags rehearsal) and varlatchd
	workDir    = os.Getenv("VL_RH_WORK")        // the run's files
	reportDir  = os.Getenv("VL_RH_REPORT")      // report.json, report.md
	tsCheckout = os.Getenv("VL_RH_TS")          // the TypeScript checkout (its S3 client)
)

func TestMain(m *testing.M) {
	switch filepath.Base(os.Args[0]) {
	case "systemctl":
		os.Exit(fakeSystemctl(os.Args[1:]))
	case "squatter":
		squat(os.Args[1])
		return
	case "envdigest":
		os.Exit(envDigest(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// --- systemd, as G5 stands in for it: the target varlatchd as a process ---

func state(name string) string { return filepath.Join(os.Getenv("VL_RH_STATE"), name) }

func fakeSystemctl(args []string) int {
	if len(args) != 2 {
		return 1
	}
	switch args[0] {
	case "start":
		if pid := readPID(); pid > 0 && alive(pid) {
			return 0
		}
		// The port-collision case: something else of this run's already
		// listens on the address (squatter), so varlatchd cannot bind it.
		if b, err := os.ReadFile(state("squat")); err == nil {
			if err := startSquatter(strings.TrimSpace(string(b))); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
		}
		if err := startService(state("varlatchd"), state("service.conf")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "stop":
		if err := stopService(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	return 1
}

func readPID() int {
	b, err := os.ReadFile(state("service.pid"))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func alive(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+1:]))
	return len(f) > 0 && f[0] != "Z"
}

func startService(bin, conf string) error {
	log, err := os.OpenFile(state("service.log"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer log.Close()
	cmd := exec.Command(bin, "serve", "--config", conf)
	// The case's own environment for the target (its trust roots), as a
	// unit's Environment= lines would give it.
	cmd.Env = append(os.Environ(), serviceEnv(state("service.env"))...)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	if err := os.WriteFile(state("service.pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		return err
	}
	data := ""
	if b, err := os.ReadFile(conf); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "data_dir = "); ok {
				data = v
			}
		}
	}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if c, err := net.Dial("unix", filepath.Join(data, "varlatchd.sock")); err == nil {
			c.Close()
			return nil
		}
		if !alive(cmd.Process.Pid) {
			return errors.New("varlatchd exited at start (service.log)")
		}
	}
	return errors.New("varlatchd did not start within 30 s")
}

// serviceEnv is a service.env file's KEY=VALUE lines (none when it is
// missing), blank lines and # comments left out.
func serviceEnv(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || !strings.Contains(l, "=") {
			continue
		}
		out = append(out, l)
	}
	return out
}

func stopService() error {
	pid := readPID()
	if pid <= 0 || !alive(pid) {
		_ = os.Remove(state("service.pid"))
		return nil
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if !alive(pid) {
			return os.Remove(state("service.pid"))
		}
	}
	return errors.New("varlatchd did not stop within 30 s")
}

// startSquatter holds addr in a process of its own (this binary as
// "squatter"), recorded in squatter.pid.
func startSquatter(addr string) error {
	self, _ := os.Executable()
	link := state("squatter")
	_ = os.Remove(link)
	if err := os.Symlink(self, link); err != nil {
		return err
	}
	cmd := exec.Command(link, addr)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return os.WriteFile(state("squatter.pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
		}
	}
	return errors.New("the squatter did not listen")
}

func squat(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		os.Exit(1)
	}
	_ = http.Serve(l, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusTeapot) }))
}

// --- running things ---

// ran is a command's outcome: its status and what it printed (stdout and
// stderr apart).
type ran struct {
	code           int
	stdout, stderr string
	took           time.Duration
}

func (r ran) String() string {
	return fmt.Sprintf("exit %d after %s; stderr: %s", r.code, r.took.Round(time.Millisecond), redact(lastLines(r.stderr, 4)))
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func run(dir string, env []string, stdin []byte, name string, args ...string) ran {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	began := time.Now()
	err := cmd.Run()
	return ran{code: exitCode(err), stdout: out.String(), stderr: errb.String(), took: time.Since(began)}
}

func exitCode(err error) int {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	if err != nil {
		return -2
	}
	return 0
}

func formatFailure(what string, r ran) string {
	return fmt.Sprintf("%s: %s\nstdout: %s", what, r, redact(lastLines(r.stdout, 6)))
}

func must(t *testing.T, r ran, what string) ran {
	t.Helper()
	if r.code != 0 {
		t.Fatal(formatFailure(what, r))
	}
	return r
}

func hexBytes(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, p, _ := net.SplitHostPort(l.Addr().String())
	return p
}

// --- the release under test ---

type release struct {
	Registry int               `json:"registry"`
	Images   map[string]string `json:"images"` // name -> repo:tag@digest
}

func loadRelease(t *testing.T) release {
	t.Helper()
	for name, v := range map[string]string{"VL_RH_RUN": runID, "VL_RH_RELEASE_DIR": releaseDir, "VL_RH_BIN": binDir, "VL_RH_WORK": workDir, "VL_RH_REPORT": reportDir, "VL_RH_TS": tsCheckout} {
		if v == "" {
			t.Skipf("%s is not set: run.sh runs this harness", name)
		}
	}
	b, err := os.ReadFile(filepath.Join(releaseDir, "images.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r release
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// pin is VARLATCH_MIGRATE_PIN for the release's varlatchd image.
func (r release) pin() string {
	ref := r.Images["varlatchd"]
	repo, digest, _ := strings.Cut(ref, "@")
	repo = repo[:strings.LastIndex(repo, ":")]
	return repo + "@" + digest
}

// --- an installation: a real Compose installation of the release ---

type installation struct {
	t                  *testing.T
	name, project, dir string
	state              string
	bucket             string
	targetRoot         string
	targetDir          string
	webPort, proxyPort string
	publicURL          string
	conf, data, keys   string
	bek, destinations  string
	readCreds          string
	fakebin            string
	kekCopy            string // a restored installation's copy of the operator's Root KEK
	isolated           bool   // a restored copy: no sync, no audit export, no egress (isolationOverride)
	proxy              *http.Server
	installationID     string
	ingress            string       // proxy or public
	acme               *acmeStack   // public ingress: the run's Pebble
	client             *http.Client // the public URL's client (TLS for public ingress)
}

// installExtra is what a case adds to an installation: .env variables, a
// Compose overlay (a file name and its text, added to COMPOSE_FILE), lines
// for the target's configuration, and the target varlatchd's environment.
type installExtra struct {
	env                      map[string]string
	composeFile, composeText string
	conf                     string
	serviceEnv               []string
}

// newInstallation is a fresh installation of the release, up and serving,
// with its own public URL (a loopback proxy to its dashboard's port), its
// target's host-install configuration, and its backup destination.
func newInstallation(t *testing.T, rel release, s3 *s3Server, name string, extras ...installExtra) *installation {
	t.Helper()
	in := prepareInstallation(t, rel, s3, name, nil, extras...)
	in.up()
	return in
}

// newSource is the run's source: a fresh installation (VL_RH_SOURCE=seed),
// or the archive VL_RH_SOURCE names restored onto one (B6).
func newSource(t *testing.T, rel release, s3 *s3Server, name string) *installation {
	t.Helper()
	if prof.restore == "" {
		return newInstallation(t, rel, s3, name)
	}
	return restoredInstallation(t, rel, s3, name)
}

// operatorKeys are the keys of an installation restored from an archive
// (B6): the operator's files, given by path, never generated.
type operatorKeys struct{ kek, bek string }

// prepareInstallation is an installation's files, its target's and its
// backup destination, not started: with keys (a restore), its Root KEK
// is the operator's and its BEK the operator's file, and it is isolated
// (isolationExtra), before the case's extras.
func prepareInstallation(t *testing.T, rel release, s3 *s3Server, name string, keys *operatorKeys, extras ...installExtra) *installation {
	t.Helper()
	in := &installation{t: t, name: name, project: "vl-rh-" + runID + "-" + name, ingress: prof.ingress}
	base := filepath.Join(workDir, name)
	in.dir, in.state = filepath.Join(base, "compose"), filepath.Join(base, "state")
	// The target host install: under a root-owned path when the harness runs
	// as root (varlatchd refuses a data directory any other user could
	// replace on its way, as on a real host's /var/lib/varlatch).
	target := filepath.Join(base, "target")
	if root := os.Getenv("VL_RH_TARGET_ROOT"); root != "" {
		in.targetRoot = root
		target = filepath.Join(root, runID, name)
	}
	in.targetDir = target
	for _, d := range []string{in.dir, in.state, filepath.Join(target, "data"), filepath.Join(target, "keys"), filepath.Join(base, "operator")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bundle := filepath.Join(releaseDir, "varlatch-compose-0.23.0.tar.gz")
	must(t, run("", nil, nil, "tar", "-xzf", bundle, "-C", in.dir, "--strip-components=1"), "unpack the release bundle")
	_ = os.MkdirAll(filepath.Join(in.dir, "secrets"), 0o700)
	_ = os.MkdirAll(filepath.Join(in.dir, "backups"), 0o700)
	// As setup makes it: 0700, the operator's, which the TypeScript
	// container (uid 999) cannot write (finding 1 of run r1). Nothing
	// needs it to: migrate streams the export (--out -) since 0.23.0.
	kek := filepath.Join(in.dir, "secrets", "varlatch-kek")
	// varlatchd (uid 999) reads the KEK through the secret's bind mount.
	kekText := []byte(hexBytes(32) + "\n")
	if keys != nil {
		// The operator's Root KEK, copied (the container's user must read
		// it; the operator's file stays 0600) and removed with the
		// installation.
		b, err := os.ReadFile(keys.kek)
		if err != nil {
			t.Fatal(err)
		}
		kekText = b
		in.kekCopy = kek
	}
	if err := os.WriteFile(kek, kekText, 0o644); err != nil {
		t.Fatal(err)
	}
	in.webPort, in.proxyPort = freePort(t), freePort(t)
	in.publicURL = "http://127.0.0.1:" + in.proxyPort
	if in.ingress == "public" {
		in.acme = startACME(t, in.state)
		in.publicURL = "https://" + prof.publicName
		in.client = tlsClient(t, in.acme)
		if err := os.WriteFile(filepath.Join(in.dir, "docker-compose.rehearsal.yml"), []byte(composeOverride(in.acme)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pg := hexBytes(12)
	env := map[string]string{
		"COMPOSE_PROJECT_NAME":        in.project,
		"POSTGRES_SUPERUSER_PASSWORD": "su-" + pg, "VARLATCH_MIGRATE_PASSWORD": "mig-" + pg,
		"VARLATCH_RUNTIME_PASSWORD": "rt-" + pg, "CONVEX_DB_PASSWORD": "cvx-" + pg,
		"CONVEX_INSTANCE_SECRET": hexBytes(32),
		"BIND_ADDRESS":           "127.0.0.1", "VARLATCH_WEB_PORT": in.webPort, "VARLATCHD_PORT": "0", "CONVEX_PORT": "0",
		"VARLATCH_KEK_HOST_PATH": "./secrets/varlatch-kek",
		"VARLATCH_PUBLIC_URL":    in.publicURL,
		"CONVEX_CLOUD_ORIGIN":    in.publicURL + "/convex", "CONVEX_SITE_ORIGIN": in.publicURL + "/convex",
		"VARLATCH_JWKS_URL": "http://varlatchd:8686/.well-known/jwks.json", "VARLATCH_CONVEX_URL": "http://convex-backend:3210",
	}
	if in.ingress == "public" {
		env["COMPOSE_FILE"] = "docker-compose.yml:docker-compose.caddy.yml:docker-compose.rehearsal.yml"
		env["VARLATCH_PUBLIC_HOST"] = prof.publicName
		env["VARLATCH_HTTP_PORT"] = net.JoinHostPort(prof.publicBind, "80")
		env["VARLATCH_HTTPS_PORT"] = net.JoinHostPort(prof.publicBind, "443")
		env["VARLATCH_ACME_CA"] = "https://pebble:14000/dir"
	}
	if keys != nil {
		in.isolated = true
		extras = append([]installExtra{isolationExtra(filepath.Join(base, "operator", "backup-destinations.json"))}, extras...)
	}
	for _, x := range extras {
		for k, v := range x.env {
			env[k] = v
		}
		if x.composeFile != "" {
			if err := os.WriteFile(filepath.Join(in.dir, x.composeFile), []byte(x.composeText), 0o644); err != nil {
				t.Fatal(err)
			}
			files := env["COMPOSE_FILE"]
			if files == "" {
				files = "docker-compose.yml"
			}
			env["COMPOSE_FILE"] = files + ":" + x.composeFile
		}
	}
	var text strings.Builder
	for k, v := range env {
		fmt.Fprintf(&text, "%s=%s\n", k, v)
	}
	if err := os.WriteFile(filepath.Join(in.dir, ".env"), []byte(text.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	// The operator's files: the BEK, the destination, its credentials.
	op := filepath.Join(base, "operator")
	in.bek = filepath.Join(op, "backup-key")
	if keys != nil {
		// The operator's file itself: the archive's BEK seals the run's
		// backups too, as on the operator's host.
		in.bek = keys.bek
	} else if err := os.WriteFile(in.bek, []byte(hexBytes(32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in.bucket = "vl-rh-" + name
	s3.createBucket(t, in.bucket)
	in.destinations = filepath.Join(op, "backup-destinations.json")
	s3.writeDestination(t, in.destinations, in.bucket, "write.json")
	in.readCreds = filepath.Join(op, "read.json")
	s3.writeCredentials(t, in.readCreds)
	// The public URL: with an own proxy, the operator's proxy to the
	// dashboard's port, which the target varlatchd binds once the dashboard
	// stops; with public ingress, Caddy on the run's address.
	if in.ingress == "proxy" {
		in.startProxy()
	}
	// The target: a host install the migration fills.
	in.data, in.keys = filepath.Join(target, "data"), filepath.Join(target, "keys")
	host := fmt.Sprintf("listen = 127.0.0.1:%s\npublic_url = %s\ndata_dir = %s\nroot_kek_file = %s\nbackup_key_file = %s\nbackup_interval = off\n",
		in.webPort, in.publicURL, in.data, filepath.Join(in.keys, "root-kek"), filepath.Join(in.keys, "backup-key"))
	if in.ingress == "public" {
		host = fmt.Sprintf("listen = 127.0.0.1:%s\nlisten_https = %s\nlisten_http_redirect = %s\nacme_ca = %s\nacme_ca_root = %s\npublic_url = %s\ndata_dir = %s\nroot_kek_file = %s\nbackup_key_file = %s\nbackup_interval = off\n",
			freePort(t), net.JoinHostPort(prof.publicBind, "443"), net.JoinHostPort(prof.publicBind, "80"), in.acme.hostDirectory, in.acme.apiRoot,
			in.publicURL, in.data, filepath.Join(in.keys, "root-kek"), filepath.Join(in.keys, "backup-key"))
	}
	var service []string
	for _, x := range extras {
		host += x.conf
		service = append(service, x.serviceEnv...)
	}
	if len(service) > 0 {
		if err := os.WriteFile(filepath.Join(in.state, "service.env"), []byte(strings.Join(service, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	in.conf = filepath.Join(target, "varlatchd.conf")
	for _, p := range []string{in.conf, filepath.Join(in.state, "service.conf")} {
		if err := os.WriteFile(p, []byte(host), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(binDir, "varlatchd"), filepath.Join(in.state, "varlatchd")); err != nil {
		t.Fatal(err)
	}
	// systemctl and varlatch-ts on PATH.
	in.fakebin = filepath.Join(base, "bin")
	_ = os.MkdirAll(in.fakebin, 0o755)
	// systemd: stood in for on a workstation; on the box, the run's own unit.
	if prof.box {
		in.installUnit(t)
	} else {
		self, _ := os.Executable()
		if err := os.Symlink(self, filepath.Join(in.fakebin, "systemctl")); err != nil {
			t.Fatal(err)
		}
	}
	cli := filepath.Join(releaseDir, "varlatch-cli-0.23.0.cjs")
	if err := os.WriteFile(filepath.Join(in.fakebin, "varlatch-ts"), []byte("#!/bin/sh\nexec node "+cli+" \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(in.remove)
	return in
}

// isolationExtra is a restored copy's (B6). The copy holds what
// production's would: webhooks, Sync Targets and audit export streams
// aimed at real destinations, with the keys that sign and open them. It
// reaches none: sync and the audit export off, its network internal
// (isolationOverride), its webhooks revoked once restored (neutralise);
// and Go's target neither (sync = off, audit_export = off), its backups
// to the run's destination (a rollback's --finish uploads a final
// archive of Go's copy before it discards it).
func isolationExtra(destinations string) installExtra {
	return installExtra{
		env:         map[string]string{"VARLATCH_SYNC": "off", "VARLATCH_AUDIT_EXPORT": "off"},
		composeFile: "docker-compose.isolated.yml", composeText: isolationOverride,
		conf: fmt.Sprintf("backup_destinations_file = %s\nbackup_destination = offsite\nsync = off\naudit_export = off\n", destinations),
	}
}

// isolationOverride is a restored copy's Compose file (B6): its network
// internal, so no container of it reaches anything outside it; only the
// dashboard joins a second network, for its published port, which the
// run's proxy reaches (nginx there proxies to varlatchd and Convex only).
const isolationOverride = `# Written by the rehearsal harness (B6): a restored copy reaches nothing
# outside its own network.
networks:
  default:
    internal: true
  edge: {}
services:
  varlatch-web:
    networks:
      default: {}
      edge: {}
`

func (in *installation) startProxy() {
	target, _ := url.Parse("http://127.0.0.1:" + in.webPort)
	l, err := net.Listen("tcp", "127.0.0.1:"+in.proxyPort)
	if err != nil {
		in.t.Fatal(err)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ErrorHandler = func(rw http.ResponseWriter, _ *http.Request, _ error) { rw.WriteHeader(http.StatusBadGateway) }
	in.proxy = &http.Server{Handler: rp, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = in.proxy.Serve(l) }()
}

func (in *installation) compose(args ...string) ran {
	return run(in.dir, nil, nil, "docker", append([]string{"compose"}, args...)...)
}

// up starts the installation as its README says: the stack, then the
// Application Plane's one-shot.
func (in *installation) up() {
	t := in.t
	must(t, in.compose("up", "-d", "--wait"), "docker compose up")
	must(t, in.compose("--profile", "deploy", "run", "--rm", "convex-deploy"), "convex-deploy")
	if code, _ := in.get("/readyz"); code != 200 {
		t.Fatalf("the public URL's /readyz is %d", code)
	}
	_, body := in.get("/v1/meta")
	var meta struct {
		InstallationID string `json:"installationId"`
		ServerVersion  string `json:"serverVersion"`
	}
	_ = json.Unmarshal([]byte(body), &meta)
	in.installationID = meta.InstallationID
	if meta.ServerVersion != "0.23.0" || meta.InstallationID == "" {
		t.Fatalf("/v1/meta: %s", redact(body))
	}
}

// admin runs the TypeScript admin CLI in the varlatchd container.
func (in *installation) admin(stdin []byte, args ...string) ran {
	a := append([]string{"compose", "exec", "-T", "varlatchd", "node", "dist/cli.js", "admin"}, args...)
	return run(in.dir, nil, stdin, "docker", a...)
}

// inside runs node inside the varlatchd container (its image has no curl).
func (in *installation) inside(script string) ran {
	return run(in.dir, nil, nil, "docker", "compose", "exec", "-T", "varlatchd", "node", "-e", script)
}

func (in *installation) get(path string) (int, string) {
	c := in.client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, in.publicURL+path, nil)
	if err != nil {
		return 0, err.Error()
	}
	// As migrate's prober asks: past any cache in front.
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	_, _ = b.ReadFrom(resp.Body)
	return resp.StatusCode, b.String()
}

// answered is what answersWithin saw: whether an answer passed within the
// deadline, how long the first passing one took, how many requests it
// made, and the last answer (the passing one, or the last that did not).
type answered struct {
	ok    bool
	took  time.Duration
	tries int
	code  int
	body  string
}

// sourceAnswers is whether a /v1/meta answer is the source's own: 200, the
// TypeScript release 0.23.0, and the installation's id (0.23.0 answers
// 200 without one while its database is down), as migrate's prober and
// waitForTypeScript judge it.
func sourceAnswers(installationID string) func(int, string) bool {
	return func(code int, body string) bool {
		var meta struct {
			InstallationID string `json:"installationId"`
			ServerVersion  string `json:"serverVersion"`
		}
		if code != http.StatusOK || json.Unmarshal([]byte(body), &meta) != nil {
			return false
		}
		return installationID != "" && meta.InstallationID == installationID && meta.ServerVersion == "0.23.0"
	}
}

// answersWithin polls get, as a client would, until pass holds of its
// answer or the deadline passes. It never judges a single request: a
// source that starts after the poll began is waited for, one that never
// answers fails at the deadline.
func answersWithin(get func() (int, string), pass func(int, string) bool, deadline, every time.Duration) answered {
	start := time.Now()
	var a answered
	for {
		a.tries++
		a.code, a.body = get()
		if pass(a.code, a.body) {
			a.ok, a.took = true, time.Since(start)
			return a
		}
		if time.Since(start)+every > deadline {
			a.took = time.Since(start)
			return a
		}
		time.Sleep(every)
	}
}

// journal is the migration's journal in the Compose directory.
func (in *installation) journal() map[string]any {
	b, err := os.ReadFile(filepath.Join(in.dir, "migration.json"))
	if err != nil {
		return nil
	}
	var j map[string]any
	_ = json.Unmarshal(b, &j)
	return j
}

// remove removes everything of the installation's, by its exact names:
// the target varlatchd and any squatter, the Compose project (its
// containers, network and volumes), the proxy, and its target directory
// under VL_RH_TARGET_ROOT.
func (in *installation) remove() {
	_ = os.Setenv("VL_RH_STATE", in.state)
	_ = stopService()
	if prof.box {
		in.removeUnit()
	}
	if b, err := os.ReadFile(filepath.Join(in.state, "squatter.pid")); err == nil {
		if pid, _ := strconv.Atoi(strings.TrimSpace(string(b))); pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	if in.proxy != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = in.proxy.Shutdown(ctx)
		cancel()
	}
	if os.Getenv("VL_RH_KEEP") == "1" {
		return
	}
	run(in.dir, nil, nil, "docker", "compose", "-p", in.project, "--profile", "deploy", "down", "-v", "--remove-orphans", "--timeout", "20")
	// down -v removes the volumes the Compose files name now: after a
	// rollback those are its fresh ones, so the installation's earlier
	// ones (kept until a --finish --delete-old-data) are removed by the
	// project's label, each by its name (run r16e left two).
	vols := run("", nil, nil, "docker", "volume", "ls", "-q", "--filter", "label=com.docker.compose.project="+in.project)
	for _, v := range strings.Fields(vols.stdout) {
		if strings.HasPrefix(v, in.project+"_") {
			run("", nil, nil, "docker", "volume", "rm", v)
		}
	}
	if in.kekCopy != "" {
		_ = os.Remove(in.kekCopy)
	}
	// The run's own files of the installation: logs, the reader's
	// repository and home (its credential), its HMAC key.
	_ = os.RemoveAll(in.state)
	if in.targetRoot != "" && in.targetDir != "" {
		_ = os.RemoveAll(in.targetDir)
		_ = os.Remove(filepath.Join(in.targetRoot, runID))
	}
}
