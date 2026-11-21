// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g5 && linux

package g5_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/check"
	"github.com/varlatch/varlatch/go/server/migration/migrate"
	"github.com/varlatch/varlatch/go/server/migration/migrationtest"
)

// G5's interrupted half (ADR-0059 G5; internal docs/design/go-step7.md
// decision 14 and slice 7.4c): the real `varlatch migrate`, built with
// -tags crashpoint, killed (SIGKILL) at every phase boundary of a
// migration, then held to decision 14's stated state there: the source's
// data unchanged (hashed), both journals, which side answers, and where
// --resume (and --abort, where it is allowed) takes it.
//
// What is real: the varlatch CLI (its engine, the Compose source's and the
// host and image targets' code, every argument and stdin it gives), the
// target varlatchd (keys, journal, gate, import, checks, the live open,
// serving under the transfer's gate), and the public URL check over HTTP.
//
// What stands in, as this test binary re-run under another name:
//   - `docker`, for the last TypeScript release's Compose installation (not
//     published yet): `compose exec … admin migration status|barrier|
//     release|mark-migrated-out|export` answer as the TypeScript CLI's do
//     (slices 7.2a and 7.2b), the gate kept in a file, the export written
//     from migrationtest's seed (digests under the run key from stdin, the
//     decision table computed once); `compose images`, `image inspect`
//     and `compose stop|start varlatch-web` as Docker would answer;
//   - `varlatch-ts`, the TypeScript host CLI's backup create and verify;
//   - `systemctl`, starting and stopping the target's varlatchd process.
// The source's public URL is a local reverse proxy standing in for the
// operator's (the own-proxy shape): it serves the TypeScript side's
// /v1/meta (503 behind a gate) while the dashboard runs, and forwards to
// the target's listen once it stopped.

// stdTB is the seed's TB for the stand-ins, which are not tests.
type stdTB struct{}

func (stdTB) Helper()                      {}
func (stdTB) Fatal(args ...any)            { fmt.Fprintln(os.Stderr, args...); os.Exit(1) }
func (stdTB) Fatalf(f string, args ...any) { fmt.Fprintf(os.Stderr, f+"\n", args...); os.Exit(1) }

func TestMain(m *testing.M) {
	switch filepath.Base(os.Args[0]) {
	case "docker":
		os.Exit(fakeDocker(os.Args[1:]))
	case "varlatch-ts":
		os.Exit(fakeTSCLI(os.Args[1:]))
	case "systemctl":
		os.Exit(fakeSystemctl(os.Args[1:]))
	case "g5-sidecar":
		os.Exit(runSidecar())
	}
	os.Exit(m.Run())
}

// state is the stand-ins' state directory (G5_STATE).
func state(name string) string { return filepath.Join(os.Getenv("G5_STATE"), name) }

// savedSource is the seed on disk: the stand-in source's "database".
type savedSource struct {
	RootKEK       string                       `json:"rootKek"`
	AuditPosition int64                        `json:"auditPosition"`
	Rows          map[string][]json.RawMessage `json:"rows"`
}

func saveSource(s migrationtest.Source, path string) error {
	out := savedSource{RootKEK: hex.EncodeToString(s.RootKEK), AuditPosition: s.AuditPosition, Rows: map[string][]json.RawMessage{}}
	for k, rows := range s.Rows {
		for _, r := range rows {
			out.Rows[k] = append(out.Rows[k], jsvalue.Stringify(r))
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func loadSource(path string) (migrationtest.Source, error) {
	var in savedSource
	b, err := os.ReadFile(path)
	if err != nil {
		return migrationtest.Source{}, err
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return migrationtest.Source{}, err
	}
	s := migrationtest.Source{AuditPosition: in.AuditPosition, Rows: map[string][]jsvalue.Object{}}
	if s.RootKEK, err = hex.DecodeString(in.RootKEK); err != nil {
		return s, err
	}
	for k, rows := range in.Rows {
		for _, r := range rows {
			v, err := jsvalue.Parse(r)
			if err != nil {
				return s, err
			}
			s.Rows[k] = append(s.Rows[k], v.(jsvalue.Object))
		}
	}
	return s, nil
}

// gateDoc is the stand-in source's maintenance gate.
type gateDoc struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Phase string `json:"phase"`
}

func readGate() *gateDoc {
	b, err := os.ReadFile(state("gate.json"))
	if err != nil {
		return nil
	}
	var g gateDoc
	if json.Unmarshal(b, &g) != nil {
		return nil
	}
	return &g
}

func writeGate(g *gateDoc) error {
	if g == nil {
		err := os.Remove(state("gate.json"))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	b, _ := json.Marshal(g)
	return os.WriteFile(state("gate.json"), b, 0o600)
}

// fakeDocker answers as Docker and the TypeScript CLI in its container.
func fakeDocker(args []string) int {
	fail := func(f string, a ...any) int { fmt.Fprintf(os.Stderr, f+"\n", a...); return 1 }
	if os.Getenv("G5_TAILNET") != "" {
		if code, ok := fakeDockerTailnet(args); ok {
			return code
		}
	}
	if code, ok := fakeDockerReverse(args); ok {
		return code
	}
	j := strings.Join(args, " ")
	switch {
	case j == "compose images --format json varlatchd":
		fmt.Println(`[{"ContainerName":"g5-varlatchd-1","Repository":"ghcr.io/varlatch/varlatchd","Tag":"0.23.0","ID":"sha256:g5image"}]`)
		return 0
	case j == "image inspect --format {{json .}} sha256:g5image":
		fmt.Printf(`{"RepoDigests":["%s"],"Config":{"Labels":{"org.opencontainers.image.version":"0.23.0"}}}`+"\n", os.Getenv("VARLATCH_MIGRATE_PIN"))
		return 0
	case len(args) == 3 && args[0] == "compose" && (args[1] == "stop" || args[1] == "start") && args[2] == "varlatch-web":
		if args[1] == "stop" {
			return okOr(os.WriteFile(state("web-stopped"), nil, 0o600))
		}
		if err := os.Remove(state("web-stopped")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fail("%v", err)
		}
		return 0
	}
	prefix := []string{"compose", "exec", "-T", "varlatchd", "node", "dist/cli.js", "admin", "migration"}
	if len(args) < len(prefix)+1 || !slices.Equal(args[:len(prefix)], prefix) {
		return fail("docker: unexpected %q", j)
	}
	if stopped("varlatchd") {
		return fail("service \"varlatchd\" is not running")
	}
	return tsMigration(args[len(prefix)], args[len(prefix)+1:])
}

// tsMigration is the TypeScript CLI's `admin migration <verb>`, in the
// daemon's container (exec) or a one-off one (run), on the database the
// installation's Compose files name now.
func tsMigration(verb string, rest []string) int {
	fail := func(f string, a ...any) int { fmt.Fprintf(os.Stderr, f+"\n", a...); return 1 }
	g := readGate()
	switch verb {
	case "status":
		b, _ := json.Marshal(map[string]any{"daemon": true, "gate": g})
		fmt.Println(string(b))
	case "barrier":
		if g != nil && g.Kind != "migration" {
			return fail("A %s gate is open; the migration barrier was not opened", g.Kind)
		}
		if g == nil {
			id := make([]byte, 8)
			_, _ = rand.Read(id)
			g = &gateDoc{Kind: "migration", ID: "gate-" + hex.EncodeToString(id), Phase: "frozen"}
			if err := writeGate(g); err != nil {
				return fail("%v", err)
			}
		}
		s, err := loadSource(currentDB())
		if err != nil {
			return fail("%v", err)
		}
		b, _ := json.Marshal(map[string]any{"gate": g, "drained": map[string]any{"ms": 3, "waitedFor": map[string]int{}},
			"frozen": map[string]any{"auditPosition": strconv.FormatInt(s.AuditPosition, 10), "at": time.Now().UTC().Format(time.RFC3339Nano), "snapshot": "00000003-0000001B-1"}})
		fmt.Println(string(b))
	case "release", "mark-migrated-out":
		if len(rest) != 2 || rest[0] != "--id" || g == nil || g.Kind != "migration" || g.ID != rest[1] {
			return fail("Migration ownership lost; no such barrier is open")
		}
		if verb == "release" {
			if err := writeGate(nil); err != nil {
				return fail("%v", err)
			}
			fmt.Println(`{"released":true}`)
		} else {
			g.Kind, g.Phase = "migrated-out", "final"
			if err := writeGate(g); err != nil {
				return fail("%v", err)
			}
			b, _ := json.Marshal(map[string]any{"gate": g})
			fmt.Println(string(b))
		}
	case "export":
		dry := slices.Contains(rest, "--dry-run")
		if len(rest) < 3 || rest[0] != "--out" || !strings.HasPrefix(rest[1], "/backups/") || rest[2] != "--digests" {
			return fail("usage")
		}
		if !dry && (g == nil || g.Kind != "migration") {
			return fail("varlatchd admin migration export: no migration barrier is held; nothing was exported")
		}
		if dry && g != nil {
			return fail("varlatchd admin migration export: a %s gate is open: a dry run reads a running installation only", g.Kind)
		}
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		key, kerr := hex.DecodeString(strings.TrimSpace(line))
		if err != nil || kerr != nil || len(key) != 32 {
			return fail("the run key on standard input is not 64 lowercase hex digits")
		}
		f, err := os.OpenFile(state("runkeys"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err == nil {
			fmt.Fprintln(f, hex.EncodeToString(key))
			f.Close()
		}
		s, err := loadSource(currentDB())
		if err != nil {
			return fail("%v", err)
		}
		var sec migrationtest.Sections
		if currentDB() == state("source.json") {
			b, err := os.ReadFile(state("decisions.json"))
			if err != nil || json.Unmarshal(b, &sec.Decisions) != nil {
				return fail("the decision table")
			}
		} else if sec.Decisions, err = decideOn(s); err != nil {
			return fail("the decision table: %v", err)
		}
		sec.At, sec.Digests = 1795000000000000, migrationtest.Digests(stdTB{}, s, key)
		out := migrationtest.Bundle(stdTB{}, s, migrationtest.Options{Sections: &sec})
		if err := os.WriteFile(filepath.Join("backups", strings.TrimPrefix(rest[1], "/backups/")), out, 0o600); err != nil {
			return fail("%v", err)
		}
		fmt.Println(`{"frozenPoint":{},"bundle":{},"preflight":{"ok":true}}`)
	default:
		return fail("unknown verb %s", verb)
	}
	return 0
}

func okOr(err error) int {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// fakeTSCLI is the TypeScript host CLI's backup create and verify.
func fakeTSCLI(args []string) int {
	j := strings.Join(args, " ")
	if f, err := os.OpenFile(state("ts-calls"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600); err == nil {
		fmt.Fprintln(f, j)
		f.Close()
	}
	const archive = "0f0e0d0c-0b0a-4908-8706-050403020100"
	switch {
	case strings.HasPrefix(j, "admin backup create "):
		if _, err := os.Stat(state("fail-backup")); err == nil {
			fmt.Fprintln(os.Stderr, "varlatch-ts: the backup failed (the test's)")
			return 1
		}
		// The real CLI's backup reads the running varlatchd, Postgres and
		// Convex (docker compose exec).
		for _, svc := range []string{"varlatchd", "postgres", "convex-backend"} {
			if stopped(svc) {
				fmt.Fprintf(os.Stderr, "service %q is not running\n", svc)
				return 1
			}
		}
		fmt.Printf("Archive created: backups/%s.vltbak (%s)\nUpload completed to offsite; remote retrieval has not been verified.\n", archive, archive)
	case strings.HasPrefix(j, "admin backup verify ") && strings.Contains(j, "--archive "+archive):
		fmt.Printf(`{"archiveId":"%s","integrity":true,"compatibility":true,"keyMatch":true,"message":"checks passed"}`+"\n", archive)
	default:
		fmt.Fprintf(os.Stderr, "varlatch-ts: unexpected %q\n", j)
		return 1
	}
	return 0
}

// fakeSystemctl starts and stops the target's varlatchd (G5_STATE's
// service.conf and varlatchd), as its unit would.
func fakeSystemctl(args []string) int {
	if len(args) != 2 {
		return 1
	}
	pid := readPID()
	switch args[0] {
	case "start":
		if pid > 0 && alive(pid) {
			return 0
		}
		return okOr(startService(state("varlatchd"), state("service.conf")))
	case "stop":
		return okOr(stopService())
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

// alive is whether pid runs (a zombie does not).
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
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	if err := os.WriteFile(state("service.pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		return err
	}
	// Running once its control socket answers.
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

// --- the gate ---

// world is one migration's setting: the stand-in source's Compose
// directory, the target, the stand-ins' state, the public URL.
type world struct {
	t                 *testing.T
	stateDir, compose string
	conf, data, keys  string
	image             bool
	coolify           bool
	serviceConf       string // the image's service configuration (container paths)
	origin, listen    string
	outputs           [][]byte
	installationID    string
	// env and extraArgs are a world's own, for every run (the tailnet's).
	env       []string
	extraArgs []string
	// secrets are a world's own, scanned for too (the tailnet's OAuth
	// client secret and auth key).
	secrets [][]byte
}

// shared is built once: the binaries, the seed and its decision table.
var shared struct {
	once                   sync.Once
	dir, varlatch, fakebin string
	source                 migrationtest.Source
	sourceFile, decisions  string
	pin                    string
	err                    error
}

func setUpShared(t *testing.T) {
	shared.once.Do(func() {
		dir, err := os.MkdirTemp("", "g5-interrupt-")
		if err != nil {
			shared.err = err
			return
		}
		shared.dir = dir
		root, _ := filepath.Abs(filepath.Join("..", "..", ".."))
		bin := filepath.Join(dir, "bin")
		_ = os.Mkdir(bin, 0o755)
		// varlatchd with the crashpoint tag too: its tailnet node joins the
		// gate's control server (tailnethook_crashpoint.go); without
		// VARLATCH_TEST_TAILNET_CONTROL it is as a release builds it.
		for _, b := range []struct{ out, pkg, tags string }{{"varlatchd", "./cmd/varlatchd", "crashpoint"}, {"varlatch", "./cmd/varlatch", "crashpoint"}} {
			args := []string{"build", "-o", filepath.Join(bin, b.out)}
			if b.tags != "" {
				args = append(args, "-tags", b.tags)
			}
			cmd := exec.Command("go", append(args, b.pkg)...)
			cmd.Dir, cmd.Env = root, append(os.Environ(), "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				shared.err = fmt.Errorf("go build %s: %v\n%s", b.pkg, err, out)
				return
			}
		}
		shared.varlatch = filepath.Join(bin, "varlatch")
		shared.fakebin = filepath.Join(dir, "fakebin")
		_ = os.Mkdir(shared.fakebin, 0o755)
		self, _ := os.Executable()
		for _, n := range []string{"docker", "varlatch-ts", "systemctl", "g5-sidecar"} {
			if err := os.Symlink(self, filepath.Join(shared.fakebin, n)); err != nil {
				shared.err = err
				return
			}
		}
		shared.source = migrationtest.Load(t)
		shared.sourceFile = filepath.Join(dir, "source.json")
		if shared.err = saveSource(shared.source, shared.sourceFile); shared.err != nil {
			return
		}
		shared.pin = "ghcr.io/varlatch/varlatchd@sha256:" + hex.EncodeToString(randomBytes(32))
		// The decision table: the TypeScript evaluator's arrives with its
		// export; here, the tuples evaluated on an import of the seed.
		first := filepath.Join(dir, "first")
		_ = os.Mkdir(first, 0o700)
		b := migrationtest.Bundle(t, shared.source, migrationtest.Options{})
		if _, err := migrate.Import(context.Background(), bytes.NewReader(b), migrate.Options{DataDir: first, RootKEK: shared.source.RootKEK, Release: "0.50.0-g5"}); err != nil {
			shared.err = err
			return
		}
		db, err := sql.Open("sqlite", "file:"+filepath.Join(first, "varlatch.db")+"?mode=ro")
		if err != nil {
			shared.err = err
			return
		}
		var decisions []bundle.Decision
		for _, d := range migrationtest.Tuples(t, db, 8) {
			got, err := check.Evaluate(context.Background(), db, d)
			if err != nil {
				shared.err = err
				return
			}
			decisions = append(decisions, got)
		}
		db.Close()
		raw, _ := json.Marshal(decisions)
		shared.decisions = filepath.Join(dir, "decisions.json")
		shared.err = os.WriteFile(shared.decisions, raw, 0o600)
	})
	if shared.err != nil {
		t.Fatal(shared.err)
	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// newWorld is a fresh source and target, the public URL's proxy serving
// it.
func newWorld(t *testing.T, image bool) *world {
	setUpShared(t)
	base := t.TempDir()
	w := &world{t: t, stateDir: filepath.Join(base, "state"), compose: filepath.Join(base, "compose"), image: image, listen: freePort(t)}
	for _, d := range []string{w.stateDir, w.compose, filepath.Join(w.compose, "backups"), filepath.Join(w.compose, "secrets")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, from := range map[string]string{"source.json": shared.sourceFile, "decisions.json": shared.decisions} {
		b, _ := os.ReadFile(from)
		if err := os.WriteFile(filepath.Join(w.stateDir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(filepath.Dir(shared.varlatch), "varlatchd"), filepath.Join(w.stateDir, "varlatchd")); err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(http.HandlerFunc(w.serveOrigin))
	t.Cleanup(proxy.Close)
	w.origin = proxy.URL
	_, port, _ := net.SplitHostPort(w.listen)
	files := map[string]string{
		"docker-compose.yml":    "name: g5-installation\nservices: {}\n", // a project named apart from its directory, as the release's is
		".env":                  "VARLATCH_PUBLIC_URL=" + w.origin + "\nBIND_ADDRESS=127.0.0.1\nVARLATCH_WEB_PORT=" + port + "\n",
		"secrets/varlatch-kek":  hex.EncodeToString(shared.source.RootKEK) + "\n",
		"bek":                   hex.EncodeToString(randomBytes(32)) + "\n",
		"read-credentials.json": "{}\n",
	}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(w.compose, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(base, "target")
	w.data, w.keys = filepath.Join(target, "data"), filepath.Join(target, "keys")
	for _, d := range []string{w.data, w.keys} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	host := fmt.Sprintf("listen = %s\npublic_url = %s\ndata_dir = %s\nroot_kek_file = %s\nbackup_key_file = %s\nbackup_interval = off\n",
		w.listen, w.origin, w.data, filepath.Join(w.keys, "root-kek"), filepath.Join(w.keys, "backup-key"))
	w.conf = filepath.Join(target, "varlatchd.conf")
	if err := os.WriteFile(w.conf, []byte(host), 0o600); err != nil {
		t.Fatal(err)
	}
	// The service's own (the systemd unit's, or, for the image, what its
	// container would read with the bind paths at their host paths).
	if err := os.WriteFile(filepath.Join(w.stateDir, "service.conf"), []byte(host), 0o600); err != nil {
		t.Fatal(err)
	}
	if image {
		w.serviceConf = filepath.Join(target, "service-varlatchd.conf")
		svc := fmt.Sprintf("listen = %s\npublic_url = %s\ndata_dir = /var/lib/varlatch\nroot_kek_file = /keys/root-kek\nbackup_key_file = /keys/backup-key\nbackup_interval = off\n", w.listen, w.origin)
		if err := os.WriteFile(w.serviceConf, []byte(svc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w.installationID = rowValue(shared.source.Rows["installation"][0], "id")
	t.Cleanup(func() {
		_ = os.Setenv("G5_STATE", w.stateDir)
		_ = stopService()
	})
	return w
}

func rowValue(o jsvalue.Object, k string) string {
	v, _ := o.Get(k)
	s, _ := v.(string)
	return s
}

// serveOrigin is the public URL: the TypeScript side's /v1/meta while its
// dashboard runs (503 behind a gate), the target's listen once it stopped.
func (w *world) serveOrigin(rw http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat(filepath.Join(w.stateDir, "web-stopped")); err == nil {
		u, _ := url.Parse("http://" + w.listen)
		httputil.NewSingleHostReverseProxy(u).ServeHTTP(rw, r)
		return
	}
	if _, err := os.Stat(filepath.Join(w.stateDir, "stopped-varlatchd")); err == nil {
		// The dashboard runs, its varlatchd does not.
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	b, _ := os.ReadFile(filepath.Join(w.stateDir, "gate.json"))
	if len(b) > 0 {
		rw.WriteHeader(http.StatusServiceUnavailable)
		_, _ = rw.Write([]byte(`{"error":{"code":"MAINTENANCE"}}`))
		return
	}
	if r.URL.Path != "/v1/meta" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}
	fmt.Fprintf(rw, `{"apiMajor":1,"serverVersion":"0.23.0","capabilities":[],"installationId":"%s"}`, w.installationID)
}

// args are the migration's options.
func (w *world) args(extra ...string) []string {
	ingress := "proxy"
	if w.coolify {
		ingress = "coolify"
	}
	a := []string{"migrate", "--ingress", ingress, "--from", w.compose, "--bek-file", filepath.Join(w.compose, "bek"), "--backup-destination", "offsite",
		"--read-credentials-file", filepath.Join(w.compose, "read-credentials.json"), "--ts-cli", "varlatch-ts", "--max-downtime", "1h",
		"--transfer-timeout", "60s", "--drain", "5s"}
	if w.image {
		a = append(a, "--to-data", w.data, "--to-keys", w.keys, "--to-config", w.serviceConf, "--to-image",
			"ghcr.io/varlatch/varlatchd:0.50.0-dev@sha256:"+hex.EncodeToString(randomBytes(32)), "--to-service", "varlatch-go")
	} else {
		a = append(a, "--config", w.conf)
	}
	return append(append(a, w.extraArgs...), extra...)
}

// run runs varlatch migrate; with pause, it is killed (SIGKILL) where it
// pauses. It returns the exit status (-1 when killed).
func (w *world) run(pause string, extra ...string) int {
	w.t.Helper()
	return w.runArgs(pause, w.args(extra...))
}

// runArgs is run with the CLI's arguments as given.
func (w *world) runArgs(pause string, args []string) int {
	t := w.t
	t.Helper()
	log := filepath.Join(w.stateDir, "crashpoints.log")
	_ = os.Remove(log)
	cmd := exec.Command(shared.varlatch, args...)
	cmd.Env = append(os.Environ(), "PATH="+shared.fakebin+":"+os.Getenv("PATH"), "G5_STATE="+w.stateDir, "VARLATCH_MIGRATE_PIN="+shared.pin,
		"VARLATCH_MIGRATE_LOG="+log, "VARLATCH_MIGRATE_PAUSE="+pause, "TMPDIR="+w.stateDir,
		fmt.Sprintf("VARLATCH_MIGRATE_IMAGE_USER=%d:%d", os.Getuid(), os.Getgid()))
	cmd.Env = append(cmd.Env, w.env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() { w.outputs = append(w.outputs, out.Bytes()) }()
	if pause == "" {
		select {
		case err := <-done:
			return exitCode(err)
		case <-time.After(5 * time.Minute):
			_ = cmd.Process.Kill()
			t.Fatalf("varlatch migrate did not finish:\n%s", out.String())
		}
	}
	for deadline := time.Now().Add(5 * time.Minute); ; time.Sleep(20 * time.Millisecond) {
		b, _ := os.ReadFile(log)
		if bytes.Contains(b, []byte("paused "+pause+"\n")) {
			_ = cmd.Process.Signal(syscall.SIGKILL)
			<-done
			return -1
		}
		select {
		case err := <-done:
			t.Fatalf("varlatch migrate ended (%d) before pausing at %q:\n%s", exitCode(err), pause, out.String())
		default:
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("varlatch migrate did not reach %q", pause)
		}
	}
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

// sourceHash is the stand-in source's data and configuration, hashed: a
// migration never changes them (decision 9).
func (w *world) sourceHash() string {
	h := sha256.New()
	for _, p := range []string{filepath.Join(w.stateDir, "source.json"), filepath.Join(w.compose, "secrets", "varlatch-kek"), filepath.Join(w.compose, ".env"),
		filepath.Join(w.compose, "docker-compose.yml")} {
		b, err := os.ReadFile(p)
		if err != nil {
			w.t.Fatal(err)
		}
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// phases are the journals' phases: the source's, the target's ("" for
// none).
func (w *world) phases() (string, string) {
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			return ""
		}
		var j struct {
			Phase string `json:"phase"`
		}
		_ = json.Unmarshal(b, &j)
		return j.Phase
	}
	return read(filepath.Join(w.compose, "migration.json")), read(filepath.Join(w.data, "migration.json"))
}

// answers is which side the public URL answers from: "source" (the
// TypeScript side's /v1/meta), "source-barrier" (its 503), "target-gated"
// (the target's /v1/meta, every other route 503), "target-open", or "none".
func (w *world) answers() string {
	get := func(p string) (int, string) {
		res, err := http.Get(w.origin + p)
		if err != nil {
			return 0, ""
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	code, body := get("/v1/meta")
	switch {
	case code == http.StatusOK && strings.Contains(body, `"serverVersion":"0.23.0"`):
		return "source"
	case code == http.StatusServiceUnavailable && strings.Contains(body, "MAINTENANCE") && !strings.Contains(body, "message"):
		return "source-barrier"
	case code == http.StatusOK:
		if c, _ := get("/v1/whoami"); c == http.StatusServiceUnavailable {
			return "target-gated"
		}
		return "target-open"
	}
	return "none"
}

// gateKind is the stand-in source's gate.
func (w *world) gateKind() string {
	b, err := os.ReadFile(filepath.Join(w.stateDir, "gate.json"))
	if err != nil {
		return ""
	}
	var g gateDoc
	_ = json.Unmarshal(b, &g)
	return g.Kind
}

// expect holds the stated state.
func (w *world) expect(when, src, tgt, answers, gate string) {
	t := w.t
	t.Helper()
	s, d := w.phases()
	if s != src || d != tgt {
		t.Errorf("%s: journals %q / %q, want %q / %q", when, s, d, src, tgt)
	}
	if a := w.answers(); a != answers {
		t.Errorf("%s: the public URL answers from %s, want %s", when, a, answers)
	}
	if g := w.gateKind(); g != gate {
		t.Errorf("%s: the source's gate %q, want %q", when, g, gate)
	}
}

// noSecrets scans every output, journal and log for the keys and the run
// keys.
func (w *world) noSecrets() {
	t := w.t
	t.Helper()
	bek, _ := os.ReadFile(filepath.Join(w.compose, "bek"))
	secrets := append([][]byte{shared.source.RootKEK, bytes.TrimSpace(bek)}, w.secrets...)
	if b, err := os.ReadFile(filepath.Join(w.stateDir, "runkeys")); err == nil {
		for _, l := range strings.Fields(string(b)) {
			k, _ := hex.DecodeString(l)
			secrets = append(secrets, k)
		}
	}
	texts := slices.Clone(w.outputs)
	for _, p := range []string{filepath.Join(w.compose, "migration.json"), filepath.Join(w.data, "migration.json"), filepath.Join(w.stateDir, "service.log"),
		filepath.Join(w.stateDir, "crashpoints.log")} {
		if b, err := os.ReadFile(p); err == nil {
			texts = append(texts, b)
		}
	}
	for _, text := range texts {
		for _, s := range secrets {
			for _, form := range migrationtest.Forms(s) {
				if len(form) >= 16 && bytes.Contains(text, form) {
					t.Fatalf("a key or run key in an output, a journal or a log:\n%s", text)
				}
			}
		}
	}
}

// startImageService and stopImageService are the operator's steps for the
// image's service: varlatchd on its configuration at the host paths.
func (w *world) startImageService() {
	w.t.Helper()
	if err := startService(filepath.Join(filepath.Dir(shared.varlatch), "varlatchd"), filepath.Join(w.stateDir, "service.conf")); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) useState() { _ = os.Setenv("G5_STATE", w.stateDir) }

// G5, interrupted: varlatch migrate killed at each phase boundary, the
// stated state held there, then --resume (and --abort) taking it to its
// end. Host install, own-proxy ingress.
func TestG5Interruptions(t *testing.T) {
	for _, c := range []struct {
		point string
		// The stated state after the kill: the journals, who answers, the
		// source's gate.
		src, tgt, answers, gate string
		// Where --resume takes it.
		resumed string
		// Whether --abort is allowed, and so tried on another run.
		abort bool
	}{
		{"entered started", "started", "started", "source", "", "open", true},
		{"entered preflight", "preflight", "preflight", "source", "", "open", true},
		{"entered dry-run", "dry-run", "dry-run", "source", "", "open", true},
		{"entered barrier", "barrier", "barrier", "source", "", "released", true},
		{"barrier held", "barrier", "barrier", "source-barrier", "migration", "released", true},
		{"entered copied", "copied", "copied", "source-barrier", "migration", "released", true},
		{"entered checked", "checked", "checked", "source-barrier", "migration", "released", true},
		{"transfer started", "transfer", "transfer", "target-gated", "migration", "open", true},
		// Journalled switched before the mark: the barrier stands.
		{"entered switched", "switched", "switched", "target-gated", "migration", "open", false},
		{"open source", "open", "switched", "target-gated", "migrated-out", "open", false},
	} {
		for _, abort := range []bool{false, true} {
			if abort && !c.abort {
				continue
			}
			name := c.point + map[bool]string{false: ", resumed", true: ", aborted"}[abort]
			t.Run(name, func(t *testing.T) {
				w := newWorld(t, false)
				w.useState()
				before := w.sourceHash()
				if code := w.run(c.point); code != -1 {
					t.Fatalf("not killed: %d", code)
				}
				w.expect("killed at "+c.point, c.src, c.tgt, c.answers, c.gate)
				// A plain run refuses an interrupted migration.
				if code := w.run(""); code != 1 {
					t.Errorf("a run over the interrupted migration: %d", code)
				}
				if !c.abort {
					// Past the switch an abort is refused, and changes
					// nothing.
					if code := w.run("", "--abort"); code != 1 {
						t.Fatalf("--abort past the switch: %d\n%s", code, w.outputs[len(w.outputs)-1])
					}
					w.expect("an abort refused at "+c.point, c.src, c.tgt, c.answers, c.gate)
				}
				final := c.resumed
				if abort {
					final = "released"
					code := w.run("", "--abort")
					if code != 0 {
						t.Fatalf("--abort: %d\n%s", code, w.outputs[len(w.outputs)-1])
					}
				} else {
					code := w.run("", "--resume")
					if (final == "open") != (code == 0) {
						t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
					}
				}
				finished := func(when string) {
					switch final {
					case "open":
						w.expect(when, "open", "open", "target-open", "migrated-out")
					case "released":
						w.expect(when, "released", "released", "source", "")
						if _, err := os.Stat(filepath.Join(w.data, "varlatch.db")); !os.IsNotExist(err) {
							t.Errorf("%s: the target's database was not discarded: %v", when, err)
						}
					}
				}
				finished(map[bool]string{false: "resumed", true: "undone"}[abort])
				if after := w.sourceHash(); after != before {
					t.Error("the source's data changed")
				}
				// --resume again changes nothing.
				if code := w.run("", "--resume"); code != 0 {
					t.Errorf("a second --resume: %d", code)
				}
				finished("after a second --resume")
				w.noSecrets()
			})
		}
	}
}

// The image's service: the operator's start at the transfer (exit 75),
// killed before it and after the switch, and an abort while it runs.
func TestG5InterruptionsImage(t *testing.T) {
	t.Run("the operator's start", func(t *testing.T) {
		w := newWorld(t, true)
		w.useState()
		before := w.sourceHash()
		if code := w.run("entered transfer"); code != -1 {
			t.Fatalf("not killed: %d", code)
		}
		// Journalled transfer before the dashboard stops: the source's 503.
		w.expect("killed at the transfer", "transfer", "transfer", "source-barrier", "migration")
		if code := w.run("", "--resume"); code != 75 {
			t.Fatalf("--resume before the start: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if out := string(w.outputs[len(w.outputs)-1]); !strings.Contains(out, "Start the Go service varlatch-go (image ghcr.io/varlatch/varlatchd, tag 0.50.0-dev, digest sha256:") ||
			strings.Contains(out, "[redacted]") {
			t.Fatalf("no start step:\n%s", w.outputs[len(w.outputs)-1])
		}
		w.startImageService()
		if code := w.run("open source", "--resume"); code != -1 {
			t.Fatalf("not killed at the open: %d", code)
		}
		w.expect("killed at the open", "open", "switched", "target-gated", "migrated-out")
		if code := w.run("", "--resume"); code != 0 {
			t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expect("resumed", "open", "open", "target-open", "migrated-out")
		if w.sourceHash() != before {
			t.Error("the source's data changed")
		}
		w.noSecrets()
	})
	t.Run("an abort while the service runs", func(t *testing.T) {
		w := newWorld(t, true)
		w.useState()
		before := w.sourceHash()
		if code := w.run(""); code != 75 {
			t.Fatalf("the transfer's stop: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.startImageService()
		w.expect("the service started", "transfer", "transfer", "target-gated", "migration")
		if code := w.run("", "--abort"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "Stop the Go service varlatch-go") {
			t.Fatalf("--abort while it runs: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		_ = stopService()
		if code := w.run("", "--resume"); code != 1 {
			t.Fatalf("the undo resumed: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expect("undone", "released", "released", "source", "")
		if w.sourceHash() != before {
			t.Error("the source's data changed")
		}
		w.noSecrets()
	})
}

// The Coolify shape (O3): the target starts, migrate stops (exit 75) with
// the domain move, writing beside the running target that it asked;
// killed after the move is checked (the switch), --resume opens it.
func TestG5InterruptionsCoolify(t *testing.T) {
	w := newWorld(t, false)
	w.coolify = true
	w.useState()
	before := w.sourceHash()
	if code := w.run(""); code != 75 {
		t.Fatalf("the domain move's stop: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if out := string(w.outputs[len(w.outputs)-1]); !strings.Contains(out, "in Coolify, move the domain of "+w.origin) {
		t.Fatalf("no domain move:\n%s", out)
	}
	w.expect("waiting for the move", "transfer", "transfer", "source-barrier", "migration")
	// Before the move: still waiting, nothing undone.
	if code := w.run("", "--resume", "--transfer-timeout", "3s"); code != 1 {
		t.Fatalf("--resume before the move: %d", code)
	}
	w.expect("still waiting", "transfer", "transfer", "source-barrier", "migration")
	// The operator moves the domain: the public URL leads to the target.
	if err := os.WriteFile(filepath.Join(w.stateDir, "web-stopped"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := w.run("entered switched", "--resume"); code != -1 {
		t.Fatalf("not killed at the switch: %d", code)
	}
	w.expect("killed at the switch", "switched", "switched", "target-gated", "migration")
	if code := w.run("", "--resume"); code != 0 {
		t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.expect("resumed", "open", "open", "target-open", "migrated-out")
	if w.sourceHash() != before {
		t.Error("the source's data changed")
	}
	w.noSecrets()
}
