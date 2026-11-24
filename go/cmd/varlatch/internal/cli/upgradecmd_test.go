// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/migrate"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate/fakerelease"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/upgrade"
	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/release"
)

func runUpgrade(t *testing.T, env MapEnv, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if env == nil {
		env = MapEnv{}
	}
	env["HOME"], env["VARLATCH_CONFIG_DIR"] = t.TempDir(), t.TempDir()
	code := Main(append([]string{"upgrade"}, args...), env, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
	return code, stdout.String(), stderr.String()
}

// A Compose installation's upgrade is the TypeScript CLI's: its options
// are refused, naming it.
func TestUpgradeRefusesComposeOptions(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--dir", "/srv/varlatch"}, "varlatch upgrade: --dir names a Compose installation"},
		{[]string{"--backup-dir=/b"}, "varlatch upgrade: --backup-dir is an option of a Compose installation's upgrade"},
		{[]string{"0.50.0", "--skip-db-backup"}, "varlatch upgrade: --skip-db-backup is an option of a Compose installation's upgrade"},
	} {
		code, _, errs := runUpgrade(t, nil, c.args...)
		if code != ExitUsage || !strings.Contains(errs, c.want) || !strings.Contains(errs, "varlatch-ts") {
			t.Errorf("%v: %d %q", c.args, code, errs)
		}
	}
}

func TestUpgradeUsageAndPrivilege(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--json"}, "--json goes with --check"},
		{[]string{"--check", "--yes"}, "--check upgrades nothing"},
		{[]string{"--repo", "someone/fork"}, "releases come from varlatch/varlatch only"},
		{[]string{"a", "b"}, "Usage:\n  varlatch upgrade"},
	} {
		if code, _, errs := runUpgrade(t, nil, c.args...); code != ExitUsage || !strings.Contains(errs, c.want) {
			t.Errorf("%v: %d %q", c.args, code, errs)
		}
	}
	if runtime.GOOS != "linux" {
		if code, _, errs := runUpgrade(t, nil, "--yes"); code != ExitUsage || !strings.Contains(errs, "runs on Linux") {
			t.Fatalf("not Linux: %d %q", code, errs)
		}
		return
	}
	defer func(f func() bool) { asRoot = f }(asRoot)
	asRoot = func() bool { return false }
	if code, _, errs := runUpgrade(t, nil, "--yes"); code != ExitDenied || !strings.Contains(errs, "needs root: run it as sudo varlatch upgrade") {
		t.Fatalf("not root: %d %q", code, errs)
	}
}

// The command end to end on a host in a temporary directory: --check
// records the newer release for the dashboard; upgrade --yes upgrades to
// it; a release that is not rollback-safe is refused until accepted. As
// root (the command's rule): the host's directories are root's.
// reversible is the test releases' declaration that a reverse migration
// returns their data to the last TypeScript release, which lib/release
// requires of a release (reversibleTo, go-step7 decision 17).
var reversible = release.LastTypeScriptRelease

func TestUpgradeCommandOnAHost(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("builds varlatchd and runs as root on Linux (go.yml's Go container)")
	}
	from, to, unsafe := cliBuild(t, "0.50.0-rc.1", ""), cliBuild(t, "0.50.0-rc.2", "g6fixture"), cliBuild(t, "0.50.0-rc.2", "g6fixture,g6unsafe")
	srv := fakerelease.New()
	defer srv.Close()
	defer func(f func(*Run) selfupdate.Source) { selfUpdateSource = f }(selfUpdateSource)
	selfUpdateSource = func(*Run) selfupdate.Source { return srv.Source() }
	publish := func(varlatchd []byte, d release.Declaration) {
		m, err := release.NewManifest("0.50.0-rc.2", d)
		if err != nil {
			t.Fatal(err)
		}
		manifest, _ := m.Bytes()
		cli, server, name := upgrade.Assets("0.50.0-rc.2", runtime.GOARCH)
		srv.Publish("0.50.0-rc.2", &fakerelease.Release{Files: map[string][]byte{cli: []byte("#!/bin/sh\necho varlatch 0.50.0-rc.2\n"), server: varlatchd, name: manifest}})
	}
	// The rc.1 build is on this checkout's schema; rc.2's G6 fixture step
	// adds one.
	fromSchema := checkoutSchema(t)
	toSchema := fromSchema + 1
	prev := &release.Previous{Version: "0.50.0-rc.1", SchemaVersion: fromSchema}

	// Not rollback-safe: refused without --accept-not-rollback-safe.
	h := newCLIHost(t, from)
	publish(unsafe, release.Declaration{SchemaVersion: toSchema, CompatibleFrom: toSchema, Previous: prev, ReversibleTo: &reversible})
	// Held after a restore: refused before anything is fetched.
	if err := backup.WriteHold(h.data, backup.Hold{ArchiveID: "a", RestoredAt: "t"}); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--accept-not-rollback-safe", "--config", h.conf); code != ExitFailure || out != "" || !strings.Contains(errs, "run varlatch admin restore resume, then upgrade. Nothing was changed.") {
		t.Fatalf("held: %d %q %q", code, out, errs)
	}
	if err := backup.RemoveHold(h.data); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--config", h.conf)
	if code != ExitFailure || !strings.Contains(out, "rollback:  NOT safe") || !strings.Contains(errs, "pass --accept-not-rollback-safe") {
		t.Fatalf("not rollback-safe: %d %q %q", code, out, errs)
	}
	h.serves(t, "0.50.0-rc.1")
	code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--accept-not-rollback-safe", "--config", h.conf)
	if code != ExitOK || !strings.Contains(out, "Upgraded to 0.50.0-rc.2") {
		t.Fatalf("accepted: %d %q %q", code, out, errs)
	}
	h.serves(t, "0.50.0-rc.2")

	// Rollback-safe: --check records it, upgrade --yes upgrades.
	h = newCLIHost(t, from)
	publish(to, release.Declaration{SchemaVersion: toSchema, CompatibleFrom: 1, RollbackSafe: true, Previous: prev, ReversibleTo: &reversible})
	code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--check", "--config", h.conf)
	if code != ExitOK || !strings.Contains(out, "varlatchd 0.50.0-rc.2 is available (this host runs 0.50.0-rc.1)") {
		t.Fatalf("--check: %d %q %q", code, out, errs)
	}
	rc, err := release.ReadReleaseCheck(h.data)
	if err != nil || rc == nil || rc.LastSuccess == nil || rc.LastSuccess.Latest.Version != "0.50.0-rc.2" || rc.LastAttempt.Failed != nil {
		t.Fatalf("the release check: %+v, %v", rc, err)
	}
	if code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--config", h.conf); code != ExitFailure || !strings.Contains(errs, "not a terminal: pass --yes") {
		t.Fatalf("no --yes off a terminal: %d %q %q", code, out, errs)
	}
	code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--config", h.conf)
	if code != ExitOK || !strings.Contains(out, "rollback:  safe") || !strings.Contains(out, "Upgraded to 0.50.0-rc.2") {
		t.Fatalf("upgrade: %d %q %q", code, out, errs)
	}
	h.serves(t, "0.50.0-rc.2")
	if code, out, _ = runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--config", h.conf); code != ExitOK || !strings.Contains(out, "varlatchd 0.50.0-rc.2 is up to date") {
		t.Fatalf("again: %d %q", code, out)
	}

	// A release that ends the migration's rollback window (decision 17):
	// while the window is open, refused with --yes alone; with
	// --end-rollback-window, recorded in Go's journal (through the running
	// varlatchd) before the upgrade, which then goes through.
	ends := release.Declaration{SchemaVersion: toSchema, CompatibleFrom: 1, RollbackSafe: true, Previous: prev, EndsRollbackWindow: true}
	h = newCLIHost(t, from)
	h.migrated(t, time.Now().Add(-time.Hour))
	publish(to, ends)
	code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--config", h.conf)
	if code != ExitFailure || !strings.Contains(out, "migration: "+release.RollbackWindowNotice) || !strings.Contains(errs, "pass --end-rollback-window") {
		t.Fatalf("a window-ending release with --yes alone: %d %q %q", code, out, errs)
	}
	h.serves(t, "0.50.0-rc.1")
	if j := h.journal(t); j.WindowEnded != nil {
		t.Fatalf("the window recorded ended after a refusal: %+v", j.WindowEnded)
	}
	code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--end-rollback-window", "--config", h.conf)
	if code != ExitOK || !strings.Contains(out, "The migration's rollback window ends") || !strings.Contains(out, "Upgraded to 0.50.0-rc.2") {
		t.Fatalf("--end-rollback-window: %d %q %q", code, out, errs)
	}
	h.serves(t, "0.50.0-rc.2")
	if j := h.journal(t); j.WindowEnded == nil || j.WindowEnded.Release != "0.50.0-rc.2" || j.Phase != migrate.Open {
		t.Fatalf("the journal after the upgrade: %+v", j)
	}
	if open, err := migrate.RollbackWindowOpen(h.data, time.Now()); err != nil || open {
		t.Errorf("the window after the upgrade: %v %v", open, err)
	}

	// The same release with no window open (never migrated, or switched
	// more than 30 days ago): no question.
	for name, switched := range map[string]time.Time{"never migrated": {}, "past the window": time.Now().Add(-31 * 24 * time.Hour)} {
		h = newCLIHost(t, from)
		if !switched.IsZero() {
			h.migrated(t, switched)
		}
		publish(to, ends)
		code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--config", h.conf)
		if code != ExitOK || strings.Contains(out, "migration:") || !strings.Contains(out, "Upgraded to 0.50.0-rc.2") {
			t.Fatalf("%s: %d %q %q", name, code, out, errs)
		}
		h.serves(t, "0.50.0-rc.2")
	}
}

// migrated gives the host's data directory a migration's journal, open
// and switched at switched, as varlatch migrate leaves it; varlatchd is
// restarted on it.
func (h *cliHost) migrated(t *testing.T, switched time.Time) {
	t.Helper()
	j := &migrate.Journal{Format: 1, ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: migrate.Open, Ingress: migrate.Proxy,
		History: []migrate.Step{{Phase: migrate.Switched, At: switched.UTC().Format(time.RFC3339Nano)}, {Phase: migrate.Open, At: switched.UTC().Format(time.RFC3339Nano)}}}
	b, err := j.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.data, migrate.JournalFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.serves(t, "0.50.0-rc.1")
}

// journal is Go's migration journal on the host.
func (h *cliHost) journal(t *testing.T) *migrate.Journal {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.data, migrate.JournalFile))
	if err != nil {
		t.Fatal(err)
	}
	var j migrate.Journal
	if err := json.Unmarshal(b, &j); err != nil {
		t.Fatal(err)
	}
	return &j
}

var (
	cliBuilds   sync.Map
	cliBuildsMu sync.Mutex
)

func cliBuild(t *testing.T, version, tags string) []byte {
	t.Helper()
	cliBuildsMu.Lock()
	defer cliBuildsMu.Unlock()
	if b, ok := cliBuilds.Load(version + tags); ok {
		return b.([]byte)
	}
	out := filepath.Join(t.TempDir(), "varlatchd")
	cmd := exec.Command("go", "build", "-tags", tags, "-trimpath", "-ldflags", "-X github.com/varlatch/varlatch/go/lib/buildinfo.Version="+version,
		"-o", out, "github.com/varlatch/varlatch/go/cmd/varlatchd")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build varlatchd: %v\n%s", err, o)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	cliBuilds.Store(version+tags, b)
	return b
}

type cliHost struct {
	bin, conf, data string
	svc             *cliService
}

func newCLIHost(t *testing.T, varlatchd []byte) *cliHost {
	t.Helper()
	dir := t.TempDir()
	h := &cliHost{bin: filepath.Join(dir, "usr", "local", "bin"), conf: filepath.Join(dir, "etc", "varlatch", "varlatchd.conf"), data: filepath.Join(dir, "data")}
	for _, d := range []string{h.bin, filepath.Dir(h.conf), h.data, filepath.Join(dir, "keys")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []string{"root-kek", "backup-key"} {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		if err := os.WriteFile(filepath.Join(dir, "keys", k), []byte(hex.EncodeToString(b)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	conf := fmt.Sprintf("listen = 127.0.0.1:0\ndata_dir = %s\nroot_kek_file = %s\nbackup_key_file = %s\nbackup_interval = off\n",
		h.data, filepath.Join(dir, "keys", "root-kek"), filepath.Join(dir, "keys", "backup-key"))
	if err := os.WriteFile(h.conf, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.bin, "varlatchd"), varlatchd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.bin, "varlatch"), []byte("#!/bin/sh\necho varlatch 0.50.0-rc.1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.svc = &cliService{bin: h.bin, conf: h.conf}
	prevService := upgradeService
	upgradeService = func() upgrade.Service { return h.svc }
	t.Cleanup(func() { upgradeService = prevService; _ = h.svc.Stop(context.Background()) })
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.serves(t, "0.50.0-rc.1")
	return h
}

// serves waits for the host's varlatchd to answer admin status as version.
func (h *cliHost) serves(t *testing.T, version string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		out, err := exec.Command(filepath.Join(h.bin, "varlatchd"), "admin", "status", "--json", "--config", h.conf).Output()
		if err == nil && strings.Contains(string(out), `"version":"`+version+`"`) && strings.Contains(string(out), `"serving":true`) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("varlatchd %s does not serve: %s %v", version, out, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// cliService runs bin/varlatchd serve as the unit would.
type cliService struct {
	bin, conf string
	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
}

func (s *cliService) Start(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil {
		return nil // as systemctl start: nothing to do for a running unit
	}
	cmd := exec.Command(filepath.Join(s.bin, "varlatchd"), "serve", "--config", s.conf)
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	s.cmd, s.done = cmd, done
	return nil
}

func (s *cliService) Stop(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd == nil {
		return nil
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.done:
	case <-time.After(30 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.done
	}
	s.cmd = nil
	return nil
}

// windowEnding: a release that ends the window ends it only while one is
// open (an open journal, switched within 30 days, not ended already), and
// is refused while a reverse is under way, whose journal it could not
// record the end in; a release that keeps the window asks nothing.
func TestWindowEnding(t *testing.T) {
	now := time.Now()
	write := func(phase migrate.Phase, switched time.Time) string {
		t.Helper()
		dir := t.TempDir()
		j := &migrate.Journal{Format: 1, ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: phase, Ingress: migrate.Proxy,
			History: []migrate.Step{{Phase: migrate.Switched, At: switched.UTC().Format(time.RFC3339Nano)}}}
		b, err := j.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, migrate.JournalFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	if ends, err := windowEnding(t.TempDir(), "0.50.1", true, now); err != nil || ends {
		t.Errorf("never migrated: %v %v", ends, err)
	}
	open := write(migrate.Open, now.Add(-time.Hour))
	if ends, err := windowEnding(open, "0.50.1", true, now); err != nil || !ends {
		t.Errorf("open: %v %v", ends, err)
	}
	if ends, err := windowEnding(open, "0.50.1", false, now); err != nil || ends {
		t.Errorf("a release that keeps the window: %v %v", ends, err)
	}
	if ends, err := windowEnding(write(migrate.Open, now.Add(-31*24*time.Hour)), "0.50.1", true, now); err != nil || ends {
		t.Errorf("past 30 days: %v %v", ends, err)
	}
	for _, p := range []migrate.Phase{migrate.Rollback, migrate.RollbackChecked, migrate.RollbackTransfer} {
		if ends, err := windowEnding(write(p, now.Add(-time.Hour)), "0.50.1", true, now); err == nil || ends || !strings.Contains(err.Error(), "a rollback is under way (the migration is in phase "+string(p)+")") {
			t.Errorf("%s: %v %v", p, ends, err)
		}
	}
}

// checkoutSchema is this checkout's schema version, as go/release/release.json
// declares it (server/db/releasecheck holds it to server/db's).
func checkoutSchema(t *testing.T) int64 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "release", "release.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		SchemaVersion int64 `json:"schemaVersion"`
	}
	if err := json.Unmarshal(b, &d); err != nil || d.SchemaVersion < 1 {
		t.Fatalf("go/release/release.json: schemaVersion %d, %v", d.SchemaVersion, err)
	}
	return d.SchemaVersion
}
