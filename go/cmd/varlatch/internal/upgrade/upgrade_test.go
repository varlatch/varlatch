// SPDX-License-Identifier: Apache-2.0

//go:build linux

package upgrade

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate/fakerelease"
	"github.com/varlatch/varlatch/go/lib/release"
	journal "github.com/varlatch/varlatch/go/lib/upgradejournal"
)

// Two prereleases of the Go line, built from this checkout: 0.50.0-rc.1,
// and 0.50.0-rc.2 with G6's fixture schema step (schema 2, compatible from
// 1: rollback-safe). "wrong" is rc.2's build saying rc.3 (a release whose
// varlatchd is not the one its manifest names: its health checks fail);
// "unsafe" the same step declared not rollback-safe.
const (
	fromVersion = "0.50.0-rc.1"
	toVersion   = "0.50.0-rc.2"
)

var (
	buildsOnce sync.Once
	builds     map[string][]byte
	buildsErr  error
)

func build(t *testing.T, name string) []byte {
	t.Helper()
	if testing.Short() {
		t.Skip("builds varlatchd")
	}
	buildsOnce.Do(func() {
		builds = map[string][]byte{}
		dir, err := os.MkdirTemp("", "varlatch-upgrade-builds-")
		if err != nil {
			buildsErr = err
			return
		}
		defer os.RemoveAll(dir)
		for _, b := range []struct{ name, version, tags string }{
			{"from", fromVersion, ""}, {"to", toVersion, "g6fixture"}, {"wrong", "0.50.0-rc.3", "g6fixture"}, {"unsafe", toVersion, "g6fixture,g6unsafe"},
		} {
			out := filepath.Join(dir, b.name)
			cmd := exec.Command("go", "build", "-tags", b.tags, "-trimpath",
				"-ldflags", "-X github.com/varlatch/varlatch/go/lib/buildinfo.Version="+b.version, "-o", out, "github.com/varlatch/varlatch/go/cmd/varlatchd")
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if o, err := cmd.CombinedOutput(); err != nil {
				buildsErr = fmt.Errorf("go build varlatchd %s: %v\n%s", b.name, err, o)
				return
			}
			if builds[b.name], buildsErr = os.ReadFile(out); buildsErr != nil {
				return
			}
		}
	})
	if buildsErr != nil {
		t.Fatal(buildsErr)
	}
	return builds[name]
}

// host is a Go installation in a temporary directory: bin/ (varlatch and
// varlatchd), etc/ (varlatchd.conf, the journal), the keys, the data
// directory, and varlatchd run as a process by the fake service.
type host struct {
	t                      *testing.T
	dir, bin, conf, data   string
	svc                    *fakeService
	installedCLI, cliBytes []byte
}

func key(t *testing.T, path string) {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(k)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newHost(t *testing.T) *host {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("a Go installation's host is Linux")
	}
	dir := t.TempDir()
	h := &host{t: t, dir: dir, bin: filepath.Join(dir, "usr", "local", "bin"), conf: filepath.Join(dir, "etc", "varlatch", "varlatchd.conf"), data: filepath.Join(dir, "data")}
	for _, d := range []string{h.bin, filepath.Dir(h.conf), h.data, filepath.Join(dir, "keys")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key(t, filepath.Join(dir, "keys", "root-kek"))
	key(t, filepath.Join(dir, "keys", "backup-key"))
	conf := fmt.Sprintf("listen = 127.0.0.1:0\ndata_dir = %s\nroot_kek_file = %s\nbackup_key_file = %s\nbackup_interval = off\n",
		h.data, filepath.Join(dir, "keys", "root-kek"), filepath.Join(dir, "keys", "backup-key"))
	if err := os.WriteFile(h.conf, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	h.installedCLI = []byte("#!/bin/sh\necho varlatch " + fromVersion + "\n")
	if err := os.WriteFile(filepath.Join(h.bin, "varlatchd"), build(t, "from"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.bin, "varlatch"), h.installedCLI, 0o755); err != nil {
		t.Fatal(err)
	}
	h.svc = &fakeService{bin: h.bin, conf: h.conf}
	t.Cleanup(func() { _ = h.svc.Stop(context.Background()) })
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.upgrader(nil).mustServe(t, fromVersion, 1)
	return h
}

// fakeService runs bin/varlatchd serve as systemd would, the binary in
// place when it starts.
type fakeService struct {
	bin, conf string
	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
}

func (f *fakeService) Start(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cmd != nil {
		return errors.New("already running")
	}
	cmd := exec.Command(filepath.Join(f.bin, "varlatchd"), "serve", "--config", f.conf)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	f.cmd, f.done = cmd, done
	return nil
}

func (f *fakeService) Stop(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cmd == nil {
		return nil
	}
	_ = f.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-f.done:
	case <-time.After(30 * time.Second):
		_ = f.cmd.Process.Kill()
		<-f.done
	}
	f.cmd = nil
	return nil
}

func (h *host) upgrader(crash func(string) bool) *Upgrader {
	return &Upgrader{BinDir: h.bin, ConfigPath: h.conf, Service: h.svc, HealthTimeout: 30 * time.Second, Crash: crash}
}

// mustServe: the running varlatchd answers as version, on schema.
func (u *Upgrader) mustServe(t *testing.T, version string, schema int64) {
	t.Helper()
	if err := u.check(context.Background(), version, schema); err != nil {
		t.Fatalf("varlatchd %s on schema %d does not serve: %v", version, schema, err)
	}
}

// databaseSchema is the data directory's database's schema version, read
// with the installed varlatchd.
func (h *host) databaseSchema() int64 {
	h.t.Helper()
	out, err := h.upgrader(nil).admin(context.Background(), filepath.Join(h.bin, "varlatchd"), "admin", "schema", "status", "--json")
	if err != nil {
		h.t.Fatal(err)
	}
	var st struct {
		Database struct {
			SchemaVersion int64 `json:"schemaVersion"`
		} `json:"database"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		h.t.Fatal(err)
	}
	return st.Database.SchemaVersion
}

func (h *host) release(t *testing.T, varlatchd string, d release.Declaration) Release {
	t.Helper()
	m, err := release.NewManifest(toVersion, d)
	if err != nil {
		t.Fatal(err)
	}
	return Release{Version: toVersion, Varlatch: []byte("#!/bin/sh\necho varlatch " + toVersion + "\n"), Varlatchd: build(t, varlatchd), Manifest: m}
}

var safe = release.Declaration{SchemaVersion: 2, CompatibleFrom: 1, RollbackSafe: true, Previous: &release.Previous{Version: fromVersion, SchemaVersion: 1}}

func (h *host) inspect(t *testing.T) Installed {
	t.Helper()
	inst, err := h.upgrader(nil).Inspect(context.Background())
	if err != nil || inst.Version != fromVersion || inst.Schema != 1 || inst.DataDir != h.data {
		t.Fatalf("inspect: %+v, %v", inst, err)
	}
	return inst
}

// The upgrade between two prereleases: the new release serves on the
// upgraded schema; the journal says done; the snapshot is kept and
// restores; the previous binaries are kept.
func TestUpgradeBetweenTwoPrereleases(t *testing.T) {
	h := newHost(t)
	inst := h.inspect(t)
	rel := h.release(t, "to", safe)
	if !RollbackSafe(rel.Manifest, inst) {
		t.Fatal("a manifest compatible from schema 1 is rollback-safe for schema 1")
	}
	var log bytes.Buffer
	u := h.upgrader(nil)
	u.Log = func(line string) { log.WriteString(line + "\n") }
	j, err := u.Run(context.Background(), inst, rel)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if j.State != journal.Done || j.Step != journal.Checked || !j.RollbackSafe || j.From != fromVersion || j.To != toVersion || j.ToSchema != 2 {
		t.Fatalf("journal: %+v", j)
	}
	u.mustServe(t, toVersion, 2)
	if got := h.databaseSchema(); got != 2 {
		t.Fatalf("the database's schema: %d", got)
	}
	if b, _ := os.ReadFile(filepath.Join(h.bin, "varlatch")); !bytes.Contains(b, []byte(toVersion)) {
		t.Fatalf("varlatch was not replaced: %s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(u.Releases(), fromVersion, "varlatch")); !bytes.Equal(b, h.installedCLI) {
		t.Fatal("the previous varlatch is not kept")
	}
	on, err := journal.Read(filepath.Dir(h.conf))
	if err != nil || on.ID != j.ID || on.Pending() {
		t.Fatalf("the journal on disk: %+v, %v", on, err)
	}
	for _, gone := range []string{"db", "original"} {
		if _, err := os.Stat(filepath.Join(j.Work, gone)); !os.IsNotExist(err) {
			t.Fatalf("%s was left: %v", gone, err)
		}
	}
	for _, want := range []string{"Verified " + toVersion, "pre-upgrade snapshot", "Stopped varlatchd " + fromVersion, "schema version 2", "serves, after its health checks"} {
		if !strings.Contains(log.String(), want) {
			t.Fatalf("the log lacks %q:\n%s", want, log.String())
		}
	}
	snapshotRestores(t, h, j.Snapshot)

	// Run again: nothing pending, and an upgrade to the same release is the
	// caller's to refuse; the journal blocks nothing.
	if _, err := h.upgrader(nil).Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// snapshotRestores restores the pre-upgrade snapshot with the previous
// release into a fresh data directory with the installation's keys, and
// checks the Root KEK opens it.
func snapshotRestores(t *testing.T, h *host, snapshot string) {
	t.Helper()
	if snapshot == "" {
		t.Fatal("no snapshot")
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "varlatchd.conf")
	if err := os.WriteFile(conf, []byte(fmt.Sprintf("listen = 127.0.0.1:0\ndata_dir = %s\nroot_kek_file = %s\nbackup_key_file = %s\nbackup_interval = off\n",
		data, filepath.Join(h.dir, "keys", "root-kek"), filepath.Join(h.dir, "keys", "backup-key"))), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := filepath.Join(dir, "varlatchd")
	if err := os.WriteFile(prev, build(t, "from"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"admin", "backup", "restore", "--in", snapshot}, {"admin", "kek", "verify"}} {
		if out, err := exec.Command(prev, append(args, "--config", conf)...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
}

// previousServes: the upgrade was undone, and the previous release serves
// on its database as it was.
func previousServes(t *testing.T, h *host, j *journal.Journal) {
	t.Helper()
	if j.State != journal.Undone {
		t.Fatalf("not undone: %+v", j)
	}
	h.upgrader(nil).mustServe(t, fromVersion, 1)
	if got := h.databaseSchema(); got != 1 {
		t.Fatalf("the database's schema after the undo: %d", got)
	}
	if b, _ := os.ReadFile(filepath.Join(h.bin, "varlatch")); !bytes.Equal(b, h.installedCLI) {
		t.Fatal("the previous varlatch is not back")
	}
	if on, err := journal.Read(filepath.Dir(h.conf)); err != nil || on.Pending() || on.State != journal.Undone {
		t.Fatalf("the journal on disk: %+v, %v", on, err)
	}
}

// Killed at each point, the next run finishes the upgrade (after its
// checks) or undoes it (before them), and the host ends in that state.
func TestAKilledUpgradeIsFinishedOrUndone(t *testing.T) {
	points := []string{"verified", "snapshot", "stopped", "prepared", "swap:original-aside", "swap:database-in",
		"install:" + toVersion + ":varlatchd", "install:" + toVersion + ":varlatch", "swapped", "started", "checked"}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			h := newHost(t)
			inst := h.inspect(t)
			j, err := h.upgrader(func(p string) bool { return p == point }).Run(context.Background(), inst, h.release(t, "to", safe))
			if !errors.Is(err, errKilled) || !j.Pending() {
				t.Fatalf("killed at %s: %+v, %v", point, j, err)
			}
			// A new run first finishes or undoes it.
			if _, err := h.upgrader(nil).Run(context.Background(), inst, h.release(t, "to", safe)); err == nil || !strings.Contains(err.Error(), "is not over") {
				t.Fatalf("a run over a pending upgrade: %v", err)
			}
			j, err = h.upgrader(nil).Recover(context.Background())
			if err != nil {
				t.Fatalf("recover: %v", err)
			}
			if point == "checked" {
				if j.State != journal.Done {
					t.Fatalf("after its checks, finished: %+v", j)
				}
				h.upgrader(nil).mustServe(t, toVersion, 2)
				return
			}
			previousServes(t, h, j)
			if !strings.Contains(j.Reason, "interrupted after step") && !strings.Contains(j.Reason, "interrupted before") {
				t.Fatalf("reason: %q", j.Reason)
			}
		})
	}
}

// An undo that is itself killed is undone again by the next run.
func TestAKilledUndoIsUndoneAgain(t *testing.T) {
	for _, point := range []string{"undo:stopped", "undo:restored", "install:" + fromVersion + ":varlatchd"} {
		t.Run(point, func(t *testing.T) {
			h := newHost(t)
			inst := h.inspect(t)
			u := h.upgrader(func(p string) bool { return p == point })
			u.HealthTimeout = 3 * time.Second
			// A release whose checks fail, so the run undoes.
			j, err := u.Run(context.Background(), inst, h.release(t, "wrong", safe))
			if !errors.Is(err, errKilled) || !j.Pending() {
				t.Fatalf("killed at %s during the undo: %+v, %v", point, j, err)
			}
			j, err = h.upgrader(nil).Recover(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			previousServes(t, h, j)
		})
	}
}

// A full disk: while staging (nothing changed, varlatchd never stopped)
// and while copying the database (after the stop: undone).
func TestAFullDiskIsUndone(t *testing.T) {
	for _, c := range []struct{ name, suffix string }{
		{"staging", filepath.Join(toVersion, "varlatchd")},
		{"the database copy", filepath.Join("db", "varlatch.db")},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHost(t)
			inst := h.inspect(t)
			u := h.upgrader(nil)
			u.Fault = func(path string) error {
				if strings.HasSuffix(path, c.suffix) {
					return &os.PathError{Op: "write", Path: path, Err: syscall.ENOSPC}
				}
				return nil
			}
			j, err := u.Run(context.Background(), inst, h.release(t, "to", safe))
			var uerr *Error
			if !errors.As(err, &uerr) || !strings.Contains(err.Error(), "no space left on device") || !strings.Contains(err.Error(), "it was undone") {
				t.Fatalf("%v", err)
			}
			previousServes(t, h, j)
		})
	}
}

// A release whose varlatchd fails its health checks (it is not the release
// its manifest names) is undone: the previous release serves again on the
// database as it was, though the copy had the new schema.
func TestAFailedHealthCheckIsUndone(t *testing.T) {
	h := newHost(t)
	inst := h.inspect(t)
	u := h.upgrader(nil)
	u.HealthTimeout = 3 * time.Second
	j, err := u.Run(context.Background(), inst, h.release(t, "wrong", safe))
	if err == nil || !strings.Contains(err.Error(), "it runs 0.50.0-rc.3, not "+toVersion) {
		t.Fatalf("%v", err)
	}
	previousServes(t, h, j)
	if j.Snapshot == "" {
		t.Fatal("the snapshot was not recorded")
	}
	snapshotRestores(t, h, j.Snapshot)
}

// A release not rollback-safe for this host: RollbackSafe says so (the
// command refuses it unless accepted); run anyway, it upgrades, and the
// journal records it.
func TestNotRollbackSafe(t *testing.T) {
	h := newHost(t)
	inst := h.inspect(t)
	unsafe := release.Declaration{SchemaVersion: 2, CompatibleFrom: 2, RollbackSafe: false, Previous: &release.Previous{Version: fromVersion, SchemaVersion: 1}}
	rel := h.release(t, "unsafe", unsafe)
	if RollbackSafe(rel.Manifest, inst) {
		t.Fatal("compatible from 2 is not rollback-safe for schema 1")
	}
	j, err := h.upgrader(nil).Run(context.Background(), inst, rel)
	if err != nil || j.State != journal.Done || j.RollbackSafe {
		t.Fatalf("%+v, %v", j, err)
	}
	h.upgrader(nil).mustServe(t, toVersion, 2)
}

// Fetch takes a release's server assets from its signed SHA256SUMS, fail
// closed: a bad signature and a wrong identity fetch nothing.
func TestFetch(t *testing.T) {
	if testing.Short() {
		t.Skip("builds varlatchd")
	}
	srv := fakerelease.New()
	defer srv.Close()
	m, err := release.NewManifest(toVersion, safe)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := m.Bytes()
	cli, server, name := Assets(toVersion, "amd64")
	files := map[string][]byte{cli: []byte("cli"), server: []byte("server"), name: manifest}
	srv.Publish(toVersion, &fakerelease.Release{Files: files})
	rel, err := Fetch(context.Background(), srv.Source(), toVersion, "amd64")
	if err != nil || string(rel.Varlatchd) != "server" || string(rel.Varlatch) != "cli" || rel.Manifest.SchemaVersion != 2 {
		t.Fatalf("%+v, %v", rel, err)
	}
	for _, c := range []struct {
		name string
		r    *fakerelease.Release
		want string
	}{
		{"a bad signature", &fakerelease.Release{Files: files, SumsAfterSigning: func(b []byte) []byte { return append(b, ' ') }}, "does NOT verify"},
		{"a wrong identity", &fakerelease.Release{Files: files, Identity: release.Identity("0.50.0-rc.9")}, "does NOT verify"},
		{"no signature", &fakerelease.Release{Files: files, NoSignature: true}, "has no signature"},
		{"a changed download", &fakerelease.Release{Files: files, Served: map[string][]byte{server: []byte("other")}}, "does not match SHA256SUMS"},
		{"another release's manifest", &fakerelease.Release{Files: map[string][]byte{cli: []byte("cli"), server: []byte("server"), name: mustManifest(t, "0.50.0-rc.1")}}, "is for 0.50.0-rc.1"},
	} {
		srv.Publish(toVersion, c.r)
		if _, err := Fetch(context.Background(), srv.Source(), toVersion, "amd64"); err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "nothing was changed") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func mustManifest(t *testing.T, version string) []byte {
	t.Helper()
	m, err := release.NewManifest(version, release.Declaration{SchemaVersion: 1, CompatibleFrom: 1})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := m.Bytes()
	return b
}
