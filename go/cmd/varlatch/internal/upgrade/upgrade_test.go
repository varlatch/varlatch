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
	"io/fs"
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

// Two prereleases of the Go line, built from this checkout: 0.50.0-rc.4, on
// this checkout's schema (fromSchema), and 0.50.0-rc.5 with G6's fixture
// schema step (toSchema, compatible from 1: rollback-safe). "wrong" is rc.5's build saying rc.6 (a release whose
// varlatchd is not the one its manifest names: its health checks fail);
// "unsafe" the same step declared not rollback-safe.
const (
	fromVersion = "0.50.0-rc.4"
	toVersion   = "0.50.0-rc.5"
)

// fromSchema is this checkout's schema version, as go/release/release.json
// declares it (server/db/releasecheck holds it to server/db's); toSchema
// is G6's fixture step's, one more.
var (
	fromSchema = checkoutSchema()
	toSchema   = fromSchema + 1
)

func checkoutSchema() int64 {
	if len(os.Args) > 1 && os.Args[1] == ChildCommand {
		return 0 // this binary as the data directory's owner, elsewhere
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "release", "release.json"))
	if err != nil {
		panic(err)
	}
	var d struct {
		SchemaVersion int64 `json:"schemaVersion"`
	}
	if err := json.Unmarshal(b, &d); err != nil || d.SchemaVersion < 1 {
		panic(fmt.Sprintf("go/release/release.json: schemaVersion %d, %v", d.SchemaVersion, err))
	}
	return d.SchemaVersion
}

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
			{"from", fromVersion, ""}, {"to", toVersion, "g6fixture"}, {"wrong", "0.50.0-rc.6", "g6fixture"}, {"unsafe", toVersion, "g6fixture,g6unsafe"},
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

func newHost(t *testing.T) *host { t.Helper(); return newHostOf(t, -1) }

// newHostOf is newHost with varlatchd and its data directory uid's, as the
// unit runs it as the varlatch user, its keys root's, which the unit hands
// it (here: copies of its own); -1 is the test's own user.
func newHostOf(t *testing.T, uid int) *host {
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
	h.svc = &fakeService{bin: h.bin, conf: h.conf, uid: uid}
	if uid >= 0 {
		// The service reads its keys from its own copies, as the unit's
		// credentials are.
		own := filepath.Join(dir, "own")
		if err := os.Mkdir(own, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"root-kek", "backup-key"} {
			b, err := os.ReadFile(filepath.Join(dir, "keys", k))
			if err != nil || os.WriteFile(filepath.Join(own, k), b, 0o400) != nil || os.Chown(filepath.Join(own, k), uid, uid) != nil {
				t.Fatal(err)
			}
		}
		h.svc.conf = filepath.Join(filepath.Dir(h.conf), "service.conf")
		if err := os.WriteFile(h.svc.conf, []byte(strings.ReplaceAll(conf, filepath.Join(dir, "keys"), own)), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{h.data, own} {
			if err := os.Chown(p, uid, uid); err != nil {
				t.Fatal(err)
			}
		}
		for p := h.bin; p != dir; p = filepath.Dir(p) {
			if err := os.Chmod(p, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		// dir's parent is the test's own temporary directory, private.
		for _, p := range []string{filepath.Dir(h.conf), filepath.Dir(filepath.Dir(h.conf)), dir, filepath.Dir(dir)} {
			if err := os.Chmod(p, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() { _ = h.svc.Stop(context.Background()) })
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.upgrader(nil).mustServe(t, fromVersion, fromSchema)
	return h
}

// fakeService runs bin/varlatchd serve as systemd would, the binary in
// place when it starts.
type fakeService struct {
	bin, conf string
	uid       int
	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
}

func (f *fakeService) Start(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cmd != nil {
		return nil // as systemctl start: nothing to do for a running unit
	}
	cmd := exec.Command(filepath.Join(f.bin, "varlatchd"), "serve", "--config", f.conf)
	if f.uid >= 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(f.uid), Gid: uint32(f.uid), Groups: []uint32{}}}
	}
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

// Config: the host's, the service's own being its copy with other keys.
func (f *fakeService) Config(context.Context) (string, error) {
	return filepath.Join(filepath.Dir(f.conf), "varlatchd.conf"), nil
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
	if err := u.check(context.Background(), version, schema, ""); err != nil {
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

// reversible is every test release's declaration that a reverse migration
// returns its data to the last TypeScript release, which lib/release
// requires of a release (reversibleTo, go-step7 decision 17).
var reversible = release.LastTypeScriptRelease

var safe = release.Declaration{SchemaVersion: toSchema, CompatibleFrom: 1, RollbackSafe: true, Previous: &release.Previous{Version: fromVersion, SchemaVersion: fromSchema}, ReversibleTo: &reversible}

func (h *host) inspect(t *testing.T) Installed {
	t.Helper()
	inst, err := h.upgrader(nil).Inspect(context.Background())
	if err != nil || inst.Version != fromVersion || inst.Schema != fromSchema || inst.DataDir != h.data {
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
		t.Fatalf("a manifest compatible from schema 1 is rollback-safe for schema %d", fromSchema)
	}
	var log bytes.Buffer
	u := h.upgrader(nil)
	u.Log = func(line string) { log.WriteString(line + "\n") }
	j, err := u.Run(context.Background(), inst, rel)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if j.State != journal.Done || j.Step != journal.Checked || !j.RollbackSafe || j.From != fromVersion || j.To != toVersion || j.ToSchema != toSchema {
		t.Fatalf("journal: %+v", j)
	}
	u.mustServe(t, toVersion, toSchema)
	if got := h.databaseSchema(); got != toSchema {
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
	for _, want := range []string{"Verified " + toVersion, "pre-upgrade snapshot", "Stopped varlatchd " + fromVersion, fmt.Sprintf("schema version %d", toSchema), "serves, after its health checks"} {
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
	h.upgrader(nil).mustServe(t, fromVersion, fromSchema)
	if got := h.databaseSchema(); got != fromSchema {
		t.Fatalf("the database's schema after the undo: %d", got)
	}
	if b, _ := os.ReadFile(filepath.Join(h.bin, "varlatch")); !bytes.Equal(b, h.installedCLI) {
		t.Fatal("the previous varlatch is not back")
	}
	if on, err := journal.Read(filepath.Dir(h.conf)); err != nil || on.Pending() || on.State != journal.Undone {
		t.Fatalf("the journal on disk: %+v, %v", on, err)
	}
}

// Killed, with the real varlatchd and database, the next run finishes the
// upgrade (after its checks) or undoes it (before them), and the host ends
// in that state. Every point is crash_test.go's; here are the ones the real
// thing differs at.
func TestAKilledUpgradeIsFinishedOrUndone(t *testing.T) {
	points := []string{"snapshot", "stop:done", "data:copy-database:create:varlatch.db", "data:keep-original:rename:original",
		"install:" + toVersion + ":varlatchd", "data:swap:rename:varlatch.db", "start:" + toVersion, "started", "checked", "done"}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			h := newHost(t)
			inst := h.inspect(t)
			j, err := h.upgrader(func(p string) bool { return p == point }).Run(context.Background(), inst, h.release(t, "to", safe))
			if !errors.Is(err, errKilled) || j.Pending() != (point != "done") {
				t.Fatalf("killed at %s: %+v, %v", point, j, err)
			}
			// A new run first finishes or undoes it.
			if point == "done" {
				if j, err := h.upgrader(nil).Recover(context.Background()); j != nil || err != nil {
					t.Fatalf("recover: %+v, %v", j, err)
				}
				h.upgrader(nil).mustServe(t, toVersion, toSchema)
				if left, _ := filepath.Glob(filepath.Join(h.data, "upgrades", "*", "original")); len(left) > 0 {
					t.Fatalf("%s is left", left)
				}
				return
			}
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
				h.upgrader(nil).mustServe(t, toVersion, toSchema)
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
	for _, point := range []string{"data:put-back:rename:varlatch.db", "undo:files-back", "start:" + fromVersion} {
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

// With the real varlatchd: the database in place is known as the original's
// upgraded copy, and another installation's, or one with less in it, is not.
func TestTheUpgradedCopyIsKnown(t *testing.T) {
	h := newHost(t)
	inst := h.inspect(t)
	j, err := h.upgrader(func(p string) bool { return p == "swapped" }).Run(context.Background(), inst, h.release(t, "to", safe))
	if !errors.Is(err, errKilled) {
		t.Fatal(err)
	}
	u := h.upgrader(nil)
	if err := u.upgradedCopy(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	// The original has more: the copy is of before.
	original := filepath.Join(j.Work, originalDir, databaseFile)
	live := filepath.Join(h.data, databaseFile)
	swap := func(a, b string) {
		t.Helper()
		for _, m := range [][2]string{{a, a + ".aside"}, {b, a}, {a + ".aside", b}} {
			if err := os.Rename(m[0], m[1]); err != nil {
				t.Fatal(err)
			}
		}
	}
	swap(original, live)
	if err := u.upgradedCopy(context.Background(), j); err != nil {
		t.Fatalf("the same history: %v", err)
	}
	swap(original, live)
	if _, err := u.admin(context.Background(), filepath.Join(h.bin, "varlatchd"), "admin", "bootstrap", "--cli-credential"); err == nil {
		t.Fatal("an offline command that writes ran while the upgrade holds")
	}
	// Another installation's, made where there was none.
	other := newHost(t)
	if err := other.svc.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(other.data, databaseFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := u.upgradedCopy(context.Background(), j); err == nil || !strings.Contains(err.Error(), "is not the original's upgraded copy") {
		t.Fatalf("another installation's: %v", err)
	}
	// To a release that cannot say.
	old := *j
	old.To = "0.50.0-rc.3"
	if err := u.upgradedCopy(context.Background(), &old); err == nil || !strings.Contains(err.Error(), "cannot say") {
		t.Fatalf("%v", err)
	}
}

// A full disk: while staging (nothing changed, varlatchd never stopped)
// and while copying the database (after the stop: undone).
func TestAFullDiskIsUndone(t *testing.T) {
	for _, c := range []struct{ name, suffix, want string }{
		{"staging", filepath.Join(toVersion, "."+"varlatchd.new"), "nothing was changed"},
		{"the database copy", filepath.Join("db"+makingDir, "varlatch.db"), "it was undone"},
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
			if !errors.As(err, &uerr) || !strings.Contains(err.Error(), "no space left on device") || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%v", err)
			}
			if c.name != "staging" {
				previousServes(t, h, j)
				return
			}
			// Nothing is recorded before the release is staged, and no part
			// of it stays.
			if on, err := journal.Read(filepath.Dir(h.conf)); j != nil || on != nil || err != nil {
				t.Fatalf("%+v, %+v, %v", j, on, err)
			}
			if _, err := os.Stat(filepath.Join(u.Releases(), toVersion)); !os.IsNotExist(err) {
				t.Fatalf("%v", err)
			}
			u.mustServe(t, fromVersion, fromSchema)
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
	// (Another release than the one the journal lets start: it does not.)
	if err == nil || !strings.Contains(err.Error(), "the health checks of "+toVersion) || !strings.Contains(err.Error(), "it was undone") {
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
	unsafe := release.Declaration{SchemaVersion: toSchema, CompatibleFrom: toSchema, RollbackSafe: false, Previous: &release.Previous{Version: fromVersion, SchemaVersion: fromSchema}, ReversibleTo: &reversible}
	rel := h.release(t, "unsafe", unsafe)
	if RollbackSafe(rel.Manifest, inst) {
		t.Fatalf("compatible from %d is not rollback-safe for schema %d", toSchema, fromSchema)
	}
	j, err := h.upgrader(nil).Run(context.Background(), inst, rel)
	if err != nil || j.State != journal.Done || j.RollbackSafe {
		t.Fatalf("%+v, %v", j, err)
	}
	h.upgrader(nil).mustServe(t, toVersion, toSchema)
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
	if err != nil || string(rel.Varlatchd) != "server" || string(rel.Varlatch) != "cli" || rel.Manifest.SchemaVersion != toSchema {
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
		{"another release's manifest", &fakerelease.Release{Files: map[string][]byte{cli: []byte("cli"), server: []byte("server"), name: mustManifest(t, "0.50.0-rc.4")}}, "is for 0.50.0-rc.4"},
	} {
		srv.Publish(toVersion, c.r)
		if _, err := Fetch(context.Background(), srv.Source(), toVersion, "amd64"); err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "nothing was changed") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func mustManifest(t *testing.T, version string) []byte {
	t.Helper()
	m, err := release.NewManifest(version, release.Declaration{SchemaVersion: 1, CompatibleFrom: 1, ReversibleTo: &reversible})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := m.Bytes()
	return b
}

// The journal cannot be written at the stopped step (a full disk under
// /etc): varlatchd is down, the journal still says stopping; the undo
// starts the previous release and checks it.
func TestAJournalThatCannotRecordTheStopIsUndone(t *testing.T) {
	h := newHost(t)
	inst := h.inspect(t)
	armed, fired := false, false
	u := h.upgrader(func(p string) bool {
		if p == "stop:done" {
			armed = true
		}
		return false
	})
	u.Fault = func(path string) error {
		if armed && !fired && filepath.Base(path) == journal.File {
			fired = true
			return &os.PathError{Op: "write", Path: path, Err: syscall.ENOSPC}
		}
		return nil
	}
	j, err := u.Run(context.Background(), inst, h.release(t, "to", safe))
	if !fired || err == nil || !strings.Contains(err.Error(), "it was undone") {
		t.Fatalf("fired %v: %v", fired, err)
	}
	previousServes(t, h, j)
	if !strings.Contains(j.Reason, "no space left on device") {
		t.Fatalf("reason: %q", j.Reason)
	}
}

// A disk too full for the upgrade is refused before anything is written:
// no journal, the staged release absent, varlatchd still serving.
func TestNotEnoughSpaceChangesNothing(t *testing.T) {
	h := newHost(t)
	inst := h.inspect(t)
	defer func(f func(string) (uint64, uint64, error)) { FreeSpace = f }(FreeSpace)
	FreeSpace = func(path string) (uint64, uint64, error) { return 1 << 20, 7, nil }
	// An earlier upgrade's, whose time is over: nothing was changed is nothing.
	old := filepath.Join(h.data, "upgrades", "0011223344556677")
	if err := os.MkdirAll(old, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(old, time.Now().Add(-60*24*time.Hour), time.Now().Add(-60*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, err := h.upgrader(nil).Run(context.Background(), inst, h.release(t, "to", safe))
	if err == nil || !strings.Contains(err.Error(), "not enough space on the filesystem of") || !strings.Contains(err.Error(), "nothing was changed") ||
		!strings.Contains(err.Error(), "a copy of the database and a snapshot, the new binaries, the kept ones and the kept snapshot, and 64 MiB to spare") {
		t.Fatalf("%v", err)
	}
	if j, err := journal.Read(filepath.Dir(h.conf)); j != nil || err != nil {
		t.Fatalf("a journal was written: %+v, %v", j, err)
	}
	if _, err := os.Stat(filepath.Join(h.upgrader(nil).Releases(), toVersion)); !os.IsNotExist(err) {
		t.Fatalf("the release was staged: %v", err)
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("an earlier upgrade's directory was removed: %v", err)
	}
	h.upgrader(nil).mustServe(t, fromVersion, fromSchema)

	// Two paths on one filesystem are counted once, against its free space.
	FreeSpace = func(path string) (uint64, uint64, error) { return 1 << 40, 7, nil }
	u, rel := h.upgrader(nil), h.release(t, "to", safe)
	if err := u.enoughSpace(context.Background(), inst, rel); err != nil {
		t.Fatal(err)
	}

	// Root's copy of the snapshot is on the binaries' filesystem, where that
	// is another: what holds the binaries alone does not do.
	size, err := u.data(context.Background(), dataOp{Op: "size", DataDir: inst.DataDir})
	if err != nil || size.Bytes == 0 {
		t.Fatalf("%+v, %v", size, err)
	}
	binaries := 2 * int64(len(rel.Varlatch)+len(rel.Varlatchd))
	for _, name := range []string{"varlatch", "varlatchd"} {
		info, err := os.Stat(filepath.Join(h.bin, name))
		if err != nil {
			t.Fatal(err)
		}
		binaries += info.Size()
	}
	for free, want := range map[int64]bool{binaries + spaceMargin: false, binaries + size.Bytes + spaceMargin: true} {
		FreeSpace = func(path string) (uint64, uint64, error) {
			if path == h.bin {
				return uint64(free), 8, nil
			}
			return 1 << 40, 7, nil
		}
		err := u.enoughSpace(context.Background(), inst, rel)
		if (err == nil) != want || err != nil && !strings.Contains(err.Error(), "not enough space on the filesystem of "+h.bin) {
			t.Fatalf("%d bytes free: %v", free, err)
		}
	}
}

// <data>/upgrades as a link: root never writes through it.
func TestALinkedUpgradesDirectoryIsRefused(t *testing.T) {
	h := newHost(t)
	inst := h.inspect(t)
	elsewhere := t.TempDir()
	// A directory older than an upgrade's 30 days, which prune would remove
	// if it followed the link.
	stale := filepath.Join(elsewhere, "stale")
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-60 * 24 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(h.data, "upgrades")); err != nil {
		t.Fatal(err)
	}
	_, err := h.upgrader(nil).Run(context.Background(), inst, h.release(t, "to", safe))
	if err == nil || !strings.Contains(err.Error(), "is not a directory (a link or another file)") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("%v", err)
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 1 || entries[0].Name() != "stale" {
		t.Fatalf("written or removed through the link: %v", entries)
	}
	h.upgrader(nil).mustServe(t, fromVersion, fromSchema)
}

// As root with varlatchd another user's, as the unit runs it: the data
// directory's work is that user's (a child of this program, killed at each
// of its points too), and nothing there is root's after.
func TestUpgradeAsRootWorksAsTheOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("runs varlatchd as another user, as root (go.yml)")
	}
	const uid = 65534
	owned := func(h *host, what string) {
		t.Helper()
		_ = filepath.WalkDir(h.data, func(p string, _ fs.DirEntry, err error) error {
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(p)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Sys().(*syscall.Stat_t).Uid; got != uid {
				t.Errorf("%s: %s is uid %d's", what, p, got)
			}
			return nil
		})
	}
	h := newHostOf(t, uid)
	inst := h.inspect(t)
	if j, err := h.upgrader(nil).Run(context.Background(), inst, h.release(t, "to", safe)); err != nil || j.State != journal.Done {
		t.Fatalf("%+v, %v", j, err)
	}
	h.upgrader(nil).mustServe(t, toVersion, toSchema)
	owned(h, "an upgrade")

	for _, point := range []string{"data:copy-database:create:varlatch.db", "data:keep-original:rename:original", "data:swap:rename:varlatch.db"} {
		h := newHostOf(t, uid)
		inst := h.inspect(t)
		u := h.upgrader(func(string) bool { return false })
		u.ChildCrash = point
		if j, err := u.Run(context.Background(), inst, h.release(t, "to", safe)); !errors.Is(err, errKilled) || !j.Pending() {
			t.Fatalf("%s: %+v, %v", point, j, err)
		}
		j, err := h.upgrader(nil).Recover(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", point, err)
		}
		previousServes(t, h, j)
		owned(h, point)
	}

	// A link of that user's leads the upgrade nowhere.
	h = newHostOf(t, uid)
	inst = h.inspect(t)
	outside := filepath.Join(h.dir, "roots")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(h.data, "upgrades")); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(filepath.Join(h.data, "upgrades"), uid, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := h.upgrader(nil).Run(context.Background(), inst, h.release(t, "to", safe)); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("%v", err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("written through a link: %v", entries)
	}
}

// The installed release on a database of a newer schema it opens (a
// rollback-safe release wrote it, and the binaries went back): it upgrades
// again, not to a release below the database's schema, and takes its
// snapshot on the way.
func TestUpgradeFromANewerSchema(t *testing.T) {
	h := newHost(t)
	u := h.upgrader(nil)
	if err := h.svc.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	newer := filepath.Join(h.dir, "varlatchd-newer")
	if err := os.WriteFile(newer, build(t, "to"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := u.admin(context.Background(), newer, "admin", "schema", "upgrade"); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	u.mustServe(t, fromVersion, fromSchema)
	inst, err := u.Inspect(context.Background())
	if err != nil || inst.Version != fromVersion || inst.Schema != fromSchema || inst.Database != toSchema {
		t.Fatalf("inspect: %+v, %v", inst, err)
	}
	low := h.release(t, "to", safe)
	low.Manifest.SchemaVersion = fromSchema
	if _, err := u.Run(context.Background(), inst, low); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("the database's schema is version %d", toSchema)) || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("a release below the database's schema: %v", err)
	}
	u.mustServe(t, fromVersion, fromSchema)
	if j, err := u.Run(context.Background(), inst, h.release(t, "to", safe)); err != nil || j.State != journal.Done {
		t.Fatalf("the upgrade: %+v, %v", j, err)
	}
	u.mustServe(t, toVersion, toSchema)
}
