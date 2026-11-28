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
	journal "github.com/varlatch/varlatch/go/lib/upgradejournal"
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
		{[]string{"--rollback", "--check"}, "--rollback returns to the last upgrade's previous release"},
		{[]string{"--rollback", "0.50.0"}, "--rollback returns to the last upgrade's previous release"},
		{[]string{"--accept-data-loss"}, "--accept-data-loss goes with --rollback"},
		{[]string{"--enable-web", "--disable-web"}, "each go alone, with --config only"},
		{[]string{"--from-request", "0.52.0"}, "each go alone, with --config only"},
		{[]string{"--from-request", "--accept-not-rollback-safe"}, "each go alone, with --config only"},
		{[]string{"--recover", "--yes"}, "each go alone, with --config only"},
		{[]string{"--enable-web", "--check"}, "each go alone, with --config only"},
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
	for _, form := range webForms {
		if code, _, errs := runUpgrade(t, nil, form); code != ExitDenied || !strings.Contains(errs, "run it as sudo varlatch upgrade "+form) {
			t.Fatalf("%s, not root: %d %q", form, code, errs)
		}
	}
}

// The command end to end on a host in a temporary directory: --check
// records the newer release for the dashboard; upgrade --yes upgrades to
// it; a release that is not rollback-safe is refused until accepted. As
// root (the command's rule), the data directory the service user's.
// reversible is the test releases' declaration that a reverse migration
// returns their data to the last TypeScript release, which lib/release
// requires of a release (reversibleTo, go-step7 decision 17).
var reversible = release.LastTypeScriptRelease

func TestUpgradeCommandOnAHost(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("builds varlatchd and runs as root on Linux (go.yml's Go container)")
	}
	from, to, unsafe := cliBuild(t, "0.50.0-rc.4", ""), cliBuild(t, "0.50.0-rc.5", "g6fixture"), cliBuild(t, "0.50.0-rc.5", "g6fixture,g6unsafe")
	srv := fakerelease.New()
	defer srv.Close()
	defer func(f func(*Run) selfupdate.Source) { selfUpdateSource = f }(selfUpdateSource)
	selfUpdateSource = func(*Run) selfupdate.Source { return srv.Source() }
	publish := func(varlatchd []byte, d release.Declaration) {
		m, err := release.NewManifest("0.50.0-rc.5", d)
		if err != nil {
			t.Fatal(err)
		}
		manifest, _ := m.Bytes()
		cli, server, name := upgrade.Assets("0.50.0-rc.5", runtime.GOARCH)
		image := []byte("ghcr.io/varlatch/varlatchd:0.50.0-rc.5@sha256:" + strings.Repeat("0123456789abcdef", 4) + "\n")
		srv.Publish("0.50.0-rc.5", &fakerelease.Release{Files: map[string][]byte{cli: []byte("#!/bin/sh\necho varlatch 0.50.0-rc.5\n"), server: varlatchd, name: manifest, targetImageAsset: image}})
	}
	// The rc.4 build is on this checkout's schema; rc.5's G6 fixture step
	// adds one.
	fromSchema := checkoutSchema(t)
	toSchema := fromSchema + 1
	prev := &release.Previous{Version: "0.50.0-rc.4", SchemaVersion: fromSchema}

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
	// And before a pending upgrade is undone over the restored database.
	pending := &journal.Journal{Format: journal.Format, ID: "0123456789abcdef", State: journal.InProgress, Step: journal.Swapped, From: "0.50.0-rc.1", To: "0.50.0-rc.2",
		DataDir: h.data, Work: filepath.Join(h.data, "upgrades", "0123456789abcdef"), BinDir: h.bin, Releases: h.bin}
	if err := journal.Write(filepath.Dir(h.conf), pending); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(filepath.Dir(h.conf), journal.File))
	if code, out, errs := runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--config", h.conf); code != ExitFailure || out != "" || !strings.Contains(errs, "is still pending") ||
		!strings.Contains(errs, "First move "+filepath.Join(filepath.Dir(h.conf), journal.File)+" away") || strings.Index(errs, "restore resume") < strings.Index(errs, "First move") {
		t.Fatalf("held with an upgrade pending: %d %q %q", code, out, errs)
	}
	if after, _ := os.ReadFile(filepath.Join(filepath.Dir(h.conf), journal.File)); string(after) != string(before) {
		t.Error("the refused upgrade changed the journal")
	}
	if err := os.Remove(filepath.Join(filepath.Dir(h.conf), journal.File)); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.RemoveHold(h.data); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--config", h.conf)
	if code != ExitFailure || !strings.Contains(out, "rollback:  NOT safe") || !strings.Contains(out, notCounted) || !strings.Contains(errs, "pass --accept-not-rollback-safe") {
		t.Fatalf("not rollback-safe: %d %q %q", code, out, errs)
	}
	h.serves(t, "0.50.0-rc.4")
	code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--accept-not-rollback-safe", "--config", h.conf)
	if code != ExitOK || !strings.Contains(out, "Upgraded to 0.50.0-rc.5") {
		t.Fatalf("accepted: %d %q %q", code, out, errs)
	}
	h.serves(t, "0.50.0-rc.5")

	// Its rollback restores the snapshot: what is lost is listed first, and
	// nothing happens without --accept-data-loss (--yes is not enough).
	code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--rollback", "--yes", "--config", h.conf)
	if code != ExitFailure || !strings.Contains(out, "the pre-upgrade snapshot is restored") || !strings.Contains(out, "LOST:") || !strings.Contains(errs, "pass --accept-data-loss") ||
		!strings.Contains(out, "  UNDONE:    ") || !strings.Contains(out, "  NOT COUNTED: "+notCounted) ||
		strings.Index(out, "UNDONE:") > strings.Index(out, "LOST:") {
		t.Fatalf("a rollback that loses changes, not accepted: %d %q %q", code, out, errs)
	}
	h.serves(t, "0.50.0-rc.5")
	code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--rollback", "--accept-data-loss", "--config", h.conf)
	if code != ExitOK || !strings.Contains(out, "Rolled back to 0.50.0-rc.4") || !strings.Contains(out, "What to do now: the restore took the changes listed above back.") ||
		!strings.Contains(out, "varlatch credential revoke <identity-id> <credential-id>") || !strings.Contains(out, "0.50.0-rc.4 has no\n    command that signs everyone out") {
		t.Fatalf("accepted: %d %q %q", code, out, errs)
	}
	h.serves(t, "0.50.0-rc.4")

	// Rollback-safe: --check records it, upgrade --yes upgrades.
	h = newCLIHost(t, from)
	publish(to, release.Declaration{SchemaVersion: toSchema, CompatibleFrom: 1, RollbackSafe: true, Previous: prev, ReversibleTo: &reversible})
	code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--check", "--config", h.conf)
	if code != ExitOK || !strings.Contains(out, "varlatchd 0.50.0-rc.5 is available (this host runs 0.50.0-rc.4)") {
		t.Fatalf("--check: %d %q %q", code, out, errs)
	}
	rc, err := release.ReadReleaseCheck(h.data)
	if err != nil || rc == nil || rc.LastSuccess == nil || rc.LastSuccess.Latest.Version != "0.50.0-rc.5" || rc.LastAttempt.Failed != nil {
		t.Fatalf("the release check: %+v, %v", rc, err)
	}
	// And the verified target, by the varlatchd installed (ADR-0065
	// Decision 3).
	if tg, err := release.ReadReleaseTarget(h.data); err != nil || tg == nil || tg.Version != "0.50.0-rc.5" || tg.Verified == nil || !tg.Verified.Declaration().SafeFor("0.50.0-rc.4", fromSchema) {
		t.Fatalf("the release target: %+v, %v", tg, err)
	}
	if code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--config", h.conf); code != ExitFailure || !strings.Contains(errs, "not a terminal: pass --yes") {
		t.Fatalf("no --yes off a terminal: %d %q %q", code, out, errs)
	}
	code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--config", h.conf)
	if code != ExitOK || !strings.Contains(out, "rollback:  safe") || !strings.Contains(out, "Going back (varlatch upgrade --rollback) keeps every change") ||
		!strings.Contains(out, "Upgraded to 0.50.0-rc.5") || !strings.Contains(out, "varlatch upgrade --rollback goes back to 0.50.0-rc.4.") {
		t.Fatalf("upgrade: %d %q %q", code, out, errs)
	}
	h.serves(t, "0.50.0-rc.5")
	if code, out, _ = runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--config", h.conf); code != ExitOK || !strings.Contains(out, "varlatchd 0.50.0-rc.5 is up to date") {
		t.Fatalf("again: %d %q", code, out)
	}
	// A rollback-safe rollback keeps the database: --yes is enough.
	code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--rollback", "--yes", "--config", h.conf)
	if code != ExitOK || !strings.Contains(out, "database:  kept as it is") || strings.Contains(out, "LOST:") || !strings.Contains(out, "Rolled back to 0.50.0-rc.4") {
		t.Fatalf("a rollback-safe rollback: %d %q %q", code, out, errs)
	}
	h.serves(t, "0.50.0-rc.4")

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
	h.serves(t, "0.50.0-rc.4")
	if j := h.journal(t); j.WindowEnded != nil {
		t.Fatalf("the window recorded ended after a refusal: %+v", j.WindowEnded)
	}
	code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--end-rollback-window", "--config", h.conf)
	if code != ExitOK || !strings.Contains(out, "The migration's rollback window ends") || !strings.Contains(out, "Upgraded to 0.50.0-rc.5") {
		t.Fatalf("--end-rollback-window: %d %q %q", code, out, errs)
	}
	h.serves(t, "0.50.0-rc.5")
	if j := h.journal(t); j.WindowEnded == nil || j.WindowEnded.Release != "0.50.0-rc.5" || j.Phase != migrate.Open {
		t.Fatalf("the journal after the upgrade: %+v", j)
	}
	if open, err := migrate.RollbackWindowOpen(h.data, time.Now()); err != nil || open {
		t.Errorf("the window after the upgrade: %v %v", open, err)
	}
	// Rolled back, it stays ended, and the rollback says so.
	code, out, errs = runUpgrade(t, MapEnv{"PATH": h.bin}, "--rollback", "--yes", "--config", h.conf)
	if code != ExitOK || !strings.Contains(out, "  migration: its rollback window was ended by the upgrade to 0.50.0-rc.5, and stays ended") || !strings.Contains(out, "Rolled back to 0.50.0-rc.4") {
		t.Fatalf("a rollback beside a migration: %d %q %q", code, out, errs)
	}
	h.serves(t, "0.50.0-rc.4")
	if open, err := migrate.RollbackWindowOpen(h.data, time.Now()); err != nil || open {
		t.Errorf("the window after the rollback: %v %v", open, err)
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
		if code != ExitOK || strings.Contains(out, "migration:") || !strings.Contains(out, "Upgraded to 0.50.0-rc.5") {
			t.Fatalf("%s: %d %q %q", name, code, out, errs)
		}
		h.serves(t, "0.50.0-rc.5")
	}
}

// A release whose schema is below the database's is refused before
// anything is asked or recorded: an open migration's rollback window is not
// ended for an upgrade that does not happen.
func TestUpgradeBelowTheDatabasesSchema(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("builds varlatchd and runs as root on Linux (go.yml's Go container)")
	}
	from, newer := cliBuild(t, "0.50.0-rc.4", ""), cliBuild(t, "0.50.0-rc.5", "g6fixture")
	srv := fakerelease.New()
	defer srv.Close()
	defer func(f func(*Run) selfupdate.Source) { selfUpdateSource = f }(selfUpdateSource)
	selfUpdateSource = func(*Run) selfupdate.Source { return srv.Source() }
	fromSchema := checkoutSchema(t)
	m, err := release.NewManifest("0.50.0-rc.6", release.Declaration{SchemaVersion: fromSchema, CompatibleFrom: 1, RollbackSafe: true,
		Previous: &release.Previous{Version: "0.50.0-rc.4", SchemaVersion: fromSchema}, EndsRollbackWindow: true})
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := m.Bytes()
	cli, server, name := upgrade.Assets("0.50.0-rc.6", runtime.GOARCH)
	srv.Publish("0.50.0-rc.6", &fakerelease.Release{Files: map[string][]byte{cli: []byte("#!/bin/sh\n"), server: from, name: manifest}})

	h := newCLIHost(t, from)
	if err := h.svc.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(h.bin, "varlatchd-newer")
	if err := os.WriteFile(other, newer, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(other, "admin", "schema", "upgrade", "--config", h.conf).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.migrated(t, time.Now().Add(-time.Hour))
	code, out, errs := runUpgrade(t, MapEnv{"PATH": h.bin}, "--yes", "--end-rollback-window", "--config", h.conf)
	if code != ExitFailure || !strings.Contains(errs, "upgrade to a release of schema") || !strings.Contains(errs, "nothing was changed") || strings.Contains(out, "migration:") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	if j := h.journal(t); j.WindowEnded != nil {
		t.Fatalf("the window was ended: %+v", j.WindowEnded)
	}
	h.serves(t, "0.50.0-rc.4")
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
	if err := os.Chown(filepath.Join(h.data, migrate.JournalFile), serviceUID, serviceUID); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.serves(t, "0.50.0-rc.4")
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
	if err := os.WriteFile(filepath.Join(h.bin, "varlatch"), []byte("#!/bin/sh\necho varlatch 0.50.0-rc.4\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.svc = &cliService{bin: h.bin, conf: h.conf}
	// As a host has it: the data directory and the server are the service
	// user's, the keys root's, of which the unit hands the server copies.
	own := filepath.Join(dir, "own")
	if err := os.Mkdir(own, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"root-kek", "backup-key"} {
		b, err := os.ReadFile(filepath.Join(dir, "keys", k))
		if err != nil || os.WriteFile(filepath.Join(own, k), b, 0o400) != nil || os.Chown(filepath.Join(own, k), serviceUID, serviceUID) != nil {
			t.Fatal(err)
		}
	}
	h.svc.conf = filepath.Join(filepath.Dir(h.conf), "service.conf")
	if err := os.WriteFile(h.svc.conf, []byte(strings.ReplaceAll(conf, filepath.Join(dir, "keys"), own)), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{h.data, own} {
		if err := os.Chown(p, serviceUID, serviceUID); err != nil {
			t.Fatal(err)
		}
	}
	// The way to them is open to that user.
	for _, leaf := range []string{h.bin, filepath.Dir(h.conf)} {
		for p := leaf; p != filepath.Dir(filepath.Dir(dir)); p = filepath.Dir(p) {
			if err := os.Chmod(p, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	prevService := upgradeService
	upgradeService = func() upgrade.Service { return h.svc }
	t.Cleanup(func() { upgradeService = prevService; _ = h.svc.Stop(context.Background()) })
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.serves(t, "0.50.0-rc.4")
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

// serviceUID stands for the user the unit runs varlatchd as.
const serviceUID = 65534

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
	asServiceUser(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	s.cmd, s.done = cmd, done
	return nil
}

// Config: the host's, the service's own being its copy with other keys.
func (s *cliService) Config(context.Context) (string, error) {
	return filepath.Join(filepath.Dir(s.conf), "varlatchd.conf"), nil
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

// The steps by hand are lines of their own, the last one too.
func TestByHandMessage(t *testing.T) {
	got := byHandMessage(&upgrade.ByHand{Why: "why", How: "losing x:\n  sudo one\n  sudo two"})
	if got != "varlatch upgrade --rollback: why. Nothing was changed. By hand, losing x:\n  sudo one\n  sudo two" {
		t.Fatalf("%q", got)
	}
}

// A recovered rollback says so, and that it can be run again.
func TestRecoveredMessage(t *testing.T) {
	j := &journal.Journal{From: "0.50.0-rc.5", To: "0.50.0-rc.4", Kind: journal.Rollback, State: journal.Undone, Reason: "interrupted after step \"stopped\"", Snapshot: "/s/x/snapshot.vltbak"}
	if got := recoveredMessage(j); !strings.HasPrefix(got, "Undid the interrupted rollback from 0.50.0-rc.5 to 0.50.0-rc.4") ||
		!strings.Contains(got, "0.50.0-rc.5 serves") || !strings.HasSuffix(got, "Run varlatch upgrade --rollback again to go back.") {
		t.Fatalf("an undone rollback: %q", got)
	}
	j.State = journal.Done
	if got := recoveredMessage(j); got != "Finished the interrupted rollback from 0.50.0-rc.5 to 0.50.0-rc.4: 0.50.0-rc.4 serves, after its health checks." {
		t.Fatalf("a finished rollback: %q", got)
	}
	j.Kind, j.From, j.To = journal.Upgrade, "0.50.0-rc.4", "0.50.0-rc.5"
	if got := recoveredMessage(j); !strings.HasPrefix(got, "Finished the interrupted upgrade from 0.50.0-rc.4 to 0.50.0-rc.5") {
		t.Fatalf("a finished upgrade: %q", got)
	}
	j.State = journal.Undone
	if got := recoveredMessage(j); !strings.HasPrefix(got, "Undid the interrupted upgrade") || !strings.Contains(got, "Run varlatch upgrade again to upgrade.") {
		t.Fatalf("an undone upgrade: %q", got)
	}
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
