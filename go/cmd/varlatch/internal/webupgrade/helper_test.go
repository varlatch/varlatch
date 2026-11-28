// SPDX-License-Identifier: Apache-2.0

//go:build linux

package webupgrade

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/upgrade"
	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/release"
	journal "github.com/varlatch/varlatch/go/lib/upgradejournal"
	"github.com/varlatch/varlatch/go/lib/upgraderequest"
)

const (
	installed = "0.51.0"
	next      = "0.52.0"
)

var (
	identity   = "idn_" + strings.Repeat("b", 26)
	reversible = release.LastTypeScriptRelease
	// oneStep is the next release, declared rollback-safe for the installed
	// one.
	oneStep = release.Declaration{SchemaVersion: 8, CompatibleFrom: 7, RollbackSafe: true, Previous: &release.Previous{Version: installed, SchemaVersion: 7}, ReversibleTo: &reversible}
)

// fixture is a host for the helper: a data directory and a taken directory
// of the test's own user, varlatchd.conf's directory, and fakes for the
// engine, GitHub and varlatchd's record.
type fixture struct {
	t                   *testing.T
	data, taken, conf   string
	now                 time.Time
	skew                time.Duration
	database            int64
	newest              string
	newestErr, fetchErr error
	declaration         release.Declaration
	windowEnds          bool
	run                 func(onStep func(*journal.Journal, journal.Step)) (*journal.Journal, error)
	ran                 int
	records             [][]string
	mu                  sync.Mutex
}

func newFixture(t *testing.T) *fixture {
	dir := t.TempDir()
	f := &fixture{t: t, data: filepath.Join(dir, "data"), taken: filepath.Join(dir, "upgrade", "taken"), conf: filepath.Join(dir, "etc"),
		now: time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC), newest: next, declaration: oneStep, database: 7}
	for _, d := range []string{f.data, f.taken, f.conf} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.accept(true)
	f.run = func(onStep func(*journal.Journal, journal.Step)) (*journal.Journal, error) {
		j := f.journal(journal.InProgress, journal.None)
		for _, s := range journal.Steps {
			j.Step = s
			onStep(j, s)
		}
		j.State = journal.Done
		f.writeJournal(j)
		return j, nil
	}
	return f
}

func (f *fixture) accept(on bool) {
	if err := os.WriteFile(filepath.Join(f.conf, upgraderequest.ConfFile), upgraderequest.EncodeConf(on), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) journal(state journal.State, step journal.Step) *journal.Journal {
	return &journal.Journal{Format: journal.Format, ID: "0123456789abcdef", From: installed, To: next, State: state, Step: step, DataDir: f.data}
}

func (f *fixture) writeJournal(j *journal.Journal) {
	if err := journal.Write(f.conf, j); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) helper() *Helper {
	return &Helper{
		ConfigDir: f.conf, TakenDir: f.taken, TakenOwner: uint32(os.Getuid()), Now: func() time.Time { return f.now.Add(f.skew) },
		DataDir: func(context.Context) (string, error) { return f.data, nil },
		Inspect: func(context.Context) (upgrade.Installed, error) {
			return upgrade.Installed{Version: installed, Schema: 7, Database: f.database, DataDir: f.data}, nil
		},
		Newest: func(context.Context) (string, error) { return f.newest, f.newestErr },
		Fetch: func(_ context.Context, v string) (upgrade.Release, error) {
			if f.fetchErr != nil {
				return upgrade.Release{}, f.fetchErr
			}
			m, err := release.NewManifest(v, f.declaration)
			if err != nil {
				f.t.Fatal(err)
			}
			return upgrade.Release{Version: v, Manifest: m}, nil
		},
		WindowEnds: func(string, string, bool) (bool, error) { return f.windowEnds, nil },
		Run: func(_ context.Context, _ upgrade.Installed, _ upgrade.Release, onStep func(*journal.Journal, journal.Step)) (*journal.Journal, error) {
			f.ran++
			return f.run(onStep)
		},
		Record: func(_ context.Context, args ...string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.records = append(f.records, args)
			return nil
		},
	}
}

// request writes a request as varlatchd does.
func (f *fixture) request(version string) upgraderequest.Request {
	f.t.Helper()
	id := make([]byte, 26)
	_, _ = rand.Read(id)
	for i := range id {
		id[i] = "abcdefghijklmnopqrstuvwxyz234567"[id[i]%32]
	}
	r := upgraderequest.NewRequest("upr_"+string(id), version, identity, f.now)
	if err := upgraderequest.WriteRequest(f.data, r); err != nil {
		f.t.Fatal(err)
	}
	return r
}

// last is the last record's phase and reason.
func (f *fixture) last() (string, string) {
	if len(f.records) == 0 {
		return "", ""
	}
	r := f.records[len(f.records)-1]
	value := func(k string) string {
		for i := 0; i+1 < len(r); i++ {
			if r[i] == k {
				return r[i+1]
			}
		}
		return ""
	}
	return value("--phase"), value("--reason")
}

// Every refusal of Decision 1, each recorded with its class and nothing
// upgraded: the engine never runs.
func TestEveryRefusal(t *testing.T) {
	for _, c := range []struct {
		name, version, reason string
		set                   func(f *fixture)
	}{
		{"expired", next, "expired", func(f *fixture) { f.skew = upgraderequest.Lifetime }},
		{"the host does not accept requests", next, "disabled", func(f *fixture) { f.accept(false) }},
		{"no web-upgrade.conf", next, "disabled", func(f *fixture) { _ = os.Remove(filepath.Join(f.conf, upgraderequest.ConfFile)) }},
		{"a prerelease", "0.52.0-rc.1", "prerelease", nil},
		{"not newer", installed, "not-newer", nil},
		{"older", "0.50.2", "not-newer", nil},
		{"another upgrade is not over", next, "pending", func(f *fixture) { f.writeJournal(f.journal(journal.InProgress, journal.Snapshot)) }},
		{"an undo that failed", next, "pending", func(f *fixture) { f.writeJournal(f.journal(journal.Failed, journal.Started)) }},
		{"held after a restore", next, "held", func(f *fixture) {
			if err := backup.WriteHold(f.data, backup.Hold{ArchiveID: "a", RestoredAt: "t"}); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"a maintenance gate", next, "maintenance", func(f *fixture) {
			if err := os.WriteFile(filepath.Join(f.data, backup.GateFile), []byte("{}"), 0o600); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"undone before", next, "undone", func(f *fixture) { f.writeJournal(f.journal(journal.Undone, journal.Started)) }},
		{"rolled back from", next, "undone", func(f *fixture) {
			up := f.journal(journal.Done, journal.Checked)
			rb := &journal.Journal{Format: journal.Format, ID: "fedcba9876543210", Kind: journal.Rollback, From: next, To: installed, State: journal.Done, Upgraded: up, DataDir: f.data}
			f.writeJournal(rb)
		}},
		{"GitHub does not answer", next, "unreachable", func(f *fixture) { f.newestErr = &selfupdate.Error{Message: "down", Unreachable: true} }},
		{"a newer release since", next, "superseded", func(f *fixture) { f.newest = "0.52.1" }},
		{"no such release", "0.53.0", "not-latest", nil},
		{"a skipped release", next, "not-rollback-safe", func(f *fixture) {
			// Checked against 0.51.1, which this host skipped.
			d := oneStep
			d.Previous = &release.Previous{Version: "0.51.1", SchemaVersion: 7}
			f.declaration = d
		}},
		{"not declared rollback-safe", next, "not-rollback-safe", func(f *fixture) {
			d := oneStep
			d.RollbackSafe, d.CompatibleFrom = false, 8
			f.declaration = d
		}},
		{"below the database's schema", next, "schema", func(f *fixture) {
			// A later release wrote the database (schema 9) and this one is
			// back: 0.52.0's schema 8 cannot be given it.
			f.database = 9
		}},
		{"it ends a rollback window", next, "ends-rollback-window", func(f *fixture) { f.windowEnds = true }},
		{"GitHub fails while downloading", next, "unreachable", func(f *fixture) { f.fetchErr = &selfupdate.Error{Message: "down", Unreachable: true} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			if c.set != nil {
				c.set(f)
			}
			r := f.request(c.version)
			o, err := f.helper().FromRequest(context.Background())
			phase, reason := f.last()
			if err != nil || o.Phase != upgraderequest.Refused || phase != "refused" || reason != c.reason || o.Reason != c.reason || o.Request.ID != r.ID {
				t.Fatalf("%+v, %v; last record %s %s", o, err, phase, reason)
			}
			if f.ran != 0 {
				t.Fatal("the engine ran")
			}
			if _, err := os.Stat(filepath.Join(f.taken, r.ID+".json")); err != nil {
				t.Fatalf("the taken request is not kept under its id: %v", err)
			}
		})
	}
}

// A request that verifies runs the engine, and the records follow its
// steps: taken, verifying, backing up (with the journal's id), restarting
// before the stop, checking, done.
func TestAnUpgradeFromARequest(t *testing.T) {
	f := newFixture(t)
	f.request(next)
	o, err := f.helper().FromRequest(context.Background())
	if err != nil || o.Phase != upgraderequest.Done || o.JournalID != "0123456789abcdef" || f.ran != 1 {
		t.Fatalf("%+v %v", o, err)
	}
	var phases []string
	for _, r := range f.records {
		phases = append(phases, r[6])
	}
	if got := strings.Join(phases, " "); got != "taken verifying backing-up restarting checking done" {
		t.Fatalf("the records: %s", got)
	}
	if !strings.Contains(strings.Join(f.records[2], " "), "--journal 0123456789abcdef") {
		t.Fatalf("backing-up names no journal: %v", f.records[2])
	}
}

// Once the host undid an upgrade to a version, the same version asked again
// is refused (Decision 6): the journal is root's, whatever varlatchd says.
// Only an upgrade by hand, which writes another journal, clears it.
func TestAnUndoThenTheSameVersionAgain(t *testing.T) {
	f := newFixture(t)
	f.run = func(onStep func(*journal.Journal, journal.Step)) (*journal.Journal, error) {
		j := f.journal(journal.InProgress, journal.None)
		for _, s := range journal.Steps[:slices.Index(journal.Steps, journal.Started)+1] {
			j.Step = s
			onStep(j, s)
		}
		j.State, j.Reason = journal.Undone, "the health checks failed"
		f.writeJournal(j)
		return j, &upgrade.Error{Message: "it was undone", Journal: j}
	}
	f.request(next)
	o, err := f.helper().FromRequest(context.Background())
	if err == nil || o.Phase != upgraderequest.Undone || o.Reason != "health" {
		t.Fatalf("the first: %+v %v", o, err)
	}
	f.request(next)
	o, err = f.helper().FromRequest(context.Background())
	if err != nil || o.Phase != upgraderequest.Refused || o.Reason != "undone" || f.ran != 1 {
		t.Fatalf("the same version again: %+v %v (ran %d)", o, err, f.ran)
	}
	// A newer release is asked for normally.
	f.newest = "0.52.1"
	d := oneStep
	f.declaration = d
	f.run = func(func(*journal.Journal, journal.Step)) (*journal.Journal, error) {
		return f.journal(journal.Done, journal.Checked), nil
	}
	f.request("0.52.1")
	if o, err := f.helper().FromRequest(context.Background()); err != nil || o.Phase != upgraderequest.Done {
		t.Fatalf("a newer one: %+v %v", o, err)
	}
}

// The backup gate: a snapshot refused for want of a destination is a
// refusal; a failed upload, or a delivered copy that does not check out, a
// failure; both before the stop, so nothing changed. A release that does not
// verify is a verification failure.
func TestTheBackupGateAndVerification(t *testing.T) {
	failAtSnapshot := func(msg string) func(func(*journal.Journal, journal.Step)) (*journal.Journal, error) {
		return func(onStep func(*journal.Journal, journal.Step)) (*journal.Journal, error) {
			j := f0journal()
			onStep(j, journal.Verified)
			j.State = journal.Undone
			return j, &upgrade.Error{Message: "the upgrade to 0.52.0 did not complete (the pre-upgrade snapshot: " + msg + "); it was undone", Journal: j}
		}
	}
	for _, c := range []struct {
		name, phase, reason string
		set                 func(f *fixture)
	}{
		{"no destination", "refused", "no-backup-destination", func(f *fixture) {
			f.run = failAtSnapshot("No backup destination is configured (backup_destinations_file, backup_destination): there is no remote copy to verify")
		}},
		{"the upload fails", "failed", "backup", func(f *fixture) { f.run = failAtSnapshot("uploading: connection refused") }},
		{"the delivered copy does not check out", "failed", "backup", func(f *fixture) {
			f.run = failAtSnapshot("the archive a's remote copy failed its check (integrity false, compatibility true, Root KEK match true)")
		}},
		{"a signature that does not verify", "failed", "verification", func(f *fixture) {
			f.fetchErr = &selfupdate.Error{Message: "SHA256SUMS is not signed by the release workflow"}
		}},
		{"an undo that did not complete", "failed", "undo", func(f *fixture) {
			f.run = func(func(*journal.Journal, journal.Step)) (*journal.Journal, error) {
				j := f.journal(journal.Failed, journal.Started)
				return j, &upgrade.Error{Message: "left", Journal: j}
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			c.set(f)
			f.request(next)
			o, _ := f.helper().FromRequest(context.Background())
			if phase, reason := f.last(); phase != c.phase || reason != c.reason || string(o.Phase) != c.phase {
				t.Fatalf("%+v: %s %s", o, phase, reason)
			}
		})
	}
}

func f0journal() *journal.Journal {
	return &journal.Journal{Format: journal.Format, ID: "0123456789abcdef", From: installed, To: next, State: journal.InProgress, Step: journal.Verified}
}

// A power cut between the request and the stop: the engine stopped at the
// snapshot, its journal in progress, the status saying it restarts. The
// next request is refused (pending) until the recovery (at boot, or
// sudo varlatch upgrade) finishes or undoes it; the status keeps the
// journal's id, which the serving release reads with the journal.
func TestAPowerCutBetweenTheRequestAndTheStop(t *testing.T) {
	f := newFixture(t)
	f.run = func(onStep func(*journal.Journal, journal.Step)) (*journal.Journal, error) {
		j := f.journal(journal.InProgress, journal.Verified)
		f.writeJournal(j)
		onStep(j, journal.Verified)
		j.Step = journal.Snapshot
		f.writeJournal(j)
		onStep(j, journal.Snapshot)
		// Where the engine stops at a crash point (here an error; on a host
		// the helper dies with the power).
		return j, errors.New("upgrade: stopped at a crash point")
	}
	f.request(next)
	_, _ = f.helper().FromRequest(context.Background())
	if phase, _ := f.last(); phase != "failed" {
		t.Fatalf("the helper's last record: %s", phase)
	}
	if !strings.Contains(strings.Join(f.records[len(f.records)-2], " "), "--phase restarting --journal 0123456789abcdef") {
		t.Fatalf("no restart recorded with the journal: %v", f.records)
	}
	f.request(next)
	if o, err := f.helper().FromRequest(context.Background()); err != nil || o.Reason != "pending" || f.ran != 1 {
		t.Fatalf("a request while it is pending: %+v %v", o, err)
	}
}

// The take and the cancel: before the take, the cancel wins and the helper
// finds nothing; after it, the cancel finds nothing (too late); racing, in
// many rounds, exactly one of them wins each time.
func TestCancelAndTake(t *testing.T) {
	f := newFixture(t)
	r := f.request(next)
	if err := upgraderequest.CancelRequest(f.data, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.helper().FromRequest(context.Background()); !errors.Is(err, ErrNoRequest) || len(f.records) != 0 {
		t.Fatalf("after the cancel: %v %v", err, f.records)
	}
	r = f.request(next)
	if _, _, err := take(f.data, f.taken, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if err := upgraderequest.CancelRequest(f.data, r.ID); !errors.Is(err, upgraderequest.ErrTaken) {
		t.Fatalf("a cancel after the take: %v", err)
	}
	for i := 0; i < 200; i++ {
		f.now = f.now.Add(time.Millisecond)
		r := f.request(next)
		var took, cancelled error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _, took = take(f.data, f.taken, uint32(os.Getuid())) }()
		go func() { defer wg.Done(); cancelled = upgraderequest.CancelRequest(f.data, r.ID) }()
		wg.Wait()
		if (took == nil) == (cancelled == nil) {
			t.Fatalf("round %d: the take said %v, the cancel %v", i, took, cancelled)
		}
		if took != nil && !errors.Is(took, ErrNoRequest) || cancelled != nil && !errors.Is(cancelled, upgraderequest.ErrTaken) {
			t.Fatalf("round %d: %v %v", i, took, cancelled)
		}
	}
}

// A forged request file: a link, a second hard link, too big, not a
// request, or the request directory replaced by a link: never acted on, and
// a link moves nothing it points to.
func TestAForgedRequestFile(t *testing.T) {
	dir := func(f *fixture) string { return filepath.Join(f.data, upgraderequest.Dir) }
	file := func(f *fixture) string { return filepath.Join(dir(f), upgraderequest.RequestFile) }
	for _, c := range []struct {
		name string
		make func(f *fixture) (keep string)
	}{
		{"a symbolic link", func(f *fixture) string {
			target := filepath.Join(f.conf, "secret")
			_ = os.WriteFile(target, []byte("not yours"), 0o600)
			_ = upgraderequest.MakeDir(f.data)
			_ = os.Symlink(target, file(f))
			return target
		}},
		{"a hard link", func(f *fixture) string {
			r := f.request(next)
			_ = r
			other := filepath.Join(f.data, "other")
			_ = os.Link(file(f), other)
			return other
		}},
		{"too big", func(f *fixture) string {
			_ = upgraderequest.MakeDir(f.data)
			_ = os.WriteFile(file(f), []byte(strings.Repeat(" ", upgraderequest.MaxBytes+1)), 0o600)
			return ""
		}},
		{"not a request", func(f *fixture) string {
			_ = upgraderequest.MakeDir(f.data)
			_ = os.WriteFile(file(f), []byte(`{"format":1,"version":"0.52.0","repo":"elsewhere/varlatch"}`), 0o600)
			return ""
		}},
		{"a directory", func(f *fixture) string {
			_ = os.MkdirAll(file(f), 0o700)
			return ""
		}},
		{"the request directory a link", func(f *fixture) string {
			elsewhere := filepath.Join(f.conf, "elsewhere")
			_ = os.MkdirAll(elsewhere, 0o700)
			_ = os.WriteFile(filepath.Join(elsewhere, upgraderequest.RequestFile), []byte("{}"), 0o600)
			_ = os.Symlink(elsewhere, dir(f))
			return filepath.Join(elsewhere, upgraderequest.RequestFile)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			keep := c.make(f)
			_, err := f.helper().FromRequest(context.Background())
			if err == nil || len(f.records) != 0 || f.ran != 0 {
				t.Fatalf("acted on: %v %v", err, f.records)
			}
			if keep != "" {
				if _, err := os.Stat(keep); err != nil {
					t.Fatalf("what the link names was moved: %v", err)
				}
			}
		})
	}
}

// Undid reads only root's journal: an upgrade to the version undone, or a
// rollback from it.
func TestUndid(t *testing.T) {
	up := &journal.Journal{Kind: journal.Upgrade, State: journal.Undone, To: next, Step: journal.Started}
	if !Undid(up, next) || Undid(up, "0.52.1") || Undid(nil, next) {
		t.Fatal("an undone upgrade")
	}
	// Undone before the stop (the backup gate): nothing served changed.
	if Undid(&journal.Journal{Kind: journal.Upgrade, State: journal.Undone, To: next, Step: journal.Verified}, next) {
		t.Fatal("an upgrade undone before the stop")
	}
	if Undid(&journal.Journal{Kind: journal.Upgrade, State: journal.Done, To: next}, next) {
		t.Fatal("a done upgrade")
	}
	rb := &journal.Journal{Kind: journal.Rollback, State: journal.Done, Upgraded: &journal.Journal{To: next}}
	if !Undid(rb, next) {
		t.Fatal("a rollback from it")
	}
	rb.State = journal.Undone
	if Undid(rb, next) {
		t.Fatal("a rollback that was itself undone leaves the upgrade")
	}
}

// As root, as the helper runs: a request file that is not the data
// directory's owner's (here root's own, in a directory of the service
// user's) is taken and never acted on; one of the owner's is. Root only:
// go.yml's Go container runs it.
func TestTakeChecksTheOwnerAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("runs as root (go.yml's Go container)")
	}
	const service = 65534
	f := newFixture(t)
	for _, p := range []string{filepath.Dir(f.taken), f.taken} {
		if err := os.Chmod(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(f.data, service, service); err != nil {
		t.Fatal(err)
	}
	h := f.helper()
	h.TakenOwner = 0
	r := f.request(next) // root's, as the test is
	if _, err := h.FromRequest(context.Background()); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "not the data directory's owner") || f.ran != 0 || len(f.records) != 0 {
		t.Fatalf("root's file: %v (ran %d, %v)", err, f.ran, f.records)
	}
	r = f.request(next)
	for _, p := range []string{filepath.Join(f.data, upgraderequest.Dir), filepath.Join(f.data, upgraderequest.Dir, upgraderequest.RequestFile)} {
		if err := os.Chown(p, service, service); err != nil {
			t.Fatal(err)
		}
	}
	if o, err := h.FromRequest(context.Background()); err != nil || o.Phase != upgraderequest.Done || o.Request.ID != r.ID {
		t.Fatalf("the owner's file: %+v %v", o, err)
	}
	// The taken directory must be root's alone.
	if err := os.Chmod(f.taken, 0o755); err != nil {
		t.Fatal(err)
	}
	f.request(next)
	if _, err := h.FromRequest(context.Background()); err == nil || !strings.Contains(err.Error(), "is not root's alone") {
		t.Fatalf("an open taken directory: %v", err)
	}
}
