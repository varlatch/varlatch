// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeSource is a TypeScript installation as the engine sees it: its
// gate, its backups, its barrier, its exports.
type fakeSource struct {
	dir     string
	info    SourceInfo
	gate    *Gate
	kek     []byte
	calls   []string
	runKeys [][]byte // each export's run key
	fail    map[string]error
	clock   *fakeClock
	// exportTakes is how long an export takes on the clock.
	exportTakes time.Duration
}

func (s *fakeSource) call(name string) error {
	s.calls = append(s.calls, name)
	return s.fail[name]
}

func (s *fakeSource) Dir() string { return s.dir }
func (s *fakeSource) Discover(context.Context) (SourceInfo, error) {
	return s.info, s.call("discover")
}
func (s *fakeSource) Gate(context.Context) (*Gate, error) {
	if err := s.call("gate"); err != nil {
		return nil, err
	}
	if s.gate == nil {
		return nil, nil
	}
	g := *s.gate
	return &g, nil
}
func (s *fakeSource) RootKEK() ([]byte, error) { return slices.Clone(s.kek), s.call("kek") }
func (s *fakeSource) Backup(context.Context) (string, error) {
	return "0f0e0d0c-0b0a-4908-8706-050403020100", s.call("backup")
}
func (s *fakeSource) VerifyBackup(_ context.Context, id string) error { return s.call("verify " + id) }
func (s *fakeSource) Barrier(context.Context, time.Duration) (BarrierRecord, error) {
	if err := s.call("barrier"); err != nil {
		if s.gate == nil {
			s.gate = &Gate{Kind: "migration", ID: "gate-1"}
		}
		return BarrierRecord{}, err
	}
	s.gate = &Gate{Kind: "migration", ID: "gate-1"}
	return BarrierRecord{GateID: "gate-1", AuditPosition: "46", FrozenAt: "2026-11-20T00:00:00Z"}, nil
}
func (s *fakeSource) Export(_ context.Context, runKey []byte, dryRun bool) (string, error) {
	what := "export"
	if dryRun {
		what = "export --dry-run"
	}
	s.runKeys = append(s.runKeys, slices.Clone(runKey))
	if s.clock != nil {
		s.clock.advance(s.exportTakes)
	}
	if err := s.call(what); err != nil {
		return "", err
	}
	p := filepath.Join(s.dir, "bundle-"+hex.EncodeToString(runKey[:4])+".jsonl")
	return p, os.WriteFile(p, []byte("a bundle"), 0o600)
}
func (s *fakeSource) Release(_ context.Context, id string) error {
	if err := s.call("release " + id); err != nil {
		return err
	}
	s.gate = nil
	return nil
}
func (s *fakeSource) MarkMigratedOut(_ context.Context, id string) error {
	if err := s.call("migrated-out " + id); err != nil {
		return err
	}
	s.gate = &Gate{Kind: "migrated-out", ID: id}
	return nil
}

// fakeTarget is varlatchd's side: its journal, its keys, its database.
type fakeTarget struct {
	dataDir  string
	journal  *JournalHead
	database bool
	calls    []string
	runKeys  [][]byte // each check's run key
	keys     [][]byte // what Keys was given
	journals [][]byte
	fail     map[string]error
	pass     bool
}

func (t *fakeTarget) call(name string) error {
	t.calls = append(t.calls, name)
	return t.fail[name]
}
func (t *fakeTarget) Describe(context.Context) (TargetInfo, TargetState, error) {
	return TargetInfo{Config: "/etc/varlatch/varlatchd.conf", DataDir: t.dataDir}, TargetState{Journal: t.journal, Database: t.database}, t.call("describe")
}
func (t *fakeTarget) Keys(_ context.Context, kek, bek []byte) (string, string, error) {
	t.keys = append(t.keys, slices.Clone(kek), slices.Clone(bek))
	return "written", "written", t.call("keys")
}
func (t *fakeTarget) WriteJournal(_ context.Context, j *Journal) error {
	if err := t.call("journal " + string(j.Phase)); err != nil {
		return err
	}
	b, _ := j.Encode()
	t.journals = append(t.journals, b)
	t.journal = &JournalHead{ID: j.ID, Phase: j.Phase}
	return nil
}
func (t *fakeTarget) Import(_ context.Context, bundle, scratch string) (CopyRecord, error) {
	what := "import"
	if scratch != "" {
		what = "import --scratch"
	}
	if err := t.call(what); err != nil {
		return CopyRecord{}, err
	}
	if scratch == "" {
		t.database = true
	}
	return CopyRecord{InstallationID: "inst_fake", Tables: 58, Rows: 902}, nil
}
func (t *fakeTarget) Check(_ context.Context, bundle, scratch string, runKey []byte) (CheckSummary, error) {
	what := "check"
	if scratch != "" {
		what = "check --scratch"
	}
	t.runKeys = append(t.runKeys, slices.Clone(runKey))
	if err := t.call(what); err != nil {
		return CheckSummary{}, err
	}
	if !t.pass && scratch == "" {
		return CheckSummary{Passed: false, Faults: []string{"rows: grants: row 2 differs from the source's in revoked_at"}}, nil
	}
	return CheckSummary{Passed: true, Checks: []CheckResult{{Name: "rows", Passed: true, Checked: 902}}}, nil
}
func (t *fakeTarget) Discard(_ context.Context, id string) error {
	if err := t.call("discard " + id); err != nil {
		return err
	}
	t.database = false
	return nil
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *fakeClock                   { return &fakeClock{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)} }
func randomBytes(n int) []byte               { b := make([]byte, n); _, _ = rand.Read(b); return b }
func hexOf(b []byte) string                  { return hex.EncodeToString(b) }
func phasesOf(j *Journal) (out []Phase) {
	for _, s := range j.History {
		out = append(out, s.Phase)
	}
	return
}
func containsCall(calls []string, c string) bool { return slices.Contains(calls, c) }

type world struct {
	src  *fakeSource
	tgt  *fakeTarget
	eng  *Engine
	said []string
	bek  []byte
}

func newWorld(t *testing.T) *world {
	t.Helper()
	clock := newClock()
	w := &world{
		src: &fakeSource{dir: t.TempDir(), info: SourceInfo{Kind: "compose", Release: LastTypeScriptRelease, Image: "ghcr.io/varlatch/varlatchd:0.23.0",
			Digest: "sha256:" + hexOf(randomBytes(32))}, kek: []byte(hexOf(randomBytes(32)) + "\n"), fail: map[string]error{}, clock: clock, exportTakes: 20 * time.Second},
		tgt: &fakeTarget{dataDir: t.TempDir(), fail: map[string]error{}, pass: true},
		bek: []byte(hexOf(randomBytes(32)) + "\n"),
	}
	w.eng = &Engine{Source: w.src, Target: w.tgt, BEK: w.bek, Options: Options{Now: clock.now, Work: t.TempDir(),
		Say: func(s string) { w.said = append(w.said, s) }}}
	return w
}

// secrets are what the journal and the progress lines may never hold.
func (w *world) noSecrets(t *testing.T) {
	t.Helper()
	files := [][]byte{}
	if b, err := os.ReadFile(filepath.Join(w.src.dir, JournalFile)); err == nil {
		files = append(files, b)
	}
	files = append(files, w.tgt.journals...)
	files = append(files, []byte(strings.Join(w.said, "\n")))
	keys := [][]byte{bytes.TrimSpace(w.src.kek), bytes.TrimSpace(w.bek)}
	for _, k := range w.src.runKeys {
		keys = append(keys, k, []byte(hexOf(k)))
	}
	for _, f := range files {
		for _, k := range keys {
			if len(k) > 0 && bytes.Contains(f, k) {
				t.Fatalf("a key in the journal or the progress lines: %s", f)
			}
		}
	}
	if st, err := os.Stat(filepath.Join(w.src.dir, JournalFile)); err == nil && st.Mode().Perm() != 0o600 {
		t.Errorf("the journal's mode is %v", st.Mode().Perm())
	}
}

// A migration end to end: every phase journalled in order, in both places;
// the source switched; one run key per copy, the export's and the checks'
// the same; the bundles removed; nothing secret journalled or said.
func TestAMigrationEndToEnd(t *testing.T) {
	w := newWorld(t)
	j, err := w.eng.Run(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	want := []Phase{Started, Preflight, DryRun, Barrier, Copied, Checked, Switched, Open}
	if !slices.Equal(phasesOf(j), want) {
		t.Fatalf("phases %v, want %v", phasesOf(j), want)
	}
	disk, err := Status(w.src.dir)
	if err != nil || disk.Phase != Open || disk.ID != j.ID || w.tgt.journal.Phase != Open || w.tgt.journal.ID != j.ID {
		t.Fatalf("the journals: %+v %+v %v", disk, w.tgt.journal, err)
	}
	if w.src.gate == nil || w.src.gate.Kind != "migrated-out" {
		t.Fatalf("the source's gate: %+v", w.src.gate)
	}
	if len(w.src.runKeys) != 2 || len(w.tgt.runKeys) != 2 || !bytes.Equal(w.src.runKeys[0], w.tgt.runKeys[0]) ||
		!bytes.Equal(w.src.runKeys[1], w.tgt.runKeys[1]) || bytes.Equal(w.src.runKeys[0], w.src.runKeys[1]) {
		t.Fatal("each copy's export and checks share one run key, and each copy has its own")
	}
	if !bytes.Equal(w.tgt.keys[0], w.src.kek) || !bytes.Equal(w.tgt.keys[1], w.bek) {
		t.Fatal("the target's keys are not the source's")
	}
	if left, _ := filepath.Glob(filepath.Join(w.src.dir, "bundle-*")); len(left) != 0 {
		t.Errorf("bundles left: %v", left)
	}
	if j.DryRun == nil || !j.DryRun.Fits || j.DryRun.ExportMs != 20000 || j.DryRun.ProjectedMs != 20000+DefaultDrain.Milliseconds() {
		t.Errorf("the dry run's report: %+v", j.DryRun)
	}
	if j.Preflight == nil || j.Preflight.ArchiveID == "" || !containsCall(w.src.calls, "verify "+j.Preflight.ArchiveID) {
		t.Errorf("the preflight's backup was not verified: %v", w.src.calls)
	}
	w.noSecrets(t)
	// Done: a second run says so.
	if _, err := w.eng.Run(context.Background(), false); err == nil || !strings.Contains(err.Error(), "is open") {
		t.Errorf("a run after open: %v", err)
	}
}

// --dry-run stops after the dry run: no barrier; a later run starts the
// same migration again from its preflight and goes through.
func TestADryRunStopsThere(t *testing.T) {
	w := newWorld(t)
	j, err := w.eng.Run(context.Background(), true)
	if err != nil || j.Phase != DryRun || !j.Stopped || !j.DryRunOnly {
		t.Fatalf("a dry run: %+v %v", j, err)
	}
	if containsCall(w.src.calls, "barrier") {
		t.Fatal("a dry run held the barrier")
	}
	again, err := w.eng.Run(context.Background(), false)
	if err != nil || again.ID != j.ID || again.Phase != Open {
		t.Fatalf("the run after the dry run: %+v %v", again, err)
	}
	w.noSecrets(t)
}

// A projection over the budget refuses the barrier: nothing switched.
func TestOverTheBudget(t *testing.T) {
	w := newWorld(t)
	w.src.exportTakes = 11 * time.Minute
	j, err := w.eng.Run(context.Background(), false)
	if !errors.Is(err, ErrOverBudget) || j.Phase != DryRun || !j.Stopped || containsCall(w.src.calls, "barrier") {
		t.Fatalf("over the budget: %+v %v %v", j, err, w.src.calls)
	}
	w.eng.Options.MaxDowntime = time.Hour
	if j, err = w.eng.Run(context.Background(), false); err != nil || j.Phase != Open {
		t.Fatalf("with a larger budget: %v", err)
	}
}

// What a migration refuses before it does anything: another source
// release, an unpinned image, a source behind a gate, a target with a
// database of its own or another migration.
func TestRefusalsBeforeAnything(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(w *world)
		why  string
	}{
		{"another release", func(w *world) { w.src.info.Release = "0.22.4" }, "starts from the last TypeScript release, 0.23.0"},
		{"no digest", func(w *world) { w.src.info.Digest = "" }, "not pinned by a digest"},
		{"a source behind a gate", func(w *world) { w.src.gate = &Gate{Kind: "restore", ID: "g"} }, "behind a restore gate"},
		{"a target with a database", func(w *world) { w.tgt.database = true }, "holds a database and no migration journal"},
		{"a target of another migration", func(w *world) { w.tgt.journal = &JournalHead{ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: Copied} }, "holds the migration mig_aaaa"},
		{"a failed backup", func(w *world) { w.src.fail["backup"] = errors.New("no space") }, "preflight: the backup"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			c.set(w)
			_, err := w.eng.Run(context.Background(), false)
			if err == nil || !strings.Contains(err.Error(), c.why) {
				t.Fatalf("%v, want %q", err, c.why)
			}
			if containsCall(w.src.calls, "barrier") || containsCall(w.tgt.calls, "import") {
				t.Fatalf("it went on: %v %v", w.src.calls, w.tgt.calls)
			}
		})
	}
}

// A failure between the barrier and the switch undoes: the barrier lifted,
// the target's database discarded, the journal released with why.
func TestAFailureAfterTheBarrierUndoes(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(w *world)
		from Phase
	}{
		{"the checks fail", func(w *world) { w.tgt.pass = false }, Copied},
		{"the import fails", func(w *world) { w.tgt.fail["import"] = errors.New("refused") }, Barrier},
		{"the export fails", func(w *world) { w.src.fail["export"] = errors.New("refused") }, Barrier},
		{"the barrier does not drain", func(w *world) { w.src.fail["barrier"] = errors.New("did not drain") }, Barrier},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			c.set(w)
			j, err := w.eng.Run(context.Background(), false)
			if err == nil || !strings.Contains(err.Error(), "reopened unchanged") || j.Phase != Released || j.Undone == nil || j.Undone.From != c.from {
				t.Fatalf("%+v %v", j, err)
			}
			if !containsCall(w.src.calls, "release gate-1") || w.src.gate != nil || w.tgt.database {
				t.Fatalf("not undone: %v %v %+v", w.src.calls, w.tgt.calls, w.src.gate)
			}
			if containsCall(w.src.calls, "migrated-out gate-1") {
				t.Fatal("switched after a failure")
			}
			// A new migration may start after an undone one.
			w.tgt.pass, w.tgt.fail, w.src.fail = true, map[string]error{}, map[string]error{}
			again, err := w.eng.Run(context.Background(), false)
			if err != nil || again.ID == j.ID || again.Phase != Open {
				t.Fatalf("the next migration: %+v %v", again, err)
			}
			w.noSecrets(t)
		})
	}
}

// An undo that cannot lift the barrier leaves the journal where it was,
// for --resume.
func TestAnUnfinishedUndo(t *testing.T) {
	w := newWorld(t)
	w.tgt.pass = false
	w.src.fail["release gate-1"] = errors.New("the daemon is gone")
	j, err := w.eng.Run(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "undoing did not finish") || j.Phase != Copied {
		t.Fatalf("%+v %v", j, err)
	}
	if _, err := w.eng.Run(context.Background(), false); err == nil || !strings.Contains(err.Error(), "--resume") {
		t.Fatalf("a run over an interrupted migration: %v", err)
	}
	delete(w.src.fail, "release gate-1")
	if j, err = w.eng.Resume(context.Background()); j.Phase != Released || err == nil || !strings.Contains(err.Error(), "reopened unchanged") {
		t.Fatalf("resume: %+v %v", j, err)
	}
}

// interrupted is a migration killed in phase p: the journals and the sides
// as it left them.
func interrupted(t *testing.T, p Phase) *world {
	t.Helper()
	w := newWorld(t)
	j := &Journal{Format: 1, ID: "mig_bbbbbbbbbbbbbbbbbbbbbbbbbb", Source: w.src.info, History: []Step{}, Barrier: &BarrierRecord{}}
	for _, q := range Phases[:slices.Index(Phases, p)+1] {
		j.enter(q, w.src.clock.now())
	}
	if err := writeJournal(w.src.dir, j); err != nil {
		t.Fatal(err)
	}
	w.tgt.journal = &JournalHead{ID: j.ID, Phase: p}
	if slices.Index(Phases, p) >= slices.Index(Phases, Barrier) {
		w.src.gate = &Gate{Kind: "migration", ID: "gate-1"}
		j.Barrier.GateID = "gate-1"
		_ = writeJournal(w.src.dir, j)
	}
	if slices.Index(Phases, p) >= slices.Index(Phases, Copied) {
		w.tgt.database = true
	}
	return w
}

// --resume, from each phase a kill can leave (decision 14's stated
// states): before the barrier, redone; held, undone; switched, opened.
func TestResumeFromEachPhase(t *testing.T) {
	for _, c := range []struct {
		phase Phase
		want  Phase
		calls []string
	}{
		{Started, Open, []string{"backup", "barrier", "migrated-out gate-1"}},
		{Preflight, Open, []string{"backup", "barrier", "migrated-out gate-1"}},
		{DryRun, Open, []string{"backup", "barrier", "migrated-out gate-1"}},
		{Barrier, Released, []string{"release gate-1"}},
		{Copied, Released, []string{"release gate-1"}},
		{Checked, Released, []string{"release gate-1"}},
		{Switched, Open, []string{"migrated-out gate-1"}},
	} {
		t.Run(string(c.phase), func(t *testing.T) {
			w := interrupted(t, c.phase)
			j, err := w.eng.Resume(context.Background())
			if j == nil || j.Phase != c.want {
				t.Fatalf("resume from %s: %+v %v", c.phase, j, err)
			}
			if (c.want == Released) != (err != nil) {
				t.Fatalf("resume from %s: %v", c.phase, err)
			}
			for _, call := range c.calls {
				if !containsCall(w.src.calls, call) {
					t.Errorf("resume from %s did not %s: %v", c.phase, call, w.src.calls)
				}
			}
			if c.want == Released && (w.tgt.database || containsCall(w.src.calls, "migrated-out gate-1")) {
				t.Errorf("undone from %s: database %v, calls %v", c.phase, w.tgt.database, w.src.calls)
			}
			// Resuming again changes nothing.
			n := len(w.src.calls)
			if j2, err := w.eng.Resume(context.Background()); err != nil || j2.Phase != c.want || len(w.src.calls) != n {
				t.Errorf("a second resume: %+v %v %v", j2, err, w.src.calls[n:])
			}
		})
	}
}

// A switched migration whose source was already marked migrated out (the
// kill came after the mark) is not marked twice.
func TestResumeAfterTheMark(t *testing.T) {
	w := interrupted(t, Switched)
	w.src.gate = &Gate{Kind: "migrated-out", ID: "gate-1"}
	j, err := w.eng.Resume(context.Background())
	if err != nil || j.Phase != Open || containsCall(w.src.calls, "migrated-out gate-1") {
		t.Fatalf("%+v %v %v", j, err, w.src.calls)
	}
}

// Nothing to resume, and a lock held by another run.
func TestResumeRefusals(t *testing.T) {
	w := newWorld(t)
	if _, err := w.eng.Resume(context.Background()); err == nil || !strings.Contains(err.Error(), "nothing to resume") {
		t.Errorf("no journal: %v", err)
	}
	unlock, err := lockDir(w.src.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := w.eng.Run(context.Background(), false); err == nil || !strings.Contains(err.Error(), "another varlatch migrate") {
		t.Errorf("a second run: %v", err)
	}
}

// The run key's text for the sides' stdin.
func TestRunKeyText(t *testing.T) {
	k := randomBytes(32)
	if got := string(RunKeyText(k)); got != hexOf(k)+"\n" {
		t.Fatal(got)
	}
}
