// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"bytes"
	"context"
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
	ingress     IngressInfo
	ingressDown bool
}

func (s *fakeSource) call(name string) error {
	s.calls = append(s.calls, name)
	return s.fail[name]
}

func (s *fakeSource) Dir() string { return s.dir }
func (s *fakeSource) CleanLeftovers() error {
	return s.call("clean")
}
func (s *fakeSource) Ingress(context.Context) (IngressInfo, error) {
	return s.ingress, s.call("ingress")
}
func (s *fakeSource) StopIngress(_ context.Context, kind Ingress) error {
	if err := s.call("stop " + string(kind)); err != nil {
		return err
	}
	s.ingressDown = true
	return nil
}

// StartIngress fails behind a gate, as the real one does: Compose starts
// the ingress's one-off dependency (varlatch-migrate) again with it, and
// the TypeScript migrate refuses during maintenance (run r8 of the 7.8b
// rehearsal).
func (s *fakeSource) StartIngress(_ context.Context, kind Ingress) error {
	if err := s.call("start " + string(kind)); err != nil {
		return err
	}
	if s.gate != nil {
		return errors.New(`docker compose start failed (exit 1): service "varlatch-migrate" didn't complete successfully: exit 1`)
	}
	s.ingressDown = false
	return nil
}
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
	keysState string // Keys answers this for both files ("written" when empty)
	dataDir   string
	journal   *JournalHead
	database  bool
	calls     []string
	runKeys   [][]byte // each check's run key
	keys      [][]byte // what Keys was given
	journals  [][]byte
	fail      map[string]error
	pass      bool
	info      TargetInfo
	running   bool
	gate      bool
	human     bool // an image's service: the operator starts and stops it
	failOpen  error
	bundles   []string
}

func (t *fakeTarget) call(name string) error {
	t.calls = append(t.calls, name)
	return t.fail[name]
}
func (t *fakeTarget) Describe(context.Context) (TargetInfo, TargetState, error) {
	info := t.info
	info.Config, info.DataDir = "/etc/varlatch/varlatchd.conf", t.dataDir
	return info, TargetState{Journal: t.journal, Database: t.database, Gate: t.gate, Running: t.running}, t.call("describe")
}
func (t *fakeTarget) Start(context.Context) error {
	if err := t.call("start"); err != nil {
		return err
	}
	if t.human {
		if !t.running {
			return &HumanStep{Instruction: "Start the Go service varlatch-go (in Coolify, Deploy it)."}
		}
		return nil
	}
	t.running = true
	return nil
}
func (t *fakeTarget) Stop(context.Context) error {
	if err := t.call("stop"); err != nil {
		return err
	}
	if t.human {
		if t.running {
			return &HumanStep{Instruction: "Stop the Go service varlatch-go (in Coolify, Stop it)."}
		}
		return nil
	}
	t.running = false
	return nil
}
func (t *fakeTarget) OpenLive(_ context.Context, id string) error {
	if err := t.call("openlive " + id); err != nil {
		return err
	}
	if t.failOpen != nil {
		return t.failOpen
	}
	if !t.running || t.journal == nil || t.journal.ID != id || (t.journal.Phase != Switched && t.journal.Phase != Open) {
		return errors.New("not a running target of this switched migration")
	}
	t.gate = false
	t.journal = &JournalHead{ID: id, Phase: Open}
	return nil
}

// fakeProber answers as the address's network would: the target's
// installation once the source's ingress is down and the target runs (or,
// in the Coolify shape, once the domain was moved).
type fakeProber struct {
	w       *world
	probes  int
	moved   bool // Coolify: the operator moved the domain
	wrong   string
	release string // another release answering (the old installation's)
}

func (p *fakeProber) Probe(_ context.Context, origin string) (string, string, error) {
	p.probes++
	if origin != "https://vault.example.test" {
		return "", "", errors.New("probed " + origin)
	}
	served := p.w.tgt.running && (p.w.src.ingressDown || (p.w.eng.Options.Ingress == Coolify && p.moved))
	if !served {
		return "", "", errors.New("connection refused")
	}
	if p.wrong != "" {
		return p.wrong, "0.50.0", nil
	}
	if p.release != "" {
		return "inst_fake", p.release, nil
	}
	return "inst_fake", "0.50.0", nil
}
func (t *fakeTarget) Keys(_ context.Context, kek, bek []byte) (string, string, error) {
	t.keys = append(t.keys, slices.Clone(kek), slices.Clone(bek))
	if t.keysState != "" {
		return t.keysState, t.keysState, t.call("keys")
	}
	return "written", "written", t.call("keys")
}
func (t *fakeTarget) WriteJournal(_ context.Context, j *Journal) error {
	if err := t.call("journal " + string(j.Phase)); err != nil {
		return err
	}
	if err := t.refuses(j); err != nil {
		return err
	}
	b, _ := j.Encode()
	t.journals = append(t.journals, b)
	t.journal = &JournalHead{ID: j.ID, Phase: j.Phase}
	switch j.Phase {
	case Transfer:
		t.gate = true
	case Open, Released:
		t.gate = false
	}
	return nil
}

// refuses is what varlatchd's admin migrate state --write refuses
// (runMigrateState and runMigrate): another migration's journal over one
// not released; a journal going back, but to started before the barrier
// or to released before the switch; and, beside a running varlatchd,
// anything but the switch or the same migration's journal in the phase it
// holds (open and released excepted).
func (t *fakeTarget) refuses(j *Journal) error {
	old := t.journal
	if t.running {
		same := old != nil && old.ID == j.ID && old.Phase == j.Phase && j.Phase != Open && j.Phase != Released
		if j.Phase != Switched && !same {
			return errors.New("varlatchd is running: stop it first; nothing was written")
		}
	}
	if old == nil {
		return nil
	}
	if old.ID != j.ID && old.Phase != Released {
		return errors.New("the data directory holds another migration; nothing was written")
	}
	if old.ID == j.ID {
		back := slices.Index(Phases, j.Phase) < slices.Index(Phases, old.Phase)
		redone := j.Phase == Started && slices.Contains(beforeBarrier, old.Phase)
		if back && j.Phase != Released && !redone {
			return errors.New("the journal does not go back; nothing was written")
		}
		if (old.Phase == Switched || old.Phase == Open) && j.Phase == Released {
			return errors.New("a switched migration is not undone; nothing was written")
		}
	}
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
	if b, err := os.ReadFile(bundle); err != nil || len(b) == 0 {
		return CopyRecord{}, errors.New("the bundle is not readable here")
	}
	t.bundles = append(t.bundles, bundle)
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
func phasesOf(j *Journal) (out []Phase) {
	for _, s := range j.History {
		out = append(out, s.Phase)
	}
	return
}
func containsCall(calls []string, c string) bool { return slices.Contains(calls, c) }

// lastCall is the index of c's last call, -1 if none.
func lastCall(calls []string, c string) int {
	for i := len(calls) - 1; i >= 0; i-- {
		if calls[i] == c {
			return i
		}
	}
	return -1
}

type world struct {
	src    *fakeSource
	tgt    *fakeTarget
	eng    *Engine
	said   []string
	bek    []byte
	prober *fakeProber
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
	w.src.ingress = IngressInfo{PublicURL: "https://vault.example.test/", Caddy: true, WebAddress: "127.0.0.1:8787"}
	w.tgt.info = TargetInfo{Release: "0.50.0", PublicURL: "https://VAULT.example.test:443", Listen: "127.0.0.1:8686", ListenHTTPS: ":443"}
	w.prober = &fakeProber{w: w}
	w.eng = &Engine{Source: w.src, Target: w.tgt, BEK: w.bek, Prober: w.prober, Options: Options{Now: clock.now, Work: t.TempDir(), Ingress: Public,
		Say: func(s string) { w.said = append(w.said, s) }}, pin: &imagePin{Repository: LastTypeScriptRepository, Digest: w.src.info.Digest},
		sleep: func(d time.Duration) { clock.advance(d) }}
	w.src.info.DigestRepository = LastTypeScriptRepository
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
	want := []Phase{Started, Preflight, DryRun, Barrier, Copied, Checked, Transfer, Switched, Open}
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
	// The address: Caddy stopped, the target serving it, checked before the
	// switch; restarted out of its isolation at open.
	if !w.src.ingressDown || !w.tgt.running || w.prober.probes == 0 || j.Transfer == nil || j.Transfer.VerifiedAt == "" ||
		j.Transfer.Origin != "https://vault.example.test" {
		t.Fatalf("the transfer: down %v, running %v, probes %d, %+v", w.src.ingressDown, w.tgt.running, w.prober.probes, j.Transfer)
	}
	if i, k := slices.Index(w.src.calls, "stop public"), slices.Index(w.src.calls, "migrated-out gate-1"); i < 0 || k < i {
		t.Fatalf("the source was switched before its address moved: %v", w.src.calls)
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
	if j.DryRun == nil || !j.DryRun.Fits || j.DryRun.ExportMs != 20000 || j.DryRun.TransferMs != 65000 || j.DryRun.TransferMeasured ||
		j.DryRun.ProjectedMs != 20000+65000+DefaultDrain.Milliseconds() {
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

// A dry run that fails (its export, here) is recorded as stopped, as one
// that ends is: the next run starts it again on the same id, never
// "interrupted" (--resume or --abort only). The barrier was never held.
func TestAFailedDryRunCanRunAgain(t *testing.T) {
	for _, dryRunOnly := range []bool{true, false} {
		w := newWorld(t)
		w.src.fail = map[string]error{"export --dry-run": errors.New("the source's migration export failed (exit 1): EACCES open /backups/x.partial")}
		j, err := w.eng.Run(context.Background(), dryRunOnly)
		if err == nil || !strings.Contains(err.Error(), "EACCES") || !strings.Contains(err.Error(), "recorded as stopped") || j == nil || !j.Stopped || !slices.Contains(beforeBarrier, j.Phase) {
			t.Fatalf("dry run only %v: a failed dry run: %+v %v", dryRunOnly, j, err)
		}
		if containsCall(w.src.calls, "barrier") {
			t.Fatal("a failed dry run held the barrier")
		}
		onDisk, err := readJournal(w.src.dir)
		if err != nil || onDisk == nil || !onDisk.Stopped || onDisk.ID != j.ID {
			t.Fatalf("the journal after a failed dry run: %+v %v", onDisk, err)
		}
		w.src.fail = nil
		again, err := w.eng.Run(context.Background(), dryRunOnly)
		want := Open
		if dryRunOnly {
			want = DryRun
		}
		if err != nil || again.ID != j.ID || again.Phase != want {
			t.Fatalf("dry run only %v: the run after a failed dry run: %+v %v", dryRunOnly, again, err)
		}
		w.noSecrets(t)
	}
}

// The pin's refusal names both images, repository and digest apart: never
// "<repository>@<digest>", which the CLI's fail-safe reads as credentials
// before the "@" and masks (a registry with a port, here).
func TestThePinRefusalNamesBothImages(t *testing.T) {
	w := newWorld(t)
	other := "sha256:" + hexOf(randomBytes(32))
	w.src.info.DigestRepository, w.src.info.Digest = "registry.example:5000/varlatch/varlatchd", other
	_, err := w.eng.Run(context.Background(), true)
	if err == nil {
		t.Fatal("another image was not refused")
	}
	msg := err.Error()
	for _, want := range []string{"repository registry.example:5000/varlatch/varlatchd, digest " + other, "not the published 0.23.0 image: repository "} {
		if !strings.Contains(msg, want) {
			t.Errorf("%q lacks %q", msg, want)
		}
	}
	if strings.Contains(msg, "@") {
		t.Errorf("%q joins a repository and a digest by @", msg)
	}
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
		{"no digest", func(w *world) { w.src.info.Digest = "" }, "not pinned by a registry digest"},
		{"another digest", func(w *world) { w.src.info.Digest = "sha256:" + hexOf(randomBytes(32)) }, "not the published 0.23.0 image"},
		{"another repository", func(w *world) { w.src.info.DigestRepository = "ghcr.io/someone/varlatchd" }, "not the published 0.23.0 image"},
		{"no pinned digest yet", func(w *world) { w.eng.pin = nil }, "0.23.0 is not yet published; this varlatch cannot migrate yet"},
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
	j := &Journal{Format: 1, ID: "mig_bbbbbbbbbbbbbbbbbbbbbbbbbb", Source: w.src.info, History: []Step{}, Barrier: &BarrierRecord{},
		Target:  TargetInfo{Config: "/etc/varlatch/varlatchd.conf", DataDir: w.tgt.dataDir, Release: "0.50.0"},
		Ingress: Public, Transfer: &TransferRecord{Origin: "https://vault.example.test"}, Copy: &CopyRecord{InstallationID: "inst_fake"}}
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
		{Transfer, Open, []string{"stop public", "migrated-out gate-1"}},
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

// A migration goes on to its own target only: a reused journal names
// another target's configuration or data directory, and is refused.
func TestNoRetarget(t *testing.T) {
	w := newWorld(t)
	if _, err := w.eng.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	w.tgt.dataDir = t.TempDir()
	_, err := w.eng.Run(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "goes on to its own target only") || containsCall(w.src.calls, "barrier") {
		t.Fatalf("a retarget: %v", err)
	}
}

// Switched, but the barrier was lifted by hand: a person decides; nothing
// is marked.
func TestAStrandedSwitch(t *testing.T) {
	for _, g := range []*Gate{nil, {Kind: "migration", ID: "another"}} {
		w := interrupted(t, Switched)
		w.src.gate = g
		j, err := w.eng.Resume(context.Background())
		if err == nil || !strings.Contains(err.Error(), "A person must decide") || !strings.Contains(err.Error(), "loses every write") ||
			j.Phase != Switched || slices.ContainsFunc(w.src.calls, func(c string) bool { return strings.HasPrefix(c, "migrated-out") }) {
			t.Fatalf("gate %+v: %+v %v %v", g, j, err, w.src.calls)
		}
	}
}

// Preflight removes what a killed run left, by its exact names: the dry
// run's scratch directories and the journal's temporary names in the work
// directory, the bundles in the backups directory; nothing else.
func TestLeftoversAreCleared(t *testing.T) {
	work, dir := t.TempDir(), t.TempDir()
	backups := filepath.Join(dir, "backups")
	for _, d := range []string{filepath.Join(work, ".dry-run-123456"), filepath.Join(work, ".dry-run-x"), filepath.Join(work, ".dry-run-99", "data"), backups,
		filepath.Join(backups, "migration-0123456789ab.jsonl.d")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]bool{ // path -> removed
		filepath.Join(work, ".migration.json.0123456789ab.tmp"):        true,
		filepath.Join(work, JournalFile):                               false,
		filepath.Join(work, ".dry-run-5"):                              false, // a file, not a directory
		filepath.Join(backups, "migration-0123456789ab.jsonl"):         true,
		filepath.Join(backups, "migration-0123456789ab.jsonl.partial"): true,
		filepath.Join(backups, "migration-0123456789AB.jsonl"):         false,
		filepath.Join(backups, "archive.vltbak"):                       false,
	}
	for p := range files {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(work, filepath.Join(backups, "migration-ba9876543210.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := cleanScratch(work); err != nil {
		t.Fatal(err)
	}
	if err := (&Compose{Directory: dir}).CleanLeftovers(); err != nil {
		t.Fatal(err)
	}
	for p, removed := range files {
		if _, err := os.Lstat(p); (err != nil) != removed {
			t.Errorf("%s: removed %v, want %v", p, err != nil, removed)
		}
	}
	for d, removed := range map[string]bool{filepath.Join(work, ".dry-run-123456"): true, filepath.Join(work, ".dry-run-99"): true,
		filepath.Join(work, ".dry-run-x"): false, filepath.Join(backups, "migration-0123456789ab.jsonl.d"): false,
		filepath.Join(backups, "migration-ba9876543210.jsonl"): false} {
		if _, err := os.Lstat(d); (err != nil) != removed {
			t.Errorf("%s: removed %v, want %v", d, err != nil, removed)
		}
	}
}

// Each shape's transfer, and what the preflight refuses of it: the origin
// (and so the RP ID) must be the source's; public ingress needs the
// target's own HTTPS and the source's Caddy; an own proxy, the target on
// the dashboard's port.
func TestTheAddressBeforeAnything(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(w *world)
		why  string
	}{
		{"no ingress", func(w *world) { w.eng.Options.Ingress = "" }, "--ingress is public, proxy or coolify"},
		{"another host", func(w *world) { w.tgt.info.PublicURL = "https://other.example.test" }, "a migration keeps the origin"},
		{"another port", func(w *world) { w.tgt.info.PublicURL = "https://vault.example.test:8443" }, "a migration keeps the origin"},
		{"another scheme", func(w *world) { w.tgt.info.PublicURL = "http://vault.example.test" }, "a migration keeps the origin"},
		{"no public URL", func(w *world) { w.tgt.info.PublicURL = "" }, "the target's public_url"},
		{"public without Caddy", func(w *world) { w.src.ingress.Caddy = false }, "runs no Caddy"},
		{"public without listen_https", func(w *world) { w.tgt.info.ListenHTTPS = "" }, "no listen_https"},
		{"a proxy on another port", func(w *world) { w.eng.Options.Ingress = Proxy }, "set the target's listen to it"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			c.set(w)
			if _, err := w.eng.Run(context.Background(), false); err == nil || !strings.Contains(err.Error(), c.why) {
				t.Fatalf("%v, want %q", err, c.why)
			}
			if containsCall(w.src.calls, "backup") {
				t.Fatal("it went on")
			}
		})
	}
}

// An own proxy: the dashboard stops, the target takes its port.
func TestAnOwnProxysTransfer(t *testing.T) {
	w := newWorld(t)
	w.eng.Options.Ingress = Proxy
	w.tgt.info.Listen, w.tgt.info.ListenHTTPS = "127.0.0.1:8787", ""
	j, err := w.eng.Run(context.Background(), false)
	if err != nil || j.Phase != Open || !containsCall(w.src.calls, "stop proxy") || j.DryRun.TransferMs != 10000 {
		t.Fatalf("%+v %v %v", j, err, w.src.calls)
	}
}

// The public URL does not answer from the target: the address goes back
// (the target stopped, Caddy started), the migration undone.
func TestATransferThatFailsGoesBack(t *testing.T) {
	w := newWorld(t)
	w.prober.wrong = "inst_other"
	w.eng.Options.TransferTimeout = 10 * time.Second
	j, err := w.eng.Run(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "not the migrated inst_fake") || j.Phase != Released || j.Undone.From != Transfer {
		t.Fatalf("%+v %v", j, err)
	}
	if w.tgt.running || w.src.ingressDown || !containsCall(w.src.calls, "start public") || !containsCall(w.src.calls, "release gate-1") ||
		containsCall(w.src.calls, "migrated-out gate-1") || w.tgt.database {
		t.Fatalf("not given back: running %v, down %v, %v", w.tgt.running, w.src.ingressDown, w.src.calls)
	}
	if w.prober.probes < 5 {
		t.Errorf("probed %d times in 10 s", w.prober.probes)
	}
}

// An undo in the transfer gives the address back in this order: the
// target stopped, the barrier lifted, then the source's ingress started.
// Started behind the barrier, the ingress does not come up (its one-off
// dependency refuses during maintenance), and the source answers nothing
// (run r8 of the 7.8b rehearsal: a single --abort after a kill in the
// transfer left the dashboard down). For each shape that has an ingress
// of this host's, by a failed transfer and by --abort.
func TestAnUndoInTheTransferLiftsTheBarrierFirst(t *testing.T) {
	for _, kind := range []Ingress{Public, Proxy} {
		for _, how := range []string{"a failed transfer", "--abort"} {
			t.Run(string(kind)+", "+how, func(t *testing.T) {
				var w *world
				if how == "--abort" {
					// Killed in the transfer: the barrier held, the
					// source's ingress stopped, the target serving.
					w = interrupted(t, Transfer)
					j, err := readJournal(w.src.dir)
					if err != nil {
						t.Fatal(err)
					}
					j.Ingress = kind
					if err := writeJournal(w.src.dir, j); err != nil {
						t.Fatal(err)
					}
					w.src.ingressDown, w.tgt.running = true, true
					if _, err := w.eng.Abort(context.Background()); err != nil {
						t.Fatalf("--abort: %v\n%v", err, w.src.calls)
					}
				} else {
					w = newWorld(t)
					w.eng.Options.Ingress = kind
					if kind == Proxy {
						w.tgt.info.Listen, w.tgt.info.ListenHTTPS = "127.0.0.1:8787", ""
					}
					w.eng.Options.TransferTimeout = 10 * time.Second
					w.prober.wrong = "inst_other"
					if _, err := w.eng.Run(context.Background(), false); err == nil || !strings.Contains(err.Error(), "not the migrated inst_fake") {
						t.Fatalf("%v", err)
					}
				}
				release, start := slices.Index(w.src.calls, "release gate-1"), lastCall(w.src.calls, "start "+string(kind))
				if release < 0 || start < release || w.src.ingressDown || w.tgt.running || w.src.gate != nil {
					t.Fatalf("not given back in order: release at %d, start at %d, down %v, target running %v, gate %v\n%v",
						release, start, w.src.ingressDown, w.tgt.running, w.src.gate, w.src.calls)
				}
				if stop := lastCall(w.tgt.calls, "stop"); stop < 0 {
					t.Fatalf("the target was not stopped: %v", w.tgt.calls)
				}
			})
		}
	}
}

// An undo in the transfer that cannot show the source's gate is gone
// leaves the ingress stopped and the journal where it was, for --resume:
// the gate unreadable, a gate that is not the migration's, the barrier's
// release refused. Each says why the ingress was not started.
func TestAnUndoInTheTransferKeepsTheIngressStoppedBehindAGate(t *testing.T) {
	for _, c := range []struct {
		name, why string
		set       func(w *world)
		abort     bool
	}{
		{"the gate unreadable", "could not confirm the source's gate is lifted, so its Caddy is not started again",
			func(w *world) { w.src.fail["gate"] = errors.New("docker: no answer") }, true},
		{"another gate", "the source's Caddy is not started again while its gate stands",
			func(w *world) { w.src.gate = &Gate{Kind: "restore", ID: "restore-1"} }, true},
		{"the release refused", "the source's Caddy is not started again while its barrier stands",
			func(w *world) { w.src.fail["release gate-1"] = errors.New("Migration ownership lost") }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var w *world
			var err error
			if c.abort {
				w = interrupted(t, Transfer)
				w.src.ingressDown, w.tgt.running = true, true
				c.set(w)
				_, err = w.eng.Abort(context.Background())
			} else {
				w = newWorld(t)
				w.prober.wrong = "inst_other"
				w.eng.Options.TransferTimeout = 10 * time.Second
				c.set(w)
				_, err = w.eng.Run(context.Background(), false)
			}
			if err == nil || !strings.Contains(err.Error(), c.why) || !strings.Contains(err.Error(), "varlatch migrate --resume tries again") {
				t.Fatalf("%v, want %q", err, c.why)
			}
			if containsCall(w.src.calls, "start public") || !w.src.ingressDown || w.tgt.running {
				t.Fatalf("the ingress started (down %v), or the target runs (%v): %v", w.src.ingressDown, w.tgt.running, w.src.calls)
			}
			j, rerr := readJournal(w.src.dir)
			if rerr != nil || j.Phase != Transfer || !j.Undoing || j.Undone != nil {
				t.Fatalf("the journal: %+v %v", j, rerr)
			}
		})
	}
}

// The Coolify shape: migrate stops at the prompt; --resume before the
// domain moved waits (nothing undone); after it, the migration opens.
func TestCoolifysTransferByHand(t *testing.T) {
	w := newWorld(t)
	w.eng.Options.Ingress = Coolify
	w.eng.Options.TransferTimeout = 4 * time.Second
	j, err := w.eng.Run(context.Background(), false)
	if !errors.Is(err, ErrAwaitingOperator) || j.Phase != Transfer || !j.Transfer.Asked || !w.tgt.running || w.src.ingressDown {
		t.Fatalf("the prompt: %+v %v", j, err)
	}
	said := strings.Join(w.said, "\n")
	if !strings.Contains(said, "move the domain of https://vault.example.test") || !strings.Contains(said, "varlatch migrate --resume") {
		t.Fatalf("the instruction: %s", said)
	}
	if j, err = w.eng.Resume(context.Background()); err == nil || !strings.Contains(err.Error(), "once the domain is moved") || j.Phase != Transfer {
		t.Fatalf("a resume before the move: %+v %v", j, err)
	}
	if containsCall(w.src.calls, "release gate-1") {
		t.Fatal("a resume before the move undid")
	}
	w.prober.moved = true
	if j, err = w.eng.Resume(context.Background()); err != nil || j.Phase != Open {
		t.Fatalf("the resume after the move: %+v %v", j, err)
	}
	w.noSecrets(t)
}

// --abort: before the switch it undoes (in the transfer, the address
// first); past it, refused.
func TestAbort(t *testing.T) {
	w := newWorld(t)
	w.eng.Options.Ingress = Coolify
	if _, err := w.eng.Run(context.Background(), false); !errors.Is(err, ErrAwaitingOperator) {
		t.Fatal(err)
	}
	j, err := w.eng.Abort(context.Background())
	if err != nil || j.Phase != Released || w.tgt.running || !containsCall(w.src.calls, "release gate-1") ||
		!strings.Contains(strings.Join(w.said, "\n"), "move the domain of https://vault.example.test back") {
		t.Fatalf("an abort in the transfer: %+v %v %v", j, err, w.said)
	}
	w2 := newWorld(t)
	if _, err := w2.eng.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if j, err := w2.eng.Abort(context.Background()); err != nil || j.Phase != Released {
		t.Fatalf("an abort after a dry run: %+v %v", j, err)
	}
	w3 := interrupted(t, Switched)
	if _, err := w3.eng.Abort(context.Background()); err == nil || !strings.Contains(err.Error(), "goes forward only") {
		t.Fatalf("an abort after the switch: %v", err)
	}
}

// The same installation's id with the old release is the old installation
// answering: the check fails, the address goes back.
func TestTheOldReleaseAnswering(t *testing.T) {
	w := newWorld(t)
	w.prober.release = "0.23.0"
	w.eng.Options.TransferTimeout = 4 * time.Second
	j, err := w.eng.Run(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "release 0.23.0, not the target's 0.50.0") || j.Phase != Released || containsCall(w.src.calls, "migrated-out gate-1") {
		t.Fatalf("%+v %v", j, err)
	}
	// Coolify: still waiting, nothing undone.
	w = newWorld(t)
	w.eng.Options.Ingress, w.eng.Options.TransferTimeout = Coolify, 4*time.Second
	w.prober.release, w.prober.moved = "0.23.0", true
	if _, err := w.eng.Run(context.Background(), false); !errors.Is(err, ErrAwaitingOperator) {
		t.Fatal(err)
	}
	if j, err = w.eng.Resume(context.Background()); err == nil || !strings.Contains(err.Error(), "release 0.23.0") || j.Phase != Transfer {
		t.Fatalf("coolify: %+v %v", j, err)
	}
}

// Open interrupted: the live open failed (the gate not ended), or the
// target went down before it served. --resume finishes it; done, it
// changes nothing.
func TestAnOpenFinishedOnResume(t *testing.T) {
	w := newWorld(t)
	w.tgt.failOpen = errors.New("the transfer's gate could not be ended")
	j, err := w.eng.Run(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "varlatch migrate --resume finishes it") || j.Phase != Open {
		t.Fatalf("%+v %v", j, err)
	}
	if w.tgt.journal.Phase != Switched || !w.tgt.gate || !w.tgt.running {
		t.Fatalf("the target: %+v gate %v running %v", w.tgt.journal, w.tgt.gate, w.tgt.running)
	}
	w.tgt.failOpen = nil
	if j, err = w.eng.Resume(context.Background()); err != nil || w.tgt.journal.Phase != Open || w.tgt.gate || !w.tgt.running {
		t.Fatalf("resume: %+v %v; target %+v gate %v running %v", j, err, w.tgt.journal, w.tgt.gate, w.tgt.running)
	}
	// The target went down before the open reached it: written open
	// offline, then started.
	w.tgt.running, w.tgt.gate, w.tgt.journal = false, true, &JournalHead{ID: j.ID, Phase: Switched}
	if _, err := w.eng.Resume(context.Background()); err != nil || !w.tgt.running || w.tgt.gate || w.tgt.journal.Phase != Open {
		t.Fatalf("a target down: %v, running %v gate %v", err, w.tgt.running, w.tgt.gate)
	}
	n := len(w.tgt.calls)
	if _, err := w.eng.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range w.tgt.calls[n:] {
		if c != "describe" {
			t.Fatalf("a resume of a finished open did %s", c)
		}
	}
}

// An undo whose target journal could not say released (its gate stuck):
// --resume finishes it, and a new migration can start.
func TestAReleaseFinishedOnResume(t *testing.T) {
	w := newWorld(t)
	w.prober.wrong = "inst_other"
	w.eng.Options.TransferTimeout = 4 * time.Second
	w.tgt.fail["journal released"] = errors.New("the transfer's gate could not be removed")
	j, err := w.eng.Run(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "varlatch migrate --resume finishes it") || j.Phase != Released || !w.tgt.gate {
		t.Fatalf("%+v %v gate %v", j, err, w.tgt.gate)
	}
	delete(w.tgt.fail, "journal released")
	if _, err := w.eng.Resume(context.Background()); err != nil || w.tgt.gate || w.tgt.journal.Phase != Released {
		t.Fatalf("resume: %v gate %v %+v", err, w.tgt.gate, w.tgt.journal)
	}
	w.prober.wrong = ""
	if j, err := w.eng.Run(context.Background(), false); err != nil || j.Phase != Open {
		t.Fatalf("the next migration: %+v %v", j, err)
	}
}

// A journal of 7.4a's development builds (transfer a string) still reads.
func TestAnOlderJournal(t *testing.T) {
	dir := t.TempDir()
	text := `{"format":1,"id":"mig_cccccccccccccccccccccccccc","phase":"dry-run","stopped":true,"dryRunOnly":true,"source":{"kind":"compose","dir":"/x","release":"0.23.0","image":"i","digest":"sha256:x","digestRepository":"r"},` +
		`"target":{"config":"/c","dataDir":"/d"},"maxDowntimeSeconds":600,"drainSeconds":60,"transfer":"none: the address transfer is slice 7.4b's","history":[]}`
	if err := os.WriteFile(filepath.Join(dir, JournalFile), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := Status(dir)
	if err != nil || j == nil || j.Phase != DryRun || j.Transfer != nil {
		t.Fatalf("%+v %v", j, err)
	}
}

func TestValidUnit(t *testing.T) {
	for name, ok := range map[string]bool{"varlatchd": true, "varlatchd.service": true, "varlatch-go@x.service": true,
		"-H": false, "--host=x": false, "/etc/x": false, "a/b": false, "": false, "a b": false} {
		if ValidUnit(name) != ok {
			t.Errorf("%q: %v", name, !ok)
		}
	}
}

// A hand-made journal in transfer with no transfer record: an abort in the
// Coolify shape says how to move the domain back, without a panic.
func TestAnAbortWithoutATransferRecord(t *testing.T) {
	w := interrupted(t, Transfer)
	j, _ := readJournal(w.src.dir)
	j.Ingress, j.Transfer = Coolify, nil
	if err := writeJournal(w.src.dir, j); err != nil {
		t.Fatal(err)
	}
	j, err := w.eng.Abort(context.Background())
	if err != nil || j.Phase != Released || !strings.Contains(strings.Join(w.said, "\n"), "move the domain of the installation's address back") {
		t.Fatalf("%+v %v %v", j, err, w.said)
	}
}

// With Stage (an image target), each bundle the target reads is a copy in
// a directory of its own under the temporary directory, given to that
// user, and gone after; so is the dry run's scratch database.
func TestStagedForTheImagesUser(t *testing.T) {
	w := newWorld(t)
	me := Owner{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	w.eng.Options.Stage, w.eng.Options.StageBase = &me, t.TempDir()
	if j, err := w.eng.Run(context.Background(), false); err != nil || j.Phase != Open {
		t.Fatalf("%+v %v", j, err)
	}
	if len(w.tgt.bundles) != 2 {
		t.Fatalf("bundles %v", w.tgt.bundles)
	}
	for _, b := range w.tgt.bundles {
		if filepath.Base(b) != "bundle.jsonl" || !strings.HasPrefix(filepath.Base(filepath.Dir(b)), ".varlatch-migrate-stage-") || filepath.Dir(filepath.Dir(b)) != w.eng.Options.StageBase {
			t.Errorf("a bundle not staged: %s", b)
		}
		if _, err := os.Stat(filepath.Dir(b)); !os.IsNotExist(err) {
			t.Errorf("a staged bundle left: %s", b)
		}
	}
}

// The stage's leftovers: a killed run's stage and configuration directories
// in this source's base removed under the lock, this run's own spared,
// nothing outside the base touched.
func TestStageLeftovers(t *testing.T) {
	w := newWorld(t)
	me := Owner{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	base := t.TempDir()
	keep := filepath.Join(base, ".varlatch-migrate-conf-111")
	for _, d := range []string{filepath.Join(base, ".varlatch-migrate-stage-222"), filepath.Join(base, ".varlatch-migrate-conf-333"), keep, filepath.Join(base, "other")} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	w.eng.Options.Stage, w.eng.Options.StageBase, w.eng.Options.StageKeep = &me, base, keep
	if _, err := w.eng.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	for d, gone := range map[string]bool{".varlatch-migrate-stage-222": true, ".varlatch-migrate-conf-333": true, ".varlatch-migrate-conf-111": false, "other": false} {
		if _, err := os.Stat(filepath.Join(base, d)); os.IsNotExist(err) != gone {
			t.Errorf("%s: gone %v, want %v", d, os.IsNotExist(err), gone)
		}
	}
}

// The fake target refuses what varlatchd refuses (TestTheSwitchBeside
// ARunningVarlatchd holds varlatchd to the same table).
func TestTheFakeTargetRefusesAsVarlatchd(t *testing.T) {
	j := func(id string, p Phase) *Journal { return &Journal{Format: 1, ID: id, Phase: p} }
	a, b := "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", "mig_bbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, c := range []struct {
		held    *JournalHead
		running bool
		write   *Journal
		ok      bool
	}{
		{nil, true, j(a, Switched), true},
		{&JournalHead{ID: a, Phase: Transfer}, true, j(b, Switched), false},
		{&JournalHead{ID: a, Phase: Transfer}, true, j(a, Transfer), true},
		{&JournalHead{ID: a, Phase: Transfer}, true, j(a, Checked), false},
		{&JournalHead{ID: a, Phase: Transfer}, true, j(a, Open), false},
		{&JournalHead{ID: a, Phase: Transfer}, true, j(a, Released), false},
		{&JournalHead{ID: a, Phase: Transfer}, false, j(a, Released), true},
		{&JournalHead{ID: a, Phase: Switched}, false, j(a, Released), false},
		{&JournalHead{ID: a, Phase: DryRun}, false, j(a, Started), true},
		{&JournalHead{ID: a, Phase: Barrier}, false, j(a, Started), false},
		{&JournalHead{ID: a, Phase: Released}, false, j(b, Started), true},
		{&JournalHead{ID: a, Phase: Copied}, false, j(b, Started), false},
	} {
		ft := &fakeTarget{journal: c.held, running: c.running, fail: map[string]error{}}
		if err := ft.WriteJournal(context.Background(), c.write); (err == nil) != c.ok {
			t.Errorf("held %+v running %v, writing %s %s: %v", c.held, c.running, c.write.ID, c.write.Phase, err)
		}
	}
}

// An image's service behind an own proxy: the start step names the port to
// publish, the dashboard's address the proxy targets.
func TestAnImageBehindAProxyNamesThePort(t *testing.T) {
	w := newWorld(t)
	w.eng.Options.Ingress = Proxy
	w.tgt.human, w.tgt.info.Kind, w.tgt.info.Listen, w.tgt.info.ListenHTTPS = true, "image", "0.0.0.0:8686", ""
	j, err := w.eng.Run(context.Background(), false)
	said := strings.Join(w.said, "\n")
	if !errors.Is(err, ErrAwaitingOperator) || j.Transfer.Publish != "127.0.0.1:8787" ||
		!strings.Contains(said, "Publish its listen (0.0.0.0:8686) on 127.0.0.1:8787, the address your proxy targets") {
		t.Fatalf("%+v %v\n%s", j.Transfer, err, said)
	}
}

// An undo left at released with the image's service running: the stop is
// asked for, with what to run after.
func TestAReleaseWaitsForTheImagesStop(t *testing.T) {
	w := newWorld(t)
	w.tgt.human = true
	j := &Journal{Format: 1, ID: "mig_eeeeeeeeeeeeeeeeeeeeeeeeee", Phase: Released, History: []Step{}}
	if err := writeJournal(w.src.dir, j); err != nil {
		t.Fatal(err)
	}
	w.tgt.journal, w.tgt.running, w.tgt.gate = &JournalHead{ID: j.ID, Phase: Transfer}, true, true
	if _, err := w.eng.Resume(context.Background()); !errors.Is(err, ErrAwaitingOperator) ||
		!strings.Contains(strings.Join(w.said, "\n"), "Stop the Go service varlatch-go (in Coolify, Stop it). Then run varlatch migrate --resume (or --abort) again.") {
		t.Fatalf("%v %v", err, w.said)
	}
	w.tgt.running = false
	if _, err := w.eng.Resume(context.Background()); err != nil || w.tgt.journal.Phase != Released || w.tgt.gate {
		t.Fatalf("after the stop: %v %+v gate %v", err, w.tgt.journal, w.tgt.gate)
	}
}
