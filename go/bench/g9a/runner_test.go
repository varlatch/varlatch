// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
)

// fakeTarget is a varlatchd stand-in for the runner's own tests: a real
// storage engine (so checkpoints, snapshots and the WAL are real) whose
// converge runs write blobs that grow the WAL.
type fakeTarget struct {
	db      *storage.DB
	targets int
	running atomic.Bool
}

func (f *fakeTarget) WALSize() int64 { return f.db.Metrics().WALBytes }

func (f *fakeTarget) Snapshot(ctx context.Context, dest string, o storage.SnapshotOptions) (storage.SnapshotStats, error) {
	return f.db.Snapshot(ctx, dest, o)
}

func (f *fakeTarget) Converge(ctx context.Context) ConvergeResult {
	if !f.running.CompareAndSwap(false, true) {
		return ConvergeResult{Err: ErrConvergeRunning}
	}
	defer f.running.Store(false)
	for i := range f.targets {
		err := f.db.Write(ctx, func(tx *storage.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO blob (target, body) VALUES (?, randomblob(16384))`, i)
			return err
		})
		if err != nil {
			return ConvergeResult{Targets: i, Err: err}
		}
	}
	return ConvergeResult{Targets: f.targets, Values: f.targets}
}

// The runner end to end, without k6 or varlatchd: converge runs, a timed
// backup and a WAL-triggered one, the samplers, then the event log. The
// timed backup must complete before the WAL-triggered attempt starts.
func TestRunner(t *testing.T) {
	if testing.Short() {
		t.Skip("probes the disk for a few seconds")
	}
	p := DefaultPlan()
	// Nine seconds of load: room for converge runs after the timed backup's
	// TRUNCATE (they grow the WAL to the WAL-triggered backup's fraction)
	// even when, on a busy host, every other tick is skipped.
	p.Phases = []Phase{{Name: "warmup", Rate: 1, Seconds: 1, Warmup: true}, {Name: "p", Rate: 1, Seconds: 9}}
	// The converge runs write past the small bound, so the WAL crosses
	// half of it from below after the timed backup's TRUNCATE.
	p.Backups = []Backup{{Phase: "p", AtSeconds: 1}, {Phase: "p", WALTriggered: WALTrigger{Fraction: 0.5, MaxAttempts: 2}}}
	p.ConvergeEverySeconds = 2.5
	p.Targets = 3
	p.IdleProbeSeconds = 3
	p.WALBound = 64 << 10
	out, data := t.TempDir(), t.TempDir()

	target := &fakeTarget{targets: p.Targets}
	r, err := NewRunner(RunnerOptions{DataDir: data, OutDir: out, Plan: p, Target: target, Tail: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	target.db, err = storage.Open(context.Background(), storage.Options{Path: filepath.Join(data, "g9a.db"), WALBound: p.WALBound, OnCheckpoint: r.OnCheckpoint})
	if err != nil {
		t.Fatal(err)
	}
	if err := target.db.Write(context.Background(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(context.Background(), `CREATE TABLE blob (id INTEGER PRIMARY KEY, target INTEGER NOT NULL, body BLOB NOT NULL) STRICT`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteManifest([]ManifestEntry{{Address: "127.0.0.2", Identity: "i1", Token: "t", Keys: []string{"K"}}}); err != nil {
		t.Fatal(err)
	}
	if err := r.Prepare(context.Background(), System{Target: TargetVarlatchd, Production: true}, time.Second); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()
	base := srv.URL
	// A k6 on another host fetches the same files.
	for path, file := range map[string]string{"/run/plan": FilePlan, "/run/manifest": FileManifest} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		served, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		want, _ := os.ReadFile(filepath.Join(out, file))
		if resp.StatusCode != 200 || string(served) != string(want) {
			t.Fatalf("GET %s: %d, %d bytes, want the %d bytes of %s", path, resp.StatusCode, len(served), len(want), file)
		}
	}
	post := func(path string, want int) {
		t.Helper()
		resp, err := http.Post(base+path, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("POST %s: %d", path, resp.StatusCode)
		}
	}
	post("/run/start", 200)
	post("/run/start", 409)
	for i := range 21 {
		r.Count(i == 20, false)
	}
	time.Sleep(time.Duration(p.PhaseSeconds("p")) * time.Second) // converge runs and the backups
	post("/run/stop", 200)
	select {
	case <-r.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the run did not end on /run/stop")
	}
	r.Finish()
	if err := target.db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	events, err := ReadEvents(filepath.Join(out, FileEvents))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	var end Event
	starts := map[int]Event{}
	ends := map[int]Event{}
	var attempts []Event
	for _, e := range events {
		switch e.Ev {
		case EvBackupStart:
			if _, dup := starts[e.Backup]; dup || e.Backup == 0 {
				t.Errorf("backup_start: %+v", e)
			}
			starts[e.Backup] = e
		case EvBackupEnd:
			ends[e.Backup] = e
			if e.Err != "" || e.Pages == 0 {
				t.Errorf("backup: %+v", e)
			}
		case EvWALBackup:
			attempts = append(attempts, e)
		case EvBackupWait, EvBackupMissed:
			t.Errorf("the timed backup did not run when due: %+v", e)
		case EvConvergeEnd:
			switch {
			case e.Err == ErrConvergeRunning.Error():
				seen["converge skipped"]++
			case e.Err != "":
				t.Errorf("converge: %s", e.Err)
			case e.Targets == p.Targets:
				seen["converge complete"]++
			default:
				t.Errorf("converge over %d of %d targets: %+v", e.Targets, p.Targets, e)
			}
		case EvError:
			t.Errorf("server error: %s", e.Err)
		case EvRunEnd:
			end = e
		}
		seen[e.Ev]++
		if e.Ev == EvCheckpoint {
			seen["checkpoint "+e.Trigger]++
		}
		if e.Ev == EvFsync && e.Idle {
			seen["fsync idle"]++
		}
		if e.Ev == EvMemory && e.Final {
			seen["memory final"]++
		}
	}
	for _, want := range []string{EvRunStart, EvRunEnd, EvWAL, EvMemory, EvBackupStart, EvBackupEnd, EvConvergeEnd, "converge complete",
		"checkpoint interval", "checkpoint snapshot", "checkpoint close", "fsync idle", "memory final"} {
		if seen[want] == 0 {
			t.Errorf("no %s event (saw %v)", want, seen)
		}
	}
	if end.Requests != 21 || end.Errors != 1 || end.BusyErrs != 0 {
		t.Errorf("run_end: %+v", end)
	}
	// The timed backup is backup 1: it started when due, completed, and its
	// end (with its own TRUNCATE) came before the first WAL-triggered
	// attempt started.
	timed, ok := starts[1]
	if !ok || timed.Attempt != 0 || timed.Phase != "p" {
		t.Fatalf("the timed backup did not start first: %+v", starts)
	}
	timedEnd, ok := ends[1]
	if !ok {
		t.Fatal("the timed backup never completed")
	}
	if len(attempts) == 0 || len(attempts) > 2 {
		t.Fatalf("%d WAL-triggered attempts, want 1 or 2 (events %v)", len(attempts), seen)
	}
	if first := starts[attempts[0].Backup]; first.T <= timedEnd.T {
		t.Errorf("the WAL-triggered attempt started at %d, before the timed backup completed at %d", first.T, timedEnd.T)
	}
	// Every WAL-triggered attempt: numbered in order, started at or over
	// half the bound, logged at its start with the same WAL size, and none
	// after one held a TRUNCATE off.
	for i, a := range attempts {
		st := starts[a.Backup]
		if a.Attempt != i+1 || a.Phase != "p" || a.Bytes < 32<<10 || st.Attempt != a.Attempt || st.Phase != "p" || st.WALBefore != a.Bytes || a.StartUs != st.T {
			t.Errorf("attempt %d: %+v, its start %+v", i+1, a, st)
		}
		if _, ok := ends[a.Backup]; !ok {
			t.Errorf("attempt %d never completed", a.Attempt)
		}
		if a.HeldOff && i != len(attempts)-1 {
			t.Errorf("an attempt after attempt %d, which held a TRUNCATE off", a.Attempt)
		}
	}
	var sys System
	b, _ := os.ReadFile(filepath.Join(out, FileSystem))
	if err := json.Unmarshal(b, &sys); err != nil || sys.Target != TargetVarlatchd || sys.IdleSync == "" || sys.Disk.Dir == "" {
		t.Fatalf("system.json: %v %+v", err, sys)
	}
	if left, err := os.ReadDir(filepath.Join(data, "backups")); err != nil || len(left) != 0 {
		t.Errorf("backup snapshots kept: %v %v", err, left)
	}
	// The plan a remote k6 fetches carries the WAL-triggered backup.
	if b, _ := os.ReadFile(filepath.Join(out, FilePlan)); !strings.Contains(string(b), `"walTriggered": {`) {
		t.Errorf("plan.json: %s", b)
	}

	// A second run into the same output directory is refused.
	if _, err := NewRunner(RunnerOptions{DataDir: data, OutDir: out, Plan: p, Target: target}); err == nil || !strings.Contains(err.Error(), "already holds a run") {
		t.Fatalf("reused output directory: %v", err)
	}
}

// slotRig is a runner with the backup scheduling of a run but a fake
// database: the WAL size is set by the test, and each snapshot (by backup
// number) sleeps and may report a size trigger it deferred, while the rig
// counts how many run at once.
type slotRig struct {
	s       *Runner
	wal     atomic.Int64
	seen    atomic.Int64 // the last size a sample read
	running atomic.Int32
	most    atomic.Int32
}

// slotSnap is one fake snapshot: it runs d, or until hold is closed if
// hold is set, and defers a size trigger first if defers.
type slotSnap struct {
	d      time.Duration
	defers bool
	hold   chan struct{}
}

func newSlotRig(t *testing.T, snap map[int]slotSnap) *slotRig {
	t.Helper()
	out := t.TempDir()
	ev, err := newEventLog(filepath.Join(out, FileEvents))
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPlan()
	p.WALBound = 1000
	r := &slotRig{}
	r.seen.Store(-1)
	r.s = &Runner{opts: RunnerOptions{DataDir: t.TempDir(), OutDir: out, Plan: p}, ev: ev, slot: newBackupSlot()}
	r.s.walSize = func() int64 { v := r.wal.Load(); r.seen.Store(v); return v }
	r.s.snapshot = func(ctx context.Context, dest string) (storage.SnapshotStats, error) {
		n := r.running.Add(1)
		defer r.running.Add(-1)
		for m := r.most.Load(); n > m && !r.most.CompareAndSwap(m, n); m = r.most.Load() {
		}
		var id int
		_, _ = fmt.Sscanf(filepath.Base(dest), "snapshot-%d.db", &id)
		b := snap[id]
		if b.defers {
			r.s.OnCheckpoint(storage.CheckpointResult{Mode: "TRUNCATE", Trigger: storage.TriggerSize, Start: time.Now(), Deferred: true}, nil)
		}
		if b.hold != nil {
			<-b.hold
		} else {
			time.Sleep(b.d)
		}
		return storage.SnapshotStats{Pages: 1, Steps: 1, Duration: b.d}, nil
	}
	return r
}

// setWAL sets the WAL size and waits until a sample has read it (the
// sizes a test sets in a row differ). The watcher acts on it just after.
func (r *slotRig) setWAL(t *testing.T, v int64) {
	t.Helper()
	r.wal.Store(v)
	waitFor(t, fmt.Sprintf("a sample of %d bytes", v), func() bool { return r.seen.Load() == v })
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !ok(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// events closes the rig's log and checks that no two backups overlapped.
func (r *slotRig) events(t *testing.T) []Event {
	t.Helper()
	if err := r.s.ev.close(); err != nil {
		t.Fatal(err)
	}
	events, err := ReadEvents(filepath.Join(r.s.opts.OutDir, FileEvents))
	if err != nil {
		t.Fatal(err)
	}
	if m := r.most.Load(); m > 1 {
		t.Errorf("%d snapshots ran at once", m)
	}
	var spans [][2]int64
	starts := map[int]int64{}
	for _, e := range events {
		switch e.Ev {
		case EvBackupStart:
			starts[e.Backup] = e.T
		case EvBackupEnd:
			spans = append(spans, [2]int64{starts[e.Backup], e.T})
		case EvError:
			t.Errorf("server error: %s", e.Err)
		}
	}
	for i := range spans {
		for j := range i {
			if spans[i][0] <= spans[j][1] && spans[j][0] <= spans[i][1] {
				t.Errorf("backups overlapped: %v and %v", spans[j], spans[i])
			}
		}
	}
	return events
}

// The timed and the WAL-triggered backups share one slot, with real
// goroutines on both paths.
func TestBackupSlot(t *testing.T) {
	bg, far := context.Background(), time.Now().Add(time.Hour)
	wal := Backup{Phase: "p50", WALTriggered: WALTrigger{Fraction: 0.5, MaxAttempts: 3}}

	// A timed backup due while a WAL-triggered attempt runs waits for it.
	// Its snapshot defers a size trigger, which the attempt must not take
	// credit for: the watcher retries, and attempt 2 holds one off.
	t.Run("timed waits", func(t *testing.T) {
		type snap = slotSnap
		r := newSlotRig(t, map[int]snap{1: {d: 300 * time.Millisecond}, 2: {d: 50 * time.Millisecond, defers: true}, 3: {d: 50 * time.Millisecond, defers: true}})
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); r.s.walBackups(ctx, context.Background(), time.Now().Add(time.Minute), wal) }()
		r.setWAL(t, 0)
		r.setWAL(t, 600) // attempt 1 (backup 1)
		waitFor(t, "attempt 1", func() bool { return r.running.Load() == 1 })
		wg.Add(1)
		go func() { defer wg.Done(); r.s.timedBackup(bg, bg, far, Backup{Phase: "p10"}) }() // backup 2
		waitFor(t, "the timed backup", func() bool { return r.s.backups.Load() == 2 && r.running.Load() == 0 })
		r.setWAL(t, 0)
		r.setWAL(t, 700) // attempt 2 (backup 3)
		waitFor(t, "attempt 2", func() bool { return r.s.backups.Load() == 3 && r.running.Load() == 0 })
		// Attempt 2 held one off: the watcher ends on its own.
		wg.Wait()
		cancel()

		var waited, timedStart Event
		var attempts []Event
		for _, e := range r.events(t) {
			switch {
			case e.Ev == EvBackupWait:
				waited = e
			case e.Ev == EvBackupStart && e.Attempt == 0:
				timedStart = e
			case e.Ev == EvWALBackup:
				attempts = append(attempts, e)
			}
		}
		if waited.Phase != "p10" || timedStart.Backup != 2 || timedStart.WaitUs < 100_000 {
			t.Errorf("the timed backup did not wait: %+v, then %+v", waited, timedStart)
		}
		if len(attempts) != 2 || attempts[0].HeldOff || !attempts[1].HeldOff || attempts[0].Bytes != 600 || attempts[1].Backup != 3 {
			t.Errorf("WAL-triggered attempts: %+v", attempts)
		}
	})

	// A crossing while a timed backup holds the slot is skipped and logged;
	// the next crossing starts the attempt.
	t.Run("crossing skipped", func(t *testing.T) {
		type snap = slotSnap
		r := newSlotRig(t, map[int]snap{1: {d: 400 * time.Millisecond}, 2: {d: 50 * time.Millisecond, defers: true}})
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); r.s.walBackups(ctx, context.Background(), time.Now().Add(time.Minute), wal) }()
		r.setWAL(t, 0)
		go func() { defer wg.Done(); r.s.timedBackup(bg, bg, far, Backup{Phase: "p10"}) }() // backup 1
		waitFor(t, "the timed backup", func() bool { return r.running.Load() == 1 })
		r.setWAL(t, 600) // skipped
		waitFor(t, "the timed backup's end", func() bool { return r.running.Load() == 0 })
		r.setWAL(t, 0)
		r.setWAL(t, 650) // attempt 1 (backup 2)
		waitFor(t, "attempt 1", func() bool { return r.s.backups.Load() == 2 && r.running.Load() == 0 })
		// Attempt 1 held one off: the watcher ends on its own.
		wg.Wait()
		cancel()

		var skipped, attempts []Event
		for _, e := range r.events(t) {
			switch e.Ev {
			case EvWALCrossing:
				skipped = append(skipped, e)
			case EvWALBackup:
				attempts = append(attempts, e)
			case EvBackupWait:
				t.Errorf("the timed backup waited: %+v", e)
			}
		}
		if len(skipped) != 1 || skipped[0].Bytes != 600 || skipped[0].Note != "a backup was running" {
			t.Errorf("skipped crossings: %+v", skipped)
		}
		if len(attempts) != 1 || attempts[0].Attempt != 1 || attempts[0].Bytes != 650 || !attempts[0].HeldOff {
			t.Errorf("WAL-triggered attempts: %+v", attempts)
		}
	})

	// A run already stopped takes the free slot at once, and the backup
	// still does not start: it logs backup_missed and frees the slot.
	t.Run("stopped before it starts", func(t *testing.T) {
		r := newSlotRig(t, map[int]slotSnap{})
		ctx, cancel := context.WithCancel(bg)
		cancel()
		r.s.timedBackup(ctx, bg, far, Backup{Phase: "p10"})
		var missed []Event
		for _, e := range r.events(t) {
			switch e.Ev {
			case EvBackupMissed:
				missed = append(missed, e)
			case EvBackupStart, EvBackupWait:
				t.Errorf("unexpected %+v", e)
			}
		}
		if len(missed) != 1 || missed[0].Note != "the run stopped before it could start" {
			t.Errorf("missed: %+v", missed)
		}
		if r.most.Load() != 0 {
			t.Error("a snapshot ran")
		}
		if !r.s.slot.tryAcquire() {
			t.Error("the slot is still taken")
		}
	})

	// A timed backup queued behind a running one waits only until its
	// phase ends or the run stops; then it logs backup_missed and never
	// starts. The running one finishes.
	for _, c := range []struct {
		name, note string
		stop       bool
	}{
		{"phase ends while queued", "its phase ended while it waited for a running backup", false},
		{"shutdown while queued", "the run stopped while it waited for a running backup", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Backup 1 holds the slot until the test releases it, so the
			// queued backup can only give up, however the scheduler runs.
			release := make(chan struct{})
			r := newSlotRig(t, map[int]slotSnap{1: {hold: release}})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() { defer wg.Done(); r.s.timedBackup(bg, bg, far, Backup{Phase: "p10"}) }() // backup 1
			waitFor(t, "backup 1", func() bool { return r.running.Load() == 1 })
			ctx, cancel := context.WithCancel(bg)
			defer cancel()
			phaseEnd := far
			t0 := time.Now()
			if c.stop {
				time.AfterFunc(100*time.Millisecond, cancel)
			} else {
				phaseEnd = t0.Add(100 * time.Millisecond)
			}
			r.s.timedBackup(ctx, bg, phaseEnd, Backup{Phase: "p30"})
			if d := time.Since(t0); d < 100*time.Millisecond {
				t.Errorf("the queued backup gave up after %s, before its deadline of 100 ms", d)
			}
			if r.running.Load() != 1 {
				t.Error("backup 1 is no longer running")
			}
			close(release)
			wg.Wait()

			var waited, missed []Event
			starts := 0
			for _, e := range r.events(t) {
				switch e.Ev {
				case EvBackupWait:
					waited = append(waited, e)
				case EvBackupMissed:
					missed = append(missed, e)
				case EvBackupStart:
					starts++
					if e.Phase != "p10" {
						t.Errorf("the queued backup started: %+v", e)
					}
				}
			}
			if len(waited) != 1 || waited[0].Phase != "p30" || len(missed) != 1 || missed[0].Phase != "p30" || missed[0].Note != c.note || starts != 1 {
				t.Errorf("waited %+v, missed %+v, %d backups started", waited, missed, starts)
			}
			// The slot is free again.
			if !r.s.slot.tryAcquire() {
				t.Error("the slot is still taken")
			}
		})
	}
}
