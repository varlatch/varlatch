// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
)

// The server end to end, without k6: seed, a handful of retrievals (one
// denied), converge runs, a timed backup and a WAL-triggered one, then the
// event log and the files.
func TestServe(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds W1 and probes the disk for a few seconds")
	}
	p := DefaultPlan()
	p.Phases = []Phase{{Name: "warmup", Rate: 1, Seconds: 1, Warmup: true}, {Name: "p", Rate: 1, Seconds: 5}}
	// The converge runs write past the small bound, so the WAL crosses
	// half of it from below after the timed backup's TRUNCATE.
	p.Backups = []Backup{{Phase: "p", AtSeconds: 1}, {Phase: "p", WALTriggered: WALTrigger{Fraction: 0.5, MaxAttempts: 2}}}
	// 2.5 s: under load a converge run can take more than 1.5 s, and the next
	// one is then refused ("previous converge still running").
	p.ConvergeEverySeconds = 2.5
	p.Targets = 3
	p.IdleProbeSeconds = 3
	p.WALBound = 64 << 10
	out, data := t.TempDir(), t.TempDir()

	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), ServeOptions{DataDir: data, OutDir: out, Plan: p, Listen: "127.0.0.1:0", Ready: func(a string) { ready <- a }, Tail: time.Minute})
	}()
	var base string
	select {
	case a := <-ready:
		base = "http://" + a
	case err := <-done:
		t.Fatal(err)
	case <-time.After(2 * time.Minute):
		t.Fatal("not ready")
	}

	var manifest []Credential
	b, err := os.ReadFile(filepath.Join(out, FileManifest))
	if err != nil {
		t.Fatal(err)
	}
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
	if err := json.Unmarshal(b, &manifest); err != nil || len(manifest) != 3*w1SecretsPerEnv {
		t.Fatalf("manifest: %v, %d entries", err, len(manifest))
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
	get := func(c Credential) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", base+"/v1/retrieve/"+c.Env+"/"+c.Key, nil)
		req.Header.Set("Authorization", "Bearer "+c.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	post("/run/start", 200)
	post("/run/start", 409)
	for i := range 20 {
		if code, body := get(manifest[i*17%len(manifest)]); code != 200 || !strings.Contains(body, `"value":"`) {
			t.Fatalf("retrieval: %d %s", code, body)
		}
	}
	bad := manifest[0]
	bad.Token = "vl_g9a_wrong"
	if code, _ := get(bad); code != 403 {
		t.Fatalf("a wrong token: %d", code)
	}
	time.Sleep(5 * time.Second) // converge runs and the backups
	post("/run/stop", 200)
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	events, err := ReadEvents(filepath.Join(out, FileEvents))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	var end Event
	starts := map[int]Event{}
	var attempts []Event
	for _, e := range events {
		if e.Ev == EvBackupStart {
			// A timed backup may start just after an attempt's TRUNCATE
			// reset the WAL, so only an attempt's size is checked (below).
			if _, dup := starts[e.Backup]; dup || e.Backup == 0 {
				t.Errorf("backup_start: %+v", e)
			}
			starts[e.Backup] = e
		}
		if e.Ev == EvWALBackup {
			attempts = append(attempts, e)
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
		if e.Ev == EvConvergeEnd && e.Err != "" {
			t.Errorf("converge: %s", e.Err)
		}
		if e.Ev == EvBackupEnd && (e.Err != "" || e.Pages == 0) {
			t.Errorf("backup: %+v", e)
		}
		if e.Ev == EvError {
			t.Errorf("server error: %s", e.Err)
		}
		if e.Ev == EvRunEnd {
			end = e
		}
	}
	for _, want := range []string{EvRunStart, EvRunEnd, EvWAL, EvMemory, EvBackupStart, EvBackupEnd, EvConvergeEnd,
		"checkpoint interval", "checkpoint snapshot", "checkpoint close", "fsync idle", "memory final"} {
		if seen[want] == 0 {
			t.Errorf("no %s event (saw %v)", want, seen)
		}
	}
	if end.Requests != 21 || end.Errors != 1 || end.BusyErrs != 0 {
		t.Errorf("run_end: %+v", end)
	}
	// Every WAL-triggered attempt: numbered in order, started at or over
	// half the bound, logged at its start with the same WAL size, and none
	// after one held a TRUNCATE off.
	if len(attempts) == 0 || len(attempts) > 2 {
		t.Errorf("%d WAL-triggered attempts, want 1 or 2 (events %v)", len(attempts), seen)
	}
	for i, a := range attempts {
		st := starts[a.Backup]
		if a.Attempt != i+1 || a.Phase != "p" || a.Bytes < 32<<10 || st.Attempt != a.Attempt || st.Phase != "p" || st.WALBefore != a.Bytes || a.StartUs != st.T {
			t.Errorf("attempt %d: %+v, its start %+v", i+1, a, st)
		}
		if a.HeldOff && i != len(attempts)-1 {
			t.Errorf("an attempt after attempt %d, which held a TRUNCATE off", a.Attempt)
		}
	}
	var sys System
	b, _ = os.ReadFile(filepath.Join(out, FileSystem))
	if err := json.Unmarshal(b, &sys); err != nil || sys.Target != StandInTarget || sys.IdleSync == "" {
		t.Fatalf("system.json: %v %+v", err, sys)
	}
	if left, err := os.ReadDir(filepath.Join(data, "backups")); err != nil || len(left) != 0 {
		t.Errorf("backup snapshots kept: %v %v", err, left)
	}
	// The plan a remote k6 fetches carries the WAL-triggered backup.
	if b, _ := os.ReadFile(filepath.Join(out, FilePlan)); !strings.Contains(string(b), `"walTriggered": {`) {
		t.Errorf("plan.json: %s", b)
	}

	// A second run into the same directories is refused.
	err = Serve(context.Background(), ServeOptions{DataDir: data, OutDir: t.TempDir(), Plan: p, Listen: "127.0.0.1:0"})
	if err == nil || !strings.Contains(err.Error(), "fresh database") {
		t.Fatalf("reused database: %v", err)
	}
}

// slotRig is a server with the backup scheduling of a run but a fake
// database: the WAL size is set by the test, and each snapshot (by backup
// number) sleeps and may report a size trigger it deferred, while the rig
// counts how many run at once.
type slotRig struct {
	s       *server
	wal     atomic.Int64
	seen    atomic.Int64 // the last size a sample read
	running atomic.Int32
	most    atomic.Int32
}

func newSlotRig(t *testing.T, snap map[int]struct {
	d      time.Duration
	defers bool
}) *slotRig {
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
	r.s = &server{opts: ServeOptions{DataDir: t.TempDir(), OutDir: out, Plan: p}, ev: ev, slot: newBackupSlot()}
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
			r.s.onCheckpoint(storage.CheckpointResult{Mode: "TRUNCATE", Trigger: storage.TriggerSize, Start: time.Now(), Deferred: true}, nil)
		}
		time.Sleep(b.d)
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
	if m := r.most.Load(); m != 1 {
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
		type snap = struct {
			d      time.Duration
			defers bool
		}
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
		type snap = struct {
			d      time.Duration
			defers bool
		}
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
			type snap = struct {
				d      time.Duration
				defers bool
			}
			r := newSlotRig(t, map[int]snap{1: {d: 600 * time.Millisecond}})
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
			if d := time.Since(t0); d < 100*time.Millisecond || d > 450*time.Millisecond {
				t.Errorf("the queued backup gave up after %s, want 100 ms (backup 1 runs 600 ms)", d)
			}
			if r.running.Load() != 1 {
				t.Error("backup 1 is no longer running")
			}
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
