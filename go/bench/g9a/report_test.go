// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeRun is the files of a run, built in memory; good() passes every
// criterion, and each case changes one thing.
type fakeRun struct {
	// k6's and the server's counts are taken from reqs unless set.
	iterations, served, refused *int
	plan                        Plan
	sys                         System
	events                      []Event
	reqs                        []Request
	dropped                     float64
	prefix                      string // what k6 may put before each request line
}

const t0 = int64(1_700_000_000_000_000) // run start, µs

func at(s float64) int64 { return t0 + int64(s*1e6) }

func good() *fakeRun {
	p := DefaultPlan()
	p.Phases = []Phase{
		{Name: "warmup", Rate: 10, Seconds: 2, Warmup: true},
		{Name: "p10", Rate: 10, Seconds: 10},
		{Name: "p50", Rate: 50, Seconds: 10},
	}
	p.Backups = []Backup{{Phase: "p50", AtSeconds: 4}} // at 16 s
	p.WALBound = 1000
	p.ConvergeEverySeconds = 10 // at 10 s and 20 s
	p.Thresholds.MemoryAfterSeconds = 1
	r := &fakeRun{plan: p}
	r.sys = System{
		Target: "varlatchd",
		Disk:   Disk{Dir: "/var/lib/varlatch", FSType: "ext4", Source: "/dev/sda1"},
		Cgroup: Cgroup{MemoryMax: "1073741824", SwapMax: "0"},
	}
	off := 0.0
	for _, ph := range p.Phases {
		for i := range int(float64(ph.Rate) * ph.Seconds) {
			r.reqs = append(r.reqs, Request{Phase: ph.Name, SchedUs: at(off + float64(i)/float64(ph.Rate)), Lat: 5 * time.Millisecond, Service: 4 * time.Millisecond, Status: 200})
		}
		off += ph.Seconds
	}
	ev := []Event{
		// Seeding, before the run: not judged.
		{T: at(-5), Ev: EvCheckpoint, Mode: "TRUNCATE", Trigger: "size", StartUs: at(-5), DurUs: 1000, LogFrames: 900, Checkpointed: 900, WALBefore: 50_000},
		{T: at(0), Ev: EvRunStart},
	}
	for s := 0; s <= 22; s++ {
		ev = append(ev, Event{T: at(float64(s)), Ev: EvWAL, Bytes: 600})
		ev = append(ev, Event{T: at(float64(s)), Ev: EvMemory, AnonBytes: 50 << 20, RSSBytes: 40 << 20, MemEvents: &MemoryEvents{Current: 200 << 20}})
		ev = append(ev, Event{T: at(float64(s)), Ev: EvCheckpoint, Mode: "PASSIVE", Trigger: "interval", StartUs: at(float64(s)), DurUs: 2000, LogFrames: 3, Checkpointed: 3, WALBefore: 600, WALAfter: 600})
	}
	for i := range 200 {
		ev = append(ev,
			Event{T: at(-3), Ev: EvFsync, StartUs: at(-3), DurUs: 1000, Kind: []string{"append", "rewrite"}[i%2], Idle: true},
			Event{T: at(float64(i) / 10), Ev: EvFsync, StartUs: at(float64(i) / 10), DurUs: 1500, Kind: []string{"append", "rewrite"}[i%2]})
	}
	ev = append(ev,
		Event{T: at(7), Ev: EvCheckpoint, Mode: "TRUNCATE", Trigger: "size", StartUs: at(7), DurUs: 30_000, LogFrames: 40, Checkpointed: 40, WALBefore: 1200},
		Event{T: at(10), Ev: EvConvergeStart},
		Event{T: at(12.5), Ev: EvConvergeEnd, Targets: 20, Values: 2500},
		Event{T: at(20), Ev: EvConvergeStart},
		Event{T: at(22.5), Ev: EvConvergeEnd, Targets: 20, Values: 2500},
		Event{T: at(16), Ev: EvBackupStart},
		Event{T: at(16.5), Ev: EvCheckpoint, Mode: "TRUNCATE", Trigger: "size", Deferred: true, StartUs: at(16.5), LogFrames: -1, Checkpointed: -1, WALBefore: 1500, WALAfter: 1500},
		Event{T: at(17.1), Ev: EvCheckpoint, Mode: "TRUNCATE", Trigger: "snapshot", StartUs: at(17), DurUs: 40_000, LogFrames: 60, Checkpointed: 60, WALBefore: 1700},
		Event{T: at(17.2), Ev: EvBackupEnd, Pages: 3000, Steps: 3, DurUs: 1_200_000},
		Event{T: at(22.9), Ev: EvMemory, Final: true, AnonBytes: 50 << 20, RSSBytes: 40 << 20, MemEvents: &MemoryEvents{Current: 200 << 20}},
		Event{T: at(23), Ev: EvRunEnd},
		// Close, after the run: not judged.
		Event{T: at(24), Ev: EvCheckpoint, Mode: "TRUNCATE", Trigger: "close", StartUs: at(24), DurUs: 1000, WALBefore: 99_999},
	)
	r.events = ev
	return r
}

func (r *fakeRun) write(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := WritePlan(filepath.Join(dir, FilePlan), r.plan); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, FileSystem), r.sys); err != nil {
		t.Fatal(err)
	}
	served, refused := 0, 0
	for _, q := range r.reqs {
		if q.Status != 0 {
			served++
			if q.Status != 200 {
				refused++
			}
		}
	}
	iterations := len(r.reqs)
	for _, o := range []struct{ to, from *int }{{&iterations, r.iterations}, {&served, r.served}, {&refused, r.refused}} {
		if o.from != nil {
			*o.to = *o.from
		}
	}
	var ev strings.Builder
	for _, e := range r.events {
		if e.Ev == EvRunEnd {
			e.Requests, e.Errors = int64(served), int64(refused)
		}
		b, _ := json.Marshal(e)
		ev.Write(append(b, '\n'))
	}
	var rq strings.Builder
	for _, q := range r.reqs {
		fmt.Fprintf(&rq, "%sR,%s,%d,%d,%d,%d,%s\n", r.prefix, q.Phase, q.SchedUs, q.Lat.Microseconds(), q.Service.Microseconds(), q.Status, q.Err)
		if r.prefix != "" {
			rq.WriteString(`time="x" level=info msg="something else"` + "\n")
		}
	}
	files := map[string]string{
		FileEvents:    ev.String(),
		FileRequests:  rq.String(),
		FileK6Summary: fmt.Sprintf(`{"dropped_iterations":{"count":%g},"iterations":{"count":%d}}`, r.dropped, iterations),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func (r *fakeRun) eventsWithout(match func(Event) bool) {
	r.events = slices.DeleteFunc(r.events, match)
}

func ptr(n int) *int { return &n }

func setMemory(r *fakeRun, f func(*Event)) {
	for i := range r.events {
		if r.events[i].Ev == EvMemory {
			m := *r.events[i].MemEvents
			r.events[i].MemEvents = &m
			f(&r.events[i])
		}
	}
}

// shortGate judges the short fake runs as if they followed G9a's profile.
func shortGate(t *testing.T) {
	saved := gatePlan
	gatePlan = func() Plan { return good().plan }
	t.Cleanup(func() { gatePlan = saved })
}

func TestReportVerdicts(t *testing.T) {
	shortGate(t)
	cases := []struct {
		name    string
		change  func(*fakeRun)
		verdict string
		want    string // in a fail or inconclusive reason
	}{
		{"good", func(*fakeRun) {}, Pass, ""},
		{"k6 log prefixes", func(r *fakeRun) { r.prefix = `time="2026-11-13T15:00:00Z" level=info msg="` }, Pass, ""},
		{"stand-in target", func(r *fakeRun) { r.sys.Target = StandInTarget }, Inconclusive, "does not pass G9a"},
		{"slow warm-up is not judged", func(r *fakeRun) {
			for i := range r.reqs {
				if r.reqs[i].Phase == "warmup" {
					r.reqs[i].Lat = time.Second
				}
			}
		}, Pass, ""},
		{"slow phase", func(r *fakeRun) {
			for i := range r.reqs {
				if r.reqs[i].Phase == "p50" {
					r.reqs[i].Lat = 150 * time.Millisecond
				}
			}
		}, Fail, "phase p50: p95 150.0 ms"},
		{"busy request", func(r *fakeRun) { r.reqs[50].Err, r.reqs[50].Status = "busy", 503 }, Fail, "1 SQLITE_BUSY"},
		{"server busy", func(r *fakeRun) {
			for i := range r.events {
				if r.events[i].Ev == EvRunEnd {
					r.events[i].BusyErrs = 2
				}
			}
		}, Fail, "SQLITE_BUSY 2 times"},
		{"dropped", func(r *fakeRun) { r.dropped = 3 }, Fail, "dropped 3"},
		{"missing requests", func(r *fakeRun) { r.reqs = slices.Delete(r.reqs, 30, 40) }, Fail, "phase p10: 90 requests in the log for 100"},
		{"one request missing", func(r *fakeRun) { r.reqs = slices.Delete(r.reqs, 30, 31) }, Fail, "phase p10: 99 requests"},
		{"one more at the phase's end", func(r *fakeRun) {
			last := r.reqs[119]
			last.SchedUs += 100_000
			r.reqs = slices.Insert(r.reqs, 120, last)
		}, Pass, ""},
		{"a lost line k6 counted", func(r *fakeRun) { r.iterations = ptr(len(r.reqs) + 1) }, Fail, "k6 completed 621 requests but the log has 620"},
		{"a refusal missing from the log", func(r *fakeRun) { r.refused = ptr(1) }, Fail, "the server answered 620 requests (1 refused); the log has 620 answered (0 refused)"},
		{"not the gate profile", func(r *fakeRun) { r.plan.WALBound, r.plan.BackupPauseMs = 2000, 50 }, Inconclusive, "differs from G9a's profile (backups, WAL bound)"},
		{"a converge run missing", func(r *fakeRun) {
			r.eventsWithout(func(e Event) bool {
				return (e.Ev == EvConvergeStart || e.Ev == EvConvergeEnd) && e.T >= at(20) && e.T < at(23)
			})
		}, Inconclusive, "1 of the plan's 2 converge runs"},
		{"a converge run over too few targets", func(r *fakeRun) {
			for i := range r.events {
				if r.events[i].Ev == EvConvergeEnd {
					r.events[i].Targets = 3
					break
				}
			}
		}, Inconclusive, "1 of the plan's 2 converge runs ran over all 20 targets"},
		{"memory.events max", func(r *fakeRun) { setMemory(r, func(e *Event) { e.MemEvents.Max = 4 }) }, Fail, "memory.events high 0, max 4"},
		{"memory.events oom_kill", func(r *fakeRun) { setMemory(r, func(e *Event) { e.MemEvents.OOMKill = 1 }) }, Fail, "oom_kill 1"},
		{"memory.events in a shared cgroup", func(r *fakeRun) {
			r.sys.Cgroup.SwapMax = "max"
			setMemory(r, func(e *Event) { e.MemEvents.High = 9 })
		}, Inconclusive, "not the server's alone"},
		{"pressure in the final reading only", func(r *fakeRun) {
			for i := range r.events {
				if r.events[i].Final {
					r.events[i].MemEvents = &MemoryEvents{Max: 1, Current: 1 << 20}
				}
			}
		}, Fail, "memory.events high 0, max 1"},
		{"no final memory reading", func(r *fakeRun) { r.eventsWithout(func(e Event) bool { return e.Final }) }, Inconclusive, "no final memory.events reading"},
		{"no memory.current", func(r *fakeRun) { setMemory(r, func(e *Event) { e.MemEvents = nil }) }, Inconclusive, "no memory.events"},
		{"unknown phase", func(r *fakeRun) { r.reqs[0].Phase = "other" }, Fail, `phase "other"`},
		{"no run end", func(r *fakeRun) { r.eventsWithout(func(e Event) bool { return e.Ev == EvRunEnd }) }, Fail, "did not finish"},
		{"server error", func(r *fakeRun) { r.events = append(r.events, Event{T: at(3), Ev: EvError, Err: "boom"}) }, Fail, "boom"},
		{"busy truncate", func(r *fakeRun) {
			for i, e := range r.events {
				if e.Trigger == "size" && !e.Deferred && e.StartUs == at(7) {
					r.events[i].Busy, r.events[i].Checkpointed, r.events[i].WALAfter = true, 20, 600
				}
			}
		}, Fail, "did not complete"},
		{"checkpoint error", func(r *fakeRun) {
			r.events = append(r.events, Event{T: at(-1), Ev: EvCheckpoint, Mode: "PASSIVE", Trigger: "interval", StartUs: at(-1), Err: "disk I/O error"})
		}, Fail, "disk I/O error"},
		{"WAL peak", func(r *fakeRun) { r.events = append(r.events, Event{T: at(9), Ev: EvWAL, Bytes: 2000}) }, Fail, "peaked at 2000"},
		{"WAL before and after the run is not judged", func(r *fakeRun) {
			r.events = append(r.events, Event{T: at(-2), Ev: EvWAL, Bytes: 9000}, Event{T: at(30), Ev: EvWAL, Bytes: 9000})
		}, Pass, ""},
		{"no size trigger", func(r *fakeRun) {
			r.eventsWithout(func(e Event) bool { return e.Trigger == "size" && !e.Deferred && e.StartUs == at(7) })
		}, Inconclusive, "size trigger was not shown"},
		{"size trigger only in warm-up", func(r *fakeRun) {
			for i, e := range r.events {
				if e.Trigger == "size" && !e.Deferred && e.StartUs == at(7) {
					r.events[i].StartUs, r.events[i].T = at(1), at(1)
				}
			}
		}, Inconclusive, "size trigger was not shown"},
		{"no backup overlapped", func(r *fakeRun) { r.eventsWithout(func(e Event) bool { return e.Deferred }) }, Inconclusive, "no backup overlapped"},
		{"deferred, then no TRUNCATE", func(r *fakeRun) { r.eventsWithout(func(e Event) bool { return e.Trigger == "snapshot" }) }, Fail, "no TRUNCATE followed"},
		{"backup missing", func(r *fakeRun) { r.plan.Backups = append(r.plan.Backups, Backup{Phase: "p10", AtSeconds: 1}) }, Inconclusive, "1 of the plan's 2 timed backups"},
		{"backup failed", func(r *fakeRun) {
			for i := range r.events {
				if r.events[i].Ev == EvBackupEnd {
					r.events[i].Err = "disk full"
				}
			}
		}, Fail, "disk full"},
		{"slow inside a TRUNCATE window", func(r *fakeRun) {
			for i, q := range r.reqs {
				if q.SchedUs >= at(16.9) && q.SchedUs <= at(17.3) {
					r.reqs[i].Lat = 300 * time.Millisecond
				}
			}
		}, Fail, "truncate-snapshot window"},
		{"memory over", func(r *fakeRun) {
			for i := range r.events {
				if r.events[i].Ev == EvMemory {
					r.events[i].AnonBytes = 400 << 20
				}
			}
		}, Fail, "400.0 MiB"},
		{"memory over in the first minute is not judged", func(r *fakeRun) {
			r.events = append(r.events, Event{T: at(0.5), Ev: EvMemory, AnonBytes: 900 << 20})
		}, Pass, ""},
		{"memory without G9 limits", func(r *fakeRun) {
			r.sys.Cgroup.MemoryMax = "max"
			for i := range r.events {
				if r.events[i].Ev == EvMemory {
					r.events[i].AnonBytes = 400 << 20
				}
			}
		}, Inconclusive, "not the server's alone"},
		{"no memory samples", func(r *fakeRun) { r.eventsWithout(func(e Event) bool { return e.Ev == EvMemory }) }, Inconclusive, "no cgroup memory"},
		{"no fsync under load", func(r *fakeRun) { r.eventsWithout(func(e Event) bool { return e.Ev == EvFsync && !e.Idle }) }, Inconclusive, "fsync distribution"},
		{"no filesystem", func(r *fakeRun) { r.sys.Disk.FSType = "" }, Inconclusive, "no filesystem"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run := good()
			c.change(run)
			rep, err := WriteReport(run.write(t))
			if err != nil {
				t.Fatal(err)
			}
			reasons := strings.Join(append(append([]string{}, rep.Fails...), rep.Missing...), "\n")
			if rep.Verdict != c.verdict || !strings.Contains(reasons, c.want) {
				t.Fatalf("verdict %s, want %s with %q; reasons:\n%s", rep.Verdict, c.verdict, c.want, reasons)
			}
			if c.verdict == Pass && (rep.SizeTruncates != 1 || rep.Deferred != 1 || rep.WALPeak != 1700) {
				t.Fatalf("size truncates %d, deferred %d, WAL peak %d", rep.SizeTruncates, rep.Deferred, rep.WALPeak)
			}
		})
	}
}

func TestReportFiles(t *testing.T) {
	shortGate(t)
	dir := good().write(t)
	rep, err := WriteReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(filepath.Join(dir, FileReport))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# G9a run: PASS", "| p50 | 50 | 10 | 500 | 500 | 0 | 0 |", "| truncate-snapshot | 17.0 |", "held TRUNCATE off 1 times", "ext4"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("report.md lacks %q:\n%s", want, md)
		}
	}
	var back Report
	b, err := os.ReadFile(filepath.Join(dir, FileVerdict))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &back); err != nil || back.Verdict != Pass || back.Fails == nil || len(back.Windows) != len(rep.Windows) {
		t.Fatalf("verdict.json: %v %+v", err, back)
	}
}

func TestPlan(t *testing.T) {
	p := DefaultPlan()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.Duration() != 36*time.Minute {
		t.Fatalf("duration %s", p.Duration())
	}
	// The 50/s backup starts from the WAL's size: its offset is its phase's
	// start, from which it watches the WAL.
	if got := p.BackupOffsets(); !slices.Equal(got, []time.Duration{8 * time.Minute, (60 + 900 + 300) * time.Second}) {
		t.Fatalf("backups at %v", got)
	}
	if w := p.Backups[1].WALTriggered; p.Backups[1].Phase != "p50" || w != (WALTrigger{Fraction: 0.95, MaxAttempts: 5}) || p.Backups[0].WALTriggered.Set() {
		t.Fatalf("backups: %+v", p.Backups)
	}
	if th := p.Backups[1].WALTriggered.Threshold(p.WALBound); th != 63753421 {
		t.Fatalf("threshold %d, want 95 %% of 64 MiB rounded up", th)
	}
	s := p.Scaled(0.01)
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.Phases[1].Seconds != 9 || s.ConvergeEverySeconds != 10 || s.IdleProbeSeconds != 5 || s.Phases[1].Rate != 10 || s.WALBound != p.WALBound {
		t.Fatalf("scaled: %+v", s)
	}
	if s.Backups[0].AtSeconds != 4.2 || s.Backups[1] != p.Backups[1] {
		t.Fatalf("scaled backups: %+v", s.Backups)
	}
	if d := p.NotGate(); len(d) != 0 {
		t.Fatalf("the default plan is not the gate: %v", d)
	}
	q := p
	q.ProbeIntervalMs, q.IdleProbeSeconds = 50, 300
	if d := q.NotGate(); len(d) != 0 {
		t.Fatalf("the fsync probe's pacing made the plan not the gate: %v", d)
	}
	q.BackupStepPages = 64
	if d := q.NotGate(); !slices.Equal(d, []string{"backups"}) {
		t.Fatalf("backup pacing: %v", d)
	}
	if d := s.NotGate(); !slices.Equal(d, []string{"phases", "backups", "converge", "thresholds"}) {
		t.Fatalf("scaled plan: %v", d)
	}
	// A gate run may raise the WAL-triggered fraction (ADR-0059 amendment
	// 4), not change the attempts or make the backup timed.
	for name, c := range map[string]struct {
		change func(*Plan)
		want   []string
	}{
		"fraction":  {func(p *Plan) { p.Backups[1].WALTriggered.Fraction = 0.98 }, nil},
		"attempts":  {func(p *Plan) { p.Backups[1].WALTriggered.MaxAttempts = 6 }, []string{"backups"}},
		"timed":     {func(p *Plan) { p.Backups[1] = Backup{Phase: "p50", AtSeconds: 450} }, []string{"backups"}},
		"no backup": {func(p *Plan) { p.Backups = p.Backups[:1] }, []string{"backups"}},
	} {
		q := DefaultPlan()
		q.Backups = slices.Clone(q.Backups)
		c.change(&q)
		if d := q.NotGate(); !slices.Equal(d, c.want) {
			t.Errorf("%s: NotGate %v, want %v", name, d, c.want)
		}
	}
	// The plan file: a timed backup has no walTriggered key.
	b, _ := json.Marshal(p.Backups)
	if want := `[{"phase":"p10","atSeconds":420},{"phase":"p50","atSeconds":0,"walTriggered":{"fraction":0.95,"maxAttempts":5}}]`; string(b) != want {
		t.Fatalf("backups as JSON: %s", b)
	}
	if n := p.Converges(); n != 35 {
		t.Fatalf("%d converge runs in the profile, want 35 (every minute, the last before the 36th)", n)
	}
	if p.Phases[1].Seconds != 900 {
		t.Fatal("Scaled changed the original")
	}
	for name, change := range map[string]func(*Plan){
		"no phases":         func(p *Plan) { p.Phases = nil },
		"all warm-up":       func(p *Plan) { p.Phases = p.Phases[:1] },
		"duplicate":         func(p *Plan) { p.Phases[2].Name = "p10" },
		"zero rate":         func(p *Plan) { p.Phases[1].Rate = 0 },
		"backup phase":      func(p *Plan) { p.Backups[0].Phase = "nope" },
		"backup past end":   func(p *Plan) { p.Backups[0].AtSeconds = 900 },
		"short idle probe":  func(p *Plan) { p.IdleProbeSeconds = 1 },
		"no bound":          func(p *Plan) { p.WALBound = 0 },
		"fraction 0":        func(p *Plan) { p.Backups[1].WALTriggered.Fraction = 0 },
		"fraction over 1":   func(p *Plan) { p.Backups[1].WALTriggered.Fraction = 1.01 },
		"fraction negative": func(p *Plan) { p.Backups[1].WALTriggered.Fraction = -0.5 },
		"fraction NaN":      func(p *Plan) { p.Backups[1].WALTriggered.Fraction = math.NaN() },
		"no attempts":       func(p *Plan) { p.Backups[1].WALTriggered.MaxAttempts = 0 },
		"WAL and offset":    func(p *Plan) { p.Backups[1].AtSeconds = 10 },
		"two WAL in a phase": func(p *Plan) {
			p.Backups = append(p.Backups, p.Backups[1])
		},
		"WAL in unknown phase": func(p *Plan) { p.Backups[1].Phase = "nope" },
	} {
		q := DefaultPlan()
		q.Phases = slices.Clone(q.Phases)
		q.Backups = slices.Clone(q.Backups)
		change(&q)
		if q.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	q = DefaultPlan()
	q.Backups[1].WALTriggered = WALTrigger{Fraction: 1, MaxAttempts: 1}
	if err := q.Validate(); err != nil {
		t.Fatalf("fraction 1, one attempt: %v", err)
	}
}

// walRun is good() with its 50/s backup started from the WAL's size: one
// attempt at 16 s that held a TRUNCATE off.
func walRun() *fakeRun {
	r := good()
	r.plan.Backups = []Backup{{Phase: "p50", WALTriggered: WALTrigger{Fraction: 0.95, MaxAttempts: 5}}}
	for i, e := range r.events {
		switch e.Ev {
		case EvBackupStart:
			r.events[i].Backup, r.events[i].Phase, r.events[i].Attempt, r.events[i].WALBefore = 1, "p50", 1, 960
		case EvBackupEnd:
			r.events[i].Backup, r.events[i].Phase, r.events[i].Attempt = 1, "p50", 1
		}
	}
	r.events = append(r.events, Event{T: at(17.3), Ev: EvWALBackup, Phase: "p50", Attempt: 1, Backup: 1, StartUs: at(16), Bytes: 960, HeldOff: true})
	return r
}

// attempt adds a WAL-triggered backup from..to that held nothing off
// (its own TRUNCATE at its end).
func (r *fakeRun) attempt(n, backup int, from, to float64) {
	r.events = append(r.events,
		Event{T: at(from), Ev: EvBackupStart, Backup: backup, Phase: "p50", Attempt: n, WALBefore: 955},
		Event{T: at(to - 0.1), Ev: EvCheckpoint, Mode: "TRUNCATE", Trigger: "snapshot", StartUs: at(to - 0.1), DurUs: 20_000, LogFrames: 10, Checkpointed: 10, WALBefore: 990},
		Event{T: at(to), Ev: EvBackupEnd, Backup: backup, Phase: "p50", Attempt: n, Pages: 3000, Steps: 3, DurUs: int64((to - from) * 1e6)},
		Event{T: at(to + 0.1), Ev: EvWALBackup, Phase: "p50", Attempt: n, Backup: backup, StartUs: at(from), Bytes: 955},
	)
}

func TestReportWALTriggered(t *testing.T) {
	saved := gatePlan
	gatePlan = func() Plan { return walRun().plan }
	t.Cleanup(func() { gatePlan = saved })
	// The held-off attempt (16 s) renumbered as the second, after one at
	// 12.5 s that held nothing off.
	second := func(r *fakeRun) {
		for i, e := range r.events {
			if e.Attempt == 1 {
				r.events[i].Attempt, r.events[i].Backup = 2, 2
			}
		}
		r.attempt(1, 1, 12.5, 13.5)
	}
	cases := []struct {
		name    string
		change  func(*fakeRun)
		verdict string
		want    string // in a fail, inconclusive or note
		heldBy  int
		tries   int
	}{
		{"held off at the first attempt", func(*fakeRun) {}, Pass, "", 1, 1},
		{"held off at the second", second, Pass, "", 2, 2},
		{"none held one off", func(r *fakeRun) {
			r.eventsWithout(func(e Event) bool { return e.Deferred })
			for i, e := range r.events {
				if e.Ev == EvWALBackup {
					r.events[i].HeldOff = false
				}
			}
			r.attempt(2, 2, 19, 20)
		}, Inconclusive, "the WAL-triggered backup in phase p50 held no size-triggered TRUNCATE off in 2 of 5 attempts at 95 % of the bound", 0, 2},
		{"never started", func(r *fakeRun) {
			r.eventsWithout(func(e Event) bool {
				return e.Ev == EvBackupStart || e.Ev == EvBackupEnd || e.Ev == EvWALBackup || e.Deferred || e.Trigger == "snapshot"
			})
		}, Inconclusive, "the WAL-triggered backup in phase p50 never started: the WAL did not cross 95 % of the bound (950 bytes)", 0, 0},
		{"never started, so nothing overlapped", func(r *fakeRun) {
			r.eventsWithout(func(e Event) bool {
				return e.Ev == EvBackupStart || e.Ev == EvBackupEnd || e.Ev == EvWALBackup || e.Deferred || e.Trigger == "snapshot"
			})
		}, Inconclusive, "no backup overlapped the bound", 0, 0},
		// Attempt 1 ends at 15.8 s, attempt 2 starts at 16 s and defers a
		// size trigger at 16.5 s, inside attempt 1's padded window: only
		// attempt 2 gets the credit, and starting it was right.
		{"back-to-back attempts", func(r *fakeRun) {
			for i, e := range r.events {
				if e.Attempt == 1 {
					r.events[i].Attempt, r.events[i].Backup = 2, 2
				}
			}
			r.attempt(1, 1, 14.8, 15.8)
		}, Pass, "", 2, 2},
		// A deferral stamped after its backup's end belongs to none.
		{"a deferral outside every backup", func(r *fakeRun) {
			for i, e := range r.events {
				if e.Deferred {
					r.events[i].StartUs, r.events[i].T = at(17.3), at(17.3)
				}
				if e.Ev == EvWALBackup {
					r.events[i].HeldOff = false
				}
			}
		}, Inconclusive, "a size trigger deferred at +17.3s fell outside every backup's interval", 0, 1},
		{"more attempts than the plan's", func(r *fakeRun) {
			second(r)
			r.plan.Backups[0].WALTriggered.MaxAttempts = 1
		}, Fail, "phase p50: 2 WAL-triggered backups, over the plan's 1 attempts", 2, 2},
		{"an attempt after one held off", func(r *fakeRun) { r.attempt(2, 2, 19, 20) }, Fail, "started after attempt 1 had held a TRUNCATE off", 1, 2},
		{"a raised fraction is a gate run", func(r *fakeRun) { r.plan.Backups[0].WALTriggered.Fraction = 0.99 }, Pass, "started at 99 % of the bound, not G9a's default 95 %", 1, 1},
		{"the server disagrees", func(r *fakeRun) {
			for i, e := range r.events {
				if e.Ev == EvWALBackup {
					r.events[i].HeldOff = false
				}
			}
		}, Pass, "the server counted held off false, the checkpoint log true", 1, 1},
		{"a slow WAL-triggered backup window", func(r *fakeRun) {
			for i, q := range r.reqs {
				if q.SchedUs >= at(15.2) && q.SchedUs <= at(15.8) {
					r.reqs[i].Lat = 300 * time.Millisecond
				}
			}
		}, Fail, "backup window at +16.0s", 1, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run := walRun()
			c.change(run)
			rep, err := WriteReport(run.write(t))
			if err != nil {
				t.Fatal(err)
			}
			reasons := strings.Join(slices.Concat(rep.Fails, rep.Missing, rep.Notes), "\n")
			if rep.Verdict != c.verdict || !strings.Contains(reasons, c.want) {
				t.Fatalf("verdict %s, want %s with %q; reasons:\n%s", rep.Verdict, c.verdict, c.want, reasons)
			}
			if len(rep.WALBackups) != 1 {
				t.Fatalf("WAL-triggered backups: %+v", rep.WALBackups)
			}
			w := rep.WALBackups[0]
			if w.HeldOffBy != c.heldBy || len(w.Attempts) != c.tries || w.ThresholdBytes != int64(math.Ceil(w.Fraction*1000)) {
				t.Fatalf("held off by %d of %d attempts (threshold %d), want %d of %d", w.HeldOffBy, len(w.Attempts), w.ThresholdBytes, c.heldBy, c.tries)
			}
			if rep.TimedBackups != 0 || rep.Backups != c.tries {
				t.Fatalf("%d backups, %d timed", rep.Backups, rep.TimedBackups)
			}
		})
	}

	// The report names the attempt and the WAL size that started it.
	dir := walRun().write(t)
	rep, err := WriteReport(dir)
	if err != nil || rep.Verdict != Pass {
		t.Fatalf("%v %+v", err, rep)
	}
	if a := rep.WALBackups[0].Attempts[0]; a.WALBytes != 960 || a.Deferred != 1 || !a.HeldOff || a.Offset != 16 || math.Abs(a.Seconds-1.2) > 1e-5 {
		t.Fatalf("attempt: %+v", a)
	}
	md, _ := os.ReadFile(filepath.Join(dir, FileReport))
	for _, want := range []string{"## WAL-triggered backups", "Phase p50: at 95 % of the bound (950 bytes), up to 5 attempts; 1 made, attempt 1 held a size-triggered TRUNCATE off.",
		"| 1 | 16.0 | 960 | 1.2 | 1 | true |", "WAL-triggered, attempt 1 of 5 at 95 % of the bound (WAL 960 bytes); held TRUNCATE off 1 times"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("report.md lacks %q:\n%s", want, md)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, FileVerdict))
	var back struct {
		WAL []WALBackupResult `json:"walTriggeredBackups"`
	}
	if err := json.Unmarshal(b, &back); err != nil || len(back.WAL) != 1 || back.WAL[0].HeldOffBy != 1 {
		t.Fatalf("verdict.json: %v %s", err, b)
	}
}

// The timed backup overlaps the bound and the WAL-triggered attempts hold
// nothing off: the run as a whole showed an overlap, but the WAL-triggered
// schedule did not, and that alone leaves it inconclusive (amendment 4).
func TestReportWALTriggeredJudgedAlone(t *testing.T) {
	run := walRun()
	run.plan.Backups = []Backup{{Phase: "p10", AtSeconds: 3}, run.plan.Backups[0]}
	saved := gatePlan
	gatePlan = func() Plan { return run.plan }
	t.Cleanup(func() { gatePlan = saved })
	for i, e := range run.events {
		switch {
		case e.Deferred: // now the timed backup's, at 5.5 s
			run.events[i].StartUs, run.events[i].T = at(5.5), at(5.5)
		case e.Ev == EvWALBackup:
			run.events[i].HeldOff = false
		}
	}
	run.events = append(run.events,
		Event{T: at(5), Ev: EvBackupStart, Backup: 3, Phase: "p10", WALBefore: 900},
		Event{T: at(6.3), Ev: EvCheckpoint, Mode: "TRUNCATE", Trigger: "snapshot", StartUs: at(6.3), DurUs: 20_000, LogFrames: 10, Checkpointed: 10, WALBefore: 1100},
		Event{T: at(6.4), Ev: EvBackupEnd, Backup: 3, Phase: "p10", Pages: 3000, Steps: 3, DurUs: 1_400_000},
	)
	rep, err := WriteReport(run.write(t))
	if err != nil {
		t.Fatal(err)
	}
	reasons := strings.Join(slices.Concat(rep.Fails, rep.Missing), "\n")
	want := "the WAL-triggered backup in phase p50 held no size-triggered TRUNCATE off in 1 of 5 attempts at 95 % of the bound"
	if rep.Verdict != Inconclusive || len(rep.Missing) != 1 || !strings.Contains(reasons, want) {
		t.Fatalf("verdict %s, want inconclusive with only %q; reasons:\n%s", rep.Verdict, want, reasons)
	}
	if rep.Deferred != 1 || rep.TimedBackups != 1 || rep.WALBackups[0].HeldOffBy != 0 {
		t.Fatalf("deferred %d, timed %d, WAL %+v", rep.Deferred, rep.TimedBackups, rep.WALBackups)
	}
	var timed Window
	for _, w := range rep.Windows {
		if w.Kind == "backup" && w.Attempt == 0 {
			timed = w
		}
	}
	if !strings.Contains(timed.Note, "held TRUNCATE off 1 times") {
		t.Fatalf("the timed backup did not overlap: %+v", timed)
	}
}

func TestWALWatch(t *testing.T) {
	w := newWALWatch(WALTrigger{Fraction: 0.95, MaxAttempts: 3}, 1000)
	// slotTaken: another backup holds the slot, so the caller cannot use
	// the crossing.
	type step struct {
		size               int64
		crossed, slotTaken bool
	}
	run := func(steps ...step) {
		t.Helper()
		for i, s := range steps {
			if c := w.observe(s.size); c != s.crossed {
				t.Fatalf("step %d (%d bytes): crossed %v", i, s.size, c)
			}
			if s.crossed && !s.slotTaken {
				w.started()
			}
		}
	}
	run(
		step{size: 980},                // over the threshold from the start: not a crossing
		step{size: 999},                //
		step{size: 0},                  // reset
		step{size: 949},                // under 950 (95 % of 1000)
		step{size: 950, crossed: true}, // at it, from below: attempt 1
		step{size: 1500},               // still over: no new crossing
	)
	if w.attempts != 1 || w.done() {
		t.Fatalf("after attempt 1: %+v", w)
	}
	w.finished(false)
	run(
		step{size: 0}, // the snapshot's TRUNCATE reset the WAL
		step{size: 960, crossed: true, slotTaken: true}, // another backup runs: no attempt
		step{size: 970}, // and no retry until the next crossing
		step{size: 10},
		step{size: 951, crossed: true}, // attempt 2
	)
	w.finished(true)
	if !w.done() || w.attempts != 2 {
		t.Fatalf("held off at attempt 2: %+v", w)
	}
	run(step{size: 0}, step{size: 999}) // done: no more attempts

	// The cap: no attempt holds one off.
	w = newWALWatch(WALTrigger{Fraction: 0.5, MaxAttempts: 2}, 1000)
	for i := range 2 {
		run(step{size: 0}, step{size: 500, crossed: true})
		if w.attempts != i+1 {
			t.Fatalf("attempt %d: %+v", i+1, w)
		}
		w.finished(false)
	}
	if !w.done() {
		t.Fatal("not done after the last attempt")
	}
	run(step{size: 0}, step{size: 600})
}

func TestCPUStat(t *testing.T) {
	c, err := parseCPUStat("usage_usec 5000000\nuser_usec 4000000\nsystem_usec 1000000\nnr_periods 120\nnr_throttled 7\nthrottled_usec 350000\nnr_bursts 0\nburst_usec 0\n")
	if err != nil || c != (CPUStat{UsageUs: 5_000_000, NrPeriods: 120, NrThrottled: 7, ThrottledUs: 350_000, Throttling: true}) {
		t.Fatalf("%v %+v", err, c)
	}
	// Without the cpu controller cpu.stat has the usage only.
	c, err = parseCPUStat("usage_usec 5000000\nuser_usec 4000000\nsystem_usec 1000000\n")
	if err != nil || c != (CPUStat{UsageUs: 5_000_000}) {
		t.Fatalf("usage only: %v %+v", err, c)
	}
	for _, bad := range []string{"", "something 1\n", "nr_periods x\nnr_throttled 1\nthrottled_usec 1\n"} {
		if _, err := parseCPUStat(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
	for in, want := range map[string]string{
		"100000 100000": "1.00 CPU (cpu.max \"100000 100000\")",
		"50000 100000":  "0.50 CPU",
		"max 100000":    "no limit (cpu.max \"max 100000\")",
		"":              "not recorded",
		"odd":           `cpu.max "odd"`,
	} {
		if got := cpuLimit(in); !strings.HasPrefix(got, want) {
			t.Errorf("cpuLimit(%q) = %q, want %q", in, got, want)
		}
	}
}

// cpuSamples puts cpu.stat in good()'s WAL samples (one a second): one
// period of 100 ms every 100 ms, throttled for 20 ms in each period of the
// second that starts at each of throttledAt.
func cpuSamples(r *fakeRun, throttledAt ...float64) {
	var throttled, us int64
	for i, e := range r.events {
		if e.Ev != EvWAL {
			continue
		}
		s := float64(e.T-t0) / 1e6
		if slices.Contains(throttledAt, s-1) {
			throttled, us = throttled+10, us+200_000
		}
		r.events[i].CPU = &CPUStat{UsageUs: int64(s * 1e6), NrPeriods: int64(s * 10), NrThrottled: throttled, ThrottledUs: 1_000_000 + us, Throttling: true}
	}
}

func TestReportCPU(t *testing.T) {
	shortGate(t)
	run := good()
	run.sys.Cgroup.CPUMax = "100000 100000"
	cpuSamples(run, 3, 16) // throttled in 3..4 s and 16..17 s
	rep, err := WriteReport(run.write(t))
	if err != nil || rep.Verdict != Pass {
		t.Fatalf("%v %+v", err, rep)
	}
	c := rep.CPU
	if c.Samples != 23 || c.Periods != 220 || c.Throttled != 20 || c.ThrottledMs != 400 || c.ThrottledBeforeMs != 1000 || !strings.HasPrefix(c.Limit, "1.00 CPU") || c.Note != "" {
		t.Fatalf("cpu: %+v", c)
	}
	for _, w := range rep.Windows {
		var want CPUWindow
		switch w.Kind {
		case "truncate-size": // 6..8.03 s: between the samples at 6 and 9
			want = CPUWindow{Periods: 30, FromOffset: 6, ToOffset: 9}
		case "truncate-snapshot": // 16..18.04 s: 16 to 19, with 16..17's throttling
			want = CPUWindow{Periods: 30, Throttled: 10, ThrottledMs: 200, FromOffset: 16, ToOffset: 19}
		case "backup": // 15..18.2 s
			want = CPUWindow{Periods: 40, Throttled: 10, ThrottledMs: 200, FromOffset: 15, ToOffset: 19}
		}
		if w.CPU == nil || *w.CPU != want {
			t.Errorf("%s window at %.1f: cpu %+v, want %+v", w.Kind, w.Offset, w.CPU, want)
		}
	}
	md := rep.Markdown()
	for _, want := range []string{"## CPU", "Limit: 1.00 CPU", "20 of 220 periods throttled, 400.0 ms throttled; 1000.0 ms throttled before the first sample",
		"| truncate-snapshot | 17.0 |", "| 10 of 30 | 200.0 | 16.0 to 19.0 |"} {
		if !strings.Contains(md, want) {
			t.Errorf("report.md lacks %q:\n%s", want, md)
		}
	}

	// Without throttling counters, without samples, without a limit.
	for name, c := range map[string]struct {
		change func(*fakeRun)
		note   string
		limit  string
	}{
		"no cpu controller": {func(r *fakeRun) {
			for i := range r.events {
				if r.events[i].Ev == EvWAL {
					r.events[i].CPU = &CPUStat{UsageUs: 1}
				}
			}
		}, "no throttling counters", "not recorded"},
		"no samples": {func(r *fakeRun) { r.sys.Cgroup.CPUNote = "cgroups are Linux only" }, "no cpu.stat samples (cgroups are Linux only)", "not recorded"},
		"no limit":   {func(r *fakeRun) { cpuSamples(r); r.sys.Cgroup.CPUMax = "max 100000" }, "", "no limit"},
	} {
		run := good()
		c.change(run)
		rep, err := WriteReport(run.write(t))
		if err != nil || rep.Verdict != Pass {
			t.Fatalf("%s: %v %+v", name, err, rep)
		}
		if !strings.Contains(rep.CPU.Note, c.note) || (c.note == "") != (rep.CPU.Note == "") || !strings.HasPrefix(rep.CPU.Limit, c.limit) {
			t.Errorf("%s: cpu %+v", name, rep.CPU)
		}
		for _, w := range rep.Windows {
			if (w.CPU != nil) != (c.note == "") {
				t.Errorf("%s: %s window cpu %+v", name, w.Kind, w.CPU)
			}
		}
	}
}
