// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"encoding/json"
	"fmt"
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
		{"backup missing", func(r *fakeRun) { r.plan.Backups = append(r.plan.Backups, Backup{Phase: "p10", AtSeconds: 1}) }, Inconclusive, "1 of the plan's 2 backups"},
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
	if got := p.BackupOffsets(); !slices.Equal(got, []time.Duration{8 * time.Minute, (60 + 900 + 300 + 450) * time.Second}) {
		t.Fatalf("backups at %v", got)
	}
	s := p.Scaled(0.01)
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.Phases[1].Seconds != 9 || s.ConvergeEverySeconds != 10 || s.IdleProbeSeconds != 5 || s.Phases[1].Rate != 10 || s.WALBound != p.WALBound {
		t.Fatalf("scaled: %+v", s)
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
	if n := p.Converges(); n != 35 {
		t.Fatalf("%d converge runs in the profile, want 35 (every minute, the last before the 36th)", n)
	}
	if p.Phases[1].Seconds != 900 {
		t.Fatal("Scaled changed the original")
	}
	for name, change := range map[string]func(*Plan){
		"no phases":        func(p *Plan) { p.Phases = nil },
		"all warm-up":      func(p *Plan) { p.Phases = p.Phases[:1] },
		"duplicate":        func(p *Plan) { p.Phases[2].Name = "p10" },
		"zero rate":        func(p *Plan) { p.Phases[1].Rate = 0 },
		"backup phase":     func(p *Plan) { p.Backups[0].Phase = "nope" },
		"backup past end":  func(p *Plan) { p.Backups[0].AtSeconds = 900 },
		"short idle probe": func(p *Plan) { p.IdleProbeSeconds = 1 },
		"no bound":         func(p *Plan) { p.WALBound = 0 },
	} {
		q := DefaultPlan()
		q.Phases = slices.Clone(q.Phases)
		change(&q)
		if q.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
