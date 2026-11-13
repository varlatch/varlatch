// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"bufio"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Verdicts. A run fails when it shows a threshold broken; it is
// inconclusive when it did not show what G9a requires (the size trigger, a
// backup overlapping it, the memory limits) or ran against the stand-in.
const (
	Pass         = "pass"
	Fail         = "fail"
	Inconclusive = "inconclusive"
)

// Request is one line of requests.log, written by k6/g9a.js: latency is
// counted from the request's scheduled start.
type Request struct {
	Phase   string
	SchedUs int64
	Lat     time.Duration
	Service time.Duration
	Status  int
	Err     string // "", "busy", "transport" or "http_<status>"
}

// Stats are latency percentiles (nearest rank).
type Stats struct {
	N                  int        `json:"n"`
	Failed             int        `json:"failed"`
	P50, P95, P99, Max float64    `json:"-"`
	Ms                 [4]float64 `json:"p50_p95_p99_maxMs"`
}

func stats(reqs []Request) Stats {
	s := Stats{N: len(reqs)}
	lat := make([]float64, 0, len(reqs))
	for _, r := range reqs {
		if r.Err != "" {
			s.Failed++
		}
		lat = append(lat, float64(r.Lat.Microseconds())/1000)
	}
	slices.Sort(lat)
	s.P50, s.P95, s.P99 = rank(lat, 50), rank(lat, 95), rank(lat, 99)
	if len(lat) > 0 {
		s.Max = lat[len(lat)-1]
	}
	s.Ms = [4]float64{s.P50, s.P95, s.P99, s.Max}
	return s
}

func rank(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	return sorted[max(0, min(len(sorted)-1, i))]
}

// PhaseResult is one phase of the plan.
type PhaseResult struct {
	Phase
	Expected int   `json:"expected"`
	Busy     int   `json:"busy"`
	Stats    Stats `json:"stats"`
}

// Window is a TRUNCATE checkpoint or a backup, widened by the plan's pad,
// and the retrievals scheduled inside it.
type Window struct {
	Kind    string  `json:"kind"` // "truncate-size", "truncate-snapshot", "backup"
	StartUs int64   `json:"startUs"`
	EndUs   int64   `json:"endUs"`
	Offset  float64 `json:"offsetSeconds"` // from the run's start
	Note    string  `json:"note,omitempty"`
	Stats   Stats   `json:"stats"`
}

// Report is everything a run showed and the verdict.
type Report struct {
	Dir     string        `json:"dir"`
	Verdict string        `json:"verdict"`
	Fails   []string      `json:"fails"`
	Missing []string      `json:"inconclusive"`
	Notes   []string      `json:"notes"`
	Plan    Plan          `json:"plan"`
	System  System        `json:"system"`
	Phases  []PhaseResult `json:"phases"`
	Windows []Window      `json:"windows"`

	WALPeak       int64   `json:"walPeakBytes"`
	SizeTruncates int     `json:"sizeTruncates"`
	Deferred      int     `json:"deferredTruncates"`
	Passives      int     `json:"passiveCheckpoints"`
	MaxPassiveMs  float64 `json:"maxPassiveMs"`

	Converges      int          `json:"converges"`
	ConvergesWant  int          `json:"convergesPlanned"`
	MemoryEvents   MemoryEvents `json:"memoryEvents"`
	CurrentMaxMiB  float64      `json:"memoryCurrentMaxMiB"`
	ConvergeMs     Stats        `json:"convergeDurations"`
	Backups        int          `json:"backups"`
	MemoryMaxMiB   float64      `json:"memoryMaxMiB"`
	RSSMaxMiB      float64      `json:"rssMaxMiB"`
	FsyncIdle      []string     `json:"fsyncIdle"`
	FsyncUnderLoad []string     `json:"fsyncUnderLoad"`
	Dropped        float64      `json:"droppedIterations"`
	ServerBusy     int64        `json:"serverBusy"`
}

func (r *Report) fail(format string, args ...any) {
	r.Fails = append(r.Fails, fmt.Sprintf(format, args...))
}
func (r *Report) missing(format string, args ...any) {
	r.Missing = append(r.Missing, fmt.Sprintf(format, args...))
}
func (r *Report) note(format string, args ...any) {
	r.Notes = append(r.Notes, fmt.Sprintf(format, args...))
}

// ReadRequests reads requests.log. k6 may prefix console lines with log
// fields, so a request is found by its "R," marker.
func ReadRequests(path string) ([]Request, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Request
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		i := strings.Index(line, "R,")
		if i < 0 || (i > 0 && line[i-1] != '"' && line[i-1] != ' ') {
			continue
		}
		rec := strings.TrimRight(line[i+2:], `" `)
		p := strings.Split(rec, ",")
		if len(p) != 6 {
			return nil, fmt.Errorf("%s:%d: %d fields in %q", path, n, len(p), rec)
		}
		var r Request
		var lat, svc int64
		var errs []error
		r.Phase = p[0]
		r.SchedUs, err = strconv.ParseInt(p[1], 10, 64)
		errs = append(errs, err)
		lat, err = strconv.ParseInt(p[2], 10, 64)
		errs = append(errs, err)
		svc, err = strconv.ParseInt(p[3], 10, 64)
		errs = append(errs, err)
		r.Status, err = strconv.Atoi(p[4])
		errs = append(errs, err)
		if err := errors.Join(errs...); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		r.Lat, r.Service, r.Err = time.Duration(lat)*time.Microsecond, time.Duration(svc)*time.Microsecond, p[5]
		out = append(out, r)
	}
	return out, sc.Err()
}

// k6Summary is the part of k6's end-of-test summary the report uses.
type k6Summary struct {
	Dropped *struct {
		Count float64 `json:"count"`
	} `json:"dropped_iterations"`
	Iterations *struct {
		Count float64 `json:"count"`
	} `json:"iterations"`
}

// Analyze judges the run in dir.
func Analyze(dir string) (*Report, error) {
	r := &Report{Dir: dir}
	var err error
	if r.Plan, err = ReadPlan(filepath.Join(dir, FilePlan)); err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(filepath.Join(dir, FileSystem)); err != nil {
		return nil, err
	} else if err := json.Unmarshal(b, &r.System); err != nil {
		return nil, fmt.Errorf("%s: %w", FileSystem, err)
	}
	events, err := ReadEvents(filepath.Join(dir, FileEvents))
	if err != nil {
		return nil, err
	}
	reqs, err := ReadRequests(filepath.Join(dir, FileRequests))
	if err != nil {
		return nil, err
	}
	var sum k6Summary
	if b, err := os.ReadFile(filepath.Join(dir, FileK6Summary)); err != nil {
		return nil, err
	} else if err := json.Unmarshal(b, &sum); err != nil {
		return nil, fmt.Errorf("%s: %w", FileK6Summary, err)
	}
	r.analyze(events, reqs, sum)
	return r, nil
}

func (r *Report) analyze(events []Event, reqs []Request, sum k6Summary) {
	p := r.Plan
	th := p.Thresholds
	if r.System.Target != "varlatchd" {
		r.missing("the load ran against %s: a run of the stand-in does not pass G9a (ADR-0059, Order)", r.System.Target)
	}
	if d := p.NotGate(); len(d) > 0 {
		r.missing("the plan differs from G9a's profile (%s): a diagnostic run, not the gate", strings.Join(d, ", "))
	}

	var start, end int64
	var runEnd *Event
	for i, e := range events {
		switch e.Ev {
		case EvRunStart:
			start = e.T
		case EvRunEnd:
			runEnd = &events[i]
			end = e.T
		case EvError:
			r.fail("the server reported: %s", e.Err)
		}
	}
	if start == 0 || runEnd == nil {
		r.fail("the event log has no run_start or no run_end: the run did not finish")
		r.finish()
		return
	}
	loadEnd := start + p.Duration().Microseconds()

	// Phases: every request present, none failed, p95 under the threshold.
	byPhase := map[string][]Request{}
	for _, q := range reqs {
		byPhase[q.Phase] = append(byPhase[q.Phase], q)
	}
	for _, ph := range p.Phases {
		pr := PhaseResult{Phase: ph, Expected: int(math.Round(float64(ph.Rate) * ph.Seconds)), Stats: stats(byPhase[ph.Name])}
		for _, q := range byPhase[ph.Name] {
			if q.Err == "busy" {
				pr.Busy++
			}
		}
		delete(byPhase, ph.Name)
		r.Phases = append(r.Phases, pr)
		if ph.Warmup {
			continue
		}
		// k6 starts rate × duration iterations, or one more when the last
		// falls on the phase's end.
		if pr.Stats.N < pr.Expected || pr.Stats.N > pr.Expected+1 {
			r.fail("phase %s: %d requests in the log for %d scheduled", ph.Name, pr.Stats.N, pr.Expected)
		}
		if pr.Stats.Failed > 0 {
			r.fail("phase %s: %d failed requests (%d SQLITE_BUSY)", ph.Name, pr.Stats.Failed, pr.Busy)
		}
		if pr.Stats.P95 > th.P95Ms {
			r.fail("phase %s: p95 %.1f ms over %.0f ms", ph.Name, pr.Stats.P95, th.P95Ms)
		}
	}
	for name, qs := range byPhase {
		r.fail("%d requests from phase %q, which the plan does not have", len(qs), name)
	}
	if sum.Dropped != nil {
		r.Dropped = sum.Dropped.Count
	}
	if r.Dropped > 0 {
		r.fail("k6 dropped %.0f requests (not sent on time)", r.Dropped)
	}
	// The log, k6 and the server must agree on every request.
	answered, refused := 0, 0
	for _, q := range reqs {
		if q.Status != 0 {
			answered++
			if q.Status != 200 {
				refused++
			}
		}
	}
	switch {
	case sum.Iterations == nil:
		r.fail("k6's summary has no iteration count")
	case int(sum.Iterations.Count) != len(reqs):
		r.fail("k6 completed %.0f requests but the log has %d", sum.Iterations.Count, len(reqs))
	}
	if runEnd.Requests != int64(answered) || runEnd.Errors != int64(refused) {
		r.fail("the server answered %d requests (%d refused); the log has %d answered (%d refused)", runEnd.Requests, runEnd.Errors, answered, refused)
	}
	r.ServerBusy = runEnd.BusyErrs
	if r.ServerBusy > 0 {
		r.fail("the server saw SQLITE_BUSY %d times", r.ServerBusy)
	}

	// Checkpoints, backups, converge runs.
	pad := seconds(th.WindowPadSeconds).Microseconds()
	var backupStart int64
	var backups []Window
	var convergeDur []Request
	var convergeStart []int64
	fullConverges := 0
	for _, e := range events {
		// Seeding writes before the run are not part of it; a checkpoint
		// error anywhere still fails it.
		if e.Ev == EvCheckpoint && e.Err != "" {
			r.fail("checkpoint %s (%s) at %+.1fs: %s", e.Mode, e.Trigger, off(e.StartUs, start), e.Err)
			continue
		}
		if t := max(e.T, e.StartUs); (e.Ev == EvWAL || e.Ev == EvCheckpoint) && (t < start || t > end) {
			continue
		}
		switch e.Ev {
		case EvWAL:
			r.WALPeak = max(r.WALPeak, e.Bytes)
		case EvCheckpoint:
			r.WALPeak = max(r.WALPeak, e.WALBefore)
			switch {
			case e.Mode == "PASSIVE":
				r.Passives++
				r.MaxPassiveMs = max(r.MaxPassiveMs, float64(e.DurUs)/1000)
			case e.Deferred:
				r.Deferred++
			case e.Trigger == "size" || e.Trigger == "snapshot":
				if e.Trigger == "size" && e.StartUs >= start && e.StartUs <= loadEnd && !r.inWarmup(e.StartUs, start) {
					r.SizeTruncates++
				}
				if e.Busy || e.Checkpointed != e.LogFrames || e.WALAfter != 0 {
					r.fail("TRUNCATE (%s) at %+.1fs did not complete: busy %v, %d of %d frames, WAL %d bytes after",
						e.Trigger, off(e.StartUs, start), e.Busy, e.Checkpointed, e.LogFrames, e.WALAfter)
				}
				r.Windows = append(r.Windows, Window{Kind: "truncate-" + e.Trigger, StartUs: e.StartUs - pad, EndUs: e.StartUs + e.DurUs + pad, Offset: off(e.StartUs, start)})
			}
		case EvBackupStart:
			backupStart = e.T
		case EvBackupEnd:
			if e.Err != "" {
				r.fail("backup at %+.1fs failed: %s", off(backupStart, start), e.Err)
			}
			backups = append(backups, Window{Kind: "backup", StartUs: backupStart - pad, EndUs: e.T + pad, Offset: off(backupStart, start)})
		case EvConvergeStart:
			convergeStart = append(convergeStart, e.T)
		case EvConvergeEnd:
			if e.Err != "" {
				r.fail("converge run ending at %+.1fs: %s", off(e.T, start), e.Err)
			}
			if n := len(convergeStart); n > 0 {
				convergeDur = append(convergeDur, Request{Lat: time.Duration(e.T-convergeStart[n-1]) * time.Microsecond})
				if e.Err == "" && e.Targets == p.Targets && convergeStart[n-1] >= start && convergeStart[n-1] <= loadEnd {
					fullConverges++
				}
			}
		}
	}
	r.Converges, r.ConvergeMs, r.ConvergesWant = len(convergeDur), stats(convergeDur), p.Converges()
	if fullConverges < r.ConvergesWant {
		r.missing("%d of the plan's %d converge runs ran over all %d targets during the load", fullConverges, r.ConvergesWant, p.Targets)
	}
	r.Backups = len(backups)
	if r.Backups != len(p.Backups) {
		r.missing("%d of the plan's %d backups ran", r.Backups, len(p.Backups))
	}
	bound := float64(p.WALBound)
	if float64(r.WALPeak) >= th.WALPeakFactor*bound {
		r.fail("the WAL peaked at %d bytes, not under %.0f × the bound (%d)", r.WALPeak, th.WALPeakFactor, p.WALBound)
	}
	if r.SizeTruncates == 0 {
		r.missing("the WAL never passed the bound (%d bytes) under load: the size trigger was not shown; raise the write rate at this bound or lower the bound (ADR-0059 G9a)", p.WALBound)
	}

	// A backup overlapped the bound when the size trigger was deferred
	// while it ran; its own TRUNCATE then has to complete (checked above).
	overlapped := 0
	for i, b := range backups {
		deferred, truncated := 0, false
		for _, e := range events {
			if e.Ev != EvCheckpoint || e.StartUs < b.StartUs || e.StartUs > b.EndUs {
				continue
			}
			if e.Deferred {
				deferred++
			} else if e.Trigger == "snapshot" {
				truncated = true
			}
		}
		switch {
		case deferred > 0 && truncated:
			overlapped++
			backups[i].Note = fmt.Sprintf("held TRUNCATE off %d times, then truncated", deferred)
		case deferred > 0:
			r.fail("the backup at %+.1fs held TRUNCATE off but no TRUNCATE followed it", b.Offset)
		default:
			backups[i].Note = "did not overlap the bound"
		}
	}
	if overlapped == 0 {
		r.missing("no backup overlapped the bound (none held a size-triggered TRUNCATE off): G9a needs a TRUNCATE right after such a backup")
	}
	r.Windows = append(r.Windows, backups...)
	slices.SortFunc(r.Windows, func(a, b Window) int { return cmp.Compare(a.StartUs, b.StartUs) })
	for i, w := range r.Windows {
		var in []Request
		for _, q := range reqs {
			if q.SchedUs >= w.StartUs && q.SchedUs <= w.EndUs {
				in = append(in, q)
			}
		}
		r.Windows[i].Stats = stats(in)
		if s := r.Windows[i].Stats; s.N > 0 && (s.P95 > th.P95Ms || s.Failed > 0) {
			r.fail("%s window at %+.1fs: p95 %.1f ms, %d failed of %d", w.Kind, w.Offset, s.P95, s.Failed, s.N)
		}
	}

	r.memory(events, start)
	r.fsync(events, start, end)
	r.finish()
}

func (r *Report) inWarmup(t, start int64) bool {
	at := 0.0
	for _, ph := range r.Plan.Phases {
		from, to := start+seconds(at).Microseconds(), start+seconds(at+ph.Seconds).Microseconds()
		if t >= from && t < to {
			return ph.Warmup
		}
		at += ph.Seconds
	}
	return false
}

func (r *Report) memory(events []Event, start int64) {
	after := start + seconds(r.Plan.Thresholds.MemoryAfterSeconds).Microseconds()
	var anon, rss, current int64
	samples := 0
	final := false
	var me MemoryEvents
	for _, e := range events {
		if e.Ev != EvMemory {
			continue
		}
		rss = max(rss, e.RSSBytes)
		if e.Final && e.MemEvents != nil {
			final = true
		}
		if m := e.MemEvents; m != nil {
			me = MemoryEvents{High: max(me.High, m.High), Max: max(me.Max, m.Max), OOM: max(me.OOM, m.OOM), OOMKill: max(me.OOMKill, m.OOMKill)}
			current = max(current, m.Current)
		}
		if e.T >= after && e.AnonBytes > 0 {
			anon = max(anon, e.AnonBytes)
			samples++
		}
	}
	r.MemoryMaxMiB, r.RSSMaxMiB, r.CurrentMaxMiB = float64(anon)/(1<<20), float64(rss)/(1<<20), float64(current)/(1<<20)
	me.Current = current
	r.MemoryEvents = me
	// Without G9's limits the server is not in a cgroup of its own, so the
	// cgroup's memory is not the server's: reported, not judged.
	cg := r.System.Cgroup
	switch {
	case samples == 0:
		r.missing("no cgroup memory samples (%s): run the server under G9A_SCOPE (memory.max 1 GiB, memory.swap.max 0)", cg.Note)
	case cg.MemoryMax != strconv.Itoa(1<<30) || cg.SwapMax != "0":
		r.missing("memory.max %q and memory.swap.max %q, not G9's 1 GiB and 0: the cgroup is not the server's alone (run under G9A_SCOPE)", cg.MemoryMax, cg.SwapMax)
	case current == 0:
		r.missing("no memory.events or memory.current samples")
	}
	own := samples > 0 && cg.MemoryMax == strconv.Itoa(1<<30) && cg.SwapMax == "0"
	if own && !final {
		r.missing("no final memory.events reading after the run's work finished")
	}
	if own && r.MemoryMaxMiB > r.Plan.Thresholds.MemoryMiB {
		r.fail("anon memory reached %.1f MiB, over %.0f MiB", r.MemoryMaxMiB, r.Plan.Thresholds.MemoryMiB)
	}
	if own && (me.High > 0 || me.Max > 0 || me.OOM > 0 || me.OOMKill > 0) {
		r.fail("the cgroup reported memory.events high %d, max %d, oom %d, oom_kill %d", me.High, me.Max, me.OOM, me.OOMKill)
	}
}

func (r *Report) fsync(events []Event, start, end int64) {
	idle := map[string][]Request{}
	load := map[string][]Request{}
	for _, e := range events {
		if e.Ev != EvFsync {
			continue
		}
		q := Request{Lat: time.Duration(e.DurUs) * time.Microsecond}
		if e.Idle {
			idle[e.Kind] = append(idle[e.Kind], q)
		} else if e.StartUs >= start && e.StartUs <= end {
			load[e.Kind] = append(load[e.Kind], q)
		}
	}
	line := func(kind string, qs []Request) string {
		s := stats(qs)
		return fmt.Sprintf("%s: %d samples, p50 %.2f ms, p95 %.2f ms, p99 %.2f ms, max %.2f ms", kind, s.N, s.P50, s.P95, s.P99, s.Max)
	}
	for _, k := range []string{"append", "rewrite"} {
		r.FsyncIdle = append(r.FsyncIdle, line(k, idle[k]))
		r.FsyncUnderLoad = append(r.FsyncUnderLoad, line(k, load[k]))
	}
	if len(idle) == 0 || len(load) == 0 {
		r.missing("the fsync distribution idle or under load is missing from the disk record")
	}
	if r.System.Disk.FSType == "" {
		r.missing("the disk record has no filesystem (%s)", r.System.Disk.Note)
	}
}

func (r *Report) finish() {
	switch {
	case len(r.Fails) > 0:
		r.Verdict = Fail
	case len(r.Missing) > 0:
		r.Verdict = Inconclusive
	default:
		r.Verdict = Pass
	}
	if r.Fails == nil {
		r.Fails = []string{}
	}
	if r.Missing == nil {
		r.Missing = []string{}
	}
}

func off(t, start int64) float64 { return float64(t-start) / 1e6 }

// Markdown renders the report for people.
func (r *Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# G9a run: %s\n\n", strings.ToUpper(r.Verdict))
	fmt.Fprintf(&b, "Target: %s\n\n", r.System.Target)
	list := func(title string, xs []string) {
		if len(xs) == 0 {
			return
		}
		fmt.Fprintf(&b, "**%s**\n\n", title)
		for _, x := range xs {
			fmt.Fprintf(&b, "- %s\n", x)
		}
		b.WriteString("\n")
	}
	list("Failed", r.Fails)
	list("Not shown (inconclusive)", r.Missing)
	list("Notes", r.Notes)

	b.WriteString("## Phases\n\n| phase | rate/s | seconds | requests | expected | failed | busy | p50 ms | p95 ms | p99 ms | max ms |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, p := range r.Phases {
		name := p.Name
		if p.Warmup {
			name += " (warm-up)"
		}
		s := p.Stats
		fmt.Fprintf(&b, "| %s | %d | %g | %d | %d | %d | %d | %.1f | %.1f | %.1f | %.1f |\n", name, p.Rate, p.Seconds, s.N, p.Expected, s.Failed, p.Busy, s.P50, s.P95, s.P99, s.Max)
	}
	fmt.Fprintf(&b, "\nk6 dropped iterations: %.0f. SQLITE_BUSY seen by the server: %d.\n\n", r.Dropped, r.ServerBusy)

	fmt.Fprintf(&b, "## WAL and checkpoints\n\nBound %d bytes; peak %d bytes (%.2f × the bound). Size-triggered TRUNCATEs under load: %d; deferred by a backup: %d; PASSIVE checkpoints: %d (slowest %.1f ms).\n\n",
		r.Plan.WALBound, r.WALPeak, float64(r.WALPeak)/float64(r.Plan.WALBound), r.SizeTruncates, r.Deferred, r.Passives, r.MaxPassiveMs)
	b.WriteString("| window | at s | requests | failed | p95 ms | p99 ms | max ms | note |\n|---|---:|---:|---:|---:|---:|---:|---|\n")
	for _, w := range r.Windows {
		s := w.Stats
		fmt.Fprintf(&b, "| %s | %.1f | %d | %d | %.1f | %.1f | %.1f | %s |\n", w.Kind, w.Offset, s.N, s.Failed, s.P95, s.P99, s.Max, w.Note)
	}
	fmt.Fprintf(&b, "\nWindows are widened by %gs on both sides.\n\n", r.Plan.Thresholds.WindowPadSeconds)

	fmt.Fprintf(&b, "## Background work\n\nConverge runs: %d of %d planned (duration p50 %.0f ms, max %.0f ms). Backups: %d.\n\n", r.Converges, r.ConvergesWant, r.ConvergeMs.P50, r.ConvergeMs.Max, r.Backups)
	me := r.MemoryEvents
	fmt.Fprintf(&b, "## Memory\n\nCgroup anon after %gs: max %.1f MiB (limit %.0f MiB). Reported only: RSS max %.1f MiB, memory.current max %.1f MiB. memory.events: high %d, max %d, oom %d, oom_kill %d. memory.max %q, memory.swap.max %q.\n\n",
		r.Plan.Thresholds.MemoryAfterSeconds, r.MemoryMaxMiB, r.Plan.Thresholds.MemoryMiB, r.RSSMaxMiB, r.CurrentMaxMiB, me.High, me.Max, me.OOM, me.OOMKill, r.System.Cgroup.MemoryMax, r.System.Cgroup.SwapMax)

	d := r.System.Disk
	fmt.Fprintf(&b, "## Disk\n\nThe verdict holds for this class of disk only.\n\n- directory %s on %s (%s, %s), mounted at %s\n- device %s %s %s, model %q, rotational %q, under %v\n- %d CPUs, %s\n",
		d.Dir, d.Source, d.FSType, d.Options, d.MountPoint, d.Device, d.DevName, d.DMName, d.Model, d.Rotational, d.Slaves, r.System.CPUs, r.System.GoOS)
	b.WriteString("\nfsync idle (before the load):\n\n")
	for _, l := range r.FsyncIdle {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	b.WriteString("\nfsync under load:\n\n")
	for _, l := range r.FsyncUnderLoad {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	return b.String()
}

// WriteReport analyzes dir and writes report.md and verdict.json there.
func WriteReport(dir string) (*Report, error) {
	r, err := Analyze(dir)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, FileReport), []byte(r.Markdown()), 0o644); err != nil {
		return nil, err
	}
	return r, writeJSON(filepath.Join(dir, FileVerdict), r)
}
