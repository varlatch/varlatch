// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varlatch/varlatch/go/lib/diskprobe"
	"github.com/varlatch/varlatch/go/lib/storage"
)

// The files a run writes to its output directory.
const (
	FilePlan     = "plan.json"
	FileManifest = "manifest.json"
	FileEvents   = "events.jsonl"
	// FileConverge holds each converge run's Targets, a line a run: each
	// Target's commits, one by one (ConvergeLine).
	FileConverge = "converge.jsonl"
	FileSystem   = "system.json"
	// FileAccessLog is varlatchd's access log, from which the report counts
	// each client address's requests per request window.
	FileAccessLog = "access.log"
	// FileConfig is the varlatchd.conf the run served with.
	FileConfig = "varlatchd.conf"
	// Written by k6 (see run.sh).
	FileRequests  = "requests.log"
	FileK6Summary = "k6-summary.json"
	// Written by the report.
	FileReport  = "report.md"
	FileVerdict = "verdict.json"
)

// TargetVarlatchd names varlatchd as the target of a run: G9a is judged
// against it (ADR-0059, Order step 3).
const TargetVarlatchd = "varlatchd"

// System is what the server records before the load: what served it, the
// disk and its idle fsync distribution, and the cgroup.
type System struct {
	// Target is what served the load: "varlatchd" for its g9a build.
	Target string `json:"target"`
	// Build is the binary that served it: its version, the SHA-256 of the
	// executable, and its build tags.
	Build Build `json:"build"`
	// Settings are the storage engine's effective settings as varlatchd
	// read them back from its connections (storage.Settings), and Production
	// whether every one equals what the production build runs with (the
	// plan may set another WAL bound for a smoke run).
	Settings   storage.Settings `json:"settings"`
	Production bool             `json:"settingsAreProduction"`
	// SettingsNote says how they differ when they do.
	SettingsNote string `json:"settingsNote,omitempty"`
	Disk         Disk   `json:"disk"`
	Cgroup       Cgroup `json:"cgroup"`
	IdleSync     string `json:"idleFsync"`
	GoOS         string `json:"goos"`
	CPUs         int    `json:"cpus"`
	Seeded       string `json:"seeded"`
	// Addresses are the loopback source addresses the load comes from, one
	// identity's credential each (ADR-0059 varlatchd-core decision 6).
	Addresses []string `json:"addresses"`
}

// Build identifies the binary that served the run.
type Build struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Tags    string `json:"tags"`
}

// ManifestEntry is one source address of the load and the requests made
// from it: one identity's credential, and the Secrets it may reveal in one
// environment. k6 gives its virtual users the addresses in turn and each
// uses its address's entry (k6/g9a.js).
type ManifestEntry struct {
	Address  string   `json:"address"`
	Identity string   `json:"identity"`
	Token    string   `json:"token"`
	Org      string   `json:"org"`
	Project  string   `json:"project"`
	Env      string   `json:"env"`
	Keys     []string `json:"keys"`
}

// Target is what a run drives inside the server: varlatchd's g9a build,
// on its own storage instance, so that snapshots and checkpoints are the
// real ones.
type Target interface {
	// WALSize is the WAL file's size in bytes.
	WALSize() int64
	// Backup takes backup number n with a snapshot paced by o: in
	// varlatchd's g9a build, a real backup (the snapshot, the paced
	// sealing, the archive's check and local retention).
	Backup(ctx context.Context, n int, o storage.SnapshotOptions) (BackupStats, error)
	// Converge runs one converge over every Sync Target; a run already in
	// progress makes it return at once with ErrConvergeRunning.
	Converge(ctx context.Context) ConvergeResult
}

// BackupStats is what a backup did: its snapshot, how long its sealing
// and check took, the archive's size (0 for a bare snapshot) and the
// destination it was uploaded to (empty when none is configured).
type BackupStats struct {
	Snapshot     storage.SnapshotStats
	Seal         time.Duration
	ArchiveBytes int64
	UploadedTo   string
}

// ConvergeResult summarizes one converge run: with the real engine,
// each Target's run (Runs) and the provider calls it made.
type ConvergeResult struct {
	Targets    int
	Values     int
	PushFailed int
	Err        error
	Runs       []TargetRun
	Calls      int64
}

// TargetRun is one Target's run as the converge engine reports it
// (feature-parity decision 7): its commits, in order.
type TargetRun struct {
	Target        string   `json:"target"`
	Commits       int      `json:"commits"`
	SharedCommits int      `json:"sharedCommits"`
	WALBytes      int64    `json:"walBytes"`
	QueuedUs      int64    `json:"queuedUs"`
	InJobsUs      int64    `json:"inJobsUs"`
	CompletionUs  int64    `json:"completionUs"`
	DurationUs    int64    `json:"durationUs"`
	Jobs          []JobRun `json:"jobs"`
}

// JobRun is one commit of a Target's run: its name (CONVERGE.md), its
// time queued, in its own body, and from the body's end to its job's
// return (its batch's later jobs, COMMIT and fsync), its batch's WAL bytes
// and jobs.
type JobRun struct {
	Point        string `json:"point"`
	QueuedUs     int64  `json:"queuedUs"`
	InJobUs      int64  `json:"inJobUs"`
	CompletionUs int64  `json:"completionUs"`
	WALBytes     int64  `json:"walBytes"`
	BatchJobs    int    `json:"batchJobs"`
	Committed    bool   `json:"committed"`
}

// ConvergeLine is a line of FileConverge: a converge run's start and its
// Targets' runs.
type ConvergeLine struct {
	T    int64       `json:"t"`
	Runs []TargetRun `json:"runs"`
}

// ErrConvergeRunning is a converge tick that found the previous run still
// going: it does nothing (Targets 0), and a G9a report counts it as a
// failure of the run.
var ErrConvergeRunning = errors.New("the previous converge run is still running")

// RunnerOptions configures NewRunner.
type RunnerOptions struct {
	// DataDir holds the database; its disk is the one measured.
	DataDir string
	// OutDir receives the plan, the manifest, events.jsonl and system.json.
	OutDir string
	Plan   Plan
	Target Target
	// Logf reports progress (default: discard).
	Logf func(format string, args ...any)
	// Tail is how long after the plan's end the run waits for POST
	// /run/stop before it stops on its own (default 2 minutes).
	Tail time.Duration
}

// Runner runs a plan inside the server: it logs every checkpoint (as
// storage.Options.OnCheckpoint), samples the WAL, memory and CPU, probes
// fsync under load, and starts the converge runs and the backups the plan
// schedules, from POST /run/start until POST /run/stop (or the plan's end
// plus the tail).
type Runner struct {
	opts RunnerOptions
	ev   *eventLog
	cg   Cgroup

	requests, errs, busy atomic.Int64
	// backups numbers the backups; slot lets one run at a time (both the
	// timed and the WAL-triggered ones take it before they start); deferred
	// counts the size triggers a snapshot held off.
	backups  atomic.Int64
	slot     backupSlot
	deferred atomic.Int64
	// walSize and backupFn are the target's, replaced in tests.
	walSize  func() int64
	backupFn func(ctx context.Context, n int) (BackupStats, error)

	startOnce sync.Once
	started   atomic.Int64 // run start, µs
	stop      chan struct{}
	stopOnce  sync.Once
	done      chan struct{}
	bg        sync.WaitGroup
	// convergeMu orders writes to FileConverge.
	convergeMu sync.Mutex
	// writes are a bound run's added writes by kind, and writesDone waits
	// for the ones in flight (writeload.go).
	writes     map[WriteKind]*writeCounts
	writesDone func()
}

// NewRunner writes the plan to the output directory and opens the event
// log. The output directory must not hold a run already.
func NewRunner(opts RunnerOptions) (*Runner, error) {
	if err := opts.Plan.Validate(); err != nil {
		return nil, err
	}
	if opts.Target == nil {
		return nil, errors.New("g9a: no target")
	}
	if _, ok := opts.Target.(Writer); opts.Plan.BoundRun() && !ok {
		return nil, errors.New("g9a: a bound run (writeScale above 1) needs a target that makes its added writes")
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.Tail <= 0 {
		opts.Tail = 2 * time.Minute
	}
	for _, d := range []string{opts.DataDir, opts.OutDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	if _, err := os.Stat(filepath.Join(opts.OutDir, FileEvents)); err == nil {
		return nil, fmt.Errorf("%s already holds a run", opts.OutDir)
	}
	if err := WritePlan(filepath.Join(opts.OutDir, FilePlan), opts.Plan); err != nil {
		return nil, err
	}
	ev, err := newEventLog(filepath.Join(opts.OutDir, FileEvents))
	if err != nil {
		return nil, err
	}
	r := &Runner{opts: opts, ev: ev, cg: ownCgroup(), slot: newBackupSlot(), stop: make(chan struct{}), done: make(chan struct{})}
	r.walSize = opts.Target.WALSize
	r.backupFn = func(ctx context.Context, n int) (BackupStats, error) {
		p := opts.Plan
		return opts.Target.Backup(ctx, n, storage.SnapshotOptions{StepPages: p.BackupStepPages, Pause: time.Duration(p.BackupPauseMs) * time.Millisecond})
	}
	go r.watch()
	return r, nil
}

// OnCheckpoint logs a checkpoint the storage engine reports
// (storage.Options.OnCheckpoint).
func (r *Runner) OnCheckpoint(c storage.CheckpointResult, err error) {
	if c.Deferred && c.Trigger == storage.TriggerSize {
		r.deferred.Add(1)
	}
	e := Event{
		Ev: EvCheckpoint, Mode: c.Mode, Trigger: c.Trigger, StartUs: us(c.Start), DurUs: c.Duration.Microseconds(),
		Busy: c.Busy, Deferred: c.Deferred, LogFrames: c.LogFrames, Checkpointed: c.Checkpointed,
		WALBefore: c.WALBefore, WALAfter: c.WALAfter,
	}
	if err != nil {
		e.Err = err.Error()
	}
	r.ev.emit(e)
}

// WriteManifest writes the load's manifest for k6.
func (r *Runner) WriteManifest(m []ManifestEntry) error {
	return writeJSON(filepath.Join(r.opts.OutDir, FileManifest), m)
}

// Prepare probes the idle disk and writes system.json: sys as the server
// describes itself, with the disk, the cgroup, the idle fsync summary and
// the time seeding took.
func (r *Runner) Prepare(ctx context.Context, sys System, seeded time.Duration) error {
	p := r.opts.Plan
	r.opts.Logf("idle fsync probe (%gs)", p.IdleProbeSeconds)
	idle, err := diskprobe.Run(ctx, diskprobe.Options{
		Dir:      r.opts.DataDir,
		Duration: seconds(p.IdleProbeSeconds),
		OnSample: r.fsyncSample(true),
	})
	// Every sample is in the event log, which the report judges from. A
	// disk too slow for enough samples in the time given is what G9a must
	// record, not a reason to stop: only the summary is missing then. Any
	// other error (a failed write or sync) stops the run.
	idleSummary := idle.String()
	switch {
	case errors.Is(err, diskprobe.ErrTooFewSamples):
		idleSummary = "no summary: " + err.Error()
		r.opts.Logf("idle fsync probe: %v", err)
	case err != nil:
		return fmt.Errorf("idle fsync probe: %w", err)
	}
	sys.Disk, sys.Cgroup, sys.IdleSync = describeDisk(r.opts.DataDir), r.cg, idleSummary
	sys.GoOS, sys.CPUs, sys.Seeded = goos(), cpus(), seeded.Round(time.Millisecond).String()
	return writeJSON(filepath.Join(r.opts.OutDir, FileSystem), sys)
}

// Count records one request of the load and whether it failed, as the
// server saw it; busy is SQLITE_BUSY reaching it.
func (r *Runner) Count(failed, busy bool) {
	r.requests.Add(1)
	if failed {
		r.errs.Add(1)
	}
	if busy {
		r.busy.Add(1)
	}
}

// Handler serves the run's control routes under /run/: the plan and the
// manifest (for a k6 on another host; the manifest holds the seeded tokens
// of this throwaway database, so serve on a private network only), and
// POST /run/start and /run/stop.
func (r *Runner) Handler() http.Handler {
	mux := http.NewServeMux()
	for path, file := range map[string]string{"GET /run/plan": FilePlan, "GET /run/manifest": FileManifest} {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			b, err := os.ReadFile(filepath.Join(r.opts.OutDir, file))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
		})
	}
	mux.HandleFunc("POST /run/start", r.handleStart)
	mux.HandleFunc("POST /run/stop", func(w http.ResponseWriter, _ *http.Request) {
		r.stopOnce.Do(func() { close(r.stop) })
		_, _ = w.Write([]byte("stopping\n"))
	})
	return mux
}

// Done is closed when the run is over: POST /run/stop, or the plan's end
// plus the tail without one (logged as an error).
func (r *Runner) Done() <-chan struct{} { return r.done }

// Stop ends the run (the server is stopping).
func (r *Runner) Stop() { r.stopOnce.Do(func() { close(r.stop) }) }

func (r *Runner) watch() {
	defer close(r.done)
	select {
	case <-r.stop:
		return
	case <-r.waitStarted():
	}
	select {
	case <-r.stop:
	case <-time.After(r.opts.Plan.Duration() + r.opts.Tail):
		r.ev.emit(Event{Ev: EvError, Err: "no POST /run/stop before the plan's end plus the tail"})
		r.Stop()
	}
}

// Finish waits for the run's work, takes the last memory sample and logs
// run_end. Call it once the load can no longer arrive and before the
// database closes; then Close once it has (its closing checkpoint is the
// log's last event).
func (r *Runner) Finish() {
	r.Stop()
	r.bg.Wait()
	r.writeLoadEnd()
	// Memory pressure up to the end counts, including during work that
	// finished after /run/stop.
	if r.started.Load() != 0 {
		r.ev.emit(r.memorySample(true))
	}
	r.ev.emit(Event{Ev: EvRunEnd, Requests: r.requests.Load(), Errors: r.errs.Load(), BusyErrs: r.busy.Load()})
	r.opts.Logf("stopped: %d requests, %d errors, %d busy", r.requests.Load(), r.errs.Load(), r.busy.Load())
}

// Close writes out and closes the event log.
func (r *Runner) Close() error { return r.ev.close() }

// writeConverge appends a converge run's Targets to FileConverge.
func (r *Runner) writeConverge(line ConvergeLine) error {
	b, err := json.Marshal(line)
	if err != nil {
		return err
	}
	r.convergeMu.Lock()
	defer r.convergeMu.Unlock()
	f, err := os.OpenFile(filepath.Join(r.opts.OutDir, FileConverge), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// waitStarted is closed by the first POST /run/start.
func (r *Runner) waitStarted() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		for r.started.Load() == 0 {
			select {
			case <-r.stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
		close(ch)
	}()
	return ch
}

func (r *Runner) fsyncSample(idle bool) func(diskprobe.Kind, time.Time, time.Duration) {
	return func(k diskprobe.Kind, start time.Time, d time.Duration) {
		r.ev.emit(Event{Ev: EvFsync, StartUs: us(start), DurUs: d.Microseconds(), Kind: k.String(), Idle: idle})
	}
}

func (r *Runner) handleStart(w http.ResponseWriter, _ *http.Request) {
	first := false
	r.startOnce.Do(func() {
		first = true
		t0 := time.Now()
		r.ev.emit(Event{T: us(t0), Ev: EvRunStart})
		r.started.Store(us(t0))
		r.runBackground(t0)
	})
	if !first {
		http.Error(w, "the run has started already", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int64{"startUs": r.started.Load()})
}

// runBackground starts the plan's work, counted from t0: the WAL, memory
// and CPU samplers, the fsync probe under load, converge runs, backups (at
// their offsets, or from the WAL's size) and a bound run's added writes. The samplers end at
// /run/stop. Converge runs are scheduled only inside the load, and a
// converge run or backup in progress at /run/stop finishes (cancelled only
// if it is still running two minutes later), so stopping never turns into
// a failed run.
func (r *Runner) runBackground(t0 time.Time) {
	p := r.opts.Plan
	ctx, cancel := context.WithCancel(context.Background())
	work, cancelWork := context.WithCancel(context.Background())
	go func() {
		<-r.stop
		cancel()
		time.AfterFunc(2*time.Minute, cancelWork)
	}()

	// cpu.stat goes with every WAL sample as well as with memory: a
	// TRUNCATE window lasts about two seconds, and one-second samples place
	// its throttling more closely than the five-second memory samples.
	r.every(ctx, t0, time.Second, func() {
		e := Event{Ev: EvWAL, Bytes: r.walSize()}
		if c, err := r.cg.cpuStat(); err == nil {
			e.CPU = &c
		}
		r.ev.emit(e)
	})
	r.every(ctx, t0, 5*time.Second, func() { r.ev.emit(r.memorySample(false)) })
	r.bg.Add(1)
	go func() {
		defer r.bg.Done()
		_, err := diskprobe.Run(ctx, diskprobe.Options{
			Dir:      r.opts.DataDir,
			Duration: p.Duration() + r.opts.Tail,
			Interval: time.Duration(p.ProbeIntervalMs) * time.Millisecond,
			OnSample: r.fsyncSample(false),
		})
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, diskprobe.ErrTooFewSamples) {
			r.ev.emit(Event{Ev: EvError, Err: "fsync probe under load: " + err.Error()})
		}
	}()
	period := seconds(p.ConvergeEverySeconds)
	loadEnd := t0.Add(p.Duration())
	r.every(ctx, t0.Add(period), period, func() {
		if !time.Now().Before(loadEnd) {
			return
		}
		r.bg.Add(1)
		go func() {
			defer r.bg.Done()
			started := time.Now()
			r.ev.emit(Event{Ev: EvConvergeStart})
			res := r.opts.Target.Converge(work)
			e := Event{Ev: EvConvergeEnd, Targets: res.Targets, Values: res.Values, Failed: res.PushFailed, Calls: res.Calls}
			for _, run := range res.Runs {
				e.Commits += run.Commits
				e.SharedCommits += run.SharedCommits
				e.WALBytes += run.WALBytes
				e.EngineUs += run.DurationUs
				e.QueuedUs += run.QueuedUs
				e.InJobsUs += run.InJobsUs
				e.CompletionUs += run.CompletionUs
			}
			if res.Err != nil {
				e.Err = res.Err.Error()
			}
			if len(res.Runs) > 0 {
				if err := r.writeConverge(ConvergeLine{T: started.UnixMicro(), Runs: res.Runs}); err != nil {
					r.ev.emit(Event{Ev: EvError, Err: "converge.jsonl: " + err.Error()})
				}
			}
			r.ev.emit(e)
		}()
	})
	if p.BoundRun() {
		r.writeLoad(ctx, work, t0, r.opts.Target.(Writer))
	}
	offsets := p.BackupOffsets()
	for i, b := range p.Backups {
		r.bg.Add(1)
		go func() {
			defer r.bg.Done()
			phaseStart, _ := p.PhaseStart(b.Phase)
			phaseEnd := t0.Add(phaseStart + seconds(p.PhaseSeconds(b.Phase)))
			select {
			case <-time.After(time.Until(t0.Add(offsets[i]))):
			case <-ctx.Done():
				if !b.WALTriggered.Set() {
					r.ev.emit(Event{Ev: EvBackupMissed, Phase: b.Phase, Note: "the run stopped before its time"})
				}
				return
			}
			if b.WALTriggered.Set() {
				r.walBackups(ctx, work, phaseEnd, b)
				return
			}
			r.timedBackup(ctx, work, phaseEnd, b)
		}()
	}
}

// memorySample reads the cgroup's anon memory and memory.events, and the
// RSS. The final one is taken once the run's work has finished.
func (r *Runner) memorySample(final bool) Event {
	e := Event{Ev: EvMemory, Final: final, RSSBytes: rssBytes()}
	var errs []string
	if c, err := r.cg.cpuStat(); err == nil {
		e.CPU = &c
	} else {
		errs = append(errs, err.Error())
	}
	if anon, err := r.cg.anonBytes(); err == nil {
		e.AnonBytes = anon
	} else {
		errs = append(errs, err.Error())
	}
	if m, err := r.cg.memoryEvents(); err == nil {
		e.MemEvents = &m
	} else {
		errs = append(errs, err.Error())
	}
	e.CgroupNote = strings.Join(errs, "; ")
	return e
}

// every calls fn at first and then every period until ctx ends.
func (r *Runner) every(ctx context.Context, first time.Time, period time.Duration, fn func()) {
	r.bg.Add(1)
	go func() {
		defer r.bg.Done()
		next := first
		for {
			select {
			case <-time.After(time.Until(next)):
			case <-ctx.Done():
				return
			}
			fn()
			next = next.Add(period)
			if late := time.Since(next); late > 0 {
				next = next.Add(late.Truncate(period) + period)
			}
		}
	}()
}

// backupSlot lets one backup run at a time: the storage engine would
// serialize two snapshots anyway, and the report credits each deferred
// size trigger to the one backup running at the time.
type backupSlot chan struct{}

func newBackupSlot() backupSlot { return make(backupSlot, 1) }

// tryAcquire takes the slot if it is free.
func (b backupSlot) tryAcquire() bool {
	select {
	case b <- struct{}{}:
		return true
	default:
		return false
	}
}

func (b backupSlot) release() { <-b }

// timedBackup runs b, now due. If another backup holds the slot, it logs
// backup_wait and waits for it, with the wait on its backup_start, but only
// until its phase ends (phaseEnd) or the run stops (ctx): a backup labelled
// with a phase starts inside it. If it cannot, it logs backup_missed with
// the reason, and the report counts it as a planned backup that did not
// run. The snapshot runs under work, so one that started finishes.
func (r *Runner) timedBackup(ctx, work context.Context, phaseEnd time.Time, b Backup) {
	start := Event{Phase: b.Phase}
	if !r.slot.tryAcquire() {
		t := time.Now()
		r.ev.emit(Event{Ev: EvBackupWait, Phase: b.Phase, Note: "a backup was running: waiting for it"})
		end := time.NewTimer(time.Until(phaseEnd))
		defer end.Stop()
		select {
		case r.slot <- struct{}{}:
		case <-end.C:
			r.ev.emit(Event{Ev: EvBackupMissed, Phase: b.Phase, Note: "its phase ended while it waited for a running backup"})
			return
		case <-ctx.Done():
			r.ev.emit(Event{Ev: EvBackupMissed, Phase: b.Phase, Note: "the run stopped while it waited for a running backup"})
			return
		}
		start.WaitUs = max(1, time.Since(t).Microseconds())
	}
	defer r.slot.release()
	// The slot can come at the same instant as the stop or the phase's end,
	// and select picks among ready cases at random; a run already stopped
	// takes the free slot above too. Either way the backup does not start.
	if ctx.Err() != nil {
		r.ev.emit(Event{Ev: EvBackupMissed, Phase: b.Phase, Note: "the run stopped before it could start"})
		return
	}
	if !time.Now().Before(phaseEnd) {
		r.ev.emit(Event{Ev: EvBackupMissed, Phase: b.Phase, Note: "its phase ended while it waited for a running backup"})
		return
	}
	r.backup(work, start)
}

// backup takes a backup through the target; the caller holds the slot.
// start is its backup_start event, numbered and timed here and given the
// WAL size unless it has one; backup returns it. Its backup_end carries
// the snapshot's pages, steps, restarts and duration, the sealing's
// duration, the archive's size and the destination it was uploaded to.
func (r *Runner) backup(ctx context.Context, start Event) Event {
	t := time.Now()
	start.Ev, start.T, start.Backup = EvBackupStart, us(t), int(r.backups.Add(1))
	if start.WALBefore == 0 {
		start.WALBefore = r.walSize()
	}
	r.ev.emit(start)
	b, err := r.backupFn(ctx, start.Backup)
	st := b.Snapshot
	e := Event{Ev: EvBackupEnd, Backup: start.Backup, Phase: start.Phase, Attempt: start.Attempt,
		Pages: st.Pages, Steps: st.Steps, Restarts: st.Restarts, DurUs: st.Duration.Microseconds(),
		SealUs: b.Seal.Microseconds(), ArchiveBytes: b.ArchiveBytes, UploadedTo: b.UploadedTo}
	if err != nil {
		e.Err = err.Error()
	}
	r.ev.emit(e)
	return start
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
