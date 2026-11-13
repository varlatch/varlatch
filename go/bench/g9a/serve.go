// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varlatch/varlatch/go/lib/diskprobe"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
)

// The files a run writes to its output directory.
const (
	FilePlan     = "plan.json"
	FileManifest = "manifest.json"
	FileEvents   = "events.jsonl"
	FileSystem   = "system.json"
	// Written by k6 (see run.sh).
	FileRequests  = "requests.log"
	FileK6Summary = "k6-summary.json"
	// Written by the report.
	FileReport  = "report.md"
	FileVerdict = "verdict.json"
)

// StandInTarget names this package's workload as the target of a run.
const StandInTarget = "g9a stand-in workload (ADR-0059 groundwork; not varlatchd)"

// System is what the server records before the load: the disk and its idle
// fsync distribution, and the cgroup.
type System struct {
	// Target is what served the load. Until Order step 3 builds varlatchd
	// it is this package's stand-in workload, whose runs cannot pass G9a.
	Target   string `json:"target"`
	Disk     Disk   `json:"disk"`
	Cgroup   Cgroup `json:"cgroup"`
	IdleSync string `json:"idleFsync"`
	GoOS     string `json:"goos"`
	CPUs     int    `json:"cpus"`
	Seeded   string `json:"seeded"`
}

// ServeOptions configures Serve.
type ServeOptions struct {
	// DataDir holds the database; it must not hold one already.
	DataDir string
	// OutDir receives the plan, the manifest, events.jsonl and system.json.
	OutDir string
	Plan   Plan
	// Listen is the address for the load (default 127.0.0.1:8080).
	Listen string
	// Ready, if set, receives the listening address once the database is
	// seeded and the idle probe is done.
	Ready func(addr string)
	// Logf reports progress (default: discard).
	Logf func(format string, args ...any)
	// Tail is how long after the plan's end the server waits for POST
	// /run/stop before it stops on its own (default 2 minutes).
	Tail time.Duration
}

type server struct {
	opts ServeOptions
	ev   *eventLog
	db   *storage.DB
	w    *Workload
	cg   Cgroup

	requests, errs atomic.Int64

	startOnce sync.Once
	started   atomic.Int64 // run start, µs
	stop      chan struct{}
	stopOnce  sync.Once
	bg        sync.WaitGroup
}

// Serve seeds a fresh database, records the system, serves the load and
// runs the plan's background work from POST /run/start until POST
// /run/stop (or the plan's end plus Tail), then closes everything.
func Serve(ctx context.Context, opts ServeOptions) error {
	if err := opts.Plan.Validate(); err != nil {
		return err
	}
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:8080"
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.Tail <= 0 {
		opts.Tail = 2 * time.Minute
	}
	for _, d := range []string{opts.DataDir, opts.OutDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	dbPath := filepath.Join(opts.DataDir, "g9a.db")
	if _, err := os.Stat(dbPath); err == nil {
		return fmt.Errorf("%s exists: every run starts from a fresh database", dbPath)
	}
	if _, err := os.Stat(filepath.Join(opts.OutDir, FileEvents)); err == nil {
		return fmt.Errorf("%s already holds a run", opts.OutDir)
	}
	if err := WritePlan(filepath.Join(opts.OutDir, FilePlan), opts.Plan); err != nil {
		return err
	}
	ev, err := newEventLog(filepath.Join(opts.OutDir, FileEvents))
	if err != nil {
		return err
	}
	s := &server{opts: opts, ev: ev, stop: make(chan struct{}), cg: ownCgroup()}
	defer func() { _ = ev.close() }()

	s.db, err = storage.Open(ctx, storage.Options{
		Path:         dbPath,
		WALBound:     opts.Plan.WALBound,
		OnCheckpoint: s.onCheckpoint,
	})
	if err != nil {
		return err
	}
	dbClosed := false
	defer func() {
		if !dbClosed {
			_ = s.db.Close()
		}
	}()

	rootKEK := envelope.GenerateKey()
	opts.Logf("seeding W1 (%d targets)", opts.Plan.Targets)
	t0 := time.Now()
	manifest, err := Seed(ctx, s.db, rootKEK, opts.Plan.Targets)
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	if s.w, err = OpenWorkload(ctx, s.db, rootKEK); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(opts.OutDir, FileManifest), manifest); err != nil {
		return err
	}

	opts.Logf("idle fsync probe (%gs)", opts.Plan.IdleProbeSeconds)
	idle, err := diskprobe.Run(ctx, diskprobe.Options{
		Dir:      opts.DataDir,
		Duration: seconds(opts.Plan.IdleProbeSeconds),
		OnSample: s.fsyncSample(true),
	})
	if err != nil {
		return fmt.Errorf("idle fsync probe: %w", err)
	}
	sys := System{
		Target: StandInTarget,
		Disk:   describeDisk(opts.DataDir), Cgroup: s.cg, IdleSync: idle.String(),
		GoOS: goos(), CPUs: cpus(), Seeded: time.Since(t0).Round(time.Millisecond).String(),
	}
	if err := writeJSON(filepath.Join(opts.OutDir, FileSystem), sys); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ready\n")) })
	mux.HandleFunc("GET /v1/retrieve/{env}/{key}", s.handleRetrieve)
	mux.HandleFunc("POST /run/start", s.handleStart)
	mux.HandleFunc("POST /run/stop", func(w http.ResponseWriter, _ *http.Request) {
		s.stopOnce.Do(func() { close(s.stop) })
		_, _ = w.Write([]byte("stopping\n"))
	})
	hs := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- hs.Serve(ln) }()
	opts.Logf("ready on %s", ln.Addr())
	if opts.Ready != nil {
		opts.Ready(ln.Addr().String())
	}

	// Stop on /run/stop, on ctx, or when the run should long be over.
	var deadline <-chan time.Time
	select {
	case <-s.stop:
	case <-ctx.Done():
	case err := <-serveErr:
		return err
	case <-s.waitStarted():
		deadline = time.After(opts.Plan.Duration() + opts.Tail)
		select {
		case <-s.stop:
		case <-ctx.Done():
		case <-deadline:
			s.ev.emit(Event{Ev: EvError, Err: "no POST /run/stop before the plan's end plus the tail"})
		case err := <-serveErr:
			return err
		}
	}
	s.stopOnce.Do(func() { close(s.stop) })
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = hs.Shutdown(sctx)
	s.bg.Wait()
	s.ev.emit(Event{Ev: EvRunEnd, Requests: s.requests.Load(), Errors: s.errs.Load(), BusyErrs: s.w.busy.Load()})
	dbClosed = true
	if err := s.db.Close(); err != nil {
		return err
	}
	opts.Logf("stopped: %d requests, %d errors, %d busy", s.requests.Load(), s.errs.Load(), s.w.busy.Load())
	return s.ev.flush()
}

// waitStarted is closed by the first POST /run/start.
func (s *server) waitStarted() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		for s.started.Load() == 0 {
			select {
			case <-s.stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
		close(ch)
	}()
	return ch
}

func (s *server) onCheckpoint(r storage.CheckpointResult, err error) {
	e := Event{
		Ev: EvCheckpoint, Mode: r.Mode, Trigger: r.Trigger, StartUs: us(r.Start), DurUs: r.Duration.Microseconds(),
		Busy: r.Busy, Deferred: r.Deferred, LogFrames: r.LogFrames, Checkpointed: r.Checkpointed,
		WALBefore: r.WALBefore, WALAfter: r.WALAfter,
	}
	if err != nil {
		e.Err = err.Error()
	}
	s.ev.emit(e)
}

func (s *server) fsyncSample(idle bool) func(diskprobe.Kind, time.Time, time.Duration) {
	return func(k diskprobe.Kind, start time.Time, d time.Duration) {
		s.ev.emit(Event{Ev: EvFsync, StartUs: us(start), DurUs: d.Microseconds(), Kind: k.String(), Idle: idle})
	}
}

func (s *server) handleRetrieve(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	value, err := s.w.Retrieve(r.Context(), token, r.PathValue("env"), r.PathValue("key"), newID())
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": string(value)})
		return
	case errors.Is(err, errDenied):
		http.Error(w, "denied", http.StatusForbidden)
	case errors.Is(err, errNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case isBusy(err):
		http.Error(w, "SQLITE_BUSY: "+err.Error(), http.StatusServiceUnavailable)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	s.errs.Add(1)
}

func (s *server) handleStart(w http.ResponseWriter, _ *http.Request) {
	first := false
	s.startOnce.Do(func() {
		first = true
		t0 := time.Now()
		s.ev.emit(Event{T: us(t0), Ev: EvRunStart})
		s.started.Store(us(t0))
		s.runBackground(t0)
	})
	if !first {
		http.Error(w, "the run has started already", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int64{"startUs": s.started.Load()})
}

// runBackground starts the plan's work, counted from t0: the WAL and memory
// samplers, the fsync probe under load, converge runs and backups. The
// samplers end at /run/stop. Converge runs are scheduled only inside the
// load, and a converge run or backup in progress at /run/stop finishes
// (cancelled only if it is still running two minutes later), so stopping
// never turns into a failed run.
func (s *server) runBackground(t0 time.Time) {
	p := s.opts.Plan
	ctx, cancel := context.WithCancel(context.Background())
	work, cancelWork := context.WithCancel(context.Background())
	go func() {
		<-s.stop
		cancel()
		time.AfterFunc(2*time.Minute, cancelWork)
	}()

	s.every(ctx, t0, time.Second, func() {
		s.ev.emit(Event{Ev: EvWAL, Bytes: s.db.Metrics().WALBytes})
	})
	s.every(ctx, t0, 5*time.Second, func() {
		e := Event{Ev: EvMemory, RSSBytes: rssBytes()}
		if anon, err := s.cg.anonBytes(); err == nil {
			e.AnonBytes = anon
		} else {
			e.CgroupNote = err.Error()
		}
		if m, err := s.cg.memoryEvents(); err == nil {
			e.MemEvents = &m
		}
		s.ev.emit(e)
	})
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		_, err := diskprobe.Run(ctx, diskprobe.Options{
			Dir:      s.opts.DataDir,
			Duration: p.Duration() + s.opts.Tail,
			Interval: time.Duration(p.ProbeIntervalMs) * time.Millisecond,
			OnSample: s.fsyncSample(false),
		})
		if err != nil && ctx.Err() == nil {
			s.ev.emit(Event{Ev: EvError, Err: "fsync probe under load: " + err.Error()})
		}
	}()
	period := seconds(p.ConvergeEverySeconds)
	loadEnd := t0.Add(p.Duration())
	s.every(ctx, t0.Add(period), period, func() {
		if !time.Now().Before(loadEnd) {
			return
		}
		s.bg.Add(1)
		go func() {
			defer s.bg.Done()
			s.ev.emit(Event{Ev: EvConvergeStart})
			r := s.w.Converge(work)
			e := Event{Ev: EvConvergeEnd, Targets: r.Targets, Values: r.Values, Failed: r.PushFailed}
			if r.Err != nil {
				e.Err = r.Err.Error()
			}
			s.ev.emit(e)
		}()
	})
	for i, off := range p.BackupOffsets() {
		s.bg.Add(1)
		go func() {
			defer s.bg.Done()
			select {
			case <-time.After(time.Until(t0.Add(off))):
			case <-ctx.Done():
				return
			}
			s.backup(work, i)
		}()
	}
}

// every calls fn at first and then every period until ctx ends.
func (s *server) every(ctx context.Context, first time.Time, period time.Duration, fn func()) {
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
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

// backup takes a paced snapshot, as the backup job will, and removes it.
func (s *server) backup(ctx context.Context, n int) {
	dir := filepath.Join(s.opts.DataDir, "backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.ev.emit(Event{Ev: EvError, Err: err.Error()})
		return
	}
	dest := filepath.Join(dir, fmt.Sprintf("snapshot-%d.db", n))
	s.ev.emit(Event{Ev: EvBackupStart})
	p := s.opts.Plan
	st, err := s.db.Snapshot(ctx, dest, storage.SnapshotOptions{StepPages: p.BackupStepPages, Pause: time.Duration(p.BackupPauseMs) * time.Millisecond})
	e := Event{Ev: EvBackupEnd, Pages: st.Pages, Steps: st.Steps, Restarts: st.Restarts, DurUs: st.Duration.Microseconds()}
	if err != nil {
		e.Err = err.Error()
	}
	s.ev.emit(e)
	_ = os.Remove(dest)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
