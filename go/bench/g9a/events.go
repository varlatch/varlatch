// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Event is one line of events.jsonl: what the server saw, with the time in
// microseconds since the Unix epoch. Fields not used by a kind are empty.
type Event struct {
	T  int64  `json:"t"`
	Ev string `json:"ev"`

	// checkpoint
	Mode         string `json:"mode,omitempty"`
	Trigger      string `json:"trigger,omitempty"`
	StartUs      int64  `json:"startUs,omitempty"`
	DurUs        int64  `json:"durUs,omitempty"`
	Busy         bool   `json:"busy,omitempty"`
	Deferred     bool   `json:"deferred,omitempty"`
	LogFrames    int64  `json:"logFrames,omitempty"`
	Checkpointed int64  `json:"checkpointed,omitempty"`
	WALBefore    int64  `json:"walBefore,omitempty"`
	WALAfter     int64  `json:"walAfter,omitempty"`

	// wal, memory
	Bytes      int64         `json:"bytes,omitempty"`
	AnonBytes  int64         `json:"anonBytes,omitempty"`
	MemEvents  *MemoryEvents `json:"memoryEvents,omitempty"`
	Final      bool          `json:"final,omitempty"`
	RSSBytes   int64         `json:"rssBytes,omitempty"`
	CgroupNote string        `json:"cgroupNote,omitempty"`
	// The cgroup's cpu.stat, read with each memory and WAL sample.
	CPU *CPUStat `json:"cpuStat,omitempty"`

	// fsync
	Kind string `json:"kind,omitempty"`
	Idle bool   `json:"idle,omitempty"`

	// backup_start, backup_end, wal_backup, wal_crossing. Backup numbers a
	// backup's start and end (from 1). For a WAL-triggered backup, Phase and
	// Attempt (from 1) say which, and WALBefore on backup_start, as Bytes on
	// wal_backup and wal_crossing, is the WAL size that started it.
	// wal_backup closes an attempt: HeldOff says a size-triggered TRUNCATE
	// was deferred while it ran. wal_crossing is a crossing that started no
	// attempt (Note says why). backup_wait is a timed backup that found
	// another running and waits for it; WaitUs on its backup_start is how
	// long it waited.
	Backup  int    `json:"backup,omitempty"`
	Phase   string `json:"phase,omitempty"`
	Attempt int    `json:"attempt,omitempty"`
	HeldOff bool   `json:"heldOff,omitempty"`
	Note    string `json:"note,omitempty"`
	WaitUs  int64  `json:"waitUs,omitempty"`

	// backup_end, converge_end
	Pages    int    `json:"pages,omitempty"`
	Steps    int    `json:"steps,omitempty"`
	Restarts int    `json:"restarts,omitempty"`
	Targets  int    `json:"targets,omitempty"`
	Values   int    `json:"values,omitempty"`
	Failed   int    `json:"failed,omitempty"`
	Err      string `json:"err,omitempty"`

	// run_end: what the server counted
	Requests int64 `json:"requests,omitempty"`
	Errors   int64 `json:"errors,omitempty"`
	BusyErrs int64 `json:"busyErrors,omitempty"`
}

// The event kinds.
const (
	EvRunStart      = "run_start"
	EvRunEnd        = "run_end"
	EvCheckpoint    = "checkpoint"
	EvWAL           = "wal"
	EvMemory        = "memory"
	EvFsync         = "fsync"
	EvBackupStart   = "backup_start"
	EvBackupEnd     = "backup_end"
	EvWALBackup     = "wal_backup"
	EvWALCrossing   = "wal_crossing"
	EvBackupWait    = "backup_wait"
	EvConvergeStart = "converge_start"
	EvConvergeEnd   = "converge_end"
	EvError         = "error"
)

func us(t time.Time) int64 { return t.UnixMicro() }

// eventLog appends events to a file; safe for concurrent use.
type eventLog struct {
	mu  sync.Mutex
	f   *os.File
	w   *bufio.Writer
	err error
}

func newEventLog(path string) (*eventLog, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &eventLog{f: f, w: bufio.NewWriterSize(f, 1<<16)}, nil
}

func (l *eventLog) emit(e Event) {
	if e.T == 0 {
		e.T = us(time.Now())
	}
	b, err := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return
	}
	if err == nil {
		_, err = l.w.Write(append(b, '\n'))
	}
	if err != nil {
		l.err = fmt.Errorf("event log: %w", err)
	}
}

func (l *eventLog) flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err == nil {
		l.err = l.w.Flush()
	}
	return l.err
}

func (l *eventLog) close() error {
	err := l.flush()
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// ReadEvents reads events.jsonl.
func ReadEvents(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for n := 1; sc.Scan(); n++ {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
