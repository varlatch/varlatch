// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"context"
	"time"
)

// walWatchEvery is how often a WAL-triggered backup samples the WAL file's
// size, more often than the once a second the WAL is logged. On the VPS the
// WAL grew about 1.1 MB a second at 50/s (ADR-0059 amendment 4), so the
// last 5 % of a 64 MiB bound filled in about 3 s, and the checkpointer looks
// at the size every 2 s. Sampled once a second, a backup would start up to
// 1.1 MB, a third of that margin, past the fraction the plan records; at a
// smoke run's small bound one step can jump past the bound itself. Ten
// stat calls a second cost nothing next to the load.
const walWatchEvery = 100 * time.Millisecond

// walWatch decides when a WAL-triggered backup starts: at a crossing of the
// threshold from below (a sample under it, then one at or over it), while
// no backup is running, until an attempt has held a size-triggered
// TRUNCATE off or the attempts are used up. A WAL already over the
// threshold when the watch begins has not crossed it.
type walWatch struct {
	threshold   int64
	maxAttempts int
	attempts    int
	heldOff     bool
	armed       bool // the last sample was under the threshold
}

func newWALWatch(w WALTrigger, bound int64) *walWatch {
	return &walWatch{threshold: w.Threshold(bound), maxAttempts: w.MaxAttempts}
}

// observe takes one WAL size; running says a backup is in progress. crossed
// is a crossing from below; start says to start attempt w.attempts now.
func (w *walWatch) observe(size int64, running bool) (crossed, start bool) {
	if w.done() {
		return false, false
	}
	if size < w.threshold {
		w.armed = true
		return false, false
	}
	if !w.armed {
		return false, false
	}
	w.armed = false
	if running {
		return true, false
	}
	w.attempts++
	return true, true
}

// finished records the outcome of the attempt observe started.
func (w *walWatch) finished(heldOff bool) { w.heldOff = w.heldOff || heldOff }

// done: an attempt held a TRUNCATE off, or none is left.
func (w *walWatch) done() bool { return w.heldOff || w.attempts >= w.maxAttempts }

// walBackups runs b's WAL-triggered backups from now until end (its
// phase's end) or ctx (/run/stop). Each attempt runs on this goroutine, so
// none starts while the last is running; one in progress at end or at
// /run/stop finishes under work. Every attempt is logged as wal_backup with
// the WAL size that started it and whether it held a TRUNCATE off, and
// every crossing that started none as wal_crossing.
func (s *server) walBackups(ctx, work context.Context, end time.Time, b Backup) {
	w := newWALWatch(b.WALTriggered, s.opts.Plan.WALBound)
	t := time.NewTicker(walWatchEvery)
	defer t.Stop()
	for !w.done() {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if !now.Before(end) {
				return
			}
		}
		size := s.db.Metrics().WALBytes
		crossed, start := w.observe(size, s.running.Load() > 0)
		if crossed && !start {
			s.ev.emit(Event{Ev: EvWALCrossing, Phase: b.Phase, Bytes: size, Note: "a backup was running"})
		}
		if !start {
			continue
		}
		before := s.deferred.Load()
		started := s.backup(work, Event{Phase: b.Phase, Attempt: w.attempts, WALBefore: size})
		// The checkpointer reports a deferral just after it found the
		// snapshot holding TRUNCATE off, so the report can arrive just after
		// the snapshot returns: count deferrals one sampling interval on.
		time.Sleep(walWatchEvery)
		held := s.deferred.Load() > before
		w.finished(held)
		s.ev.emit(Event{Ev: EvWALBackup, Phase: b.Phase, Attempt: started.Attempt, Backup: started.Backup, StartUs: started.T,
			Bytes: size, HeldOff: held})
	}
}
