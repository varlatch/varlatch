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

// walWatch decides when a WAL-triggered backup may start: at a crossing of
// the threshold from below (a sample under it, then one at or over it),
// until an attempt has held a size-triggered TRUNCATE off or the attempts
// are used up. A WAL already over the threshold when the watch begins has
// not crossed it. Whether the backup slot is free is the caller's to find
// out; a crossing it could not use is gone.
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

// observe takes one WAL size and says whether it crossed the threshold from
// below while attempts remain.
func (w *walWatch) observe(size int64) (crossed bool) {
	if w.done() {
		return false
	}
	if size < w.threshold {
		w.armed = true
		return false
	}
	crossed, w.armed = w.armed, false
	return crossed
}

// started counts an attempt, begun at a crossing.
func (w *walWatch) started() { w.attempts++ }

// finished records the outcome of the attempt last started.
func (w *walWatch) finished(heldOff bool) { w.heldOff = w.heldOff || heldOff }

// done: an attempt held a TRUNCATE off, or none is left.
func (w *walWatch) done() bool { return w.heldOff || w.attempts >= w.maxAttempts }

// walBackups runs b's WAL-triggered backups from now until end (its
// phase's end) or ctx (/run/stop). At a crossing it takes the backup slot
// if it is free (a crossing while another backup holds it is logged as
// wal_crossing and skipped), and holds it until the attempt's deferrals are
// counted, so no other backup's can be credited to it. One in progress at
// end or at /run/stop finishes under work. Every attempt is logged as
// wal_backup with the WAL size that started it and whether it held a
// TRUNCATE off.
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
		size := s.walSize()
		if !w.observe(size) {
			continue
		}
		if !s.slot.tryAcquire() {
			s.ev.emit(Event{Ev: EvWALCrossing, Phase: b.Phase, Bytes: size, Note: "a backup was running"})
			continue
		}
		// An attempt starts inside its phase or not at all.
		if !time.Now().Before(end) {
			s.slot.release()
			return
		}
		w.started()
		w.finished(s.walAttempt(work, b.Phase, w.attempts, size))
	}
}

// walAttempt runs one WAL-triggered backup in the slot the caller took,
// releases it, logs wal_backup and says whether it held a TRUNCATE off.
func (s *server) walAttempt(work context.Context, phase string, attempt int, size int64) bool {
	defer s.slot.release()
	before := s.deferred.Load()
	started := s.backup(work, Event{Phase: phase, Attempt: attempt, WALBefore: size})
	// The checkpointer reports a deferral just after it found the snapshot
	// holding TRUNCATE off, so the report can arrive just after the snapshot
	// returns: count deferrals one sampling interval on, still in the slot.
	time.Sleep(walWatchEvery)
	held := s.deferred.Load() > before
	s.ev.emit(Event{Ev: EvWALBackup, Phase: phase, Attempt: attempt, Backup: started.Backup, StartUs: started.T, Bytes: size, HeldOff: held})
	return held
}
