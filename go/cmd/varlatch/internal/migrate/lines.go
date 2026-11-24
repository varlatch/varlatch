// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"sync"
	"sync/atomic"
	"time"
)

// Lines is where a migrate command's lines go (Options.Say and
// Options.Progress): one queue, and one goroutine that writes it, the only
// writer while there is one. A reader that does not read must not hold a
// migration up (an --abort between Go's stop and the barrier's lifting would
// leave both servers shut), so neither waits for the writer. A line of Say's
// is never dropped; one of Progress's is, when the backlog is over
// linesBacklog or the writer is stuck.
type Lines struct {
	write func(string)
	mu    sync.Mutex
	queue []queued
	since time.Time     // when the write that goes on began
	more  chan struct{} // something was queued, or closed
	ended chan struct{}
	shut  bool
}

// queued is a line, or (written) a mark.
type queued struct {
	text    string
	written chan struct{}
}

const (
	linesBacklog = 64
	// linesStuck is how long a write may take before the writer is taken
	// for stuck.
	linesStuck = time.Second
)

// currentLines is the command's, for the crash points (crashpoint.go), which
// flush it before they park.
var currentLines atomic.Pointer[Lines]

// NewLines starts the writer: write is called for one line at a time.
func NewLines(write func(string)) *Lines {
	l := &Lines{write: write, more: make(chan struct{}, 1), ended: make(chan struct{})}
	currentLines.Store(l)
	go l.run()
	return l
}

// Say queues a line. It never waits, and drops none (but after Close).
func (l *Lines) Say(text string) { l.add(queued{text: text}, false) }

// Progress queues a line, or drops it. It never waits.
func (l *Lines) Progress(text string) { l.add(queued{text: text}, true) }

func (l *Lines) add(q queued, mayDrop bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.shut || mayDrop && (len(l.queue) >= linesBacklog || !l.since.IsZero() && time.Since(l.since) > linesStuck) {
		return
	}
	l.queue = append(l.queue, q)
	l.wake()
}

func (l *Lines) wake() {
	select {
	case l.more <- struct{}{}:
	default:
	}
}

func (l *Lines) run() {
	defer close(l.ended)
	for {
		l.mu.Lock()
		l.since = time.Time{}
		if len(l.queue) == 0 {
			shut := l.shut
			l.mu.Unlock()
			if shut {
				return
			}
			<-l.more
			continue
		}
		q := l.queue[0]
		l.queue = l.queue[1:]
		l.since = time.Now()
		l.mu.Unlock()
		if q.written != nil {
			close(q.written)
			continue
		}
		l.write(q.text)
	}
}

// Flush waits, limit at the most, until every line before it is written:
// before anything else writes where the lines go. It says whether they are.
func (l *Lines) Flush(limit time.Duration) bool {
	mark := queued{written: make(chan struct{})}
	l.add(mark, false)
	return within(mark.written, limit)
}

// Close takes no more lines, and waits, limit at the most, until those there
// are written and the writer has ended. It says whether they are.
func (l *Lines) Close(limit time.Duration) bool {
	currentLines.CompareAndSwap(l, nil)
	l.mu.Lock()
	l.shut = true
	l.wake()
	l.mu.Unlock()
	return within(l.ended, limit)
}

func within(done <-chan struct{}, limit time.Duration) bool {
	t := time.NewTimer(limit)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}
