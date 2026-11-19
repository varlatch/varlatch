// SPDX-License-Identifier: Apache-2.0

package matcher

import (
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Marker is redactionMarker: what replaces a match, the item's name and
// no character of its value.
func Marker(item string) []byte { return []byte("[REDACTED:" + item + "]") }

// RedactionMode is which feature turned redaction on: `--redact` (ADR-0038
// Decision 10), or assisted mode (ADR-0043 Decision 4), where it is the
// default and a short value reaches the redactor only when the operator
// allowed it.
type RedactionMode string

const (
	ModeRedact   RedactionMode = "redact"
	ModeAssisted RedactionMode = "assisted"
)

// OutputRedaction is redact.ts's OutputRedaction: each of the child's
// streams (stdout, stderr) passes through its own matcher, registered with
// exactly the sensitive values delivered to the child in this run, and
// each complete match is written as [REDACTED:<item>].
//   - Bytes, never text: nothing is decoded or re-encoded.
//   - Held bytes (a possible start of a value) are never released on a
//     timer. At a clean end of a stream they are released unchanged; if
//     the run was interrupted before the stream ended, the stream failed,
//     or the destination failed, they are discarded.
//   - Nothing the child writes can switch masking off.
type OutputRedaction struct {
	entries     []SecretEntry
	mode        RedactionMode
	interrupted atomic.Bool
	// Skipped are the items whose value is too short to register, sorted
	// and unique; they pass through unchanged.
	Skipped []string
}

// NewOutputRedaction is new OutputRedaction(entries, mode).
func NewOutputRedaction(entries []SecretEntry, mode RedactionMode) *OutputRedaction {
	r := &OutputRedaction{entries: entries, mode: mode}
	skipped := slices.Clone(NewStreamMatcher(entries, Marker).Skipped)
	slices.Sort(skipped)
	r.Skipped = slices.Compact(skipped)
	return r
}

// Notices are what the run says on stderr before the child starts: item
// names only.
func (r *OutputRedaction) Notices() []string {
	if r.mode == ModeAssisted {
		// Silent when there is nothing to mask: assisted mode is every run's default.
		if len(r.Skipped) == 0 {
			return nil
		}
		return []string{"varlatch: allowed with --allow-unmasked, so not masked (shorter than " + strconv.Itoa(MinLength) + " bytes): " + strings.Join(r.Skipped, ", ")}
	}
	if len(r.entries) == 0 {
		return []string{"varlatch: --redact: no Secret was delivered to this run, so there is nothing to mask"}
	}
	if len(r.Skipped) == 0 {
		return nil
	}
	return []string{"varlatch: --redact does not mask values shorter than " + strconv.Itoa(MinLength) + " bytes; these pass through unchanged: " + strings.Join(r.Skipped, ", ")}
}

// Interrupt says the run was interrupted (a signal it forwards to the
// child): from now on, a stream's held bytes are discarded when it ends.
func (r *OutputRedaction) Interrupt() { r.interrupted.Store(true) }

// Pair is one stream to relay: what the child writes, and where it goes.
// The source is closed when the destination fails, as a direct pipe's
// reader would go away, so the child's next write to it fails.
type Pair struct {
	Source io.ReadCloser
	Dest   io.Writer
}

// chunkSize is how much one read takes from the child's pipe.
const chunkSize = 64 * 1024

// Relay relays each source to its destination, concurrently, and returns
// when every source has ended and its output was written. Each write
// completes before the next read, so the child's pipe is read no faster
// than the output is written.
func (r *OutputRedaction) Relay(pairs []Pair) {
	var wg sync.WaitGroup
	for _, p := range pairs {
		wg.Add(1)
		go func(p Pair) {
			defer wg.Done()
			r.relayOne(p)
		}(p)
	}
	wg.Wait()
}

func (r *OutputRedaction) relayOne(p Pair) {
	matcher := NewStreamMatcher(r.entries, Marker)
	closed := false
	write := func(b []byte) {
		if closed || len(b) == 0 {
			return
		}
		if _, err := p.Dest.Write(b); err != nil {
			// The destination went away: stop reading, as a direct pipe would.
			closed = true
			_ = p.Source.Close()
		}
	}
	clean := true
	buf := make([]byte, chunkSize)
	for !closed {
		n, err := p.Source.Read(buf)
		if n > 0 {
			out, _ := matcher.Push(buf[:n])
			write(out)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			clean = false
			break
		}
	}
	if clean && !closed && !r.interrupted.Load() {
		// A clean end: what is still held cannot complete a match.
		end, _ := matcher.End()
		write(end.Output)
		return
	}
	matcher.Abort()
}
