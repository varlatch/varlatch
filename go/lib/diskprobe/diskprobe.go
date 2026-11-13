// SPDX-License-Identifier: Apache-2.0

// Package diskprobe measures how long durable writes take in a directory
// (ADR-0059 Decision 2, disk requirement). It makes 4 KiB writes durable the
// two ways the database's write-ahead log does: appending to a growing file
// (the WAL after a TRUNCATE checkpoint, which needs space and a new size on
// disk) and rewriting blocks already allocated (a reused WAL). The two
// alternate, are reported separately, and a disk passes only if both have a
// p99 under the limit. Setup and varlatch doctor run a short probe on the
// data directory and warn when it fails; the G9a harness runs a long one and
// records every sample.
package diskprobe

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"slices"
	"time"
)

// DefaultLimit is ADR-0059's disk requirement: fsync p99 under 10 ms.
const DefaultLimit = 10 * time.Millisecond

const (
	blockSize = 4096
	// rewriteSpan is the allocated area the rewrite samples cycle through.
	rewriteSpan = 1 << 20
	// appendCap is where the growing file is truncated to empty again (the
	// WAL bound), so a long run does not fill the disk.
	appendCap = 64 << 20
	// minSamples is the fewest samples of each kind a p99 is computed from.
	minSamples = 100
)

// ErrTooFewSamples means the probe ran without error but made fewer than
// 100 samples of a kind in its time, too few for a p99: the disk is slower
// than the interval allows. The samples were still passed to OnSample.
var ErrTooFewSamples = errors.New("diskprobe: too few samples for a p99")

// Kind is the kind of durable write a sample made.
type Kind int

const (
	// Append extends a growing file, then syncs it.
	Append Kind = iota
	// Rewrite overwrites an allocated block, then syncs it.
	Rewrite
)

func (k Kind) String() string {
	if k == Append {
		return "append"
	}
	return "rewrite"
}

// Options configures Run. Only Dir is required.
type Options struct {
	// Dir is the directory to measure (the data directory).
	Dir string
	// Duration is how long to probe (default 5 s). A sync already running
	// when it ends, or when ctx is cancelled, cannot be interrupted and is
	// waited for.
	Duration time.Duration
	// Interval is the time from one sample's start to the next (default
	// 10 ms). A sample slower than the interval starts the next at once.
	Interval time.Duration
	// Limit is the p99 a disk must stay under (default DefaultLimit).
	Limit time.Duration
	// OnSample, if set, is called after every sample (the G9a harness
	// records them all).
	OnSample func(kind Kind, start time.Time, latency time.Duration)
}

// Stats summarizes one kind of sample.
type Stats struct {
	Samples                  int
	P50, P95, P99, P999, Max time.Duration
	Over100ms                int
}

// Result summarizes a probe.
type Result struct {
	Append, Rewrite Stats
	Limit           time.Duration
	// Pass reports whether both p99 values are under Limit.
	Pass bool
}

// String is a one-line summary for setup, doctor and logs.
func (r Result) String() string {
	verdict := "ok"
	if !r.Pass {
		verdict = "too slow"
	}
	one := func(name string, s Stats) string {
		return fmt.Sprintf("%s p99 %s (p50 %s, max %s, %d samples, %d over 100 ms)",
			name, ms(s.P99), ms(s.P50), ms(s.Max), s.Samples, s.Over100ms)
	}
	return fmt.Sprintf("fsync %s (limit %s): %s; %s", verdict, ms(r.Limit), one("append", r.Append), one("rewrite", r.Rewrite))
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000) }

// env is what the probe needs from the outside world; tests replace it.
type env struct {
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
	sync  func(*os.File) error
	// appendCap is where the growing file starts over.
	appendCap int64
}

var realEnv = env{now: time.Now, sleep: sleepCtx, sync: datasync, appendCap: appendCap}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Run probes opts.Dir. It creates two temporary files there (mode 0600) and
// removes them before returning. It fails if ctx ends before it returns, or
// if it could not take enough samples of each kind for a p99.
func Run(ctx context.Context, opts Options) (Result, error) {
	return run(ctx, opts, realEnv)
}

func run(ctx context.Context, opts Options, e env) (Result, error) {
	if opts.Dir == "" {
		return Result{}, errors.New("diskprobe: no directory")
	}
	if opts.Duration <= 0 {
		opts.Duration = 5 * time.Second
	}
	if opts.Interval <= 0 {
		opts.Interval = 10 * time.Millisecond
	}
	if opts.Limit <= 0 {
		opts.Limit = DefaultLimit
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	grow, err := tempFile(opts.Dir)
	if err != nil {
		return Result{}, err
	}
	defer removeFile(grow)
	reuse, err := tempFile(opts.Dir)
	if err != nil {
		return Result{}, err
	}
	defer removeFile(reuse)
	// The rewrite samples overwrite an area allocated and synced first.
	pl := newPayload()
	area := make([]byte, rewriteSpan)
	for off := 0; off < rewriteSpan; off += blockSize {
		copy(area[off:], pl.next())
	}
	if _, err := reuse.WriteAt(area, 0); err != nil {
		return Result{}, fmt.Errorf("diskprobe: %w", err)
	}
	if err := reuse.Sync(); err != nil {
		return Result{}, fmt.Errorf("diskprobe: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	lats := map[Kind][]time.Duration{}
	var appendOff, rewriteOff int64
	end := e.now().Add(opts.Duration)
	for i := 0; e.now().Before(end); i++ {
		kind := Kind(i % 2)
		f, off := reuse, rewriteOff
		if kind == Append {
			if appendOff >= e.appendCap {
				// Start over, as the WAL does after a TRUNCATE checkpoint;
				// not measured.
				if err := grow.Truncate(0); err != nil {
					return Result{}, fmt.Errorf("diskprobe: %w", err)
				}
				if err := grow.Sync(); err != nil {
					return Result{}, fmt.Errorf("diskprobe: %w", err)
				}
				appendOff = 0
			}
			f, off = grow, appendOff
		}
		block := pl.next()
		start := e.now()
		if _, err := f.WriteAt(block, off); err != nil {
			return Result{}, fmt.Errorf("diskprobe: write: %w", err)
		}
		if err := e.sync(f); err != nil {
			return Result{}, fmt.Errorf("diskprobe: sync: %w", err)
		}
		lat := e.now().Sub(start)
		if kind == Append {
			appendOff += blockSize
		} else {
			rewriteOff = (rewriteOff + blockSize) % rewriteSpan
		}
		lats[kind] = append(lats[kind], lat)
		if opts.OnSample != nil {
			opts.OnSample(kind, start, lat)
		}
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if rest := opts.Interval - lat; rest > 0 {
			if err := e.sleep(ctx, rest); err != nil {
				return Result{}, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	for _, k := range []Kind{Append, Rewrite} {
		if n := len(lats[k]); n < minSamples {
			return Result{}, fmt.Errorf("%w: only %d %s samples in %s; at least %d of each kind are needed", ErrTooFewSamples, n, k, opts.Duration, minSamples)
		}
	}
	r := Result{Append: summarize(lats[Append]), Rewrite: summarize(lats[Rewrite]), Limit: opts.Limit}
	r.Pass = r.Append.P99 < opts.Limit && r.Rewrite.P99 < opts.Limit
	return r, nil
}

func tempFile(dir string) (*os.File, error) {
	f, err := os.CreateTemp(dir, ".varlatch-diskprobe-*")
	if err != nil {
		return nil, fmt.Errorf("diskprobe: %w", err)
	}
	return f, nil
}

func removeFile(f *os.File) {
	_ = f.Close() // before Remove: Windows cannot remove an open file
	_ = os.Remove(f.Name())
}

// payload produces 4 KiB blocks of fresh pseudo-random bytes: incompressible
// (like encrypted WAL frames on compressing storage) and never the same
// twice, so no layer can skip a write as unchanged.
type payload struct {
	rng   *rand.ChaCha8
	block []byte
}

func newPayload() *payload {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(rand.Uint32())
	}
	return &payload{rng: rand.NewChaCha8(seed), block: make([]byte, blockSize)}
}

// next returns the next block; it is valid until the following call.
func (p *payload) next() []byte {
	_, _ = p.rng.Read(p.block)
	return p.block
}

func summarize(lats []time.Duration) Stats {
	s := slices.Clone(lats)
	slices.Sort(s)
	st := Stats{
		Samples: len(s),
		P50:     percentile(s, 50),
		P95:     percentile(s, 95),
		P99:     percentile(s, 99),
		P999:    percentile(s, 99.9),
		Max:     s[len(s)-1],
	}
	for _, l := range s {
		if l > 100*time.Millisecond {
			st.Over100ms++
		}
	}
	return st
}

// percentile is the nearest-rank percentile of sorted samples: the smallest
// sample at or below which at least p percent of the samples fall.
func percentile(sorted []time.Duration, p float64) time.Duration {
	n := len(sorted)
	rank := int(math.Ceil(float64(n)*p/100 - 1e-9)) // the epsilon absorbs float error
	rank = min(max(rank, 1), n)
	return sorted[rank-1]
}
