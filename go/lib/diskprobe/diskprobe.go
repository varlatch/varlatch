// SPDX-License-Identifier: Apache-2.0

// Package diskprobe measures how long durable writes take in a directory
// (ADR-0059 Decision 2, disk requirement): it writes a 4 KiB block and
// syncs it, at a fixed interval, in a private temporary file, the way the
// database's write-ahead log is made durable. Setup and varlatch doctor run
// a short probe on the data directory and warn when its p99 is over the
// limit; the G9a harness runs a long one and records every sample.
package diskprobe

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"time"
)

// DefaultLimit is ADR-0059's disk requirement: fsync p99 under 10 ms.
const DefaultLimit = 10 * time.Millisecond

const (
	blockSize = 4096
	span      = 1 << 20 // the probe rewrites blocks within the first MiB
	// minSamples is the fewest samples a p99 is computed from.
	minSamples = 100
)

// syncFn makes a sample durable; tests replace it.
var syncFn = datasync

// Options configures Run. Only Dir is required.
type Options struct {
	// Dir is the directory to measure (the data directory).
	Dir string
	// Duration is how long to probe (default 5 s).
	Duration time.Duration
	// Interval is the time from one sample's start to the next (default
	// 10 ms). A sample slower than the interval starts the next at once.
	Interval time.Duration
	// Limit is the p99 a disk must stay under (default DefaultLimit).
	Limit time.Duration
	// OnSample, if set, is called after every sample (the G9a harness
	// records them all).
	OnSample func(start time.Time, latency time.Duration)
}

// Result summarizes a probe.
type Result struct {
	Samples                 int
	P50, P95, P99, P999, Max time.Duration
	Over100ms               int
	Limit                   time.Duration
	// Pass reports whether P99 is under Limit.
	Pass bool
}

// String is a one-line summary for setup, doctor and logs.
func (r Result) String() string {
	verdict := "ok"
	if !r.Pass {
		verdict = "too slow"
	}
	return fmt.Sprintf("fsync %s: p99 %s (limit %s), p50 %s, p95 %s, max %s, %d samples, %d over 100 ms",
		verdict, ms(r.P99), ms(r.Limit), ms(r.P50), ms(r.P95), ms(r.Max), r.Samples, r.Over100ms)
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000) }

// Run probes opts.Dir. It creates one temporary file there (mode 0600) and
// removes it before returning. It fails if it could not take enough samples
// for a p99, or if ctx ends first.
func Run(ctx context.Context, opts Options) (Result, error) {
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

	f, err := os.CreateTemp(opts.Dir, ".varlatch-diskprobe-*")
	if err != nil {
		return Result{}, fmt.Errorf("diskprobe: %w", err)
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()
	// Allocate the span first, so the samples measure the data sync of
	// rewritten blocks (as with a reused WAL), not the file growing.
	if _, err := f.WriteAt(make([]byte, span), 0); err != nil {
		return Result{}, fmt.Errorf("diskprobe: %w", err)
	}
	if err := f.Sync(); err != nil {
		return Result{}, fmt.Errorf("diskprobe: %w", err)
	}

	block := make([]byte, blockSize)
	var lats []time.Duration
	end := time.Now().Add(opts.Duration)
	for off := int64(0); time.Now().Before(end); off = (off + blockSize) % span {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		block[0]++ // a changed block, so nothing can skip the write
		start := time.Now()
		if _, err := f.WriteAt(block, off); err != nil {
			return Result{}, fmt.Errorf("diskprobe: write: %w", err)
		}
		if err := syncFn(f); err != nil {
			return Result{}, fmt.Errorf("diskprobe: sync: %w", err)
		}
		lat := time.Since(start)
		lats = append(lats, lat)
		if opts.OnSample != nil {
			opts.OnSample(start, lat)
		}
		if rest := opts.Interval - lat; rest > 0 {
			select {
			case <-ctx.Done():
				return Result{}, ctx.Err()
			case <-time.After(rest):
			}
		}
	}
	if len(lats) < minSamples {
		return Result{}, fmt.Errorf("diskprobe: only %d samples in %s; at least %d are needed for a p99", len(lats), opts.Duration, minSamples)
	}
	return summarize(lats, opts.Limit), nil
}

func summarize(lats []time.Duration, limit time.Duration) Result {
	s := slices.Clone(lats)
	slices.Sort(s)
	r := Result{
		Samples: len(s),
		P50:     percentile(s, 50),
		P95:     percentile(s, 95),
		P99:     percentile(s, 99),
		P999:    percentile(s, 99.9),
		Max:     s[len(s)-1],
		Limit:   limit,
	}
	for _, l := range s {
		if l > 100*time.Millisecond {
			r.Over100ms++
		}
	}
	r.Pass = r.P99 < limit
	return r
}

// percentile is the nearest-rank percentile of sorted samples: the smallest
// sample at or below which at least p percent of the samples fall.
func percentile(sorted []time.Duration, p float64) time.Duration {
	n := len(sorted)
	rank := int(math.Ceil(float64(n)*p/100 - 1e-9)) // the epsilon absorbs float error
	rank = min(max(rank, 1), n)
	return sorted[rank-1]
}
