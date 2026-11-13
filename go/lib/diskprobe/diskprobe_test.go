// SPDX-License-Identifier: Apache-2.0

package diskprobe

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeClock drives the probe without real time: syncs take scripted
// latencies and sleeps return at once, each advancing the clock.
type fakeClock struct {
	t       time.Time
	samples int
	latency func(i int) time.Duration
	onSync  func(i int)
	files   map[string][]int64 // file name -> its size at each sync
}

func (c *fakeClock) env(appendCap int64) env {
	return env{
		now: func() time.Time { return c.t },
		sleep: func(ctx context.Context, d time.Duration) error {
			c.t = c.t.Add(d)
			return ctx.Err()
		},
		sync: func(f *os.File) error {
			i := c.samples
			c.samples++
			if c.onSync != nil {
				c.onSync(i)
			}
			if c.files != nil {
				st, err := f.Stat()
				if err != nil {
					return err
				}
				c.files[f.Name()] = append(c.files[f.Name()], st.Size())
			}
			c.t = c.t.Add(c.latency(i))
			return nil
		},
		appendCap: appendCap,
	}
}

func constant(d time.Duration) func(int) time.Duration { return func(int) time.Duration { return d } }

func TestRun(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClock{t: time.Unix(0, 0), latency: constant(time.Millisecond)}
	counts := map[Kind]int{}
	r, err := run(context.Background(), Options{
		Dir: dir, Duration: 5 * time.Second, Interval: 10 * time.Millisecond,
		OnSample: func(k Kind, _ time.Time, lat time.Duration) {
			if lat != time.Millisecond {
				t.Errorf("latency %v", lat)
			}
			counts[k]++
		},
	}, c.env(appendCap))
	if err != nil {
		t.Fatal(err)
	}
	// 5 s at one sample every 10 ms, alternating.
	if r.Append.Samples != 250 || r.Rewrite.Samples != 250 || counts[Append] != 250 || counts[Rewrite] != 250 {
		t.Fatalf("samples %d/%d, callbacks %v", r.Append.Samples, r.Rewrite.Samples, counts)
	}
	if !r.Pass || r.Limit != DefaultLimit || r.Append.P99 != time.Millisecond {
		t.Fatalf("result %+v", r)
	}
	if !strings.Contains(r.String(), "fsync ok") || !strings.Contains(r.String(), "append p99 1.0 ms") {
		t.Fatal(r.String())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left %d files behind", len(entries))
	}
}

// Each kind is judged on its own: a disk whose appends are slow fails even
// when rewrites are fast, and the other way round.
func TestRunVerdictPerKind(t *testing.T) {
	for _, slow := range []Kind{Append, Rewrite} {
		c := &fakeClock{t: time.Unix(0, 0), latency: func(i int) time.Duration {
			if Kind(i%2) == slow {
				return 20 * time.Millisecond
			}
			return time.Millisecond
		}}
		r, err := run(context.Background(), Options{Dir: t.TempDir(), Duration: 10 * time.Second}, c.env(appendCap))
		if err != nil {
			t.Fatal(err)
		}
		slowStats, fastStats := r.Append, r.Rewrite
		if slow == Rewrite {
			slowStats, fastStats = r.Rewrite, r.Append
		}
		if r.Pass || slowStats.P99 != 20*time.Millisecond || fastStats.P99 != time.Millisecond {
			t.Fatalf("slow %s: %v", slow, r)
		}
		if !strings.Contains(r.String(), "too slow") {
			t.Fatal(r.String())
		}
	}
}

// The append file grows by one block per append sample and starts over at
// the cap; the rewrite file stays at its allocated size.
func TestRunFileSizes(t *testing.T) {
	const capBlocks = 64
	c := &fakeClock{t: time.Unix(0, 0), latency: constant(0), files: map[string][]int64{}}
	if _, err := run(context.Background(), Options{Dir: t.TempDir(), Duration: 4 * time.Second}, c.env(capBlocks*blockSize)); err != nil {
		t.Fatal(err)
	}
	if len(c.files) != 2 {
		t.Fatalf("%d files synced", len(c.files))
	}
	var appendSizes, rewriteSizes []int64
	for _, sizes := range c.files {
		if sizes[0] == rewriteSpan {
			rewriteSizes = sizes
		} else {
			appendSizes = sizes
		}
	}
	if len(rewriteSizes) != 200 || len(appendSizes) != 200 {
		t.Fatalf("%d rewrite and %d append syncs, want 200 each", len(rewriteSizes), len(appendSizes))
	}
	for _, s := range rewriteSizes {
		if s != rewriteSpan {
			t.Fatalf("the rewrite file changed size: %d", s)
		}
	}
	resets := 0
	for i, s := range appendSizes {
		want := int64(i%capBlocks+1) * blockSize // grows a block per sample, back to one block after the cap
		if s != want {
			t.Fatalf("append sync %d: size %d, want %d", i, s, want)
		}
		if i > 0 && s < appendSizes[i-1] {
			resets++
		}
	}
	if resets != 3 {
		t.Fatalf("%d resets at the cap, want 3", resets)
	}
}

// Cancellation during a sample that also carries the run past its duration
// still ends in an error, never a result.
func TestRunCancelledDuringLastSync(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &fakeClock{t: time.Unix(0, 0)}
	c.latency = func(i int) time.Duration {
		if i == 299 {
			return time.Hour // past the end
		}
		return time.Millisecond
	}
	c.onSync = func(i int) {
		if i == 299 {
			cancel()
		}
	}
	dir := t.TempDir()
	if _, err := run(ctx, Options{Dir: dir, Duration: 5 * time.Second}, c.env(appendCap)); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("a cancelled probe left its files")
	}
}

func TestRunCancelledBefore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	if _, err := Run(ctx, Options{Dir: dir}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("files created after cancellation")
	}
}

func TestRunTooFewSamples(t *testing.T) {
	c := &fakeClock{t: time.Unix(0, 0), latency: constant(time.Second)}
	_, err := run(context.Background(), Options{Dir: t.TempDir(), Duration: 50 * time.Second}, c.env(appendCap))
	if !errors.Is(err, ErrTooFewSamples) || !strings.Contains(err.Error(), "only 25 append samples") {
		t.Fatalf("got %v", err)
	}
}

// Operational errors are not ErrTooFewSamples, which the G9a harness
// tolerates.
func TestRunErrors(t *testing.T) {
	if _, err := Run(context.Background(), Options{}); err == nil || errors.Is(err, ErrTooFewSamples) {
		t.Fatalf("ran without a directory: %v", err)
	}
	if _, err := Run(context.Background(), Options{Dir: filepath.Join(t.TempDir(), "missing")}); err == nil || errors.Is(err, ErrTooFewSamples) {
		t.Fatalf("ran in a missing directory: %v", err)
	}
}

// The real clock and sync, on whatever disk runs the tests: either a
// result or, on a disk too slow for enough samples, the error saying so;
// never a file left.
func TestRunRealSync(t *testing.T) {
	dir := t.TempDir()
	r, err := Run(context.Background(), Options{Dir: dir, Duration: 2 * time.Second, Interval: time.Millisecond})
	switch {
	case err == nil:
		t.Log(r)
	case strings.Contains(err.Error(), "samples"):
		t.Logf("this disk is too slow for a p99 in two seconds: %v", err)
	default:
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left %d files behind", len(entries))
	}
}

// Every block written differs from every other, across many laps of the
// rewrite area, and does not compress.
func TestPayload(t *testing.T) {
	p := newPayload()
	seen := map[[32]byte]bool{}
	laps := 3 * rewriteSpan / blockSize
	for range laps {
		h := sha256.Sum256(p.next())
		if seen[h] {
			t.Fatal("a block repeated")
		}
		seen[h] = true
	}
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	for range 64 {
		_, _ = w.Write(p.next())
	}
	_ = w.Close()
	if buf.Len() < 64*blockSize*99/100 {
		t.Fatalf("64 blocks compressed to %d bytes", buf.Len())
	}
}

func TestSummarize(t *testing.T) {
	var lats []time.Duration
	for i := 200; i >= 1; i-- { // 1..200 ms, unsorted input
		lats = append(lats, time.Duration(i)*time.Millisecond)
	}
	s := summarize(lats)
	for name, v := range map[string][2]time.Duration{
		"p50": {s.P50, 100 * time.Millisecond}, "p95": {s.P95, 190 * time.Millisecond},
		"p99": {s.P99, 198 * time.Millisecond}, "p99.9": {s.P999, 200 * time.Millisecond},
		"max": {s.Max, 200 * time.Millisecond},
	} {
		if v[0] != v[1] {
			t.Errorf("%s %v, want %v", name, v[0], v[1])
		}
	}
	if s.Over100ms != 100 || s.Samples != 200 {
		t.Fatalf("%+v", s)
	}
	if lats[0] != 200*time.Millisecond {
		t.Fatal("summarize reordered its input")
	}
	if percentile([]time.Duration{7}, 99) != 7 {
		t.Fatal("single sample")
	}
}
