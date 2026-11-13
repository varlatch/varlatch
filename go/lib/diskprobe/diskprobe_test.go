// SPDX-License-Identifier: Apache-2.0

package diskprobe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSync replaces the real sync with a fixed delay, so that the probe's
// logic is tested independently of the disk the tests run on.
func fakeSync(t *testing.T, d time.Duration) {
	t.Helper()
	syncFn = func(*os.File) error { time.Sleep(d); return nil }
	t.Cleanup(func() { syncFn = datasync })
}

func TestRun(t *testing.T) {
	fakeSync(t, 200*time.Microsecond)
	dir := t.TempDir()
	var calls int
	r, err := Run(context.Background(), Options{
		Dir: dir, Duration: 300 * time.Millisecond, Interval: time.Millisecond,
		OnSample: func(start time.Time, lat time.Duration) {
			if start.IsZero() || lat < 200*time.Microsecond {
				t.Errorf("sample %v %v", start, lat)
			}
			calls++
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Samples < minSamples || calls != r.Samples {
		t.Fatalf("%d samples, %d callbacks", r.Samples, calls)
	}
	if !(r.P50 <= r.P95 && r.P95 <= r.P99 && r.P99 <= r.P999 && r.P999 <= r.Max) {
		t.Fatalf("percentiles out of order: %+v", r)
	}
	if r.Limit != DefaultLimit || !r.Pass {
		t.Fatalf("verdict: %+v", r)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left %d files behind", len(entries))
	}
	if !strings.Contains(r.String(), "fsync ok: p99") {
		t.Fatal(r.String())
	}

	fakeSync(t, 2*time.Millisecond)
	r, err = Run(context.Background(), Options{Dir: dir, Duration: 400 * time.Millisecond, Interval: time.Millisecond, Limit: time.Millisecond})
	if err != nil || r.Pass || !strings.Contains(r.String(), "too slow") {
		t.Fatalf("a slow disk passed: %v, %v", r, err)
	}
}

// The real sync, on whatever disk runs the tests: either a result or, on a
// disk too slow for enough samples, the error saying so; never a file left.
func TestRunRealSync(t *testing.T) {
	dir := t.TempDir()
	r, err := Run(context.Background(), Options{Dir: dir, Duration: time.Second, Interval: time.Millisecond})
	switch {
	case err == nil:
		t.Log(r)
	case strings.Contains(err.Error(), "samples"):
		t.Logf("this disk is too slow for a p99 in one second: %v", err)
	default:
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left %d files behind", len(entries))
	}
}

func TestRunTooFewSamples(t *testing.T) {
	fakeSync(t, 0)
	_, err := Run(context.Background(), Options{Dir: t.TempDir(), Duration: 50 * time.Millisecond, Interval: 20 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "samples") {
		t.Fatalf("got %v", err)
	}
}

func TestRunErrors(t *testing.T) {
	fakeSync(t, time.Millisecond)
	if _, err := Run(context.Background(), Options{}); err == nil {
		t.Fatal("ran without a directory")
	}
	if _, err := Run(context.Background(), Options{Dir: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("ran in a missing directory")
	}
	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if _, err := Run(ctx, Options{Dir: dir, Duration: time.Minute}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("a cancelled probe left its file")
	}
}

func TestSummarize(t *testing.T) {
	var lats []time.Duration
	for i := 200; i >= 1; i-- { // 1..200 ms, unsorted input
		lats = append(lats, time.Duration(i)*time.Millisecond)
	}
	r := summarize(lats, 150*time.Millisecond)
	want := map[string][2]time.Duration{
		"p50": {r.P50, 100 * time.Millisecond}, "p95": {r.P95, 190 * time.Millisecond},
		"p99": {r.P99, 198 * time.Millisecond}, "p99.9": {r.P999, 200 * time.Millisecond},
		"max": {r.Max, 200 * time.Millisecond},
	}
	for name, v := range want {
		if v[0] != v[1] {
			t.Errorf("%s %v, want %v", name, v[0], v[1])
		}
	}
	if r.Over100ms != 100 || r.Pass || lats[0] != 200*time.Millisecond {
		t.Fatalf("%+v (input reordered: %v)", r, lats[0] != 200*time.Millisecond)
	}
	if summarize(lats, time.Second).Pass != true {
		t.Fatal("p99 under the limit did not pass")
	}
	if percentile([]time.Duration{7}, 99) != 7 {
		t.Fatal("single sample")
	}
}
