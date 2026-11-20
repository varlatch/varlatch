// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var testKey = Secret{Item: "API_KEY", VersionID: "ver_api", Value: "api-key-aaaabbbbccccdddd"}

// growth times the small and the large work: each once untimed first, then
// small, large, small, large, small, large, each after a garbage
// collection, and the fastest of each (internal/matcher's helper).
func growth(small, large func()) (time.Duration, time.Duration) {
	small()
	large()
	var bestSmall, bestLarge time.Duration
	for i := range 3 {
		for _, f := range []struct {
			run  func()
			best *time.Duration
		}{{small, &bestSmall}, {large, &bestLarge}} {
			runtime.GC()
			start := time.Now()
			f.run()
			if took := time.Since(start); i == 0 || took < *f.best {
				*f.best = took
			}
		}
	}
	return bestSmall, bestLarge
}

// growsLinearly is the shared criterion: eight times the input in at most
// 24 times the time, plus 20 ms. It judges growth only, never a machine's
// speed.
func growsLinearly(small, large time.Duration) bool {
	return large <= 24*small+20*time.Millisecond
}

const (
	// minSmall: a real shape's smaller run lasts at least this long, so
	// the 20 ms of slack is small beside it.
	minSmall = 50 * time.Millisecond
	// minControl: the quadratic control's smaller run lasts at least this
	// long.
	minControl = 7 * time.Millisecond
)

// sized is the smallest n (from start, by steps of 1.5, at most limit)
// whose run lasts at least floor, the faster of two runs (the first may be
// cold), as growth will time it.
func sized(start, limit int, floor time.Duration, run func(n int) func()) int {
	n := start
	for n < limit {
		work := run(n)
		best := time.Duration(0)
		for i := range 2 {
			runtime.GC()
			began := time.Now()
			work()
			if took := time.Since(began); i == 0 || took < best {
				best = took
			}
		}
		if best >= floor {
			break
		}
		n = n * 3 / 2
	}
	return min(n, limit)
}

// scanOnce scans content as one file, pushed in 64 KiB chunks, as a path
// scan reads it.
func scanOnce(secrets []Secret, content []byte) *Report {
	e := NewEngine(secrets, Limits{MaxFileSize: 1 << 40, MaxTotalSize: 1 << 40}, nil)
	f := e.Begin("f")
	for at := 0; at < len(content); at += readChunk {
		f.Push(content[at:min(at+readChunk, len(content))])
	}
	f.End()
	return e.Result()
}

// TestScanIsLinear: every adversarial shape for the engine (lines and
// occurrences past the listing limit, markers at every turn, markers cut
// at each chunk's end, names at their longest bound, a value's start that
// never completes) takes time linear in the file's size by growsLinearly,
// each shape sized on this machine so its smaller run lasts at least
// minSmall; and a deliberately quadratic control, sized to at least
// minControl and timed the same way, is judged not linear, so the
// criterion can fail.
func TestScanIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("timing")
	}
	shapes := []struct {
		name string
		unit string
	}{
		{"lines and occurrences", "x\n" + testKey.Value + "\n"},
		{"markers on every line", testKey.Value + " # varlatch:allow API_KEY\n"},
		{"markers without names", "varlatch:allow"},
		{"marker gaps", "varlatch:allow" + strings.Repeat(" ", 16)},
		{"names at the bound", "varlatch:allow " + strings.Repeat("N", 300) + "\n"},
		{"a start that never completes", testKey.Value[:20]},
	}
	for _, shape := range shapes {
		run := func(size int) func() {
			content := []byte(strings.Repeat(shape.unit, size/len(shape.unit)+1)[:size])
			return func() { scanOnce([]Secret{testKey}, content) }
		}
		n := sized(64<<10, 16<<20, minSmall, run)
		small, large := growth(run(n), run(8*n))
		t.Logf("%s: %d bytes %v, %d bytes %v (%.1fx)", shape.name, n, small, 8*n, large, float64(large)/float64(small))
		if !growsLinearly(small, large) {
			t.Errorf("%s: %d bytes %v, %d bytes %v: not linear", shape.name, n, small, 8*n, large)
		}
	}
	// The control: a line index that searched every newline it holds for
	// each new one.
	quadratic := func(n int) func() {
		return func() {
			var held []int
			sum := 0
			for i := range n {
				for _, h := range held {
					sum += h
				}
				held = append(held, i)
			}
			if sum < 0 {
				t.Log(sum)
			}
		}
	}
	n := sized(500, 32000, minControl, quadratic)
	small, large := growth(quadratic(n), quadratic(8*n))
	t.Logf("the quadratic control, n = %d: %v then %v (%.1fx)", n, small, large, float64(large)/float64(small))
	if growsLinearly(small, large) {
		t.Errorf("the quadratic control (%v then %v) was judged linear", small, large)
	}
}

// TestBoundedState: whatever a file holds, the engine keeps a bounded
// amount of it: the newline positions it still needs, the carried bytes
// of a marker cut at a chunk's end, and the listed occurrences.
func TestBoundedState(t *testing.T) {
	e := NewEngine([]Secret{testKey}, Limits{MaxFileSize: 1 << 40, MaxTotalSize: 1 << 40}, nil)
	f := e.Begin("f")
	line := []byte(testKey.Value + " varlatch:allow OTHER\n" + strings.Repeat("x\n", 30))
	for range 20_000 {
		f.Push(line)
		if len(f.lines.newlines) > 2*4096+int(f.window) {
			t.Fatalf("%d newline positions held", len(f.lines.newlines))
		}
	}
	f.Push([]byte("varlatch:allow" + strings.Repeat(" ", 10)))
	if len(f.markers.carry) > markerSpan {
		t.Fatalf("%d bytes carried", len(f.markers.carry))
	}
	if len(f.occurrences) != MaxListedPerFile {
		t.Fatalf("%d occurrences listed", len(f.occurrences))
	}
	f.End()
	report := e.Result()
	if len(report.Unlisted) != 1 || report.Unlisted[0].Count != 20_000-MaxListedPerFile {
		t.Fatalf("unlisted %+v", report.Unlisted)
	}
}

// TestBoundsBeforeReading: a file over the per-file bound, or past the
// total, is refused by its listed size and never opened: here it cannot
// be (mode 000), and the reason is the bound, not the open.
func TestBoundsBeforeReading(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX modes that hold")
	}
	dir := t.TempDir()
	for name, size := range map[string]int{"big": 2048, "fits": 10, "past": 100} {
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"big", "past"} {
		if err := os.Chmod(filepath.Join(dir, name), 0); err != nil {
			t.Fatal(err)
		}
	}
	listing, err := ListPaths([]string{"."}, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine([]Secret{testKey}, Limits{MaxFileSize: 1024, MaxTotalSize: 50}, nil)
	ScanPaths(e, listing)
	report := e.Result()
	got := map[string]string{}
	for _, n := range report.NotScanned {
		got[n.Path] = n.Reason
	}
	if got["big"] != "larger than the per-file bound (2 KiB > 1 KiB)" || got["past"] != "over the total size bound of 50 bytes" || report.FilesScanned != 1 {
		t.Fatalf("not scanned %v, %d scanned", got, report.FilesScanned)
	}
}

// TestStagedTotalBound: --staged admits a file with the sizes of the files
// admitted before it counted, so the staged content as a whole stays
// within --max-total-size (go/README.md, `scan-staged-total`).
func TestStagedTotalBound(t *testing.T) {
	e := NewEngine([]Secret{testKey}, Limits{MaxFileSize: 1000, MaxTotalSize: 150}, nil)
	var admitted []string
	reserved := int64(0)
	for _, f := range []StagedFile{{"a", "1", 100}, {"b", "2", 100}, {"c", "3", 30}, {"d", "4", 30}} {
		if e.Admit(f.Path, f.Size, reserved) {
			admitted = append(admitted, f.Path)
			reserved += f.Size
		}
	}
	if strings.Join(admitted, ",") != "a,c" {
		t.Fatalf("admitted %v", admitted)
	}
}

// TestOneFileAtATime: the engine refuses a second open file, and the end
// of one that is finished.
func TestOneFileAtATime(t *testing.T) {
	e := NewEngine([]Secret{testKey}, DefaultLimits, nil)
	f := e.Begin("a")
	mustPanic(t, func() { e.Begin("b") })
	f.End()
	mustPanic(t, f.End)
	mustPanic(t, func() { f.Push([]byte("x")) })
}

func mustPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	f()
}
