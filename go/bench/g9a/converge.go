// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// ConvergeCost is what the converge runs cost the database, as the real
// engine reports it (feature-parity decision 7): per run, its commits, WAL
// bytes, engine time, writer queue time and provider calls; per commit
// point, how often it committed, its time in the job and its batch's WAL
// bytes. Reported only: no criterion reads it, but a pull request that
// raises the commits or WAL bytes per run by more than 20 % says why.
type ConvergeCost struct {
	Runs []ConvergeRunCost `json:"runs"`
	// Per Target run, over every run.
	CommitsPerTarget  Spread      `json:"commitsPerTarget"`
	WALBytesPerTarget Spread      `json:"walBytesPerTarget"`
	Points            []PointCost `json:"points"`
}

// ConvergeRunCost is one converge run's totals over its Targets.
type ConvergeRunCost struct {
	Offset        float64 `json:"offsetSeconds"`
	Targets       int     `json:"targets"`
	Values        int     `json:"values"`
	Calls         int64   `json:"providerCalls"`
	Commits       int     `json:"commits"`
	SharedCommits int     `json:"sharedCommits"`
	WALBytes      int64   `json:"walBytes"`
	EngineMs      float64 `json:"engineMs"`
	QueuedMs      float64 `json:"queuedMs"`
	InJobsMs      float64 `json:"inJobsMs"`
	CompletionMs  float64 `json:"completionMs"`
}

// PointCost is one commit point over every run.
type PointCost struct {
	Point string `json:"point"`
	// Count is how many jobs ran at this point; Committed how many wrote.
	Count, Committed int
	InJobMs          Spread `json:"inJobMs"`
	QueuedMs         Spread `json:"queuedMs"`
	CompletionMs     Spread `json:"completionMs"`
	// BatchWALBytes is the WAL bytes of the batches that held them.
	BatchWALBytes Spread `json:"batchWALBytes"`
	// Shared counts those whose batch held other jobs too.
	Shared int `json:"shared"`
}

// Spread is a set of values' median and extremes.
type Spread struct {
	Min    float64 `json:"min"`
	Median float64 `json:"median"`
	Max    float64 `json:"max"`
}

func spread(v []float64) Spread {
	if len(v) == 0 {
		return Spread{}
	}
	s := slices.Clone(v)
	sort.Float64s(s)
	return Spread{Min: s[0], Median: rank(s, 50), Max: s[len(s)-1]}
}

// ReadConverge reads FileConverge: nil if the run wrote none (a run of a
// varlatchd before 4.9d's real engine).
func ReadConverge(path string) ([]ConvergeLine, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []ConvergeLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for n := 1; sc.Scan(); n++ {
		var l ConvergeLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, n, err)
		}
		out = append(out, l)
	}
	return out, sc.Err()
}

// convergeCost sums the runs: the converge_end events in order for the
// totals, the lines for the points.
func convergeCost(ends []Event, starts []int64, start int64, lines []ConvergeLine) *ConvergeCost {
	if len(lines) == 0 {
		return nil
	}
	c := &ConvergeCost{}
	for i, e := range ends {
		run := ConvergeRunCost{Targets: e.Targets, Values: e.Values, Calls: e.Calls, Commits: e.Commits, SharedCommits: e.SharedCommits,
			WALBytes: e.WALBytes, EngineMs: float64(e.EngineUs) / 1e3, QueuedMs: float64(e.QueuedUs) / 1e3, InJobsMs: float64(e.InJobsUs) / 1e3,
			CompletionMs: float64(e.CompletionUs) / 1e3}
		if i < len(starts) {
			run.Offset = off(starts[i], start)
		}
		c.Runs = append(c.Runs, run)
	}
	var commits, wal []float64
	type acc struct {
		count, committed, shared         int
		inJob, queued, completion, batch []float64
	}
	points := map[string]*acc{}
	var order []string
	for _, l := range lines {
		for _, run := range l.Runs {
			commits = append(commits, float64(run.Commits))
			wal = append(wal, float64(run.WALBytes))
			for _, j := range run.Jobs {
				a := points[j.Point]
				if a == nil {
					a = &acc{}
					points[j.Point] = a
					order = append(order, j.Point)
				}
				a.count++
				if j.Committed {
					a.committed++
				}
				if j.BatchJobs > 1 {
					a.shared++
				}
				a.inJob = append(a.inJob, float64(j.InJobUs)/1e3)
				a.queued = append(a.queued, float64(j.QueuedUs)/1e3)
				a.completion = append(a.completion, float64(j.CompletionUs)/1e3)
				a.batch = append(a.batch, float64(j.WALBytes))
			}
		}
	}
	c.CommitsPerTarget, c.WALBytesPerTarget = spread(commits), spread(wal)
	for _, p := range order {
		a := points[p]
		c.Points = append(c.Points, PointCost{Point: p, Count: a.count, Committed: a.committed, Shared: a.shared,
			InJobMs: spread(a.inJob), QueuedMs: spread(a.queued), CompletionMs: spread(a.completion), BatchWALBytes: spread(a.batch)})
	}
	return c
}

// markdown is the report's converge section.
func (c *ConvergeCost) markdown(b *strings.Builder) {
	b.WriteString("### Converge runs (the real engine)\n\n")
	b.WriteString("Commits, WAL bytes and times are the engine's own (feature-parity decision 7). A commit's WAL bytes are its share of its batch's when the batch held other jobs (`shared`), exact otherwise. A pull request that raises commits or WAL bytes per run by more than 20 % says why.\n\n")
	b.WriteString("In jobs is the jobs' own bodies; completion, from each body's end to its job's return (its batch's later jobs, COMMIT and fsync).\n\n")
	b.WriteString("| Run at | Targets | Values | Provider calls | Commits | Shared | WAL bytes | Engine time | Queued | In jobs | Completion |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, r := range c.Runs {
		fmt.Fprintf(b, "| %+.1f s | %d | %d | %d | %d | %d | %d | %.0f ms | %.0f ms | %.0f ms | %.0f ms |\n",
			r.Offset, r.Targets, r.Values, r.Calls, r.Commits, r.SharedCommits, r.WALBytes, r.EngineMs, r.QueuedMs, r.InJobsMs, r.CompletionMs)
	}
	fmt.Fprintf(b, "\nPer Target run: commits %s, WAL bytes %s (min / median / max).\n\n", c.CommitsPerTarget.text(0), c.WALBytesPerTarget.text(0))
	b.WriteString("| Commit point | Jobs | Committed | Shared | In job (ms) | Completion (ms) | Queued (ms) | Batch WAL bytes |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, p := range c.Points {
		fmt.Fprintf(b, "| %s | %d | %d | %d | %s | %s | %s | %s |\n", p.Point, p.Count, p.Committed, p.Shared, p.InJobMs.text(1), p.CompletionMs.text(1), p.QueuedMs.text(1), p.BatchWALBytes.text(0))
	}
	b.WriteString("\n")
}

func (s Spread) text(digits int) string {
	f := func(v float64) string {
		if digits == 0 {
			return fmt.Sprintf("%.0f", math.Round(v))
		}
		return fmt.Sprintf("%.*f", digits, v)
	}
	return f(s.Min) + " / " + f(s.Median) + " / " + f(s.Max)
}

// converge-baseline.json is the engine's cost on a smoke run (see its
// "about"): CheckCost holds a run to it.
//
//go:embed converge-baseline.json
var baselineJSON []byte

// CostBaseline is converge-baseline.json.
type CostBaseline struct {
	About             string     `json:"about"`
	ChangesPerRun     int        `json:"changesPerRun"`
	CommitsPerTarget  int        `json:"commitsPerTarget"`
	Points            []string   `json:"points"`
	WALBytesPerTarget int64      `json:"walBytesPerTarget"`
	WALMedian         [2]float64 `json:"walMedian"`
	WALEach           [2]float64 `json:"walEach"`
}

// Baseline is the embedded converge-baseline.json, checked for
// consistency (its points are its commits, 2k + 7 of them).
func Baseline() (CostBaseline, error) {
	var b CostBaseline
	if err := json.Unmarshal(baselineJSON, &b); err != nil {
		return b, fmt.Errorf("converge-baseline.json: %w", err)
	}
	if len(b.Points) != b.CommitsPerTarget || b.CommitsPerTarget != 2*b.ChangesPerRun+7 || b.WALBytesPerTarget <= 0 ||
		!(0 < b.WALMedian[0] && b.WALMedian[0] < b.WALMedian[1]) || !(0 < b.WALEach[0] && b.WALEach[0] < b.WALEach[1]) {
		return b, fmt.Errorf("converge-baseline.json is not consistent: %d points, %d commits for k = %d", len(b.Points), b.CommitsPerTarget, b.ChangesPerRun)
	}
	return b, nil
}

// CheckCost holds the converge runs of the run in dir to the baseline
// (feature-parity decision 7): in every run each of the plan's Targets ran
// once, with exactly the successful path's commits (by name and in order,
// every one committed), and WAL bytes within the baseline's range, for
// each Target and for the run's median Target (each run's own: one bad
// run does not hide behind good ones). It applies to a run that is not
// G9a's own profile (no gate criterion changes) with the baseline's k;
// applies is false otherwise, with the reason in problems. Problems are
// empty when the cost is within the baseline.
func CheckCost(dir string) (problems []string, applies bool, err error) {
	b, err := Baseline()
	if err != nil {
		return nil, false, err
	}
	p, err := ReadPlan(filepath.Join(dir, FilePlan))
	if err != nil {
		return nil, false, err
	}
	switch {
	case len(p.NotGate()) == 0:
		return []string{"G9a's own profile: the gate's criteria, not the smoke's baseline"}, false, nil
	case p.ChangesPerRun != b.ChangesPerRun:
		return []string{fmt.Sprintf("the plan changes %d values a run, the baseline %d", p.ChangesPerRun, b.ChangesPerRun)}, false, nil
	}
	lines, err := ReadConverge(filepath.Join(dir, FileConverge))
	if err != nil {
		return nil, true, err
	}
	if len(lines) == 0 {
		if p.Converges() > 0 {
			problems = append(problems, fmt.Sprintf("no converge run recorded (%s), %d planned", FileConverge, p.Converges()))
		}
		return problems, true, nil
	}
	lo, hi := float64(b.WALBytesPerTarget)*b.WALEach[0], float64(b.WALBytesPerTarget)*b.WALEach[1]
	mlo, mhi := float64(b.WALBytesPerTarget)*b.WALMedian[0], float64(b.WALBytesPerTarget)*b.WALMedian[1]
	for i, l := range lines {
		run := fmt.Sprintf("run %d", i+1)
		seen := map[string]bool{}
		var wal []float64
		for _, r := range l.Runs {
			seen[r.Target] = true
			wal = append(wal, float64(r.WALBytes))
			var points []string
			committed := true
			for _, j := range r.Jobs {
				points = append(points, j.Point)
				committed = committed && j.Committed
			}
			if r.Commits != b.CommitsPerTarget || !slices.Equal(points, b.Points) || !committed {
				problems = append(problems, fmt.Sprintf("%s, Target %s: %d commits %v (committed: %v), the baseline %d %v",
					run, r.Target, r.Commits, points, committed, b.CommitsPerTarget, b.Points))
			}
			if w := float64(r.WALBytes); w < lo || w > hi {
				problems = append(problems, fmt.Sprintf("%s, Target %s: %d WAL bytes, outside %.0f to %.0f", run, r.Target, r.WALBytes, lo, hi))
			}
		}
		if len(l.Runs) != p.Targets || len(seen) != p.Targets {
			problems = append(problems, fmt.Sprintf("%s: %d Target runs of %d Targets, the plan has %d", run, len(l.Runs), len(seen), p.Targets))
		}
		if len(wal) > 0 {
			sort.Float64s(wal)
			if m := wal[len(wal)/2]; m < mlo || m > mhi {
				problems = append(problems, fmt.Sprintf("%s: the median Target wrote %.0f WAL bytes, outside %.0f to %.0f", run, m, mlo, mhi))
			}
		}
	}
	return problems, true, nil
}
