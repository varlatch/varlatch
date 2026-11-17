// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
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
	return Spread{Min: s[0], Median: rank(s, 0.5), Max: s[len(s)-1]}
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
