// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// costRun writes a run directory: a smoke plan and converge.jsonl with
// runs of 20 Target runs each, every one the baseline's commits and wal
// bytes, then edit applied to each run (by its index).
func costRun(t *testing.T, plan Plan, runs int, wal int64, edit func(run int, l *ConvergeLine)) string {
	t.Helper()
	b, err := Baseline()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pb, _ := json.Marshal(plan)
	if err := os.WriteFile(filepath.Join(dir, FilePlan), pb, 0o644); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for i := range runs {
		l := ConvergeLine{T: int64(i)}
		for k := range plan.Targets {
			r := TargetRun{Target: fmt.Sprintf("snt_%02d", k), Commits: b.CommitsPerTarget, WALBytes: wal}
			for _, p := range b.Points {
				r.Jobs = append(r.Jobs, JobRun{Point: p, Committed: true, BatchJobs: 1})
			}
			l.Runs = append(l.Runs, r)
		}
		if edit != nil {
			edit(i, &l)
		}
		lb, _ := json.Marshal(l)
		lines = append(lines, string(lb))
	}
	if runs > 0 {
		if err := os.WriteFile(filepath.Join(dir, FileConverge), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// CheckCost holds each converge run to converge-baseline.json: the
// commits by name and in order, each Target's WAL bytes and each run's own
// median Target (one bad run does not hide behind good ones); not on G9a's
// own profile.
func TestCheckCost(t *testing.T) {
	b, err := Baseline()
	if err != nil {
		t.Fatal(err)
	}
	smoke := DefaultPlan().Scaled(0.05)
	base := b.WALBytesPerTarget
	for _, c := range []struct {
		name    string
		plan    Plan
		runs    int
		edit    func(int, *ConvergeLine)
		applies bool
		want    string // a problem's text; "" for none
	}{
		{name: "within the baseline", plan: smoke, runs: 3, applies: true},
		{name: "one run of three at twice the WAL", plan: smoke, runs: 3, applies: true, want: "run 2: the median Target wrote",
			edit: func(i int, l *ConvergeLine) {
				if i == 1 {
					for k := range l.Runs {
						l.Runs[k].WALBytes = 2 * base
					}
				}
			}},
		{name: "one Target far over", plan: smoke, runs: 2, applies: true, want: "WAL bytes, outside",
			edit: func(i int, l *ConvergeLine) { l.Runs[3].WALBytes = 3 * base }},
		{name: "one commit per Target", plan: smoke, runs: 2, applies: true, want: "1 commits",
			edit: func(i int, l *ConvergeLine) {
				for k := range l.Runs {
					l.Runs[k].Commits, l.Runs[k].Jobs = 1, l.Runs[k].Jobs[:1]
				}
			}},
		{name: "a commit not committed", plan: smoke, runs: 1, applies: true, want: "committed: false",
			edit: func(i int, l *ConvergeLine) { l.Runs[0].Jobs[4].Committed = false }},
		{name: "commits out of order", plan: smoke, runs: 1, applies: true, want: "the baseline",
			edit: func(i int, l *ConvergeLine) {
				j := l.Runs[0].Jobs
				j[0], j[1] = j[1], j[0]
			}},
		{name: "a Target missing", plan: smoke, runs: 1, applies: true, want: "19 Target runs",
			edit: func(i int, l *ConvergeLine) { l.Runs = l.Runs[1:] }},
		{name: "no run recorded", plan: smoke, runs: 0, applies: true, want: "no converge run recorded"},
		{name: "G9a's own profile", plan: DefaultPlan(), runs: 1, applies: false, want: "G9a's own profile"},
	} {
		t.Run(c.name, func(t *testing.T) {
			problems, applies, err := CheckCost(costRun(t, c.plan, c.runs, base, c.edit))
			if err != nil {
				t.Fatal(err)
			}
			text := strings.Join(problems, "\n")
			if applies != c.applies || (c.want == "") != (len(problems) == 0) || !strings.Contains(text, c.want) {
				t.Fatalf("applies %v, problems:\n%s\nwant applies %v and %q", applies, text, c.applies, c.want)
			}
		})
	}
}

// spread's median is the upper middle, as CheckCost reads it: never the
// minimum (rank given 0.5 for 50 made it so), and of an even count the
// upper of the two middle values, not their mean or the lower one.
func TestSpread(t *testing.T) {
	got := spread([]float64{131840, 131840, 152440, 160680, 160680, 168920, 201880})
	if want := (Spread{Min: 131840, Median: 160680, Max: 201880}); got != want {
		t.Fatalf("spread = %+v, want %+v", got, want)
	}
	if got := spread([]float64{4, 1, 3, 2}); got.Median != 3 {
		t.Fatalf("spread of 1..4: median %v, want 3 (the upper middle)", got.Median)
	}
	// The first CI run of the converge review (44083176486): 20 Targets,
	// the two middle values 156560 and 160680. The review and CheckCost
	// quote 160680.
	run1 := []float64{131840, 131840, 144200, 148320, 148320, 148320, 148320, 152440, 152440, 156560,
		160680, 168920, 168920, 168920, 168920, 173040, 177160, 185400, 189520, 201880}
	if got := spread(run1); got.Median != 160680 || got.Median != upperMedian(sortedCopy(run1)) {
		t.Fatalf("spread of the review's first run: median %v, want 160680", got.Median)
	}
	if got := spread(nil); got != (Spread{}) {
		t.Fatalf("spread(nil) = %+v", got)
	}
}

func sortedCopy(v []float64) []float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	return s
}
