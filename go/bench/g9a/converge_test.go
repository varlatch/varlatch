// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
