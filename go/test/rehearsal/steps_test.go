// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// stepEnd is a migrate line that says how a step ended, and after how long
// (internal/migrate/progress.go). A released varlatch before 0.50.0-rc.3
// says none.
var stepEnd = regexp.MustCompile(`^(?:Done in|Failed after|Left to you after) [0-9hms]+: `)

// stepLines are stderr's step ends, in order.
func stepLines(stderr string) []string {
	var out []string
	for _, l := range strings.Split(stderr, "\n") {
		if l = strings.TrimRight(l, "\r"); stepEnd.MatchString(l) {
			out = append(out, l)
		}
	}
	return out
}

// migrateMode is what a migrate command does, by its options.
func migrateMode(args []string) string {
	for _, m := range []string{"--abort", "--resume", "--rollback", "--finish", "--dry-run", "--from-archive", "--status"} {
		if slices.Contains(args, m) {
			return m
		}
	}
	return "the migration"
}

var stepRuns struct {
	sync.Mutex
	n int
}

// measureSteps puts into the report (redacted, as every measurement) how
// long each step of a varlatch migrate took: the check's own detail keeps
// the last lines of stderr only. In the order the commands ran.
func measureSteps(dir, name string, args []string, stderr string, took time.Duration) {
	if filepath.Base(name) != "varlatch" || len(args) == 0 || args[0] != "migrate" {
		return
	}
	lines := stepLines(stderr)
	if len(lines) == 0 {
		return
	}
	stepRuns.Lock()
	stepRuns.n++
	n := stepRuns.n
	stepRuns.Unlock()
	measure(fmt.Sprintf("steps %02d: %s: %s (%s)", n, filepath.Base(filepath.Dir(dir)), migrateMode(args), took.Round(time.Millisecond)), strings.Join(lines, " / "))
}
