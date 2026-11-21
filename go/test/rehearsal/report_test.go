// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// The report: each must-cover item's checks, what was measured, and every
// way the real TypeScript side differed from G5's stand-ins. It is written
// at the end, whatever passed. Nothing secret goes in: what it quotes from
// a program's output is filtered by redact first.

type check struct {
	Item   int    `json:"item"`
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

type difference struct {
	Item    int    `json:"item"`
	StandIn string `json:"standIn"`
	Real    string `json:"real"`
	Bearing string `json:"bearing"`
}

var report struct {
	sync.Mutex
	Run          string            `json:"run"`
	Started      time.Time         `json:"started"`
	Finished     time.Time         `json:"finished"`
	Images       map[string]string `json:"images"`
	Checks       []check           `json:"checks"`
	Measurements map[string]string `json:"measurements"`
	Differences  []difference      `json:"differences"`
}

// passed records a check; failed records a failed one (and fails t, but
// carries on: the report wants every item).
func record(t *testing.T, item int, name string, ok bool, detail string) {
	t.Helper()
	report.Lock()
	report.Checks = append(report.Checks, check{Item: item, Name: name, Passed: ok, Detail: redact(detail)})
	report.Unlock()
	if !ok {
		t.Errorf("item %d, %s: %s", item, name, redact(detail))
	} else {
		t.Logf("item %d, %s: ok %s", item, name, redact(detail))
	}
}

func measure(name, value string) {
	report.Lock()
	defer report.Unlock()
	if report.Measurements == nil {
		report.Measurements = map[string]string{}
	}
	report.Measurements[name] = value
}

func differs(item int, standIn, real, bearing string) {
	report.Lock()
	defer report.Unlock()
	report.Differences = append(report.Differences, difference{Item: item, StandIn: standIn, Real: redact(real), Bearing: bearing})
}

// secrets is every value of the run's that must never reach the report:
// registered as they are generated.
var secrets struct {
	sync.Mutex
	values []string
}

func secret(v string) string {
	secrets.Lock()
	secrets.values = append(secrets.values, v)
	secrets.Unlock()
	return v
}

var tokenShaped = regexp.MustCompile(`\b(vlt_[A-Za-z0-9_]{8,}|[0-9a-f]{40,})\b`)

// redact removes every registered secret and anything token-shaped (a
// Varlatch token, a long hex string: keys, run keys, digests of secrets).
func redact(s string) string {
	secrets.Lock()
	for _, v := range secrets.values {
		if len(v) >= 6 {
			s = strings.ReplaceAll(s, v, "[redacted]")
		}
	}
	secrets.Unlock()
	return tokenShaped.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, "vlt_") {
			return "[token]"
		}
		return m[:8] + "[...]"
	})
}

func writeReport(t *testing.T) {
	report.Lock()
	defer report.Unlock()
	report.Finished = time.Now().UTC()
	if err := os.MkdirAll(reportDir, 0o700); err != nil {
		t.Error(err)
		return
	}
	b, _ := json.MarshalIndent(&report, "", "  ")
	if err := os.WriteFile(filepath.Join(reportDir, "report.json"), append(b, '\n'), 0o600); err != nil {
		t.Error(err)
	}
	var md strings.Builder
	fmt.Fprintf(&md, "# Real-source rehearsal %s\n\n%s to %s (UTC). Images:\n\n", report.Run, report.Started.Format(time.RFC3339), report.Finished.Format(time.RFC3339))
	for name, ref := range report.Images {
		fmt.Fprintf(&md, "- %s: `%s`\n", name, ref)
	}
	passed := 0
	for _, c := range report.Checks {
		if c.Passed {
			passed++
		}
	}
	fmt.Fprintf(&md, "\n## Checks: %d of %d passed\n\n| Item | Check | Result | Detail |\n| --- | --- | --- | --- |\n", passed, len(report.Checks))
	for _, c := range report.Checks {
		res := "pass"
		if !c.Passed {
			res = "**FAIL**"
		}
		fmt.Fprintf(&md, "| %d | %s | %s | %s |\n", c.Item, c.Name, res, strings.ReplaceAll(c.Detail, "|", "\\|"))
	}
	fmt.Fprintf(&md, "\n## Measurements\n\n")
	for k, v := range report.Measurements {
		fmt.Fprintf(&md, "- %s: %s\n", k, v)
	}
	fmt.Fprintf(&md, "\n## Where the real TypeScript side differs from G5's stand-ins\n\n")
	if len(report.Differences) == 0 {
		md.WriteString("None found.\n")
	}
	for _, d := range report.Differences {
		fmt.Fprintf(&md, "- **Item %d.** Stand-in: %s Real: %s Bearing: %s\n", d.Item, d.StandIn, d.Real, d.Bearing)
	}
	if err := os.WriteFile(filepath.Join(reportDir, "report.md"), []byte(md.String()), 0o600); err != nil {
		t.Error(err)
	}
}
