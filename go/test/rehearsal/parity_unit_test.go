// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParityAccountsForEndedBrowserSessions(t *testing.T) {
	makeExport := func(rows, digests, decisions int64) exportCounts {
		var s exportCounts
		s.Bundle.Tables = 58
		s.Bundle.Rows = rows
		s.Bundle.Digests = digests
		s.Bundle.Decisions = decisions
		return s
	}
	makeCopy := func(copied, ended, checkedRows, digests, decisions int64) journalCopy {
		c := journalCopy{
			Tables:        58,
			Rows:          copied,
			SessionsEnded: ended,
		}
		c.Checks = &struct {
			Passed bool `json:"passed"`
			Checks []struct {
				Name    string `json:"name"`
				Passed  bool   `json:"passed"`
				Checked int64  `json:"checked"`
			} `json:"checks"`
			Faults []string `json:"faults"`
		}{
			Passed: true,
			Checks: []struct {
				Name    string `json:"name"`
				Passed  bool   `json:"passed"`
				Checked int64  `json:"checked"`
			}{
				{Name: "rows", Passed: true, Checked: checkedRows},
				{Name: "encryption-classes", Passed: true, Checked: digests},
				{Name: "audit", Passed: true, Checked: 800},
				{Name: "authorization", Passed: true, Checked: decisions},
				{Name: "authentication", Passed: true, Checked: 25},
			},
		}
		return c
	}

	// Exact match with ended browser sessions: 1,000 + 17 == 1,017.
	ok, detail := parity(makeExport(1017, 42, 500), makeCopy(1000, 17, 1017, 42, 500))
	if !ok {
		t.Fatalf("parity with ended sessions should pass: %s", detail)
	}
	if !strings.Contains(detail, "17 sessions ended") {
		t.Errorf("detail should record sessions ended: %s", detail)
	}

	// Zero ended sessions (seeded copies and post-rollback forward runs).
	if ok, detail := parity(makeExport(1050, 48, 520), makeCopy(1050, 0, 1050, 48, 520)); !ok {
		t.Fatalf("parity with 0 ended sessions should pass: %s", detail)
	}

	// Exact equality, never >=: any mismatch in copied + ended vs export fails.
	for _, tc := range []struct {
		name        string
		exportRows  int64
		copiedRows  int64
		ended       int64
		checkedRows int64
	}{
		{"export larger than copied plus ended", 1018, 1000, 17, 1018},
		{"export smaller than copied plus ended", 1016, 1000, 17, 1016},
		{"ended count too low by one", 1017, 1000, 16, 1017},
		{"ended count too high by one", 1017, 1000, 18, 1017},
		{"negative ended sessions refused", 999, 1000, -1, 999},
	} {
		if ok, detail := parity(makeExport(tc.exportRows, 42, 500), makeCopy(tc.copiedRows, tc.ended, tc.checkedRows, 42, 500)); ok {
			t.Errorf("%s: expected fail, got pass (%s)", tc.name, detail)
		}
	}

	// journalOf reads sessionsEnded on forward copy, and ignores it on reverse
	// export because reverse export deletes auth_sessions before writing the bundle.
	dir := t.TempDir()
	journalJSON := `{
  "copy": {
    "tables": 58,
    "rows": 1000,
    "sessionsEnded": 17,
    "checks": {
      "passed": true,
      "checks": [
        {"name": "rows", "passed": true, "checked": 1017},
        {"name": "encryption-classes", "passed": true, "checked": 42},
        {"name": "authorization", "passed": true, "checked": 500}
      ]
    }
  },
  "rollback": {
    "export": {
      "tables": 58,
      "rows": 1040,
      "sessionsEnded": 1
    },
    "checks": {
      "passed": true,
      "checks": [
        {"name": "rows", "passed": true, "checked": 1040},
        {"name": "encryption-classes", "passed": true, "checked": 48},
        {"name": "authorization", "passed": true, "checked": 520}
      ]
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "migration.json"), []byte(journalJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	fwd, rev, err := (&installation{dir: dir}).journalOf()
	if err != nil {
		t.Fatalf("journalOf: %v", err)
	}
	if ok, detail := parity(makeExport(1017, 42, 500), fwd); !ok {
		t.Errorf("forward journal parity failed: %s", detail)
	}
	if ok, detail := parity(makeExport(1040, 48, 520), rev); !ok {
		t.Errorf("reverse journal parity failed: %s", detail)
	}
}
