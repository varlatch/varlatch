// SPDX-License-Identifier: AGPL-3.0-or-later

package values_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
)

// goTestAll matches go.yml running every package's tests: go test, any
// flags without a package pattern (such as -count=1), then ./... .
var goTestAll = regexp.MustCompile(`go test (-[a-z]+(=\S+)? )*\./\.\.\.`)

// G3's matrix (testdata/g3-matrix.json): one entry per encryption class
// (each envelope purpose go/lib/envelope defines) × fixture release ×
// envelope version × direction, saying at which level it is proven
// (database: through both servers' code that reads the rows; envelope:
// lib/envelope's sealed fixtures) and naming the tests that prove it.
// TestG3Matrix fails when an entry names a test that does not exist or that
// CI does not run, and when a purpose or envelope version has no entry.
// TestG3Gate is the 0.50.0 gate's check, run unconditionally since every
// class it covers reached the database level (step 4.10, decision 9): it
// fails if any class but the JWT signing keys is proven at the envelope
// level only, so a later change cannot reopen an entry.

type g3Proof struct {
	Go     string `json:"go"`     // a Go test file, relative to go/
	Vitest string `json:"vitest"` // a vitest file, relative to the repository
	CI     string `json:"ci"`     // a workflow, relative to the repository
	Test   string `json:"test"`   // a Go test (Name or Name/subtest) or a vitest title
	Run    string `json:"run"`    // a command the workflow runs
}

type g3Entry struct {
	Purpose           string    `json:"purpose"`
	Class             string    `json:"class"`
	Release           string    `json:"release"`
	EnvelopeVersion   int       `json:"envelopeVersion"`
	Direction         string    `json:"direction"`
	Level             string    `json:"level"`
	Tests             []g3Proof `json:"tests"`
	FixtureKey        string    `json:"fixtureKey"`
	Reason            string    `json:"reason"`
	DatabaseLevelWith string    `json:"databaseLevelWith"`
}

type g3Matrix struct {
	Comment          string    `json:"comment"`
	Releases         []string  `json:"releases"`
	EnvelopeVersions []int     `json:"envelopeVersions"`
	Entries          []g3Entry `json:"entries"`
}

const repoRoot = "../../.." // from go/server/values

func readG3(t *testing.T) g3Matrix {
	t.Helper()
	b, err := os.ReadFile("testdata/g3-matrix.json")
	if err != nil {
		t.Fatal(err)
	}
	var m g3Matrix
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("g3-matrix.json: %v", err)
	}
	return m
}

// envelopePurposes are the purposes go/lib/envelope defines (its Purpose*
// constants), read from its source so a new one cannot be left out.
func envelopePurposes(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("../../lib/envelope/context.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range regexp.MustCompile(`(?m)^\s*Purpose\w+\s*=\s*"([^"]+)"`).FindAllStringSubmatch(string(b), -1) {
		out = append(out, m[1])
	}
	if len(out) < 10 {
		t.Fatalf("found %d purposes in lib/envelope/context.go: the pattern no longer matches its constants", len(out))
	}
	return out
}

func readText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return string(b)
}

// checkProof reports why a proof does not hold: its test is missing, or
// CI does not run it.
func checkProof(t *testing.T, p g3Proof, workflow string) error {
	switch {
	case p.Go != "":
		src := readText(t, filepath.Join("../..", p.Go))
		if regexp.MustCompile(`(?m)^//go:build`).MatchString(src) {
			return fmt.Errorf("%s has a build constraint: go test ./... does not run it", p.Go)
		}
		name, sub, _ := strings.Cut(p.Test, "/")
		if !strings.Contains(src, "func "+name+"(t *testing.T)") {
			return fmt.Errorf("%s has no test %s", p.Go, name)
		}
		if sub != "" && !strings.Contains(src, sub) {
			return fmt.Errorf("%s: test %s has no subtest %q", p.Go, name, sub)
		}
		if !goTestAll.MatchString(workflow) {
			return fmt.Errorf("go.yml no longer runs go test ./...")
		}
	case p.Vitest != "":
		src := readText(t, filepath.Join(repoRoot, p.Vitest))
		title := regexp.QuoteMeta(fmt.Sprintf("%q", p.Test))
		if !regexp.MustCompile(`\bit(\.skipIf\([^)]*\))?\(\s*` + title).MatchString(src) {
			return fmt.Errorf("%s has no test %q", p.Vitest, p.Test)
		}
		rel := strings.TrimPrefix(p.Vitest, "services/varlatchd/")
		if !strings.Contains(workflow, "vitest run "+rel) {
			return fmt.Errorf("go.yml does not run %s", p.Vitest)
		}
	case p.CI != "":
		if p.CI != ".github/workflows/go.yml" {
			return fmt.Errorf("unknown workflow %s", p.CI)
		}
		if p.Run == "" || !strings.Contains(workflow, p.Run) {
			return fmt.Errorf("go.yml does not run %q", p.Run)
		}
	default:
		return fmt.Errorf("a proof names no Go test, vitest test or CI command")
	}
	return nil
}

// fixtureHas reports whether a release's envelope fixture (lib/envelope
// testdata, sealed by that release's TypeScript code) holds key, at its top
// or in an Organization, non-empty.
func fixtureHas(t *testing.T, release, key string) bool {
	t.Helper()
	var f map[string]any
	if err := json.Unmarshal([]byte(readText(t, "../../lib/envelope/testdata/ts-"+release+".json")), &f); err != nil {
		t.Fatal(err)
	}
	nonEmpty := func(v any) bool {
		switch x := v.(type) {
		case nil:
			return false
		case []any:
			return len(x) > 0
		}
		return true
	}
	if nonEmpty(f[key]) {
		return true
	}
	orgs, _ := f["organizations"].([]any)
	for _, o := range orgs {
		if m, ok := o.(map[string]any); ok && nonEmpty(m[key]) {
			return true
		}
	}
	return false
}

func TestG3Matrix(t *testing.T) {
	m := readG3(t)
	workflow := readText(t, filepath.Join(repoRoot, ".github/workflows/go.yml"))
	if !slices.Equal(m.EnvelopeVersions, []int{envelope.FormatVersion}) {
		t.Errorf("envelope versions %v, lib/envelope has %d", m.EnvelopeVersions, envelope.FormatVersion)
	}
	if !slices.Equal(m.Releases, []string{"v0.21.0", "v0.22.0"}) {
		t.Errorf("releases %v", m.Releases)
	}
	purposes := envelopePurposes(t)
	seen := map[string]bool{}
	for i, e := range m.Entries {
		key := fmt.Sprintf("%s %s v%d %s", e.Purpose, e.Release, e.EnvelopeVersion, e.Direction)
		where := fmt.Sprintf("entry %d (%s)", i, key)
		if seen[key] {
			t.Errorf("%s: twice", where)
		}
		seen[key] = true
		if !slices.Contains(purposes, e.Purpose) {
			t.Errorf("%s: lib/envelope has no purpose %q", where, e.Purpose)
		}
		if e.Class == "" {
			t.Errorf("%s: no class", where)
		}
		switch e.Level {
		case "database", "envelope":
			if len(e.Tests) == 0 {
				t.Errorf("%s: no test proves it", where)
			}
			for _, p := range e.Tests {
				if err := checkProof(t, p, workflow); err != nil {
					t.Errorf("%s: %v", where, err)
				}
			}
			if e.Level == "envelope" && e.DatabaseLevelWith == "" {
				t.Errorf("%s: envelope-level without the step that makes it database-level", where)
			}
			if e.Level == "envelope" && e.Direction == "ts-to-go" && (e.FixtureKey == "" || !fixtureHas(t, e.Release, e.FixtureKey)) {
				t.Errorf("%s: the %s envelope fixture holds no %q", where, e.Release, e.FixtureKey)
			}
		case "not-in-release":
			if e.FixtureKey == "" || fixtureHas(t, e.Release, e.FixtureKey) {
				t.Errorf("%s: not in the release, but the %s envelope fixture holds %q", where, e.Release, e.FixtureKey)
			}
		case "not-applicable":
			if e.Reason == "" {
				t.Errorf("%s: not applicable, with no reason", where)
			}
		default:
			t.Errorf("%s: unknown level %q", where, e.Level)
		}
	}
	for _, p := range purposes {
		for _, r := range m.Releases {
			for _, v := range m.EnvelopeVersions {
				for _, d := range []string{"ts-to-go", "go-to-ts"} {
					if key := fmt.Sprintf("%s %s v%d %s", p, r, v, d); !seen[key] {
						t.Errorf("no entry for %s", key)
					}
				}
			}
		}
	}
}

// TestG3Gate is the 0.50.0 gate's G3 check: every class but the JWT
// signing keys (only Convex uses them) must be proven at the database level
// in both directions by then.
func TestG3Gate(t *testing.T) {
	for _, e := range readG3(t).Entries {
		if e.Level == "envelope" && e.Purpose != envelope.PurposeJWTSigningKey {
			t.Errorf("%s (%s, %s, %s): proven at the envelope level only; database level due with %s", e.Class, e.Purpose, e.Release, e.Direction, e.DatabaseLevelWith)
		}
	}
}
