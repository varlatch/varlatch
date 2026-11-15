// SPDX-License-Identifier: AGPL-3.0-or-later

// Package valuestest loads the read path's fixtures (go/server/values/
// testdata, written by services/varlatchd/test/go-values-fixture.test.ts)
// into a Go database, for the tests of go/server/values and the G7 tests
// of go/server/daemon. Test support only: nothing in a build imports it.
package valuestest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"

	"github.com/varlatch/varlatch/go/server/paritytest"
)

// Row is one row as PostgreSQL held it (JSON numbers kept as json.Number).
type Row = map[string]any

// Recorded is one request of the table and the TypeScript server's answer.
type Recorded struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Method     string  `json:"method"`
	Path       string  `json:"path"`
	Credential string  `json:"credential"`
	Body       *any    `json:"body,omitempty"`
	RawBody    *string `json:"rawBody,omitempty"`
	// UserAgent is the User-Agent sent; CLIAgent when empty.
	UserAgent string `json:"userAgent,omitempty"`
	Expect    struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	} `json:"expect"`
	Audit    []Row `json:"audit"`
	Exposure []Row `json:"exposure"`
}

// UnmarshalJSON tells a JSON null body from none.
func (r *Recorded) UnmarshalJSON(b []byte) error {
	type plain Recorded
	if err := json.Unmarshal(b, (*plain)(r)); err != nil {
		return err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return err
	}
	if raw, ok := probe["body"]; ok && r.Body == nil {
		var v any
		_ = json.Unmarshal(raw, &v)
		r.Body = &v
	}
	return nil
}

// Fixture is one file of testdata.
type Fixture struct {
	Comment    string            `json:"comment"`
	Ref        string            `json:"ref"`
	RootKEK    string            `json:"rootKek"`
	Tokens     map[string]string `json:"tokens"`
	Plaintexts map[string]string `json:"plaintexts"`
	Rows       map[string][]Row  `json:"rows"`
	Requests   []Recorded        `json:"requests"`
	Counters   []Row             `json:"counters"`
}

// Tables is the order the generator exports them in, which their foreign
// keys allow.
var Tables = []string{"installation", "identities", "user", "auth_user_links", "credentials", "organizations", "org_memberships", "projects",
	"environments", "contract_revisions", "env_values", "value_versions", "grants", "requirements", "security_controls", "organization_freezes"}

// CLIAgent is the CLI's User-Agent the table's requests send by default.
const CLIAgent = "varlatch-cli/0.22.0 (linux; x64)"

// here is this package's directory: testdata and the schema mapping are
// found from it, whichever package's test reads them.
func here() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

// Path is a file of go/server/values/testdata.
func Path(name string) string { return filepath.Join(here(), "..", "testdata", name) }

// Read reads a fixture file.
func Read(path string) (Fixture, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Fixture{}, err
	}
	var f Fixture
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	err = dec.Decode(&f)
	return f, err
}

// Prepare makes the database file at path from the fixture's rows
// (paritytest.Prepare, the parity kit's loader).
func Prepare(path string, f Fixture) error { return paritytest.Prepare(path, f.Rows, Tables) }

// Slugged returns the ID of the row of table whose slug is slug (and, for
// a Project, whose Organization is org).
func (f Fixture) Slugged(table, slug, org string) string {
	for _, r := range f.Rows[table] {
		if r["slug"] == slug && (org == "" || r["organization_id"] == org) {
			s, _ := r["id"].(string)
			return s
		}
	}
	return ""
}
