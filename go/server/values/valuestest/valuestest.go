// SPDX-License-Identifier: AGPL-3.0-or-later

// Package valuestest loads the read path's fixtures (go/server/values/
// testdata, written by services/varlatchd/test/go-values-fixture.test.ts)
// into a Go database, for the tests of go/server/values and the G7 tests
// of go/server/daemon. Test support only: nothing in a build imports it.
package valuestest

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db"
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

type mapping struct {
	Tables map[string]struct {
		SQLite  string                     `json:"sqlite"`
		Columns map[string]json.RawMessage `json:"columns"`
	} `json:"tables"`
}

var isoTime = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$`)

// Prepare makes the database file at path: the schema (db.Init), then the
// fixture's rows, each PostgreSQL table and column by its mapping
// (go/server/db/mapping.json), as the migration will copy them: booleans
// as 0 and 1, times as microseconds, jsonb and arrays as JSON text. The
// rows' foreign keys are the source database's, so they are not checked
// while loading. The file is closed when Prepare returns, its WAL
// truncated.
func Prepare(path string, f Fixture) error {
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: path})
	if err != nil {
		return err
	}
	if _, err := db.Init(ctx, store, "test"); err != nil {
		_ = store.Close()
		return err
	}
	if err := store.Close(); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(here(), "..", "..", "db", "mapping.json"))
	if err != nil {
		return err
	}
	var m mapping
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	conn, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(0)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)")
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, table := range Tables {
		tm, ok := m.Tables[table]
		if !ok {
			return fmt.Errorf("no mapping for %s", table)
		}
		for _, r := range f.Rows[table] {
			keys := make([]string, 0, len(r))
			for k := range r {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var cols, marks []string
			var args []any
			for _, pg := range keys {
				var col string
				if err := json.Unmarshal(tm.Columns[pg], &col); err != nil {
					return fmt.Errorf("%s.%s has no column name in the mapping: %w", table, pg, err)
				}
				v, err := sqliteValue(r[pg])
				if err != nil {
					return fmt.Errorf("%s.%s: %w", table, pg, err)
				}
				cols, marks, args = append(cols, col), append(marks, "?"), append(args, v)
			}
			q := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", tm.SQLite, strings.Join(cols, ", "), strings.Join(marks, ", "))
			if _, err := conn.Exec(q, args...); err != nil {
				return fmt.Errorf("%s: %w", q, err)
			}
		}
	}
	_, err = conn.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}

func sqliteValue(v any) (any, error) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case json.Number:
		return x.Int64()
	case string:
		if isoTime.MatchString(x) {
			ts, err := time.Parse(time.RFC3339Nano, x)
			if err != nil {
				return nil, err
			}
			return ts.UnixMicro(), nil
		}
		return x, nil
	case map[string]any, []any:
		b, err := json.Marshal(x)
		return string(b), err
	}
	return v, nil
}

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
