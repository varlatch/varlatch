// SPDX-License-Identifier: AGPL-3.0-or-later

// Package paritytest is the Go side of the parity kit (ADR-0059 step 4,
// feature-parity decision 3): it loads a fixture that the TypeScript
// server wrote (services/varlatchd/test/go-fixture-kit.ts) into a Go
// database through the schema mapping, replays its table of requests
// against varlatchd, and requires the same answers: the status, the
// headers that matter, the body byte for byte, the audit events, the rows
// each request added or changed in the slice's side tables, and the
// Security Control report counts. What a write makes that the file cannot
// fix (new IDs, times, envelopes) is normalized as the TypeScript side
// normalizes it (Normalizer). Test support only: nothing in a build
// imports it.
//
// A slice uses it so: the TypeScript test builds a database through /v1
// and records its table (go-core-fixture.test.ts for step 4.1); the Go
// test reads the file, Prepares a database from its rows, builds the
// server on it and calls Replay. testdata holds the files.
package paritytest

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

// SideTable is a table whose inserted, updated and deleted rows each
// request records, diffed by its primary key (Key) and ordered by a stable
// semantic key (SortBy) before new IDs are numbered.
type SideTable struct {
	Name   string   `json:"name"`
	Key    []string `json:"key"`
	SortBy []string `json:"sortBy"`
	// Volatile columns hold what a write cannot fix (a time, an envelope).
	Volatile []string `json:"volatile,omitempty"`
}

// Recorded is one request of the table and the TypeScript server's answer.
type Recorded struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Method     string  `json:"method"`
	Path       string  `json:"path"`
	Credential string  `json:"credential"`
	Body       *any    `json:"body,omitempty"`
	RawBody    *string `json:"rawBody,omitempty"`
	UserAgent  string  `json:"userAgent,omitempty"`
	// Concurrent requests are sent this many times at once; Answers holds
	// every answer, sorted, and Expect the first.
	Concurrent int      `json:"concurrent,omitempty"`
	Expect     answer   `json:"expect"`
	Answers    []answer `json:"answers,omitempty"`
	Audit      []Row    `json:"audit"`
	// Side is, per side table, the "inserted", "updated" and "deleted"
	// rows, normalized, in PostgreSQL's form.
	Side map[string]map[string][]Row `json:"side"`
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

// Fixture is one file the kit wrote.
type Fixture struct {
	Comment    string            `json:"comment"`
	Ref        string            `json:"ref"`
	RootKEK    string            `json:"rootKek"`
	Tokens     map[string]string `json:"tokens"`
	Rows       map[string][]Row  `json:"rows"`
	SideTables []SideTable       `json:"sideTables"`
	Requests   []Recorded        `json:"requests"`
	Counters   []Row             `json:"counters"`
}

// CLIAgent is the User-Agent a request sends when it names none.
const CLIAgent = "varlatch-cli/0.22.0 (linux; x64)"

func here() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

// Path is a file of this package's testdata.
func Path(name string) string { return filepath.Join(here(), "testdata", name) }

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

func readMapping() (mapping, error) {
	var m mapping
	raw, err := os.ReadFile(filepath.Join(here(), "..", "db", "mapping.json"))
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(raw, &m)
}

var isoTime = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$`)

// Prepare makes the database file at path: the schema (db.Init), then the
// rows of tables, each PostgreSQL table and column by its mapping
// (go/server/db/mapping.json), as the migration will copy them: booleans
// as 0 and 1, times as microseconds, jsonb and arrays as JSON text. The
// rows' foreign keys are the source database's, so they are not checked
// while loading. The file is closed when Prepare returns, its WAL
// truncated.
func Prepare(path string, rows map[string][]Row, tables []string) error {
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
	m, err := readMapping()
	if err != nil {
		return err
	}
	conn, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(0)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)")
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, table := range tables {
		tm, ok := m.Tables[table]
		if !ok {
			return fmt.Errorf("no mapping for %s", table)
		}
		for _, r := range rows[table] {
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
				v, err := SQLiteValue(r[pg])
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

// SQLiteValue is a PostgreSQL value as the schema mapping stores it.
func SQLiteValue(v any) (any, error) {
	switch x := v.(type) {
	case bool:
		if x {
			return int64(1), nil
		}
		return int64(0), nil
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
