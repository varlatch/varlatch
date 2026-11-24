// SPDX-License-Identifier: AGPL-3.0-or-later

package migrate

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/canonical"
	"github.com/varlatch/varlatch/go/server/migration/check"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
	"github.com/varlatch/varlatch/go/server/migration/migrationtest"
)

// TestScale times the migration's steps at VARLATCH_SCALE_ROWS audit events
// of about 1.4 kB (off by default: it makes a database of hundreds of MB in
// VARLATCH_SCALE_DIR). With VARLATCH_SCALE_PROFILE, a CPU profile of each
// step is written there.
func TestScale(t *testing.T) {
	want, _ := strconv.Atoi(os.Getenv("VARLATCH_SCALE_ROWS"))
	if want == 0 {
		t.Skip("VARLATCH_SCALE_ROWS is not set")
	}
	base := os.Getenv("VARLATCH_SCALE_DIR")
	dir, err := os.MkdirTemp(base, "varlatch-scale-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	step := func(name string, fn func() error) {
		t.Helper()
		if p := os.Getenv("VARLATCH_SCALE_PROFILE"); p != "" {
			f, err := os.Create(filepath.Join(p, name+".pprof"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := pprof.StartCPUProfile(f); err != nil {
				t.Fatal(err)
			}
			defer pprof.StopCPUProfile()
		}
		at := time.Now()
		err := fn()
		t.Logf("%-28s %6.1f s", name, time.Since(at).Seconds())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	ctx := context.Background()
	s := migrationtest.Load(t)
	seed := migrationtest.Bundle(t, s, migrationtest.Options{})
	path := filepath.Join(dir, "bundle")
	scaleBundle(t, seed, path, want)
	if st, err := os.Stat(path); err == nil {
		t.Logf("bundle: %d MB", st.Size()>>20)
	}
	in, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	m, _ := manifest.Load()

	step("bundle.Verify", func() error { _, err := bundle.Verify(in, m); return err })
	step("decode", func() error {
		_, _ = in.Seek(0, 0)
		r, err := bundle.NewReader(in, m)
		if err != nil {
			return err
		}
		for range bundle.Tables(m) {
			tb, n, err := r.NextTable()
			if err != nil {
				return err
			}
			for range n {
				row, err := r.Row()
				if err == nil {
					_, err = bundle.Decode(tb, row)
				}
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	var res Result
	step("import", func() error {
		_, _ = in.Seek(0, 0)
		var err error
		res, err = Import(ctx, in, Options{DataDir: data, RootKEK: s.RootKEK, Release: "0.50.0-test"})
		return err
	})
	database := filepath.Join(data, config.DatabaseFile)
	if st, err := os.Stat(database); err == nil {
		t.Logf("%d rows; database: %d MB", res.Rows, st.Size()>>20)
	}
	var db *sql.DB
	if db, err = sql.Open("sqlite", "file:"+database+"?mode=ro"); err != nil {
		t.Fatal(err)
	}
	step("check", func() error {
		rep, err := check.Run(ctx, db, in, check.Options{RootKEK: s.RootKEK, RunKey: make([]byte, 32)})
		for _, c := range rep.Checks {
			t.Logf("  %s: passed %t, checked %d", c.Name, c.Passed, c.Checked)
		}
		// The synthetic bundle has no digests, so the classes fail by design;
		// the rows and the audit log do not.
		if err == nil && (!rep.Result(check.Rows).Passed || !rep.Result(check.Audit).Passed) {
			return fmt.Errorf("%+v", rep.Result(check.Rows).Failures)
		}
		return err
	})
	_ = db.Close()
	// Kept for server/backups' TestScaleBackup.
	if keep := os.Getenv("VARLATCH_SCALE_KEEP"); keep != "" {
		if err := copyFile(database, filepath.Join(keep, config.DatabaseFile)); err != nil {
			t.Fatal(err)
		}
	}
	step("snapshot, default pace", func() error {
		return scaleSnapshot(ctx, database, filepath.Join(dir, "a.db"), storage.SnapshotOptions{})
	})
	step("snapshot, unpaced", func() error {
		return scaleSnapshot(ctx, database, filepath.Join(dir, "b.db"), storage.SnapshotOptions{StepPages: 4096, Pause: time.Nanosecond})
	})
	step("export", func() error {
		out, err := os.Create(filepath.Join(dir, "reverse"))
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = ExportReverse(ctx, out, Options{DataDir: data, Release: "0.50.0-test"})
		return err
	})
}

func scaleSnapshot(ctx context.Context, path, to string, o storage.SnapshotOptions) error {
	db, err := storage.Open(ctx, storage.Options{Path: path})
	if err != nil {
		return err
	}
	_, err = db.Snapshot(ctx, to, o)
	if cerr := db.Close(); err == nil {
		err = cerr
	}
	return err
}

// scaleBundle writes seed again with audit events appended until there are
// want, each with a decision trace like a disclosure's.
func scaleBundle(t *testing.T, seed []byte, path string, want int) {
	t.Helper()
	m, err := manifest.Load()
	if err != nil {
		t.Fatal(err)
	}
	r, err := bundle.NewReader(bytes.NewReader(seed), m)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	h := r.Header()
	h.FrozenPoint.AuditPosition = int64(want)
	w, err := bundle.NewWriter(out, m, h)
	if err != nil {
		t.Fatal(err)
	}
	for range bundle.Tables(m) {
		tb, n, err := r.NextTable()
		if err != nil {
			t.Fatal(err)
		}
		total := n
		if tb.Source == "audit_events" {
			total = want
		}
		if err := w.Table(tb.Source, total); err != nil {
			t.Fatal(err)
		}
		var last []any
		for range n {
			row, err := r.Row()
			if err != nil {
				t.Fatal(err)
			}
			if last, err = bundle.Decode(tb, row); err != nil {
				t.Fatal(err)
			}
			if err := w.Row(row); err != nil {
				t.Fatal(err)
			}
		}
		if tb.Source != "audit_events" {
			continue
		}
		at := map[string]int{}
		for i, c := range tb.Columns {
			at[c.Source] = i
		}
		for i := n + 1; i <= want; i++ {
			v := append([]any(nil), last...)
			v[at["id"]] = fmt.Sprintf("evt_%024x", uint64(i)*0x9E3779B97F4A7C15)
			v[at["event_order"]] = int64(i)
			v[at["event_type"]] = "secret.disclosed"
			v[at["decision"]] = "allow"
			v[at["request_id"]] = fmt.Sprintf("req_%032x", uint64(i)*0xD1B54A32D192ED03)
			v[at["organization_id"]] = fmt.Sprintf("org_%026d", i%7)
			v[at["actor_identity_id"]] = fmt.Sprintf("idn_%026d", i%40)
			v[at["resource"]] = string(jsvalue.Stringify(jsvalue.Jsonb(jsvalue.Object{{Key: "id", Value: fmt.Sprintf("env_%026d", i%30)}, {Key: "type", Value: "environment"}, {Key: "projectId", Value: "prj_00000000000000000000000001"}})))
			v[at["authz"]] = string(jsvalue.Stringify(jsvalue.Jsonb(scaleTrace(i))))
			v[at["metadata"]] = string(jsvalue.Stringify(jsvalue.Jsonb(jsvalue.Object{{Key: "keys", Value: strings.Repeat("EXAMPLE_NAME,", 12)}, {Key: "count", Value: float64(12)}, {Key: "versionId", Value: fmt.Sprintf("ver_%026d", i)}})))
			row, err := canonical.AppendRow(nil, tb.Types(), v)
			if err != nil {
				t.Fatal(err)
			}
			if err := w.Row(row); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Digests(0); err != nil {
		t.Fatal(err)
	}
	if err := w.Decisions(0, 1); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func scaleTrace(i int) jsvalue.Object {
	var grants []any
	for j := range 4 {
		grants = append(grants, jsvalue.Object{{Key: "id", Value: fmt.Sprintf("rol_%026d", i%50+j)}, {Key: "role", Value: "environment.reader"},
			{Key: "scope", Value: "environment"}, {Key: "scopeId", Value: fmt.Sprintf("env_%026d", i%30)}, {Key: "version", Value: float64(j)}})
	}
	return jsvalue.Object{{Key: "version", Value: float64(1)}, {Key: "policy", Value: "default"}, {Key: "grants", Value: grants},
		{Key: "requirements", Value: []any{}}, {Key: "principal", Value: fmt.Sprintf("idn_%026d", i%40)}}
}
