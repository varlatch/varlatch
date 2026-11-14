// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/query"
)

func openFile(t *testing.T, path string) *storage.DB {
	t.Helper()
	s, err := storage.Open(context.Background(), storage.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestInitCreatesTheSchemaOnceAndRecordsItsVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "varlatch.db")
	s := openFile(t, path)
	st, err := Init(context.Background(), s, "0.50.0")
	if err != nil || !st.Created || st.Version != SchemaVersion || st.CompatibleFrom != SchemaVersion {
		t.Fatalf("Init on a new file: %+v, %v", st, err)
	}
	v, err := query.New(s.Reader()).GetSchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.Version != SchemaVersion || v.CompatibleFrom != SchemaVersion || v.CreatedByRelease != "0.50.0" || v.UpdatedByRelease != "0.50.0" ||
		v.CreatedAt == 0 || v.CreatedAt != v.UpdatedAt {
		t.Fatalf("schema_version: %+v", v)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A restart finds the schema and leaves it as it is.
	s = openFile(t, path)
	defer s.Close()
	st, err = Init(context.Background(), s, "0.50.1")
	if err != nil || st.Created || st.Version != SchemaVersion {
		t.Fatalf("Init on an initialized file: %+v, %v", st, err)
	}
	again, err := query.New(s.Reader()).GetSchemaVersion(context.Background())
	if err != nil || again != v {
		t.Fatalf("schema_version changed: %+v, %v", again, err)
	}
}

// Two starts racing on a new file: one creates the schema, the other finds
// it (Init's check and creation are one job on the single writer).
func TestInitIsAtomic(t *testing.T) {
	s := openFile(t, filepath.Join(t.TempDir(), "varlatch.db"))
	defer s.Close()
	var wg sync.WaitGroup
	states := make([]State, 4)
	errs := make([]error, 4)
	for i := range states {
		wg.Add(1)
		go func() { defer wg.Done(); states[i], errs[i] = Init(context.Background(), s, "0.50.0") }()
	}
	wg.Wait()
	created := 0
	for i, st := range states {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if st.Created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("%d Init calls created the schema, want 1", created)
	}
}

func TestInitRefusesAForeignDatabase(t *testing.T) {
	s := openFile(t, filepath.Join(t.TempDir(), "other.db"))
	defer s.Close()
	exec(t, s, "CREATE TABLE notes (body TEXT) STRICT")
	if _, err := Init(context.Background(), s, "0.50.0"); !errors.Is(err, ErrNotVarlatch) {
		t.Fatalf("Init on another program's database: %v", err)
	}
}

func TestInitRefusesABadReleaseName(t *testing.T) {
	s := openFile(t, filepath.Join(t.TempDir(), "varlatch.db"))
	defer s.Close()
	for _, r := range []string{"", strings.Repeat("9", 65)} {
		if _, err := Init(context.Background(), s, r); err == nil {
			t.Fatalf("Init with release %q succeeded", r)
		}
	}
}

// A newer schema opens only if its compatible_from allows this varlatchd:
// a rollback-safe release (ADR-0059 Decision 8) leaves it at the version
// before its own.
func TestInitChecksANewerSchema(t *testing.T) {
	s := openDB(t)
	exec(t, s, "UPDATE schema_version SET version = 2, compatible_from = 1")
	st, err := Init(context.Background(), s, testRelease)
	if err != nil || st.Version != 2 || st.Created {
		t.Fatalf("a rollback-safe newer schema: %+v, %v", st, err)
	}
	exec(t, s, "UPDATE schema_version SET compatible_from = 2")
	_, err = Init(context.Background(), s, testRelease)
	var ve *VersionError
	if !errors.As(err, &ve) || ve.Database != 2 || ve.CompatibleFrom != 2 || ve.Binary != SchemaVersion {
		t.Fatalf("a newer schema that is not compatible: %v", err)
	}
	if !strings.Contains(err.Error(), "needs a varlatchd that knows version 2") {
		t.Fatalf("message: %v", err)
	}
	older := &VersionError{Database: 1, CompatibleFrom: 1, Binary: 2}
	if !strings.Contains(older.Error(), "older than this varlatchd's 2; run varlatch upgrade") {
		t.Fatalf("message: %v", older)
	}
}

// Foreign keys hold inside write jobs (lib/storage turns them on for every
// connection), and the schema's tables are all STRICT.
func TestSchemaRules(t *testing.T) {
	s := openDB(t)
	refusedBy(t, tryExec(s, "INSERT INTO credentials (id, identity_id, kind, token_hash) VALUES ('crd_x', 'idn_missing', 'cli', 'h')"),
		"FOREIGN KEY constraint failed")
	exec(t, s, "INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'A')")
	refusedBy(t, tryExec(s, "INSERT INTO credentials (id, identity_id, kind, token_hash, created_at) VALUES ('crd_x', 'idn_a', 'cli', 'h', '2026-11-14')"),
		"cannot store TEXT value in INTEGER column")
	refusedBy(t, tryExec(s, "UPDATE identities SET disabled = 2"), "CHECK constraint failed")
	refusedBy(t, tryExec(s, "INSERT INTO roles (id, organization_id, name, actions) VALUES ('rol_a', 'org_a', 'r', '\"secret.use\"')"),
		"CHECK constraint failed")
	var n int
	if err := s.Reader().QueryRow("SELECT count(*) FROM pragma_table_list WHERE schema = 'main' AND type = 'table' AND name NOT LIKE 'sqlite%' AND strict = 0").Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d tables are not STRICT (%v)", n, err)
	}
}
