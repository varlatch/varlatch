// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db"
)

// setSchema writes the database's schema_version directly, varlatchd
// stopped: a database another release left.
func setSchema(t *testing.T, in install, version, compatibleFrom int64) {
	t.Helper()
	s, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(in.data, "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Write(context.Background(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(context.Background(), "UPDATE schema_version SET version = ?, compatible_from = ?", version, compatibleFrom)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

type statusDoc struct {
	Binary struct {
		SchemaVersion  int64 `json:"schemaVersion"`
		CompatibleFrom int64 `json:"compatibleFrom"`
	} `json:"binary"`
	Database *struct {
		SchemaVersion    int64  `json:"schemaVersion"`
		CompatibleFrom   int64  `json:"compatibleFrom"`
		CreatedByRelease string `json:"createdByRelease"`
	} `json:"database"`
	Opens        bool `json:"opens"`
	NeedsUpgrade bool `json:"needsUpgrade"`
}

func schemaStatus(t *testing.T, in install) statusDoc {
	t.Helper()
	code, out, errOut := runAdmin(t, "schema", "status", "--json", "--config", in.conf)
	var doc statusDoc
	if code != ExitOK || json.Unmarshal([]byte(out), &doc) != nil {
		t.Fatalf("schema status --json: %d %q %q", code, out, errOut)
	}
	if doc.Binary.SchemaVersion != db.SchemaVersion || doc.Binary.CompatibleFrom != db.CompatibleFrom {
		t.Fatalf("binary: %+v", doc.Binary)
	}
	return doc
}

func TestAdminSchemaBeforeTheDatabase(t *testing.T) {
	in := newInstall(t, "")
	if doc := schemaStatus(t, in); doc.Database != nil || !doc.Opens || doc.NeedsUpgrade {
		t.Fatalf("%+v", doc)
	}
	code, out, _ := runAdmin(t, "schema", "status", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, "Database: none yet") {
		t.Fatalf("%d %q", code, out)
	}
	code, out, errOut := runAdmin(t, "schema", "upgrade", "--config", in.conf)
	if code != ExitFailure || out != "" || !strings.Contains(errOut, "there is no database at") {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); !os.IsNotExist(err) {
		t.Fatalf("upgrade created a database: %v", err)
	}
}

func TestAdminSchemaStatusAndUpgrade(t *testing.T) {
	in := newInstall(t, "")
	r := start(t, in)
	// status reads beside a running varlatchd; upgrade is refused.
	if doc := schemaStatus(t, in); doc.Database == nil || doc.Database.SchemaVersion != db.SchemaVersion || !doc.Opens || doc.NeedsUpgrade {
		t.Fatalf("status beside varlatchd: %+v", doc)
	}
	code, _, errOut := runAdmin(t, "schema", "upgrade", "--config", in.conf)
	if code != ExitFailure || !strings.Contains(errOut, "varlatchd is running on") || !strings.Contains(errOut, "nothing was written") {
		t.Fatalf("upgrade beside varlatchd: %d %q", code, errOut)
	}
	r.stop(t)

	code, out, errOut := runAdmin(t, "schema", "upgrade", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, "already version 1: nothing to do") {
		t.Fatalf("upgrade of a current database: %d %q %q", code, out, errOut)
	}
	code, out, _ = runAdmin(t, "schema", "upgrade", "--json", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"from":1,"to":1,"compatibleFrom":1,"changed":false`) {
		t.Fatalf("upgrade --json: %d %q", code, out)
	}

	// A newer database a rollback-safe release wrote: this varlatchd opens
	// it, and upgrade leaves it alone.
	setSchema(t, in, db.SchemaVersion+1, db.SchemaVersion)
	if doc := schemaStatus(t, in); !doc.Opens || doc.NeedsUpgrade || doc.Database.SchemaVersion != db.SchemaVersion+1 {
		t.Fatalf("a rollback-safe newer database: %+v", doc)
	}
	if code, out, _ = runAdmin(t, "schema", "upgrade", "--config", in.conf); code != ExitOK || !strings.Contains(out, "this varlatchd may open it: nothing to do") {
		t.Fatalf("%d %q", code, out)
	}
	start(t, in).stop(t)

	// One it may not open: status says so, upgrade refuses, serve refuses.
	setSchema(t, in, db.SchemaVersion+1, db.SchemaVersion+1)
	if doc := schemaStatus(t, in); doc.Opens || doc.NeedsUpgrade {
		t.Fatalf("a newer database it may not open: %+v", doc)
	}
	code, out, _ = runAdmin(t, "schema", "status", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, "This varlatchd cannot open it: it needs varlatchd of schema 2 or later.") {
		t.Fatalf("%d %q", code, out)
	}
	if code, _, errOut = runAdmin(t, "schema", "upgrade", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "needs a varlatchd that knows version 2") {
		t.Fatalf("%d %q", code, errOut)
	}
	// serve stops with a failure before it serves anything.
	served := make(chan struct{}, 1)
	done := make(chan int, 1)
	stderr := &syncBuffer{}
	go func() {
		done <- Serve(Options{ConfigPath: in.conf, Stderr: stderr, Signals: make(chan os.Signal, 1), Ready: func(net.Addr) { served <- struct{}{} }})
	}()
	select {
	case code := <-done:
		if code != ExitFailure || !strings.Contains(stderr.String(), "needs a varlatchd that knows version 2") {
			t.Fatalf("serve on a database it may not open: %d %q", code, stderr.String())
		}
	case <-served:
		t.Fatal("serve served a database it may not open")
	case <-time.After(30 * time.Second):
		t.Fatal("serve neither served nor stopped")
	}
}

func TestAdminSchemaUpgradeWaitsForARestore(t *testing.T) {
	in := newInstall(t, "")
	start(t, in).stop(t)
	if err := os.WriteFile(filepath.Join(in.data, backup.GateFile), []byte(`{"id":"g","kind":"restore","phase":"paused"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runAdmin(t, "schema", "upgrade", "--config", in.conf)
	if code != ExitFailure || !strings.Contains(errOut, "a restore has not completed") {
		t.Fatalf("%d %q", code, errOut)
	}
}

func TestAdminSchemaUsage(t *testing.T) {
	in := newInstall(t, "")
	for _, args := range [][]string{{"schema"}, {"schema", "migrate"}, {"schema", "status", "--json", "--json"}, {"schema", "upgrade", "--yes"}} {
		code, out, errOut := runAdmin(t, append(args, "--config", in.conf)...)
		if code != 64 || out != "" || !strings.Contains(errOut, "Usage: varlatchd admin schema status|upgrade [--json] [--config <file>]") {
			t.Errorf("%v: %d %q %q", args, code, out, errOut)
		}
	}
}
