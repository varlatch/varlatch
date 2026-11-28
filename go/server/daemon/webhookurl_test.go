// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/keyenv"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/webhooks"
	"github.com/varlatch/varlatch/go/server/write"
)

// The release before schema 8 (0.51.0, schema 7) reads and writes webhooks
// with these statements (its queries/webhooks.sql): url only. After a
// rollback it runs them on the schema-8 database, which it may open
// (compatible from 1).
const (
	previousListWebhooks = `SELECT id, organization_id, url, event_types, created_at, revoked_at, failure_count, last_attempt_at, last_status, version, updated_at
FROM webhooks WHERE organization_id = ? AND revoked_at IS NULL
ORDER BY created_at, id`
	previousDeliverableWebhooks = `SELECT w.id, w.organization_id, w.url, w.event_types, w.secret_envelope, w.cursor_order
FROM webhooks w JOIN organizations o ON o.id = w.organization_id
WHERE w.revoked_at IS NULL AND w.suspended_by_deletion IS NULL AND o.deleted_at IS NULL
ORDER BY w.created_at, w.id`
	previousInsertWebhook = `INSERT INTO webhooks (id, organization_id, url, event_types, secret_envelope, created_by, created_at, cursor_occurred_at, cursor_event_id, cursor_order)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	previousUpdateWebhook = `UPDATE webhooks SET url = ?, event_types = ?, version = version + 1, updated_at = ?
WHERE id = ? RETURNING version, updated_at`
)

// webhookURLs is every webhook's url and url_envelope, by id.
func webhookURLs(t *testing.T, in install) map[string][2]sql.NullString {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+filepath.Join(in.data, "varlatch.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rows, err := conn.Query(`SELECT id, url, url_envelope FROM webhooks`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][2]sql.NullString{}
	for rows.Next() {
		var id string
		var url, sealed sql.NullString
		if err := rows.Scan(&id, &url, &sealed); err != nil {
			t.Fatal(err)
		}
		out[id] = [2]sql.NullString{url, sealed}
	}
	return out
}

// withStore runs f on the stopped installation's database.
func withStore(t *testing.T, in install, f func(ctx context.Context, w *write.Writer)) {
	t.Helper()
	ctx := context.Background()
	s, err := storage.Open(ctx, storage.Options{Path: filepath.Join(in.data, "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	f(ctx, &write.Writer{Store: s, Gates: write.NewGates()})
}

// installRootKEK is the installation's Root KEK, from its key file.
func installRootKEK(t *testing.T, in install) []byte {
	t.Helper()
	material, err := os.ReadFile(in.kekFile)
	if err != nil {
		t.Fatal(err)
	}
	k, err := envelope.ParseRootKEK(string(material))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// startSealed starts varlatchd and waits until every webhook of a live
// Organization has an envelope of its url (the start pass), then stops it.
func startSealed(t *testing.T, in install, org string) {
	t.Helper()
	r := start(t, in)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if all := webhookURLs(t, in); sealedAll(t, in, org, all) {
			break
		}
		if time.Now().After(deadline) {
			r.stop(t)
			t.Fatalf("the start pass did not seal every webhook URL: %s", r.stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	r.stop(t)
}

// sealedAll is whether every row's envelope opens to its url.
func sealedAll(t *testing.T, in install, org string, all map[string][2]sql.NullString) bool {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+filepath.Join(in.data, "varlatch.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	urls := webhooks.NewURLs(installRootKEK(t, in), conn)
	defer urls.Close()
	for id, v := range all {
		if !v[1].Valid {
			return false
		}
		got, err := urls.Of(context.Background(), org, id, "", v[1])
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if got != v[0].String {
			return false
		}
	}
	return true
}

// Schema 8 is rollback-safe for webhook URLs. A database of the release
// before (schema 7) is upgraded at start in the image, and its URLs sealed
// at start; url stays filled, so the release before, rolled back to, reads
// the same webhooks with its own statements and writes them; rolled
// forward again, varlatchd seals what it wrote (a new webhook, a changed
// URL) at start, and a start after that writes nothing.
func TestWebhookURLsAcrossARollback(t *testing.T) {
	t.Setenv(keyenv.ImageMarker, "varlatchd")
	if !db.RollbackSafeFrom(db.SchemaVersion - 1) {
		t.Fatal("schema 8 must be rollback-safe")
	}
	in := newInstall(t, "")
	start(t, in).stop(t)
	rootKEK := installRootKEK(t, in)
	var org string
	withStore(t, in, func(ctx context.Context, w *write.Writer) {
		if err := w.Store.Write(ctx, func(tx *storage.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice')`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		o, err := orgs.Create(ctx, w, rootKEK, "idn_a", "acme", "Acme")
		if err != nil {
			t.Fatal(err)
		}
		org = o.ID
	})
	// The release before: schema 7, a webhook as it writes one. Its URL is
	// on loopback, which the outbound policy refuses without a request.
	previousSchema(t, in)
	if _, err := sqlExec(t, in, previousInsertWebhook, "whk_old", org, "http://127.0.0.1:9/old?token=one", nil, "{}", "idn_a", 1, 1, "", 0); err != nil {
		t.Fatal(err)
	}

	// This release: upgraded and sealed at start; url kept.
	startSealed(t, in, org)
	if got := readRecorded(t, in); got.version != db.SchemaVersion {
		t.Fatalf("not upgraded: %+v", got)
	}
	if v := webhookURLs(t, in)["whk_old"]; v[0].String != "http://127.0.0.1:9/old?token=one" {
		t.Fatalf("url after the start pass: %q", v[0].String)
	}

	// Rolled back: the release before reads url, as this release left it,
	// and writes url only.
	var listed []string
	rows := sqlQuery(t, in, previousListWebhooks, org)
	for _, r := range rows {
		listed = append(listed, r[2])
	}
	if len(listed) != 1 || listed[0] != "http://127.0.0.1:9/old?token=one" {
		t.Fatalf("the release before lists %v", listed)
	}
	if rows := sqlQuery(t, in, previousDeliverableWebhooks); len(rows) != 1 || rows[0][2] != "http://127.0.0.1:9/old?token=one" {
		t.Fatalf("the release before delivers to %v", rows)
	}
	if _, err := sqlExec(t, in, previousUpdateWebhook, "http://127.0.0.1:9/changed?token=two", nil, 2, "whk_old"); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlExec(t, in, previousInsertWebhook, "whk_new", org, "http://127.0.0.1:9/new?token=three", nil, "{}", "idn_a", 2, 2, "", 0); err != nil {
		t.Fatal(err)
	}

	// Rolled forward: the changed URL and the new webhook are sealed at
	// start; a start after that writes nothing.
	startSealed(t, in, org)
	after := webhookURLs(t, in)
	if after["whk_old"][0].String != "http://127.0.0.1:9/changed?token=two" || after["whk_new"][0].String != "http://127.0.0.1:9/new?token=three" {
		t.Fatalf("url rolled forward: %v", after)
	}
	startSealed(t, in, org)
	if again := webhookURLs(t, in); again["whk_old"] != after["whk_old"] || again["whk_new"] != after["whk_new"] {
		t.Fatal("a start with nothing to seal wrote an envelope again")
	}
}

// sqlExec runs one statement on the stopped installation's database, as
// another release's varlatchd would.
func sqlExec(t *testing.T, in install, q string, args ...any) (int64, error) {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+filepath.Join(in.data, "varlatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	res, err := conn.Exec(q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// sqlQuery runs one query on the stopped installation's database: every
// row's columns as text.
func sqlQuery(t *testing.T, in install, q string, args ...any) [][]string {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+filepath.Join(in.data, "varlatch.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rows, err := conn.Query(q, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out [][]string
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			row[i] = v.String
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
