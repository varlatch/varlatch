// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/write"
)

// `admin audit-export discard-plan` (feature-parity decision 11): it
// reaches the daemon through its socket and takes the export's gate, so
// it waits while something in the daemon holds the export (a change's
// probe, the worker's lease), then restarts the stream. It refuses a plan
// this release can upload, and a usage error never reaches the daemon.
func TestAuditExportCommand(t *testing.T) {
	in := newInstall(t, "")
	writers := make(chan *write.Writer, 1)
	r := startWith(t, in, &hooks{writer: func(w *write.Writer) { writers <- w }})
	w := <-writers
	ctx := context.Background()
	material, err := os.ReadFile(in.kekFile)
	if err != nil {
		t.Fatal(err)
	}
	rootKEK, err := envelope.ParseRootKEK(string(material))
	if err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if err := w.Store.Write(ctx, func(tx *storage.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice')`)
	org, err := orgs.Create(ctx, w, rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMicro()
	const id, stream = "aex_aaaaaaaaaaaaaaaaaaaaaaaaaa", "aes_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	exec(`INSERT INTO audit_exports (id, organization_id, endpoint, region, bucket, prefix, path_style, credential_envelope, stream_id, stream_started_at,
		cursor_order, state, created_by) VALUES (?, ?, 'https://s3.example.test', 'us-east-1', 'bucket', '', 1, '{}', ?, ?, 0, 'active', 'idn_a')`, id, org.ID, stream, now)
	plan := func(format int) {
		exec(`DELETE FROM audit_export_plans WHERE export_id = ?`, id)
		exec(`INSERT INTO audit_export_plans (id, export_id, export_version, stream_id, generation, kind, object_name, body, sha256, md5, content_type, format_version, planned_at)
			VALUES ('aep_aaaaaaaaaaaaaaaaaaaaaaaaaa', ?, 1, ?, 0, 'manifest', 'x/stream.json', X'7B7D', ?, ?, 'application/json', ?, ?)`,
			id, stream, strings.Repeat("a", 64), strings.Repeat("b", 32), format, now)
	}
	args := func(reason string) []string {
		return []string{"audit-export", "discard-plan", "--export", id, "--reason", reason, "--config", in.conf}
	}

	plan(1)
	if code, _, errOut := runAdmin(t, args("unsupported-format")...); code != ExitFailure ||
		errOut != "varlatchd admin audit-export: VALIDATION_FAILED: The pending plan is in format 1, which this release uploads; it is not discarded\n" {
		t.Errorf("format 1: %d %q", code, errOut)
	}
	if code, _, errOut := runAdmin(t, "audit-export", "discard-plan", "--export", id, "--config", in.conf); code != 64 || !strings.HasPrefix(errOut, AuditExportUsage) {
		t.Errorf("usage: %d %q", code, errOut)
	}

	// Held in the daemon: the command waits on the export's gate.
	plan(2)
	_, release, err := w.Gates.Acquire(ctx, write.Resource("audit_export", id))
	if err != nil {
		t.Fatal(err)
	}
	p := spawnAdmin(t, append(args("unsupported-format"), "--json")...)
	deadline := time.Now().Add(20 * time.Second)
	for !func() bool {
		for _, g := range w.Gates.Waiting() {
			if g == write.Resource("audit_export", id) {
				return true
			}
		}
		return false
	}() {
		if time.Now().After(deadline) {
			release()
			t.Fatalf("the command did not reach the export's gate: %s", p.stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-p.done:
		release()
		t.Fatalf("the command finished while the export was held: %v %s", err, p.stderr.String())
	case <-time.After(300 * time.Millisecond):
	}
	release()
	select {
	case err := <-p.done:
		if err != nil {
			t.Fatalf("%v %s", err, p.stderr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the command did not finish after the release")
	}
	var out struct{ ExportID, StreamID string }
	if err := json.Unmarshal(p.stdout.Bytes(), &out); err != nil || out.ExportID != id || !strings.HasPrefix(out.StreamID, "aes_") || out.StreamID == stream {
		t.Fatalf("printed %q: %v", p.stdout.String(), err)
	}
	var current string
	var reason string
	_ = w.Store.Reader().QueryRow(`SELECT stream_id FROM audit_exports WHERE id = ?`, id).Scan(&current)
	_ = w.Store.Reader().QueryRow(`SELECT json_extract(metadata, '$.cause') FROM audit_events WHERE event_type = 'audit_export.stream_started'`).Scan(&reason)
	if current != out.StreamID || reason != "unsupported-format" {
		t.Errorf("stream %s, cause %q", current, reason)
	}

	// Offline, under the lock: the same command, the same words (the
	// pending plan is the new stream's manifest).
	r.stop(t)
	if code, out, errOut := runAdmin(t, args("expired")...); code != ExitFailure || out != "" ||
		errOut != "varlatchd admin audit-export: VALIDATION_FAILED: The pending plan's retention has not expired; it can still be uploaded, so it is not discarded\n" {
		t.Errorf("offline: %d %q %q", code, out, errOut)
	}
}
