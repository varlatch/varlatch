// SPDX-License-Identifier: AGPL-3.0-or-later

package values_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
)

// exportWorld is newWorld with admin-step-up at enforce and a read path
// that consumes approvals: alice has a CLI credential, two Secrets are set.
func exportWorld(t *testing.T) *world {
	wd := newWorld(t)
	wd.contract([]string{"S", "T"}, "S", "T")
	wd.set("dev", "S", "s-value")
	wd.set("dev", "T", "t-value")
	exec := func(q string, args ...any) {
		t.Helper()
		if err := wd.store.Write(context.Background(), func(tx *storage.Tx) error { _, err := tx.ExecContext(context.Background(), q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO credentials (id, identity_id, kind, token_hash) VALUES ('crd_a', 'idn_a', 'cli', 'h_a')`)
	exec(`INSERT INTO security_controls (organization_id, control, mode, version) VALUES (?, 'admin-step-up', 'enforce', 2)`, wd.org)
	public, _ := url.Parse("http://127.0.0.1:8686")
	approvals := auth.New(wd.store, auth.Options{PublicURL: public, RootKEK: wd.rootKEK, PersonGate: wd.w.Gates.PersonGate})
	wd.svc = values.New(wd.store, wd.rootKEK, values.Options{Approvals: approvals, Gates: wd.w.Gates})
	t.Cleanup(wd.svc.Settled)
	return wd
}

func (wd *world) export(ctx context.Context, body string, approval *string) (jsvalue.Object, error) {
	return wd.svc.Disclose(ctx, values.Request{
		Principal: alice(), RequestID: "req_export", Method: "POST",
		Route: "/v1/organizations/:org/projects/:project/environments/:environment/disclosures",
		Org:   "acme", Project: "api", Environment: "dev", Approval: approval,
	}, []byte(body))
}

func errCode(err error, key string) (string, any) {
	var de *domainerr.Error
	if !errors.As(err, &de) {
		return "", nil
	}
	v, _ := de.Details.Get(key)
	return de.Code, v
}

func (wd *world) approve(t *testing.T, err error) string {
	t.Helper()
	code, view := errCode(err, "approval")
	if code != "STEP_UP_REQUIRED" {
		t.Fatalf("%v", err)
	}
	id, _ := view.(jsvalue.Object).Get("id")
	if err := wd.store.Write(context.Background(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(context.Background(), `UPDATE approval_intents SET approved_at = ?, approved_with_passkey_id = 'pk_1', approval_user_verified = 1 WHERE id = ?`, time.Now().UnixMicro(), id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id.(string)
}

func (wd *world) disclosures(t *testing.T) int64 {
	return paritytest.Rows(t, wd.store, `SELECT count(*) AS n FROM audit_events WHERE event_type = 'secret.disclosed'`)[0]["n"].(int64)
}

// An export under admin-step-up's enforce (exportstepup.ts): without an
// approval it answers STEP_UP_REQUIRED for the exact set of Secrets and
// discloses and audits nothing; with the approved intent it discloses and
// records the approval; the approval is used once; a header that cannot
// be an approval id is not found; a disclosure that is not an export
// needs none.
func TestExportUnderEnforce(t *testing.T) {
	wd := exportWorld(t)
	ctx := context.Background()
	body := `{"scope":"all-authorized-secrets","purpose":"export"}`
	_, err := wd.export(ctx, body, nil)
	if wd.disclosures(t) != 0 {
		t.Fatal("audited without an approval")
	}
	id := wd.approve(t, err)
	intent := paritytest.Rows(t, wd.store, `SELECT operation, json_extract(summary, '$.title') AS title FROM approval_intents WHERE id = ?`, id)[0]
	if intent["operation"] != "secret.export" || !strings.HasPrefix(intent["title"].(string), `Export 2 Secrets of project "API" (`) || !strings.HasSuffix(intent["title"].(string), `to a file: ["S", "T"]`) {
		t.Fatalf("intent %v", intent)
	}
	out, err := wd.export(ctx, body, &id)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(jsvalue.Stringify(out)); !strings.Contains(got, `"s-value"`) || !strings.Contains(got, `"t-value"`) {
		t.Fatalf("disclosed %s", got)
	}
	ev := paritytest.Rows(t, wd.store, `SELECT json_extract(metadata, '$.approvalId') AS id, json_extract(metadata, '$.purpose') AS purpose FROM audit_events WHERE event_type = 'secret.disclosed'`)
	if len(ev) != 1 || ev[0]["id"] != id || ev[0]["purpose"] != "export" {
		t.Fatalf("audit %v", ev)
	}
	if _, err := wd.export(ctx, body, &id); func() bool { c, r := errCode(err, "reason"); return c != "APPROVAL_INVALID" || r != "consumed" }() {
		t.Fatalf("used again: %v", err)
	}
	bad := "nope"
	if _, err := wd.export(ctx, body, &bad); func() bool { c, r := errCode(err, "reason"); return c != "APPROVAL_INVALID" || r != "not-found" }() {
		t.Fatalf("malformed: %v", err)
	}
	// Another selection does not fit the approval of the first.
	_, err = wd.export(ctx, `{"items":["S"],"purpose":"export"}`, nil)
	other := wd.approve(t, err)
	if _, err := wd.export(ctx, body, &other); func() bool { c, r := errCode(err, "reason"); return c != "APPROVAL_INVALID" || r != "mismatch" }() {
		t.Fatalf("another set: %v", err)
	}
	if _, err := wd.export(ctx, `{"items":["S"]}`, &bad); err != nil {
		t.Fatalf("not an export: %v", err)
	}
}

// A capture that went stale between the snapshot and the audit job (a value
// written meanwhile) answers STATE_CHANGED, discloses and audits nothing,
// and leaves the approval usable: the repeated request makes a fresh
// capture and uses it.
func TestExportStaleCapture(t *testing.T) {
	wd := exportWorld(t)
	body := `{"items":["S"],"purpose":"export"}`
	_, err := wd.export(context.Background(), body, nil)
	id := wd.approve(t, err)
	hooked := values.WithReadHook(context.Background(), once(t, betweenValueReads, func() { wd.set("dev", "S", "s-new") }))
	if _, err := wd.export(hooked, body, &id); func() bool { c, r := errCode(err, "reason"); return c != "STATE_CHANGED" || r != "stale-capture" }() {
		t.Fatalf("stale: %v", err)
	}
	if wd.disclosures(t) != 0 {
		t.Fatal("audited a stale capture")
	}
	out, err := wd.export(context.Background(), body, &id)
	if err != nil || !strings.Contains(string(jsvalue.Stringify(out)), `"s-new"`) {
		t.Fatalf("repeated: %v %v", out, err)
	}
}
