// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// approvalOf is the approval a STEP_UP_REQUIRED carries: its id and state.
func approvalOf(t *testing.T, err error) (string, jsvalue.Object) {
	t.Helper()
	if codeOf(err) != "STEP_UP_REQUIRED" {
		t.Fatalf("want STEP_UP_REQUIRED, got %v", err)
	}
	de := domainErr(err)
	v, _ := de.Details.Get("approval")
	view := v.(jsvalue.Object)
	id, _ := view.Get("id")
	return id.(string), view
}

func get(o jsvalue.Object, key string) any { v, _ := o.Get(key); return v }

// enforce puts the person in an Organization with a Security Control at
// enforce: removing a trusted passkey then needs a step-up approval
// (ADR-0054 Decision 4).
func (e *env) enforce(identityID string) {
	e.t.Helper()
	if err := e.store.Write(e.ctx, func(tx *storage.Tx) error {
		for _, st := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_acme', 'acme', 'Acme', '{}')`, nil},
			{`INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ('org_acme', ?, 'admin')`, []any{identityID}},
			{`INSERT INTO security_controls (organization_id, control, mode, version, changed_by) VALUES ('org_acme', 'admin-step-up', 'enforce', 1, ?)`, []any{identityID}},
		} {
			if _, err := tx.ExecContext(e.ctx, st.sql, st.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
}

// TypeScript's STEP_UP_REQUIRED flow for removing a trusted passkey under
// an enforced Security Control: the removal without an approval creates
// an intent and refuses; the person approves it with a trusted passkey and
// user verification, on a challenge bound to the intent and their session;
// the repeated removal consumes it, once, from the same session only.
func TestRemovingATrustedPasskeyNeedsAStepUpApproval(t *testing.T) {
	e := newEnv(t)
	k := newSoftKey(t)
	me := e.dashboard(k)
	// A second trusted passkey, by recovery, to remove.
	g, _ := e.svc.IssueRecoveryGrant(e.ctx, auth.Recovery{IdentityID: me.identityID})
	second := e.enrollWith(newSoftKey(t), "another-browser-csrf-token-0123456789abcdef", g.Token)
	req := auth.RequesterOf(me.principal)

	e.enforce(me.identityID)

	err := e.svc.RemoveOwnPasskey(e.ctx, req, second.PasskeyID, "")
	id, view := approvalOf(t, err)
	if get(view, "operation") != "passkey.remove" || get(view, "state") != "pending" || get(view, "url") != origin+"/approve/"+id {
		t.Fatalf("approval %s", jsvalue.Stringify(view))
	}
	if n := e.count(`SELECT count(*) FROM passkeys WHERE id = ?`, second.PasskeyID); n != 1 {
		t.Fatal("removed without an approval")
	}
	// Not approved yet: refused, and the passkey stays.
	if err := e.svc.RemoveOwnPasskey(e.ctx, req, second.PasskeyID, id); reasonOf(err) != "pending" {
		t.Fatalf("pending approval: %v", err)
	}
	// Polled by the requesting credential: too soon the second time.
	if _, err := e.svc.GetApproval(e.ctx, req, id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.GetApproval(e.ctx, req, id); err == nil {
		t.Fatal("no SLOW_DOWN")
	}
	o, err := e.svc.StartApproval(e.ctx, me.identityID, me.session.ID, id)
	if err != nil || o.UserVerification != "required" || len(o.AllowCredentials) != 2 || o.Timeout > 120_000 {
		t.Fatalf("%+v %v", o, err)
	}
	// Without user verification: refused, audited, and the challenge spent.
	k.NoUV = true
	if _, err := e.svc.ApproveApproval(e.ctx, me.identityID, me.session.ID, id, k.Assert(t, o, origin), "req_a"); reasonOf(err) != "user-verification-required" {
		t.Fatalf("no UV: %v", err)
	}
	k.NoUV = false
	if _, err := e.svc.ApproveApproval(e.ctx, me.identityID, me.session.ID, id, k.Assert(t, o, origin), "req_a"); reasonOf(err) != "challenge" {
		t.Fatalf("spent challenge: %v", err)
	}
	// Another session's challenge does not approve.
	if _, err := e.svc.StartApproval(e.ctx, me.identityID, "ses_other", id); err != nil {
		t.Fatal(err)
	}
	o, _ = e.svc.StartApproval(e.ctx, me.identityID, me.session.ID, id)
	approved, err := e.svc.ApproveApproval(e.ctx, me.identityID, me.session.ID, id, k.Assert(t, o, origin), "req_a")
	if err != nil || get(approved, "state") != "approved" {
		t.Fatalf("%v %v", approved, err)
	}
	// Approved for this passkey: another passkey's removal does not fit.
	if err := e.svc.RemoveOwnPasskey(e.ctx, req, mustPasskey(t, e, me.identityID, second.PasskeyID), id); reasonOf(err) != "mismatch" {
		t.Fatalf("another target: %v", err)
	}
	// A CLI credential of the same person is another requester.
	cli := e.cliOf(me.identityID)
	if err := e.svc.RemoveOwnPasskey(e.ctx, auth.RequesterOf(cli), second.PasskeyID, id); reasonOf(err) != "mismatch" {
		t.Fatalf("another requester: %v", err)
	}
	// Another bearer of the same session is the same requester: it removes.
	b2, _ := e.svc.MintBearer(e.ctx, me.session, nil)
	p2, _, _ := e.svc.Authenticate(e.ctx, b2.Token)
	if err := e.svc.RemoveOwnPasskey(e.ctx, auth.RequesterOf(p2), second.PasskeyID, id); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM passkeys WHERE id = ?`, second.PasskeyID); n != 0 {
		t.Fatal("not removed")
	}
	if n := e.count(`SELECT count(*) FROM approval_intents WHERE id = ? AND consumed_at IS NOT NULL`, id); n != 1 {
		t.Fatal("not consumed")
	}
	// Used once: the next removal asks again.
	first := mustPasskey(t, e, me.identityID, "")
	if err := e.svc.RemoveOwnPasskey(e.ctx, req, first, id); reasonOf(err) != "mismatch" && reasonOf(err) != "consumed" {
		t.Fatalf("reused: %v", err)
	}
}

// An approval asked from a dashboard session dies with it, and one can be
// cancelled.
func TestApprovalSessionEndedAndCancel(t *testing.T) {
	e := newEnv(t)
	k := newSoftKey(t)
	me := e.dashboard(k)
	e.enforce(me.identityID)
	req := auth.RequesterOf(me.principal)
	pk := mustPasskey(t, e, me.identityID, "")
	id, _ := approvalOf(t, e.svc.RemoveOwnPasskey(e.ctx, req, pk, ""))
	o, _ := e.svc.StartApproval(e.ctx, me.identityID, me.session.ID, id)
	if _, err := e.svc.ApproveApproval(e.ctx, me.identityID, me.session.ID, id, k.Assert(t, o, origin), "r"); err != nil {
		t.Fatal(err)
	}
	// The session ends after the approval: the bearer is revoked with it,
	// and the intent's session is gone.
	if err := e.store.Write(e.ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(e.ctx, `DELETE FROM auth_sessions WHERE id = ?`, me.session.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RemoveOwnPasskey(e.ctx, req, pk, id); reasonOf(err) != "session-ended" {
		t.Fatalf("session ended: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM approval_intents WHERE id = ? AND consumed_at IS NULL`, id); n != 1 {
		t.Fatal("a refused consumption was kept")
	}
	cancelled, err := e.svc.CancelApproval(e.ctx, me.identityID, id)
	if err != nil || get(cancelled, "state") != "closed" || get(cancelled, "closeReason") != "cancelled" {
		t.Fatalf("%v %v", cancelled, err)
	}
	if _, err := e.svc.CancelApproval(e.ctx, me.identityID, id); reasonOf(err) != "closed" {
		t.Fatalf("cancel twice: %v", err)
	}
	// Another person's approval is not found.
	if _, err := e.svc.GetApproval(e.ctx, auth.Requester{IdentityID: "idn_other", CredentialID: "crd_x"}, id); codeOf(err) != "RESOURCE_NOT_FOUND" {
		t.Fatalf("another's: %v", err)
	}
	// An expired intent.
	id2, _ := approvalOf(t, e.svc.RemoveOwnPasskey(e.ctx, auth.RequesterOf(e.cliOf(me.identityID)), pk, ""))
	e.clock.add(11 * time.Minute)
	if _, err := e.svc.StartApproval(e.ctx, me.identityID, me.session.ID, id2); reasonOf(err) != "expired" {
		t.Fatalf("expired: %v", err)
	}
}

// A machine credential cannot ask for an approval.
func TestMachineCredentialCannotAskForApproval(t *testing.T) {
	e := newEnv(t)
	me := e.dashboard(newSoftKey(t))
	e.enforce(me.identityID)
	pk := mustPasskey(t, e, me.identityID, "")
	err := e.svc.RemoveOwnPasskey(e.ctx, auth.Requester{IdentityID: me.identityID, IdentityKind: "human", CredentialID: "crd_svc", CredentialKind: auth.KindService}, pk, "")
	if reasonOf(err) != "machine-credential" {
		t.Fatalf("%v", err)
	}
}
