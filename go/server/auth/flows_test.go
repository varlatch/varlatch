// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/auth"
)

// signedIn is a person signed in to the dashboard: their session and a
// browser bearer minted from it.
type signedIn struct {
	identityID string
	session    *auth.Session
	principal  *auth.Principal
}

func (e *env) dashboard(k *softKey) signedIn {
	e.t.Helper()
	reg, _ := e.enroll(k, browserCSRF)
	s := e.session(reg.Session.SessionToken)
	b, err := e.svc.MintBearer(e.ctx, s, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	p, _, _ := e.svc.Authenticate(e.ctx, b.Token)
	return signedIn{identityID: reg.IdentityID, session: s, principal: p}
}

// Device sign-in end to end: request, a wrong code counted, the lookup's
// challenge, approval with a fresh assertion, one collection, then
// CONSUMED; the collected credential carries the approval's evidence.
func TestDeviceSignIn(t *testing.T) {
	e := newEnv(t)
	k := newSoftKey(t)
	me := e.dashboard(k)
	ua := "varlatch-cli/0.22.0 (linux; x64)"
	req, err := e.svc.RequestDeviceSignIn(e.ctx, 3600, nil, "192.0.2.7", &ua, "req_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(req.DeviceCode) != 43 || len(req.UserCode) != 9 || req.UserCode[4] != '-' {
		t.Fatalf("%+v", req)
	}
	poll := func() auth.PollOutcome {
		out, err := e.svc.PollDeviceSignIn(e.ctx, req.DeviceCode, &ua, "req_p")
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if out := poll(); out.Kind != auth.PollPending || out.Interval != 5 {
		t.Fatalf("first poll %+v", out)
	}
	if out := poll(); out.Kind != auth.PollSlowDown || out.Interval != 10 {
		t.Fatalf("polled too soon %+v", out)
	}
	if _, err := e.svc.FindSignInByCode(e.ctx, me.identityID, "192.0.2.9", "BBBB-BBBB", "req_w"); err != auth.ErrWrongCode {
		t.Fatalf("wrong code: %v", err)
	}
	if n := e.count(`SELECT failures FROM device_code_attempt_windows WHERE scope = 'identity' AND key = ?`, me.identityID); n != 1 {
		t.Fatalf("wrong codes counted %d", n)
	}
	// Typed lower-case without the dash.
	signIn, err := e.svc.FindSignInByCode(e.ctx, me.identityID, "192.0.2.9", strings.ToLower(strings.ReplaceAll(req.UserCode, "-", "")), "req_l")
	if err != nil || signIn.ID != req.ID || *signIn.RequesterUserAgent != ua {
		t.Fatalf("%+v %v", signIn, err)
	}
	o, err := e.svc.ApprovalChallenge(e.ctx, signIn.ID, me.identityID, me.session.ID)
	if err != nil || o == nil || o.UserVerification != "preferred" || len(o.AllowCredentials) != 1 {
		t.Fatalf("%+v %v", o, err)
	}
	// Another session's challenge does not approve: the challenge is bound
	// to the session (and spent by the attempt).
	if err := e.svc.ApproveDeviceSignIn(e.ctx, signIn.ID, me.identityID, "ses_other", k.Assert(t, *o, origin), "req_a"); codeOf(err) != "PERMISSION_DENIED" {
		t.Fatalf("other session: %v", err)
	}
	o, _ = e.svc.ApprovalChallenge(e.ctx, signIn.ID, me.identityID, me.session.ID)
	resp := k.Assert(t, *o, origin)
	if err := e.svc.ApproveDeviceSignIn(e.ctx, signIn.ID, me.identityID, me.session.ID, resp, "req_a"); err != nil {
		t.Fatal(err)
	}
	// Decided: the same response cannot approve again.
	if err := e.svc.ApproveDeviceSignIn(e.ctx, signIn.ID, me.identityID, me.session.ID, resp, "req_a"); codeOf(err) != "STATE_CHANGED" {
		t.Fatalf("second approval: %v", err)
	}
	e.clock.add(11 * time.Second)
	out := poll()
	if out.Kind != auth.PollIssued || !strings.HasPrefix(out.Issued.Token, "vlt_cli_") {
		t.Fatalf("collection %+v", out)
	}
	if again := poll(); again.Kind != auth.PollConsumed || *again.CredentialID != out.Issued.CredentialID {
		t.Fatalf("second collection %+v", again)
	}
	p, _, _ := e.svc.Authenticate(e.ctx, out.Issued.Token)
	if p == nil || p.Identity.ID != me.identityID || *p.Credential.ExpiresAt-e.clock.now().UnixMicro() > 3600_000_000 {
		t.Fatalf("collected credential %+v", p)
	}
	if gap, _ := auth.VerificationGap(e.ctx, e.store.Reader(), out.Issued.CredentialID, auth.KindCLI); gap != "" {
		t.Fatalf("device evidence gap %q", gap)
	}
	if n := e.count(`SELECT count(*) FROM credentials WHERE id = ? AND client = 'varlatch CLI 0.22.0 on Linux' AND evidence_user_verified = 1`, out.Issued.CredentialID); n != 1 {
		t.Fatalf("credential row")
	}
	for _, typ := range []string{"authentication.device_requested", "authentication.device_code_rejected", "authentication.failed", "authentication.device_approved", "authentication.device_collected"} {
		if n := e.count(`SELECT count(*) FROM audit_events WHERE event_type = ?`, typ); n < 1 {
			t.Errorf("no %s", typ)
		}
	}
}

// Denial, expiry, and the attempt limits.
func TestDeviceSignInDenyExpireLimits(t *testing.T) {
	e := newEnv(t)
	me := e.dashboard(newSoftKey(t))
	req, _ := e.svc.RequestDeviceSignIn(e.ctx, 600, nil, "192.0.2.7", nil, "r")
	s, _ := e.svc.FindSignInByCode(e.ctx, me.identityID, "p", req.UserCode, "r")
	if err := e.svc.DenyDeviceSignIn(e.ctx, s.ID, me.identityID, "r"); err != nil {
		t.Fatal(err)
	}
	if out, _ := e.svc.PollDeviceSignIn(e.ctx, req.DeviceCode, nil, "r"); out.Kind != auth.PollDenied {
		t.Fatalf("%+v", out)
	}
	req2, _ := e.svc.RequestDeviceSignIn(e.ctx, 600, nil, "192.0.2.7", nil, "r")
	e.clock.add(11 * time.Minute)
	if out, _ := e.svc.PollDeviceSignIn(e.ctx, req2.DeviceCode, nil, "r"); out.Kind != auth.PollExpired {
		t.Fatalf("%+v", out)
	}
	// Five wrong codes lock the person's code entry, even for a right code.
	req3, _ := e.svc.RequestDeviceSignIn(e.ctx, 600, nil, "192.0.2.7", nil, "r")
	for range 5 {
		_, _ = e.svc.FindSignInByCode(e.ctx, me.identityID, "p2", "BBBB-BBBB", "r")
	}
	if _, err := e.svc.FindSignInByCode(e.ctx, me.identityID, "p2", req3.UserCode, "r"); codeOf(err) != "RATE_LIMITED" {
		t.Fatalf("locked: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM audit_events WHERE event_type = 'authentication.device_code_locked'`); n != 1 {
		t.Fatalf("%d lock events", n)
	}
	// Ten pending sign-ins per client address.
	for range 9 {
		if _, err := e.svc.RequestDeviceSignIn(e.ctx, 600, nil, "198.51.100.1", nil, "r"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.RequestDeviceSignIn(e.ctx, 600, nil, "198.51.100.1", nil, "r"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RequestDeviceSignIn(e.ctx, 600, nil, "198.51.100.1", nil, "r"); codeOf(err) != "RATE_LIMITED" {
		t.Fatalf("pending cap: %v", err)
	}
}

// Concurrent approvals of two sign-ins with one passkey, their counters in
// either order: the counter only moves forward.
func TestConcurrentApprovalsNeverMoveCounterBack(t *testing.T) {
	e := newEnv(t)
	k := newSoftKey(t)
	me := e.dashboard(k)
	const n = 10
	type approval struct {
		id   string
		resp json.RawMessage
	}
	approvals := make([]approval, n)
	for i := range n {
		req, _ := e.svc.RequestDeviceSignIn(e.ctx, 600, nil, "203.0.113.1", nil, "r")
		s, _ := e.svc.FindSignInByCode(e.ctx, me.identityID, "p", req.UserCode, "r")
		o, _ := e.svc.ApprovalChallenge(e.ctx, s.ID, me.identityID, me.session.ID)
		// Highest counter first: later approvals carry lower counters.
		approvals[i] = approval{s.ID, k.AssertWith(t, o.RPID, o.Challenge, origin, uint32(100-i))}
	}
	var wg sync.WaitGroup
	for _, a := range approvals {
		wg.Go(func() {
			if err := e.svc.ApproveDeviceSignIn(e.ctx, a.id, me.identityID, me.session.ID, a.resp, "r"); err != nil && codeOf(err) != "PERMISSION_DENIED" {
				t.Errorf("approval: %v", err)
			}
		})
	}
	wg.Wait()
	if c := storedCounter(t, e); c != 100 {
		t.Fatalf("counter %d", c)
	}
	// Each approved sign-in was approved with a counter above every one
	// approved before it, so the counters of the approvals form a rising
	// sequence ending at the stored one.
	if n := e.count(`SELECT count(*) FROM device_sign_ins WHERE status = 'approved'`); n < 1 {
		t.Fatal("no approval")
	}
}

// Passkey confirmation: an added passkey is unconfirmed; a challenge for it
// lists only trusted passkeys and requires user verification; an assertion
// without it is refused with details.reason user-verification-required and
// spends the challenge; a verified one confirms it.
func TestPasskeyConfirmation(t *testing.T) {
	e := newEnv(t)
	trusted := newSoftKey(t)
	me := e.dashboard(trusted)
	// Add a second passkey from the session.
	added := newSoftKey(t)
	ro, err := e.svc.RegistrationOptions(e.ctx, auth.CSRFBinding(browserCSRF), "", me.session)
	if err != nil {
		t.Fatal(err)
	}
	if len(ro.ExcludeCredentials) != 1 {
		t.Fatalf("exclude %+v", ro.ExcludeCredentials)
	}
	reg, err := e.svc.Register(e.ctx, auth.CSRFBinding(browserCSRF), me.session, added.Register(t, ro, origin), "Laptop", "", "")
	if err != nil || reg.Session != nil {
		t.Fatalf("%+v %v", reg, err)
	}
	list, _ := e.svc.ListOwnPasskeys(e.ctx, me.identityID)
	var target auth.OwnPasskey
	for _, p := range list {
		if p.ID == reg.PasskeyID {
			target = p
		}
	}
	if target.Trust != "unconfirmed" || target.TrustedVia != nil || *target.Name != "Laptop" {
		t.Fatalf("added passkey %+v", target)
	}
	o, err := e.svc.StartConfirmation(e.ctx, me.identityID, me.session.ID, reg.PasskeyID)
	if err != nil || o.UserVerification != "required" || len(o.AllowCredentials) != 1 || o.AllowCredentials[0].ID != b64(trusted.ID) {
		t.Fatalf("%+v %v", o, err)
	}
	trusted.NoUV = true
	if _, err := e.svc.Confirm(e.ctx, me.identityID, me.session.ID, reg.PasskeyID, trusted.Assert(t, o, origin), "r"); codeOf(err) != "PERMISSION_DENIED" || !strings.Contains(err.Error(), "PIN") {
		t.Fatalf("without UV: %v", err)
	} else if reason := detailsReason(err); reason != "user-verification-required" {
		t.Fatalf("reason %q", reason)
	}
	trusted.NoUV = false
	// The challenge was spent by the refusal.
	if _, err := e.svc.Confirm(e.ctx, me.identityID, me.session.ID, reg.PasskeyID, trusted.Assert(t, o, origin), "r"); detailsReason(err) != "challenge" {
		t.Fatalf("spent challenge: %v", err)
	}
	// The passkey being confirmed cannot confirm itself.
	o, _ = e.svc.StartConfirmation(e.ctx, me.identityID, me.session.ID, reg.PasskeyID)
	if _, err := e.svc.Confirm(e.ctx, me.identityID, me.session.ID, reg.PasskeyID, added.Assert(t, o, origin), "r"); detailsReason(err) != "unknown-passkey" {
		t.Fatalf("self-confirmation: %v", err)
	}
	o, _ = e.svc.StartConfirmation(e.ctx, me.identityID, me.session.ID, reg.PasskeyID)
	confirmed, err := e.svc.Confirm(e.ctx, me.identityID, me.session.ID, reg.PasskeyID, trusted.Assert(t, o, origin), "r")
	if err != nil || confirmed.Trust != "trusted" || *confirmed.TrustedVia != "confirmed" || *confirmed.ConfirmedByPasskeyID == "" {
		t.Fatalf("%+v %v", confirmed, err)
	}
	if _, err := e.svc.StartConfirmation(e.ctx, me.identityID, me.session.ID, reg.PasskeyID); codeOf(err) != "STATE_CHANGED" {
		t.Fatalf("already trusted: %v", err)
	}
	// Removal of one's own passkey; another's is not found.
	if err := e.svc.RemoveOwnPasskey(e.ctx, me.identityID, reg.PasskeyID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RemoveOwnPasskey(e.ctx, "idn_someone", me.principal.Identity.ID); codeOf(err) != "RESOURCE_NOT_FOUND" {
		t.Fatalf("another's: %v", err)
	}
}

func detailsReason(err error) string { return reasonOf(err) }

// passkey-verification gaps, by evidence: a session signed in without user
// verification, a passkey not trusted now, a kind that carries none.
func TestVerificationGaps(t *testing.T) {
	e := newEnv(t)
	k := newSoftKey(t)
	me := e.dashboard(k)
	if gap, _ := auth.VerificationGap(e.ctx, e.store.Reader(), me.principal.Credential.ID, auth.KindBrowser); gap != "" {
		t.Fatalf("enrollment session: %q", gap)
	}
	k.NoUV = true
	started := mustSignIn(t, e, k)
	b, _ := e.svc.MintBearer(e.ctx, e.session(started.SessionToken), nil)
	if gap, _ := auth.VerificationGap(e.ctx, e.store.Reader(), mustID(t, e, b.Token), auth.KindBrowser); gap != auth.GapNotUserVerified {
		t.Fatalf("no UV: %q", gap)
	}
	if gap, _ := auth.VerificationGap(e.ctx, e.store.Reader(), me.principal.Credential.ID, auth.KindService); gap != auth.GapNoEvidence {
		t.Fatalf("service kind: %q", gap)
	}
	refusal := auth.PasskeyVerificationRequired("org_x", auth.GapUntrusted)
	if refusal.Domain.Code != "PASSKEY_VERIFICATION_REQUIRED" || reasonOf(refusal) != "untrusted-passkey" || refusal.SelfLockout {
		t.Fatalf("%+v", refusal)
	}
}
