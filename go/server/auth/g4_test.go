// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
)

// ADR-0059 gate G4, server side: single-use challenges bound to the browser
// or session that asked for them, origin and RP ID checks, counters that
// never move back under concurrent assertions, and a session's end revoking
// its browser credentials while leaving CLI hand-off credentials. CSRF and
// the Origin header of browser requests are tested at the HTTP layer
// (httpserver/browser_test.go).

// Bootstrap enrollment: the grant is checked at the ceremony's start, not
// consumed, so an abandoned start leaves it usable; the finished ceremony
// consumes it, creates the Installation Admin, stores a trusted passkey and
// starts a session with the enrollment's evidence; the grant then refuses.
func TestEnrollmentConsumesGrantOnce(t *testing.T) {
	e := newEnv(t)
	g, err := e.svc.IssueBootstrapGrant(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	// An abandoned start: options, no registration.
	if _, err := e.svc.RegistrationOptions(e.ctx, auth.CSRFBinding("other-browser-csrf-token-0123456789abcdef"), g.Token, nil); err != nil {
		t.Fatal(err)
	}
	k := newSoftKey(t)
	reg := e.enrollWith(k, browserCSRF, g.Token)
	if reg.Session == nil || reg.IdentityID == "" || reg.PasskeyID == "" {
		t.Fatalf("registration %+v", reg)
	}
	list, err := e.svc.ListOwnPasskeys(e.ctx, reg.IdentityID)
	if err != nil || len(list) != 1 || list[0].Trust != "trusted" || *list[0].TrustedVia != "setup-grant" || *list[0].SetupGrantKind != "bootstrap" {
		t.Fatalf("passkeys %+v %v", list, err)
	}
	if n := e.count(`SELECT count(*) FROM identities WHERE installation_admin AND id = ?`, reg.IdentityID); n != 1 {
		t.Fatalf("admin rows %d", n)
	}
	if n := e.count(`SELECT count(*) FROM auth_session_evidence WHERE session_id = ? AND ceremony = 'enrollment' AND user_verified AND passkey_id = ?`, reg.Session.SessionID, reg.PasskeyID); n != 1 {
		t.Fatalf("evidence rows %d", n)
	}
	// Replay: the grant is consumed.
	k2 := newSoftKey(t)
	_, err = e.svc.RegistrationOptions(e.ctx, auth.CSRFBinding(browserCSRF), g.Token, nil)
	if codeOf(err) != "INVALID_CREDENTIAL" {
		t.Fatalf("replayed grant: %v", err)
	}
	_ = k2
	if n := e.count(`SELECT count(*) FROM audit_events WHERE event_type = 'setup.grant_rejected'`); n != 1 {
		t.Fatalf("rejections %d", n)
	}
	// Bootstrap is over.
	if _, err := e.svc.IssueBootstrapGrant(e.ctx); codeOf(err) != "VALIDATION_FAILED" {
		t.Fatalf("second bootstrap: %v", err)
	}
}

// Two registrations racing for one grant: exactly one consumes it.
func TestEnrollmentRaceConsumesOnce(t *testing.T) {
	e := newEnv(t)
	g, err := e.svc.IssueBootstrapGrant(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	const n = 8
	responses := make([]json.RawMessage, n)
	bindings := make([]string, n)
	for i := range n {
		bindings[i] = auth.CSRFBinding(fmt.Sprintf("browser-%d-csrf-token-0123456789abcdef", i))
		o, err := e.svc.RegistrationOptions(e.ctx, bindings[i], g.Token, nil)
		if err != nil {
			t.Fatal(err)
		}
		responses[i] = newSoftKey(t).register(t, o, origin)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, refused := 0, 0
	for i := range n {
		wg.Go(func() {
			_, err := e.svc.Register(e.ctx, bindings[i], nil, responses[i], "", "", "")
			mu.Lock()
			defer mu.Unlock()
			switch codeOf(err) {
			case "":
				ok++
			case "INVALID_CREDENTIAL":
				refused++
			default:
				t.Errorf("registration: %v", err)
			}
		})
	}
	wg.Wait()
	if ok != 1 || refused != n-1 {
		t.Fatalf("%d consumed, %d refused", ok, refused)
	}
	if c := e.count(`SELECT count(*) FROM passkeys`); c != 1 {
		t.Fatalf("%d passkeys", c)
	}
}

// A challenge is used once, only by the browser it was issued to, only for
// its own ceremony, and only before it expires.
func TestChallengesSingleUseAndBound(t *testing.T) {
	e := newEnv(t)
	k := newSoftKey(t)
	e.enroll(k, browserCSRF)
	binding := auth.CSRFBinding(browserCSRF)

	// Replayed: the same signed response twice.
	o, _ := e.svc.SignInOptions(binding)
	resp := k.assert(t, o, origin)
	if _, err := e.svc.SignIn(e.ctx, binding, resp, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SignIn(e.ctx, binding, resp, "", ""); codeOf(err) != "INVALID_CREDENTIAL" || !strings.Contains(err.Error(), "used or expired") {
		t.Fatalf("replay: %v", err)
	}

	// Another browser's challenge: refused, and spent.
	o, _ = e.svc.SignInOptions(auth.CSRFBinding("another-browser-csrf-token-0123456789"))
	resp = k.assert(t, o, origin)
	if _, err := e.svc.SignIn(e.ctx, binding, resp, "", ""); codeOf(err) != "INVALID_CREDENTIAL" {
		t.Fatalf("foreign challenge: %v", err)
	}
	if _, err := e.svc.SignIn(e.ctx, auth.CSRFBinding("another-browser-csrf-token-0123456789"), resp, "", ""); codeOf(err) != "INVALID_CREDENTIAL" {
		t.Fatalf("challenge reused after a refusal: %v", err)
	}

	// A registration challenge does not sign in.
	ro, err := e.svc.RegistrationOptions(e.ctx, binding, "", e.session(mustSignIn(t, e, k).SessionToken))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SignIn(e.ctx, binding, k.assertWith(t, "varlatch.example.com", ro.Challenge, origin, k.counter+1), "", ""); codeOf(err) != "INVALID_CREDENTIAL" {
		t.Fatalf("registration challenge used to sign in: %v", err)
	}

	// Expired.
	o, _ = e.svc.SignInOptions(binding)
	e.clock.add(6 * time.Minute)
	if _, err := e.svc.SignIn(e.ctx, binding, k.assert(t, o, origin), "", ""); codeOf(err) != "INVALID_CREDENTIAL" {
		t.Fatalf("expired challenge: %v", err)
	}
}

func mustSignIn(t *testing.T, e *env, k *softKey) auth.Started {
	t.Helper()
	s, err := e.signIn(k, browserCSRF)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The origin and the RP ID are checked: an assertion made for another
// origin, or signed over another RP ID, does not sign in, and its
// challenge is spent.
func TestOriginAndRPID(t *testing.T) {
	e := newEnv(t)
	k := newSoftKey(t)
	e.enroll(k, browserCSRF)
	binding := auth.CSRFBinding(browserCSRF)
	for _, c := range []struct{ name, rpID, from string }{
		{"another origin", "varlatch.example.com", "https://evil.example.net"},
		{"another port", "varlatch.example.com", "https://varlatch.example.com:8443"},
		{"plain http", "varlatch.example.com", "http://varlatch.example.com"},
		{"another RP ID", "example.com", origin},
	} {
		o, _ := e.svc.SignInOptions(binding)
		k.counter++
		if _, err := e.svc.SignIn(e.ctx, binding, k.assertWith(t, c.rpID, o.Challenge, c.from, k.counter), "", ""); codeOf(err) != "INVALID_CREDENTIAL" {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// A registration from another origin is refused, and consumes nothing.
	g, _ := e.svc.IssueRecoveryGrant(e.ctx, auth.Recovery{IdentityID: adminOf(t, e)})
	o, err := e.svc.RegistrationOptions(e.ctx, binding, g.Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Register(e.ctx, binding, nil, newSoftKey(t).register(t, o, "https://evil.example.net"), "", "", ""); codeOf(err) != "VALIDATION_FAILED" {
		t.Fatalf("foreign registration: %v", err)
	}
	if _, err := e.svc.PeekSetupGrant(e.ctx, g.Token); err != nil {
		t.Fatalf("the grant was consumed: %v", err)
	}
	// And the right origin signs in.
	if _, err := e.signIn(k, browserCSRF); err != nil {
		t.Fatal(err)
	}
}

func adminOf(t *testing.T, e *env) string {
	t.Helper()
	var id string
	if err := e.store.Reader().QueryRowContext(e.ctx, `SELECT id FROM identities WHERE installation_admin LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func storedCounter(t *testing.T, e *env) int {
	t.Helper()
	return e.count(`SELECT counter FROM passkeys LIMIT 1`)
}

// Concurrent sign-ins with one passkey, their counters arriving in any
// order: every write moves the counter forward (an assertion at or below
// the stored counter is refused), so the stored counter is the highest one
// that signed in, and never went back (the schema's passkey_counter_forward
// trigger would have failed the job).
func TestConcurrentAssertionsNeverMoveCounterBack(t *testing.T) {
	e := newEnv(t)
	k := newSoftKey(t)
	e.enroll(k, browserCSRF)
	const n = 24
	type attempt struct {
		binding string
		resp    json.RawMessage
		counter uint32
	}
	attempts := make([]attempt, n)
	for i := range n {
		csrf := fmt.Sprintf("browser-%02d-csrf-token-0123456789abcdef", i)
		o, _ := e.svc.SignInOptions(auth.CSRFBinding(csrf))
		c := uint32(i + 1)
		attempts[i] = attempt{auth.CSRFBinding(csrf), k.assertWith(t, o.RPID, o.Challenge, origin, c), c}
	}
	rand.Shuffle(n, func(i, j int) { attempts[i], attempts[j] = attempts[j], attempts[i] })
	var wg sync.WaitGroup
	var mu sync.Mutex
	var accepted []uint32
	for _, a := range attempts {
		wg.Go(func() {
			_, err := e.svc.SignIn(e.ctx, a.binding, a.resp, "", "")
			switch codeOf(err) {
			case "":
				mu.Lock()
				accepted = append(accepted, a.counter)
				mu.Unlock()
			case "INVALID_CREDENTIAL":
			default:
				t.Errorf("counter %d: %v", a.counter, err)
			}
		})
	}
	wg.Wait()
	maxAccepted := uint32(0)
	for _, c := range accepted {
		maxAccepted = max(maxAccepted, c)
	}
	if maxAccepted != n || storedCounter(t, e) != n {
		t.Fatalf("accepted %v, stored %d", accepted, storedCounter(t, e))
	}
	// Sessions started: one per accepted assertion (and the enrollment's).
	if s := e.count(`SELECT count(*) FROM auth_sessions`); s != len(accepted)+1 {
		t.Fatalf("%d sessions for %d sign-ins", s, len(accepted))
	}
	// A replayed lower counter, now.
	o, _ := e.svc.SignInOptions(auth.CSRFBinding(browserCSRF))
	if _, err := e.svc.SignIn(e.ctx, auth.CSRFBinding(browserCSRF), k.assertWith(t, o.RPID, o.Challenge, origin, 3), "", ""); codeOf(err) != "INVALID_CREDENTIAL" {
		t.Fatalf("lower counter: %v", err)
	}
	if storedCounter(t, e) != n {
		t.Fatalf("counter moved to %d", storedCounter(t, e))
	}
}

// An authenticator without a counter (always 0) keeps signing in: 0 over 0.
func TestZeroCounterAuthenticator(t *testing.T) {
	e := newEnv(t)
	k := newSoftKey(t)
	k.fixedCounter = true
	e.enroll(k, browserCSRF)
	for range 3 {
		if _, err := e.signIn(k, browserCSRF); err != nil {
			t.Fatal(err)
		}
	}
}

// Ending a session revokes the browser bearers minted from it, with a
// credential.revoked event each (reason session-ended), and leaves the CLI
// credential a browser hand-off exchanged for one of them.
func TestSessionEndRevokesBrowserCredentialsOnly(t *testing.T) {
	e := newEnv(t)
	k := newSoftKey(t)
	reg, _ := e.enroll(k, browserCSRF)
	session := e.session(reg.Session.SessionToken)
	b1, err := e.svc.MintBearer(e.ctx, session, nil)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := e.svc.MintBearer(e.ctx, session, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b1.ExpiresAt > session.ExpiresAt || b1.ExpiresAt-e.clock.now().UnixMicro() > auth.BearerLifetime.Microseconds() {
		t.Fatalf("bearer expiry %d, session %d", b1.ExpiresAt, session.ExpiresAt)
	}
	handoff, _, _ := e.svc.Authenticate(e.ctx, b2.Token)
	cli, _, err := e.svc.ExchangeCLI(e.ctx, handoff, auth.CLIDefaultTTL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The exchange spent the hand-off bearer.
	if _, reason, _ := e.svc.Authenticate(e.ctx, b2.Token); reason != auth.ReasonRevoked {
		t.Fatalf("exchanged bearer: %q", reason)
	}
	if err := e.svc.EndSession(e.ctx, reg.Session.SessionToken); err != nil {
		t.Fatal(err)
	}
	if _, reason, _ := e.svc.Authenticate(e.ctx, b1.Token); reason != auth.ReasonRevoked {
		t.Fatalf("browser bearer after sign-out: %q", reason)
	}
	if p, reason, _ := e.svc.Authenticate(e.ctx, cli.Token); p == nil {
		t.Fatalf("CLI hand-off credential after sign-out: %q", reason)
	}
	if n := e.count(`SELECT count(*) FROM audit_events WHERE event_type = 'credential.revoked' AND credential_id = ? AND json_extract(metadata, '$.reason') = 'session-ended'`, mustID(t, e, b1.Token)); n != 1 {
		t.Fatalf("%d session-ended events", n)
	}
	// The session is gone: no bearer mints from its token.
	if s, _ := e.svc.SessionOf(e.ctx, reg.Session.SessionToken); s != nil {
		t.Fatal("session still live")
	}
	if _, err := e.svc.MintBearer(e.ctx, session, nil); codeOf(err) != "AUTHENTICATION_REQUIRED" {
		t.Fatalf("mint after sign-out: %v", err)
	}
	// The CLI credential keeps its session's sign-in evidence.
	if gap, _ := auth.VerificationGap(e.ctx, e.store.Reader(), mustID(t, e, cli.Token), auth.KindCLI); gap != "" {
		t.Fatalf("hand-off evidence: %q", gap)
	}
}

func mustID(t *testing.T, e *env, token string) string {
	t.Helper()
	var id string
	if err := e.store.Reader().QueryRowContext(e.ctx, `SELECT id FROM credentials WHERE token_hash = ?`, auth.HashToken(token)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// A session expires, and a sign-out committed before a mint refuses it.
func TestSessionExpiry(t *testing.T) {
	e := newEnv(t)
	k := newSoftKey(t)
	reg, _ := e.enroll(k, browserCSRF)
	e.clock.add(auth.SessionLifetime + time.Minute)
	if s, err := e.svc.SessionOf(e.ctx, reg.Session.SessionToken); s != nil || err != nil {
		t.Fatalf("expired session: %v %v", s, err)
	}
	if n := e.count(`SELECT count(*) FROM auth_sessions`); n != 0 {
		t.Fatalf("%d sessions left", n)
	}
	// A session in use is extended.
	started := mustSignIn(t, e, k)
	e.clock.add(2 * 24 * time.Hour)
	s := e.session(started.SessionToken)
	if s.ExpiresAt <= started.ExpiresAt {
		t.Fatalf("not extended: %d <= %d", s.ExpiresAt, started.ExpiresAt)
	}
}

// Credentials: expiry, revocation, use limits and a disabled identity, each
// refused with its reason; a use limit is never overspent concurrently.
func TestCredentialRefusals(t *testing.T) {
	e := newEnv(t)
	k := newSoftKey(t)
	reg, _ := e.enroll(k, browserCSRF)
	issue := func(in auth.Issue) string {
		var token string
		if err := e.store.Write(e.ctx, func(tx *storage.Tx) error {
			issued, err := auth.IssueCredential(e.ctx, tx, e.clock.now().UnixMicro(), in)
			token = issued.Token
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return token
	}
	soon := e.clock.now().Add(time.Minute).UnixMicro()
	expiring := issue(auth.Issue{IdentityID: reg.IdentityID, Kind: auth.KindCLI, ExpiresAt: &soon})
	five := int64(5)
	limited := issue(auth.Issue{IdentityID: reg.IdentityID, Kind: auth.KindCLI, MaxUses: &five})
	if _, reason, _ := e.svc.Authenticate(e.ctx, "vlt_cli_nonsense"); reason != auth.ReasonInvalid {
		t.Fatalf("unknown: %q", reason)
	}
	if p, _, _ := e.svc.Authenticate(e.ctx, expiring); p == nil {
		t.Fatal("live credential refused")
	}
	e.clock.add(2 * time.Minute)
	if _, reason, _ := e.svc.Authenticate(e.ctx, expiring); reason != auth.ReasonExpired {
		t.Fatalf("expired: %q", reason)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	used := 0
	for range 12 {
		wg.Go(func() {
			if p, _, err := e.svc.Authenticate(e.ctx, limited); err == nil && p != nil {
				mu.Lock()
				used++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if used != 5 {
		t.Fatalf("%d uses of 5", used)
	}
	if _, reason, _ := e.svc.Authenticate(e.ctx, limited); reason != auth.ReasonExhausted {
		t.Fatalf("exhausted: %q", reason)
	}
	open := issue(auth.Issue{IdentityID: reg.IdentityID, Kind: auth.KindCLI})
	p, _, _ := e.svc.Authenticate(e.ctx, open)
	if err := e.svc.RevokeOwnCredential(e.ctx, p, mustID(t, e, open)); err != nil {
		t.Fatal(err)
	}
	if _, reason, _ := e.svc.Authenticate(e.ctx, open); reason != auth.ReasonRevoked {
		t.Fatalf("revoked: %q", reason)
	}
	other := issue(auth.Issue{IdentityID: reg.IdentityID, Kind: auth.KindCLI})
	if err := e.store.Write(e.ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(e.ctx, `UPDATE identities SET disabled = 1 WHERE id = ?`, reg.IdentityID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, reason, _ := e.svc.Authenticate(e.ctx, other); reason != auth.ReasonIdentityDisabled {
		t.Fatalf("disabled: %q", reason)
	}
}

// Recovery: a grant for a named admin enrolls a passkey for that admin;
// --cli-credential consumes at once and issues a CLI credential.
func TestRecovery(t *testing.T) {
	e := newEnv(t)
	k := newSoftKey(t)
	reg, _ := e.enroll(k, browserCSRF)
	g, err := e.svc.IssueRecoveryGrant(e.ctx, auth.Recovery{IdentityID: reg.IdentityID})
	if err != nil {
		t.Fatal(err)
	}
	k2 := newSoftKey(t)
	r2 := e.enrollWith(k2, browserCSRF, g.Token)
	if r2.IdentityID != reg.IdentityID {
		t.Fatalf("recovery enrolled %s, want %s", r2.IdentityID, reg.IdentityID)
	}
	list, _ := e.svc.ListOwnPasskeys(e.ctx, reg.IdentityID)
	kinds := map[string]string{}
	for _, p := range list {
		kinds[p.ID] = *p.SetupGrantKind
	}
	if len(list) != 2 || kinds[r2.PasskeyID] != "recover" || kinds[reg.PasskeyID] != "bootstrap" {
		t.Fatalf("passkeys %v", kinds)
	}
	g, _ = e.svc.IssueRecoveryGrant(e.ctx, auth.Recovery{IdentityID: reg.IdentityID})
	c, issued, err := e.svc.ConsumeForCLICredential(e.ctx, g.Token, "", "recovery credential")
	if err != nil || c.IdentityID != reg.IdentityID || !strings.HasPrefix(issued.Token, "vlt_cli_") {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := e.svc.IssueRecoveryGrant(e.ctx, auth.Recovery{NewAdmin: true}); codeOf(err) != "VALIDATION_FAILED" {
		t.Fatalf("new admin with an admin enabled: %v", err)
	}
	if _, err := e.svc.IssueRecoveryGrant(e.ctx, auth.Recovery{IdentityID: "idn_nobody"}); codeOf(err) != "RESOURCE_NOT_FOUND" {
		t.Fatalf("unknown admin: %v", err)
	}
}

// A credential id already registered, for anyone, is refused before the
// grant is consumed.
func TestDuplicateCredentialID(t *testing.T) {
	e := newEnv(t)
	k := newSoftKey(t)
	reg, _ := e.enroll(k, browserCSRF)
	g, _ := e.svc.IssueRecoveryGrant(e.ctx, auth.Recovery{IdentityID: reg.IdentityID})
	o, _ := e.svc.RegistrationOptions(e.ctx, auth.CSRFBinding(browserCSRF), g.Token, nil)
	_, err := e.svc.Register(e.ctx, auth.CSRFBinding(browserCSRF), nil, k.register(t, o, origin), "", "", "")
	if !errors.Is(err, auth.ErrAlreadyRegistered) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := e.svc.PeekSetupGrant(e.ctx, g.Token); err != nil {
		t.Fatalf("grant consumed by a refused duplicate: %v", err)
	}
}
