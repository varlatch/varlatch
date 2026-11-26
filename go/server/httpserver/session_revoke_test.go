// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/auth/authtest"
)

// enrollWithKey is enrollOver, keeping the authenticator so that another
// browser can sign in with it.
func enrollWithKey(t *testing.T, b *testBrowser, ta *testAuth) (string, *authtest.Key) {
	t.Helper()
	g, err := ta.svc.IssueBootstrapGrant(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var opts struct{ PublicKey auth.CreationOptions }
	decodeInto(t, b.post("/auth/passkey/registration/options", map[string]any{"token": g.Token}), &opts)
	key := authtest.New(t)
	var reg struct {
		IdentityID string
		SignedIn   bool
	}
	decodeInto(t, b.post("/auth/passkey/registration", map[string]any{"response": json.RawMessage(key.Register(t, opts.PublicKey, b.origin)), "name": "Test"}), &reg)
	if !reg.SignedIn {
		t.Fatalf("not signed in: %+v", reg)
	}
	return reg.IdentityID, key
}

func signInWith(t *testing.T, b *testBrowser, key *authtest.Key) {
	t.Helper()
	var opts struct{ PublicKey auth.RequestOptions }
	decodeInto(t, b.post("/auth/passkey/sign-in/options", nil), &opts)
	if w := b.post("/auth/passkey/sign-in", map[string]any{"response": json.RawMessage(key.Assert(t, opts.PublicKey, b.origin))}); w.Code >= 300 {
		t.Fatalf("sign-in: %d %s", w.Code, w.Body.String())
	}
}

func mint(t *testing.T, b *testBrowser) string {
	t.Helper()
	var bearer struct{ Token string }
	decodeInto(t, b.post("/auth/varlatch-token", nil), &bearer)
	return bearer.Token
}

func credentialOf(t *testing.T, s *Server, token string) string {
	t.Helper()
	var me struct{ Credential struct{ ID string } }
	decodeInto(t, do(s, "GET", "/v1/me", "", map[string]string{"Authorization": "Bearer " + token}), &me)
	return me.Credential.ID
}

// Revoking another browser's credential from Active sessions signs that
// browser out: its session ends with the credential, so it cannot mint a
// new bearer from its cookie. The revoking browser stays signed in, and
// revoking an older bearer of its own session does not end it.
func TestRevokingABrowserCredentialEndsItsSession(t *testing.T) {
	s, ta := browserServer(t, browserOrigin)
	mine := newBrowser(t, s, browserOrigin)
	_, key := enrollWithKey(t, mine, ta)
	other := newBrowser(t, s, browserOrigin)
	signInWith(t, other, key)

	myOld := mint(t, mine)
	myBearer := mint(t, mine)
	theirs := mint(t, other)
	auth := map[string]string{"Authorization": "Bearer " + myBearer}

	if w := do(s, "DELETE", "/v1/me/credentials/"+credentialOf(t, s, theirs), "", auth); w.Code != 204 {
		t.Fatalf("revoke the other browser's credential: %d %s", w.Code, w.Body.String())
	}
	if w := do(s, "GET", "/v1/me", "", map[string]string{"Authorization": "Bearer " + theirs}); w.Code != 401 {
		t.Fatalf("the revoked bearer: %d", w.Code)
	}
	if w := other.post("/auth/varlatch-token", nil); w.Code != 401 {
		t.Fatalf("the other browser minted a new bearer after its credential was revoked: %d %s", w.Code, w.Body.String())
	}
	if n := countRows(t, ta, "SELECT count(*) FROM auth_sessions"); n != 1 {
		t.Fatalf("%d sessions, want only the revoking browser's", n)
	}

	// An older bearer of this browser's own session ("Sign out everywhere
	// else" revokes it too): the session stays.
	if w := do(s, "DELETE", "/v1/me/credentials/"+credentialOf(t, s, myOld), "", auth); w.Code != 204 {
		t.Fatalf("revoke an older bearer of this session: %d %s", w.Code, w.Body.String())
	}
	if w := do(s, "GET", "/v1/me", "", auth); w.Code != 200 {
		t.Fatalf("this browser's bearer after revoking its older one: %d", w.Code)
	}
	mint(t, mine)

	// Revoking the presenting credential ("Sign out this browser") ends this
	// session too.
	if w := do(s, "DELETE", "/v1/me/credentials/"+credentialOf(t, s, myBearer), "", auth); w.Code != 204 {
		t.Fatalf("revoke this browser's credential: %d %s", w.Code, w.Body.String())
	}
	if w := mine.post("/auth/varlatch-token", nil); w.Code != 401 {
		t.Fatalf("this browser minted after revoking its own credential: %d", w.Code)
	}
}

// A browser whose bearers have all expired still has its session: revoking
// one of its expired bearers ends that session too, so "Sign out everywhere
// else" reaches a browser idle for more than 15 minutes.
func TestRevokingAnExpiredBrowserCredentialEndsItsSession(t *testing.T) {
	s, ta := browserServer(t, browserOrigin)
	mine := newBrowser(t, s, browserOrigin)
	_, key := enrollWithKey(t, mine, ta)
	other := newBrowser(t, s, browserOrigin)
	signInWith(t, other, key)
	theirs := credentialOf(t, s, mint(t, other))
	if err := ta.store.Write(context.Background(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(context.Background(), "UPDATE credentials SET expires_at = 1 WHERE id = ?", theirs)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	myBearer := mint(t, mine)
	if w := do(s, "DELETE", "/v1/me/credentials/"+theirs, "", map[string]string{"Authorization": "Bearer " + myBearer}); w.Code != 204 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if w := other.post("/auth/varlatch-token", nil); w.Code != 401 {
		t.Fatalf("the idle browser minted a new bearer: %d %s", w.Code, w.Body.String())
	}
}

// The same-session exception is the browser's own: a CLI credential from
// the browser hand-off carries its session too, but revoking a browser
// bearer of that session with it ends the session, as it would from any
// other credential. Revoking the hand-off credential leaves the session.
func TestACLICallerRevokingABrowserCredentialEndsItsSession(t *testing.T) {
	s, ta := browserServer(t, browserOrigin)
	mine := newBrowser(t, s, browserOrigin)
	_, key := enrollWithKey(t, mine, ta)
	var cli struct{ ID, Token string }
	decodeInto(t, do(s, "POST", "/v1/me/credentials/cli", `{}`, map[string]string{"Authorization": "Bearer " + mint(t, mine), "Content-Type": "application/json"}), &cli)
	bearer := credentialOf(t, s, mint(t, mine))
	if w := do(s, "DELETE", "/v1/me/credentials/"+bearer, "", map[string]string{"Authorization": "Bearer " + cli.Token}); w.Code != 204 {
		t.Fatalf("revoke the browser's bearer with the CLI credential: %d %s", w.Code, w.Body.String())
	}
	if w := mine.post("/auth/varlatch-token", nil); w.Code != 401 {
		t.Fatalf("the browser minted a new bearer after the CLI revoked its credential: %d %s", w.Code, w.Body.String())
	}
	if n := countRows(t, ta, "SELECT count(*) FROM auth_sessions"); n != 0 {
		t.Fatalf("%d sessions, want none", n)
	}

	// The hand-off credential revoked from a browser leaves the browser's
	// session alone.
	other := newBrowser(t, s, browserOrigin)
	signInWith(t, other, key)
	decodeInto(t, do(s, "POST", "/v1/me/credentials/cli", `{}`, map[string]string{"Authorization": "Bearer " + mint(t, other), "Content-Type": "application/json"}), &cli)
	if w := do(s, "DELETE", "/v1/me/credentials/"+cli.ID, "", map[string]string{"Authorization": "Bearer " + mint(t, other)}); w.Code != 204 {
		t.Fatalf("revoke the hand-off credential: %d %s", w.Code, w.Body.String())
	}
	mint(t, other)
}
