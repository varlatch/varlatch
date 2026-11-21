// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/auth/authtest"
)

// serverWith is a server at pub over svc's database.
func serverWith(t *testing.T, pub *url.URL, svc *auth.Service) *Server {
	t.Helper()
	s, err := New(Options{
		Version: "0.50.0-test", PublicURL: pub, Sync: true, Web: webFS,
		Backend:   &fakeBackend{id: "inst_test", schema: true, kek: true, installation: true},
		AccessLog: NewAccessLog(io.Discard), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: time.Now, Auth: svc,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// register runs a passkey registration with token from b's origin: the
// response, and what the server answered.
func register(t *testing.T, b *testBrowser, token string, key *authtest.Key) (int, string, bool) {
	t.Helper()
	w := b.post("/auth/passkey/registration/options", map[string]any{"token": token})
	if w.Code != 200 {
		return w.Code, "", false
	}
	var opts struct{ PublicKey auth.CreationOptions }
	decodeInto(t, w, &opts)
	w = b.post("/auth/passkey/registration", map[string]any{"response": json.RawMessage(key.Register(t, opts.PublicKey, b.origin)), "name": "Test"})
	var reg struct {
		IdentityID string
		SignedIn   bool
	}
	_ = json.Unmarshal(w.Body.Bytes(), &reg)
	return w.Code, reg.IdentityID, reg.SignedIn
}

// signIn signs in from b's origin with key, its assertion made for rpID.
func signIn(t *testing.T, b *testBrowser, key *authtest.Key, rpID string) int {
	t.Helper()
	var opts struct{ PublicKey auth.RequestOptions }
	decodeInto(t, b.post("/auth/passkey/sign-in/options", nil), &opts)
	key.Counter++
	resp := key.AssertWith(t, rpID, opts.PublicKey.Challenge, b.origin, key.Counter)
	return b.post("/auth/passkey/sign-in", map[string]any{"response": json.RawMessage(resp)}).Code
}

// A move (slice 6.9, decision 13): the relying party is the public URL's
// host, so at the new address a passkey of the old one is refused, before
// the operator confirms the change (its assertion names the old RP ID)
// and after it (the passkey is gone); a re-enrollment link adds a passkey
// to the same identity, from the new origin only, once; the new passkey
// signs in there.
func TestMoveReenrollsAtTheNewRelyingParty(t *testing.T) {
	const oldURL, newURL = "https://vault.example.com", "https://vault2.example.com"
	ctx := context.Background()
	sOld, ta := browserServer(t, oldURL)
	old := authtest.New(t)
	g, err := ta.svc.IssueBootstrapGrant(ctx)
	if err != nil {
		t.Fatal(err)
	}
	code, admin, ok := register(t, newBrowser(t, sOld, oldURL), g.Token, old)
	if code != 200 || admin == "" || !ok {
		t.Fatalf("enrollment at the old address: %d %q", code, admin)
	}
	if code := signIn(t, newBrowser(t, sOld, oldURL), old, "vault.example.com"); code != 200 {
		t.Fatalf("sign-in at the old address: %d", code)
	}

	// The same database, served at the new address.
	pub, _ := url.Parse(newURL)
	svc := auth.New(ta.store, auth.Options{PublicURL: pub, RootKEK: make([]byte, 32)})
	s := serverWith(t, pub, svc)
	if code := signIn(t, newBrowser(t, s, newURL), old, "vault.example.com"); code == 200 {
		t.Fatal("the old relying party's passkey signed in at the new address")
	}
	// The operator confirms the move: the old passkeys are removed.
	done, err := svc.CompletePublicURLChange(ctx, oldURL, newURL)
	if err != nil || done.PasskeysRemoved != 1 {
		t.Fatalf("public-url-changed: %+v %v", done, err)
	}
	if code := signIn(t, newBrowser(t, s, newURL), old, "vault2.example.com"); code == 200 {
		t.Fatal("a removed passkey signed in")
	}
	grants, err := svc.IssueReenrollmentGrants(ctx, auth.Reenroll{IdentityIDs: []string{admin}})
	if err != nil || len(grants) != 1 {
		t.Fatalf("reenroll: %v", err)
	}
	// From the old origin, the new address refuses the ceremony.
	if code, _, _ := register(t, newBrowser(t, s, oldURL), grants[0].Token, authtest.New(t)); code == 200 {
		t.Fatal("a re-enrollment from the old origin")
	}
	fresh := authtest.New(t)
	if code, id, ok := register(t, newBrowser(t, s, newURL), grants[0].Token, fresh); code != 200 || id != admin || !ok {
		t.Fatalf("re-enrollment: %d %q %v", code, id, ok)
	}
	if code, _, _ := register(t, newBrowser(t, s, newURL), grants[0].Token, authtest.New(t)); code == 200 {
		t.Fatal("a re-enrollment link worked twice")
	}
	if code := signIn(t, newBrowser(t, s, newURL), fresh, "vault2.example.com"); code != 200 {
		t.Fatalf("sign-in with the new passkey: %d", code)
	}
	if n := countRows(t, ta, `SELECT count(*) FROM audit_events WHERE event_type = 'reenrollment.completed'`); n != 1 {
		t.Fatalf("reenrollment.completed: %d", n)
	}
	if n := countRows(t, ta, `SELECT count(*) FROM passkey_provenance WHERE setup_grant_kind = 'reenroll'`); n != 1 {
		t.Fatalf("the new passkey's provenance: %d", n)
	}
}
