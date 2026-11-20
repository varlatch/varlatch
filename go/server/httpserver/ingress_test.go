// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/auth/authtest"
	"github.com/varlatch/varlatch/go/server/tailnet"
)

// The origins of every ingress a Go installation may serve (ADR-0059
// Decision 6; step 6, slice 6.3b), and a few near misses.
var ingressOrigins = []string{
	"http://localhost:8686",             // localhost
	"http://127.0.0.1:8686",             // the plain listener by address
	"https://vault.example.com",         // own proxy, or public HTTPS on 443
	"https://vault.example.com:8443",    // public HTTPS on another port
	"http://vault.example.com",          // the redirect listener's scheme
	"https://varlatch.corp.ts.net:8443", // the tailnet browser endpoint
	"https://evil.vault.example.com",    // a name below the RP ID
	"https://example.com",               // the name above it
}

// TestIngressOriginsAndRPID: whatever ingress an installation uses
// (localhost, its own proxy, or public HTTPS, beside a tailnet listener),
// there is one relying party, its public URL's: the RP ID is the public
// URL's host, and a passkey ceremony (registration and sign-in) is
// accepted only from the public URL's exact origin, scheme and port
// included. Every other ingress's origin is refused twice over: by the
// state-changing request's Origin check (before the body is read), and,
// with the right Origin header, by the origin the authenticator signed
// (clientDataJSON); an assertion for another RP ID is refused too. A
// refused attempt signs nothing in, and the right one then does.
func TestIngressOriginsAndRPID(t *testing.T) {
	for _, mode := range []struct {
		name, public string
		proxies      bool
	}{
		{"localhost", "http://localhost:8686", false},
		{"own proxy", "https://vault.example.com", true},
		{"public HTTPS", "https://vault.example.com:8443", false},
	} {
		t.Run(mode.name, func(t *testing.T) {
			pub, _ := url.Parse(mode.public)
			s, _, _, _, ta := newTestServerAuth(t, func(o *Options) {
				o.PublicURL = pub
				if mode.proxies {
					o.TrustedProxies = func(string) bool { return true }
				}
			})
			rp := auth.RelyingPartyOf(pub)
			if rp.ID != pub.Hostname() || rp.Origin != mode.public {
				t.Fatalf("the relying party %+v", rp)
			}
			b := newBrowser(t, s, rp.Origin)

			// Registration: the RP ID is the public URL's host; another
			// origin, signed by the authenticator, is refused.
			g, err := ta.svc.IssueBootstrapGrant(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			creation := func() auth.CreationOptions {
				var opts struct{ PublicKey auth.CreationOptions }
				decodeInto(t, b.post("/auth/passkey/registration/options", map[string]any{"token": g.Token}), &opts)
				if opts.PublicKey.RP.ID != rp.ID {
					t.Fatalf("registration's RP ID %q", opts.PublicKey.RP.ID)
				}
				return opts.PublicKey
			}
			key := authtest.New(t)
			for _, other := range ingressOrigins {
				if other == rp.Origin {
					continue
				}
				w := b.send("POST", "/auth/passkey/registration/options", map[string]any{"token": g.Token}, map[string]string{"Origin": other, CSRFHeader: b.csrf()})
				if e := decode(t, w); w.Code != http.StatusForbidden || e.Error.Details["reason"] != "origin" {
					t.Errorf("registration options from %s: %d %s", other, w.Code, w.Body.String())
				}
				if w := b.post("/auth/passkey/registration", map[string]any{"response": json.RawMessage(key.Register(t, creation(), other)), "name": "Test"}); w.Code < 400 {
					t.Errorf("a registration signed for %s: %d %s", other, w.Code, w.Body.String())
				}
			}
			var reg struct{ SignedIn bool }
			decodeInto(t, b.post("/auth/passkey/registration", map[string]any{"response": json.RawMessage(key.Register(t, creation(), rp.Origin)), "name": "Test"}), &reg)
			if !reg.SignedIn {
				t.Fatal("the registration from the public origin did not sign in")
			}
			if w := b.post("/auth/sign-out", nil); w.Code != 204 {
				t.Fatalf("sign-out %d", w.Code)
			}

			// Sign-in: the same rules, and the RP ID the assertion names.
			request := func() auth.RequestOptions {
				var opts struct{ PublicKey auth.RequestOptions }
				decodeInto(t, b.post("/auth/passkey/sign-in/options", nil), &opts)
				if opts.PublicKey.RPID != rp.ID {
					t.Fatalf("sign-in's RP ID %q", opts.PublicKey.RPID)
				}
				return opts.PublicKey
			}
			signedIn := func() bool {
				var sess struct{ IdentityID *string }
				decodeInto(t, b.send("GET", "/auth/session", nil, nil), &sess)
				return sess.IdentityID != nil
			}
			for _, other := range ingressOrigins {
				if other == rp.Origin {
					continue
				}
				w := b.send("POST", "/auth/passkey/sign-in/options", nil, map[string]string{"Origin": other, CSRFHeader: b.csrf()})
				if e := decode(t, w); w.Code != http.StatusForbidden || e.Error.Details["reason"] != "origin" {
					t.Errorf("sign-in options from %s: %d %s", other, w.Code, w.Body.String())
				}
				if w := b.post("/auth/passkey/sign-in", map[string]any{"response": json.RawMessage(key.Assert(t, request(), other))}); w.Code < 400 || signedIn() {
					t.Errorf("an assertion signed for %s: %d %s", other, w.Code, w.Body.String())
				}
			}
			for _, otherRP := range []string{"example.com", "varlatch.corp.ts.net", "localhost", "vault.example.com.evil"} {
				if otherRP == rp.ID {
					continue
				}
				o := request()
				key.Counter++
				if w := b.post("/auth/passkey/sign-in", map[string]any{"response": json.RawMessage(key.AssertWith(t, otherRP, o.Challenge, rp.Origin, key.Counter))}); w.Code < 400 || signedIn() {
					t.Errorf("an assertion for RP ID %s: %d %s", otherRP, w.Code, w.Body.String())
				}
			}
			if w := b.post("/auth/passkey/sign-in", map[string]any{"response": json.RawMessage(key.Assert(t, request(), rp.Origin))}); w.Code >= 300 || !signedIn() {
				t.Fatalf("the sign-in from the public origin: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

// TestTailnetListenerRunsNoCeremony: the tailnet listener (and its
// browser endpoint, built the same way) serves no passkey ceremony, no
// browser session and no enrollment page, whatever the public URL is: a
// ceremony runs only at the public URL's origin.
func TestTailnetListenerRunsNoCeremony(t *testing.T) {
	tl, _, _, _ := newTestServer(t, tailnetListener(tailnet.Refusal(tailnet.Unrecognized)))
	for _, p := range []string{"/auth/passkey/sign-in/options", "/auth/passkey/sign-in", "/auth/passkey/registration/options", "/auth/passkey/registration", "/auth/sign-out", "/auth/varlatch-token"} {
		for _, origin := range ingressOrigins {
			if w := do(tl, "POST", p, `{}`, map[string]string{"Origin": origin, "Content-Type": "application/json"}); w.Code != http.StatusNotFound {
				t.Errorf("POST %s from %s on a tailnet listener: %d", p, origin, w.Code)
			}
		}
	}
}

// TestMisdirectedIsLoggedAndCharged: on a direct connection (the public
// HTTPS listener), a request for a host other than the public URL's gets
// 421 and goes through the access log (with its status) and, on the API,
// the request window, like any other request; the public host, in any
// case and with a port, is served; a connection that is not direct (the
// plain listener) is never refused for its Host.
func TestMisdirectedIsLoggedAndCharged(t *testing.T) {
	s, _, _, logBuf := newTestServer(t, func(o *Options) { o.PublicURL, _ = url.Parse("https://vault.example.com") })
	send := func(host, path string, directConn bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = host
		r.RemoteAddr = "192.0.2.10:40000"
		if directConn {
			r = r.WithContext(context.WithValue(r.Context(), directKey{}, true))
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := send("other.example.com", "/v1/meta", true); w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("another host, direct: %d %s", w.Code, w.Body.String())
	}
	var rec AccessRecord
	lines := strings.Split(strings.TrimSpace(logBuf.String()), "\n")
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &rec); err != nil || rec.Status != http.StatusMisdirectedRequest || rec.Path != "/v1/meta" || !rec.Window {
		t.Errorf("the 421's access record: %+v %v", rec, err)
	}
	if w := send("other.example.com", "/", true); w.Code != http.StatusMisdirectedRequest {
		t.Errorf("another host, direct, a page: %d", w.Code)
	}
	for _, host := range []string{"vault.example.com", "VAULT.example.com:443", "vault.example.com:8443"} {
		if w := send(host, "/v1/meta", true); w.Code != 200 {
			t.Errorf("%s, direct: %d", host, w.Code)
		}
	}
	if w := send("other.example.com", "/v1/meta", false); w.Code != 200 {
		t.Errorf("another host on the plain listener: %d", w.Code)
	}
}
