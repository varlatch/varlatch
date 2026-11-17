// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/tailnet"
)

func tailnetListener(res tailnet.Resolution) func(*Options) {
	return func(o *Options) {
		o.PublicURL = nil
		o.Tailnet = &TailnetListener{Resolve: func(context.Context, string) tailnet.Resolution { return res }}
	}
}

func metaCapabilities(t *testing.T, s http.Handler) []string {
	t.Helper()
	w := do(s, "GET", "/v1/meta", "", nil)
	var m struct{ Capabilities []string }
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	return m.Capabilities
}

// /v1/meta lists tailnet.browser-reads where a browser endpoint is
// configured; a tailnet listener serves no browser session, so it lists
// no auth.session (and no auth.device, having no public URL).
func TestMetaOnTheListeners(t *testing.T) {
	plain, _, _, _ := newTestServer(t, nil)
	if slices.Contains(metaCapabilities(t, plain), "tailnet.browser-reads") {
		t.Error("tailnet.browser-reads without a browser endpoint")
	}
	withEndpoint, _, _, _ := newTestServer(t, func(o *Options) { o.BrowserEndpoint = func() string { return "https://varlatch.corp.ts.net:8443" } })
	if caps := metaCapabilities(t, withEndpoint); !slices.Contains(caps, "tailnet.browser-reads") || !slices.Contains(caps, "auth.session") {
		t.Errorf("the ordinary listener with a browser endpoint: %v", caps)
	}
	tl, _, _, _ := newTestServer(t, tailnetListener(tailnet.Refusal(tailnet.Unrecognized)))
	if caps := metaCapabilities(t, tl); slices.Contains(caps, "auth.session") || slices.Contains(caps, "auth.device") {
		t.Errorf("a tailnet listener: %v", caps)
	}
}

// A tailnet listener is the API alone: no dashboard, browser session or
// enrollment page (as the TypeScript tailnet apps, built without them).
func TestTailnetListenerServesTheAPIOnly(t *testing.T) {
	tl, _, _, _ := newTestServer(t, tailnetListener(tailnet.Refusal(tailnet.Unrecognized)))
	for _, p := range []string{"/", "/o/acme/projects", "/auth/session", "/enroll", "/enroll.js"} {
		if w := do(tl, "GET", p, "", nil); w.Code != http.StatusNotFound {
			t.Errorf("GET %s on a tailnet listener: %d", p, w.Code)
		}
	}
	if w := do(tl, "GET", "/healthz", "", nil); w.Code != http.StatusOK {
		t.Errorf("GET /healthz: %d", w.Code)
	}
}

// On a tailnet listener every peer comes from the node, so a recognized
// device gets a request window of its own: one device's 600 requests do
// not refuse another's.
func TestRequestWindowPerDevice(t *testing.T) {
	dev := func(id string) tailnet.Resolution {
		name := "d"
		return tailnet.Resolution{Context: &authz.TailnetContext{Tailnet: "corp.ts.net", NodeID: id, NodeName: &name}}
	}
	var current tailnet.Resolution
	tl, _, _, _ := newTestServer(t, func(o *Options) {
		o.PublicURL = nil
		o.Tailnet = &TailnetListener{Resolve: func(context.Context, string) tailnet.Resolution { return current }}
	})
	current = dev("nA")
	for i := 0; i < 600; i++ {
		if w := do(tl, "GET", "/v1/meta", "", nil); w.Code != http.StatusOK {
			t.Fatalf("request %d of device A: %d", i+1, w.Code)
		}
	}
	if w := do(tl, "GET", "/v1/meta", "", nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("device A's 601st request: %d", w.Code)
	}
	current = dev("nB")
	if w := do(tl, "GET", "/v1/meta", "", nil); w.Code != http.StatusOK {
		t.Fatalf("device B's first request: %d", w.Code)
	}
}

// #220 review P1: while its admission refuses (tailnet access closed),
// a tailnet listener answers every request 403 TAILNET_CONTEXT_UNAVAILABLE
// before resolving the peer; an admitted request runs under the
// admission's context.
func TestTailnetListenerAdmission(t *testing.T) {
	resolved := 0
	var admitted context.Context
	open := false
	type key struct{}
	tl, _, _, _ := newTestServer(t, func(o *Options) {
		o.PublicURL = nil
		o.Tailnet = &TailnetListener{
			Resolve: func(ctx context.Context, _ string) tailnet.Resolution {
				resolved++
				admitted = ctx
				return tailnet.Refusal(tailnet.Unrecognized)
			},
			Admit: func(ctx context.Context) (context.Context, func(), bool) {
				if !open {
					return nil, nil, false
				}
				return context.WithValue(ctx, key{}, "admitted"), func() {}, true
			},
		}
	})
	for _, p := range []string{"/healthz", "/v1/meta", "/v1/organizations"} {
		w := do(tl, "GET", p, "", nil)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"code":"TAILNET_CONTEXT_UNAVAILABLE"`) || !strings.Contains(w.Body.String(), TailnetClosedMessage) {
			t.Errorf("GET %s while closed: %d %s", p, w.Code, w.Body.String())
		}
	}
	if w := do(tl, "POST", "/v1/organizations", `{"name":"A","slug":"a"}`, nil); w.Code != http.StatusForbidden {
		t.Errorf("POST while closed: %d", w.Code)
	}
	if resolved != 0 {
		t.Fatalf("a peer was resolved while closed: %d", resolved)
	}
	open = true
	if w := do(tl, "GET", "/healthz", "", nil); w.Code != http.StatusOK || resolved != 1 || admitted.Value(key{}) != "admitted" {
		t.Fatalf("while open: %d, %d resolved", w.Code, resolved)
	}
}

// A dashboard on a public origin reaching the browser endpoint on its
// tailnet address: Chromium's Private Network Access preflight asks for
// Access-Control-Allow-Private-Network, which only the browser endpoint
// gives, and only to an origin it already allows.
func TestPrivateNetworkPreflight(t *testing.T) {
	const allowed = "https://dash.example.com"
	browser := func(o *Options) {
		tailnetListener(tailnet.Refusal(tailnet.Unrecognized))(o)
		o.Tailnet.Browser = &BrowserEndpoint{Host: func() string { return "varlatch.corp.ts.net" }, Port: 8443, Origins: []string{allowed}}
	}
	endpoint, _, _, _ := newTestServer(t, browser)
	plainTailnet, _, _, _ := newTestServer(t, tailnetListener(tailnet.Refusal(tailnet.Unrecognized)))
	ordinary, _, _, _ := newTestServer(t, nil)
	preflight := func(origin string) map[string]string {
		return map[string]string{
			"Origin":                                 origin,
			"Access-Control-Request-Method":          "GET",
			"Access-Control-Request-Headers":         "authorization",
			"Access-Control-Request-Private-Network": "true",
		}
	}
	const url = "https://varlatch.corp.ts.net:8443/v1/tailnet/context"

	w := do(endpoint, "OPTIONS", url, "", preflight(allowed))
	if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Private-Network") != "true" ||
		w.Header().Get("Access-Control-Allow-Origin") != allowed {
		t.Errorf("an allowed origin's preflight: %d %v", w.Code, w.Header())
	}
	plain := preflight(allowed)
	delete(plain, "Access-Control-Request-Private-Network")
	if w := do(endpoint, "OPTIONS", url, "", plain); w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Private-Network") != "" {
		t.Errorf("a preflight that does not ask: %d %v", w.Code, w.Header())
	}
	if w := do(endpoint, "OPTIONS", url, "", preflight("https://elsewhere.example.com")); w.Code != http.StatusForbidden ||
		w.Header().Get("Access-Control-Allow-Private-Network") != "" || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("another origin's preflight: %d %v", w.Code, w.Header())
	}
	for name, s := range map[string]http.Handler{"the plain tailnet listener": plainTailnet, "the ordinary listener": ordinary} {
		if w := do(s, "OPTIONS", url, "", preflight(allowed)); w.Header().Get("Access-Control-Allow-Private-Network") != "" {
			t.Errorf("%s: %d %v", name, w.Code, w.Header())
		}
	}
}
