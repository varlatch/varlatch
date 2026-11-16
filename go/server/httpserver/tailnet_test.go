// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
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
	withEndpoint, _, _, _ := newTestServer(t, func(o *Options) { o.BrowserEndpoint = "https://varlatch.corp.ts.net:8443" })
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
