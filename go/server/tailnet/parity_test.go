// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet_test

import (
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api/openapicheck"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/tailnet"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// tailnetTables are the tables of tailnet-v0.22.0.json
// (go-tailnet-fixture.test.ts).
var tailnetTables = []string{"installation", "identities", "credentials", "organizations", "org_memberships", "grants", "requirements",
	"projects", "contract_revisions", "environments", "env_values", "value_versions", "capabilities", "audit_events"}

// The fixture's listeners (PUBLIC_URL, BROWSER and LISTENERS there).
var (
	browser         = &httpserver.BrowserEndpoint{Host: func() string { return "varlatch.corp.ts.net" }, Port: 8443, Origins: []string{"https://dash.example.com"}}
	browserEndpoint = "https://varlatch.corp.ts.net:8443"
)

func device(tailnetName, id, name string, tags []string, login string) tailnet.Resolution {
	c := &authz.TailnetContext{Tailnet: tailnetName, NodeID: id, NodeName: &name, Tags: tags}
	if login != "" {
		c.UserLogin = &login
	}
	return tailnet.Resolution{Context: c}
}

var listeners = map[string]struct {
	res     tailnet.Resolution
	browser bool
}{
	"tn-prod":         {res: device("corp.ts.net", "nProd1CNTRL", "build-1", []string{"tag:prod"}, "")},
	"tn-user":         {res: device("corp.ts.net", "nLaptopCNTRL", "laptop", []string{}, "alice@example.com")},
	"tn-ci":           {res: device("corp.ts.net", "nCi1CNTRL", "ci-1", []string{"tag:ci"}, "")},
	"tn-shared":       {res: tailnet.Refusal(tailnet.Shared)},
	"tn-unavailable":  {res: tailnet.Refusal(tailnet.ResolverUnavailable)},
	"browser":         {res: device("corp.ts.net", "nProd1CNTRL", "build-1", []string{"tag:prod"}, ""), browser: true},
	"browser-refused": {res: tailnet.Refusal(tailnet.Unrecognized), browser: true},
}

// TestTypeScriptFixture replays the table against varlatchd's listeners on
// the file's rows: the ordinary one, and a tailnet listener per name with
// the same stand-in device check.
func TestTypeScriptFixture(t *testing.T) {
	f, err := paritytest.Read(paritytest.Path("tailnet-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 40 {
		t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
	}
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, tailnetTables); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), storage.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rootKEK, err := hex.DecodeString(f.RootKEK)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := url.Parse("http://127.0.0.1:8686")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	now := paritytest.HourClock()
	approvals := auth.New(store, auth.Options{Log: log, RootKEK: rootKEK, PublicURL: public, PersonGate: w.Gates.PersonGate, Now: now})
	vs := values.New(store, rootKEK, values.Options{Log: log, Approvals: approvals, Gates: w.Gates, Now: now})
	t.Cleanup(vs.Settled)
	server := func(publicURL *url.URL, tl *httpserver.TailnetListener) http.Handler {
		h, err := httpserver.New(httpserver.Options{
			Version: f.Version(), Backend: daemon.NewBackend(store, rootKEK), Log: log, PublicURL: publicURL,
			Auth: approvals, Values: vs, Writer: w, RootKEK: rootKEK, Now: now,
			Tailnet: tl, BrowserEndpoint: func() string { return browserEndpoint },
		})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	handlers := map[string]http.Handler{}
	for name, l := range listeners {
		res := l.res
		tl := &httpserver.TailnetListener{Resolve: func(context.Context, string) tailnet.Resolution { return res }}
		if l.browser {
			tl.Browser = browser
		}
		handlers[name] = server(nil, tl)
	}
	cap := ""
	for _, c := range f.Rows["capabilities"] {
		if c["run_id"] == "known-tailnet" {
			cap, _ = c["id"].(string)
		}
	}
	paritytest.Replay(t, paritytest.Target{
		Handler: server(public, nil), Listeners: handlers, Store: store, Settled: vs.Settled, Now: now,
		Path: strings.NewReplacer("{cap}", cap).Replace,
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
	}, f)
}
