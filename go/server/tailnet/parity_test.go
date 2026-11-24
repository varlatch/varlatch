// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	fx := newFixtureServer(t)
	f, store, server := fx.f, fx.store, fx.server
	handlers := map[string]http.Handler{}
	for name, l := range listeners {
		handlers[name] = server(nil, fx.listener(l.res, l.browser))
	}
	cap := ""
	for _, c := range f.Rows["capabilities"] {
		if c["run_id"] == "known-tailnet" {
			cap, _ = c["id"].(string)
		}
	}
	paritytest.Replay(t, paritytest.Target{
		Handler: server(fx.public, nil), Listeners: handlers, Store: store, Settled: fx.settled, Now: fx.now,
		Path: strings.NewReplacer("{cap}", cap).Replace,
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
	}, f)
}

// fixtureServer builds varlatchd's handlers on the fixture's rows.
type fixtureServer struct {
	f       paritytest.Fixture
	store   *storage.DB
	public  *url.URL
	settled func()
	now     func() time.Time
	server  func(publicURL *url.URL, tl *httpserver.TailnetListener) http.Handler
}

// listener is a tailnet listener whose device check answers res: the
// browser endpoint's with browserEndpoint, else the API's.
func (fixtureServer) listener(res tailnet.Resolution, browserEndpoint bool) *httpserver.TailnetListener {
	tl := &httpserver.TailnetListener{Resolve: func(context.Context, string) tailnet.Resolution { return res }}
	if browserEndpoint {
		tl.Browser = browser
	}
	return tl
}

func newFixtureServer(t *testing.T) fixtureServer {
	t.Helper()
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
	return fixtureServer{f: f, store: store, public: public, settled: vs.Settled, now: now, server: server}
}

// What a Requirement refuses on the API's listener it refuses on the browser
// endpoint, with the same codes and the same record, as a page of the
// dashboard asks for it: a device that does not meet it (the dashboard says
// so), and any device while the node cannot say whose a connection is. The
// names and states stay readable.
func TestTheBrowserEndpointRefusesADeviceThatDoesNotMeetTheRequirement(t *testing.T) {
	const env = "/v1/organizations/tn/projects/api/environments/production"
	for name, c := range map[string]struct {
		res            tailnet.Resolution
		code, recorded string
	}{
		"a device the Requirement does not name": {device("corp.ts.net", "nCi1CNTRL", "ci-1", []string{"tag:ci"}, ""), "TAILNET_CONTEXT_UNAVAILABLE", `"nodeId":"nCi1CNTRL"`},
		"the node cannot say whose device it is": {tailnet.Refusal(tailnet.ResolverUnavailable), "TAILNET_CONTEXT_REQUIRED", `"refused":"resolver-unavailable"`},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newFixtureServer(t)
			h := fx.server(nil, fx.listener(c.res, true))
			send := func(method, path, body string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(method, path, strings.NewReader(body))
				req.Host = "varlatch.corp.ts.net:8443"
				req.Header.Set("Origin", "https://dash.example.com")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+fx.f.Tokens["alice"])
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				return rec
			}
			denied := func() int { return len(paritytest.PGAudit(t, fx.store, "authorization.denied")) }
			before := denied()
			for n, r := range []*httptest.ResponseRecorder{
				send("POST", env+"/disclosures", `{"items":["SECRET"]}`),
				send("GET", env+"/effective-configuration?include=values", ""),
			} {
				if r.Code != 403 || !strings.Contains(r.Body.String(), `"code":"`+c.code+`"`) {
					t.Errorf("request %d: %d %s", n, r.Code, r.Body)
				}
			}
			if got := denied(); got != before+2 {
				t.Fatalf("%d denials recorded, want 2", got-before)
			}
			for _, e := range paritytest.PGAudit(t, fx.store, "authorization.denied")[before:] {
				if got, _ := json.Marshal(e["tailnet"]); !strings.Contains(string(got), c.recorded) {
					t.Errorf("recorded %s, want %s", got, c.recorded)
				}
			}
			if r := send("GET", env+"/effective-configuration", ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"SECRET"`) {
				t.Errorf("the names and states: %d %s", r.Code, r.Body)
			}
		})
	}
}
