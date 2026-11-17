// SPDX-License-Identifier: AGPL-3.0-or-later

package githubapps_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api/openapicheck"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/githubapps"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// mintTables are the tables of github-mint-v0.22.0.json
// (go-github-mint-fixture.test.ts).
var mintTables = []string{"installation", "identities", "credentials", "organizations", "org_memberships", "projects", "environments",
	"grants", "security_controls", "approval_intents", "organization_freezes", "organization_deletions", "github_apps",
	"platform_connections", "sync_targets", "audit_events"}

// mintApps and mintInstallations are the fixture's APPS and INSTALLATIONS.
var mintApps = map[string]struct {
	appID int64
	keys  []string
}{
	"Iv1.acme": {2002, []string{"beta", "other"}}, "Iv1.enf": {3003, []string{"beta", "other"}},
	"Iv1.rep": {5005, []string{"beta", "other"}}, "Iv1.frozen": {6006, []string{"beta", "other"}},
}

type mintRepo struct {
	name              string
	private, archived bool
}

type mintInstallation struct {
	client, account, typ      string
	appID                     int64
	suspended, refuses, fails bool
	selection                 string
	repos                     []mintRepo
}

var mintInstallations = map[int64]mintInstallation{
	77: {client: "Iv1.acme", account: "acme-inc", repos: []mintRepo{{name: "web", private: true}, {name: "api"}, {name: "old", archived: true}}},
	79: {client: "Iv1.acme", account: "acme-inc", refuses: true, selection: "selected", repos: []mintRepo{{name: "web", private: true}}},
	80: {client: "Iv1.acme", account: "acme-inc", fails: true},
	81: {client: "Iv1.acme", account: "acme-inc", suspended: true},
	82: {client: "Iv1.acme", account: "acme-inc", appID: 9999},
	83: {client: "Iv1.acme", account: "alice-personal", typ: "User"},
	91: {client: "Iv1.enf", account: "enf-inc", repos: []mintRepo{{name: "site"}}},
	95: {client: "Iv1.rep", account: "rep-inc", repos: []mintRepo{{name: "app"}}},
}

var (
	oneInstallation = regexp.MustCompile(`^/app/installations/(\d+)$`)
	accessTokens    = regexp.MustCompile(`^/app/installations/(\d+)/access_tokens$`)
	mintedToken     = regexp.MustCompile(`^Bearer minted-(\d+)-(.+)$`)
	repoPath        = regexp.MustCompile(`^/repos/([^/]+)/([^/]+)(/.*)?$`)
	envPublicKey    = regexp.MustCompile(`^/environments/([^/]+)/secrets/public-key$`)
)

// mintGitHub is the fixture's fake GitHub.
func mintGitHub(k keys, log *[]string, mu *sync.Mutex) *http.Client {
	return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		a := r.Header.Get("Authorization")
		var body string
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			body = string(b)
		}
		line := r.Method + " " + r.URL.Scheme + "://" + r.URL.Host + r.URL.RequestURI() + " " + authLine(k, a)
		if body != "" {
			line += " " + body
		}
		mu.Lock()
		*log = append(*log, line)
		mu.Unlock()
		answer := func(status int, b any, extra map[string]string) (*http.Response, error) {
			h := http.Header{"Content-Type": {"application/json"}}
			for name, v := range extra {
				h.Set(name, v)
			}
			return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(string(jsvalue.Stringify(b)))), Request: r}, nil
		}
		msg := func(m string) jsvalue.Object { return jsvalue.Object{{Key: "message", Value: m}} }
		notFound := func() (*http.Response, error) { return answer(404, msg("Not Found"), nil) }
		if r.URL.Host != "api.github.com" {
			return nil, fmt.Errorf("fetch failed")
		}
		// The adapters send an opaque path, as written.
		path := r.URL.Path
		if r.URL.Opaque != "" {
			path, _, _ = strings.Cut(r.URL.Opaque, "?")
		}

		// Signed as an App.
		if path == "/app" || strings.HasPrefix(path, "/app/") {
			jwt, _ := strings.CutPrefix(a, "Bearer ")
			c, ok := payloadOf(jwt)
			if !ok {
				return answer(401, msg("A JSON web token could not be decoded"), nil)
			}
			date := map[string]string{"Date": time.Unix(c.Iat+60, 0).UTC().Format(http.TimeFormat)}
			app, known := mintApps[c.Iss]
			key := signer(k, jwt)
			if key == "conversion" {
				return answer(500, msg("Server Error"), date)
			}
			if !known || !slices.Contains(app.keys, key) {
				return answer(401, msg("Bad credentials"), date)
			}
			mine := func(id int64) bool { i, ok := mintInstallations[id]; return ok && i.client == c.Iss }
			entry := func(id int64) jsvalue.Object {
				i := mintInstallations[id]
				appID, typ, selection := app.appID, "Organization", "all"
				if i.appID != 0 {
					appID = i.appID
				}
				if i.typ != "" {
					typ = i.typ
				}
				if i.selection != "" {
					selection = i.selection
				}
				var suspended any
				if i.suspended {
					suspended = "2026-02-01T00:00:00Z"
				}
				return jsvalue.Object{{Key: "id", Value: id}, {Key: "app_id", Value: appID},
					{Key: "account", Value: jsvalue.Object{{Key: "login", Value: i.account}, {Key: "id", Value: 500 + id}, {Key: "type", Value: typ}}},
					{Key: "repository_selection", Value: selection}, {Key: "suspended_at", Value: suspended}}
			}
			if r.Method == http.MethodGet && path == "/app" {
				return answer(200, jsvalue.Object{{Key: "id", Value: app.appID}, {Key: "slug", Value: c.Iss[4:]}, {Key: "client_id", Value: c.Iss}}, date)
			}
			if r.Method == http.MethodGet && path == "/app/installations" {
				list := []any{}
				if r.URL.Query().Get("page") == "1" {
					var ids []int64
					for id, i := range mintInstallations {
						if mine(id) && i.appID == 0 {
							ids = append(ids, id)
						}
					}
					sort.Slice(ids, func(x, y int) bool { return ids[x] < ids[y] })
					for _, id := range ids {
						list = append(list, entry(id))
					}
				}
				return answer(200, list, date)
			}
			if m := oneInstallation.FindStringSubmatch(path); r.Method == http.MethodGet && m != nil {
				id, _ := strconv.ParseInt(m[1], 10, 64)
				if !mine(id) {
					return notFound()
				}
				return answer(200, entry(id), date)
			}
			if m := accessTokens.FindStringSubmatch(path); r.Method == http.MethodPost && m != nil {
				id, _ := strconv.ParseInt(m[1], 10, 64)
				if !mine(id) {
					return notFound()
				}
				i := mintInstallations[id]
				if i.fails {
					return answer(500, msg("Server Error"), nil)
				}
				v, _ := jsvalue.Parse([]byte(body))
				narrowed, _ := v.(jsvalue.Object)
				repos, scoped := narrowed.Get("repositories")
				if scoped && i.refuses {
					return answer(422, msg("There is at least one repository that does not exist or is not accessible to the parent installation."), nil)
				}
				scope := "all"
				if scoped {
					var names []string
					for _, n := range repos.([]any) {
						names = append(names, n.(string))
					}
					scope = strings.Join(names, "+")
				}
				return answer(201, jsvalue.Object{{Key: "token", Value: "minted-" + m[1] + "-" + scope}, {Key: "expires_at", Value: "2026-09-01T13:00:00Z"}}, nil)
			}
			return notFound()
		}

		// With an installation token.
		m := mintedToken.FindStringSubmatch(a)
		if m == nil {
			return answer(401, msg("Bad credentials"), nil)
		}
		id, _ := strconv.ParseInt(m[1], 10, 64)
		inst, scope := mintInstallations[id], m[2]
		if r.Method == http.MethodGet && path == "/installation/repositories" {
			perPage, page := 30, 1
			if v := r.URL.Query().Get("per_page"); v != "" {
				perPage, _ = strconv.Atoi(v)
			}
			if v := r.URL.Query().Get("page"); v != "" {
				page, _ = strconv.Atoi(v)
			}
			repos := []any{}
			for x := (page - 1) * perPage; x < page*perPage && x < len(inst.repos); x++ {
				rp := inst.repos[x]
				repos = append(repos, jsvalue.Object{{Key: "name", Value: rp.name}, {Key: "full_name", Value: inst.account + "/" + rp.name},
					{Key: "owner", Value: jsvalue.Object{{Key: "login", Value: inst.account}}}, {Key: "private", Value: rp.private}, {Key: "archived", Value: rp.archived}})
			}
			selection := inst.selection
			if selection == "" {
				selection = "all"
			}
			return answer(200, jsvalue.Object{{Key: "total_count", Value: len(inst.repos)}, {Key: "repository_selection", Value: selection}, {Key: "repositories", Value: repos}}, nil)
		}
		if r.Method == http.MethodGet && path == "/users/"+inst.account {
			typ := inst.typ
			if typ == "" {
				typ = "Organization"
			}
			return answer(200, jsvalue.Object{{Key: "login", Value: inst.account}, {Key: "type", Value: typ}}, nil)
		}
		if p := repoPath.FindStringSubmatch(path); r.Method == http.MethodGet && p != nil && p[1] == inst.account {
			repo, rest := p[2], p[3]
			known := repo == "public" || slices.ContainsFunc(inst.repos, func(x mintRepo) bool { return x.name == repo })
			if !known || scope != "all" && scope != repo {
				return notFound()
			}
			if rest == "" {
				return answer(200, jsvalue.Object{{Key: "full_name", Value: inst.account + "/" + repo}, {Key: "private", Value: repo != "public"}}, nil)
			}
			if scope == "all" {
				return answer(403, msg("Resource not accessible by integration"), nil)
			}
			env := envPublicKey.FindStringSubmatch(rest)
			if rest == "/actions/secrets/public-key" || env != nil && env[1] == "prod" {
				return answer(200, jsvalue.Object{{Key: "key_id", Value: "568250167242549743"}, {Key: "key", Value: "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk="}}, nil)
			}
			return notFound()
		}
		return notFound()
	})}
}

// mintPath is the fixture's fillPath: the Connections by name.
func mintPath(f paritytest.Fixture) func(string) string {
	conn := func(name string) string {
		for _, r := range f.Rows["platform_connections"] {
			if r["name"] == name {
				return r["id"].(string)
			}
		}
		return ""
	}
	r := strings.NewReplacer("{main}", conn("Main"), "{gone}", conn("Gone"), "{picky}", conn("Picky"), "{broken}", conn("Broken"), "{orphan}", conn("Orphan"))
	return r.Replace
}

// gateDenialOnPostgres is syncs' adjustment of the same name, for the
// rotation: the re-authorization gate's authorize records its
// authorization.denied through the pool, where it commits on PostgreSQL;
// the fixture's single-connection PGlite rolls it back with the effect's
// transaction. Go records it (a DeferredDenial, after the final job), as
// the TypeScript server does in production; the fixture's request is held
// to that event, built from its rows.
func gateDenialOnPostgres(t *testing.T, f *paritytest.Fixture) {
	t.Helper()
	find := func(table, key string, value any) paritytest.Row {
		for _, r := range f.Rows[table] {
			if r[key] == value {
				return r
			}
		}
		t.Fatalf("no %s with %s %v", table, key, value)
		return nil
	}
	dave := find("identities", "name", "dave")
	credential := find("credentials", "identity_id", dave["id"])
	acme := find("organizations", "slug", "acme")
	target := find("sync_targets", "connection_id", find("platform_connections", "name", "Main")["id"])
	adjusted := false
	for i := range f.Requests {
		r := &f.Requests[i]
		if r.Name != "rotate without disclosure authority" {
			continue
		}
		if len(r.Audit) != 0 {
			t.Fatalf("%s: the fixture now records %d events; drop this adjustment", r.Name, len(r.Audit))
		}
		r.Audit = []paritytest.Row{{
			"action": "secret.reveal", "actor_identity_id": dave["id"], "authz": map[string]any{"denial": "no-grant", "requirements": []any{}},
			"client": "varlatch CLI 0.22.0 on Linux", "credential_id": credential["id"], "decision": "deny", "event_type": "authorization.denied",
			"listener": "ordinary", "metadata": nil, "organization_id": acme["id"], "request_id": "{requestId}",
			"resource":       map[string]any{"environmentId": target["environment_id"], "projectId": target["project_id"]},
			"schema_version": float64(1), "tailnet": nil,
		}}
		adjusted = true
	}
	if !adjusted {
		t.Fatal("no rotation refused by the gate in the fixture")
	}
}

// TestMintFixtures replays both releases' files of the App's installations,
// App Connections (created, checked, listed with installation tokens
// minted per use) and key rotations: every answer, audit event, changed
// row and request to GitHub the same. The rotated keys open to the PEM
// given (G3 at the database level: Go sealed them).
func TestMintFixtures(t *testing.T) {
	for _, file := range []string{"github-mint-v0.22.0.json", "github-mint-v0.21.0.json"} {
		t.Run(file, func(t *testing.T) {
			f, x := read(t, paritytest.Path(file))
			if len(f.Requests) < 50 {
				t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
			}
			gateDenialOnPostgres(t, &f)
			k := readKeys(t)
			path := filepath.Join(t.TempDir(), "varlatch.db")
			if err := paritytest.Prepare(path, f.Rows, mintTables); err != nil {
				t.Fatal(err)
			}
			store, err := storage.Open(context.Background(), storage.Options{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			rootKEK, err := hex.DecodeString(f.RootKEK)
			if err != nil {
				t.Fatal(err)
			}
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			policy := outbound.New(nil, outbound.Options{Log: log})
			t.Cleanup(policy.Close)
			var mu sync.Mutex
			var sent []string
			public, _ := url.Parse(publicURL)
			w := &write.Writer{Store: store, Gates: write.NewGates()}
			now := paritytest.HourClock()
			approvals := auth.New(store, auth.Options{Log: log, RootKEK: rootKEK, PublicURL: public, PersonGate: w.Gates.PersonGate, Now: now})
			vs := values.New(store, rootKEK, values.Options{Log: log, Approvals: approvals, Gates: w.Gates, Now: now})
			h, err := httpserver.New(httpserver.Options{
				Version: f.Version(), Backend: daemon.NewBackend(store, rootKEK), Log: log, PublicURL: public,
				Auth: approvals, Values: vs, Writer: w, RootKEK: rootKEK, Now: now, Outbound: policy,
				Sync: true, SyncClient: mintGitHub(k, &sent, &mu),
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				vs.Settled()
				_ = store.Close()
			})
			got := map[string][]string{}
			paritytest.Replay(t, paritytest.Target{
				Handler: h, Store: store, Settled: vs.Settled, Path: mintPath(f), Now: now,
				Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
					openapicheck.Recorder{T: t}.Exchange(req, body, rec)
				},
				Inspect: func(_ testing.TB, c paritytest.Recorded, _ paritytest.Raw) {
					mu.Lock()
					defer mu.Unlock()
					if len(sent) > 0 {
						got[c.ID] = sent
						sent = nil
					}
				},
			}, f)
			if !reflect.DeepEqual(got, x.Exchanges) {
				for id, want := range x.Exchanges {
					if !reflect.DeepEqual(got[id], want) {
						t.Errorf("%s: sent\n%s\nwant\n%s", id, strings.Join(got[id], "\n"), strings.Join(want, "\n"))
					}
				}
				for id := range got {
					if _, ok := x.Exchanges[id]; !ok {
						t.Errorf("%s: sent %v, the TypeScript server sent nothing", id, got[id])
					}
				}
			}
			// The rotated Apps' keys, sealed by Go, open to the key given.
			for _, appID := range []int64{2002, 3003, 5005} {
				var id, org, sealed string
				if err := store.Reader().QueryRow(`SELECT id, organization_id, key_envelope FROM github_apps WHERE github_app_id = ? AND removed_at IS NULL`, appID).
					Scan(&id, &org, &sealed); err != nil {
					t.Fatalf("App %d: %v", appID, err)
				}
				pemText, err := githubapps.OpenKey(orgKEK(t, store, rootKEK, org), org, id, sealed)
				if err != nil || pemText != k["other"] {
					t.Errorf("App %d: its key does not open to the rotated PEM (%v)", appID, err)
				}
			}
		})
	}
}
