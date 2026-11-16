// SPDX-License-Identifier: AGPL-3.0-or-later

package access_test

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
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api/openapicheck"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// accessTables are the tables of access-v0.22.0.json
// (go-access-fixture.test.ts).
var accessTables = []string{"installation", "identities", "user", "auth_user_links", "credentials", "organizations", "org_memberships",
	"projects", "environments", "roles", "groups", "group_members", "team_projects", "grants", "security_controls",
	"security_control_counters", "approval_intents", "organization_freezes", "organization_deletions", "idempotency_keys"}

// publicURL is the public URL both servers answer with (approvals need one).
const publicURL = "http://127.0.0.1:8686"

var placeholder = regexp.MustCompile(`\{(org|idn|role|group|prj|env|grant):([^}]+)\}`)

// actionsOf reads a grants row's actions: an array, or its JSON text.
func actionsOf(v any) []string {
	var list []any
	switch x := v.(type) {
	case []any:
		list = x
	case string:
		_ = json.Unmarshal([]byte(x), &list)
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// fillPath is go-access-fixture.test.ts's: rows named by what they are.
func fillPath(t *testing.T, f paritytest.Fixture) func(string) string {
	find := func(table string, match func(paritytest.Row) bool) string {
		for _, r := range f.Rows[table] {
			if match(r) {
				return r["id"].(string)
			}
		}
		t.Fatalf("no %s row for a placeholder", table)
		return ""
	}
	org := func(slug string) string {
		return find("organizations", func(r paritytest.Row) bool { return r["slug"] == slug })
	}
	resolve := func(kind, arg string) string {
		a, b, _ := strings.Cut(arg, ":")
		switch kind {
		case "org":
			return org(a)
		case "idn":
			return find("identities", func(r paritytest.Row) bool { return r["name"] == a })
		case "role":
			return find("roles", func(r paritytest.Row) bool { return r["organization_id"] == org(a) && r["name"] == b })
		case "group":
			return find("groups", func(r paritytest.Row) bool { return r["organization_id"] == org(a) && r["name"] == b })
		case "prj":
			return find("projects", func(r paritytest.Row) bool { return r["organization_id"] == org(a) && r["slug"] == b })
		case "env":
			project, env, _ := strings.Cut(b, "/")
			pid := find("projects", func(r paritytest.Row) bool { return r["organization_id"] == org(a) && r["slug"] == project })
			return find("environments", func(r paritytest.Row) bool { return r["project_id"] == pid && r["name"] == env })
		case "grant":
			roles := map[string]string{}
			for _, r := range f.Rows["roles"] {
				roles[r["id"].(string)] = r["name"].(string)
			}
			return find("grants", func(r paritytest.Row) bool {
				role, _ := r["role_id"].(string)
				return r["organization_id"] == org(a) && (slices.Contains(actionsOf(r["actions"]), b) || (role != "" && roles[role] == b))
			})
		}
		t.Fatalf("unknown placeholder %s", kind)
		return ""
	}
	cache := map[string]string{}
	return func(p string) string {
		return placeholder.ReplaceAllStringFunc(p, func(m string) string {
			if v, ok := cache[m]; ok {
				return v
			}
			sub := placeholder.FindStringSubmatch(m)
			v := resolve(sub[1], sub[2])
			cache[m] = v
			return v
		})
	}
}

// fixtureServer is the Go server on access-v0.22.0.json's rows.
type fixtureServer struct {
	f     paritytest.Fixture
	h     http.Handler
	store *storage.DB
	vs    *values.Service
	now   func() time.Time
}

func newFixtureServer(t *testing.T) fixtureServer {
	t.Helper()
	f, err := paritytest.Read(paritytest.Path("access-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, accessTables); err != nil {
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
	public, _ := url.Parse(publicURL)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	// Its report counts are kept per hour: the replay runs in one.
	now := paritytest.HourClock()
	approvals := auth.New(store, auth.Options{Log: log, RootKEK: rootKEK, PublicURL: public, PersonGate: w.Gates.PersonGate, Now: now})
	vs := values.New(store, rootKEK, values.Options{Log: log, Approvals: approvals, Gates: w.Gates, Now: now})
	h, err := httpserver.New(httpserver.Options{
		Version: f.Version(), Backend: daemon.NewBackend(store, rootKEK), Log: log, PublicURL: public,
		Auth: approvals, Values: vs, Writer: w, RootKEK: rootKEK, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		vs.Settled()
		_ = store.Close()
	})
	return fixtureServer{f: f, h: h, store: store, vs: vs, now: now}
}

// The access fixture's operations give the TypeScript server's answers
// (step 4.4b): Grants of every shape (created, revoked, replaced under an
// Idempotency-Key, with every zod issue of the declaration), roles,
// groups and teams (created, changed in place, deleted), memberships and
// Team-Project links, the lists, each control off, at report and at
// enforce with approvals approved, pending, used and bound to another
// request. Every request, its audit events, the side rows it wrote, the
// report counts; every response valid against the OpenAPI document.
func TestTypeScriptFixture(t *testing.T) {
	fx := newFixtureServer(t)
	f, h, store, vs, now := fx.f, fx.h, fx.store, fx.vs, fx.now
	if len(f.Requests) < 200 {
		t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
	}
	paritytest.Replay(t, paritytest.Target{
		Handler: h, Store: store, Settled: vs.Settled, Path: fillPath(t, f), Now: now,
		// The API takes any string as an action (z.string()), which the
		// OpenAPI document's enum does not describe: the answers that show
		// the file's marker actions ("fx.…") or an unknown one are left
		// out of the document check.
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			if b := rec.Body.String(); strings.Contains(b, `"fx.`) || strings.Contains(b, "no.such-action") {
				return
			}
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
	}, f)
}

// Through the routes, a Grant naming another Organization's group or role
// gets exactly the answer one naming an unknown id gets (the foreign key's
// 500), on create and on replace.
func TestForeignReferenceAnswersAsAnUnknownOne(t *testing.T) {
	fx := newFixtureServer(t)
	fill := fillPath(t, fx.f)
	requestID := regexp.MustCompile(`"requestId":"[^"]*"`)
	send := func(path, body, key string) (int, string, string) {
		t.Helper()
		req := httptest.NewRequest("POST", "/v1/organizations/"+fill(path), strings.NewReader(fill(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+fx.f.Tokens["alice"])
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		rec := httptest.NewRecorder()
		fx.h.ServeHTTP(rec, req)
		fx.vs.Settled()
		return rec.Code, rec.Header().Get("Content-Type"), requestID.ReplaceAllString(rec.Body.String(), `"requestId":"-"`)
	}
	const org = `"scope":{"kind":"organization"}`
	cases := []struct{ name, path, foreign, unknown string }{
		{"create, a group", "{org:acc}/grants",
			`{"subjectGroupId":"{group:rep:devs}",` + org + `,"actions":["project.read"]}`,
			`{"subjectGroupId":"grp_unknownaaaaaaaaaaaaaaaaaaa",` + org + `,"actions":["project.read"]}`},
		{"create, a role", "{org:acc}/grants",
			`{"subjectIdentityId":"{idn:dave}",` + org + `,"roleId":"{role:rep:reader}"}`,
			`{"subjectIdentityId":"{idn:dave}",` + org + `,"roleId":"rol_unknownaaaaaaaaaaaaaaaaaaa"}`},
		{"replace, a group", "{org:acc}/grants/{grant:acc:fx.keep}/replace",
			`{"subjectGroupId":"{group:rep:devs}",` + org + `,"actions":["project.read"]}`,
			`{"subjectGroupId":"grp_unknownaaaaaaaaaaaaaaaaaaa",` + org + `,"actions":["project.read"]}`},
		{"replace, a role", "{org:acc}/grants/{grant:acc:fx.keep}/replace",
			`{"subjectIdentityId":"{idn:dave}",` + org + `,"roleId":"{role:rep:reader}"}`,
			`{"subjectIdentityId":"{idn:dave}",` + org + `,"roleId":"rol_unknownaaaaaaaaaaaaaaaaaaa"}`},
	}
	for i, c := range cases {
		key := func(kind string) string {
			if strings.HasPrefix(c.name, "replace") {
				return "foreign-" + kind + "-" + string(rune('a'+i))
			}
			return ""
		}
		fs, ft, fb := send(c.path, c.foreign, key("foreign"))
		us, ut, ub := send(c.path, c.unknown, key("unknown"))
		if fs != us || ft != ut || fb != ub {
			t.Errorf("%s: another Organization's %d %s %s, an unknown one's %d %s %s", c.name, fs, ft, fb, us, ut, ub)
		}
		if fs != http.StatusInternalServerError || fb != `{"error":{"code":"INTERNAL","message":"Internal error","requestId":"-"}}` {
			t.Errorf("%s: %d %s", c.name, fs, fb)
		}
	}
	var n int
	if err := fx.store.Reader().QueryRow(`SELECT (SELECT count(*) FROM grants g JOIN groups x ON x.id = g.subject_group_id WHERE x.organization_id <> g.organization_id) +
		(SELECT count(*) FROM grants g JOIN roles x ON x.id = g.role_id WHERE x.organization_id <> g.organization_id)`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d Grants naming another Organization's group or role", n)
	}
}
