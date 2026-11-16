// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api/openapicheck"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

var writeGoSealed = flag.String("write-go-sealed", "", "write the v0.22.0 connections fixture with the canary, every Organization KEK, every Connection credential and the App's key sealed again by Go to this path")

// connectionsTables are the tables of connections-v0.22.0.json
// (go-connections-fixture.test.ts).
var connectionsTables = []string{"installation", "identities", "credentials", "organizations", "org_memberships", "projects", "environments",
	"grants", "security_controls", "approval_intents", "organization_freezes", "organization_deletions", "github_apps",
	"platform_connections", "sync_targets", "sync_runs", "member_integrations", "audit_events"}

// The fixture's public URL, resolver and fake platforms (PUBLIC_URL,
// RESOLVE, GITHUB_KEY, EXPIRES and platforms there).
const publicURL = "http://127.0.0.1:8686"

var resolved = map[string]string{
	"coolify.public.example":        "93.184.216.40",
	"happy-animal-123.convex.cloud": "93.184.216.41",
	"coolify.internal":              "10.1.2.40",
}

var githubKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x09", 32)))

const expires = "2026-09-01 12:00:00 UTC"

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// platforms is the fixture's fake GitHub, Coolify and Convex: each request
// logged as "METHOD URL AUTHORIZATION [BODY]" and answered by host, path
// and credential.
func platforms(log *[]string, mu *sync.Mutex) *http.Client {
	return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		auth := r.Header.Get("Authorization")
		line := r.Method + " " + r.URL.Scheme + "://" + r.URL.Host + r.URL.RequestURI() + " " + auth
		if r.Body != nil {
			if b, _ := io.ReadAll(r.Body); len(b) > 0 {
				line += " " + string(b)
			}
		}
		mu.Lock()
		*log = append(*log, line)
		mu.Unlock()
		path := r.URL.EscapedPath()
		if r.URL.Opaque != "" {
			path, _, _ = strings.Cut(r.URL.Opaque, "?")
		}
		answer := func(status int, body any, extra map[string]string) (*http.Response, error) {
			h := http.Header{"Content-Type": {"application/json"}}
			for k, v := range extra {
				h.Set(k, v)
			}
			text, ok := body.(string)
			if !ok {
				b, _ := json.Marshal(body)
				text = string(b)
			}
			return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(text)), Request: r}, nil
		}
		rejected := strings.Contains(auth, "rejected")
		switch r.URL.Host {
		case "api.github.com":
			if rejected {
				return answer(401, map[string]any{"message": "Bad credentials"}, nil)
			}
			expiry := map[string]string{}
			if strings.Contains(auth, "expiring") {
				expiry["github-authentication-token-expiration"] = expires
			}
			repo := func(name string, private bool, extra map[string]any) map[string]any {
				m := map[string]any{"name": name, "owner": map[string]any{"login": "acme"}, "private": private}
				for k, v := range extra {
					m[k] = v
				}
				return m
			}
			switch {
			case path == "/users/acme":
				return answer(200, map[string]any{"login": "acme", "type": "Organization"}, expiry)
			case path == "/orgs/acme/repos":
				return answer(200, []any{repo("api", false, nil), repo("web", true, nil), repo("old", false, map[string]any{"archived": true})}, expiry)
			case strings.HasSuffix(path, "/public-key"):
				if strings.Contains(path, "/missing/") {
					return answer(404, map[string]any{"message": "Not Found"}, nil)
				}
				return answer(200, map[string]any{"key_id": "k1", "key": githubKey}, expiry)
			case path == "/repos/acme/api":
				return answer(200, map[string]any{"name": "api"}, expiry)
			}
			return answer(404, map[string]any{"message": "Not Found"}, nil)
		case "coolify.public.example":
			if rejected {
				return answer(401, map[string]any{"message": "Unauthenticated."}, nil)
			}
			switch path {
			case "/api/v1/version":
				return answer(200, "4.0.0-beta.420", nil)
			case "/api/v1/applications":
				return answer(200, []any{
					map[string]any{"uuid": "app-uuid-1", "name": "Web", "fqdn": "https://web.example.com,https://www.example.com"},
					map[string]any{"uuid": "app-uuid-2", "name": "api", "fqdn": nil},
				}, nil)
			case "/api/v1/services":
				return answer(200, []any{map[string]any{"uuid": "svc-uuid-1", "name": "Stack"}}, nil)
			case "/api/v1/applications/app-uuid-1":
				return answer(200, map[string]any{"uuid": "app-uuid-1", "name": "Web"}, nil)
			case "/api/v1/services/svc-uuid-1":
				return answer(200, map[string]any{"uuid": "svc-uuid-1", "name": "Stack",
					"applications": []any{map[string]any{"name": "web"}}, "databases": []any{map[string]any{"name": "db"}}}, nil)
			case "/api/v1/services/svc-uuid-1/envs":
				return answer(200, []any{map[string]any{"key": "A", "value": "1"}, map[string]any{"key": "B"}}, nil)
			}
			return answer(404, map[string]any{"message": "Not found."}, nil)
		case "happy-animal-123.convex.cloud":
			if rejected {
				return answer(401, map[string]any{"code": "BadAdminKey"}, nil)
			}
			if path == "/api/check_admin_key" {
				return answer(200, map[string]any{"success": true}, nil)
			}
			return answer(404, map[string]any{}, nil)
		}
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: io.ErrUnexpectedEOF}
	})}
}

// extra is what the connections fixture holds beyond the kit's members.
type extra struct {
	Credentials map[string]string   `json:"credentials"`
	AppKey      string              `json:"appKey"`
	Exchanges   map[string][]string `json:"exchanges"`
}

// gateDenialOnPostgres is what the TypeScript server writes on PostgreSQL
// and the fixture's PGlite does not: the re-authorization gate's
// authorize records its authorization.denied through ctx.db, the pool, on
// a connection of its own, so it commits while the replacement's
// transaction rolls back; PGlite has one connection, where the rollback
// takes the event with it. Go records it (a DeferredDenial, after the
// job), as the TypeScript server does in production; the fixture's request
// is held to that event, built from its rows.
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
	bob := find("identities", "name", "bob")
	credential := find("credentials", "identity_id", bob["id"])
	acme := find("organizations", "slug", "acme")
	gh := ""
	for _, c := range f.Rows["platform_connections"] {
		if c["organization_id"] == acme["id"] && c["name"] == "GitHub" {
			gh = c["id"].(string)
		}
	}
	var first paritytest.Row
	for _, target := range f.Rows["sync_targets"] {
		if target["connection_id"] == gh && (first == nil || target["id"].(string) < first["id"].(string)) {
			first = target
		}
	}
	for i := range f.Requests {
		r := &f.Requests[i]
		if r.Name != "replace without disclosure authority" {
			continue
		}
		if len(r.Audit) != 0 {
			t.Fatalf("%s: the fixture now records %d events; drop this adjustment", r.Name, len(r.Audit))
		}
		r.Audit = []paritytest.Row{{
			"action": "secret.reveal", "actor_identity_id": bob["id"], "authz": map[string]any{"denial": "no-grant", "requirements": []any{}},
			"client": "varlatch CLI 0.22.0 on Linux", "credential_id": credential["id"], "decision": "deny", "event_type": "authorization.denied",
			"listener": "ordinary", "metadata": nil, "organization_id": acme["id"], "request_id": "{requestId}",
			"resource":       map[string]any{"environmentId": first["environment_id"], "projectId": first["project_id"]},
			"schema_version": float64(1), "tailnet": nil,
		}}
		return
	}
	t.Fatal("no request: replace without disclosure authority")
}

func read(t *testing.T, path string) (paritytest.Fixture, extra) {
	t.Helper()
	f, err := paritytest.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var x extra
	if err := json.Unmarshal(b, &x); err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 100 || len(x.Exchanges) < 20 || len(x.Credentials) < 9 {
		t.Fatalf("%s: %d requests, %d exchanges, %d credentials: the fixture is incomplete", path, len(f.Requests), len(x.Exchanges), len(x.Credentials))
	}
	gateDenialOnPostgres(t, &f)
	return f, x
}

// fillPath is go-connections-fixture.test.ts's: acme's id and the named
// Connections, by Organization and name.
func fillPath(f paritytest.Fixture) func(string) string {
	orgID := func(slug string) string {
		for _, o := range f.Rows["organizations"] {
			if o["slug"] == slug {
				return o["id"].(string)
			}
		}
		return ""
	}
	conn := func(slug, name string) string {
		for _, c := range f.Rows["platform_connections"] {
			if c["organization_id"] == orgID(slug) && c["name"] == name {
				return c["id"].(string)
			}
		}
		return ""
	}
	return strings.NewReplacer(
		"{acmeId}", orgID("acme"),
		"{gh}", conn("acme", "GitHub"), "{ghExpiring}", conn("acme", "Expiring"), "{coolify}", conn("acme", "Coolify"),
		"{convex}", conn("acme", "Convex"), "{app}", conn("acme", "App"), "{frozenConn}", conn("frozen", "Frozen"),
		"{deletingConn}", conn("deleting", "Deleting"), "{repConn}", conn("rep", "Rep conn"), "{enfConn}", conn("enf", "Enf conn"),
		"{enfDel}", conn("enf", "Enf del"),
	).Replace
}

// replay runs the table against varlatchd on the file's rows, with the
// fake platforms, and compares each request's requests to them.
func replay(t *testing.T, f paritytest.Fixture, x extra) {
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, connectionsTables); err != nil {
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
	policy := outbound.New(nil, outbound.Options{Log: log, Resolve: func(_ context.Context, name string) ([]outbound.Answer, error) {
		if a, ok := resolved[name]; ok {
			return []outbound.Answer{{Address: a, Family: 4}}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}})
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
		Sync: true, SyncClient: platforms(&sent, &mu),
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
		Handler: h, Store: store, Settled: vs.Settled, Path: fillPath(f), Now: now,
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
}

// The connections fixtures give the TypeScript server's answers (step
// 4.9b): listPlatformConnections, createPlatformConnection (zod, the
// adapters' validation, the outbound policy's refusals, frozen, deleting,
// at report and at enforce with its approval), checkPlatformAccess and
// listPlatformDestinations (stored, replacement and new credentials,
// destinations, expiry), getPlatformConnection (with its Targets),
// replacePlatformCredential (versions, the disclosure gate, resumed
// Targets) and revokePlatformConnection, with their audit events and side
// rows, and every request to the platforms. Those sent with a stored
// credential show that varlatchd opened every credential the TypeScript
// code sealed, this release's and v0.21.0's (G3 at the database level,
// Platform Connection credentials, ts-to-go).
func TestTypeScriptFixtures(t *testing.T) {
	for _, name := range []string{"connections-v0.22.0.json", "connections-v0.21.0.json"} {
		t.Run(name, func(t *testing.T) {
			f, x := read(t, paritytest.Path(name))
			replay(t, f, x)
		})
	}
}

func envelopeValue(t *testing.T, e envelope.Envelope) map[string]any {
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// goSealed is the v0.22.0 fixture with the Root KEK canary, every
// Organization KEK, every Connection credential and the App's key sealed
// again by Go.
func goSealed(t *testing.T) (paritytest.Fixture, extra, map[string]map[string]any) {
	f, x := read(t, paritytest.Path("connections-v0.22.0.json"))
	rootKEK, err := hex.DecodeString(f.RootKEK)
	if err != nil {
		t.Fatal(err)
	}
	for _, inst := range f.Rows["installation"] {
		canary, err := envelope.NewCanary(rootKEK, inst["id"].(string))
		if err != nil {
			t.Fatal(err)
		}
		inst["kek_canary"] = envelopeValue(t, canary)
	}
	kekOf := map[string][]byte{}
	for _, o := range f.Rows["organizations"] {
		id := o["id"].(string)
		kek, wrapped, err := envelope.WrapOrgKEK(rootKEK, id)
		if err != nil {
			t.Fatal(err)
		}
		kekOf[id] = kek
		o["wrapped_org_kek"] = envelopeValue(t, wrapped)
	}
	sealedOf := map[string]map[string]any{}
	for _, c := range f.Rows["platform_connections"] {
		if c["credential_envelope"] == nil {
			continue
		}
		id, org := c["id"].(string), c["organization_id"].(string)
		credential, ok := x.Credentials[id]
		if !ok {
			t.Fatalf("no credential for %s", id)
		}
		sealed, err := envelope.Seal(kekOf[org], []byte(credential), envelope.PlatformCredentialContext(org, id))
		if err != nil {
			t.Fatal(err)
		}
		sealedOf[id] = envelopeValue(t, sealed)
		c["credential_envelope"] = sealedOf[id]
	}
	for _, a := range f.Rows["github_apps"] {
		id, org := a["id"].(string), a["organization_id"].(string)
		sealed, err := envelope.Seal(kekOf[org], []byte(x.AppKey), envelope.GitHubAppKeyContext(org, id))
		if err != nil {
			t.Fatal(err)
		}
		a["key_envelope"] = envelopeValue(t, sealed)
	}
	for _, r := range f.Requests {
		for _, rows := range r.Side["platform_connections"] {
			resealSide(rows, sealedOf)
		}
	}
	f.Comment = "Written by the Go tests (go test ./server/syncs -run TestGoSealedFixture -args -write-go-sealed=<file>): the v0.22.0 connections fixture with the Root KEK canary, every Organization KEK, every Connection credential and the App's key sealed again by Go; services/varlatchd/test/go-connections-fixture.test.ts opens it with the TypeScript server."
	f.Ref = "go"
	return f, x, sealedOf
}

// resealSide puts the envelope Go sealed into side rows of the Connections
// it sealed one for.
func resealSide(rows []paritytest.Row, sealedOf map[string]map[string]any) {
	for _, row := range rows {
		// Only an envelope the row holds as one: a volatile one reads as a
		// placeholder ("{fresh}") and stays so.
		if _, sealed := row["credential_envelope"].(map[string]any); sealed {
			if id, ok := row["id"].(string); ok && sealedOf[id] != nil {
				row["credential_envelope"] = sealedOf[id]
			}
		}
	}
}

// TestGoSealedFixture: credentials Go sealed open in varlatchd with the
// TypeScript server's answers and exchanges; with -write-go-sealed, the
// file for the TypeScript side (G3, go-to-ts).
func TestGoSealedFixture(t *testing.T) {
	f, x, sealedOf := goSealed(t)
	replay(t, f, x)
	if *writeGoSealed == "" {
		return
	}
	var raw map[string]json.RawMessage
	b, err := os.ReadFile(paritytest.Path("connections-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	var requests []map[string]any
	if err := json.Unmarshal(raw["requests"], &requests); err != nil {
		t.Fatal(err)
	}
	for _, r := range requests {
		side, _ := r["side"].(map[string]any)
		changes, _ := side["platform_connections"].(map[string]any)
		for _, rows := range changes {
			for _, row := range rows.([]any) {
				resealSide([]paritytest.Row{row.(map[string]any)}, sealedOf)
			}
		}
	}
	for k, v := range map[string]any{"comment": f.Comment, "ref": f.Ref, "rows": f.Rows, "requests": requests} {
		enc, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		raw[k] = enc
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(*writeGoSealed, append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
