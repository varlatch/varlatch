// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api/openapicheck"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/syncs"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// convergeTables are the tables of converge-v0.22.0.json
// (go-converge-fixture.test.ts).
var convergeTables = []string{"installation", "identities", "credentials", "organizations", "org_memberships", "projects", "environments",
	"contract_revisions", "env_values", "value_versions", "platform_connections", "sync_targets", "sync_ledger", "sync_runs", "sync_cursor",
	"member_integrations", "audit_events"}

// The fake GitHub's key pair (SEAL_SECRET, SEAL_PUBLIC there).
var (
	sealSecret = [32]byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	sealPublic = "e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM="
)

const (
	composeRaw       = "services:\n  web:\n    image: x\n    environment:\n      PORT: 80\n"
	composeGenerated = "services:\n  web:\n    image: x\n    env_file:\n      - .env\n"
)

// fakePlatforms is the fixture's FakePlatforms: the same state, answers
// and log.
type fakePlatforms struct {
	mu      sync.Mutex
	log     []string
	github  map[string]map[string]string
	coolify map[string][]map[string]any
	convex  [][2]string
	next    int
	// onRequest, when set, sees each request's number (from 1) before it
	// is answered: the fence tests.
	onRequest func(n int)
	sent      atomic.Int64
	// The G7 tests' additions, unused by the fixture: activated is what a
	// Coolify application or service runs, its stored values as of its
	// last deploy or restart; refuse names hosts refused as the outbound
	// policy refuses them; crashAfter, when set, stops the engine as a
	// process that died right after the platform accepted that request.
	activated  map[string]map[string]string
	refuse     map[string]bool
	crashAfter int
}

func newFakePlatforms() *fakePlatforms {
	row := func(uuid, key, value string, literal bool) map[string]any {
		return map[string]any{"uuid": uuid, "key": key, "value": value, "is_preview": false, "is_literal": literal, "is_multiline": true,
			"is_shown_once": false, "is_buildtime": false, "is_runtime": true}
	}
	return &fakePlatforms{
		github: map[string]map[string]string{},
		coolify: map[string][]map[string]any{
			"/applications/app-uuid-1": {row("seed-1", "PORT", "1234", true), row("seed-2", "DATABASE_URL", "postgres://db/prod", false)},
			"/services/svc-uuid-1":     {},
		},
		convex: [][2]string{{"API_KEY", "key-1"}, {"STALE", "x"}},
		next:   1,
		activated: map[string]map[string]string{
			"/applications/app-uuid-1": {"PORT": "1234", "DATABASE_URL": "postgres://db/prod"},
			"/services/svc-uuid-1":     {},
		},
		refuse: map[string]bool{},
	}
}

// clone is a copy of f's state, with no hooks.
func (f *fakePlatforms) clone() *fakePlatforms {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := &fakePlatforms{github: map[string]map[string]string{}, coolify: map[string][]map[string]any{}, convex: slices.Clone(f.convex),
		next: f.next, activated: map[string]map[string]string{}, refuse: maps.Clone(f.refuse)}
	for k, v := range f.github {
		c.github[k] = maps.Clone(v)
	}
	for k, rows := range f.coolify {
		list := make([]map[string]any, len(rows))
		for i, r := range rows {
			list[i] = maps.Clone(r)
		}
		c.coolify[k] = list
	}
	for k, v := range f.activated {
		c.activated[k] = maps.Clone(v)
	}
	c.sent.Store(f.sent.Load())
	return c
}

func (f *fakePlatforms) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.log
	f.log = nil
	return out
}

func (f *fakePlatforms) drift() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.coolify["/applications/app-uuid-1"] {
		if r["key"] == "PORT" {
			r["value"] = "1"
		}
	}
}

var (
	githubSecret = regexp.MustCompile(`^/repos/([^/]+)/([^/]+)/actions/secrets/(.+)$`)
	coolifyPath  = regexp.MustCompile(`^(/(?:applications|services)/[^/]+)(/envs(?:/([^/]+))?|/start|/restart)$`)
)

func (f *fakePlatforms) client() *http.Client {
	return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		n := int(f.sent.Add(1))
		if f.onRequest != nil {
			f.onRequest(n)
		}
		if f.refuse[r.URL.Host] {
			return nil, &outbound.RefusedError{Reason: outbound.PrivateAddress, Destination: outbound.Destination{Scheme: "https", Host: r.URL.Host, Port: 443}, Addresses: []string{"10.1.2.3"}}
		}
		res, err := f.answer(r)
		if n == f.crashAfter {
			panic(syncs.Crash{})
		}
		return res, err
	})}
}

// answer is the fake platforms' answer to one request, with its effect.
func (f *fakePlatforms) answer(r *http.Request) (*http.Response, error) {
	{
		f.mu.Lock()
		defer f.mu.Unlock()
		auth := r.Header.Get("Authorization")
		var body string
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			body = string(b)
		}
		line := r.Method + " " + r.URL.Scheme + "://" + r.URL.Host + r.URL.RequestURI() + " " + auth
		answer := func(status int, v any, extra map[string]string) (*http.Response, error) {
			f.log = append(f.log, line)
			h := http.Header{"Content-Type": {"application/json"}}
			for k, x := range extra {
				h.Set(k, x)
			}
			text := ""
			if status != 204 {
				b, _ := json.Marshal(v)
				text = string(b)
			}
			return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(text)), Request: r}, nil
		}
		path := r.URL.EscapedPath()
		if r.URL.Opaque != "" {
			path, _, _ = strings.Cut(r.URL.Opaque, "?")
		}
		switch r.URL.Host {
		case "api.github.com":
			expiry := map[string]string{}
			if strings.Contains(auth, "expiring") {
				expiry["github-authentication-token-expiration"] = expires
			}
			m := githubSecret.FindStringSubmatch(path)
			if m == nil {
				return answer(404, map[string]any{"message": "Not Found"}, nil)
			}
			repo, name := m[1]+"/"+m[2], m[3]
			if name == "public-key" && r.Method == "GET" {
				return answer(200, map[string]any{"key_id": "k1", "key": sealPublic}, expiry)
			}
			secrets := f.github[repo]
			if secrets == nil {
				secrets = map[string]string{}
				f.github[repo] = secrets
			}
			switch r.Method {
			case "PUT":
				var sent struct {
					EncryptedValue string `json:"encrypted_value"`
					KeyID          string `json:"key_id"`
				}
				_ = json.Unmarshal([]byte(body), &sent)
				opened := "<unopenable>"
				sealed, _ := base64.StdEncoding.DecodeString(sent.EncryptedValue)
				pub, _ := base64.StdEncoding.DecodeString(sealPublic)
				if plain, ok := box.OpenAnonymous(nil, sealed, (*[32]byte)(pub), &sealSecret); ok {
					opened = string(plain)
				}
				line += " opened=" + opened + " key_id=" + sent.KeyID
				if strings.HasPrefix(name, "BROKEN") {
					return answer(500, map[string]any{"message": "boom"}, nil)
				}
				_, existed := secrets[name]
				secrets[name] = opened
				if existed {
					return answer(204, nil, expiry)
				}
				return answer(201, map[string]any{}, expiry)
			case "DELETE":
				if _, existed := secrets[name]; existed {
					delete(secrets, name)
					return answer(204, nil, nil)
				}
				return answer(404, map[string]any{"message": "Not Found"}, nil)
			}
			return answer(404, map[string]any{"message": "Not Found"}, nil)
		case "coolify.public.example":
			if body != "" {
				line += " " + body
			}
			p := strings.TrimPrefix(path, "/api/v1")
			if r.Method == "GET" && p == "/services/svc-uuid-1" {
				return answer(200, map[string]any{"uuid": "svc-uuid-1", "name": "Stack", "docker_compose_raw": composeRaw,
					"docker_compose": composeGenerated, "compose_parsing_version": "3"}, nil)
			}
			m := coolifyPath.FindStringSubmatch(p)
			if m == nil {
				return answer(404, map[string]any{"message": "Not found."}, nil)
			}
			rows, ok := f.coolify[m[1]]
			if !ok {
				return answer(404, map[string]any{"message": "Not found."}, nil)
			}
			if m[2] == "/start" || m[2] == "/restart" {
				running := map[string]string{}
				for _, row := range rows {
					k, _ := row["key"].(string)
					v, _ := row["value"].(string)
					running[k] = v
				}
				f.activated[m[1]] = running
				return answer(200, map[string]any{"message": "Queued."}, nil)
			}
			switch r.Method {
			case "GET":
				list := make([]any, len(rows))
				for i, row := range rows {
					list[i] = row
				}
				return answer(200, list, nil)
			case "POST":
				row := map[string]any{}
				_ = json.Unmarshal([]byte(body), &row)
				row["uuid"] = "env-" + itoa(f.next)
				row["is_preview"] = false
				f.next++
				f.coolify[m[1]] = append(rows, row)
				return answer(201, map[string]any{"uuid": row["uuid"]}, nil)
			case "PATCH":
				sent := map[string]any{}
				_ = json.Unmarshal([]byte(body), &sent)
				for _, row := range rows {
					if row["key"] == sent["key"] {
						for k, v := range sent {
							row[k] = v
						}
						return answer(201, map[string]any{"uuid": row["uuid"]}, nil)
					}
				}
				return answer(404, map[string]any{"message": "Not found."}, nil)
			case "DELETE":
				for i, row := range rows {
					if m[3] != "" && row["uuid"] == m[3] {
						f.coolify[m[1]] = append(rows[:i:i], rows[i+1:]...)
						return answer(200, map[string]any{"message": "Deleted."}, nil)
					}
				}
				return answer(404, map[string]any{"message": "Not found."}, nil)
			}
			return answer(404, map[string]any{"message": "Not found."}, nil)
		case "happy-animal-123.convex.cloud":
			if body != "" {
				line += " " + body
			}
			switch {
			case r.Method == "POST" && path == "/api/query":
				list := make([]any, len(f.convex))
				for i, kv := range f.convex {
					list[i] = map[string]any{"name": kv[0], "value": kv[1]}
				}
				return answer(200, map[string]any{"status": "success", "value": list}, nil)
			case r.Method == "POST" && path == "/api/update_environment_variables":
				var sent struct {
					Changes []struct {
						Name  string  `json:"name"`
						Value *string `json:"value"`
					} `json:"changes"`
				}
				_ = json.Unmarshal([]byte(body), &sent)
				for _, c := range sent.Changes {
					i := -1
					for j, kv := range f.convex {
						if kv[0] == c.Name {
							i = j
						}
					}
					switch {
					case c.Value == nil && i >= 0:
						f.convex = append(f.convex[:i:i], f.convex[i+1:]...)
					case c.Value != nil && i >= 0:
						f.convex[i][1] = *c.Value
					case c.Value != nil:
						f.convex = append(f.convex, [2]string{c.Name, *c.Value})
					}
				}
				return answer(200, map[string]any{}, nil)
			}
			return answer(404, map[string]any{}, nil)
		}
		f.log = append(f.log, line)
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: io.ErrUnexpectedEOF}
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// withTicks is the fixture's withTicks: the test's own paths, the engine's
// tick and the drift, in front of the server.
func withTicks(h http.Handler, engine *syncs.Service, fake *fakePlatforms) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply := func(v jsvalue.Object) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(jsvalue.Stringify(v))
		}
		switch {
		case r.URL.Path == "/__test/sync-tick":
			opts := syncs.RunOptions{}
			if r.URL.RawQuery == "repair=0" {
				opts.RepairInterval = time.Nanosecond // under a microsecond: every Target is due for repair
			}
			engine.RunOnce(r.Context(), opts)
			exchanges := []any{}
			for _, x := range fake.take() {
				exchanges = append(exchanges, x)
			}
			reply(jsvalue.Object{{Key: "exchanges", Value: exchanges}})
		case r.URL.Path == "/__test/platform-drift":
			fake.drift()
			reply(jsvalue.Object{{Key: "drifted", Value: true}})
		default:
			h.ServeHTTP(w, r)
		}
	})
}

// convergePath is the fixture's fillPath.
func convergePath(t *testing.T, f paritytest.Fixture) func(string) string {
	var pairs []string
	for key, canonical := range map[string]string{
		"tGh": `["github-actions","acme","api"]`, "tCoolApp": `["coolify","https://coolify.public.example","app-uuid-1"]`,
	} {
		id := ""
		for _, r := range f.Rows["sync_targets"] {
			if r["canonical_destination"] == canonical {
				id = r["id"].(string)
			}
		}
		if id == "" {
			t.Fatalf("no Target %s", canonical)
		}
		pairs = append(pairs, "{"+key+"}", id)
	}
	for _, c := range f.Rows["platform_connections"] {
		if c["name"] == "Convex" {
			pairs = append(pairs, "{convex}", c["id"].(string))
		}
	}
	return strings.NewReplacer(pairs...).Replace
}

// The converge fixture gives the TypeScript engine's runs (step 4.9d):
// between ordinary requests, the engine runs once against the fake
// platforms, and its requests to them, its ledger rows, the Targets'
// columns and its audit events are the TypeScript engine's. The runs
// cover the first forced pass (read-back, adoption, a rewrite, a
// redeploy, a credential's expiry), triggers, an orphan's deletion, a
// failed write and its backoff, pushSyncTarget, drift put back, a paused
// and resumed Target, a new destination and a revoked Connection.
func TestConvergeFixture(t *testing.T) {
	f, err := paritytest.Read(paritytest.Path("converge-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 25 {
		t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
	}
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, convergeTables); err != nil {
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
	fake := newFakePlatforms()
	public, _ := url.Parse(publicURL)
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	now := paritytest.HourClock()
	approvals := auth.New(store, auth.Options{Log: log, RootKEK: rootKEK, PublicURL: public, PersonGate: w.Gates.PersonGate, Now: now})
	vs := values.New(store, rootKEK, values.Options{Log: log, Approvals: approvals, Gates: w.Gates, Now: now})
	h, err := httpserver.New(httpserver.Options{
		Version: f.Version(), Backend: daemon.NewBackend(store, rootKEK), Log: log, PublicURL: public,
		Auth: approvals, Values: vs, Writer: w, RootKEK: rootKEK, Now: now, Outbound: policy,
		Sync: true, SyncClient: fake.client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		vs.Settled()
		_ = store.Close()
	})
	engine := &syncs.Service{Writer: w, Approvals: approvals, RootKEK: rootKEK, Policy: policy, Now: now, Log: log}
	syncs.UseClient(engine, fake.client())
	paritytest.Replay(t, paritytest.Target{
		Handler: withTicks(h, engine, fake), Store: store, Settled: vs.Settled, Path: convergePath(t, f), Now: now,
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			if !strings.HasPrefix(req.URL.Path, "/__test/") {
				openapicheck.Recorder{T: t}.Exchange(req, body, rec)
			}
		},
	}, f)
}
