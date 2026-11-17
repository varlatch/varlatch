// SPDX-License-Identifier: AGPL-3.0-or-later

package githubapps_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
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

var writeGoSealed = flag.String("write-go-sealed", "", "write the v0.22.0 GitHub App fixture with the canary, every Organization KEK, every App key and every pending key sealed again by Go to this path")

// appTables are the tables of github-app-v0.22.0.json
// (go-github-app-fixture.test.ts).
var appTables = []string{"installation", "identities", "credentials", "organizations", "org_memberships", "projects", "environments",
	"grants", "security_controls", "approval_intents", "organization_freezes", "organization_deletions", "github_apps",
	"github_app_registrations", "platform_connections", "sync_targets", "audit_events"}

const publicURL = "http://127.0.0.1:8686"

// sweepPath is the fixture's SWEEP_PATH.
const sweepPath = "/__fixture/sweep-github-app-registrations"

// keys is github-app-keys.json: the fixture's RSA keys.
type keys map[string]string

func readKeys(t testing.TB) keys {
	b, err := os.ReadFile(paritytest.Path("github-app-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var k keys
	if err := json.Unmarshal(b, &k); err != nil {
		t.Fatal(err)
	}
	return k
}

type conversionApp struct {
	id                  int64
	slug, clientID      string
	ownerLogin, ownerTy string
	ownerID             int64
}

// conversions and imports are the fixture's CONVERSIONS and IMPORTS.
var conversions = map[string]conversionApp{
	"code-good":     {1001, "varlatch-acme-good", "Iv1.acmegood", "acme-inc", "Organization", 501},
	"code-mismatch": {1002, "varlatch-acme-personal", "Iv1.personal", "alice-personal", "User", 777},
	"code-inuse":    {2002, "varlatch-beta", "Iv1.beta", "acme-inc", "Organization", 501},
	"code-enf":      {3003, "varlatch-enf", "Iv1.enf", "acme-inc", "Organization", 501},
	"code-rep":      {5005, "varlatch-rep", "Iv1.rep", "acme-inc", "Organization", 501},
}

type importApp struct {
	key         string
	status      int
	permissions jsvalue.Object
	id          int64
}

func perms(pairs ...string) jsvalue.Object {
	var o jsvalue.Object
	for i := 0; i < len(pairs); i += 2 {
		o = append(o, jsvalue.Member{Key: pairs[i], Value: pairs[i+1]})
	}
	return o
}

var imports = map[string]importApp{
	"4004": {key: "import", permissions: perms("secrets", "write", "environments", "write", "metadata", "read", "actions", "read", "checks", "write")},
	"4005": {key: "import", status: 401},
	"4006": {key: "import", permissions: perms("secrets", "write", "metadata", "read")},
	"4007": {key: "import", status: 500},
	"4008": {key: "import", permissions: perms("secrets", "write", "environments", "write", "metadata", "read"), id: 9999},
	"2002": {key: "import", permissions: perms("secrets", "write", "environments", "write", "metadata", "admin")},
	"4010": {key: "import", permissions: perms("secrets", "admin", "environments", "write", "metadata", "read")},
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

var keyNames = []string{"conversion", "import", "beta", "other"}

// signer is the fixture's signer: which key signed a JWT, "?" for none.
func signer(k keys, jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "?"
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "?"
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	for _, name := range keyNames {
		key := githubapps.ParseRSAKey(k[name])
		if key != nil && rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig) == nil {
			return name
		}
	}
	return "?"
}

type claims struct {
	Iss      string
	Iat, Exp int64
}

func payloadOf(jwt string) (claims, bool) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return claims{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, false
	}
	var c claims
	return c, json.Unmarshal(b, &c) == nil
}

// authLine is the fixture's authLine.
func authLine(k keys, a string) string {
	jwt, ok := strings.CutPrefix(a, "Bearer ")
	if !ok || len(strings.Split(jwt, ".")) != 3 {
		return a
	}
	c, _ := payloadOf(jwt)
	return fmt.Sprintf("Bearer jwt(iss=%s,key=%s,window=%d)", c.Iss, signer(k, jwt), c.Exp-c.Iat)
}

var conversionPath = regexp.MustCompile(`^/app-manifests/([^/]+)/conversions$`)

// github is the fixture's fake GitHub.
func github(k keys, log *[]string, mu *sync.Mutex) *http.Client {
	return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		a := r.Header.Get("Authorization")
		mu.Lock()
		*log = append(*log, r.Method+" "+r.URL.Scheme+"://"+r.URL.Host+r.URL.EscapedPath()+" "+authLine(k, a))
		mu.Unlock()
		answer := func(status int, body any, extra map[string]string) (*http.Response, error) {
			h := http.Header{"Content-Type": {"application/json"}}
			for name, v := range extra {
				h.Set(name, v)
			}
			return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(string(jsvalue.Stringify(body)))), Request: r}, nil
		}
		msg := func(m string) jsvalue.Object { return jsvalue.Object{{Key: "message", Value: m}} }
		if r.URL.Host != "api.github.com" {
			return nil, fmt.Errorf("fetch failed")
		}
		if m := conversionPath.FindStringSubmatch(r.URL.EscapedPath()); r.Method == http.MethodPost && m != nil {
			code, _ := url.PathUnescape(m[1])
			switch code {
			case "code-noanswer":
				return nil, fmt.Errorf("fetch failed")
			case "code-used":
				return answer(422, msg("Validation Failed"), nil)
			case "code-garbage":
				return answer(201, jsvalue.Object{{Key: "id", Value: "not-an-app"}}, nil)
			}
			c, ok := conversions[code]
			if !ok {
				return answer(404, msg("Not Found"), nil)
			}
			return answer(201, jsvalue.Object{
				{Key: "id", Value: c.id}, {Key: "slug", Value: c.slug}, {Key: "client_id", Value: c.clientID}, {Key: "pem", Value: k["conversion"]},
				{Key: "owner", Value: jsvalue.Object{{Key: "login", Value: c.ownerLogin}, {Key: "id", Value: c.ownerID}, {Key: "type", Value: c.ownerTy}}},
				{Key: "client_secret", Value: "never-read"}, {Key: "webhook_secret", Value: nil},
			}, nil)
		}
		if r.Method == http.MethodGet && r.URL.Path == "/app" {
			jwt, _ := strings.CutPrefix(a, "Bearer ")
			c, ok := payloadOf(jwt)
			if !ok {
				return answer(401, msg("A JSON web token could not be decoded"), nil)
			}
			date := map[string]string{"Date": time.Unix(c.Iat+60, 0).UTC().Format(http.TimeFormat)}
			app, known := imports[c.Iss]
			if !known || signer(k, jwt) != app.key || app.status == 401 {
				return answer(401, msg("Bad credentials"), date)
			}
			if app.status != 0 {
				return answer(app.status, msg("Server Error"), date)
			}
			id := app.id
			if id == 0 {
				fmt.Sscan(c.Iss, &id)
			}
			return answer(200, jsvalue.Object{
				{Key: "id", Value: id}, {Key: "slug", Value: "imported-" + c.Iss}, {Key: "client_id", Value: "Iv1.imported" + c.Iss},
				{Key: "owner", Value: jsvalue.Object{{Key: "login", Value: "acme-inc"}, {Key: "id", Value: int64(501)}, {Key: "type", Value: "Organization"}}},
				{Key: "permissions", Value: app.permissions},
			}, date)
		}
		return answer(404, msg("Not Found"), nil)
	})}
}

// extra is the fixture's own members.
type extra struct {
	Exchanges map[string][]string `json:"exchanges"`
}

func read(t testing.TB, path string) (paritytest.Fixture, extra) {
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
	return f, x
}

// fillPath is the fixture's: the registrations and Apps by the file's
// rows, and the imported App by the replay's own answer.
func fillPath(f paritytest.Fixture, impApp *string) func(string) string {
	org := func(slug string) string {
		for _, r := range f.Rows["organizations"] {
			if r["slug"] == slug {
				return r["id"].(string)
			}
		}
		return ""
	}
	reg := func(state string) string {
		for _, r := range f.Rows["github_app_registrations"] {
			if r["state_hash"] == auth.HashToken(state) {
				return r["id"].(string)
			}
		}
		return ""
	}
	app := func(slug string) string {
		for _, r := range f.Rows["github_apps"] {
			if r["organization_id"] == org(slug) {
				return r["id"].(string)
			}
		}
		return ""
	}
	r := strings.NewReplacer("{daveReg}", reg("state-dave"), "{lapsedReg}", reg("state-lapsed"), "{pendingReg}", reg("state-pending"),
		"{consumedReg}", reg("state-consumed"), "{discardReg}", reg("state-discard"), "{enfPendingReg}", reg("state-enf-pending"),
		"{betaApp}", app("beta"))
	return func(p string) string { return strings.ReplaceAll(r.Replace(p), "{impApp}", *impApp) }
}

// replay replays f against varlatchd, its exchanges compared too, and
// returns the store it ran on.
func replay(t *testing.T, f paritytest.Fixture, x extra) *storage.DB {
	k := readKeys(t)
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, appTables); err != nil {
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
	client := github(k, &sent, &mu)
	h, err := httpserver.New(httpserver.Options{
		Version: f.Version(), Backend: daemon.NewBackend(store, rootKEK), Log: log, PublicURL: public,
		Auth: approvals, Values: vs, Writer: w, RootKEK: rootKEK, Now: now, Outbound: policy,
		Sync: true, SyncClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		vs.Settled()
		_ = store.Close()
	})
	sweeper := &githubapps.Service{Writer: w, Approvals: approvals, RootKEK: rootKEK, Policy: policy, Now: now, Log: log}
	handler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != sweepPath {
			h.ServeHTTP(rw, r)
			return
		}
		n, err := sweeper.Sweep(r.Context())
		if err != nil {
			t.Fatal(err)
		}
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write(jsvalue.Stringify(jsvalue.Object{{Key: "ended", Value: n}}))
	})
	impApp := ""
	got := map[string][]string{}
	paritytest.Replay(t, paritytest.Target{
		Handler: handler, Store: store, Settled: vs.Settled, Path: fillPath(f, &impApp), Now: now,
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			if req.URL.Path != sweepPath {
				openapicheck.Recorder{T: t}.Exchange(req, body, rec)
			}
		},
		Inspect: func(_ testing.TB, c paritytest.Recorded, raw paritytest.Raw) {
			mu.Lock()
			defer mu.Unlock()
			if len(sent) > 0 {
				got[c.ID] = sent
				sent = nil
			}
			if c.Name == "import" && len(raw.Statuses) > 0 && raw.Statuses[0] == http.StatusCreated {
				var body struct {
					App struct{ ID string } `json:"app"`
				}
				_ = json.Unmarshal(raw.Bodies[0], &body)
				impApp = body.App.ID
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
	// G3 at the database level: the attached App's key, unwrapped from the
	// pending key the fixture's code sealed and sealed again by Go, opens
	// to the PEM GitHub handed over; the imported App's to the key given.
	for appID, want := range map[int64]string{1009: k["conversion"], 3009: k["conversion"], 4010: k["import"]} {
		var id, org string
		var sealed string
		if err := store.Reader().QueryRow(`SELECT id, organization_id, key_envelope FROM github_apps WHERE github_app_id = ? AND removed_at IS NULL`, appID).
			Scan(&id, &org, &sealed); err != nil {
			t.Fatalf("App %d: %v", appID, err)
		}
		kek := orgKEK(t, store, rootKEK, org)
		pemText, err := githubapps.OpenKey(kek, org, id, sealed)
		if err != nil || pemText != want {
			t.Errorf("App %d: its key does not open to the PEM it was given (%v)", appID, err)
		}
	}
	return store
}

func orgKEK(t testing.TB, store *storage.DB, rootKEK []byte, org string) []byte {
	var wrapped string
	if err := store.Reader().QueryRow(`SELECT wrapped_org_kek FROM organizations WHERE id = ?`, org).Scan(&wrapped); err != nil {
		t.Fatal(err)
	}
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(wrapped), &env); err != nil {
		t.Fatal(err)
	}
	kek, err := envelope.UnwrapOrgKEK(rootKEK, env, org)
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

// TestTypeScriptFixtures replays both releases' files: every answer,
// audit event, changed row and request to GitHub the same; the pending
// keys each release sealed open here (G3, ts-to-go).
func TestTypeScriptFixtures(t *testing.T) {
	for _, file := range []string{"github-app-v0.22.0.json", "github-app-v0.21.0.json"} {
		t.Run(file, func(t *testing.T) {
			f, x := read(t, paritytest.Path(file))
			if len(f.Requests) < 50 {
				t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
			}
			replay(t, f, x)
		})
	}
}

func envelopeValue(t testing.TB, v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// goSealed is the v0.22.0 fixture with the canary, every Organization KEK,
// every App key and every pending key sealed again by Go.
func goSealed(t *testing.T) (paritytest.Fixture, extra) {
	f, x := read(t, paritytest.Path("github-app-v0.22.0.json"))
	k := readKeys(t)
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
	seal := func(org, id, pemText string) map[string]any {
		sealed, err := envelope.Seal(kekOf[org], []byte(pemText), envelope.GitHubAppKeyContext(org, id))
		if err != nil {
			t.Fatal(err)
		}
		return envelopeValue(t, sealed)
	}
	for _, a := range f.Rows["github_apps"] {
		if a["key_envelope"] != nil {
			a["key_envelope"] = seal(a["organization_id"].(string), a["id"].(string), k["beta"])
		}
	}
	for _, r := range f.Rows["github_app_registrations"] {
		if r["pending_key_envelope"] != nil {
			r["pending_key_envelope"] = seal(r["organization_id"].(string), r["id"].(string), k["conversion"])
		}
	}
	f.Comment = "Written by the Go tests (go test ./server/githubapps -run TestGoSealedFixture -args -write-go-sealed=<file>): the v0.22.0 GitHub App fixture with the Root KEK canary, every Organization KEK, every App key and every pending key sealed again by Go; services/varlatchd/test/go-github-app-fixture.test.ts opens it with the TypeScript server."
	f.Ref = "go"
	return f, x
}

// TestGoSealedFixture: keys Go sealed open in varlatchd with the
// TypeScript server's answers and exchanges; with -write-go-sealed, the
// file for the TypeScript side (G3, go-to-ts).
func TestGoSealedFixture(t *testing.T) {
	f, x := goSealed(t)
	replay(t, f, x)
	if *writeGoSealed == "" {
		return
	}
	var raw map[string]json.RawMessage
	b, err := os.ReadFile(paritytest.Path("github-app-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]any{"comment": f.Comment, "ref": f.Ref, "rows": f.Rows} {
		enc, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		raw[name] = enc
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(*writeGoSealed, append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
