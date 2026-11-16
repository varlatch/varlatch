// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
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

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api/openapicheck"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/oidc"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// The fixture's tables, public URL and issuers (go-oidc-fixture.test.ts).
var tables = []string{"installation", "identities", "credentials", "organizations", "org_memberships", "security_controls",
	"security_control_counters", "approval_intents", "organization_freezes", "oidc_bindings"}

const (
	publicURL = "http://127.0.0.1:8686"
	issuer    = "https://issuer.example"
	down      = "https://down.example"
	refused   = "https://refused.example"
)

var resolved = map[string]string{"issuer.example": "93.184.215.14", "down.example": "93.184.215.15", "refused.example": "10.0.0.9"}

type extra struct {
	OIDC struct {
		JWKS   []any             `json:"jwks"`
		Tokens map[string]string `json:"tokens"`
	} `json:"oidc"`
	Fetched map[string][]string `json:"fetched"`
}

// issuers is the fixture's issuers, each URL fetched recorded: the
// refused one through the outbound policy's own fetch.
func issuers(policy *outbound.Policy, jwks []any, log *[]string, mu *sync.Mutex) oidc.Fetcher {
	viaPolicy := oidc.PolicyFetcher(policy)
	return func(ctx context.Context, raw string) (*oidc.Response, error) {
		mu.Lock()
		*log = append(*log, raw)
		mu.Unlock()
		switch {
		case strings.HasPrefix(raw, refused):
			return viaPolicy(ctx, raw)
		case raw == issuer+"/.well-known/openid-configuration":
			return &oidc.Response{Status: 200, Body: jsvalue.Stringify(jsvalue.Object{{Key: "issuer", Value: issuer}, {Key: "jwks_uri", Value: issuer + "/jwks"}})}, nil
		case raw == issuer+"/jwks":
			b, _ := json.Marshal(map[string]any{"keys": jwks})
			return &oidc.Response{Status: 200, Body: b}, nil
		case strings.HasPrefix(raw, down):
			return &oidc.Response{Status: 503}, nil
		}
		return &oidc.Response{Status: 404}, nil
	}
}

// fills is the table's placeholders, from the file's rows and tokens.
func fills(f paritytest.Fixture, x extra) *strings.Replacer {
	find := func(table, column, value string) string {
		for _, r := range f.Rows[table] {
			if r[column] == value {
				return r["id"].(string)
			}
		}
		return ""
	}
	pairs := []string{
		"{acmeId}", find("organizations", "slug", "acme"), "{deployer}", find("identities", "name", "deployer"),
		"{worker}", find("identities", "name", "worker"), "{alice}", find("identities", "name", "Alice"),
		"{fci}", find("identities", "name", "fci"), "{eci}", find("identities", "name", "eci"),
		"{b8}", find("oidc_bindings", "subject", "revoked:*"), "{fb2}", find("oidc_bindings", "subject", "frozen-revoke:*"),
		"{eb1}", find("oidc_bindings", "subject", "enf-old:*"),
	}
	for name, t := range x.OIDC.Tokens {
		pairs = append(pairs, "{oidc:"+name+"}", t)
	}
	return strings.NewReplacer(pairs...)
}

// The OIDC fixture gives the TypeScript server's answers (step 4.8):
// listOidcBindings, createOidcBinding (zod, the issuer's validation, the
// outbound policy's refusal and its record, approvals under enforce,
// frozen), revokeOidcBinding and exchangeOidcToken (every reason a token
// is refused, claim matching, audiences, lifetimes, a retired identity, a
// revoked binding, an issuer down or refused by the policy, frozen), with
// their audit events and side rows; and each request's fetches of the
// issuers' documents, the same.
func TestTypeScriptFixture(t *testing.T) {
	path := paritytest.Path("oidc-v0.22.0.json")
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
	if len(f.Requests) < 50 || len(x.OIDC.Tokens) < 10 {
		t.Fatalf("%d requests, %d tokens: the fixture is incomplete", len(f.Requests), len(x.OIDC.Tokens))
	}
	db := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(db, f.Rows, tables); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), storage.Options{Path: db})
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
	var fetched []string
	public, _ := url.Parse(publicURL)
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	now := paritytest.HourClock()
	approvals := auth.New(store, auth.Options{Log: log, RootKEK: rootKEK, PublicURL: public, PersonGate: w.Gates.PersonGate, Now: now})
	vs := values.New(store, rootKEK, values.Options{Log: log, Approvals: approvals, Gates: w.Gates, Now: now})
	h, err := httpserver.New(httpserver.Options{
		Version: f.Version(), Backend: daemon.NewBackend(store, rootKEK), Log: log, PublicURL: public,
		Auth: approvals, Values: vs, Writer: w, RootKEK: rootKEK, Now: now, Outbound: policy,
		OIDCFetch: issuers(policy, x.OIDC.JWKS, &fetched, &mu),
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
		Handler: h, Store: store, Settled: vs.Settled, Path: fills(f, x).Replace, Now: now,
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
		Inspect: func(_ testing.TB, c paritytest.Recorded, _ paritytest.Raw) {
			mu.Lock()
			defer mu.Unlock()
			if len(fetched) > 0 {
				got[c.ID] = fetched
				fetched = nil
			}
		},
	}, f)
	if !reflect.DeepEqual(got, x.Fetched) {
		t.Errorf("the issuers' documents fetched:\n got %v\nwant %v", got, x.Fetched)
	}
}
