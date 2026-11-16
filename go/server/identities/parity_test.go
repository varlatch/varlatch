// SPDX-License-Identifier: AGPL-3.0-or-later

package identities_test

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
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// identitiesTables are the tables of identities-v0.22.0.json
// (go-identities-fixture.test.ts).
var identitiesTables = []string{"installation", "identities", "user", "auth_user_links", "credentials", "organizations", "org_memberships",
	"security_controls", "security_control_counters", "approval_intents", "organization_freezes", "organization_deletions"}

// publicURL is the public URL both servers answer with (approvals need one).
const publicURL = "http://127.0.0.1:8686"

// fillPath is go-identities-fixture.test.ts's: Organizations, identities
// by name (and Organization) and credentials by owner and name.
func fillPath(f paritytest.Fixture) func(string) string {
	orgID := func(slug string) string {
		for _, o := range f.Rows["organizations"] {
			if o["slug"] == slug {
				return o["id"].(string)
			}
		}
		return ""
	}
	identity := func(name, org string) string {
		for _, i := range f.Rows["identities"] {
			if i["name"] == name && (org == "" || i["organization_id"] == orgID(org)) {
				return i["id"].(string)
			}
		}
		return ""
	}
	credential := func(owner string, match func(paritytest.Row) bool) string {
		for _, c := range f.Rows["credentials"] {
			if c["identity_id"] == owner && match(c) {
				return c["id"].(string)
			}
		}
		return ""
	}
	named := func(name string) func(paritytest.Row) bool {
		return func(c paritytest.Row) bool { return c["name"] == name }
	}
	svc := identity("svc", "ids")
	pairs := []string{
		"{idsId}", orgID("ids"),
		"{svcId}", svc,
		"{wlId}", identity("wl", "ids"),
		"{ciId}", identity("ci", "ids"),
		"{brokerId}", identity("broker", "ids"),
		"{agentId}", identity("agent", "ids"),
		"{agentOffId}", identity("agent-off", "ids"),
		"{oldId}", identity("old", "ids"),
		"{bobId}", identity("bob", ""),
		"{osvcId}", identity("osvc", "other"),
		"{fsvcId}", identity("fsvc", "frozen"),
		"{fsvc2Id}", identity("fsvc2", "frozen"),
		"{fagentId}", identity("fagent", "frozen"),
		"{suspId}", identity("susp", "deleting"),
		"{dsvcId}", identity("dsvc", "deleting"),
		"{rsvcId}", identity("rsvc", "rep"),
		"{roldId}", identity("rold", "rep"),
		"{esvcId}", identity("esvc", "enf"),
		"{eoldId}", identity("eold", "enf"),
		"{svcCred}", credential(svc, named("svc credential")),
		"{svcTtlCred}", credential(svc, named("svc-expiring")),
		"{svcLimitedCred}", credential(svc, named("svc-limited")),
		"{svcOidcCred}", credential(svc, named("gh-actions")),
		"{wlCred}", credential(identity("wl", "ids"), named("wl credential")),
		"{setupRunCred}", credential(identity("agent", "ids"), named("setup-run")),
		"{offRunCred}", credential(identity("agent-off", "ids"), named("off-run")),
		"{bobCliCred}", credential(identity("bob", ""), func(c paritytest.Row) bool { return c["kind"] == "cli" }),
		"{fsvcCred}", credential(identity("fsvc", "frozen"), named("fsvc credential")),
		"{fRunCred}", credential(identity("fagent", "frozen"), named("f-run")),
	}
	return strings.NewReplacer(pairs...).Replace
}

// The identities fixture's operations give the TypeScript server's answers
// (step 4.4a): listIdentities, createServiceIdentity (every kind, every
// zod issue, at report and at enforce with approvals approved, pending,
// used and bound to another request), issueIdentityCredential (service
// credentials, and a Broker's agent-run credentials), listing and revoking
// them, retiring, reactivating (at enforce, with its approval) and
// renaming. Every request, its audit events, the side rows it wrote
// (identities, credentials, report counters, approval intents), the report
// counts; every response valid against the OpenAPI document.
func TestTypeScriptFixture(t *testing.T) {
	f, err := paritytest.Read(paritytest.Path("identities-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 150 {
		t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
	}
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, identitiesTables); err != nil {
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
	paritytest.Replay(t, paritytest.Target{
		Handler: h, Store: store, Settled: vs.Settled, Path: fillPath(f), Now: now,
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
	}, f)
}
