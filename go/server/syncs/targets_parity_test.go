// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs_test

import (
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

// targetsTables are the tables of targets-v0.22.0.json
// (go-targets-fixture.test.ts).
var targetsTables = []string{"installation", "identities", "credentials", "organizations", "org_memberships", "projects", "environments",
	"contract_revisions", "grants", "security_controls", "organization_freezes", "organization_deletions", "github_apps",
	"platform_connections", "sync_targets", "sync_ledger", "sync_runs", "member_integrations", "audit_events"}

// targetsPath is go-targets-fixture.test.ts's fillPath: acme's id, the
// named Connections by Organization and name, and the Targets by their
// canonical destination.
func targetsPath(t *testing.T, f paritytest.Fixture) func(string) string {
	orgID := func(slug string) string {
		for _, o := range f.Rows["organizations"] {
			if o["slug"] == slug {
				return o["id"].(string)
			}
		}
		t.Fatalf("no Organization %s", slug)
		return ""
	}
	pairs := []string{"{acmeId}", orgID("acme")}
	for key, c := range map[string][2]string{
		"gh": {"acme", "GitHub"}, "gh2": {"acme", "GitHub 2"}, "coolify": {"acme", "Coolify"}, "revokedConn": {"acme", "Revoked"},
		"appConn": {"acme", "App"}, "frozenConn": {"frozen", "Frozen"}, "deletingConn": {"deleting", "Deleting"},
	} {
		id := ""
		for _, r := range f.Rows["platform_connections"] {
			if r["organization_id"] == orgID(c[0]) && r["name"] == c[1] {
				id = r["id"].(string)
			}
		}
		if id == "" {
			t.Fatalf("no Connection %s", c[1])
		}
		pairs = append(pairs, "{"+key+"}", id)
	}
	for key, canonical := range map[string]string{
		"tApi": `["github-actions","acme","api"]`, "tWeb": `["github-actions","acme","web"]`,
		"tCoolify": `["coolify","https://coolify.public.example","app-uuid-1"]`, "tPause": `["github-actions","acme","pause"]`,
		"tBudget": `["github-actions","acme","budget"]`, "tRevokedConn": `["github-actions","acme","orphan"]`,
		"tRedeploy": `["github-actions","acme","redeploy"]`, "frozenTarget": `["github-actions","acme","frozen"]`,
		"deletingTarget": `["github-actions","acme","deleting"]`,
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
	return strings.NewReplacer(pairs...).Replace
}

// The targets fixture gives the TypeScript server's answers (step 4.9c):
// listOrgSyncTargets and listSyncTargets (Organization and environment
// Grants), createSyncTarget (zod, the adapters' destination and name
// rules, mapping normalization, claimed destinations, unusable
// Connections, the disclosure gate, frozen, deleting), getSyncTarget (its
// ledger's names, notes, drift and a live run), updateSyncTarget
// (versions, narrowing and widening, destinations, re-pointing, redeploy),
// pauseSyncTarget (with ?wait), resumeSyncTarget and revokeSyncTarget,
// with their audit events and side rows. No request reaches a platform:
// the fake client fails the test if one is sent.
func TestTargetsFixture(t *testing.T) {
	f, err := paritytest.Read(paritytest.Path("targets-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 70 {
		t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
	}
	h, store, vs, now, sent, mu := targetsServer(t, f, true)
	paritytest.Replay(t, paritytest.Target{
		Handler: h, Store: store, Settled: vs.Settled, Path: targetsPath(t, f), Now: now,
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
		Inspect: func(t testing.TB, c paritytest.Recorded, _ paritytest.Raw) {
			mu.Lock()
			defer mu.Unlock()
			if len(*sent) > 0 {
				t.Errorf("%s: sent %v; no Sync Target operation calls a platform", c.ID, *sent)
				*sent = nil
			}
		},
	}, f)
}

// TestPauseWaitsForALiveRun: with ?wait=true the pause answers once the
// Target's live run is gone (here deleted after 400 ms), polling for it,
// and its answer is the Target read again, paused; without, at once.
func TestPauseWaitsForALiveRun(t *testing.T) {
	f, err := paritytest.Read(paritytest.Path("targets-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	h, store, _, _, _, _ := targetsServer(t, f, true)
	target := targetsPath(t, f)("{tCoolify}")
	pause := func(query string) (*httptest.ResponseRecorder, time.Duration) {
		req := httptest.NewRequest("POST", "/v1/organizations/acme/projects/api/environments/dev/sync-targets/"+target+"/pause"+query, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+f.Tokens["alice"])
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		began := time.Now()
		h.ServeHTTP(rec, req)
		return rec, time.Since(began)
	}
	go func() {
		time.Sleep(400 * time.Millisecond)
		if err := store.Write(context.Background(), func(tx *storage.Tx) error {
			_, err := tx.ExecContext(context.Background(), `DELETE FROM sync_runs WHERE target_id = ?`, target)
			return err
		}); err != nil {
			t.Error(err)
		}
	}()
	rec, took := pause("?wait=true")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"state":"paused"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if took < 400*time.Millisecond || took > 5*time.Second {
		t.Errorf("answered after %v: not once the run was gone", took)
	}
	// No live run: the pause answers without waiting for one. A wait polls
	// every 250 ms for up to 30 s, so 2 s tells the two apart and leaves
	// room for a slow runner (the race detector).
	if rec, took = pause("?wait=true"); rec.Code != http.StatusOK || took > 2*time.Second {
		t.Errorf("no live run: %d after %v", rec.Code, took)
	}
}

// TestSyncOffRefusesTargetWrites: with sync off (varlatchd.conf), creating,
// changing and resuming a Target answer the TypeScript server's refusal;
// reading, pausing and revoking still work.
func TestSyncOffRefusesTargetWrites(t *testing.T) {
	f, err := paritytest.Read(paritytest.Path("targets-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	h, _, _, _, _, _ := targetsServer(t, f, false)
	path := targetsPath(t, f)
	env := "/v1/organizations/acme/projects/api/environments/production/sync-targets"
	for _, c := range []struct {
		method, path, body string
		status             int
	}{
		{"POST", env, `{"connectionId":"{gh}","destination":{"repo":"off"},"mapping":{"kind":"wildcard"}}`, 403},
		{"PATCH", env + "/{tApi}", `{"expectedVersion":1,"removeOrphans":true}`, 403},
		{"POST", env + "/{tBudget}/resume", `{}`, 403},
		{"GET", "/v1/organizations/acme/sync-targets", "", 200},
		{"GET", env + "/{tApi}", "", 200},
		{"POST", env + "/{tPause}/pause", `{}`, 200},
		{"DELETE", env + "/{tPause}", "", 204},
	} {
		var body io.Reader
		if c.body != "" {
			body = strings.NewReader(path(c.body))
		}
		req := httptest.NewRequest(c.method, path(c.path), body)
		req.Header.Set("Authorization", "Bearer "+f.Tokens["alice"])
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.status {
			t.Errorf("%s %s: %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
		if c.status == 403 && !strings.Contains(rec.Body.String(), `"message":"Outbound sync is disabled on this Installation; use the CLI mode (varlatch sync push)"`) {
			t.Errorf("%s %s: %s", c.method, c.path, rec.Body.String())
		}
	}
}

// targetsServer is varlatchd on the targets fixture's rows, with the fake
// platforms (whose requests it collects), sync on or off.
func targetsServer(t *testing.T, f paritytest.Fixture, syncOn bool) (http.Handler, *storage.DB, *values.Service, func() time.Time, *[]string, *sync.Mutex) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, targetsTables); err != nil {
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
		Sync: syncOn, SyncClient: platforms(&sent, &mu),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		vs.Settled()
		_ = store.Close()
	})
	return h, store, vs, now, &sent, &mu
}
