// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs_test

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
	"sync"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// What mints a token from a GitHub App is step 4.10's (the owner,
// 2026-11-17): until it lands, creating an App Connection, and a check or
// a listing with one, answer 501 NOT_IMPLEMENTED_YET once the request is
// valid, and nothing reaches a platform or the database. 4.10 replaces
// this test with the answers the TypeScript server gives.
func TestAppMintingNotBuiltYet(t *testing.T) {
	f, _ := read(t, paritytest.Path("connections-v0.22.0.json"))
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
	policy := outbound.New(nil, outbound.Options{Log: log})
	t.Cleanup(policy.Close)
	var mu sync.Mutex
	var sent []string
	public, _ := url.Parse(publicURL)
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	approvals := auth.New(store, auth.Options{Log: log, RootKEK: rootKEK, PublicURL: public, PersonGate: w.Gates.PersonGate})
	vs := values.New(store, rootKEK, values.Options{Log: log, Approvals: approvals, Gates: w.Gates})
	h, err := httpserver.New(httpserver.Options{
		Version: f.Version(), Backend: daemon.NewBackend(store, rootKEK), Log: log, PublicURL: public,
		Auth: approvals, Values: vs, Writer: w, RootKEK: rootKEK, Outbound: policy,
		Sync: true, SyncClient: platforms(&sent, &mu),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		vs.Settled()
		_ = store.Close()
	})
	app := fillPath(f)("{app}")
	if !strings.HasPrefix(app, "pcn_") {
		t.Fatalf("no App Connection in the fixture: %q", app)
	}
	events := func() int {
		var n int
		if err := store.Reader().QueryRow(`SELECT count(*) FROM audit_events`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := events()
	for _, c := range []struct{ name, path, body string }{
		{"create on an installation", "/v1/organizations/acme/platform-connections", `{"credentialKind":"github-app","installationId":77,"name":"App 2"}`},
		{"check with the App Connection", "/v1/organizations/acme/platform-connections/check", `{"connectionId":"` + app + `"}`},
		{"check a repository with it", "/v1/organizations/acme/platform-connections/check", `{"connectionId":"` + app + `","destination":{"repo":"api"}}`},
		{"list with the App Connection", "/v1/organizations/acme/platform-connections/destinations", `{"connectionId":"` + app + `"}`},
	} {
		req := httptest.NewRequest("POST", c.path, strings.NewReader(c.body))
		req.Header.Set("Authorization", "Bearer "+f.Tokens["alice"])
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var body struct {
			Error struct{ Code string } `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != http.StatusNotImplemented || body.Error.Code != "NOT_IMPLEMENTED_YET" {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body.String())
		}
	}
	if len(sent) != 0 {
		t.Errorf("a platform was asked: %v", sent)
	}
	if n := events(); n != before {
		t.Errorf("%d audit events written", n-before)
	}
}
