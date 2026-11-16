// SPDX-License-Identifier: AGPL-3.0-or-later

package outbound_test

import (
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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

// outboundTables are the tables of outbound-v0.22.0.json
// (go-outbound-fixture.test.ts).
var outboundTables = []string{"installation", "identities", "credentials", "organizations", "org_memberships", "organization_freezes",
	"webhooks", "platform_connections", "oidc_bindings", "audit_events"}

// allow and resolve are the fixture's allow list and resolver (ALLOW and
// RESOLVE there).
const allow = "private.example,hooks.internal:8443,127.0.0.1/32:*"

var answers = map[string][]outbound.Answer{
	"hooks.public.example":  {{"93.184.216.34", 4}, {"2606:2800:220:1::1", 6}},
	"private.example":       {{"10.0.0.5", 4}},
	"hooks.internal":        {{"10.1.2.3", 4}},
	"intranet.example":      {{"192.168.1.20", 4}},
	"plain.example":         {{"93.184.216.35", 4}},
	"meta.example":          {{"169.254.169.254", 4}},
	"mixed.example":         {{"10.9.9.9", 4}, {"93.184.216.36", 4}},
	"coolify.internal":      {{"172.16.4.4", 4}},
	"convex.public.example": {{"93.184.216.37", 4}},
	"issuer.internal":       {{"100.64.1.1", 4}},
}

func resolve(_ context.Context, name string) ([]outbound.Answer, error) {
	if a, ok := answers[name]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// The outbound fixture's two pages give the TypeScript server's answers
// (step 4.7a): getInstallationOutbound (the allow list as parsed, its
// warnings, every refused destination by Organization with what the
// suggestion leaves out, the suggested value, the unresolved count) and
// refusedDestinations (an Organization's refused destinations with the
// earliest recorded refusal of each in the last 30 days), for an
// Installation Admin, a member and an outsider, a frozen, a deleted and an
// unknown Organization; every response valid against the OpenAPI document.
func TestTypeScriptFixture(t *testing.T) {
	f, err := paritytest.Read(paritytest.Path("outbound-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 10 {
		t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
	}
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, outboundTables); err != nil {
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
	entries, err := outbound.ParseAllow(allow)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	now := paritytest.HourClock()
	approvals := auth.New(store, auth.Options{Log: log, RootKEK: rootKEK, PersonGate: w.Gates.PersonGate, Now: now})
	vs := values.New(store, rootKEK, values.Options{Log: log, Approvals: approvals, Gates: w.Gates, Now: now})
	h, err := httpserver.New(httpserver.Options{
		Version: f.Version(), Backend: daemon.NewBackend(store, rootKEK), Log: log,
		Auth: approvals, Values: vs, Writer: w, RootKEK: rootKEK, Now: now,
		Outbound: outbound.New(entries, outbound.Options{Resolve: resolve}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		vs.Settled()
		_ = store.Close()
	})
	acme := ""
	for _, o := range f.Rows["organizations"] {
		if o["slug"] == "acme" {
			acme = o["id"].(string)
		}
	}
	paritytest.Replay(t, paritytest.Target{
		Handler: h, Store: store, Settled: vs.Settled, Path: strings.NewReplacer("{acmeId}", acme).Replace, Now: now,
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
	}, f)
}
