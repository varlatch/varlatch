// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities_test

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
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// TestRetiringTheAgentRevokesItsCapabilities: a retired Agent's
// Capabilities stop working at once, not when they expire, and stay
// revoked (ADR-0034 §3: retirement revokes what was issued, so a later
// reactivation resurrects nothing).
func TestRetiringTheAgentRevokesItsCapabilities(t *testing.T) {
	f, err := paritytest.Read(paritytest.Path("capabilities-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(dbPath, f.Rows, capabilitiesTables); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), storage.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rootKEK, err := hex.DecodeString(f.RootKEK)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := url.Parse("http://127.0.0.1:8686")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := &write.Writer{Store: store, Gates: write.NewGates()}
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
	t.Cleanup(vs.Settled)
	fill := fillPath(f, nil)

	call := func(method, path, credential, body string) (int, string) {
		t.Helper()
		var r io.Reader
		if body != "" {
			r = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, "http://127.0.0.1:8686"+fill(path), r)
		req.Header.Set("Authorization", "Bearer "+f.Tokens[credential])
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		vs.Settled()
		return rec.Code, rec.Body.String()
	}
	const exercises = "/v1/organizations/cap/projects/api/environments/development/capabilities/{cap:live}/exercises"
	const exercise = `{"capabilitySecret":"vlt_cap_known_live","destination":{"host":"api.example.com","port":443},` +
		`"placements":[{"item":"SECRET_A","target":"header:authorization"}]}`

	if code, body := call(http.MethodPost, exercises, "broker", exercise); code != http.StatusOK {
		t.Fatalf("exercise before retirement: %d %s", code, body)
	}
	if code, body := call(http.MethodPost, "/v1/organizations/cap/identities/{idn:agent}/retire", "alice", ""); code != http.StatusOK {
		t.Fatalf("retire the Agent: %d %s", code, body)
	}
	code, body := call(http.MethodPost, exercises, "broker", exercise)
	if code != http.StatusForbidden {
		t.Fatalf("exercise after retirement: %d %s, want 403 (revoked)", code, body)
	}
	var refusal struct {
		Error struct {
			Details struct {
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &refusal); err != nil || refusal.Error.Details.Reason != "revoked" {
		t.Fatalf("exercise after retirement: %s, want reason revoked", body)
	}

	// Every live Capability of the Agent is revoked, each audited; another
	// Agent's are untouched.
	var live, revokedEvents, othersLive int
	ctx, db, agent := context.Background(), store.Reader(), fill("{idn:agent}")
	for _, c := range []struct {
		q   string
		arg []any
		n   *int
	}{
		{"SELECT count(*) FROM capabilities WHERE agent_identity_id = ? AND revoked_at IS NULL", []any{agent}, &live},
		{"SELECT count(*) FROM capabilities WHERE agent_identity_id <> ? AND revoked_at IS NULL", []any{agent}, &othersLive},
		{"SELECT count(*) FROM audit_events WHERE event_type = 'capability.revoked'", nil, &revokedEvents},
	} {
		if err := db.QueryRowContext(ctx, c.q, c.arg...).Scan(c.n); err != nil {
			t.Fatal(err)
		}
	}
	if live != 0 {
		t.Fatalf("%d of the retired Agent's Capabilities are still live", live)
	}
	if othersLive == 0 {
		t.Fatal("another Agent's Capabilities were revoked too")
	}
	// known-untargeted, known-live, known-theirs, known-expired, known-prod:
	// the Agent's unrevoked ones (an expired one is revoked too, harmlessly).
	if revokedEvents != 5 {
		t.Fatalf("%d capability.revoked events, want 5", revokedEvents)
	}
}
