// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/githubapps"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/syncs"
)

// A Target on a GitHub App Connection converges with an installation
// token minted for the run (credentialOf; ADR-0047 Decisions 3 and 4).

const appDestination = `["github-actions","acme","api"]`

// appEngineWorld is the converge fixture's world with its GitHub
// Connection turned into an App Connection on installation 7 of App 1
// (client id Iv1.x), its key sealed under the Organization's KEK, and
// GitHub's token endpoint in front of the fake platforms: installation 7
// mints "minted-7-<repositories>", any other is not installed.
type appEngineWorld struct {
	*engineWorld
	mu     sync.Mutex
	mints  []string
	tokens int
}

func newAppEngineWorld(t *testing.T) *appEngineWorld {
	w := &appEngineWorld{engineWorld: newEngineWorld(t)}
	rows := paritytest.Rows(t, w.store, `SELECT id, wrapped_org_kek FROM organizations WHERE slug = 'acme'`)
	org := rows[0]["id"].(string)
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(rows[0]["wrapped_org_kek"].(string)), &env); err != nil {
		t.Fatal(err)
	}
	kek, err := envelope.UnwrapOrgKEK(w.engine.RootKEK, env, org)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := githubapps.SealKey(kek, org, "gha_test", rsaKey(t))
	if err != nil {
		t.Fatal(err)
	}
	w.exec(`INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope)
		VALUES ('gha_test', ?, 1, 'varlatch-acme', 'Iv1.x', 'acme', 2, 'organization', ?)`, org, sealed)
	w.exec(`UPDATE platform_connections SET credential_kind = 'github-app', credential_envelope = NULL, github_app_id = 'gha_test',
		github_installation_id = 7 WHERE name = 'GitHub'`)
	platforms := w.fake.client().Transport
	syncs.UseClient(w.engine, &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.github.com" || !strings.HasPrefix(r.URL.Path, "/app/") {
			return platforms.RoundTrip(r)
		}
		body, _ := io.ReadAll(r.Body)
		w.mu.Lock()
		defer w.mu.Unlock()
		w.mints = append(w.mints, r.Method+" "+r.URL.Path+" "+string(body))
		answer := func(status int, text string) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(text)), Request: r}, nil
		}
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/7/access_tokens" {
			return answer(404, `{"message":"Not Found"}`)
		}
		var n struct{ Repositories []string }
		_ = json.Unmarshal(body, &n)
		w.tokens++
		return answer(201, `{"token":"minted-7-`+strings.Join(n.Repositories, "+")+`","expires_at":"2026-09-01T13:00:00Z"}`)
	})})
	return w
}

func (w *appEngineWorld) appTarget() paritytest.Row {
	for _, r := range w.targets() {
		if r["canonical_destination"] == appDestination {
			return r
		}
	}
	w.t.Fatal("no Target on the App Connection")
	return nil
}

// The run mints one token, narrowed to the Target's repository with write
// on its secrets, and pushes with it; the Connection records no expiry.
func TestAppConnectionTargetsConverge(t *testing.T) {
	w := newAppEngineWorld(t)
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	r := w.appTarget()
	if r["generation"] == int64(0) || r["needs_sync"] != int64(0) || r["failure_count"] != int64(0) {
		t.Fatalf("the App Connection's Target did not converge: %v", r)
	}
	if len(w.mints) != 1 || w.mints[0] != `POST /app/installations/7/access_tokens {"repositories":["api"],"permissions":{"secrets":"write","metadata":"read"}}` {
		t.Fatalf("mints: %q", w.mints)
	}
	pushed := 0
	for _, line := range w.fake.take() {
		if strings.Contains(line, "/repos/acme/api/") {
			pushed++
			if !strings.Contains(line, " Bearer minted-7-api") {
				t.Errorf("not sent with the minted token: %s", line)
			}
		}
	}
	if pushed == 0 {
		t.Fatal("nothing pushed for the App Connection's Target")
	}
	for _, c := range paritytest.Rows(t, w.store, `SELECT credential_expires_at FROM platform_connections WHERE name = 'GitHub'`) {
		if c["credential_expires_at"] != nil {
			t.Errorf("an App Connection's expiry was recorded: %v", c)
		}
	}
}

// A removed App, or an installation GitHub does not know: the run fails
// with Varlatch's reading of it, and nothing is pushed.
func TestAppConnectionTargetsFailWithoutAToken(t *testing.T) {
	for _, c := range []struct{ name, setup, want string }{
		{"removed", `UPDATE github_apps SET removed_at = 1, key_envelope = NULL`,
			"GitHub App: This Connection's GitHub App was removed from Varlatch, so Varlatch can no longer act for it."},
		{"uninstalled", `UPDATE platform_connections SET github_installation_id = 8 WHERE name = 'GitHub'`,
			"GitHub App: The GitHub App is no longer installed on acme. Install it again on GitHub, or choose another installation."},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newAppEngineWorld(t)
			w.exec(c.setup)
			w.engine.RunOnce(context.Background(), syncs.RunOptions{})
			r := w.appTarget()
			if r["last_result"] != c.want || r["failure_count"] != int64(1) {
				t.Fatalf("got %v %v, want %q", r["last_result"], r["failure_count"], c.want)
			}
			for _, line := range w.fake.take() {
				if strings.Contains(line, "/repos/acme/api/") {
					t.Errorf("sent without a token: %s", line)
				}
			}
		})
	}
}
