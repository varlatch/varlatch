// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/oauth/oauthparams"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/syncs"
	"github.com/varlatch/varlatch/go/server/values"
)

// An OAuth connection (ADR-0062) is not in what a Sync Target pushes: an item
// that was a value and becomes one leaves the destinations as a deleted one
// does, and nothing of it is opened.
func TestConnectionsAreNeverPushed(t *testing.T) {
	ctx := context.Background()
	w := newEngineWorld(t)
	w.engine.RunOnce(ctx, syncs.RunOptions{})
	if !strings.Contains(w.platforms(), "API_KEY") {
		t.Fatal("the first run pushed no API_KEY")
	}
	q := query.New(w.store.Reader())
	var org, project, env, alice string
	if err := w.store.Reader().QueryRow(`SELECT p.organization_id, p.id, e.id, (SELECT id FROM identities WHERE name = 'Alice')
		FROM environments e JOIN projects p ON p.id = e.project_id JOIN sync_targets t ON t.environment_id = e.id LIMIT 1`).Scan(&org, &project, &env, &alice); err != nil {
		t.Fatal(err)
	}
	p, err := q.LiveProject(ctx, query.LiveProjectParams{OrganizationID: org, SlugOrID: project})
	if err != nil {
		t.Fatal(err)
	}
	e, err := q.LiveEnvironment(ctx, query.LiveEnvironmentParams{ProjectID: project, NameOrID: env})
	if err != nil {
		t.Fatal(err)
	}
	principal := &auth.Principal{}
	principal.Identity.ID, principal.Identity.Kind = alice, "human"
	target := values.Target{OrganizationID: org, Project: p, Env: e}
	for _, item := range []string{"API_KEY", "DATABASE_URL"} {
		if _, err := values.DeleteValue(ctx, w.engine.Writer, principal, target, item, time.Now); err != nil {
			t.Fatal(err)
		}
		if err := w.store.Write(ctx, func(tx *storage.Tx) error {
			_, _, _, err := values.CreateConnection(ctx, tx, w.engine.RootKEK, principal, target, item, values.ConnectionInput{
				Params: oauthparams.Params{V: oauthparams.Version, Provider: "generic", TokenEndpoint: "https://idp.example/token", AuthMethod: oauthparams.AuthBasic,
					Grant: oauthparams.ClientCredentials, ClientID: "client-1"}, ClientSecret: "made-up-client-secret"}, "req_t", time.Now().UnixMicro())
			return err
		}); err != nil {
			t.Fatalf("%s: %v", item, err)
		}
	}
	w.fake.take()
	w.later()
	w.engine.RunOnce(ctx, syncs.RunOptions{})
	sent := strings.Join(w.fake.take(), "\n")
	for what, text := range map[string]string{"sent": sent, "the platforms": w.platforms()} {
		if strings.Contains(text, "made-up-client-secret") || strings.Contains(text, "ciphertext") {
			t.Errorf("%s holds it: %s", what, text)
		}
	}
	if !strings.Contains(sent, "DELETE https://api.github.com/repos/acme/api/actions/secrets/API_KEY") {
		t.Errorf("API_KEY is left at a destination that removes what is gone:\n%s", sent)
	}
	for _, r := range paritytest.Rows(t, w.store, `SELECT metadata FROM audit_events WHERE event_type = 'sync.values_decrypted' ORDER BY event_order DESC LIMIT 5`) {
		if text := fmt.Sprint(r["metadata"]); strings.Contains(text, "API_KEY") || strings.Contains(text, "DATABASE_URL") {
			t.Errorf("decrypted: %s", text)
		}
	}
	var row, version string
	if err := w.store.Reader().QueryRow("SELECT id, current_version_id FROM env_values WHERE environment_id = ? AND item_name = 'API_KEY'", env).Scan(&row, &version); err != nil {
		t.Fatal(err)
	}
	if v, err := values.OpenForSync(ctx, w.store.Reader(), make([]byte, 32), org, row, version); err == nil || v != "" || !strings.Contains(err.Error(), "OAuth connection") {
		t.Errorf("opened: %v", err)
	}
}
