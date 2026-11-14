// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/db/query"
)

// testAuth is an installation in a temporary database, with one person
// (idn_parity) and its credentials by state: valid, revoked, expired and
// agent-run, as the parity table names them.
type testAuth struct {
	svc    *auth.Service
	store  *storage.DB
	tokens map[string]string
}

func newTestAuth(t *testing.T, pub *url.URL, now func() time.Time) *testAuth {
	t.Helper()
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := db.Init(ctx, store, "test"); err != nil {
		t.Fatal(err)
	}
	ta := &testAuth{svc: auth.New(store, auth.Options{PublicURL: pub, Now: now}), store: store, tokens: map[string]string{}}
	err = store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		if err := q.CreateInstallation(ctx, query.CreateInstallationParams{ID: "inst_test", KekCanary: "{}"}); err != nil {
			return err
		}
		if err := q.InsertHumanIdentity(ctx, query.InsertHumanIdentityParams{ID: "idn_parity", Name: "Parity", InstallationAdmin: true, CreatedAt: 1}); err != nil {
			return err
		}
		n := now().UnixMicro()
		past := n - time.Hour.Microseconds()
		for state, in := range map[string]auth.Issue{
			"valid":     {IdentityID: "idn_parity", Kind: auth.KindCLI},
			"revoked":   {IdentityID: "idn_parity", Kind: auth.KindCLI},
			"expired":   {IdentityID: "idn_parity", Kind: auth.KindCLI, ExpiresAt: &past},
			"agent-run": {IdentityID: "idn_parity", Kind: auth.KindAgentRun},
		} {
			issued, err := auth.IssueCredential(ctx, tx, n, in)
			if err != nil {
				return err
			}
			ta.tokens[state] = issued.Token
			if state == "revoked" {
				if err := auth.RevokeCredential(ctx, tx, n, issued.CredentialID, "idn_parity", nil); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return ta
}
