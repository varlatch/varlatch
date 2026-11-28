// SPDX-License-Identifier: AGPL-3.0-or-later

package backups

import (
	"context"
	"database/sql"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/webhooks"
	"github.com/varlatch/varlatch/go/server/write"
)

// An archive carries a webhook's URL in both forms, as the database holds
// them: a sealed row comes back with url and url_envelope unchanged, and a
// row with no envelope yet (an older release's, or one written before the
// start pass ran) comes back with none, which varlatchd's start pass
// (webhooks.SealURLs) then seals under the restored Organization KEK.
func TestRestoreCarriesWebhookURLs(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	w := &write.Writer{Store: f.store, Gates: write.NewGates()}
	f.exec(t, `INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice')`)
	org, err := orgs.Create(ctx, w, f.rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"whk_sealed", "whk_plain"} {
		f.exec(t, `INSERT INTO webhooks (id, organization_id, url, secret_envelope, cursor_occurred_at) VALUES (?, ?, ?, '{}', 1)`,
			id, org.ID, "https://hooks.example.test/"+id+"?token=t")
	}
	// Both sealed, then one as an older release leaves it: url only.
	if n, err := webhooks.SealURLs(ctx, w, f.rootKEK); err != nil || n != 2 {
		t.Fatalf("sealed %d, %v", n, err)
	}
	f.exec(t, `UPDATE webhooks SET url_envelope = NULL WHERE id = 'whk_plain'`)
	sealedText := queryOne(t, f.cfg.DatabasePath(), `SELECT url_envelope FROM webhooks WHERE id = 'whk_sealed'`)

	res, err := f.service(nil).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.target(t)
	if _, err := Restore(ctx, cfg, res.Path, f.bekOf(t), f.rootKEK, nil); err != nil {
		t.Fatal(err)
	}
	db := cfg.DatabasePath()
	if got := queryOne(t, db, `SELECT url_envelope FROM webhooks WHERE id = 'whk_sealed'`); got != sealedText {
		t.Errorf("the sealed row's envelope came back as %q", got)
	}
	if got := queryOne(t, db, `SELECT count(*) FROM webhooks WHERE url_envelope IS NULL`); got != "1" {
		t.Errorf("%s rows came back without an envelope", got)
	}
	if got := queryOne(t, db, `SELECT group_concat(url, ' ') FROM (SELECT url FROM webhooks ORDER BY id)`); got != "https://hooks.example.test/whk_plain?token=t https://hooks.example.test/whk_sealed?token=t" {
		t.Errorf("url came back as %q", got)
	}

	// The start pass on the restored database seals the row with none.
	restored, err := storage.Open(ctx, storage.Options{Path: db})
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	n, err := webhooks.SealURLs(ctx, &write.Writer{Store: restored, Gates: write.NewGates()}, f.rootKEK)
	if err != nil || n != 1 {
		t.Fatalf("the start pass after the restore: %d, %v", n, err)
	}
	urls := webhooks.NewURLs(f.rootKEK, restored.Reader())
	defer urls.Close()
	rows, err := restored.Reader().QueryContext(ctx, `SELECT id, url, url_envelope FROM webhooks`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, url string
		var sealed sql.NullString
		if err := rows.Scan(&id, &url, &sealed); err != nil {
			t.Fatal(err)
		}
		if !sealed.Valid {
			t.Errorf("%s: still no envelope", id)
			continue
		}
		if got, err := urls.Of(ctx, org.ID, id, "", sealed); err != nil || got != url {
			t.Errorf("%s: the envelope holds %q (%v), url %q", id, got, err, url)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
