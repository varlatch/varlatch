// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/check"
	"github.com/varlatch/varlatch/go/server/migration/migrate"
	"github.com/varlatch/varlatch/go/server/migration/migrationtest"
	"github.com/varlatch/varlatch/go/server/webhooks"
	"github.com/varlatch/varlatch/go/server/write"
)

// sealURLs seals the webhook URLs of the database at path, as varlatchd
// does when it starts (webhooks.SealURLs): how many.
func sealURLs(t *testing.T, s seeded, path string) int {
	t.Helper()
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	n, err := webhooks.SealURLs(ctx, &write.Writer{Store: store, Gates: write.NewGates()}, s.source.RootKEK)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// An import leaves every webhook URL envelope empty, and the checks find
// none to hold; varlatchd's own class is no class of the bundle's.
func TestAnImportHoldsNoURLEnvelope(t *testing.T) {
	s := setUp(t)
	db := openRO(t, s.db)
	defer db.Close()
	var hooks, sealed int
	if err := db.QueryRow(`SELECT count(*), count(url_envelope) FROM webhooks`).Scan(&hooks, &sealed); err != nil || hooks == 0 || sealed != 0 {
		t.Fatalf("%d webhooks, %d sealed (%v)", hooks, sealed, err)
	}
	for _, c := range check.TargetOnlyClassNames {
		if slices.Contains(check.ClassNames, c) {
			t.Errorf("%s is a bundle's class too", c)
		}
	}
	if !slices.Contains(check.TargetOnlyClassNames, envelope.PurposeWebhookURL) {
		t.Errorf("the checks do not know %s", envelope.PurposeWebhookURL)
	}
	for _, it := range migrationtest.Items(t, s.source) {
		if it.Class == envelope.PurposeWebhookURL {
			t.Fatal("the source holds a webhook URL envelope")
		}
	}
}

// Once varlatchd sealed the webhook URLs, a reverse carries url, which this
// release keeps filled, and no envelope: the reverse checks open each one
// and hold it against its row's url, and pass; one that holds another URL,
// or does not open, fails at encryption-classes. A forward import of that
// reverse bundle leaves the envelopes empty again, url as it was.
func TestTheReverseChecksWithURLEnvelopes(t *testing.T) {
	s := setUp(t)
	ctx := context.Background()
	path := copyDB(t, s)
	n := sealURLs(t, s, path)
	if n == 0 {
		t.Fatal("the seed has no webhook to seal")
	}
	keep := filepath.Join(t.TempDir(), "keep")
	var rev bytes.Buffer
	if _, err := migrate.ExportReverse(ctx, &rev, migrate.Options{DataDir: filepath.Dir(path), Keep: keep, Release: "0.50.0-check"}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rev.Bytes(), []byte("url_envelope")) {
		t.Error("the reverse bundle names url_envelope")
	}
	kept := filepath.Join(keep, config.DatabaseFile)
	db := openRO(t, kept)
	var org, id, url, sealed string
	if err := db.QueryRow(`SELECT organization_id, id, url, url_envelope FROM webhooks w WHERE url_envelope IS NOT NULL
		AND organization_id IN (SELECT id FROM organizations WHERE org_kek_destroyed_at IS NULL) ORDER BY id LIMIT 1`).Scan(&org, &id, &url, &sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rev.Bytes(), []byte(sealed)) {
		t.Error("the reverse bundle carries a URL envelope")
	}
	decisions := []bundle.Decision{}
	for _, d := range tuples(t, db) {
		got, err := check.Evaluate(ctx, db, d)
		if err != nil {
			t.Fatal(err)
		}
		decisions = append(decisions, got)
	}
	db.Close()
	rebuilt := migrationtest.FromReverse(t, rev.Bytes(), s.source.RootKEK)
	b := migrationtest.Bundle(t, rebuilt, migrationtest.Options{Sections: &migrationtest.Sections{Digests: migrationtest.Digests(t, rebuilt, s.runKey), Decisions: decisions, At: 1}})
	runOn := func(path string) check.Report {
		t.Helper()
		db := openRO(t, path)
		defer db.Close()
		rep, err := check.Run(ctx, db, bytes.NewReader(b), check.Options{RootKEK: s.source.RootKEK, RunKey: s.runKey, Reverse: true})
		if err != nil {
			t.Fatal(err)
		}
		noSecrets(t, s, rep)
		return rep
	}
	rep := runOn(kept)
	if !rep.Passed {
		t.Fatalf("the reverse checks:\n%s", rep.Text())
	}
	if got, want := rep.Result(check.Classes).Checked, int64(len(migrationtest.Digests(t, rebuilt, s.runKey))+n); got < want {
		t.Errorf("encryption-classes checked %d items, want at least %d (%d URL envelopes)", got, want, n)
	}

	// Another URL's envelope, and one that does not open.
	wrapped := ""
	db = openRO(t, kept)
	if err := db.QueryRow(`SELECT wrapped_org_kek FROM organizations WHERE id = ?`, org).Scan(&wrapped); err != nil {
		t.Fatal(err)
	}
	db.Close()
	var w envelope.Envelope
	if err := json.Unmarshal([]byte(wrapped), &w); err != nil {
		t.Fatal(err)
	}
	kek, err := envelope.UnwrapOrgKEK(s.source.RootKEK, w, org)
	if err != nil {
		t.Fatal(err)
	}
	other, err := webhooks.SealURL(kek, org, id, "https://elsewhere.example.test/hook")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, envelope, says string }{
		{"another URL", other, "does not hold the row's url"},
		{"another webhook's", sealedFor(t, kek, org, "whk_another", url), "does not open"},
	} {
		t.Run(c.name, func(t *testing.T) {
			damaged := migrationtest.CopyDB(t, kept)
			damage(t, damaged, "UPDATE webhooks SET url_envelope = '"+c.envelope+"' WHERE id = '"+id+"'")
			rep := runOn(damaged)
			fs := failed(rep)[check.Classes]
			if rep.Passed || len(fs) != 1 || fs[0].Class != envelope.PurposeWebhookURL || !strings.Contains(fs[0].What, c.says) || !strings.Contains(fs[0].What, id) {
				t.Fatalf("%+v\n%s", fs, rep.Text())
			}
		})
	}

	// Forward again: url as it was, no envelope.
	dir := t.TempDir()
	if _, err := migrate.Import(ctx, bytes.NewReader(b), migrate.Options{DataDir: dir, RootKEK: s.source.RootKEK, Release: "0.50.0-check"}); err != nil {
		t.Fatal(err)
	}
	again := openRO(t, filepath.Join(dir, config.DatabaseFile))
	defer again.Close()
	var back string
	var envelopes int
	if err := again.QueryRow(`SELECT url, (SELECT count(url_envelope) FROM webhooks) FROM webhooks WHERE id = ?`, id).Scan(&back, &envelopes); err != nil || back != url || envelopes != 0 {
		t.Errorf("imported again: %q, %d envelopes (%v)", back, envelopes, err)
	}
}

func sealedFor(t *testing.T, kek []byte, org, id, url string) string {
	t.Helper()
	s, err := webhooks.SealURL(kek, org, id, url)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
