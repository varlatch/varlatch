// SPDX-License-Identifier: AGPL-3.0-or-later

package webhooks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/orgs"
)

// stored is a webhook's row as it rests: url and url_envelope.
func (wd *world) stored(id string) (string, sql.NullString) {
	wd.t.Helper()
	var url string
	var sealed sql.NullString
	if err := wd.store.Reader().QueryRowContext(context.Background(), `SELECT url, url_envelope FROM webhooks WHERE id = ?`, id).Scan(&url, &sealed); err != nil {
		wd.t.Fatal(err)
	}
	return url, sealed
}

// opened is a webhook's url_envelope opened under its Organization's KEK.
func (wd *world) opened(id string) string {
	wd.t.Helper()
	var org string
	var sealed sql.NullString
	if err := wd.store.Reader().QueryRowContext(context.Background(), `SELECT organization_id, url_envelope FROM webhooks WHERE id = ?`, id).Scan(&org, &sealed); err != nil {
		wd.t.Fatal(err)
	}
	if !sealed.Valid {
		wd.t.Fatalf("webhook %s has no URL envelope", id)
	}
	urls := NewURLs(wd.s.RootKEK, wd.store.Reader())
	defer urls.Close()
	url, err := urls.Of(context.Background(), org, id, "", sealed)
	if err != nil {
		wd.t.Fatal(err)
	}
	return url
}

// raw inserts webhooks as an older release, an import or a restore leaves
// them: url only.
func (wd *world) raw(org string, n int, prefix string) []string {
	wd.t.Helper()
	var ids []string
	for i := range n {
		id := fmt.Sprintf("whk_%s%04d", prefix, i)
		wd.exec(`INSERT INTO webhooks (id, organization_id, url, secret_envelope, cursor_occurred_at) VALUES (?, ?, ?, '{}', 1)`,
			id, org, fmt.Sprintf("https://hooks.example.test/%s/%d?token=t%d", prefix, i, i))
		ids = append(ids, id)
	}
	return ids
}

// A URL envelope opens to the URL under its own Organization and webhook,
// and as nothing else: not as the webhook's signing secret, not as another
// webhook's URL.
func TestURLEnvelopeRoundTrip(t *testing.T) {
	kek := envelope.GenerateKey()
	const url = "https://hooks.example.test/a?token=secret-part"
	sealed, err := SealURL(kek, "org_a", "whk_a", url)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "secret-part") || strings.Contains(sealed, "hooks.example.test") {
		t.Fatalf("the envelope shows the URL: %s", sealed)
	}
	if got, err := OpenURL(kek, "org_a", "whk_a", sealed); err != nil || got != url {
		t.Fatalf("%q, %v", got, err)
	}
	for _, c := range []struct {
		kek     []byte
		org, id string
	}{
		{envelope.GenerateKey(), "org_a", "whk_a"}, {kek, "org_b", "whk_a"}, {kek, "org_a", "whk_b"},
	} {
		if _, err := OpenURL(c.kek, c.org, c.id, sealed); err == nil {
			t.Errorf("opened under %s %s", c.org, c.id)
		}
	}
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(sealed), &env); err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Open(kek, env, envelope.WebhookSecretContext("org_a", "whk_a")); err == nil {
		t.Error("a URL envelope opened as the signing secret")
	}
	if _, err := OpenURL(kek, "org_a", "whk_a", "not an envelope"); err == nil {
		t.Error("opened text that is no envelope")
	}
}

// Create and Update write both forms: url, which the release before reads
// after a rollback, and the envelope of the same URL.
func TestWritersKeepBothForms(t *testing.T) {
	wd := newWorld(t, "127.0.0.1/32:*")
	created := wd.create("http://127.0.0.1:9/a?token=one")
	id := created.Webhook.ID
	if url, sealed := wd.stored(id); url != "http://127.0.0.1:9/a?token=one" || !sealed.Valid || wd.opened(id) != url {
		t.Fatalf("created: %q %v", url, sealed.Valid)
	}
	next := "http://127.0.0.1:9/b?token=two"
	if _, _, err := wd.s.Update(context.Background(), Request{Principal: alice()}, wd.org.ID, id, Patch{ExpectedVersion: 1, URL: &next}); err != nil {
		t.Fatal(err)
	}
	url, before := wd.stored(id)
	if url != next || wd.opened(id) != next {
		t.Fatalf("updated: %q, envelope %q", url, wd.opened(id))
	}
	// A change of the filter alone writes the envelope again, of the same URL.
	if _, _, err := wd.s.Update(context.Background(), Request{Principal: alice()}, wd.org.ID, id, Patch{ExpectedVersion: 2, SetEventTypes: true, EventTypes: []string{"project.created"}}); err != nil {
		t.Fatal(err)
	}
	if url, after := wd.stored(id); url != next || after == before || wd.opened(id) != next {
		t.Fatalf("filter changed: %q, envelope %q", url, wd.opened(id))
	}
}

// Every reader takes the envelope's URL, and url only for a row with none:
// the list, the read an update starts from (and its audit event's
// redaction), delivery; an envelope that does not open fails the read.
func TestReadersPreferTheEnvelope(t *testing.T) {
	rc := newReceiver(t)
	wd := newWorld(t, "127.0.0.1/32:*")
	hook := wd.create(rc.url("/sealed?token=abc"))
	id := hook.Webhook.ID
	// url says otherwise; the envelope is the one read.
	wd.exec(`UPDATE webhooks SET url = 'https://plain.example.test/other' WHERE id = ?`, id)
	list := func() string {
		t.Helper()
		items, err := List(context.Background(), wd.store.Reader(), wd.s.RootKEK, wd.org.ID)
		if err != nil {
			t.Fatal(err)
		}
		v, _ := items[0].(jsvalue.Object).Get("url")
		return v.(string)
	}
	if got := list(); got != rc.url("/sealed?token=abc") {
		t.Fatalf("list: %q", got)
	}
	wd.event("project.created", nil)
	wd.deliver()
	if got := rc.requests(); len(got) != 1 || got[0].target != "/sealed?token=abc" {
		t.Fatalf("delivered to %+v", got)
	}
	// The update reads the envelope's URL as the current one: the audit
	// event's oldUrl is its redaction.
	next := rc.url("/next?token=def")
	if _, _, err := wd.s.Update(context.Background(), Request{Principal: alice()}, wd.org.ID, id, Patch{ExpectedVersion: 1, URL: &next}); err != nil {
		t.Fatal(err)
	}
	var md string
	if err := wd.store.Reader().QueryRow(`SELECT metadata FROM audit_events WHERE event_type = 'webhook.updated'`).Scan(&md); err != nil {
		t.Fatal(err)
	}
	if want := audit.RedactWebhookURL(rc.url("/sealed?token=abc")); !strings.Contains(md, `"oldUrl":"`+want+`"`) || strings.Contains(md, "plain.example.test") {
		t.Fatalf("webhook.updated metadata %s, want oldUrl %s", md, want)
	}
	// No envelope: url.
	wd.exec(`UPDATE webhooks SET url_envelope = NULL, url = ? WHERE id = ?`, rc.url("/plain"), id)
	if got := list(); got != rc.url("/plain") {
		t.Fatalf("list without an envelope: %q", got)
	}
	// An envelope that does not open is no reason to read url.
	wd.exec(`UPDATE webhooks SET url_envelope = '{"formatVersion":1}' WHERE id = ?`, id)
	if _, err := List(context.Background(), wd.store.Reader(), wd.s.RootKEK, wd.org.ID); err == nil {
		t.Fatal("listed a webhook whose envelope does not open")
	}
	if _, err := read(context.Background(), wd.store.Reader(), wd.s.RootKEK, wd.org.ID, id); err == nil {
		t.Fatal("read a webhook whose envelope does not open")
	}
}

// SealURLs seals every row without an envelope (revoked ones included) and
// every envelope of a URL url no longer holds, leaves a webhook whose
// Organization's KEK was destroyed and an envelope that does not open; a
// second pass writes nothing.
func TestSealURLs(t *testing.T) {
	wd := newWorld(t, "127.0.0.1/32:*")
	ctx := context.Background()
	fresh := wd.raw(wd.org.ID, 3, "a")
	wd.exec(`UPDATE webhooks SET revoked_at = 1 WHERE id = ?`, fresh[2])
	current := wd.create("http://127.0.0.1:9/current").Webhook.ID
	changed := wd.create("http://127.0.0.1:9/before").Webhook.ID
	// An older release changed the URL after a rollback.
	wd.exec(`UPDATE webhooks SET url = 'http://127.0.0.1:9/after' WHERE id = ?`, changed)
	broken := wd.create("http://127.0.0.1:9/broken").Webhook.ID
	wd.exec(`UPDATE webhooks SET url_envelope = '{"formatVersion":1}' WHERE id = ?`, broken)
	gone, err := orgs.Create(ctx, wd.s.Writer, wd.s.RootKEK, "idn_a", "gone", "Gone")
	if err != nil {
		t.Fatal(err)
	}
	deleted := wd.raw(gone.ID, 1, "g")[0]
	wd.exec(`UPDATE organizations SET deleted_at = 1, wrapped_org_kek = NULL, org_kek_destroyed_at = 1 WHERE id = ?`, gone.ID)
	_, currentBefore := wd.stored(current)

	n, err := SealURLs(ctx, wd.s.Writer, wd.s.RootKEK)
	if n != 4 || err == nil || !strings.Contains(err.Error(), broken) {
		t.Fatalf("first pass: %d, %v", n, err)
	}
	for _, id := range append(fresh, changed) {
		url, _ := wd.stored(id)
		if got := wd.opened(id); got != url {
			t.Errorf("%s: sealed %q, url %q", id, got, url)
		}
	}
	if _, after := wd.stored(current); after != currentBefore {
		t.Error("an envelope that holds url was sealed again")
	}
	if _, s := wd.stored(broken); s.String != `{"formatVersion":1}` {
		t.Errorf("an envelope that does not open was replaced: %q", s.String)
	}
	if _, s := wd.stored(deleted); s.Valid {
		t.Error("a webhook of a deleted Organization was sealed")
	}

	// Idempotent: nothing is written again.
	wd.exec(`UPDATE webhooks SET url_envelope = NULL WHERE id = ?`, broken)
	if n, err := SealURLs(ctx, wd.s.Writer, wd.s.RootKEK); n != 1 || err != nil {
		t.Fatalf("second pass: %d, %v", n, err)
	}
	before := map[string]string{}
	for _, id := range append(fresh, changed, current, broken) {
		_, s := wd.stored(id)
		before[id] = s.String
	}
	if n, err := SealURLs(ctx, wd.s.Writer, wd.s.RootKEK); n != 0 || err != nil {
		t.Fatalf("third pass: %d, %v", n, err)
	}
	for id, s := range before {
		if _, after := wd.stored(id); after.String != s {
			t.Errorf("%s was written again", id)
		}
	}
}

// A pass cut short after its first batch keeps what it sealed; the next
// seals the rest and no more; the one after, nothing.
func TestSealURLsCutShort(t *testing.T) {
	wd := newWorld(t, "127.0.0.1/32:*")
	ctx := context.Background()
	ids := wd.raw(wd.org.ID, sealBatch*2+50, "c")
	stop := errors.New("killed")
	afterSealBatch = func(int) error { return stop }
	n, err := SealURLs(ctx, wd.s.Writer, wd.s.RootKEK)
	afterSealBatch = nil
	if n != sealBatch || !errors.Is(err, stop) {
		t.Fatalf("cut short: %d, %v", n, err)
	}
	if got := wd.count(`SELECT count(*) FROM webhooks WHERE url_envelope IS NOT NULL`); got != sealBatch {
		t.Fatalf("%d sealed after the first batch", got)
	}
	var batches []int
	afterSealBatch = func(n int) error { batches = append(batches, n); return nil }
	t.Cleanup(func() { afterSealBatch = nil })
	if n, err := SealURLs(ctx, wd.s.Writer, wd.s.RootKEK); n != len(ids)-sealBatch || err != nil {
		t.Fatalf("the next pass: %d, %v", n, err)
	}
	if fmt.Sprint(batches) != fmt.Sprint([]int{sealBatch, 50}) {
		t.Errorf("batches written %v", batches)
	}
	for _, id := range ids {
		if url, _ := wd.stored(id); wd.opened(id) != url {
			t.Fatalf("%s holds another URL", id)
		}
	}
	batches = nil
	if n, err := SealURLs(ctx, wd.s.Writer, wd.s.RootKEK); n != 0 || err != nil || batches != nil {
		t.Fatalf("a pass with nothing to do: %d, %v, %v", n, err, batches)
	}
}

// The pass's write never replaces what changed after it read: another URL,
// or another envelope.
func TestSealURLsWritesOnlyWhatItRead(t *testing.T) {
	wd := newWorld(t, "127.0.0.1/32:*")
	id := wd.raw(wd.org.ID, 1, "w")[0]
	url, _ := wd.stored(id)
	seal := func(url, seen string) int64 {
		t.Helper()
		var n int64
		err := wd.store.Write(context.Background(), func(tx *storage.Tx) error {
			var err error
			n, err = query.New(tx).SealWebhookURL(context.Background(), query.SealWebhookURLParams{
				UrlEnvelope: sql.NullString{String: `{"x":1}`, Valid: true}, ID: id, Url: url, Seen: sql.NullString{String: seen, Valid: true}})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if seal("https://other.example.test/", "") != 0 || seal(url, `{"y":1}`) != 0 {
		t.Fatal("written over a change")
	}
	if seal(url, "") != 1 || seal(url, "") != 0 || seal(url, `{"x":1}`) != 1 {
		t.Fatal("the write the pass read for was not made")
	}
}

// The delivery loop's pass seals first: the one at start, and every later
// one after a restore or a migration brought rows in.
func TestTheLoopsPassSeals(t *testing.T) {
	wd := newWorld(t, "127.0.0.1/32:*")
	id := wd.raw(wd.org.ID, 1, "p")[0]
	wd.s.pass(context.Background(), nil)
	if url, _ := wd.stored(id); wd.opened(id) != url {
		t.Fatal("the pass did not seal")
	}
}
