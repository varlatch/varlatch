// SPDX-License-Identifier: AGPL-3.0-or-later

package webhooks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/write"
)

// A webhook's URL rests sealed under its Organization's KEK (schema
// version 8, envelope purpose webhook-url, bound to the Organization and
// the webhook), as its signing secret does: a URL may carry a token in its
// path or query. This release writes the envelope and the plaintext url
// column both, so the release before it, which reads url only, reads the
// same webhooks after a rollback. Every reader takes the envelope, and url
// only while a row has none: a row an import, a restore or an older
// release wrote. SealURLs seals those, when varlatchd starts and on every
// delivery pass; the next release stops writing url.

// SealURL is a webhook's url_envelope: its URL sealed under the
// Organization's KEK.
func SealURL(orgKEK []byte, organizationID, webhookID, url string) (string, error) {
	sealed, err := envelope.Seal(orgKEK, []byte(url), envelope.WebhookURLContext(organizationID, webhookID))
	if err != nil {
		return "", err
	}
	text, err := json.Marshal(sealed)
	return string(text), err
}

// OpenURL opens what SealURL sealed.
func OpenURL(orgKEK []byte, organizationID, webhookID, sealed string) (string, error) {
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(sealed), &env); err != nil {
		return "", fmt.Errorf("webhook %s: its URL envelope is not an envelope", webhookID)
	}
	url, err := envelope.Open(orgKEK, env, envelope.WebhookURLContext(organizationID, webhookID))
	if err != nil {
		return "", fmt.Errorf("webhook %s: its URL envelope does not open: %w", webhookID, err)
	}
	return string(url), nil
}

// unwrapOrgKEK is orgKekOf on a row's wrapped_org_kek: a deleted
// Organization's KEK is destroyed, so it fails closed.
func unwrapOrgKEK(rootKEK []byte, organizationID string, wrapped sql.NullString) ([]byte, error) {
	if !wrapped.Valid {
		return nil, domainerr.New("ORGANIZATION_DELETED", "This Organization was deleted: its key is destroyed")
	}
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(wrapped.String), &env); err != nil {
		return nil, err
	}
	return envelope.UnwrapOrgKEK(rootKEK, env, organizationID)
}

// URLs reads webhooks' URLs in one snapshot (DB): the envelope's, under
// each Organization's KEK, unwrapped once when its first envelope needs it;
// url only for a row with no envelope. Close clears the keys.
type URLs struct {
	RootKEK []byte
	DB      query.DBTX
	keks    map[string][]byte
}

// NewURLs reads URLs in db's snapshot.
func NewURLs(rootKEK []byte, db query.DBTX) *URLs { return &URLs{RootKEK: rootKEK, DB: db} }

// Of is a webhook's URL, from its row's url (plain) and url_envelope
// (sealed). An envelope that does not open is an error, never a reason to
// read url.
func (u *URLs) Of(ctx context.Context, organizationID, webhookID, plain string, sealed sql.NullString) (string, error) {
	if !sealed.Valid {
		return plain, nil
	}
	kek, ok := u.keks[organizationID]
	if !ok {
		o, err := query.New(u.DB).RetrievalOrganization(ctx, organizationID)
		if err != nil {
			return "", err
		}
		if kek, err = unwrapOrgKEK(u.RootKEK, organizationID, o.WrappedOrgKek); err != nil {
			return "", err
		}
		if u.keks == nil {
			u.keks = map[string][]byte{}
		}
		u.keks[organizationID] = kek
	}
	return OpenURL(kek, organizationID, webhookID, sealed.String)
}

// Close clears the keys the reads unwrapped.
func (u *URLs) Close() {
	for _, k := range u.keks {
		clear(k)
	}
	u.keks = nil
}

// sealBatch is how many webhooks one write job of SealURLs seals at most.
const sealBatch = 100

// afterSealBatch, when set (tests), is told how many rows each batch
// sealed, once its job committed; an error it answers ends the pass there.
var afterSealBatch func(n int) error

// SealURLs seals, under its Organization's KEK, the URL of every webhook
// (revoked ones included) whose row has no envelope, or one that does not
// hold the row's url: an older release that ran after a rollback changed
// url and left the envelope of the URL before. A webhook whose
// Organization's KEK was destroyed is left as it is: no key seals it.
//
// It reads in batches by id, opens and seals outside the writer, then
// writes each batch in one job, every row only while it still holds the
// url and the envelope the pass read (a change made meanwhile is the newer
// one, and already sealed). So a pass cut short (a crash, a stop) leaves
// what it sealed sealed and the rest to the next, and a pass with nothing
// to do writes nothing. An envelope that does not open is left as it is,
// never sealed again from url: the error names it, and the pass goes on.
// sealed is how many rows were written.
func SealURLs(ctx context.Context, w *write.Writer, rootKEK []byte) (sealed int, err error) {
	type pending struct {
		id, url, seen, envelope string
	}
	keks := map[string][]byte{}
	defer func() {
		for _, k := range keks {
			clear(k)
		}
	}()
	var problems []error
	after := ""
	for {
		rows, err := query.New(w.Store.Reader()).WebhookURLsAfter(ctx, query.WebhookURLsAfterParams{After: after, Batch: sealBatch})
		if err != nil {
			return sealed, err
		}
		if len(rows) == 0 {
			break
		}
		after = rows[len(rows)-1].ID
		var batch []pending
		for _, r := range rows {
			if !r.WrappedOrgKek.Valid {
				continue
			}
			kek, ok := keks[r.OrganizationID]
			if !ok {
				if kek, err = unwrapOrgKEK(rootKEK, r.OrganizationID, r.WrappedOrgKek); err != nil {
					problems = append(problems, fmt.Errorf("organization %s: its KEK does not open: %w", r.OrganizationID, err))
					keks[r.OrganizationID] = nil
					continue
				}
				keks[r.OrganizationID] = kek
			}
			if kek == nil {
				continue
			}
			if r.UrlEnvelope.Valid {
				held, err := OpenURL(kek, r.OrganizationID, r.ID, r.UrlEnvelope.String)
				if err != nil {
					problems = append(problems, err)
					continue
				}
				if held == r.Url {
					continue
				}
			}
			text, err := SealURL(kek, r.OrganizationID, r.ID, r.Url)
			if err != nil {
				return sealed, err
			}
			batch = append(batch, pending{id: r.ID, url: r.Url, seen: r.UrlEnvelope.String, envelope: text})
		}
		if len(batch) > 0 {
			n := 0
			if err := w.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
				n = 0
				q := query.New(tx)
				for _, p := range batch {
					written, err := q.SealWebhookURL(ctx, query.SealWebhookURLParams{
						UrlEnvelope: sql.NullString{String: p.envelope, Valid: true}, ID: p.id, Url: p.url,
						Seen: sql.NullString{String: p.seen, Valid: true},
					})
					if err != nil {
						return err
					}
					n += int(written)
				}
				return nil
			}); err != nil {
				return sealed, err
			}
			sealed += n
			if afterSealBatch != nil {
				if err := afterSealBatch(n); err != nil {
					return sealed, err
				}
			}
		}
		if len(rows) < sealBatch {
			break
		}
	}
	return sealed, errors.Join(problems...)
}
