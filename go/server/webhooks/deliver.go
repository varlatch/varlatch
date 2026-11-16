// SPDX-License-Identifier: AGPL-3.0-or-later

package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
)

// SignatureHeader carries "t=<unix-seconds>,v1=<hex HMAC-SHA256>".
const SignatureHeader = "X-Varlatch-Signature"

const (
	// batchSize is DELIVERY_BATCH: the most events one delivery carries.
	batchSize = 100
	// Interval is the delivery loop's (startWebhookLoop's 30 s).
	Interval = 30 * time.Second
)

// deliveryTimeout is DELIVERY_TIMEOUT_MS: one delivery, connection
// included. A variable for tests.
var deliveryTimeout = 10 * time.Second

// deletionEvents are the deletion lifecycle's events: never delivered
// (ADR-0051 Decision 9), they are in the audit log, and in the tombstone
// export afterwards.
var deletionEvents = map[string]bool{
	"organization.deletion_scheduled": true,
	"organization.deletion_approved":  true,
	"organization.deletion_cancelled": true,
	"organization.deleted":            true,
	"audit_tombstone.reader_removed":  true,
}

// Sign is signWebhookBody: hex HMAC-SHA256 over "<seconds>.<body>".
func Sign(secret string, seconds int64, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(m, "%d.", seconds)
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// DeliverOnce is deliverWebhooksOnce: one pass over every active webhook
// of a live Organization. Each advances its cursor only after a 2xx
// answer, so a failure retries the same batch on the next pass (at least
// once). A failure never ends the pass: it is recorded on the row and
// logged.
func (s *Service) DeliverOnce(ctx context.Context) error {
	hooks, err := query.New(s.store().Reader()).DeliverableWebhooks(ctx)
	if err != nil {
		return err
	}
	for _, h := range hooks {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.deliverOne(ctx, h); err != nil && ctx.Err() == nil {
			s.log().Error("webhook delivery failed", "webhook", h.ID, "error", err)
		}
	}
	return ctx.Err()
}

// resourceIDs are the projectId and environmentId an event's resource
// names, as strings.
func resourceIDs(r query.AuditEvent) (project, environment string, err error) {
	if !r.Resource.Valid {
		return "", "", nil
	}
	v, err := jsvalue.Parse([]byte(r.Resource.String))
	if err != nil {
		return "", "", err
	}
	if s, ok := v.(string); ok {
		if v, err = jsvalue.Parse([]byte(s)); err != nil {
			return "", "", err
		}
	}
	o, _ := v.(jsvalue.Object)
	p, _ := o.Get("projectId")
	e, _ := o.Get("environmentId")
	project, _ = p.(string)
	environment, _ = e.(string)
	return project, environment, nil
}

// withoutDeletedProjects is withoutDeletedProjects: the events of a batch
// that name no deleted Project, directly or through one of its
// environments (ADR-0051 Decision 3), and none of the deletion
// lifecycle's.
func withoutDeletedProjects(ctx context.Context, db query.DBTX, batch []query.AuditEvent) ([]query.AuditEvent, error) {
	projects, envs := []any{}, []any{}
	seenP, seenE := map[string]bool{}, map[string]bool{}
	for _, r := range batch {
		p, e, err := resourceIDs(r)
		if err != nil {
			return nil, err
		}
		if p != "" && !seenP[p] {
			seenP[p] = true
			projects = append(projects, p)
		}
		if e != "" && !seenE[e] {
			seenE[e] = true
			envs = append(envs, e)
		}
	}
	goneP, goneE := map[string]bool{}, map[string]bool{}
	if len(projects)+len(envs) > 0 {
		rows, err := query.New(db).DeletedProjectsAmong(ctx, query.DeletedProjectsAmongParams{
			ProjectIds: string(jsvalue.Stringify(projects)), EnvironmentIds: string(jsvalue.Stringify(envs)),
		})
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			goneP[r.ProjectID] = true
			if r.EnvironmentID.Valid {
				goneE[r.EnvironmentID.String] = true
			}
		}
	}
	out := make([]query.AuditEvent, 0, len(batch))
	for _, r := range batch {
		if deletionEvents[r.EventType] {
			continue
		}
		if len(goneP) > 0 {
			p, e, _ := resourceIDs(r)
			if goneP[p] || goneE[e] {
				continue
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// requestURL is the URL as fetch sends it: parsed and serialized as
// `new URL` does (the host the outbound check decided, not one Go's parser
// reads differently), the path and query exactly as fetch writes them,
// no fragment.
//
// The path goes out as written through Opaque, except one that starts with
// "//": net/url sends an Opaque of that form as an absolute URL
// ("http://x/y" for the path //x/y). That one goes through Path and
// RawPath, which net/url sends as written when it can; a path it would
// write otherwise (a "|", which it escapes, or a stray "%") then differs
// from fetch's in those characters only.
func requestURL(raw string) (*url.URL, bool) {
	u, ok := whatwg.ParseURL(raw)
	if !ok || u.Username != "" || u.Password != "" {
		return nil, false
	}
	path, q := u.RequestTarget()
	out := &url.URL{Scheme: u.Protocol[:len(u.Protocol)-1], Host: u.Host, RawQuery: q}
	if !strings.HasPrefix(path, "//") {
		out.Opaque = path
		return out, true
	}
	if decoded, err := url.PathUnescape(path); err == nil {
		out.Path, out.RawPath = decoded, path
	} else {
		out.Path = path
	}
	return out, true
}

// deliverOne is deliverOne: the next batch after the cursor, filtered;
// eligibility again right before sending; then one signed POST through
// the outbound policy, and its outcome on the row.
func (s *Service) deliverOne(ctx context.Context, h query.DeliverableWebhooksRow) error {
	reader := s.store().Reader()
	types, err := parseEventTypes(h.EventTypes)
	if err != nil {
		return err
	}
	var filter any
	if len(types) > 0 {
		filter = string(jsvalue.Stringify(eventTypesJS(types)))
	}
	batch, err := query.New(reader).WebhookEvents(ctx, query.WebhookEventsParams{
		OrganizationID: sql.NullString{String: h.OrganizationID, Valid: true}, After: h.CursorOrder, EventTypes: filter, Batch: batchSize,
	})
	if err != nil || len(batch) == 0 {
		return err
	}
	last := batch[len(batch)-1]
	rows, err := withoutDeletedProjects(ctx, reader, batch)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return s.Writer.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
			return query.New(tx).SkipWebhookEvents(ctx, query.SkipWebhookEventsParams{EventOrder: last.EventOrder, EventID: last.ID, ID: h.ID})
		})
	}

	// Eligibility again, right before sending (ADR-0051 Decision 9): a
	// deletion scheduled or completed since the pass started suspends or
	// removes the webhook, and the KEK is read afresh (gone once
	// destroyed). A request already sent before that may still arrive.
	wrapped, err := query.New(reader).WebhookStillDeliverable(ctx, h.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	kek, err := s.orgKEK(h.OrganizationID, wrapped)
	if err != nil {
		return err
	}
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(h.SecretEnvelope), &env); err != nil {
		return err
	}
	secret, err := envelope.Open(kek, env, envelope.WebhookSecretContext(h.OrganizationID, h.ID))
	if err != nil {
		return err
	}
	events := make([]any, len(rows))
	for i, r := range rows {
		if events[i], err = audit.Serialize(r); err != nil {
			return err
		}
	}
	body := jsvalue.Stringify(jsvalue.Object{{Key: "webhookId", Value: h.ID}, {Key: "organizationId", Value: h.OrganizationID}, {Key: "events", Value: events}})
	seconds := s.now().Unix()
	status, ok := s.post(ctx, h, body, "t="+strconv.FormatInt(seconds, 10)+",v1="+Sign(string(secret), seconds, body))
	if ctx.Err() != nil {
		// Stopping: the attempt is not recorded, and the next start
		// retries it, as a restart of the TypeScript server does.
		return ctx.Err()
	}
	at := sql.NullInt64{Int64: s.now().UnixMicro(), Valid: true}
	return s.Writer.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
		q := query.New(tx)
		if ok {
			return q.WebhookDelivered(ctx, query.WebhookDeliveredParams{EventOrder: last.EventOrder, EventID: last.ID, AttemptAt: at,
				Status: sql.NullString{String: status, Valid: true}, ID: h.ID})
		}
		return q.WebhookFailed(ctx, query.WebhookFailedParams{AttemptAt: at, Status: sql.NullString{String: status, Valid: true}, ID: h.ID})
	})
}

// post sends one delivery, never following a redirect, and answers the
// status to store and whether it was a 2xx. As the TypeScript server
// stores them: the status code; a refusal by the outbound policy as
// outbound_refused (recorded within the rate bound; the cursor stays, and
// the events go out once the host allows the destination); the
// delivery's own deadline as TimeoutError (fetch's AbortSignal.timeout);
// any other failure as TypeError (fetch's network error), the dialer's
// connect timeout included, as undici reports it.
func (s *Service) post(ctx context.Context, h query.DeliverableWebhooksRow, body []byte, signature string) (string, bool) {
	target, valid := requestURL(h.Url)
	if !valid {
		return "TypeError", false
	}
	ctx, cancel := context.WithTimeout(ctx, deliveryTimeout)
	defer cancel()
	origin := url.URL{Scheme: target.Scheme, Host: target.Host}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin.String(), bytes.NewReader(body))
	if err != nil {
		return "TypeError", false
	}
	req.URL = target
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(SignatureHeader, signature)
	client := s.client
	if client == nil {
		client = s.Policy.Client(outbound.Webhook)
	}
	res, err := client.Do(req)
	if err != nil {
		if refusal := outbound.RefusalOf(err); refusal != nil {
			if rerr := s.Policy.RecordRefusal(context.WithoutCancel(ctx), s.store(), outbound.RefusalRecord{
				OrganizationID: h.OrganizationID, Purpose: outbound.Webhook, Phase: "connection", Refusal: refusal,
				Resource: jsvalue.Object{{Key: "webhookId", Value: h.ID}},
			}); rerr != nil {
				s.log().Error("outbound refusal audit failed", "error", rerr)
			}
			return outbound.LastStatusRefused, false
		}
		// The delivery's own deadline is fetch's AbortSignal.timeout; the
		// dialer's connect timeout (undici's) is a network error.
		if errors.Is(err, context.DeadlineExceeded) && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "TimeoutError", false
		}
		return "TypeError", false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	res.Body.Close()
	return strconv.Itoa(res.StatusCode), res.StatusCode >= 200 && res.StatusCode < 300
}

// RunLoop is startWebhookLoop: a pass at once, then one every interval,
// until ctx ends. Each pass enters the maintenance admission (admit, nil
// for none): while a gate is open the pass is skipped, and one admitted is
// counted until it ends, so a gate's drain waits for it. A pass that fails
// is logged; the next runs as planned.
func (s *Service) RunLoop(ctx context.Context, interval time.Duration, admit func() (leave func(), ok bool)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.pass(ctx, admit)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) pass(ctx context.Context, admit func() (func(), bool)) {
	if admit != nil {
		leave, ok := admit()
		if !ok {
			return
		}
		defer leave()
	}
	if err := s.DeliverOnce(ctx); err != nil && ctx.Err() == nil {
		s.log().Error("webhook loop error", "error", err)
	}
}
