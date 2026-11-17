// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/pgtime"
)

// The audit log's reads (ADR-0016; ADR-0059 step 4.3c): listAuditEvents
// and exportAuditEvents, as http/app.ts serves them. Each runs under the
// incident freeze's audit exception and needs audit.read; the filters
// (capability audit.filters, audit.ParseFilters) only add conditions.

const (
	listAuditEventsPattern   = "GET /v1/organizations/{org}/audit-events"
	exportAuditEventsPattern = "GET /v1/organizations/{org}/audit-events/export"
	auditEventsRoute         = "/v1/organizations/:org/audit-events"
	auditExportRoute         = "/v1/organizations/:org/audit-events/export"
	// auditExportBatch is the export stream's rows per read.
	auditExportBatch = 250
)

func init() {
	for _, p := range []string{listAuditEventsPattern, exportAuditEventsPattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitListAuditEventsResponse(w http.ResponseWriter) error { return r.visit(w) }

// auditFilters reads the request's filter parameters (c.req.queries).
func auditFilters(ctx context.Context) (audit.Filters, error) {
	q := rawOf(ctx).query
	return audit.ParseFilters(func(name string) []string { return q[name] })
}

// pgTimestamptzText is occurred_at::text in a UTC session: PostgreSQL's
// text form of a timestamptz, its fraction without trailing zeros.
func pgTimestamptzText(micros int64) string {
	t := time.UnixMicro(micros).UTC()
	s := t.Format("2006-01-02 15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += strings.TrimRight(fmt.Sprintf(".%06d", us), "0")
	}
	return s + "+00"
}

// cursorTime is $3::timestamptz for a cursor's time, read as PostgreSQL
// reads it (pgtime) when the page is read: any form its timestamptz input
// takes, now and today at the time of the query, and infinity after
// every event; the text it refuses fails the request as PostgreSQL's
// error does the TypeScript server's.
func (o *operations) cursorTime(s string) (int64, error) {
	t, err := pgtime.Parse(s, o.s.opts.Now(), o.s.opts.Zones)
	if err != nil {
		return 0, fmt.Errorf("audit cursor: %w", err)
	}
	return t.UnixMicro(), nil
}

// auditLimit is Math.max(1, Math.min(Math.floor(Number(limit ?? 100)) ||
// 100, 500)).
func auditLimit(raw []string) int {
	if len(raw) == 0 {
		return 100
	}
	f := math.Floor(jsvalue.ToNumber(raw[0]))
	if f == 0 || math.IsNaN(f) {
		f = 100
	}
	return int(max(1, min(f, 500)))
}

func scanAuditEvents(rows *sql.Rows) ([]query.AuditEvent, error) {
	defer rows.Close()
	var out []query.AuditEvent
	for rows.Next() {
		var e query.AuditEvent
		if err := rows.Scan(&e.EventOrder, &e.ID, &e.SchemaVersion, &e.EventType, &e.OccurredAt, &e.ActorIdentityID,
			&e.AuthenticationMethodID, &e.CredentialID, &e.OrganizationID, &e.Action, &e.Resource, &e.Decision, &e.Authz,
			&e.Tailnet, &e.Listener, &e.RequestID, &e.Metadata, &e.Client); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const auditEventColumns = `event_order, id, schema_version, event_type, occurred_at, actor_identity_id, authentication_method_id,
	credential_id, organization_id, action, resource, decision, authz, tailnet, listener, request_id, metadata, client`

// ListAuditEvents is GET …/audit-events: the audit exception,
// audit.read; a page of events, newest first, by (occurredAt, eventId),
// limit 1 to 500 (100 by default), after a cursor, narrowed by the
// filters, and the credentials the page's events name (name, kind,
// client; never token material).
func (o *operations) ListAuditEvents(ctx context.Context, _ api.ListAuditEventsRequestObject) (api.ListAuditEventsResponseObject, error) {
	q, err := o.enterRoute(ctx, auditEventsRoute, authz.DuringFreezeAudit)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "audit.read"); err != nil {
		return nil, err
	}
	raw := rawOf(ctx).query
	limit := auditLimit(raw["limit"])
	var decoded []string
	if c, present := raw["cursor"]; present && c[0] != "" {
		if decoded = decodeCursor(c[0]); decoded == nil {
			return nil, domainerr.New("VALIDATION_FAILED", "Invalid cursor")
		}
	}
	filters, err := auditFilters(ctx)
	if err != nil {
		return nil, err
	}
	where := []string{"organization_id = ?"}
	args := []any{q.org.ID}
	if decoded != nil {
		// Read by PostgreSQL once the filters were checked.
		conds, more, err := o.cursorConditions(decoded)
		if err != nil {
			return nil, err
		}
		where, args = append(where, conds...), append(args, more...)
	}
	conds, more := filters.Conditions()
	where = append(where, conds...)
	args = append(args, more...)
	args = append(args, limit+1)
	reader := o.s.opts.Auth.Store().Reader()
	rows, err := reader.QueryContext(ctx, "SELECT "+auditEventColumns+" FROM audit_events WHERE "+strings.Join(where, " AND ")+
		" ORDER BY occurred_at DESC, id DESC LIMIT ?", args...)
	if err != nil {
		return nil, err
	}
	events, err := scanAuditEvents(rows)
	if err != nil {
		return nil, err
	}
	page := events[:min(len(events), limit)]
	var next any
	if len(events) > limit && len(page) > 0 {
		last := page[len(page)-1]
		next = encodeCursor([]string{pgTimestamptzText(last.OccurredAt), last.ID})
	}
	items := make([]any, 0, len(page))
	var credentialIDs []any
	seen := map[string]bool{}
	for _, e := range page {
		o, err := audit.Serialize(e)
		if err != nil {
			return nil, err
		}
		items = append(items, o)
		if e.CredentialID.Valid && !seen[e.CredentialID.String] {
			seen[e.CredentialID.String] = true
			credentialIDs = append(credentialIDs, e.CredentialID.String)
		}
	}
	credentials := jsvalue.Object{}
	if len(credentialIDs) > 0 {
		// In the table's order, as PostgreSQL's ANY() without ORDER BY gives
		// the rows of a table nothing was deleted from.
		rows, err := reader.QueryContext(ctx, "SELECT id, name, kind, client FROM credentials WHERE id IN (?"+strings.Repeat(", ?", len(credentialIDs)-1)+") ORDER BY rowid", credentialIDs...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var id, kind string
			var name, client sql.NullString
			if err := rows.Scan(&id, &name, &kind, &client); err != nil {
				return nil, err
			}
			credentials = append(credentials, jsvalue.Member{Key: id, Value: jsvalue.Object{
				{Key: "name", Value: nullString(name)}, {Key: "kind", Value: kind}, {Key: "client", Value: nullString(client)},
			}})
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "items", Value: items}, {Key: "nextCursor", Value: next}, {Key: "credentials", Value: credentials}}), nil
}

func nullString(s sql.NullString) any {
	if !s.Valid {
		return nil
	}
	return s.String
}

// ndjsonReply streams an audit export: Content-Type application/x-ndjson,
// never cached, one event per line, read a batch at a time.
type ndjsonReply struct {
	stream func(w http.ResponseWriter) error
}

func (r ndjsonReply) VisitExportAuditEventsResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	return r.stream(w)
}

// ExportAuditEvents is GET …/audit-events/export: the audit exception,
// audit.read, the filters validated before the stream starts, the
// passkey-verification checkpoint before it reads, then NDJSON in audit
// order up to the high-water mark when the export starts, a batch of 250
// at a time.
func (o *operations) ExportAuditEvents(ctx context.Context, _ api.ExportAuditEventsRequestObject) (api.ExportAuditEventsResponseObject, error) {
	q, err := o.enterRoute(ctx, auditExportRoute, authz.DuringFreezeAudit)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "audit.read"); err != nil {
		return nil, err
	}
	filters, err := auditFilters(ctx)
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return o.auditExportStream(ctx, q.org.ID, filters)
}

// auditExportStream is auditExport: an Organization's events as NDJSON, in
// audit order up to the high-water mark when the export starts, narrowed
// by the filters (none for a deleted Organization's), a batch at a time.
func (o *operations) auditExportStream(ctx context.Context, org string, filters audit.Filters) (ndjsonReply, error) {
	reader := o.s.opts.Auth.Store().Reader()
	var upper int64
	if err := reader.QueryRowContext(ctx, "SELECT coalesce(max(event_order), 0) FROM audit_events WHERE organization_id = ?", org).Scan(&upper); err != nil {
		return ndjsonReply{}, err
	}
	return ndjsonReply{stream: func(w http.ResponseWriter) error {
		flusher, _ := w.(http.Flusher)
		for cursor := int64(0); ; {
			where := []string{"organization_id = ? AND event_order > ? AND event_order <= ?"}
			args := []any{org, cursor, upper}
			conds, more := filters.Conditions()
			where = append(where, conds...)
			args = append(args, more...)
			rows, err := reader.QueryContext(ctx, "SELECT "+auditEventColumns+" FROM audit_events WHERE "+strings.Join(where, " AND ")+
				" ORDER BY event_order LIMIT "+strconv.Itoa(auditExportBatch), args...)
			if err != nil {
				return err
			}
			batch, err := scanAuditEvents(rows)
			if err != nil {
				return err
			}
			if len(batch) == 0 {
				return nil
			}
			lines, err := audit.ExportLines(batch)
			if err != nil {
				return err
			}
			if _, err := w.Write(lines); err != nil {
				return err
			}
			if flusher != nil {
				flusher.Flush()
			}
			cursor = batch[len(batch)-1].EventOrder
		}
	}}, nil
}
