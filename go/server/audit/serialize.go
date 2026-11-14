// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"bytes"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/whatwg"
)

// RedactWebhookURL is redactWebhookUrl (ADR-0029 §7): the URL with its
// userinfo dropped and its path, query and fragment contents replaced, as a
// webhook URL may carry embedded tokens.
func RedactWebhookURL(raw string) string {
	u, ok := whatwg.ParseURL(raw)
	if !ok {
		return "[invalid-url]"
	}
	s := u.Protocol + "//" + u.Host
	if u.Pathname == "/" {
		s += "/"
	} else {
		s += "/[redacted]"
	}
	if u.Search != "" {
		s += "?[redacted]"
	}
	if u.Hash != "" {
		s += "#[redacted]"
	}
	return s
}

// fromJsonb is a stored JSON column as the TypeScript server reads it back:
// node-postgres parses the jsonb text (PostgreSQL's key order, then
// JSON.parse's: integer-like keys first), and parseMaybe parses a string
// result once more. So a column holding a JSON string is decoded twice:
// '"{\"a\":1}"' becomes an object, and a string that is not JSON text is
// an error (the TypeScript server's serializeAuditEvent throws).
func fromJsonb(c sql.NullString) (any, error) {
	if !c.Valid {
		return nil, nil
	}
	v, err := jsvalue.Parse([]byte(c.String))
	if err != nil {
		return nil, err
	}
	v = jsvalue.JSOrder(jsvalue.Jsonb(v))
	if s, ok := v.(string); ok {
		return jsvalue.Parse([]byte(s))
	}
	return v, nil
}

func nullable(c sql.NullString) any {
	if !c.Valid {
		return nil
	}
	return c.String
}

// ISOTime is new Date(t).toISOString() for a time in microseconds since the
// Unix epoch, as the TypeScript server reads a timestamptz (milliseconds,
// the rest truncated).
func ISOTime(micros int64) string {
	ms := micros / 1000
	if micros < 0 && micros%1000 != 0 {
		ms-- // floor, as the parser's millisecond arithmetic gives
	}
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}

// Serialize is serializeAuditEvent: the public wire shape of an audit event
// (ADR-0016, ADR-0018), shared by the audit listing, its export and webhook
// delivery. Historical webhook.* events predate URL redaction, so their
// metadata URLs are redacted here.
func Serialize(r query.AuditEvent) (jsvalue.Object, error) {
	parse := func(name string, c sql.NullString) (any, error) {
		v, err := fromJsonb(c)
		if err != nil {
			return nil, fmt.Errorf("audit: event %s: %s: %w", r.ID, name, err)
		}
		return v, nil
	}
	metadata, err := parse("metadata", r.Metadata)
	if err != nil {
		return nil, err
	}
	resource, err := parse("resource", r.Resource)
	if err != nil {
		return nil, err
	}
	authz, err := parse("authz", r.Authz)
	if err != nil {
		return nil, err
	}
	tailnet, err := parse("tailnet", r.Tailnet)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(r.EventType, "webhook.") {
		metadata = redactWebhookMetadata(metadata)
	}
	return jsvalue.Object{
		{Key: "schemaVersion", Value: r.SchemaVersion},
		{Key: "eventId", Value: r.ID},
		{Key: "eventType", Value: r.EventType},
		{Key: "occurredAt", Value: ISOTime(r.OccurredAt)},
		{Key: "actorIdentityId", Value: nullable(r.ActorIdentityID)},
		{Key: "authenticationMethodId", Value: nullable(r.AuthenticationMethodID)},
		{Key: "credentialId", Value: nullable(r.CredentialID)},
		// The acting request's client, as reported; null before it existed.
		{Key: "client", Value: nullable(r.Client)},
		{Key: "organizationId", Value: nullable(r.OrganizationID)},
		{Key: "action", Value: nullable(r.Action)},
		{Key: "resource", Value: resource},
		{Key: "decision", Value: r.Decision},
		{Key: "authorization", Value: authz},
		{Key: "tailnetContext", Value: tailnet},
		{Key: "listener", Value: nullable(r.Listener)},
		{Key: "requestId", Value: nullable(r.RequestID)},
		{Key: "metadata", Value: metadata},
	}, nil
}

// redactWebhookMetadata is `{ ...metadata }` with url, oldUrl and newUrl
// redacted where they are strings. An array spreads into an object keyed by
// its indexes, as in JavaScript.
func redactWebhookMetadata(v any) any {
	var o jsvalue.Object
	switch x := v.(type) {
	case jsvalue.Object:
		o = append(jsvalue.Object{}, x...)
	case []any:
		for i, e := range x {
			o = append(o, jsvalue.Member{Key: strconv.Itoa(i), Value: e})
		}
	default:
		return v
	}
	for _, k := range []string{"url", "oldUrl", "newUrl"} {
		if s, ok := mustString(o.Get(k)); ok {
			o = o.Set(k, RedactWebhookURL(s))
		}
	}
	return o
}

func mustString(v any, _ bool) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// EventJSON is the event's JSON, as the audit listing's items and webhook
// deliveries hold it.
func EventJSON(r query.AuditEvent) ([]byte, error) {
	o, err := Serialize(r)
	if err != nil {
		return nil, err
	}
	return jsvalue.Stringify(o), nil
}

// ExportLines is the body of the audit export endpoint
// (GET .../audit-events/export): one event per line, each line ending in a
// newline.
func ExportLines(rows []query.AuditEvent) ([]byte, error) {
	var b bytes.Buffer
	for _, r := range rows {
		line, err := EventJSON(r)
		if err != nil {
			return nil, err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

// ExportStreamLine is one event line of an audit export stream's batch
// (domain/auditexport.ts batchPlan): the event with its position first, as
// a string. The line has no newline.
func ExportStreamLine(r query.AuditEvent) ([]byte, error) {
	o, err := Serialize(r)
	if err != nil {
		return nil, err
	}
	return jsvalue.Stringify(append(jsvalue.Object{{Key: "position", Value: strconv.FormatInt(r.EventOrder, 10)}}, o...)), nil
}
