// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/server/domainerr"
)

// Server-side audit filters (capability audit.filters, ADR-0016 §10;
// audit/filters.ts). Every filter narrows the events an audit.read caller
// already sees; none widens or changes authorization. Filters are ANDed
// and only add WHERE clauses, so the listing's (occurredAt, eventId)
// order, and with it every cursor, means the same with or without them.

// Filters is AuditFilters. An empty field is no filter.
type Filters struct {
	Decision string
	// EventType is an exact event type, or with EventTypePrefix a prefix
	// ending in a dot ("value." for value.*).
	EventType       string
	EventTypePrefix bool
	ActorIdentityID string
	// Actor "varlatch": Varlatch's own events, recorded with no actor, but
	// not a failed authentication (authentication.*), which has no actor
	// either.
	Actor                  string
	ProjectID, Environment string
	Item                   string
	// Since (inclusive) and Until (exclusive), in microseconds as
	// PostgreSQL reads the RFC 3339 text; nil for none.
	Since, Until *int64
}

// FilterParams is AUDIT_FILTER_PARAMS.
var FilterParams = []string{"decision", "eventType", "actorIdentityId", "actor", "projectId", "environmentId", "item", "since", "until"}

var (
	eventTypePattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,200}$`)
	itemNamePattern   = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	rfc3339Pattern    = regexp.MustCompile(`(?i)^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|([+-])(\d{2}):(\d{2}))$`)
)

func invalid(message string) error { return domainerr.New("VALIDATION_FAILED", message) }

// timestamp is timestamp: the microseconds PostgreSQL makes of the text
// (the fraction rounded to microseconds, half to even, the offset
// applied), and the milliseconds JavaScript compares since and until in.
func timestamp(name, raw string) (micros, ms int64, err error) {
	m := rfc3339Pattern.FindStringSubmatch(raw)
	n := func(i int) int { v, _ := strconv.Atoi(m[i]); return v }
	valid := m != nil
	if valid {
		y, mo, d, h, mi, s := n(1), n(2), n(3), n(4), n(5), n(6)
		date := time.Date(y, time.Month(mo), d, 0, 0, 0, 0, time.UTC)
		valid = y >= 1 && mo >= 1 && mo <= 12 && int(date.Month()) == mo && date.Day() == d && h <= 23 && mi <= 59 && s <= 59 &&
			(m[9] == "" || n(10) <= 23 && n(11) <= 59)
	}
	if !valid {
		return 0, 0, invalid(name + " must be an RFC 3339 timestamp with a time zone, such as 2026-10-01T00:00:00Z")
	}
	t := time.Date(n(1), time.Month(n(2)), n(3), n(4), n(5), n(6), 0, time.UTC)
	offset := int64(0)
	if m[9] != "" {
		offset = int64(n(10)*60+n(11)) * 60
		if m[9] == "-" {
			offset = -offset
		}
	}
	var frac float64
	if m[7] != "" {
		frac, _ = strconv.ParseFloat("0"+m[7], 64)
	}
	base := t.Unix() - offset
	return base*1_000_000 + int64(math.RoundToEven(frac*1_000_000)), base*1000 + int64(math.Floor(frac*1000)), nil
}

// ParseFilters is parseAuditFilters: values(name) returns every value
// given for a query parameter; a filter given twice, or empty, is refused.
func ParseFilters(values func(name string) []string) (Filters, error) {
	var f Filters
	var bad error
	one := func(name string) (string, bool) {
		all := values(name)
		if bad != nil || len(all) == 0 {
			return "", false
		}
		if len(all) > 1 {
			bad = invalid(name + " may be given only once")
			return "", false
		}
		if all[0] == "" {
			bad = invalid(name + " must not be empty")
			return "", false
		}
		return all[0], true
	}
	if v, ok := one("decision"); ok {
		if v != Allow && v != Deny && v != Info {
			return f, invalid("decision must be allow, deny, or info")
		}
		f.Decision = v
	}
	if v, ok := one("eventType"); ok {
		name, prefix := strings.CutSuffix(v, ".*")
		// The patterns are ASCII: a string that matches has as many bytes as
		// JavaScript counts characters.
		if len(name) > 200 || !eventTypePattern.MatchString(name) {
			return f, invalid("eventType must be an event type, such as value.written, or a prefix ending in .*, such as value.*")
		}
		if prefix {
			f.EventType, f.EventTypePrefix = name+".", true
		} else {
			f.EventType = v
		}
	}
	for _, p := range []struct {
		name string
		dst  *string
	}{{"actorIdentityId", &f.ActorIdentityID}, {"projectId", &f.ProjectID}, {"environmentId", &f.Environment}} {
		if v, ok := one(p.name); ok {
			if !identifierPattern.MatchString(v) {
				return f, invalid(p.name + " must be an ID")
			}
			*p.dst = v
		}
	}
	if v, ok := one("actor"); ok {
		if v != "varlatch" {
			return f, invalid("actor must be varlatch, for Varlatch's own events; filter by an identity with actorIdentityId")
		}
		if f.ActorIdentityID != "" {
			return f, invalid("actor and actorIdentityId cannot be combined: give one of them")
		}
		f.Actor = v
	}
	if v, ok := one("item"); ok {
		if len(v) > 200 || !itemNamePattern.MatchString(v) {
			return f, invalid("item must be a Config Item name, such as DATABASE_URL")
		}
		f.Item = v
	}
	since, hasSince := one("since")
	until, hasUntil := one("until")
	if bad != nil {
		return f, bad
	}
	var fromMS, toMS int64
	if hasSince {
		micros, ms, err := timestamp("since", since)
		if err != nil {
			return f, err
		}
		f.Since, fromMS = &micros, ms
	}
	if hasUntil {
		micros, ms, err := timestamp("until", until)
		if err != nil {
			return f, err
		}
		f.Until, toMS = &micros, ms
	}
	if hasSince && hasUntil && toMS < fromMS {
		return f, invalid("until must not be before since")
	}
	return f, nil
}

// Conditions is auditFilterConditions over SQLite's audit_events: the
// conditions, ANDed, and their arguments in order. An item matches an
// event that names it in its resource (itemName) or lists it in its
// metadata's items ("NAME" or "NAME@version" entries, comma-separated);
// an item name holds neither a comma nor an @, so the match is exact.
func (f Filters) Conditions() ([]string, []any) {
	var conds []string
	var args []any
	add := func(cond string, a ...any) {
		conds = append(conds, cond)
		args = append(args, a...)
	}
	if f.Decision != "" {
		add("decision = ?", f.Decision)
	}
	if f.EventType != "" {
		if f.EventTypePrefix {
			add("substr(event_type, 1, ?) = ?", len(f.EventType), f.EventType)
		} else {
			add("event_type = ?", f.EventType)
		}
	}
	if f.ActorIdentityID != "" {
		add("actor_identity_id = ?", f.ActorIdentityID)
	}
	if f.Actor == "varlatch" {
		// Nor what somebody unknown did with an entry link (ADR-0063).
		add("(actor_identity_id IS NULL AND substr(event_type, 1, 15) <> 'authentication.' AND json_extract(resource, '$.entryLinkId') IS NULL AND json_extract(metadata, '$.entryLinkId') IS NULL)")
	}
	if f.ProjectID != "" {
		add("json_extract(resource, '$.projectId') = ?", f.ProjectID)
	}
	if f.Environment != "" {
		add("json_extract(resource, '$.environmentId') = ?", f.Environment)
	}
	if f.Item != "" {
		add(`(json_extract(resource, '$.itemName') = ?
			OR instr(',' || json_extract(metadata, '$.items') || ',', ',' || ? || ',') > 0
			OR instr(',' || json_extract(metadata, '$.items'), ',' || ? || '@') > 0)`, f.Item, f.Item, f.Item)
	}
	if f.Since != nil {
		add("occurred_at >= ?", *f.Since)
	}
	if f.Until != nil {
		add("occurred_at < ?", *f.Until)
	}
	return conds, args
}
