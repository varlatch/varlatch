// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
)

// Where refused outbound destinations are visible (ADR-0057 Decision 8;
// domain/refuseddestinations.ts), beyond the operator's terminal: the
// installation page, for Installation Admins, and each Organization's
// Security page, for its admins. Both run the configured destinations
// check with the policy varlatchd started with (DNS lookups only, never a
// request), its scans shared while running and reused for 30 seconds.
// What they answer never holds a resolved address, a path, a query or a
// credential.

const (
	getInstallationOutboundPattern = "GET /v1/installation/outbound"
	refusedDestinationsPattern     = "GET /v1/organizations/{org}/security/refused-destinations"
)

// refusedSinceDays is how far back `since` looks in the audit log.
const refusedSinceDays = 30

func (r reply) VisitGetInstallationOutboundResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitRefusedDestinationsResponse(w http.ResponseWriter) error     { return r.visit(w) }

// policy is the server's outbound policy, or the strict one (nothing
// beyond public https).
func (o *operations) policy() *outbound.Policy {
	if o.s.opts.Outbound != nil {
		return o.s.opts.Outbound
	}
	return strictPolicy
}

var strictPolicy = outbound.New(nil, outbound.Options{})

func (o *operations) clock() func() time.Time {
	if o.s.opts.Now != nil {
		return o.s.opts.Now
	}
	return time.Now
}

func nullable(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// GetInstallationOutbound is installationOutbound: the allow list as
// parsed, doctor's warnings about it, every refused destination by
// Organization, and the value that would allow the refused names.
func (o *operations) GetInstallationOutbound(ctx context.Context, _ api.GetInstallationOutboundRequestObject) (api.GetInstallationOutboundResponseObject, error) {
	if err := installationAdmin(ctx); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	p := o.policy()
	reader := o.s.opts.Auth.Store().Reader()
	report, err := p.SharedCheck(ctx, reader, "", o.clock())
	if err != nil {
		return nil, err
	}
	// By Organization; within one, in the check's order.
	refused := report.Refused()
	slices.SortStableFunc(refused, func(a, b outbound.RefusedView) int { return strings.Compare(a.Organization, b.Organization) })
	type org struct{ slug, name string }
	orgs := map[string]org{}
	var ids []any
	for _, d := range refused {
		if _, seen := orgs[d.OrganizationID]; !seen {
			orgs[d.OrganizationID] = org{}
			ids = append(ids, d.OrganizationID)
		}
	}
	if len(ids) > 0 {
		rows, err := reader.QueryContext(ctx, "SELECT id, slug, name FROM organizations WHERE id IN (?"+strings.Repeat(",?", len(ids)-1)+")", ids...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var g org
			if err := rows.Scan(&id, &g.slug, &g.name); err != nil {
				rows.Close()
				return nil, err
			}
			orgs[id] = g
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	items := []any{}
	for _, d := range refused {
		g := orgs[d.OrganizationID]
		if g.slug == "" {
			g = org{d.Organization, d.Organization}
		}
		items = append(items, jsvalue.Object{
			{Key: "organization", Value: jsvalue.Object{{Key: "id", Value: d.OrganizationID}, {Key: "slug", Value: g.slug}, {Key: "name", Value: g.name}}},
			{Key: "kind", Value: string(d.Kind)}, {Key: "id", Value: d.ID}, {Key: "name", Value: nullable(d.Name)},
			{Key: "scheme", Value: d.Scheme}, {Key: "host", Value: d.Host}, {Key: "port", Value: float64(d.Port)},
			{Key: "reason", Value: string(d.Reason)}, {Key: "notSuggested", Value: nullable(d.NotSuggested)},
		})
	}
	allow, warnings := []any{}, []any{}
	for _, a := range report.Allow {
		allow = append(allow, a)
	}
	for _, w := range outbound.Warnings(p.Entries) {
		warnings = append(warnings, w)
	}
	return ok(jsvalue.Object{
		{Key: "generatedAt", Value: report.CheckedAt}, {Key: "allow", Value: allow}, {Key: "checked", Value: float64(len(report.Destinations))},
		{Key: "warnings", Value: warnings}, {Key: "refused", Value: items}, {Key: "suggested", Value: nullable(report.Suggested)},
		{Key: "unresolved", Value: float64(countVerdict(report.Destinations, "unresolved"))},
	}), nil
}

func countVerdict(ds []outbound.Checked, verdict string) int {
	n := 0
	for _, d := range ds {
		if d.Verdict == verdict {
			n++
		}
	}
	return n
}

// RefusedDestinations is organizationRefusedDestinations: the
// Organization's configured destinations the policy refuses, each with
// when its first refusal in the last 30 days was recorded. Inspection
// while frozen; organization.manage; never cached; never the allow list.
func (o *operations) RefusedDestinations(ctx context.Context, _ api.RefusedDestinationsRequestObject) (api.RefusedDestinationsResponseObject, error) {
	q, err := o.enterRoute(ctx, securityRoute+"refused-destinations", authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.manage"); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	reader := o.s.opts.Auth.Store().Reader()
	report, err := o.policy().SharedCheck(ctx, reader, q.org.ID, o.clock())
	if err != nil {
		return nil, err
	}
	// The check's filter also matches a slug: only this Organization's rows.
	var own []outbound.Checked
	for _, d := range report.Destinations {
		if d.OrganizationID == q.org.ID {
			own = append(own, d)
		}
	}
	var refused []outbound.RefusedView
	for _, d := range report.Refused() {
		if d.OrganizationID == q.org.ID {
			refused = append(refused, d)
		}
	}
	since := map[string]string{}
	if len(refused) > 0 {
		args := []any{q.org.ID, o.clock()().Add(-refusedSinceDays * 24 * time.Hour).UnixMicro()}
		for _, d := range refused {
			args = append(args, d.ID)
		}
		rows, err := reader.QueryContext(ctx, `SELECT object_id, host, port, min(occurred_at) FROM (
			SELECT coalesce(json_extract(resource, '$.webhookId'), json_extract(resource, '$.connectionId'), json_extract(resource, '$.oidcBindingId')) AS object_id,
				json_extract(metadata, '$.host') AS host, json_extract(metadata, '$.port') AS port, occurred_at
			FROM audit_events WHERE organization_id = ? AND event_type = 'outbound.refused' AND occurred_at >= ?)
			WHERE object_id IN (?`+strings.Repeat(",?", len(refused)-1)+`) GROUP BY 1, 2, 3`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, host, port *string
			var at int64
			if err := rows.Scan(&id, &host, &port, &at); err != nil {
				rows.Close()
				return nil, err
			}
			since[fmt.Sprintf("%s|%s|%s", deref(id), deref(host), deref(port))] = audit.ISOTime(at)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	items := []any{}
	for _, d := range refused {
		var s any
		if v, ok := since[fmt.Sprintf("%s|%s|%d", d.ID, d.Host, d.Port)]; ok {
			s = v
		}
		items = append(items, jsvalue.Object{
			{Key: "kind", Value: string(d.Kind)}, {Key: "id", Value: d.ID}, {Key: "name", Value: nullable(d.Name)},
			{Key: "scheme", Value: d.Scheme}, {Key: "host", Value: d.Host}, {Key: "port", Value: float64(d.Port)},
			{Key: "reason", Value: string(d.Reason)}, {Key: "since", Value: s},
		})
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{
		{Key: "generatedAt", Value: report.CheckedAt}, {Key: "sinceDays", Value: float64(refusedSinceDays)},
		{Key: "checked", Value: float64(len(own))}, {Key: "unresolved", Value: float64(countVerdict(own, "unresolved"))},
		{Key: "items", Value: items},
	}), nil
}

func deref(s *string) string {
	if s == nil {
		return "null"
	}
	return *s
}
