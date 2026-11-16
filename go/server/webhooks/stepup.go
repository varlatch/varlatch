// SPDX-License-Identifier: AGPL-3.0-or-later

package webhooks

import (
	"slices"
	"unicode/utf16"

	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
)

// admin-step-up for webhooks (ADR-0054 Decision 5;
// domain/integrationstepup.ts' webhook part): what an approval binds and
// the summary its approver reads. The URL is secret-bearing input (it may
// carry a token in its path or query): the full URL is in the bound body,
// so the keyed hash the intent stores covers it, and the summary shows it
// redacted as its audit events do. The signing secret is the server's and
// never bound. Each binds the query {}.
//
//   - webhook.create: target the Organization; body url (full) and
//     eventTypes (a set; null when left out: every event); no version.
//   - webhook.update: target the webhook; body the resulting url and
//     eventTypes; the version the request expects. A patch that changes
//     neither (a reordering of the event types included) needs none.
//   - webhook.delete: target the webhook; no body; the version the server
//     reads, checked again in the job.

// Ref is a live webhook as a binding reads it (WebhookRef).
type Ref struct {
	ID, URL    string
	EventTypes []string // nil: every event
	Version    int64
}

// jsLess is JavaScript's a < b on strings: by UTF-16 code units.
func jsLess(a, b string) int {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

// boundEventTypes is boundEventTypes: the filter as a set (without
// duplicates, in JavaScript's default order), or nil for every event.
func boundEventTypes(eventTypes []string) []string {
	if eventTypes == nil {
		return nil
	}
	out := []string{}
	for _, t := range eventTypes {
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	slices.SortFunc(out, jsLess)
	return out
}

// boundJS is a bound filter as the body holds it.
func boundJS(set []string) any {
	if set == nil {
		return nil
	}
	out := make([]any, len(set))
	for i, t := range set {
		out[i] = t
	}
	return out
}

func eventWords(set []string) string {
	if set == nil {
		return "every event"
	}
	return "event types " + security.QuotedList(set)
}

// Same is sameWebhook: the same URL and the same set of event types.
func Same(aURL string, aTypes []string, bURL string, bTypes []string) bool {
	if aURL != bURL {
		return false
	}
	a, b := boundEventTypes(aTypes), boundEventTypes(bTypes)
	return (a == nil) == (b == nil) && slices.Equal(a, b)
}

func label(r Ref) string { return security.LabelWithID("webhook", audit.RedactWebhookURL(r.URL), r.ID) }

func added(field, to string) auth.ApprovalChange { return auth.ApprovalChange{Field: field, To: &to} }

func change(field, from, to string) auth.ApprovalChange {
	return auth.ApprovalChange{Field: field, From: &from, To: &to}
}

// createBinding is webhookCreateBinding.
func createBinding(organizationID, organizationName, url string, eventTypes []string) *auth.Binding {
	set := boundEventTypes(eventTypes)
	redacted := audit.RedactWebhookURL(url)
	org := organizationID
	return &auth.Binding{
		Operation: "webhook.create", OrganizationID: &org,
		Target: map[string]string{"organizationId": organizationID},
		Body:   body(url, set),
		Query:  map[string]string{},
		Summary: auth.ApprovalSummary{
			Title: "Send the audit events of " + security.LabelWithID("organization", organizationName, organizationID) +
				" to " + security.Quoted(redacted) + " (" + eventWords(set) + ")",
			Changes: []auth.ApprovalChange{added("url", security.Quoted(redacted)), added("eventTypes", eventWords(set))},
		},
	}
}

func body(url string, set []string) any {
	return jsvalue.Object{{Key: "url", Value: url}, {Key: "eventTypes", Value: boundJS(set)}}
}

// updateBinding is webhookUpdateBinding, for a patch that changes the
// webhook: its resulting state, the version the request expects.
func updateBinding(organizationID string, current Ref, url string, eventTypes []string, expectedVersion int64) *auth.Binding {
	set := boundEventTypes(eventTypes)
	var changes []auth.ApprovalChange
	if url != current.URL {
		// Decided on the bound URL, never on its redaction: a changed
		// token that redacts the same is still listed, without showing it.
		from, to := audit.RedactWebhookURL(current.URL), audit.RedactWebhookURL(url)
		if from == to {
			changes = append(changes, change("url", security.Quoted(from)+" (current)", security.Quoted(to)+" (another URL: the part that changed is not shown)"))
		} else {
			changes = append(changes, change("url", security.Quoted(from), security.Quoted(to)))
		}
	}
	before := boundEventTypes(current.EventTypes)
	if (before == nil) != (set == nil) || !slices.Equal(before, set) {
		changes = append(changes, change("eventTypes", eventWords(before), eventWords(set)))
	}
	if changes == nil {
		changes = []auth.ApprovalChange{}
	}
	org, version := organizationID, expectedVersion
	return &auth.Binding{
		Operation: "webhook.update", OrganizationID: &org,
		Target:          map[string]string{"webhookId": current.ID},
		Body:            body(url, set),
		Query:           map[string]string{},
		ExpectedVersion: &version,
		Summary:         auth.ApprovalSummary{Title: "Change " + label(current) + " to " + security.Quoted(audit.RedactWebhookURL(url)), Changes: changes},
	}
}

// deleteBinding is webhookDeleteBinding, at the version the server read.
func deleteBinding(organizationID string, current Ref) *auth.Binding {
	org, version := organizationID, current.Version
	return &auth.Binding{
		Operation: "webhook.delete", OrganizationID: &org,
		Target:          map[string]string{"webhookId": current.ID},
		Query:           map[string]string{},
		ExpectedVersion: &version,
		Summary:         auth.ApprovalSummary{Title: "Stop sending audit events to " + label(current), Changes: []auth.ApprovalChange{}},
	}
}
