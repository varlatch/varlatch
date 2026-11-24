// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/server/config"
)

// `varlatchd admin changes --since <time> [--json]` (ADR-0059 Decision 8;
// internal docs/design/go-step6.md, slice 6.6c): the audit events recorded
// since a time, which `varlatch upgrade --rollback` lists before it
// restores the pre-upgrade snapshot (every one of them is then lost). It
// reads the database read-only, beside a running varlatchd or not, and
// shows no value: each event's type, time, decision and Organization, and
// a count by type.

const changesUsage = "Usage: varlatchd admin changes --since <time> [--json] [--config <file>]"

// changesShown is how many of the newest events are listed one by one;
// those restoreUndoes names are all listed.
const changesShown = 20

// restoreUndoes are the audit event types whose effect a snapshot restore
// takes back to the host's harm: a credential, grant, capability or binding
// revoked since the snapshot works again; a member, identity or reader
// removed is back; a rotated Secret's or replaced credential's old value is
// the current one again; a deletion or freeze is undone. They are listed
// first, before the rest of what the restore loses
// (TestRestoreUndoesCoversEveryRevocation keeps this list whole).
var restoreUndoes = []string{
	"audit_export.credential_replaced", "audit_export.removed", "audit_tombstone.reader_removed",
	"capability.revoked", "credential.revoked", "environment.deleted", "grant.revoked", "group.deleted",
	"group.member_removed", "identity.retired", "invitation.revoked", "membership.removed",
	"oidc_binding.revoked", "organization.deleted", "organization.deletion_scheduled", "organization.frozen",
	"project.deleted", "requirement.revoked", "role.deleted", "sync.connection_credential_replaced",
	"sync.connection_revoked", "sync.github_app_key_rotated", "sync.github_app_removed", "sync.target_disabled",
	"sync.target_revoked", "team.deleted", "team.member_removed", "team.project_removed",
	"value.deleted", "value.rotation_completed", "webhook.revoked",
}

func changesArgs(rest []string) (since time.Time, asJSON bool, msg string) {
	given := false
	for i := 0; i < len(rest); i++ {
		switch a := rest[i]; {
		case a == "--json" && !asJSON:
			asJSON = true
		case a == "--since" && !given && i+1 < len(rest):
			t, err := time.Parse(time.RFC3339, rest[i+1])
			if err != nil {
				return time.Time{}, false, changesUsage
			}
			since, given = t, true
			i++
		default:
			return time.Time{}, false, changesUsage
		}
	}
	if !given {
		return time.Time{}, false, changesUsage
	}
	return since, asJSON, ""
}

type changeJSON struct {
	OccurredAt     string  `json:"occurredAt"`
	EventType      string  `json:"eventType"`
	Decision       string  `json:"decision"`
	OrganizationID *string `json:"organizationId"`
	// Resource is the event's resource (its kind and identifiers, never a
	// value), for a revocation: what to revoke again.
	Resource *string `json:"resource,omitempty"`
}

type changesJSON struct {
	Since  string           `json:"since"`
	Total  int64            `json:"total"`
	ByType map[string]int64 `json:"byType"`
	// Latest are the newest events, at most changesShown, newest first.
	Latest []changeJSON `json:"latest"`
	// Revocations are the RevocationsTotal events of restoreUndoes since
	// the time, newest first.
	RevocationsTotal int64        `json:"revocationsTotal"`
	Revocations      []changeJSON `json:"revocations"`
}

func runChanges(cfg *config.Config, rest []string, stdout, stderr io.Writer) int {
	const what = "varlatchd admin changes"
	since, asJSON, _ := changesArgs(rest)
	path := cfg.DatabasePath()
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(stderr, "%s: there is no database at %s\n", what, path)
		return ExitFailure
	}
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&_pragma=busy_timeout(5000)"}
	conn, err := sql.Open("sqlite", u.String())
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", what, err)
		return ExitFailure
	}
	defer conn.Close()
	at := since.UnixMicro()
	out := changesJSON{Since: since.UTC().Format(time.RFC3339), ByType: map[string]int64{}, Latest: []changeJSON{}, Revocations: []changeJSON{}}
	rows, err := conn.Query("SELECT event_type, count(*) FROM audit_events WHERE occurred_at >= ? GROUP BY event_type ORDER BY event_type", at)
	if err != nil {
		fmt.Fprintf(stderr, "%s: cannot read the audit log: %v\n", what, err)
		return ExitFailure
	}
	for rows.Next() {
		var t string
		var n int64
		if err := rows.Scan(&t, &n); err != nil {
			rows.Close()
			fmt.Fprintf(stderr, "%s: %v\n", what, err)
			return ExitFailure
		}
		out.ByType[t], out.Total = n, out.Total+n
	}
	if err := closeRows(rows); err != nil {
		fmt.Fprintf(stderr, "%s: cannot read the audit log: %v\n", what, err)
		return ExitFailure
	}
	rows, err = conn.Query("SELECT occurred_at, event_type, decision, organization_id FROM audit_events WHERE occurred_at >= ? ORDER BY event_order DESC LIMIT ?", at, changesShown)
	if err != nil {
		fmt.Fprintf(stderr, "%s: cannot read the audit log: %v\n", what, err)
		return ExitFailure
	}
	for rows.Next() {
		var c changeJSON
		var micros int64
		if err := rows.Scan(&micros, &c.EventType, &c.Decision, &c.OrganizationID); err != nil {
			rows.Close()
			fmt.Fprintf(stderr, "%s: %v\n", what, err)
			return ExitFailure
		}
		c.OccurredAt = time.UnixMicro(micros).UTC().Format("2006-01-02T15:04:05.000Z")
		out.Latest = append(out.Latest, c)
	}
	if err := closeRows(rows); err != nil {
		fmt.Fprintf(stderr, "%s: cannot read the audit log: %v\n", what, err)
		return ExitFailure
	}
	marks := strings.TrimSuffix(strings.Repeat("?, ", len(restoreUndoes)), ", ")
	args := []any{at}
	for _, t := range restoreUndoes {
		args = append(args, t)
	}
	// Every event of a listed type, whatever its decision: the services
	// record these changes as info (a refusal is authorization.denied,
	// another type), so a filter on the decision would hide them.
	where := "occurred_at >= ? AND event_type IN (" + marks + ")"
	rows, err = conn.Query("SELECT occurred_at, event_type, decision, organization_id, resource FROM audit_events WHERE "+where+" ORDER BY event_order DESC", args...)
	if err != nil {
		fmt.Fprintf(stderr, "%s: cannot read the audit log: %v\n", what, err)
		return ExitFailure
	}
	for rows.Next() {
		var c changeJSON
		var micros int64
		if err := rows.Scan(&micros, &c.EventType, &c.Decision, &c.OrganizationID, &c.Resource); err != nil {
			rows.Close()
			fmt.Fprintf(stderr, "%s: %v\n", what, err)
			return ExitFailure
		}
		c.OccurredAt = time.UnixMicro(micros).UTC().Format("2006-01-02T15:04:05.000Z")
		out.Revocations = append(out.Revocations, c)
	}
	if err := closeRows(rows); err != nil {
		fmt.Fprintf(stderr, "%s: cannot read the audit log: %v\n", what, err)
		return ExitFailure
	}
	out.RevocationsTotal = int64(len(out.Revocations))
	if asJSON {
		return printJSON(stdout, stderr, what, out)
	}
	fmt.Fprintf(stdout, "%d audit events since %s, %d of them revocations, removals, rotations, replacements, deletions and freezes.\n", out.Total, out.Since, out.RevocationsTotal)
	for _, c := range out.Latest {
		org := "the installation"
		if c.OrganizationID != nil {
			org = *c.OrganizationID
		}
		fmt.Fprintf(stdout, "  %s  %s (%s, %s)\n", c.OccurredAt, c.EventType, c.Decision, org)
	}
	return ExitOK
}

// closeRows ends a read: the error that stopped it, if one did (a list cut
// short would show less than the restore loses).
func closeRows(rows *sql.Rows) error {
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	return rows.Close()
}
