// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
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

// changesShown is how many of the newest events are listed one by one.
const changesShown = 20

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
}

type changesJSON struct {
	Since  string           `json:"since"`
	Total  int64            `json:"total"`
	ByType map[string]int64 `json:"byType"`
	// Latest are the newest events, at most changesShown, newest first.
	Latest []changeJSON `json:"latest"`
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
	out := changesJSON{Since: since.UTC().Format(time.RFC3339), ByType: map[string]int64{}, Latest: []changeJSON{}}
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
	rows.Close()
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
	rows.Close()
	if asJSON {
		return printJSON(stdout, stderr, what, out)
	}
	fmt.Fprintf(stdout, "%d audit events since %s.\n", out.Total, out.Since)
	for _, c := range out.Latest {
		org := "the installation"
		if c.OrganizationID != nil {
			org = *c.OrganizationID
		}
		fmt.Fprintf(stdout, "  %s  %s (%s, %s)\n", c.OccurredAt, c.EventType, c.Decision, org)
	}
	return ExitOK
}
