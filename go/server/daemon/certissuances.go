// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/publictls"
)

// `varlatchd admin certificate issuances [--json]` (step 6 decision 16):
// the certificate issuance count for the public host, from the
// installation's database (certificate_issuances), read-only: what a
// restore checks before varlatchd first asks the CA (setup --restore), so
// that one past Let's Encrypt's five per exact name per week is refused
// before it asks. It needs no running varlatchd, and changes nothing.

// Two more forms carry the count across a migration of a tailnet name
// (go-step7 decision 11), whose certificate requests the handoff's ledger
// holds outside any database:
//   - issuances --all --json lists every attempt kept (any name), read-only:
//     a rollback merges Go's into its ledger before the name moves back;
//   - record --attempts <json> records attempts made elsewhere, as they
//     ended, each once (by name and start): the forward migration writes
//     its ledger into Go's count once Go's installation is open.

const certificateUsage = "Usage: varlatchd admin certificate issuances [--all] [--json] | varlatchd admin certificate record --attempts <json>  (each with [--config <file>])"

// issuanceKeep is how long the count keeps an attempt (publictls's).
const issuanceKeep = 30 * 24 * time.Hour

// recordedAttempt is an attempt, as --all lists it and record takes it.
type recordedAttempt struct {
	Name      string     `json:"name"`
	StartedAt time.Time  `json:"startedAt"`
	Outcome   string     `json:"outcome"`
	EndedAt   *time.Time `json:"endedAt,omitempty"`
}

// issuancesReport is its --json.
type issuancesReport struct {
	// Name is the public host (listen_https); "" when varlatchd serves no
	// public HTTPS, and there is nothing to count.
	Name string `json:"name"`
	CA   string `json:"ca,omitempty"`
	// Limit is the most attempts the CA allows in the window, as
	// varlatchd keeps it (0: none kept for this CA).
	Limit    int        `json:"limit"`
	Window   string     `json:"window"`
	Attempts int        `json:"attempts"`
	Oldest   *time.Time `json:"oldest,omitempty"`
	// Until is when the oldest counted attempt leaves the window.
	Until *time.Time `json:"until,omitempty"`
	// Full is whether the next attempt would pass the limit: varlatchd
	// would refuse it before asking.
	Full bool `json:"full"`
}

func certificateArgs(rest []string) (asJSON bool, msg string) {
	if len(rest) == 0 {
		return false, certificateUsage
	}
	switch rest[0] {
	case "issuances":
		all := false
		for _, a := range rest[1:] {
			switch a {
			case "--json":
				asJSON = true
			case "--all":
				all = true
			default:
				return false, certificateUsage
			}
		}
		if all && !asJSON {
			return false, certificateUsage
		}
		return asJSON, ""
	case "record":
		if len(rest) != 3 || rest[1] != "--attempts" {
			return false, certificateUsage
		}
		if _, err := parseAttempts(rest[2]); err != nil {
			return false, "varlatchd admin certificate record: " + err.Error()
		}
		return false, ""
	}
	return false, certificateUsage
}

// parseAttempts reads record's --attempts: names lower-case, 1 to 253
// bytes; outcomes the count's.
func parseAttempts(raw string) ([]recordedAttempt, error) {
	var in []recordedAttempt
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, fmt.Errorf("--attempts is not a JSON array of {name, startedAt, outcome, endedAt}: %v", err)
	}
	for _, a := range in {
		switch {
		case a.Name == "" || len(a.Name) > 253 || a.Name != strings.ToLower(a.Name):
			return nil, fmt.Errorf("%q is not a certificate's name (lower-case, at most 253 bytes)", a.Name)
		case a.Outcome != "started" && a.Outcome != publictls.OutcomeIssued && a.Outcome != publictls.OutcomeRefused:
			return nil, fmt.Errorf("the outcome %q is not started, issued or refused", a.Outcome)
		case a.StartedAt.IsZero():
			return nil, fmt.Errorf("the attempt for %s has no start", a.Name)
		}
	}
	return in, nil
}

// listIssuances is issuances --all: every attempt kept, read-only.
func listIssuances(cfg *config.Config, stdout, stderr io.Writer) int {
	out := struct {
		Attempts []recordedAttempt `json:"attempts"`
	}{Attempts: []recordedAttempt{}}
	conn, err := openReadOnly(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin certificate issuances: %s\n", err.Error())
		return ExitFailure
	}
	if conn != nil {
		defer conn.Close()
		rows, err := query.New(conn).ListCertificateIssuances(context.Background())
		if err != nil && !strings.Contains(err.Error(), "no such table: certificate_issuances") {
			fmt.Fprintf(stderr, "varlatchd admin certificate issuances: %s\n", err.Error())
			return ExitFailure
		}
		for _, r := range rows {
			a := recordedAttempt{Name: r.Name, StartedAt: time.UnixMicro(r.StartedAt).UTC(), Outcome: r.Outcome}
			if r.EndedAt.Valid {
				end := time.UnixMicro(r.EndedAt.Int64).UTC()
				a.EndedAt = &end
			}
			out.Attempts = append(out.Attempts, a)
		}
	}
	b, _ := json.Marshal(out)
	fmt.Fprintln(stdout, string(b))
	return ExitOK
}

// runCertificateRecord is record (a host command: in the daemon, or
// offline under the lock): each attempt not recorded yet, and not past the
// count's keep, is written as it ended.
func runCertificateRecord(ctx context.Context, env *hostEnv, rest []string, stdout, stderr io.Writer) int {
	if _, msg := certificateArgs(rest); msg != "" || len(rest) != 3 || rest[0] != "record" {
		fmt.Fprintln(stderr, certificateUsage)
		return 64
	}
	attempts, _ := parseAttempts(rest[2])
	since := time.Now().Add(-issuanceKeep)
	n := 0
	err := env.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		for _, a := range attempts {
			if a.StartedAt.Before(since) {
				continue
			}
			have, err := q.CertificateIssuanceRecorded(ctx, query.CertificateIssuanceRecordedParams{Name: a.Name, StartedAt: a.StartedAt.UnixMicro()})
			if err != nil {
				return err
			}
			if have > 0 {
				continue
			}
			end := sql.NullInt64{}
			if a.EndedAt != nil {
				end = sql.NullInt64{Int64: a.EndedAt.UnixMicro(), Valid: true}
			}
			if err := q.RecordCertificateIssuance(ctx, query.RecordCertificateIssuanceParams{Name: a.Name, StartedAt: a.StartedAt.UnixMicro(), Outcome: a.Outcome, EndedAt: end}); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin certificate record: %s\n", err.Error())
		return ExitFailure
	}
	fmt.Fprintf(stdout, "Recorded %d certificate attempts (%d given).\n", n, len(attempts))
	return ExitOK
}

func runCertificateIssuances(cfg *config.Config, rest []string, now time.Time, stdout, stderr io.Writer) int {
	if slices.Contains(rest, "--all") {
		return listIssuances(cfg, stdout, stderr)
	}
	asJSON, _ := certificateArgs(rest)
	fail := func(err error) int {
		fmt.Fprintf(stderr, "varlatchd admin certificate issuances: %s\n", err.Error())
		return ExitFailure
	}
	rep := issuancesReport{Window: publictls.IssuanceWindow.String()}
	if p := cfg.PublicHTTPS; p != nil {
		rep.Name, rep.CA, rep.Limit = strings.ToLower(p.Host), p.CA, publictls.LimitFor(p.CA)
		conn, err := openReadOnly(cfg)
		if err != nil {
			return fail(err)
		}
		if conn != nil {
			defer conn.Close()
			row, err := query.New(conn).CountCertificateIssuances(context.Background(), query.CountCertificateIssuancesParams{Name: rep.Name, StartedAt: now.Add(-publictls.IssuanceWindow).UnixMicro()})
			// A database from before the count (an older archive) has no
			// table: nothing was counted.
			if err != nil && !strings.Contains(err.Error(), "no such table: certificate_issuances") {
				return fail(err)
			}
			if err == nil && row.N > 0 {
				oldest := time.UnixMicro(row.Oldest).UTC()
				until := oldest.Add(publictls.IssuanceWindow)
				rep.Attempts, rep.Oldest, rep.Until = int(row.N), &oldest, &until
			}
		}
		rep.Full = rep.Limit > 0 && rep.Attempts >= rep.Limit
	}
	if asJSON {
		b, err := json.Marshal(rep)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintln(stdout, string(b))
		return ExitOK
	}
	switch {
	case rep.Name == "":
		fmt.Fprintln(stdout, "varlatchd serves no public HTTPS (listen_https is unset): it asks no CA for a certificate.")
	case rep.Limit == 0:
		fmt.Fprintf(stdout, "Certificate requests for %s in the last 7 days: %d (the CA %s has no limit varlatchd keeps).\n", rep.Name, rep.Attempts, rep.CA)
	case rep.Full:
		fmt.Fprintf(stdout, "Certificate requests for %s in the last 7 days: %d, Let's Encrypt's limit of %d: varlatchd asks for none until %s.\n", rep.Name, rep.Attempts, rep.Limit, rep.Until.Format(time.RFC3339))
	default:
		fmt.Fprintf(stdout, "Certificate requests for %s in the last 7 days: %d of Let's Encrypt's %d.\n", rep.Name, rep.Attempts, rep.Limit)
	}
	return ExitOK
}
