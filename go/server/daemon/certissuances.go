// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

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

const certificateUsage = "Usage: varlatchd admin certificate issuances [--json] [--config <file>]"

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
	if len(rest) == 0 || rest[0] != "issuances" {
		return false, certificateUsage
	}
	for _, a := range rest[1:] {
		if a != "--json" {
			return false, certificateUsage
		}
		asJSON = true
	}
	return asJSON, ""
}

func runCertificateIssuances(cfg *config.Config, rest []string, now time.Time, stdout, stderr io.Writer) int {
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
