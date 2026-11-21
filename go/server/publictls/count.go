// SPDX-License-Identifier: AGPL-3.0-or-later

package publictls

import (
	"context"
	"database/sql"
	"net/url"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/query"
)

// The certificate issuance count (ADR-0059 Decision 9; internal
// docs/design/go-step6.md decision 16): every order or renewal the
// installation starts for its name is recorded before the CA is asked, in
// the installation's database, so the count survives a backup and a
// restore. An attempt counts unless the CA answered with a problem (it
// issued nothing): one that timed out, or that a crash cut short, counts as
// issued. With Let's Encrypt, an attempt that would pass its five
// certificates per exact name per week by this count is refused before it
// asks.

// IssuanceWindow is the period the count covers (Let's Encrypt's week).
const IssuanceWindow = 7 * 24 * time.Hour

// IssuanceSlack is how long past the week varlatchd holds a name at its
// limit: the CA's own window may end a little after this installation's
// clock says. A check made before varlatchd asks (setup --restore) counts
// over the window and this slack together.
const IssuanceSlack = time.Hour

// LetsEncryptLimit is Let's Encrypt's duplicate certificate limit: five
// certificates for the same exact set of names per week.
const LetsEncryptLimit = 5

// issuanceKeep is how long a recorded attempt is kept: well past the
// window, for doctor and for a restore's check.
const issuanceKeep = 30 * 24 * time.Hour

// Outcomes of a recorded attempt.
const (
	OutcomeIssued  = "issued"
	OutcomeRefused = "refused"
)

// Issuances is where the count is kept (StoreIssuances in varlatchd; tests
// replace it).
type Issuances interface {
	// Count is the attempts for name since since that count, and the
	// oldest of them (zero when none).
	Count(ctx context.Context, name string, since time.Time) (int, time.Time, error)
	// Begin records an attempt for name, started at at.
	Begin(ctx context.Context, name string, at time.Time) (int64, error)
	// End records how it ended (OutcomeIssued or OutcomeRefused).
	End(ctx context.Context, id int64, outcome string, at time.Time) error
}

// LimitFor is the limit varlatchd keeps for a CA: Let's Encrypt's, for its
// production and staging directories; none (0) for another CA, whose
// attempts are still counted.
func LimitFor(ca string) int {
	u, err := url.Parse(ca)
	if err != nil {
		return 0
	}
	switch strings.ToLower(u.Hostname()) {
	case "acme-v02.api.letsencrypt.org", "acme-staging-v02.api.letsencrypt.org":
		return LetsEncryptLimit
	}
	return 0
}

// StoreIssuances keeps the count in the installation's database.
type StoreIssuances struct{ DB *storage.DB }

func (s StoreIssuances) Count(ctx context.Context, name string, since time.Time) (int, time.Time, error) {
	row, err := query.New(s.DB.Reader()).CountCertificateIssuances(ctx, query.CountCertificateIssuancesParams{Name: name, StartedAt: since.UnixMicro()})
	if err != nil {
		return 0, time.Time{}, err
	}
	oldest := time.Time{}
	if row.N > 0 {
		oldest = time.UnixMicro(row.Oldest)
	}
	return int(row.N), oldest, nil
}

func (s StoreIssuances) Begin(ctx context.Context, name string, at time.Time) (int64, error) {
	var id int64
	err := s.DB.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		if err := q.PruneCertificateIssuances(ctx, at.Add(-issuanceKeep).UnixMicro()); err != nil {
			return err
		}
		var err error
		id, err = q.BeginCertificateIssuance(ctx, query.BeginCertificateIssuanceParams{Name: name, StartedAt: at.UnixMicro()})
		return err
	})
	return id, err
}

func (s StoreIssuances) End(ctx context.Context, id int64, outcome string, at time.Time) error {
	return s.DB.Write(ctx, func(tx *storage.Tx) error {
		return query.New(tx).EndCertificateIssuance(ctx, query.EndCertificateIssuanceParams{
			Outcome: outcome, EndedAt: sql.NullInt64{Int64: at.UnixMicro(), Valid: true}, ID: id,
		})
	})
}
