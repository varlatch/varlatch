// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Moving an installation to another public URL (ADR-0059 step 6, slice
// 6.9; issue #103; domain/bootstrap.ts): the public URL is the passkeys'
// relying party, so a move is a re-enrollment event. Every passkey of the
// old address is removed once, explicitly, when the operator runs
// `admin public-url-changed` (CompletePublicURLChange), and each person
// gets a one-time link that adds a passkey to their existing identity
// (`admin reenroll`, IssueReenrollmentGrants). Both are host-exec
// authority, like recovery.

// Re-enrollment links' lifetime: a day by default, a week at most.
const (
	ReenrollTTLDefault = 24 * time.Hour
	ReenrollTTLMax     = 7 * 24 * time.Hour
)

// ReenrollmentGrant is one person's re-enrollment link token, returned
// once: it is never logged or stored, only its hash.
type ReenrollmentGrant struct {
	IdentityID        string
	Name              string
	InstallationAdmin bool
	Token             string
	ExpiresAt         int64
}

// Reenroll names who gets a link: every enabled person (All), or the named
// identities; and the links' lifetime (0 is ReenrollTTLDefault).
type Reenroll struct {
	All         bool
	IdentityIDs []string
	TTL         time.Duration
}

// IssueReenrollmentGrants issues one re-enrollment grant per person
// (issueReenrollmentGrants): a new one revokes that person's unused ones,
// so at most one link per person is live. Installation Admins come first,
// then the oldest. Each issuance is audited (reenrollment.grant_issued),
// without the token.
func (s *Service) IssueReenrollmentGrants(ctx context.Context, in Reenroll) ([]ReenrollmentGrant, error) {
	ttl := in.TTL
	if ttl == 0 {
		ttl = ReenrollTTLDefault
	}
	if ttl < 0 || ttl > ReenrollTTLMax {
		return nil, domainerr.New("VALIDATION_FAILED", fmt.Sprintf("Link lifetime must be more than 0 and at most %d hours", int(ReenrollTTLMax/time.Hour)))
	}
	if in.All == (len(in.IdentityIDs) > 0) {
		return nil, domainerr.New("VALIDATION_FAILED", "Name every person (--all) or some (--identity), not both")
	}
	var grants []ReenrollmentGrant
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		inst, err := q.InstallationBootstrap(ctx)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err != nil || !inst.BootstrappedAt.Valid {
			return domainerr.New("VALIDATION_FAILED", "Installation is not bootstrapped yet; use bootstrap")
		}
		var rows []query.ReenrollCandidatesRow
		if in.All {
			if rows, err = q.ReenrollCandidates(ctx); err != nil {
				return err
			}
		} else {
			named, err := q.ReenrollSubjects(ctx, in.IdentityIDs)
			if err != nil {
				return err
			}
			for _, r := range named {
				rows = append(rows, query.ReenrollCandidatesRow(r))
			}
			for _, id := range in.IdentityIDs {
				i := slices.IndexFunc(rows, func(r query.ReenrollCandidatesRow) bool { return r.ID == id })
				if i < 0 || rows[i].Kind != "human" {
					return domainerr.New("RESOURCE_NOT_FOUND", "No person with identity "+id)
				}
				if rows[i].Disabled {
					return domainerr.New("VALIDATION_FAILED", "Identity "+id+" is disabled")
				}
			}
		}
		slices.SortStableFunc(rows, func(a, b query.ReenrollCandidatesRow) int {
			switch {
			case a.InstallationAdmin != b.InstallationAdmin:
				if a.InstallationAdmin {
					return -1
				}
				return 1
			case a.CreatedAt != b.CreatedAt:
				return cmp.Compare(a.CreatedAt, b.CreatedAt)
			}
			return strings.Compare(a.ID, b.ID)
		})
		now := s.micros()
		expires := (now/1000 + ttl.Milliseconds()) * 1000
		grants = grants[:0]
		for _, row := range rows {
			if _, err := q.RevokeLiveReenrollGrants(ctx, query.RevokeLiveReenrollGrantsParams{Now: sql.NullInt64{Int64: now, Valid: true}, IdentityID: sql.NullString{String: row.ID, Valid: true}}); err != nil {
				return err
			}
			token := setupToken("vlt_reenroll_")
			subject := row.ID
			if err := q.InsertSetupGrant(ctx, query.InsertSetupGrantParams{
				ID: ids.New(ids.SetupGrant), Kind: GrantReenroll, SubjectIdentityID: nullStr(&subject), TokenHash: HashToken(token),
				ExpiresAt: expires, CreatedAt: now,
			}); err != nil {
				return err
			}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Type: "reenrollment.grant_issued", Decision: audit.Info,
				Resource: jsvalue.Object{{Key: "identityId", Value: row.ID}},
				Metadata: jsvalue.Object{{Key: "expiresAt", Value: ISO(expires)}, {Key: "installationAdmin", Value: row.InstallationAdmin}},
			}); err != nil {
				return err
			}
			grants = append(grants, ReenrollmentGrant{IdentityID: row.ID, Name: row.Name, InstallationAdmin: row.InstallationAdmin, Token: token, ExpiresAt: expires})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return grants, nil
}

// PublicURLChange is what CompletePublicURLChange did.
type PublicURLChange struct {
	From, To                  string
	PasskeysRemoved           int64
	SessionsEnded             int64
	BrowserCredentialsRevoked int64
}

// PeopleIDs are every identity's id, in id order: the people whose gates
// CompletePublicURLChange's caller takes exclusive first, as the
// TypeScript code locks every person before their passkeys.
func (s *Service) PeopleIDs(ctx context.Context) ([]string, error) {
	return query.New(s.store.Reader()).AllIdentityIDs(ctx)
}

// CompletePublicURLChange records that the installation now answers at to
// instead of from (completePublicUrlChange): every passkey, registered for
// the old relying party, can never sign in again, so all are removed;
// every browser session ends, and the dashboard's credentials minted from
// them are revoked (each recorded as credential.revoked with the reason
// public-url-changed). CLI, agent and machine credentials hold no address
// and keep working. Explicit, never automatic: a typo in public_url must
// not erase anyone's passkeys, and the archive taken before the move keeps
// them for a move back. Once per move: after it, the recorded address is
// to, so a rerun (or a wrong from) removes nothing.
func (s *Service) CompletePublicURLChange(ctx context.Context, fromURL, toURL string) (PublicURLChange, error) {
	from, err := originOf(fromURL)
	if err != nil {
		return PublicURLChange{}, err
	}
	to, err := originOf(toURL)
	if err != nil {
		return PublicURLChange{}, err
	}
	if from == to {
		return PublicURLChange{}, domainerr.New("VALIDATION_FAILED", "The installation already answers at this address")
	}
	var out PublicURLChange
	err = s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		recorded, err := q.InstallationPublicURL(ctx)
		if err != nil {
			return err
		}
		if recorded.Valid && recorded.String == to {
			return domainerr.New("VALIDATION_FAILED", fmt.Sprintf("The passkeys of %s were already removed when the installation moved to %s", from, to))
		}
		if recorded.Valid && recorded.String != from {
			return domainerr.New("VALIDATION_FAILED", fmt.Sprintf("The installation last moved to %s, not %s: check --from", recorded.String, from))
		}
		now := s.micros()
		removed, err := q.DeleteAllPasskeys(ctx)
		if err != nil {
			return err
		}
		// The browser credentials first, then the sessions: deleting a
		// session revokes its browser credentials and audits that
		// (session_end_revokes_browser_credentials), so here each is
		// revoked, and recorded, once, with this reason.
		live, err := q.LiveBrowserCredentials(ctx, sql.NullInt64{Int64: now, Valid: true})
		if err != nil {
			return err
		}
		for _, c := range live {
			if err := q.RevokeBrowserCredential(ctx, query.RevokeBrowserCredentialParams{Now: sql.NullInt64{Int64: now, Valid: true}, ID: c.ID}); err != nil {
				return err
			}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Type: "credential.revoked", Decision: audit.Info, CredentialID: audit.Value(c.ID),
				Resource: jsvalue.Object{{Key: "identityId", Value: c.IdentityID}},
				Metadata: jsvalue.Object{{Key: "reason", Value: "public-url-changed"}},
			}); err != nil {
				return err
			}
		}
		ended, err := q.DeleteAllAuthSessions(ctx)
		if err != nil {
			return err
		}
		if err := q.SetInstallationPublicURL(ctx, sql.NullString{String: to, Valid: true}); err != nil {
			return err
		}
		out = PublicURLChange{From: from, To: to, PasskeysRemoved: removed, SessionsEnded: ended, BrowserCredentialsRevoked: int64(len(live))}
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "installation.public_url_changed", Decision: audit.Info,
			Metadata: jsvalue.Object{
				{Key: "from", Value: out.From}, {Key: "to", Value: out.To},
				{Key: "passkeysRemoved", Value: out.PasskeysRemoved}, {Key: "sessionsEnded", Value: out.SessionsEnded},
				{Key: "browserCredentialsRevoked", Value: out.BrowserCredentialsRevoked},
			},
		})
		return err
	})
	if err != nil {
		return PublicURLChange{}, err
	}
	return out, nil
}

// originOf is a URL's origin (scheme, host and port, without the scheme's
// default port), as new URL(u).origin.
func originOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
		return "", domainerr.New("VALIDATION_FAILED", "Not a URL: "+raw)
	}
	host := strings.ToLower(u.Host)
	if p := u.Port(); u.Scheme == "https" && p == "443" || u.Scheme == "http" && p == "80" {
		host = strings.TrimSuffix(host, ":"+p)
	}
	return u.Scheme + "://" + host, nil
}

// MoveFacts is what a move to another public URL affects, read only.
type MoveFacts struct {
	People             int64 `json:"people"`
	InstallationAdmins int64 `json:"installationAdmins"`
	AdminsWithPasskey  int64 `json:"adminsWithPasskey"`
	Passkeys           int64 `json:"passkeys"`
	Sessions           int64 `json:"sessions"`
	TailnetConstraints int64 `json:"tailnetConstraints"`
	PendingInvitations int64 `json:"pendingInvitations"`
}

// MoveFacts reads what a move affects (moveFacts).
func (s *Service) MoveFacts(ctx context.Context) (MoveFacts, error) {
	r, err := query.New(s.store.Reader()).MoveFacts(ctx, s.micros())
	if err != nil {
		return MoveFacts{}, err
	}
	return MoveFacts(r), nil
}
