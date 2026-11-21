// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Setup grants (ADR-0010/0019/0020; domain/bootstrap.ts): short-lived,
// single-use, purpose-limited. Issuing one is host-exec authority (the
// admin commands); every issuance and consumption is audited.

// SetupGrantTTL is a bootstrap or recovery grant's lifetime.
const SetupGrantTTL = 15 * time.Minute

// Setup grant kinds.
const (
	GrantBootstrap = "bootstrap"
	GrantRecover   = "recover"
	GrantInvite    = "invite"
	GrantReenroll  = "reenroll"
)

// Grant is an issued setup grant: its token, returned once.
type Grant struct {
	Token     string
	ExpiresAt int64
}

// IssueBootstrapGrant issues the first enrollment's grant
// (issueBootstrapGrant). An installation already bootstrapped refuses,
// naming any enabled Installation Admin left without a passkey.
func (s *Service) IssueBootstrapGrant(ctx context.Context) (Grant, error) {
	return s.IssueBootstrapGrantRevoking(ctx, false)
}

// revokeUnused revokes, in the issuing job and before the new grant is
// inserted, the bootstrap and recovery links issued before and never used
// (setup's reissue). Their count goes into the issued event's metadata,
// which records the revocation; -1 when not asked.
func revokeUnused(ctx context.Context, q *query.Queries, now int64, revoke bool) (int64, error) {
	if !revoke {
		return -1, nil
	}
	return q.RevokeUnusedSetupLinks(ctx, sql.NullInt64{Int64: now, Valid: true})
}

// withRevoked is the issued event's metadata with the revoked count.
func withRevoked(meta jsvalue.Object, revoked int64) jsvalue.Object {
	if revoked < 0 {
		return meta
	}
	return append(meta, jsvalue.Member{Key: "revokedUnused", Value: float64(revoked)})
}

// IssueBootstrapGrantRevoking is IssueBootstrapGrant that first revokes the
// unused bootstrap and recovery links when revoke is set (`admin bootstrap
// --revoke-unused`, which setup runs).
func (s *Service) IssueBootstrapGrantRevoking(ctx context.Context, revoke bool) (Grant, error) {
	var g Grant
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		inst, err := q.InstallationBootstrap(ctx)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("the installation is not initialized: start varlatchd serve once first")
		}
		if err != nil {
			return err
		}
		if inst.BootstrappedAt.Valid {
			stranded, err := q.AdminsWithoutPasskey(ctx)
			if err != nil {
				return err
			}
			hint := ""
			if len(stranded) > 0 {
				hint = fmt.Sprintf(" Enabled Installation Admin(s) without an enrolled passkey: %s; if enrollment was interrupted, run: admin recover --identity %s",
					strings.Join(stranded, ", "), stranded[0])
			}
			return domainerr.New("VALIDATION_FAILED", "Installation is already bootstrapped; use recovery instead."+hint)
		}
		now := s.micros()
		revoked, err := revokeUnused(ctx, q, now, revoke)
		if err != nil {
			return err
		}
		token := setupToken("vlt_setup_")
		expires := (now/1000 + SetupGrantTTL.Milliseconds()) * 1000
		if err := q.InsertSetupGrant(ctx, query.InsertSetupGrantParams{
			ID: ids.New(ids.SetupGrant), Kind: GrantBootstrap, TokenHash: HashToken(token), ExpiresAt: expires, CreatedAt: now,
		}); err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "bootstrap.grant_issued", Decision: audit.Info, Metadata: withRevoked(jsvalue.Object{{Key: "expiresAt", Value: ISO(expires)}}, revoked),
		}); err != nil {
			return err
		}
		g = Grant{Token: token, ExpiresAt: expires}
		return nil
	})
	return g, err
}

// Recovery is a recovery grant's target: a named Installation Admin
// (Enable re-enables a disabled one), or a new admin when none is enabled.
type Recovery struct {
	IdentityID string
	Enable     bool
	NewAdmin   bool
	// RevokeUnused first revokes the unused bootstrap and recovery links
	// (`admin recover --revoke-unused`, which setup runs).
	RevokeUnused bool
}

// IssueRecoveryGrant issues a break-glass recovery grant
// (issueRecoveryGrant, ADR-0020 §1).
func (s *Service) IssueRecoveryGrant(ctx context.Context, in Recovery) (Grant, error) {
	var g Grant
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		inst, err := q.InstallationBootstrap(ctx)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err != nil || !inst.BootstrappedAt.Valid {
			return domainerr.New("VALIDATION_FAILED", "Installation is not bootstrapped yet; use bootstrap")
		}
		var subject *string
		if in.NewAdmin {
			n, err := q.EnabledInstallationAdminCount(ctx)
			if err != nil {
				return err
			}
			if n > 0 {
				return domainerr.New("VALIDATION_FAILED", fmt.Sprintf("--new-admin is only allowed when zero enabled Installation Admins exist (found %d)", n))
			}
		} else {
			row, err := q.GetIdentity(ctx, in.IdentityID)
			if errors.Is(err, sql.ErrNoRows) || err == nil && !row.InstallationAdmin {
				return domainerr.New("RESOURCE_NOT_FOUND", "Installation Admin identity not found")
			}
			if err != nil {
				return err
			}
			if row.Disabled && !in.Enable {
				return domainerr.New("VALIDATION_FAILED", "Identity is disabled; pass --enable to explicitly re-enable during recovery")
			}
			if row.Disabled {
				if err := q.EnableIdentity(ctx, row.ID); err != nil {
					return err
				}
				if _, err := audit.Record(ctx, tx, audit.Event{
					Type: "recovery.identity_reenabled", Decision: audit.Info,
					Resource: jsvalue.Object{{Key: "identityId", Value: row.ID}},
				}); err != nil {
					return err
				}
			}
			subject = &row.ID
		}
		now := s.micros()
		revoked, err := revokeUnused(ctx, q, now, in.RevokeUnused)
		if err != nil {
			return err
		}
		token := setupToken("vlt_recover_")
		expires := (now/1000 + SetupGrantTTL.Milliseconds()) * 1000
		if err := q.InsertSetupGrant(ctx, query.InsertSetupGrantParams{
			ID: ids.New(ids.SetupGrant), Kind: GrantRecover, SubjectIdentityID: nullStr(subject), TokenHash: HashToken(token),
			ExpiresAt: expires, CreatedAt: now,
		}); err != nil {
			return err
		}
		resource := jsvalue.Object{{Key: "newAdmin", Value: "true"}}
		if subject != nil {
			resource = jsvalue.Object{{Key: "identityId", Value: *subject}}
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "recovery.grant_issued", Decision: audit.Info, Resource: resource,
			Metadata: withRevoked(jsvalue.Object{{Key: "expiresAt", Value: ISO(expires)}}, revoked),
		}); err != nil {
			return err
		}
		g = Grant{Token: token, ExpiresAt: expires}
		return nil
	})
	return g, err
}

// errGrantRejected is a setup token that is invalid, consumed, revoked or
// expired: the refusal, after setup.grant_rejected is recorded.
var errGrantRejected = domainerr.New("INVALID_CREDENTIAL", "Setup token is invalid, consumed, or expired")

// rejectSetupGrant records setup.grant_rejected in a job of its own, so it
// survives the job that declined the consumption, and returns the refusal.
func (s *Service) rejectSetupGrant(ctx context.Context) error {
	if err := s.store.Write(ctx, func(tx *storage.Tx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Type: "setup.grant_rejected", Decision: audit.Deny,
			Metadata: jsvalue.Object{{Key: "reason", Value: "invalid-consumed-or-expired"}},
		})
		return err
	}); err != nil {
		return err
	}
	return errGrantRejected
}

// PeekedGrant is a live setup grant, checked without consuming it.
type PeekedGrant struct {
	ID          string
	Kind        string
	DisplayName string
}

// PeekSetupGrant checks a setup grant without consuming it (issue #23):
// enrollment's ceremony start, so a cancelled prompt leaves the grant
// usable until it expires (peekSetupGrant).
func (s *Service) PeekSetupGrant(ctx context.Context, token string) (PeekedGrant, error) {
	row, err := query.New(s.store.Reader()).PeekSetupGrant(ctx, query.PeekSetupGrantParams{TokenHash: HashToken(token), Now: s.micros()})
	if errors.Is(err, sql.ErrNoRows) || err == nil && row.Kind == GrantReenroll && row.SubjectDisabled {
		return PeekedGrant{}, s.rejectSetupGrant(ctx)
	}
	if err != nil {
		return PeekedGrant{}, err
	}
	name := "Installation Admin"
	if row.Kind == GrantInvite {
		name = "Invited user"
		if row.InviteName.Valid {
			name = row.InviteName.String
		}
	} else if row.SubjectName.Valid {
		name = row.SubjectName.String
	}
	return PeekedGrant{ID: row.ID, Kind: row.Kind, DisplayName: name}, nil
}

// Consumed is a consumed setup grant: the identity it enrolls.
type Consumed struct {
	IdentityID string
	Kind       string
	GrantID    string
}

// consumeSetupGrant consumes a setup grant in the caller's write job
// (consumeSetupGrant). For a bootstrap, and a recovery naming no identity,
// it creates the Installation Admin; for an invitation, an ordinary person
// with their membership. A grant that cannot be consumed returns
// ok == false and changes nothing: the caller rejects it after the job.
// Single use holds because the single writer runs the check and the
// consumption with nothing between.
func consumeSetupGrant(ctx context.Context, tx query.DBTX, now int64, token, adminName string) (Consumed, bool, error) {
	q := query.New(tx)
	g, err := q.SetupGrantByTokenHash(ctx, HashToken(token))
	if errors.Is(err, sql.ErrNoRows) {
		return Consumed{}, false, nil
	}
	if err != nil {
		return Consumed{}, false, err
	}
	if g.ConsumedAt.Valid || g.RevokedAt.Valid || g.ExpiresAt <= now {
		return Consumed{}, false, nil
	}
	if g.InviteOrganizationID.Valid {
		// An invitation needs its Organization live, as lockLiveScope's
		// writer protocol (ADR-0051, ADR-0055): not deleted, no deletion
		// open, not frozen for an incident. One that is not is refused like
		// a dead grant, before anything is consumed or created.
		if live, err := invitationOrganizationLive(ctx, tx, g.InviteOrganizationID.String); err != nil || !live {
			return Consumed{}, false, err
		}
	}
	if g.Kind == GrantReenroll {
		// The person may have been disabled since the link was issued.
		subject, err := q.GetIdentity(ctx, g.SubjectIdentityID.String)
		if errors.Is(err, sql.ErrNoRows) || err == nil && subject.Disabled {
			return Consumed{}, false, nil
		}
		if err != nil {
			return Consumed{}, false, err
		}
	}
	if err := q.ConsumeSetupGrant(ctx, query.ConsumeSetupGrantParams{ConsumedAt: sql.NullInt64{Int64: now, Valid: true}, ID: g.ID}); err != nil {
		return Consumed{}, false, err
	}
	identityID := g.SubjectIdentityID.String
	if !g.SubjectIdentityID.Valid && g.Kind == GrantInvite {
		identityID = ids.New(ids.Identity)
		name := "Invited user"
		if g.InviteName.Valid {
			name = g.InviteName.String
		} else if adminName != "" {
			name = adminName
		}
		if err := q.InsertHumanIdentity(ctx, query.InsertHumanIdentityParams{ID: identityID, Name: name, CreatedAt: now}); err != nil {
			return Consumed{}, false, err
		}
		if err := q.InsertMembership(ctx, query.InsertMembershipParams{
			OrganizationID: g.InviteOrganizationID.String, IdentityID: identityID, Role: g.InviteRole.String, CreatedAt: now,
		}); err != nil {
			return Consumed{}, false, err
		}
	} else if !g.SubjectIdentityID.Valid {
		identityID = ids.New(ids.Identity)
		if adminName == "" {
			adminName = "Installation Admin"
		}
		if err := q.InsertHumanIdentity(ctx, query.InsertHumanIdentityParams{ID: identityID, Name: adminName, InstallationAdmin: true, CreatedAt: now}); err != nil {
			return Consumed{}, false, err
		}
	}
	if g.Kind == GrantBootstrap {
		if err := q.MarkInstallationBootstrapped(ctx, sql.NullInt64{Int64: now, Valid: true}); err != nil {
			return Consumed{}, false, err
		}
	}
	eventType := map[string]string{
		GrantBootstrap: "bootstrap.completed", GrantInvite: "invitation.accepted",
		GrantReenroll: "reenrollment.completed", GrantRecover: "recovery.completed",
	}[g.Kind]
	resource := jsvalue.Object{{Key: "identityId", Value: identityID}}
	if g.Kind == GrantInvite {
		resource = append(resource, jsvalue.Member{Key: "invitationId", Value: g.ID})
	}
	if _, err := audit.Record(ctx, tx, audit.Event{
		Type: eventType, Decision: audit.Info, ActorIdentityID: &identityID,
		OrganizationID: ptrStr(g.InviteOrganizationID), Resource: resource,
	}); err != nil {
		return Consumed{}, false, err
	}
	return Consumed{IdentityID: identityID, Kind: g.Kind, GrantID: g.ID}, true, nil
}

// ConsumeForCLICredential is the admin commands' headless path
// (--cli-credential): consume a grant just issued and issue a CLI
// credential for its identity, both in one write job.
func (s *Service) ConsumeForCLICredential(ctx context.Context, token, adminName, credentialName string) (Consumed, Issued, error) {
	var c Consumed
	var issued Issued
	rejected := false
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		rejected = false
		now := s.micros()
		var ok bool
		var err error
		c, ok, err = consumeSetupGrant(ctx, tx, now, token, adminName)
		if err != nil {
			return err
		}
		if !ok {
			rejected = true
			return nil
		}
		issued, err = IssueCredential(ctx, tx, now, Issue{IdentityID: c.IdentityID, Kind: KindCLI, Name: &credentialName})
		return err
	})
	if err == nil && rejected {
		err = s.rejectSetupGrant(ctx)
	}
	return c, issued, err
}

// invitationOrganizationLive reports whether an invitation's Organization
// takes writes: it exists and is not deleted, has no open deletion
// (refuseIfFrozen), and is not frozen for an incident
// (refuseIfIncidentFrozen, no exception).
func invitationOrganizationLive(ctx context.Context, tx query.DBTX, organizationID string) (bool, error) {
	q := query.New(tx)
	if _, err := q.LiveOrganization(ctx, organizationID); errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if _, err := q.OpenOrganizationDeletion(ctx, organizationID); err == nil {
		return false, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if err := authz.RefuseIfIncidentFrozen(ctx, tx, organizationID, ""); err != nil {
		var frozen *authz.FrozenError
		if errors.As(err, &frozen) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
