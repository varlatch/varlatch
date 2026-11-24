// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"

	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Entry links (ADR-0063, go/server/entry) end with the credential they were
// made with. A machine's is looked at when a link is used. A person's is
// not: their bearers and CLI logins end all the time in the ordinary way (a
// bearer lives 15 minutes, a browser signs out, `varlatch logout` revokes its
// own credential), and that ends no link they sent. What ends them is taking
// a session away, which is known only while it happens, so it ends the links
// in its own job: revoking a credential with another one, and losing the
// membership. Which login a link was made with is not asked then: whoever had
// one may have given it up themselves.

// EntryLinkCredentialEnded is the reason of a link that ended with its
// credential.
const EntryLinkCredentialEnded = "credential-ended"

// EntryLinkResource is a link in the audit log. Its secret, and what that is
// hashed to, are in no event.
func EntryLinkResource(l query.EntryLink) jsvalue.Object {
	return jsvalue.Object{{Key: "entryLinkId", Value: l.ID}, {Key: "projectId", Value: l.ProjectID}, {Key: "environmentId", Value: l.EnvironmentID},
		{Key: "itemName", Value: l.ItemName}}
}

// recordEndedEntryLinks records the links a withdrawal ended.
func recordEndedEntryLinks(ctx context.Context, tx query.DBTX, links []query.EntryLink, actor string) error {
	for _, l := range links {
		_, err := audit.Record(ctx, tx, audit.Event{
			Type: "capability.revoked", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &l.OrganizationID,
			Resource: append(EntryLinkResource(l), jsvalue.Member{Key: "issuedByIdentityId", Value: l.RequestedBy}),
			Metadata: jsvalue.Object{{Key: "entryLink", Value: l.RestrictedTo}, {Key: "reason", Value: EntryLinkCredentialEnded}},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// endEntryLinksOfPerson ends, in the job that revokes a person's credential
// from elsewhere, all the person's links but those of the credential, or the
// browser session, it is revoked with. A credential that revokes itself signs
// out and withdraws nothing.
func endEntryLinksOfPerson(ctx context.Context, tx query.DBTX, now int64, p *Principal, credentialID string) error {
	if p.Identity.Kind != "human" || credentialID == p.Credential.ID {
		return nil
	}
	links, err := query.New(tx).EndEntryLinksOfPerson(ctx, query.EndEntryLinksOfPersonParams{
		Now: now, RequestedBy: p.Identity.ID, RevokedWith: p.Credential.ID,
	})
	if err != nil {
		return err
	}
	return recordEndedEntryLinks(ctx, tx, links, p.Identity.ID)
}

// EndEntryLinksOfMember ends, in the job that ends a membership, the links
// the person made there: they stay ended if the person is added again.
func EndEntryLinksOfMember(ctx context.Context, tx query.DBTX, now int64, organizationID, identityID, actorID string) error {
	links, err := query.New(tx).EndEntryLinksOfMember(ctx, query.EndEntryLinksOfMemberParams{Now: now, RequestedBy: identityID, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	return recordEndedEntryLinks(ctx, tx, links, actorID)
}
