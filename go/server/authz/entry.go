// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"context"

	"github.com/varlatch/varlatch/go/server/db/query"
)

// EntryLinkCreate is the action that lets a machine identity make an entry
// link (ADR-0063): a link a person enters one Secret's value with, once.
// EntryLinkCreateOpen is the same for a link anyone who holds it may use,
// and nothing else: neither holds the other.
//
// Like CapabilityIssue they are not among Actions: no built-in role holds
// them, so each is an explicit Grant, and they count for machines that run
// on their own, never for an Agent or a person. They read nothing, reveal
// nothing and overwrite nothing: a link that replaces a value needs
// config.value.write too. A person makes links with config.value.write.
const (
	EntryLinkCreate     = "entry-link.create"
	EntryLinkCreateOpen = "entry-link.create-open"
	valueWrite          = "config.value.write"
)

// EntryLinkAction is the action that a link needs of an identity of this
// kind: open is whether anyone who holds it may use it.
func EntryLinkAction(kind string, open bool) string {
	switch {
	case kind == "human":
		return valueWrite
	case open:
		return EntryLinkCreateOpen
	}
	return EntryLinkCreate
}

// DecideEntryLink decides the action a link needs of p on a resource.
func DecideEntryLink(ctx context.Context, db query.DBTX, p Principal, open bool, r Resource, opts Options) (Decision, error) {
	if p.human() {
		return Decide(ctx, db, p, valueWrite, r, opts)
	}
	return decideForMachines(ctx, db, p, EntryLinkAction(p.IdentityKind, open), r, opts)
}
