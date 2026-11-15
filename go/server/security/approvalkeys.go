// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"context"
	"slices"
	"time"

	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// ApprovalKeys is approvalKeys (ADR-0054 Decisions 4 and 11): for each
// live admin of the Organization (a live admin membership of a person who
// is not disabled), which of their passkeys are trusted and which are
// unconfirmed. Metadata only: a passkey's name, provenance and dates, never
// its credential id, public key or counter, and no passkey ids. A passkey
// without a provenance row counts as unconfirmed.
//
// Admins come in the order of their names, then ids (byte order, as the
// test databases' C collation sorts them); within an admin, trusted
// passkeys first, oldest first within each.
func ApprovalKeys(ctx context.Context, db query.DBTX, organizationID string, now func() time.Time) (jsvalue.Object, error) {
	rows, err := query.New(db).AdminApprovalKeys(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	type key struct {
		trusted bool
		value   jsvalue.Object
	}
	type admin struct {
		id, name             string
		trusted, unconfirmed int64
		lastConfirmed        int64
		keys                 []key
	}
	var admins []*admin
	byID := map[string]*admin{}
	for _, r := range rows {
		a := byID[r.IdentityID]
		if a == nil {
			a = &admin{id: r.IdentityID, name: r.IdentityName}
			byID[r.IdentityID] = a
			admins = append(admins, a)
		}
		if !r.PasskeyID.Valid {
			continue
		}
		trusted := r.Trust.Valid && r.Trust.String == "trusted"
		trust := "unconfirmed"
		var name, via, createdAt, trustedAt any
		if r.PasskeyName.Valid {
			name = r.PasskeyName.String
		}
		if r.CreatedAt.Valid {
			createdAt = audit.ISOTime(r.CreatedAt.Int64)
		}
		if trusted {
			trust = "trusted"
			if r.TrustedVia.Valid {
				via = r.TrustedVia.String
			}
			if r.TrustedAt.Valid {
				trustedAt = audit.ISOTime(r.TrustedAt.Int64)
			}
			a.trusted++
			// The latest confirmation by a trusted passkey, compared as the
			// ISO strings TypeScript compares (millisecond precision).
			if r.TrustedVia.String == "confirmed" && r.TrustedAt.Valid {
				if a.lastConfirmed == 0 || audit.ISOTime(r.TrustedAt.Int64) > audit.ISOTime(a.lastConfirmed) {
					a.lastConfirmed = r.TrustedAt.Int64
				}
			}
		} else {
			a.unconfirmed++
		}
		a.keys = append(a.keys, key{trusted: trusted, value: jsvalue.Object{
			{Key: "name", Value: name}, {Key: "trust", Value: trust}, {Key: "trustedVia", Value: via},
			{Key: "createdAt", Value: createdAt}, {Key: "trustedAt", Value: trustedAt},
		}})
	}
	items := make([]any, 0, len(admins))
	withTrusted := int64(0)
	for _, a := range admins {
		// Stable: trusted first, keeping the oldest-first order within each.
		slices.SortStableFunc(a.keys, func(x, y key) int {
			switch {
			case x.trusted == y.trusted:
				return 0
			case x.trusted:
				return -1
			}
			return 1
		})
		keys := make([]any, len(a.keys))
		for i, k := range a.keys {
			keys[i] = k.value
		}
		var last any
		if a.lastConfirmed != 0 {
			last = audit.ISOTime(a.lastConfirmed)
		}
		if a.trusted > 0 {
			withTrusted++
		}
		items = append(items, jsvalue.Object{
			{Key: "identity", Value: jsvalue.Object{{Key: "id", Value: a.id}, {Key: "name", Value: a.name}}},
			{Key: "trusted", Value: a.trusted}, {Key: "unconfirmed", Value: a.unconfirmed},
			{Key: "lastConfirmedAt", Value: last}, {Key: "passkeys", Value: keys},
		})
	}
	n := int64(len(admins))
	return jsvalue.Object{
		{Key: "generatedAt", Value: audit.ISOTime(now().UnixMicro())},
		{Key: "summary", Value: jsvalue.Object{{Key: "admins", Value: n}, {Key: "withTrustedKey", Value: withTrusted}, {Key: "withoutTrustedKey", Value: n - withTrusted}}},
		{Key: "items", Value: items},
	}, nil
}
