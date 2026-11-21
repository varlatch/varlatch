// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/server/migration/canonical"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
)

// authState is the authentication state the authentication check reads,
// table by table (source names): what decides who can sign in, with what,
// until when. Each source row is looked up in the target by its key, on its
// own, and these columns compared.
var authState = map[string][]string{
	"identities":         {"kind", "disabled", "organization_id", "installation_admin", "suspended_by_deletion"},
	"user":               {"email", "emailVerified"},
	"auth_user_links":    {"identity_id"},
	"passkey":            {"userId", "credentialID", "publicKey", "counter", "deviceType", "backedUp", "transports"},
	"passkey_provenance": {"trust", "trusted_via", "trusted_at", "setup_grant_kind", "confirmed_by_passkey_id"},
	"credentials":        {"identity_id", "kind", "token_hash", "expires_at", "revoked_at", "max_uses", "auth_session_id"},
	"oidc_bindings":      {"identity_id", "organization_id", "issuer", "audience", "subject", "claims", "revoked_at"},
	"setup_grants":       {"kind", "subject_identity_id", "token_hash", "expires_at", "consumed_at", "revoked_at"},
	"device_sign_ins":    {"device_code_hash", "status", "expires_at", "approved_by_identity_id", "issued_credential_id"},
}

// authenticationRow is the authentication check of one source row: the
// target's row with the same key, and the same state.
func (c *checker) authenticationRow(ctx context.Context, t manifest.Table, v []any) error {
	cols, ok := authState[t.Source]
	if !ok {
		return nil
	}
	c.checked(Authentication, 1)
	if c.authnSeen == nil {
		c.authnSeen = map[string]int{}
	}
	c.authnSeen[t.Source]++
	where := make([]string, len(t.OrderBy))
	args := make([]any, len(t.OrderBy))
	for i, k := range t.OrderBy {
		where[i] = ident(targetColumn(t.Columns[column(t, k)])) + " = ?"
		args[i] = normalize(v[column(t, k)])
	}
	sel := make([]string, len(cols))
	for i, col := range cols {
		sel[i] = ident(targetColumn(t.Columns[column(t, col)]))
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	name := keyName(t, v)
	err := c.db.QueryRowContext(ctx, "SELECT "+strings.Join(sel, ", ")+" FROM "+ident(targetTable(t))+" WHERE "+strings.Join(where, " AND "), args...).Scan(ptrs...)
	if errors.Is(err, sql.ErrNoRows) {
		c.fail(Authentication, t.Source, "", "%s is missing", name)
		return nil
	}
	if err != nil {
		return err
	}
	var changed []string
	for i, col := range cols {
		k := column(t, col)
		got := vals[i]
		if t.Source == "credentials" && col == "revoked_at" {
			id, _ := v[column(t, "id")].(string)
			if at, ok := c.revoked[id]; ok && v[k] == nil {
				// Revoked by the migration: expected at its event's moment.
				if g, isInt := got.(int64); isInt && g == at {
					got = nil
				}
			}
		}
		a, errA := canonical.AppendValue(nil, t.Columns[k].Type, got)
		b, errB := canonical.AppendValue(nil, t.Columns[k].Type, v[k])
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			changed = append(changed, col)
		}
	}
	if len(changed) > 0 {
		c.fail(Authentication, t.Source, "", "%s: %s changed", name, strings.Join(changed, ", "))
	}
	return nil
}

// authenticationEnd is the rest of the authentication check: no row of
// these tables the source does not have, no session kept, and every live
// browser credential of a session the migration ended revoked (by the
// trigger, at installation.migrated's moment or before it).
func (c *checker) authenticationEnd(ctx context.Context) error {
	tables := make([]string, 0, len(authState))
	for s := range authState {
		tables = append(tables, s)
	}
	slices.Sort(tables)
	for _, s := range tables {
		t, ok := c.m.Table(s)
		if !ok {
			return errors.New("check: the manifest has no table " + s)
		}
		var n int
		if err := c.db.QueryRowContext(ctx, "SELECT count(*) FROM "+ident(targetTable(t))).Scan(&n); err != nil {
			return err
		}
		if n > c.authnSeen[s] {
			c.fail(Authentication, s, "", "%d rows the source does not have", n-c.authnSeen[s])
		}
	}
	if c.o.Reverse && len(c.sessions) > 0 {
		c.fail(Authentication, "session", "", "the rebuilt installation holds %d browser sessions; it starts with none", len(c.sessions))
	}
	var sessions int
	if err := c.db.QueryRowContext(ctx, "SELECT count(*) FROM auth_sessions").Scan(&sessions); err != nil {
		return err
	}
	if sessions != 0 {
		c.fail(Authentication, "session", "", "%d browser sessions kept; every session ends in the migration", sessions)
	}
	ids := make([]string, 0, len(c.browser))
	for id := range c.browser {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if c.migratedAt == 0 || !c.ends(id, c.migratedAt) {
			continue
		}
		var revoked sql.NullInt64
		err := c.db.QueryRowContext(ctx, "SELECT revoked_at FROM credentials WHERE id = ?", id).Scan(&revoked)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if !revoked.Valid || revoked.Int64 > c.migratedAt {
			c.fail(Authentication, "credentials", "", "%s, a browser credential of an ended session, is not revoked", id)
		}
	}
	return nil
}
