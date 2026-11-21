// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
)

// Unauthenticated is the answer for a credential that is not active: the
// request is refused before any authorization (decision 8's credential
// states).
const Unauthenticated = "UNAUTHENTICATED"

// authorization is the authorization differential (decision 8): every
// decision of the bundle's table evaluated again on the target, by
// varlatchd's evaluator, and the answers compared. The decisions are
// streamed, never held whole.
func (c *checker) authorization(ctx context.Context, r *bundle.Reader) error {
	n, _, err := r.Decisions()
	if err != nil {
		return err
	}
	if n == 0 {
		// No decision table where credentials can act: nothing would be
		// held, which is no pass.
		var live int
		if err := c.db.QueryRowContext(ctx, "SELECT count(*) FROM credentials WHERE revoked_at IS NULL").Scan(&live); err != nil {
			return err
		}
		if live > 0 {
			c.fail(Authorization, "", "", "the bundle holds no decision table; the target has %d live credentials", live)
		}
	}
	for i := 1; i <= n; i++ {
		d, err := r.Decision()
		if err != nil {
			return err
		}
		c.checked(Authorization, 1)
		got, err := Evaluate(ctx, c.db, d)
		var missing *MissingError
		if errors.As(err, &missing) {
			c.fail(Authorization, missing.Table, "", "decision %d: %s %s is not in the target", i, missing.Table, missing.ID)
			continue
		}
		if err != nil {
			return fmt.Errorf("check: decision %d: %w", i, err)
		}
		if got.Allowed != d.Allowed || got.Code != d.Code {
			c.fail(Authorization, "", "", "decision %d: %s (%s) %s on %s: the source %s, the target %s",
				i, d.Credential, d.State, d.Action, resourceName(d), answer(d), answer(got))
		}
	}
	return nil
}

func answer(d bundle.Decision) string {
	if d.Allowed {
		return "allows"
	}
	return "denies (" + d.Code + ")"
}

func resourceName(d bundle.Decision) string {
	switch {
	case d.Environment != "":
		return d.Environment
	case d.Project != "":
		return d.Project
	}
	return d.Organization
}

// MissingError is a decision naming a credential or an environment the
// target does not have.
type MissingError struct {
	Table, ID string
}

func (e *MissingError) Error() string {
	return fmt.Sprintf("%s %s is not in the database", e.Table, e.ID)
}

// Evaluate answers one decision on db: d with Allowed and Code set as
// varlatchd decides it. A credential that is not active is refused before
// authorization (UNAUTHENTICATED); an active one is its identity, deciding
// with authz.Decide on the resource the decision names (an environment's
// root and tier read from db), with the decision's Tailnet Context.
func Evaluate(ctx context.Context, db *sql.DB, d bundle.Decision) (bundle.Decision, error) {
	var identity, kind string
	var org sql.NullString
	err := db.QueryRowContext(ctx, `SELECT c.identity_id, i.kind, i.organization_id FROM credentials c JOIN identities i ON i.id = c.identity_id WHERE c.id = ?`,
		d.Credential).Scan(&identity, &kind, &org)
	if errors.Is(err, sql.ErrNoRows) {
		return d, &MissingError{Table: "credentials", ID: d.Credential}
	}
	if err != nil {
		return d, err
	}
	if d.State != bundle.Active {
		d.Allowed, d.Code = false, Unauthenticated
		return d, nil
	}
	res := authz.Resource{OrganizationID: d.Organization, ProjectID: d.Project}
	if d.Environment != "" {
		var parent sql.NullString
		var tier string
		err := db.QueryRowContext(ctx, "SELECT parent_environment_id, tier FROM environments WHERE id = ?", d.Environment).Scan(&parent, &tier)
		if errors.Is(err, sql.ErrNoRows) {
			return d, &MissingError{Table: "environments", ID: d.Environment}
		}
		if err != nil {
			return d, err
		}
		root := d.Environment
		if parent.Valid {
			root = parent.String
		}
		res.Environment = &authz.Environment{ID: d.Environment, RootID: root, Tier: tier}
	}
	p := authz.Principal{IdentityID: identity, IdentityKind: kind, CredentialID: d.Credential}
	if kind != "human" {
		p.OrganizationID = org.String
	}
	var tc *authz.TailnetContext
	if d.Tailnet != nil {
		tc = &authz.TailnetContext{Tailnet: d.Tailnet.Tailnet, NodeID: d.Tailnet.NodeID, Tags: d.Tailnet.Tags, UserLogin: d.Tailnet.UserLogin}
	}
	dec, err := authz.Decide(ctx, db, p, d.Action, res, authz.Options{TailnetContext: tc})
	if err != nil {
		return d, err
	}
	d.Allowed, d.Code = dec.Allowed, ""
	if !dec.Allowed {
		d.Code = "PERMISSION_DENIED"
		if dec.Err != nil {
			d.Code = dec.Err.Code
		}
	}
	return d, nil
}
