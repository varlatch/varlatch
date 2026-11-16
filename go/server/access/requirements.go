// SPDX-License-Identifier: AGPL-3.0-or-later

package access

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// Tailnet Requirements (ADR-0014, ADR-0046's data): restrictive policy
// objects, changed in place (ADR-0029) and revoked, the change and the
// revocation protected by requirement-protection (ADR-0054 Decision 5;
// requirementprotection.ts). A target is a tier or Environments; a
// selector a tailnet and the tags, users and nodes any of which satisfies
// it. Both are stored as jsonb stores them, and read back in its order.

// Requirement is a live Requirement as stored.
type Requirement struct {
	ID        string
	Kind      string
	Target    jsvalue.Object
	Selector  jsvalue.Object
	CreatedAt int64
	Version   int64
	UpdatedAt sql.NullInt64
}

// JS is the Requirement as listRequirements and updateRequirement give it.
func (r Requirement) JS() jsvalue.Object {
	return jsvalue.Object{
		{Key: "id", Value: r.ID}, {Key: "kind", Value: r.Kind}, {Key: "target", Value: r.Target}, {Key: "selector", Value: r.Selector},
		{Key: "createdAt", Value: audit.ISOTime(r.CreatedAt)}, {Key: "version", Value: r.Version}, {Key: "updatedAt", Value: isoNullable(r.UpdatedAt)},
	}
}

func parseObject(text string) (jsvalue.Object, error) {
	v, err := jsvalue.Parse([]byte(text))
	if err != nil {
		return nil, err
	}
	o, ok := v.(jsvalue.Object)
	if !ok {
		return nil, errors.New("access: a stored Requirement member is not an object")
	}
	return o, nil
}

func requirementOf(id, kind, target, config string, createdAt, version int64, updatedAt sql.NullInt64) (Requirement, error) {
	t, err := parseObject(target)
	if err != nil {
		return Requirement{}, err
	}
	s, err := parseObject(config)
	if err != nil {
		return Requirement{}, err
	}
	// As jsonb gives them back, whatever order the stored text has (a row
	// copied from PostgreSQL, or written by an earlier build).
	t, s = jsvalue.Jsonb(t).(jsvalue.Object), jsvalue.Jsonb(s).(jsvalue.Object)
	return Requirement{ID: id, Kind: kind, Target: t, Selector: s, CreatedAt: createdAt, Version: version, UpdatedAt: updatedAt}, nil
}

// Requirements is listRequirements: the live Requirements, oldest first.
func Requirements(ctx context.Context, db query.DBTX, organizationID string) ([]any, error) {
	rows, err := query.New(db).OrganizationRequirements(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		req, err := requirementOf(r.ID, r.Kind, r.Target, r.Config, r.CreatedAt, r.Version, r.UpdatedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, req.JS())
	}
	return out, nil
}

// ReadRequirement is readRequirement: a live Requirement of the
// Organization; nil when there is none.
func ReadRequirement(ctx context.Context, db query.DBTX, organizationID, requirementID string) (*Requirement, error) {
	if err := pgText(requirementID); err != nil {
		return nil, err
	}
	r, err := query.New(db).LiveRequirement(ctx, query.LiveRequirementParams{ID: requirementID, OrganizationID: organizationID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	req, err := requirementOf(r.ID, r.Kind, r.Target, r.Config, r.CreatedAt, r.Version, r.UpdatedAt)
	return &req, err
}

func requirementNotFound() error { return domainerr.New("RESOURCE_NOT_FOUND", "Requirement not found") }

func requirementConflict() error {
	return domainerr.New("VERSION_CONFLICT", "Requirement was modified concurrently; reload and retry")
}

// CheckSelector is the routes' selector check, after the schema: it names
// at least one tag, user or node.
func CheckSelector(selector jsvalue.Object) error {
	for _, key := range []string{"tags", "users", "nodes"} {
		if v, ok := selector.Get(key); ok {
			if list, _ := v.([]any); len(list) > 0 {
				return nil
			}
		}
	}
	return domainerr.New("VALIDATION_FAILED", "Selector must name at least one tag, user, or node")
}

// jsonbText is a target or selector as the jsonb column stores it, or the
// failure of the statement that would write it there.
func jsonbText(o jsvalue.Object) (string, error) {
	if err := jsvalue.JsonbRefuses(o); err != nil {
		return "", err
	}
	return string(jsvalue.Stringify(jsvalue.Jsonb(o))), nil
}

func tailnetOf(selector jsvalue.Object) any {
	v, _ := selector.Get("tailnet")
	return v
}

// CreateRequirement is POST …/requirements: a new Requirement only
// restricts, so it is never protected and runs as recovery while frozen.
// target and selector are zod's output; the answer echoes them.
func CreateRequirement(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID string, target, selector jsvalue.Object, now func() time.Time) (jsvalue.Object, []auth.PendingReport, error) {
	actor := p.Identity.ID
	id := ids.New(ids.Requirement)
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(organizationID, write.Shared), write.Person(actor, write.Shared)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID, DuringFreeze: authz.DuringFreezeRecovery}); err != nil {
			return err
		}
		var err error
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return err
		}
		targetText, err := jsonbText(target)
		if err != nil {
			return err
		}
		configText, err := jsonbText(selector)
		if err != nil {
			return err
		}
		if err := query.New(tx).InsertRequirement(ctx, query.InsertRequirementParams{
			ID: id, OrganizationID: organizationID, Target: targetText, Config: configText,
			CreatedBy: sql.NullString{String: actor, Valid: true}, CreatedAt: now().UnixMicro(),
		}); err != nil {
			return err
		}
		action := "policy.manage"
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "requirement.created", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "requirementId", Value: id}},
			Metadata: jsvalue.Object{{Key: "kind", Value: "tailnet"}, {Key: "tailnet", Value: tailnetOf(selector)}},
		})
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return jsvalue.Object{
		{Key: "id", Value: id}, {Key: "kind", Value: "tailnet"}, {Key: "target", Value: target}, {Key: "selector", Value: selector},
		{Key: "version", Value: int64(1)}, {Key: "updatedAt", Value: nil},
	}, reports, nil
}

// RequirementPatch is updateRequirement's body: the version it expects,
// and the target and selector it sets (nil: unchanged), as zod gives them.
type RequirementPatch struct {
	ExpectedVersion int64
	Target          jsvalue.Object
	Selector        jsvalue.Object
	// Body is zod's output, which the Idempotency-Key's digest covers.
	Body jsvalue.Object
}

// UpdateRequirement is PATCH …/requirements/{requirement} (ADR-0029): the
// Requirement changed in place, under an Idempotency-Key when the request
// has one. A protected operation (requirement.update) whose binding is the
// resulting target and selector in their bound form: a patch that means
// the same Requirement needs no approval, yet is written and counted as
// before (only one whose JSON text is unchanged answers the row as it is,
// and the patch's own text differs from jsonb's whenever it names a
// selector, as in TypeScript).
func UpdateRequirement(ctx context.Context, w *write.Writer, approvals *auth.Service, rootKEK []byte, req Request, organizationID, requirementID string, patch RequirementPatch, now func() time.Time) (write.Response, []auth.PendingReport, error) {
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	claim := write.Claim{IdentityID: actor, Endpoint: "PATCH requirements " + requirementID, Key: req.IdempotencyKey, Digest: write.BodyHash(patch.Body, rootKEK)}
	next := func(current Requirement) (jsvalue.Object, jsvalue.Object) {
		target, selector := current.Target, current.Selector
		if patch.Target != nil {
			target = patch.Target
		}
		if patch.Selector != nil {
			selector = patch.Selector
		}
		return target, selector
	}
	return idempotentProtected(ctx, w, r, organizationID, claim, func(ctx context.Context, tx *storage.Tx, reports *[]auth.PendingReport) (write.Response, error) {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID},
			Checks: []security.Check{{Control: security.RequirementProtection, Operation: "requirement.update"}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				current, err := ReadRequirement(ctx, db, organizationID, requirementID)
				if err == nil && current == nil {
					err = requirementNotFound()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				current, err := ReadRequirement(ctx, db, organizationID, requirementID)
				switch {
				case err != nil:
					return nil, err
				case current == nil:
					return nil, requirementNotFound()
				case current.Version != patch.ExpectedVersion:
					return nil, requirementConflict()
				}
				target, selector := next(*current)
				if SameRequirementState(current.Target, current.Selector, target, selector) {
					return nil, nil
				}
				return requirementUpdateBinding(ctx, db, organizationID, *current, target, selector, patch.ExpectedVersion)
			},
			AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return write.Response{}, err
		}
		*reports = p.Access
		row, err := ReadRequirement(ctx, tx, organizationID, requirementID)
		switch {
		case err != nil:
			return write.Response{}, err
		case row == nil:
			return write.Response{}, requirementNotFound()
		case row.Version != patch.ExpectedVersion:
			return write.Response{}, requirementConflict()
		}
		target, selector := next(*row)
		answer := func(version int64, updatedAt any) write.Response {
			return write.Response{Status: 200, Payload: jsvalue.Object{
				{Key: "id", Value: requirementID}, {Key: "kind", Value: row.Kind}, {Key: "target", Value: target}, {Key: "selector", Value: selector},
				{Key: "createdAt", Value: audit.ISOTime(row.CreatedAt)}, {Key: "version", Value: version}, {Key: "updatedAt", Value: updatedAt},
			}}
		}
		oldTarget, oldSelector := string(jsvalue.Stringify(row.Target)), string(jsvalue.Stringify(row.Selector))
		newTarget, newSelector := string(jsvalue.Stringify(target)), string(jsvalue.Stringify(selector))
		if newTarget == oldTarget && newSelector == oldSelector {
			return answer(row.Version, isoNullable(row.UpdatedAt)), nil
		}
		targetText, err := jsonbText(target)
		if err != nil {
			return write.Response{}, err
		}
		configText, err := jsonbText(selector)
		if err != nil {
			return write.Response{}, err
		}
		at := now().UnixMicro()
		updated, err := query.New(tx).UpdateRequirement(ctx, query.UpdateRequirementParams{
			Target: targetText, Config: configText, UpdatedAt: sql.NullInt64{Int64: at, Valid: true}, ID: requirementID,
		})
		if err != nil {
			return write.Response{}, err
		}
		if err := moveToEnd(ctx, tx, requirementID); err != nil {
			return write.Response{}, err
		}
		// Report mode (ADR-0054 Decision 9): an edit without an approval,
		// counted whether or not it means another Requirement.
		if err := p.Count(ctx, tx); err != nil {
			return write.Response{}, err
		}
		action := "policy.manage"
		md := jsvalue.Object{
			{Key: "oldTarget", Value: oldTarget}, {Key: "newTarget", Value: newTarget},
			{Key: "oldSelector", Value: oldSelector}, {Key: "newSelector", Value: newSelector},
			{Key: "version", Value: updated.Version},
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "requirement.updated", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "requirementId", Value: requirementID}}, Metadata: append(md, security.ApprovalMetadata(p.Approval)...),
		}); err != nil {
			return write.Response{}, err
		}
		return answer(updated.Version, isoNullable(updated.UpdatedAt)), nil
	})
}

// moveToEnd puts an updated Requirement last in the rowid order, where
// PostgreSQL's heap puts the updated row: loadTailnetRequirements reads
// without an ORDER BY, and the order shows in reach's conditions and in
// the Requirements an authorization event lists.
// sqlc models no rowid, so the statement is written here.
func moveToEnd(ctx context.Context, tx query.DBTX, requirementID string) error {
	_, err := tx.ExecContext(ctx, `UPDATE requirements SET rowid = (SELECT max(rowid) + 1 FROM requirements) WHERE id = ?`, requirementID)
	return err
}

func requirementChanged() error {
	return domainerr.New("STATE_CHANGED", "The Requirement changed while it was being removed; nothing was removed. Read it again and ask for a new approval")
}

// DeleteRequirement is DELETE …/requirements/{requirement}: a protected
// operation (requirement.revoke), bound to the version the server read and
// checked again before the revocation.
func DeleteRequirement(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID, requirementID string, now func() time.Time) ([]auth.PendingReport, error) {
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	var reports []auth.PendingReport
	err := w.Job(ctx, r.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID},
			Checks: []security.Check{{Control: security.RequirementProtection, Operation: "requirement.revoke"}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				current, err := ReadRequirement(ctx, db, organizationID, requirementID)
				if err == nil && current == nil {
					err = requirementNotFound()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				current, err := ReadRequirement(ctx, db, organizationID, requirementID)
				switch {
				case err != nil:
					return nil, err
				case current == nil:
					return nil, requirementNotFound()
				}
				return requirementRevokeBinding(ctx, db, organizationID, *current)
			},
			AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		locked, err := ReadRequirement(ctx, tx, organizationID, requirementID)
		switch {
		case err != nil:
			return err
		case locked == nil:
			return requirementNotFound()
		case p.Binding != nil && p.Binding.ExpectedVersion != nil && locked.Version != *p.Binding.ExpectedVersion:
			return requirementChanged()
		}
		if err := query.New(tx).RevokeRequirement(ctx, query.RevokeRequirementParams{RevokedAt: sql.NullInt64{Int64: now().UnixMicro(), Valid: true}, ID: requirementID}); err != nil {
			return err
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		action := "policy.manage"
		e := audit.Event{Type: "requirement.revoked", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "requirementId", Value: requirementID}}}
		if p.Approval != nil {
			e.Metadata = security.ApprovalMetadata(p.Approval)
		}
		_, err = audit.Record(ctx, tx, e)
		return err
	})
	return reports, err
}

// ---- requirement-protection's bindings (requirementprotection.ts)

func listOf(o jsvalue.Object, key string) []string {
	v, _ := o.Get(key)
	return stringList(v)
}

// normalizedRequirement is normalizedRequirement: the bound form, sets
// sorted and without duplicates, a left-out list as [].
func normalizedRequirement(target, selector jsvalue.Object) jsvalue.Object {
	var t jsvalue.Object
	if str(target, "kind") == "tier" {
		t = jsvalue.Object{{Key: "kind", Value: "tier"}, {Key: "tier", Value: str(target, "tier")}}
	} else {
		t = jsvalue.Object{{Key: "kind", Value: "environments"}, {Key: "environmentIds", Value: stringsJS(jsSet(listOf(target, "environmentIds")))}}
	}
	return jsvalue.Object{{Key: "target", Value: t}, {Key: "selector", Value: jsvalue.Object{
		{Key: "tailnet", Value: str(selector, "tailnet")},
		{Key: "tags", Value: stringsJS(jsSet(listOf(selector, "tags")))},
		{Key: "users", Value: stringsJS(jsSet(listOf(selector, "users")))},
		{Key: "nodes", Value: stringsJS(jsSet(listOf(selector, "nodes")))},
	}}}
}

// SameRequirementState is sameRequirementState: the same bound form.
func SameRequirementState(aTarget, aSelector, bTarget, bSelector jsvalue.Object) bool {
	return auth.CanonicalJSON(normalizedRequirement(aTarget, aSelector)) == auth.CanonicalJSON(normalizedRequirement(bTarget, bSelector))
}

// environmentNames is environmentNames: the Organization's environments
// among ids, as project/environment with the id; another id keeps none.
func environmentNames(ctx context.Context, db query.DBTX, organizationID string, ids []string) (map[string]string, error) {
	names := map[string]string{}
	if err := pgText(ids...); err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	err := inChunks(idsOf(set), func(chunk []string) error {
		rows, err := query.New(db).NamedEnvironments(ctx, query.NamedEnvironmentsParams{Ids: chunk, OrganizationID: organizationID})
		for _, r := range rows {
			names[r.ID] = security.LabelWithID("", jsString(r.Name), r.ID)
		}
		return err
	})
	return names, err
}

// jsString is a text column's value, whatever the driver gave for it.
func jsString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	}
	return ""
}

func describeTarget(target jsvalue.Object, names map[string]string) string {
	if str(target, "kind") == "tier" {
		return "the " + str(target, "tier") + " tier"
	}
	ids := listOf(target, "environmentIds")
	labels := make([]string, len(ids))
	for i, id := range ids {
		labels[i] = or(names, id, "environment")
	}
	return "environments " + security.LabelList(jsSet(labels))
}

func describeSelector(selector jsvalue.Object) string {
	n, _ := normalizedRequirement(jsvalue.Object{{Key: "kind", Value: "tier"}, {Key: "tier", Value: ""}}, selector).Get("selector")
	s := n.(jsvalue.Object)
	var parts []string
	for _, k := range []struct{ key, word string }{{"tags", "tags"}, {"users", "users"}, {"nodes", "nodes"}} {
		if list := listOf(s, k.key); len(list) > 0 {
			parts = append(parts, k.word+" "+security.QuotedList(list))
		}
	}
	joined := ""
	for i, p := range parts {
		if i > 0 {
			joined += "; "
		}
		joined += p
	}
	return "tailnet " + security.Quoted(str(s, "tailnet")) + ": " + joined
}

// targetLoosens is targetLoosens: another kind or tier, or an
// environment taken out.
func targetLoosens(before, after jsvalue.Object) bool {
	bk, ak := str(before, "kind"), str(after, "kind")
	if bk != ak {
		return true
	}
	if bk == "tier" {
		return str(before, "tier") != str(after, "tier")
	}
	if bk == "environments" {
		kept := listOf(after, "environmentIds")
		for _, id := range listOf(before, "environmentIds") {
			if !slices.Contains(kept, id) {
				return true
			}
		}
		return false
	}
	return true
}

// selectorLoosens is selectorLoosens: another tailnet, or a tag, user or
// node added.
func selectorLoosens(before, after jsvalue.Object) bool {
	if str(before, "tailnet") != str(after, "tailnet") {
		return true
	}
	for _, key := range []string{"tags", "users", "nodes"} {
		had := listOf(before, key)
		for _, v := range listOf(after, key) {
			if !slices.Contains(had, v) {
				return true
			}
		}
	}
	return false
}

func requirementUpdateBinding(ctx context.Context, db query.DBTX, organizationID string, current Requirement, target, selector jsvalue.Object, expected int64) (*auth.Binding, error) {
	var envIDs []string
	if str(current.Target, "kind") == "environments" {
		envIDs = append(envIDs, listOf(current.Target, "environmentIds")...)
	}
	if str(target, "kind") == "environments" {
		envIDs = append(envIDs, listOf(target, "environmentIds")...)
	}
	names, err := environmentNames(ctx, db, organizationID, envIDs)
	if err != nil {
		return nil, err
	}
	beforeTarget, afterTarget := describeTarget(current.Target, names), describeTarget(target, names)
	beforeSelector, afterSelector := describeSelector(current.Selector), describeSelector(selector)
	var changes []auth.ApprovalChange
	if beforeTarget != afterTarget {
		changes = append(changes, auth.ApprovalChange{Field: "target", From: &beforeTarget, To: &afterTarget, Loosens: targetLoosens(current.Target, target)})
	}
	if beforeSelector != afterSelector {
		changes = append(changes, auth.ApprovalChange{Field: "selector", From: &beforeSelector, To: &afterSelector, Loosens: selectorLoosens(current.Selector, selector)})
	}
	return binding("requirement.update", organizationID, map[string]string{"requirementId": current.ID}, normalizedRequirement(target, selector), &expected,
		auth.ApprovalSummary{Title: "Change the Tailnet Requirement " + current.ID + " on " + beforeTarget, Changes: changes}), nil
}

func requirementRevokeBinding(ctx context.Context, db query.DBTX, organizationID string, current Requirement) (*auth.Binding, error) {
	var envIDs []string
	if str(current.Target, "kind") == "environments" {
		envIDs = listOf(current.Target, "environmentIds")
	}
	names, err := environmentNames(ctx, db, organizationID, envIDs)
	if err != nil {
		return nil, err
	}
	version := current.Version
	return binding("requirement.revoke", organizationID, map[string]string{"requirementId": current.ID}, nil, &version, auth.ApprovalSummary{
		Title: "Remove the Tailnet Requirement " + current.ID + " on " + describeTarget(current.Target, names) + " (" + describeSelector(current.Selector) + "). What it constrained is no longer constrained",
	}), nil
}
