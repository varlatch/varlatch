// SPDX-License-Identifier: AGPL-3.0-or-later

// Package contracts is a Project's Configuration Contract revisions (the
// TypeScript domain/contracts.ts, ADR-0013; ADR-0059 step 4.1b): pushing a
// candidate revision (re-normalized and hashed by the server, deduplicated
// by content hash, never activated implicitly), activating one (a
// distinct, audited operation, with the semantic diff against what it
// replaces), and reading them. The Contract model is go/lib/contract. Each
// write is one job of the single writer, its gates taken before
// (go/server/write).
package contracts

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// FromJS is a JSON value as varlatchd's reader holds it (jsvalue), in
// go/lib/contract's model; a lone surrogate stays as it is.
func FromJS(v any) any {
	switch x := v.(type) {
	case jsvalue.Object:
		o := make(contract.Object, len(x))
		for i, m := range x {
			o[i] = contract.Member{Key: m.Key, Value: FromJS(m.Value)}
		}
		return o
	case []any:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = FromJS(e)
		}
		return a
	}
	return v
}

// toJS is go/lib/contract's model as a jsvalue, for storage and audit.
func toJS(v any) any {
	switch x := v.(type) {
	case contract.Object:
		o := make(jsvalue.Object, len(x))
		for i, m := range x {
			o[i] = jsvalue.Member{Key: m.Key, Value: toJS(m.Value)}
		}
		return o
	case []any:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = toJS(e)
		}
		return a
	}
	return v
}

// invalid is normalizeOrReject's refusal: CONTRACT_INVALID with the issues.
func invalid(err error) error {
	var ve *contract.ValidationError
	if !errors.As(err, &ve) {
		return err
	}
	issues := make([]any, len(ve.Issues))
	for i, s := range ve.Issues {
		issues[i] = s
	}
	return &domainerr.Error{Code: "CONTRACT_INVALID", Message: ve.Error(), Details: jsvalue.Object{{Key: "issues", Value: issues}}}
}

// stored reads a stored JSON column as the TypeScript server reads its
// jsonb: members in jsonb's order, as JSON.parse enumerates them.
func stored(text string) (any, error) {
	v, err := jsvalue.Parse([]byte(text))
	if err != nil {
		return nil, err
	}
	return jsvalue.JSOrder(jsvalue.Jsonb(v)), nil
}

// jsonbText is a value as a jsonb column holds it.
func jsonbText(v any) string { return string(jsvalue.Stringify(jsvalue.Jsonb(v))) }

// versionOf is semanticsVersionOf a stored Contract: absent means 1.
func versionOf(text string) (int, error) {
	v, err := stored(text)
	if err != nil {
		return 0, err
	}
	o, _ := v.(jsvalue.Object)
	if n, ok := o.Get("semanticsVersion"); ok {
		if f, ok := n.(float64); ok {
			return int(f), nil
		}
	}
	return 1, nil
}

// RevisionJS is serialize.revision: the revision as the API answers it,
// active when it is the Project's active one.
func RevisionJS(r query.ContractRevision, activeID string) (jsvalue.Object, error) {
	c, err := stored(r.Contract)
	if err != nil {
		return nil, err
	}
	version, err := versionOf(r.Contract)
	if err != nil {
		return nil, err
	}
	out := jsvalue.Object{
		{Key: "id", Value: r.ID}, {Key: "projectId", Value: r.ProjectID}, {Key: "contentHash", Value: r.ContentHash},
		{Key: "semanticsVersion", Value: version}, {Key: "active", Value: r.ID == activeID}, {Key: "contract", Value: c},
	}
	if r.Provenance.Valid {
		p, err := stored(r.Provenance.String)
		if err != nil {
			return nil, err
		}
		if p != nil {
			out = append(out, jsvalue.Member{Key: "provenance", Value: p})
		}
	}
	return append(out, jsvalue.Member{Key: "createdAt", Value: audit.ISOTime(r.CreatedAt)}), nil
}

// Get is getRevision: the Project's revision, or RESOURCE_NOT_FOUND.
func Get(ctx context.Context, db query.DBTX, projectID, revisionID string) (query.ContractRevision, error) {
	r, err := query.New(db).ContractRevision(ctx, query.ContractRevisionParams{ID: revisionID, ProjectID: projectID})
	if errors.Is(err, sql.ErrNoRows) {
		return r, domainerr.NotFound("Contract revision")
	}
	return r, err
}

// Push is pushRevision (ADR-0013, ADR-0038 Decision 3). The Contract is
// normalized before anything else; one that names its semantics version
// pins it, otherwise the revision keeps the active revision's version (a
// project without one gets the newest), checked again in the job. In one
// job behind the Organization's and the requester's gates: the writer's
// checks (Organization and Project live), the passkey-verification
// checkpoint, the version, deduplication by content hash (an existing
// revision is answered as it is, with no event), then the revision and
// contract.revision_pushed. It returns the report counts to record once
// the request succeeds.
func Push(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, projectID string, input any, provenance jsvalue.Object) (query.ContractRevision, []auth.PendingReport, error) {
	in := FromJS(input)
	o, isObject := in.(contract.Object)
	pinned := false
	if isObject {
		for _, m := range o {
			if m.Key == "semanticsVersion" {
				pinned = true
			}
		}
	}
	pushed, err := contract.Normalize(in, contract.Options{VersionUndecided: !pinned})
	if err != nil {
		return query.ContractRevision{}, nil, invalid(err)
	}
	var rev query.ContractRevision
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(organizationID, write.Shared), write.Person(p.Identity.ID, write.Shared)}
	err = w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID, ProjectID: projectID}); err != nil {
			return err
		}
		var err error
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return err
		}
		q := query.New(tx)
		c := pushed
		if !pinned {
			version := contract.LatestSemanticsVersion
			active, err := q.ActiveContractRevisionID(ctx, projectID)
			if err != nil {
				return err
			}
			if active.Valid {
				if r, err := Get(ctx, tx, projectID, active.String); err == nil {
					if version, err = versionOf(r.Contract); err != nil {
						return err
					}
				} else if !isNotFound(err) {
					return err
				}
			}
			v := pushed.Value()
			v = append(v[:1], append(contract.Object{{Key: "semanticsVersion", Value: float64(version)}}, v[1:]...)...)
			if c, err = contract.Normalize(v, contract.Options{}); err != nil {
				return invalid(err)
			}
		}
		hash := c.Hash()
		existing, err := q.ContractRevisionByHash(ctx, query.ContractRevisionByHashParams{ProjectID: projectID, ContentHash: hash})
		if err == nil {
			rev = existing
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		body := toJS(c.Value())
		// jsonb refuses what PostgreSQL refuses (U+0000, a lone surrogate):
		// the insert fails there, so the request fails here.
		if err := jsvalue.JsonbRefuses(body); err != nil {
			return err
		}
		var prov sql.NullString
		if provenance != nil {
			if err := jsvalue.JsonbRefuses(provenance); err != nil {
				return err
			}
			prov = sql.NullString{String: jsonbText(provenance), Valid: true}
		}
		id := ids.New("rev")
		actor := p.Identity.ID
		if err := q.InsertContractRevision(ctx, query.InsertContractRevisionParams{
			ID: id, ProjectID: projectID, ContentHash: hash, Contract: jsonbText(body), Provenance: prov,
			CreatedBy: sql.NullString{String: actor, Valid: true},
		}); err != nil {
			return err
		}
		action := "contract.submit"
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "contract.revision_pushed", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "projectId", Value: projectID}, {Key: "contractRevisionId", Value: id}},
			Metadata: jsvalue.Object{{Key: "contentHash", Value: hash}, {Key: "itemCount", Value: len(c.Items)}, {Key: "semanticsVersion", Value: c.Version()}},
		}); err != nil {
			return err
		}
		rev, err = Get(ctx, tx, projectID, id)
		return err
	})
	if err != nil {
		return query.ContractRevision{}, nil, err
	}
	return rev, reports, nil
}

func isNotFound(err error) bool {
	var de *domainerr.Error
	return errors.As(err, &de) && de.Code == "RESOURCE_NOT_FOUND"
}

// parsed is a stored revision's Contract in go/lib/contract's model.
func parsed(r query.ContractRevision) (contract.Contract, error) {
	v, err := contract.ParseJSON([]byte(r.Contract))
	if err != nil {
		return contract.Contract{}, err
	}
	return contract.Normalize(v, contract.Options{})
}

// Activate is activateRevision (ADR-0013): in one job behind the
// Organization's and the requester's gates, the writer's checks, the
// Project's active revision read in the job (so two activations each diff
// against what they replace), the revision (RESOURCE_NOT_FOUND before the
// passkey-verification checkpoint, as there), the diff's summary, the
// update and contract.activated.
func Activate(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, projectID, revisionID string) (query.ContractRevision, []auth.PendingReport, error) {
	var rev query.ContractRevision
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(organizationID, write.Shared), write.Person(p.Identity.ID, write.Shared)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID, ProjectID: projectID}); err != nil {
			return err
		}
		q := query.New(tx)
		active, err := q.ActiveContractRevisionID(ctx, projectID)
		if err != nil {
			return err
		}
		if rev, err = Get(ctx, tx, projectID, revisionID); err != nil {
			return err
		}
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return err
		}
		summary := jsvalue.Object{{Key: "initial", Value: true}}
		if active.Valid {
			prev, err := q.ContractRevision(ctx, query.ContractRevisionParams{ID: active.String, ProjectID: projectID})
			if err == nil {
				from, err := parsed(prev)
				if err != nil {
					return err
				}
				to, err := parsed(rev)
				if err != nil {
					return err
				}
				d := contract.DiffContracts(from, to)
				names := func(cs []string) string { return strings.Join(cs, ",") }
				var sens, req []string
				for _, c := range d.SensitivityChanged {
					sens = append(sens, c.Name)
				}
				for _, c := range d.RequirednessChanged {
					req = append(req, c.Name)
				}
				summary = jsvalue.Object{
					{Key: "initial", Value: false}, {Key: "securityRelevant", Value: d.SecurityRelevant},
					{Key: "itemsAdded", Value: len(d.ItemsAdded)}, {Key: "itemsRemoved", Value: len(d.ItemsRemoved)},
					{Key: "sensitivityChanged", Value: names(sens)}, {Key: "requirednessChanged", Value: names(req)},
				}
				if sv := d.SemanticsVersionChanged; sv != nil {
					summary = append(summary, jsvalue.Member{Key: "semanticsVersionFrom", Value: sv[0]}, jsvalue.Member{Key: "semanticsVersionTo", Value: sv[1]})
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		if err := q.ActivateContractRevision(ctx, query.ActivateContractRevisionParams{ActiveContractRevisionID: sql.NullString{String: rev.ID, Valid: true}, ID: projectID}); err != nil {
			return err
		}
		actor, action := p.Identity.ID, "contract.activate"
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "contract.activated", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "projectId", Value: projectID}, {Key: "contractRevisionId", Value: rev.ID}},
			Metadata: summary,
		})
		return err
	})
	if err != nil {
		return query.ContractRevision{}, nil, err
	}
	return rev, reports, nil
}
