// SPDX-License-Identifier: AGPL-3.0-or-later

// Package projects is an Organization's Projects (the TypeScript
// domain/projects.ts without deletion, which is step 4.12; ADR-0059 step
// 4.1c): creating one and renaming one, each one job of the single writer
// behind the Organization's and the requester's shared gates, with the
// writer's checks and the passkey-verification checkpoint inside it.
package projects

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// Project is a live Project row.
type Project = query.LiveProjectRow

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// JS is serialize.project: the Project as the API answers it.
func JS(p Project) jsvalue.Object {
	var active any
	if p.ActiveContractRevisionID.Valid {
		active = p.ActiveContractRevisionID.String
	}
	return jsvalue.Object{
		{Key: "id", Value: p.ID}, {Key: "organizationId", Value: p.OrganizationID}, {Key: "slug", Value: p.Slug},
		{Key: "name", Value: p.Name}, {Key: "contractAuthority", Value: p.ContractAuthority},
		{Key: "activeContractRevisionId", Value: active}, {Key: "createdAt", Value: audit.ISOTime(p.CreatedAt)},
	}
}

// Get is getProject: the Organization's live Project by ID or slug, or
// RESOURCE_NOT_FOUND.
func Get(ctx context.Context, db query.DBTX, organizationID, slugOrID string) (Project, error) {
	p, err := query.New(db).LiveProject(ctx, query.LiveProjectParams{OrganizationID: organizationID, SlugOrID: slugOrID})
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, domainerr.NotFound("Project")
	}
	return p, err
}

// List is listProjects: the Organization's live Projects, oldest first.
func List(ctx context.Context, db query.DBTX, organizationID string) ([]Project, error) {
	rows, err := query.New(db).ListLiveProjects(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Project, len(rows))
	for i, r := range rows {
		out[i] = Project(r)
	}
	return out, nil
}

// Create is createProject: the slug checked first; then, in one job behind
// the Organization's and the requester's shared gates, the writer's checks
// and the checkpoint, the slug's uniqueness among the live Projects (the
// index the TypeScript insert meets), the Project, and project.created. now
// is read inside the job: Projects list in creation order, so created_at
// has the clock's resolution, not the column default's millisecond.
func Create(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, slug, name, contractAuthority string, now func() time.Time) (Project, []auth.PendingReport, error) {
	if !slugPattern.MatchString(slug) {
		return Project{}, nil, domainerr.New("VALIDATION_FAILED", "Invalid project slug")
	}
	var project Project
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(organizationID, write.Shared), write.Person(p.Identity.ID, write.Shared)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		var err error
		if project, reports, err = create(ctx, tx, p, organizationID, slug, name, contractAuthority, now().UnixMicro()); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return Project{}, nil, err
	}
	return project, reports, nil
}

// create is Create's job, in a transaction the caller holds.
func create(ctx context.Context, tx query.DBTX, p *auth.Principal, organizationID, slug, name, contractAuthority string, at int64) (Project, []auth.PendingReport, error) {
	if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID}); err != nil {
		return Project{}, nil, err
	}
	reports, err := write.Checkpoint(ctx, tx, p, organizationID)
	if err != nil {
		return Project{}, nil, err
	}
	// The name as PostgreSQL takes it: U+0000 fails the insert (before
	// the unique index) with 500 INTERNAL, a lone surrogate is stored as
	// U+FFFD.
	stored, err := write.Text(name)
	if err != nil {
		return Project{}, nil, err
	}
	q := query.New(tx)
	taken, err := q.LiveProjectSlugTaken(ctx, query.LiveProjectSlugTakenParams{OrganizationID: organizationID, Slug: slug})
	if err != nil {
		return Project{}, nil, err
	}
	if taken > 0 {
		return Project{}, nil, domainerr.New("VALIDATION_FAILED", "Project slug already exists in this organization")
	}
	id := ids.New("prj")
	if err := q.InsertProject(ctx, query.InsertProjectParams{
		ID: id, OrganizationID: organizationID, Slug: slug, Name: stored, ContractAuthority: contractAuthority, CreatedAt: at,
	}); err != nil {
		return Project{}, nil, err
	}
	actor := p.Identity.ID
	if _, err := audit.Record(ctx, tx, audit.Event{
		Type: "project.created", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
		Resource: jsvalue.Object{{Key: "projectId", Value: id}, {Key: "projectSlug", Value: slug}},
		Metadata: jsvalue.Object{{Key: "contractAuthority", Value: contractAuthority}},
	}); err != nil {
		return Project{}, nil, err
	}
	project, err := Get(ctx, tx, organizationID, id)
	return project, reports, err
}

// Rename is renameProject: the display name only; the slug, which the CLI,
// URLs, Contracts and grants use, never changes. The name passed the
// route's zod check (1 to 200 code points); here, as there, it must also be
// at most 200 UTF-16 units (JavaScript's length), so 200 emoji pass the
// route and are refused here. Then, in one job: the writer's checks (the
// Project included), the checkpoint, the update, and project.renamed with
// both names.
func Rename(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, projectID, name string) (Project, []auth.PendingReport, error) {
	if name == "" || utf16Length(name) > 200 {
		return Project{}, nil, domainerr.New("VALIDATION_FAILED", "Invalid project name")
	}
	var project Project
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(organizationID, write.Shared), write.Person(p.Identity.ID, write.Shared)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID, ProjectID: projectID}); err != nil {
			return err
		}
		var err error
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return err
		}
		q := query.New(tx)
		prev, err := q.ProjectNames(ctx, query.ProjectNamesParams{OrganizationID: organizationID, ID: projectID})
		if errors.Is(err, sql.ErrNoRows) {
			return domainerr.NotFound("Project")
		}
		if err != nil {
			return err
		}
		// U+0000 fails the update; a lone surrogate is stored as U+FFFD,
		// then fails in the audit event's jsonb metadata (both 500
		// INTERNAL, as PostgreSQL fails them).
		stored, err := write.Text(name)
		if err != nil {
			return err
		}
		if err := q.RenameProject(ctx, query.RenameProjectParams{Name: stored, ID: projectID}); err != nil {
			return err
		}
		action, actor := "project.manage", p.Identity.ID
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "project.renamed", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "projectId", Value: projectID}, {Key: "projectSlug", Value: prev.Slug}},
			Metadata: jsvalue.Object{{Key: "previousName", Value: prev.Name}, {Key: "name", Value: name}},
		}); err != nil {
			return err
		}
		project, err = Get(ctx, tx, organizationID, projectID)
		return err
	})
	if err != nil {
		return Project{}, nil, err
	}
	return project, reports, nil
}

// utf16Length is JavaScript's String.prototype.length: a lone surrogate
// (kept as WTF-8 by jsvalue) is one unit, an astral code point two.
func utf16Length(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if i+2 < len(s) && s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			n, i = n+1, i+3
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r >= 0x10000 {
			n++
		}
		n, i = n+1, i+size
	}
	return n
}
