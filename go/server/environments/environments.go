// SPDX-License-Identifier: AGPL-3.0-or-later

// Package environments is a Project's environments (the TypeScript
// domain/environments.ts; ADR-0012, ADR-0020, ADR-0025; ADR-0059 step
// 4.1c): creating a root or a derived environment, and removing one (a
// tombstone). Each write is one job of the single writer behind the
// Organization's and the requester's shared gates, with the writer's
// checks and the passkey-verification checkpoint inside it, where the
// TypeScript code runs them.
package environments

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/contracts"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/projects"
	"github.com/varlatch/varlatch/go/server/write"
)

// Environment is a live environment row.
type Environment = query.LiveEnvironmentRow

var (
	rootName    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	derivedName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}/[a-z0-9][a-z0-9._-]{0,62}$`)
)

// RootID is rootIdOf: the root environment's ID, its own for a root.
func RootID(e Environment) string {
	if e.ParentEnvironmentID.Valid {
		return e.ParentEnvironmentID.String
	}
	return e.ID
}

// JS is serialize.environment: the environment as the API answers it,
// before the route adds its tailnet fields.
func JS(e Environment) jsvalue.Object {
	str := func(s sql.NullString) any {
		if s.Valid {
			return s.String
		}
		return nil
	}
	var expires any
	if e.ExpiresAt.Valid {
		expires = audit.ISOTime(e.ExpiresAt.Int64)
	}
	return jsvalue.Object{
		{Key: "id", Value: e.ID}, {Key: "projectId", Value: e.ProjectID}, {Key: "name", Value: e.Name},
		{Key: "kind", Value: e.Kind}, {Key: "tier", Value: e.Tier},
		{Key: "parentEnvironmentId", Value: str(e.ParentEnvironmentID)}, {Key: "ownerIdentityId", Value: str(e.OwnerIdentityID)},
		{Key: "expiresAt", Value: expires}, {Key: "createdAt", Value: audit.ISOTime(e.CreatedAt)},
	}
}

// Get is getEnvironment: the Project's live environment by ID or name, or
// RESOURCE_NOT_FOUND.
func Get(ctx context.Context, db query.DBTX, projectID, nameOrID string) (Environment, error) {
	e, err := query.New(db).LiveEnvironment(ctx, query.LiveEnvironmentParams{ProjectID: projectID, NameOrID: nameOrID})
	if errors.Is(err, sql.ErrNoRows) {
		return Environment{}, domainerr.NotFound("Environment")
	}
	return e, err
}

// List is listEnvironments: the Project's live environments, oldest first.
func List(ctx context.Context, db query.DBTX, projectID string) ([]Environment, error) {
	rows, err := query.New(db).ListLiveEnvironments(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]Environment, len(rows))
	for i, r := range rows {
		out[i] = Environment(r)
	}
	return out, nil
}

// Input is createEnvironment's input as the route's zod schema leaves it:
// nil for an absent member. ExpiresAt passed z.string().datetime().
type Input struct {
	Name                string
	Tier                *string
	Kind                *string
	ParentEnvironmentID *string
	ExpiresAt           *string
}

func invalid(message string) error { return domainerr.New("VALIDATION_FAILED", message) }

// Create is createEnvironment (ADR-0012): a root is shared and declares a
// tier; a derived environment (one level only) inherits its parent's tier,
// is personal (the default) or preview, is named parent/suffix, and is not
// personal under a production-tier parent (ADR-0020); only a preview
// environment may expire. In one job, in the TypeScript order: the
// writer's checks (the Organization and the Project); for a derived one,
// the parent (RESOURCE_NOT_FOUND), the checkpoint, then the rules; for a
// root, the rules, then the checkpoint; then the name's uniqueness among
// the live environments, the insert and environment.created. A personal
// environment is owned by its creator. now is read inside the job.
func Create(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, projectID string, in Input, now func() time.Time) (Environment, []auth.PendingReport, error) {
	var env Environment
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(organizationID, write.Shared), write.Person(p.Identity.ID, write.Shared)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		var err error
		env, reports, err = create(ctx, tx, p, organizationID, projectID, in, now().UnixMicro())
		return err
	})
	if err != nil {
		return Environment{}, nil, err
	}
	return env, reports, nil
}

func create(ctx context.Context, tx query.DBTX, p *auth.Principal, organizationID, projectID string, in Input, at int64) (Environment, []auth.PendingReport, error) {
	if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID, ProjectID: projectID}); err != nil {
		return Environment{}, nil, err
	}
	var reports []auth.PendingReport
	var tier, kind string
	var parentID sql.NullString
	derived := in.ParentEnvironmentID != nil && *in.ParentEnvironmentID != "" // JavaScript truthiness
	if derived {
		parent, err := Get(ctx, tx, projectID, *in.ParentEnvironmentID)
		if err != nil {
			return Environment{}, nil, err
		}
		// The parent is live; then passkey-verification (ADR-0054
		// Decision 7), before the rules.
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return Environment{}, nil, err
		}
		switch {
		case parent.ParentEnvironmentID.Valid:
			return Environment{}, nil, invalid("Derived environments cannot themselves be parents (one-level inheritance)")
		case in.Tier != nil && *in.Tier != parent.Tier:
			return Environment{}, nil, invalid("Derived environments inherit their parent's tier and cannot change it")
		}
		kind = "personal"
		if in.Kind != nil {
			kind = *in.Kind
		}
		switch {
		case kind == "shared":
			return Environment{}, nil, invalid("Derived environments must be personal or preview")
		case kind == "personal" && parent.Tier == "production":
			return Environment{}, nil, invalid("Personal environments derived from production-tier are not allowed")
		case !derivedName.MatchString(in.Name) || !strings.HasPrefix(in.Name, parent.Name+"/"):
			return Environment{}, nil, invalid("Derived environment names use the parent/suffix form")
		}
		tier, parentID = parent.Tier, sql.NullString{String: parent.ID, Valid: true}
	} else {
		switch {
		case in.Tier == nil:
			return Environment{}, nil, invalid("Root environments must declare a tier")
		case in.Kind != nil && *in.Kind != "shared":
			return Environment{}, nil, invalid("Root environments are shared")
		case !rootName.MatchString(in.Name):
			return Environment{}, nil, invalid("Invalid environment name")
		}
		tier, kind = *in.Tier, "shared"
	}
	if in.ExpiresAt != nil && kind != "preview" {
		return Environment{}, nil, invalid("Only preview environments may expire")
	}
	if !derived {
		var err error
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return Environment{}, nil, err
		}
	}
	// The insert's parameters as PostgreSQL reads them, before its unique
	// index: a timestamp it cannot take fails the statement (500).
	var expires sql.NullInt64
	if in.ExpiresAt != nil {
		micros, err := PostgresTimestamp(*in.ExpiresAt)
		if err != nil {
			return Environment{}, nil, err
		}
		expires = sql.NullInt64{Int64: micros, Valid: true}
	}
	q := query.New(tx)
	taken, err := q.LiveEnvironmentNameTaken(ctx, query.LiveEnvironmentNameTakenParams{ProjectID: projectID, Name: in.Name})
	if err != nil {
		return Environment{}, nil, err
	}
	if taken > 0 {
		return Environment{}, nil, invalid("Environment name already exists in this project")
	}
	var owner sql.NullString
	if kind == "personal" {
		owner = sql.NullString{String: p.Identity.ID, Valid: true}
	}
	id := ids.New("env")
	if err := q.InsertEnvironment(ctx, query.InsertEnvironmentParams{
		ID: id, ProjectID: projectID, Name: in.Name, Kind: kind, Tier: tier, ParentEnvironmentID: parentID,
		OwnerIdentityID: owner, ExpiresAt: expires, CreatedAt: at,
	}); err != nil {
		return Environment{}, nil, err
	}
	actor := p.Identity.ID
	if _, err := audit.Record(ctx, tx, audit.Event{
		Type: "environment.created", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
		Resource: jsvalue.Object{{Key: "projectId", Value: projectID}, {Key: "environmentId", Value: id}, {Key: "environmentName", Value: in.Name}},
		Metadata: jsvalue.Object{{Key: "kind", Value: kind}, {Key: "tier", Value: tier}, {Key: "derived", Value: derived}},
	}); err != nil {
		return Environment{}, nil, err
	}
	env, err := Get(ctx, tx, projectID, id)
	return env, reports, err
}

// datetime is z.string().datetime(), which the route checked: a date,
// "T", hours, minutes and seconds, an optional fraction, and "Z".
var datetime = regexp.MustCompile(`^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.\d+)?Z$`)

// ErrTimestamp is a datetime zod accepts and PostgreSQL's timestamptz
// refuses (22007, 22008): the insert fails, and the route answers 500
// INTERNAL, having written nothing (go/README.md, Known TypeScript
// defects).
var ErrTimestamp = errors.New("environments: PostgreSQL refuses the timestamp (the TypeScript server answers 500 INTERNAL)")

// maxFractionDigits is the longest fraction PostgreSQL 17 takes in zod's
// datetime shape. timestamptz_in splits the text into a work buffer of
// MAXDATELEN + MAXDATEFIELDS = 153 bytes (ParseDateTime, datetime.c),
// each field followed by a NUL, and APPEND_CHAR refuses a character at an
// index whose next one would reach the end (index + 1 >= 153): the date
// "yyyy-mm-dd" and its NUL take 11 bytes, "t" and its NUL 2, the time
// "hh:mm:ss.<n digits>" and its NUL 10 + n, so the final "z" lands at
// index 23 + n, and n may be at most 128. The fraction's digits never fail
// otherwise (strtod, then rint).
const maxFractionDigits = 128

// PostgresTimestamp is the microseconds PostgreSQL stores for a datetime
// zod accepted, or ErrTimestamp where PostgreSQL refuses it: year 0, or a
// fraction longer than maxFractionDigits. The fraction is rounded to
// microseconds as its parser rounds it (strtod of the fraction, then rint
// of the microseconds: half to even on the double), and may carry into
// the next second.
func PostgresTimestamp(s string) (int64, error) {
	m := datetime.FindStringSubmatch(s)
	if m == nil || len(m[7]) > 1+maxFractionDigits {
		return 0, ErrTimestamp
	}
	n := func(i int) int { v, _ := strconv.Atoi(m[i]); return v }
	if n(1) == 0 {
		return 0, ErrTimestamp
	}
	t := time.Date(n(1), time.Month(n(2)), n(3), n(4), n(5), n(6), 0, time.UTC)
	var frac float64
	if m[7] != "" {
		frac, _ = strconv.ParseFloat(m[7], 64)
	}
	return t.Unix()*1_000_000 + int64(math.RoundToEven(frac*1_000_000)), nil
}

// referencesError is the refusal of removing an environment the active
// Contract's requiredness selectors name.
func referencesError(names []string) error {
	items := make([]any, len(names))
	for i, n := range names {
		items[i] = n
	}
	return &domainerr.Error{
		Code: "VALIDATION_FAILED",
		Message: "The active Contract Revision references this environment (required selector on: " + strings.Join(names, ", ") +
			"); activate a revision without the reference first",
		Details: jsvalue.Object{{Key: "items", Value: items}},
	}
}

// Delete is deleteEnvironment (ADR-0025): an explicit tombstone. First,
// read before the job as there (on the Project as the route read it), the
// active Contract's references to the environment block the removal. Then,
// in one job: the writer's checks (the environment included) and the
// checkpoint; live derived environments block it; then the tombstone, its
// values soft-deleted, its outstanding Capabilities revoked, and
// environment.deleted. Grants naming it go inert under default-deny; the
// encrypted version history stays at rest.
func Delete(ctx context.Context, w *write.Writer, reader query.DBTX, p *auth.Principal, organizationID string, project projects.Project, env Environment, now func() time.Time) ([]auth.PendingReport, error) {
	active, err := contracts.Active(ctx, reader, project.ID, project.ActiveContractRevisionID)
	if err != nil {
		return nil, err
	}
	if active != nil {
		var names []string
		for _, it := range active.Items {
			if sel := it.Required.Selector; it.Required.Kind == "selector" && sel != nil && sel.Kind == "environments" {
				for _, id := range sel.EnvironmentIDs {
					if id == env.ID {
						names = append(names, it.Name)
						break
					}
				}
			}
		}
		if len(names) > 0 {
			return nil, referencesError(names)
		}
	}
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(organizationID, write.Shared), write.Person(p.Identity.ID, write.Shared)}
	err = w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		var err error
		reports, err = remove(ctx, tx, p, organizationID, project.ID, env, now().UnixMicro())
		return err
	})
	if err != nil {
		return nil, err
	}
	return reports, nil
}

func remove(ctx context.Context, tx query.DBTX, p *auth.Principal, organizationID, projectID string, env Environment, at int64) ([]auth.PendingReport, error) {
	if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID, ProjectID: projectID, EnvironmentIDs: []string{env.ID}}); err != nil {
		return nil, err
	}
	reports, err := write.Checkpoint(ctx, tx, p, organizationID)
	if err != nil {
		return nil, err
	}
	q := query.New(tx)
	children, err := q.LiveChildEnvironmentNames(ctx, sql.NullString{String: env.ID, Valid: true})
	if err != nil {
		return nil, err
	}
	if len(children) > 0 {
		names := make([]any, len(children))
		for i, c := range children {
			names[i] = c
		}
		return nil, &domainerr.Error{
			Code:    "VALIDATION_FAILED",
			Message: "This environment has live derived environments (" + strings.Join(children, ", ") + "); delete them first",
			Details: jsvalue.Object{{Key: "children", Value: names}},
		}
	}
	n, err := q.DeleteEnvironment(ctx, query.DeleteEnvironmentParams{DeletedAt: sql.NullInt64{Int64: at, Valid: true}, ID: env.ID})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, domainerr.NotFound("Environment")
	}
	if err := q.DeleteValuesOfEnvironment(ctx, query.DeleteValuesOfEnvironmentParams{DeletedAt: sql.NullInt64{Int64: at, Valid: true}, EnvironmentID: env.ID}); err != nil {
		return nil, err
	}
	// The tokens of its OAuth connections go with it (ADR-0062).
	if err := q.ForgetOAuthConnectionsOfEnvironment(ctx, env.ID); err != nil {
		return nil, err
	}
	revoked, err := q.RevokeCapabilitiesOfEnvironment(ctx, query.RevokeCapabilitiesOfEnvironmentParams{RevokedAt: sql.NullInt64{Int64: at, Valid: true}, EnvironmentID: env.ID})
	if err != nil {
		return nil, err
	}
	actor := p.Identity.ID
	if _, err := audit.Record(ctx, tx, audit.Event{
		Type: "environment.deleted", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
		Resource: jsvalue.Object{{Key: "projectId", Value: projectID}, {Key: "environmentId", Value: env.ID}, {Key: "environmentName", Value: env.Name}},
		Metadata: jsvalue.Object{
			{Key: "kind", Value: env.Kind}, {Key: "tier", Value: env.Tier}, {Key: "derived", Value: env.ParentEnvironmentID.Valid},
			{Key: "expired", Value: Expired(env, at)}, {Key: "capabilitiesRevoked", Value: revoked},
		},
	}); err != nil {
		return nil, err
	}
	return reports, nil
}

// Expired is isExpired (ADR-0020), at a time in microseconds: expiry is
// compared in milliseconds, as JavaScript's Date holds both times.
func Expired(e Environment, atMicros int64) bool {
	if !e.ExpiresAt.Valid {
		return false
	}
	floorMs := func(us int64) int64 {
		ms := us / 1000
		if us < 0 && us%1000 != 0 {
			ms--
		}
		return ms
	}
	return floorMs(e.ExpiresAt.Int64) <= floorMs(atMicros)
}
