// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/lib/storage"
	vsync "github.com/varlatch/varlatch/go/lib/sync"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// Sync Targets (ADR-0031 sections 1 to 6, ADR-0050; ADR-0059 step 4.9c): a
// Target binds one Environment to one destination on a Connection and is
// standing disclosure authority. The routes run the write-time disclosure
// gate (secret.reveal and config.value.read on the Environment) before
// creating one and before a change that widens what it discloses; these
// operations write the rows, in one job each. Revoking and pausing fence a
// run in progress (a new generation).

// ---------------------------------------------------------------------------
// Mappings.

// MappingItem is one item of an explicit mapping.
type MappingItem struct {
	Name   string
	Rename *string
	// SecretAffirmed: disclosure of the item as a Secret was authorized.
	SecretAffirmed bool
}

// Mapping is SyncMapping: a wildcard (with exclusions) or explicit items.
type Mapping struct {
	Wildcard bool
	Exclude  []string // nil: no exclusions member
	Items    []MappingItem
}

// JS is the mapping as the TypeScript code builds it.
func (m Mapping) JS() jsvalue.Object {
	if m.Wildcard {
		o := jsvalue.Object{{Key: "kind", Value: "wildcard"}}
		if m.Exclude != nil {
			list := make([]any, len(m.Exclude))
			for i, e := range m.Exclude {
				list[i] = e
			}
			o = append(o, jsvalue.Member{Key: "exclude", Value: list})
		}
		return o
	}
	items := make([]any, len(m.Items))
	for i, it := range m.Items {
		o := jsvalue.Object{{Key: "name", Value: it.Name}}
		if it.Rename != nil {
			o = append(o, jsvalue.Member{Key: "rename", Value: *it.Rename})
		}
		items[i] = append(o, jsvalue.Member{Key: "secretAffirmed", Value: it.SecretAffirmed})
	}
	return jsvalue.Object{{Key: "kind", Value: "explicit"}, {Key: "items", Value: items}}
}

// stored is the mapping as the jsonb column holds it.
func (m Mapping) stored() string { return string(jsvalue.Stringify(jsvalue.Jsonb(m.JS()))) }

// ErrStoredMapping is a stored mapping this server cannot read: not the
// shape normalizeMapping writes. Imported or migrated data can hold one
// (a TypeScript database's row as it was); it fails its Target's runs and
// requests, never the daemon.
var ErrStoredMapping = errors.New("the Sync Target's stored mapping is not one this server reads")

func badMapping(what string) error { return fmt.Errorf("%w: %s", ErrStoredMapping, what) }

// ErrStoredDestination is a stored destination this server cannot read.
var ErrStoredDestination = errors.New("the Sync Target's stored destination is not one this server reads")

// StoredDestination reads a stored destination: a JSON object, in
// JavaScript's member order. Anything else is an ErrStoredDestination,
// never a panic.
func StoredDestination(text string) (jsvalue.Object, error) {
	v, err := jsvalue.Parse([]byte(text))
	if err != nil {
		return nil, fmt.Errorf("%w: not JSON", ErrStoredDestination)
	}
	o, ok := jsvalue.JSOrder(v).(jsvalue.Object)
	if !ok {
		return nil, fmt.Errorf("%w: not an object", ErrStoredDestination)
	}
	return o, nil
}

// ParseMapping reads a stored mapping: a wildcard, with its exclusions, or
// an explicit list of at least one item, each named. Anything else is an
// ErrStoredMapping, never a panic.
func ParseMapping(text string) (Mapping, error) {
	v, err := jsvalue.Parse([]byte(text))
	if err != nil {
		return Mapping{}, badMapping("not JSON")
	}
	o, ok := v.(jsvalue.Object)
	if !ok {
		return Mapping{}, badMapping("not an object")
	}
	kind, _ := o.Get("kind")
	if kind == "wildcard" {
		m := Mapping{Wildcard: true}
		if raw, ok := o.Get("exclude"); ok {
			list, ok := raw.([]any)
			if !ok {
				return Mapping{}, badMapping("its exclusions are not a list")
			}
			m.Exclude = []string{}
			for _, e := range list {
				s, ok := e.(string)
				if !ok {
					return Mapping{}, badMapping("an exclusion is not a string")
				}
				m.Exclude = append(m.Exclude, s)
			}
		}
		return m, nil
	}
	if kind != nil && kind != "explicit" {
		return Mapping{}, badMapping("its kind is neither wildcard nor explicit")
	}
	raw, _ := o.Get("items")
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return Mapping{}, badMapping("it lists no item")
	}
	var m Mapping
	for _, r := range items {
		it, ok := r.(jsvalue.Object)
		if !ok {
			return Mapping{}, badMapping("an item is not an object")
		}
		n, _ := it.Get("name")
		name, ok := n.(string)
		if !ok || name == "" {
			return Mapping{}, badMapping("an item has no name")
		}
		item := MappingItem{Name: name}
		if rr, ok := it.Get("rename"); ok && rr != nil {
			s, ok := rr.(string)
			if !ok {
				return Mapping{}, badMapping("an item's rename is not a string")
			}
			item.Rename = &s
		}
		affirmed, _ := it.Get("secretAffirmed")
		item.SecretAffirmed = affirmed == true
		m.Items = append(m.Items, item)
	}
	return m, nil
}

var exclusionPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\*?$`)

const maxExclusions = 200

func invalid(message string) error { return domainerr.New("VALIDATION_FAILED", message) }

// NormalizeMapping is normalizeMapping: the mapping's shape and its
// destination names checked against the adapter and, when given, the
// canonical destination. raw is the zod-parsed body's mapping. An
// explicit item keeps an affirmation it had in previous unless it is
// sensitive now (then the gate just passed affirms it).
func NormalizeMapping(platform string, raw jsvalue.Object, sensitive func(string) bool, previous *Mapping, destination vsync.Fields) (Mapping, error) {
	kind, _ := raw.Get("kind")
	if kind == "wildcard" {
		var exclude []string
		if list, ok := raw.Get("exclude"); ok {
			for _, e := range list.([]any) {
				if s := e.(string); !slices.Contains(exclude, s) {
					exclude = append(exclude, s)
				}
			}
		}
		if len(exclude) == 0 {
			return Mapping{Wildcard: true}, nil
		}
		if len(exclude) > maxExclusions {
			return Mapping{}, invalid(fmt.Sprintf("At most %d exclusions", maxExclusions))
		}
		for _, e := range exclude {
			if !exclusionPattern.MatchString(e) {
				return Mapping{}, invalid(`Invalid exclusion "` + e + `": an exact item name or a prefix ending in *`)
			}
		}
		slices.SortFunc(exclude, jsCompare)
		return Mapping{Wildcard: true, Exclude: exclude}, nil
	}
	list, _ := raw.Get("items")
	items, _ := list.([]any)
	if len(items) == 0 {
		return Mapping{}, invalid("Explicit mapping must list at least one item")
	}
	adapter, err := vsync.GetAdapter(platform)
	if err != nil {
		return Mapping{}, validation(err)
	}
	prev := map[string]MappingItem{}
	if previous != nil && !previous.Wildcard {
		for _, it := range previous.Items {
			prev[it.Name] = it
		}
	}
	seenSources, seenDests := map[string]bool{}, map[string]bool{}
	var out []MappingItem
	for _, rawItem := range items {
		it := rawItem.(jsvalue.Object)
		n, _ := it.Get("name")
		name := n.(string)
		var rename *string
		if r, ok := it.Get("rename"); ok {
			s := r.(string)
			rename = &s
		}
		if seenSources[name] {
			return Mapping{}, invalid("Duplicate mapped item: " + name)
		}
		seenSources[name] = true
		source := name
		if rename != nil {
			source = *rename
		}
		destName := adapter.CanonicalizeName(source)
		if problem := adapter.ValidateName(destName, destination); problem != "" {
			return Mapping{}, invalid(name + ": " + problem)
		}
		if seenDests[destName] {
			return Mapping{}, invalid("Two mapped items resolve to the same destination name " + destName)
		}
		seenDests[destName] = true
		affirmed := sensitive(name) || prev[name].SecretAffirmed
		out = append(out, MappingItem{Name: name, Rename: rename, SecretAffirmed: affirmed})
	}
	return Mapping{Items: out}, nil
}

// jsCompare is JavaScript's default sort order (UTF-16 code units; the
// names here are ASCII, where it is byte order).
func jsCompare(a, b string) int { return strings.Compare(a, b) }

// MappingWidens is mappingWidens: next discloses more than prev, which
// re-runs the write-time gate.
func MappingWidens(prev, next Mapping) bool {
	if next.Wildcard {
		if !prev.Wildcard {
			return true
		}
		for _, e := range prev.Exclude {
			if !slices.Contains(next.Exclude, e) {
				return true
			}
		}
		return false
	}
	if prev.Wildcard {
		return false
	}
	before := map[string]MappingItem{}
	for _, it := range prev.Items {
		before[it.Name] = it
	}
	for _, it := range next.Items {
		b, ok := before[it.Name]
		if !ok || (it.SecretAffirmed && !b.SecretAffirmed) {
			return true
		}
	}
	return false
}

// RequiredDisclosureActions is requiredDisclosureActions: a wildcard needs
// both; explicit items each need their class's, in their order.
func RequiredDisclosureActions(m Mapping, sensitive func(string) bool) []string {
	if m.Wildcard {
		return []string{"secret.reveal", "config.value.read"}
	}
	var out []string
	for _, it := range m.Items {
		action := "config.value.read"
		if sensitive(it.Name) {
			action = "secret.reveal"
		}
		if !slices.Contains(out, action) {
			out = append(out, action)
		}
	}
	return out
}

// summary is mappingSummary.
func (m Mapping) summary() string {
	if m.Wildcard {
		if len(m.Exclude) > 0 {
			return "* except " + strings.Join(m.Exclude, ",")
		}
		return "*"
	}
	parts := make([]string, len(m.Items))
	for i, it := range m.Items {
		parts[i] = it.Name
		if it.Rename != nil {
			parts[i] += "->" + *it.Rename
		}
	}
	return strings.Join(parts, ",")
}

// ---------------------------------------------------------------------------
// Reads.

func targetNotFound() error { return domainerr.New("RESOURCE_NOT_FOUND", "Sync Target not found") }

// ListTargets is listTargets of an Organization, or of one environment
// when environmentID is set.
func ListTargets(ctx context.Context, db query.DBTX, organizationID, environmentID string) ([]Target, error) {
	q := query.New(db)
	if environmentID == "" {
		rows, err := q.OrganizationTargets(ctx, organizationID)
		out := make([]Target, len(rows))
		for i, r := range rows {
			out[i] = Target(r)
		}
		return out, err
	}
	rows, err := q.EnvironmentTargets(ctx, query.EnvironmentTargetsParams{OrganizationID: organizationID, EnvironmentID: environmentID})
	out := make([]Target, len(rows))
	for i, r := range rows {
		out[i] = Target(r)
	}
	return out, err
}

// GetTarget is getTarget: a live Target of the Organization.
func GetTarget(ctx context.Context, db query.DBTX, organizationID, targetID string) (Target, error) {
	r, err := query.New(db).LiveTarget(ctx, query.LiveTargetParams{ID: targetID, OrganizationID: organizationID})
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, targetNotFound()
	}
	return Target(r), err
}

// Running is whether the Target has a run that has not passed its
// deadline (liveRunStarts).
func Running(ctx context.Context, db query.DBTX, targetID string, now int64) (bool, error) {
	rows, err := query.New(db).LiveRunStarts(ctx, query.LiveRunStartsParams{TargetIds: `["` + targetID + `"]`, Now: now})
	return len(rows) > 0, err
}

// LedgerJS is the Target's per-name delivery state as GET shows it.
func LedgerJS(ctx context.Context, db query.DBTX, targetID string) ([]any, error) {
	rows, err := query.New(db).TargetLedger(ctx, targetID)
	if err != nil {
		return nil, err
	}
	out := make([]any, len(rows))
	for i, r := range rows {
		var e any
		if r.LastError.Valid {
			e = r.LastError.String
		}
		out[i] = jsvalue.Object{{Key: "name", Value: r.DestName}, {Key: "state", Value: r.State},
			{Key: "updatedAt", Value: audit.ISOTime(r.UpdatedAt)}, {Key: "error", Value: e}}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Writes.

// usableConnection is usableConnection: the Connection live, and an App
// Connection's App live.
func usableConnection(ctx context.Context, db query.DBTX, organizationID, connectionID string) (query.AnyConnectionRow, error) {
	q := query.New(db)
	c, err := q.AnyConnection(ctx, query.AnyConnectionParams{ID: connectionID, OrganizationID: organizationID})
	if errors.Is(err, sql.ErrNoRows) || (err == nil && c.RevokedAt.Valid) {
		return c, connectionNotFound()
	}
	if err != nil {
		return c, err
	}
	if c.CredentialKind == "github-app" {
		n, err := q.LiveGitHubApp(ctx, query.LiveGitHubAppParams{ID: c.GithubAppID.String, OrganizationID: organizationID})
		if err != nil {
			return c, err
		}
		if n == 0 {
			return c, invalid("This Connection's GitHub App was removed from Varlatch")
		}
	}
	return c, nil
}

func destinationClaimed() error {
	return domainerr.New("VERSION_CONFLICT", "Another Sync Target already claims this destination; a destination has exactly one writer")
}

// claim checks the destination claim (the unique index
// sync_targets_destination_claim, which answers the same).
func claim(ctx context.Context, db query.DBTX, canonical, targetID string) error {
	n, err := query.New(db).DestinationClaimed(ctx, query.DestinationClaimedParams{Canonical: canonical, ID: targetID})
	if err == nil && n > 0 {
		err = destinationClaimed()
	}
	return err
}

func expandsMetadata(destination vsync.Fields) jsvalue.Object {
	if v := destination.Get("platformExpands"); v != "" {
		return jsvalue.Object{{Key: "platformExpands", Value: v}}
	}
	return nil
}

func fieldsJS(f vsync.Fields) jsvalue.Object {
	o := jsvalue.Object{}
	for _, x := range f {
		o = append(o, jsvalue.Member{Key: x.Key, Value: x.Value})
	}
	return o
}

// TargetInput is createTarget's input.
type TargetInput struct {
	ConnectionID  string
	Destination   jsvalue.Object
	Mapping       Mapping
	RemoveOrphans bool
	Redeploy      bool
}

// CreateTarget is createTarget: in one job, the scope (the Organization,
// the Project and the environment live, the requester's checkpoint), the
// Connection usable, the destination canonical and unclaimed, the row, the
// integration index and sync.target_created with the gate's decisions.
func (s *Service) CreateTarget(ctx context.Context, req Request, org authz.Organization, projectID, environmentID string, in TargetInput, decisions jsvalue.Object) (Target, []auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	id := ids.New(ids.SyncTarget)
	var out Target
	var reports []auth.PendingReport
	err := s.Writer.Job(ctx, []write.Gate{write.Organization(org.ID, write.Shared), write.Person(actor, write.Shared)}, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: org.ID, ProjectID: projectID, EnvironmentIDs: []string{environmentID}}); err != nil {
			return err
		}
		var err error
		if reports, err = write.Checkpoint(ctx, tx, req.Principal, org.ID); err != nil {
			return err
		}
		c, err := usableConnection(ctx, tx, org.ID, in.ConnectionID)
		if err != nil {
			return err
		}
		adapter, err := vsync.GetAdapter(c.Platform)
		if err != nil {
			return validation(err)
		}
		dest, err := adapter.CanonicalizeDestination(SyncObject(in.Destination))
		if err != nil {
			return validation(err)
		}
		canonical := vsync.CanonicalDestinationIdentity(adapter.Platform(), c.BaseIdentity, dest.Key)
		if err := claim(ctx, tx, canonical, id); err != nil {
			return err
		}
		at := s.now().UnixMicro()
		if err := query.New(tx).InsertTarget(ctx, query.InsertTargetParams{
			ID: id, OrganizationID: org.ID, ProjectID: projectID, EnvironmentID: environmentID, ConnectionID: c.ID,
			Destination: string(jsvalue.Stringify(jsvalue.Jsonb(fieldsJS(dest.Fields)))), CanonicalDestination: canonical,
			Mapping: in.Mapping.stored(), RemoveOrphans: in.RemoveOrphans, Redeploy: in.Redeploy,
			CreatedBy: sql.NullString{String: actor, Valid: true}, CreatedAt: at,
		}); err != nil {
			return err
		}
		if err := indexIntegration(ctx, tx, org.ID, actor, "target", id, []string{"created"}, at); err != nil {
			return err
		}
		action := "config.sync.manage"
		md := jsvalue.Object{
			{Key: "platform", Value: string(adapter.Platform())},
			{Key: "destination", Value: string(adapter.Platform()) + ":" + dest.Key},
			{Key: "mapping", Value: in.Mapping.summary()}, {Key: "removeOrphans", Value: in.RemoveOrphans},
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "sync.target_created", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID, Action: &action,
			Resource: jsvalue.Object{{Key: "targetId", Value: id}, {Key: "environmentId", Value: environmentID}, {Key: "connectionId", Value: c.ID}},
			Authz:    decisions, Metadata: append(md, expandsMetadata(dest.Fields)...),
		}); err != nil {
			return err
		}
		out, err = GetTarget(ctx, tx, org.ID, id)
		return err
	})
	return out, reports, err
}

// TargetPatch is updateTarget's patch: nil keeps a field.
type TargetPatch struct {
	ExpectedVersion int64
	Mapping         *Mapping
	Destination     jsvalue.Object // nil: kept
	HasDestination  bool
	ConnectionID    *string
	RemoveOrphans   *bool
	Redeploy        *bool
}

func targetConflict() error {
	return domainerr.New("VERSION_CONFLICT", "Sync Target was modified concurrently; reload and retry")
}

// UpdateTarget is updateTarget: destination changes and Connection
// re-points are new disclosure grants (the route ran the gate and passes
// its decisions; nil when none ran). A destination-identity change
// releases the old claim, takes the new one, resets the ledger and fences
// a run in progress; turning redeploys off fences one too.
func (s *Service) UpdateTarget(ctx context.Context, req Request, org authz.Organization, target Target, patch TargetPatch, decisions jsvalue.Object) (Target, []auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	var out Target
	var reports []auth.PendingReport
	err := s.Writer.Job(ctx, []write.Gate{write.Organization(org.ID, write.Shared), write.Person(actor, write.Shared)}, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: org.ID, ProjectID: target.ProjectID, EnvironmentIDs: []string{target.EnvironmentID}}); err != nil {
			return err
		}
		q := query.New(tx)
		current, err := GetTarget(ctx, tx, org.ID, target.ID)
		if err != nil {
			return err
		}
		// Existence first, then passkey-verification.
		if reports, err = write.Checkpoint(ctx, tx, req.Principal, org.ID); err != nil {
			return err
		}
		if current.Version != patch.ExpectedVersion || current.ConnectionID != target.ConnectionID {
			return targetConflict()
		}
		connectionID := current.ConnectionID
		if patch.ConnectionID != nil {
			connectionID = *patch.ConnectionID
		}
		c, err := usableConnection(ctx, tx, org.ID, connectionID)
		if err != nil {
			return err
		}
		if patch.ConnectionID != nil {
			old, err := q.AnyConnection(ctx, query.AnyConnectionParams{ID: current.ConnectionID, OrganizationID: org.ID})
			if err == nil && old.Platform != c.Platform {
				return invalid("A Sync Target cannot be re-pointed across platform types")
			}
		}
		adapter, err := vsync.GetAdapter(c.Platform)
		if err != nil {
			return validation(err)
		}
		raw := patch.Destination
		if !patch.HasDestination {
			if raw, err = StoredDestination(current.Destination); err != nil {
				return err
			}
		}
		dest, err := adapter.CanonicalizeDestination(SyncObject(raw))
		if err != nil {
			return validation(err)
		}
		canonical := vsync.CanonicalDestinationIdentity(adapter.Platform(), c.BaseIdentity, dest.Key)
		changed := canonical != current.CanonicalDestination
		if changed {
			if err := claim(ctx, tx, canonical, current.ID); err != nil {
				return err
			}
		}
		// A stored mapping this server cannot read is repaired by a patch
		// that gives a whole mapping: the previous one is then unknown, and
		// the new one counts as widening (the caller ran the disclosure
		// gate for it).
		prev, err := ParseMapping(current.Mapping)
		prevUnknown := false
		if err != nil {
			if patch.Mapping == nil || !errors.Is(err, ErrStoredMapping) {
				return err
			}
			prevUnknown = true
		}
		mapping := prev
		if patch.Mapping != nil {
			mapping = *patch.Mapping
		}
		removeOrphans, redeploy := current.RemoveOrphans, current.Redeploy
		if patch.RemoveOrphans != nil {
			removeOrphans = *patch.RemoveOrphans
		}
		if patch.Redeploy != nil {
			redeploy = *patch.Redeploy
		}
		var flag int64
		if changed {
			flag = 1
		}
		at := s.now().UnixMicro()
		if err := q.UpdateTarget(ctx, query.UpdateTargetParams{
			ConnectionID: c.ID, Destination: string(jsvalue.Stringify(jsvalue.Jsonb(fieldsJS(dest.Fields)))), Canonical: canonical,
			Mapping: mapping.stored(), RemoveOrphans: removeOrphans, Redeploy: redeploy, At: sql.NullInt64{Int64: at, Valid: true},
			Changed: flag, ID: current.ID,
		}); err != nil {
			return err
		}
		if current.Redeploy && patch.Redeploy != nil && !*patch.Redeploy && !changed {
			if err := q.FenceTarget(ctx, current.ID); err != nil {
				return err
			}
		}
		if changed {
			// The new destination starts with an empty ledger and a full
			// write; a run against the old one is fenced.
			if err := q.ClearLedger(ctx, current.ID); err != nil {
				return err
			}
			if err := q.FenceTargetCycle(ctx, current.ID); err != nil {
				return err
			}
		}
		var changes []string
		if c.ID != target.ConnectionID {
			changes = append(changes, "repointed")
		}
		if changed {
			changes = append(changes, "destination_changed")
		}
		if err := indexIntegration(ctx, tx, org.ID, actor, "target", current.ID, changes, at); err != nil {
			return err
		}
		action := "config.sync.manage"
		md := jsvalue.Object{
			{Key: "destination", Value: string(adapter.Platform()) + ":" + dest.Key}, {Key: "destinationChanged", Value: changed},
			{Key: "connectionRepointed", Value: c.ID != target.ConnectionID}, {Key: "mapping", Value: mapping.summary()},
			{Key: "widened", Value: prevUnknown || MappingWidens(prev, mapping)},
		}
		e := audit.Event{
			Type: "sync.target_updated", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID, Action: &action,
			Resource: jsvalue.Object{{Key: "targetId", Value: current.ID}, {Key: "environmentId", Value: current.EnvironmentID}, {Key: "connectionId", Value: c.ID}},
			Metadata: append(md, expandsMetadata(dest.Fields)...),
		}
		if decisions != nil {
			e.Authz = decisions
		}
		if _, err := audit.Record(ctx, tx, e); err != nil {
			return err
		}
		out, err = GetTarget(ctx, tx, org.ID, current.ID)
		return err
	})
	return out, reports, err
}

// Transition is a Target state change.
type Transition string

const (
	Pause  Transition = "pause"
	Resume Transition = "resume"
	Revoke Transition = "revoke"
)

// SetTargetState is setTargetState: pausing (a recovery operation while
// frozen) and revoking fence a run in progress; resuming queues an
// immediate converge. Pausing a paused Target changes nothing; a disabled
// one cannot be paused, nor one whose Connection was revoked resumed.
func (s *Service) SetTargetState(ctx context.Context, req Request, org authz.Organization, targetID string, t Transition) (*Target, []auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	var out *Target
	var reports []auth.PendingReport
	err := s.Writer.Job(ctx, []write.Gate{write.Organization(org.ID, write.Shared), write.Person(actor, write.Shared)}, func(ctx context.Context, tx *storage.Tx) error {
		scope := write.Scope{OrganizationID: org.ID}
		if t == Pause {
			scope.DuringFreeze = authz.DuringFreezeRecovery
		}
		if err := write.CheckLive(ctx, tx, scope); err != nil {
			return err
		}
		current, err := GetTarget(ctx, tx, org.ID, targetID)
		if err != nil {
			return err
		}
		if reports, err = write.Checkpoint(ctx, tx, req.Principal, org.ID); err != nil {
			return err
		}
		q := query.New(tx)
		at := sql.NullInt64{Int64: s.now().UnixMicro(), Valid: true}
		event := "sync.target_resumed"
		switch t {
		case Revoke:
			event = "sync.target_revoked"
			err = q.RevokeTarget(ctx, query.RevokeTargetParams{At: at, ID: targetID})
		case Pause:
			if current.State == "disabled" {
				return invalid("This Target is already stopped (disabled); resume or re-point it instead of pausing")
			}
			if current.State == "paused" {
				out = &current
				return nil
			}
			event = "sync.target_paused"
			err = q.PauseTarget(ctx, query.PauseTargetParams{At: at, ID: targetID})
		default:
			if current.State == "disabled" && current.DisabledReason.Valid && current.DisabledReason.String == "connection-revoked" {
				return invalid("This Target's Connection is revoked; re-point it to another Connection before resuming")
			}
			err = q.ResumeTargetState(ctx, query.ResumeTargetStateParams{At: at, ID: targetID})
		}
		if err != nil {
			return err
		}
		action := "config.sync.manage"
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: event, Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID, Action: &action,
			Resource: jsvalue.Object{{Key: "targetId", Value: targetID}, {Key: "environmentId", Value: current.EnvironmentID}},
		}); err != nil {
			return err
		}
		if t != Revoke {
			got, err := GetTarget(ctx, tx, org.ID, targetID)
			if err != nil {
				return err
			}
			out = &got
		}
		return nil
	})
	return out, reports, err
}
