// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/targets"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// The read side of broker Capabilities (ADR-0022, domain/capabilities.ts):
// an exercise, and an issuance's precondition. A Capability narrows
// potential future use and never expands the Agent's Grants: an exercise
// evaluates the Agent's secret.use (with Tailnet Requirements) on the
// snapshot, resolves the effective versions then (Model B), and commits its
// audit event before anything is decrypted.

// RequireBroker is the routes' requireBroker: only a Broker of the
// Organization exercises a Capability, or issues one for itself; anyone
// else learns nothing.
func RequireBroker(p *auth.Principal, organizationID string) error {
	if p.Identity.Kind != "broker" || p.Identity.OrganizationID == nil || *p.Identity.OrganizationID != organizationID {
		return domainerr.New("RESOURCE_NOT_FOUND", "Not found")
	}
	return nil
}

// HashSecret is hashCapabilitySecret: SHA-256 of the secret, in hex.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// How a single-use Capability's secret is stored (ADR-0060): its hash
// behind one of these, so whether it is spent is part of what a secret is
// matched by. A server that does not know them (an earlier varlatchd after
// a rollback, the TypeScript server after a reverse migration) matches no
// secret against either, and refuses the exercise.
const (
	singleUseUnused = "once:"
	singleUseUsed   = "used:"
)

// StoredSecret is what a Capability's row keeps of its secret.
func StoredSecret(secret string, singleUse bool) string {
	if singleUse {
		return singleUseUnused + HashSecret(secret)
	}
	return HashSecret(secret)
}

// SecretState reads a stored secret: its hash, whether the Capability is
// single-use, and whether that use is spent.
func SecretState(stored string) (hash string, singleUse, used bool) {
	if h, ok := strings.CutPrefix(stored, singleUseUnused); ok {
		return h, true, false
	}
	if h, ok := strings.CutPrefix(stored, singleUseUsed); ok {
		return h, true, true
	}
	return stored, false, false
}

// errCapabilityEnded is a single-use Capability another exercise or a
// revocation got to first, between the snapshot and the use.
var errCapabilityEnded = errors.New("values: the Capability was used or revoked meanwhile")

// agentEvaluation is evaluateAgentSecretUse: the Agent's action on the
// environment, with the Organization's Requirements and the request's
// Tailnet Context (on a tailnet listener; none elsewhere).
func agentEvaluation(ctx context.Context, db query.DBTX, st *State, agentID, action string) (authz.Evaluation, error) {
	if _, err := write.Text(agentID); err != nil {
		return authz.Evaluation{}, err
	}
	grants, err := authz.LoadGrants(ctx, db, st.Org.ID, agentID)
	if err != nil {
		return authz.Evaluation{}, err
	}
	reqs, err := authz.LoadRequirements(ctx, db, st.Org.ID)
	if err != nil {
		return authz.Evaluation{}, err
	}
	return authz.Evaluate(authz.Input{Action: action, Resource: st.resource(), Grants: grants, Requirements: reqs, TailnetContext: authz.TailnetFrom(ctx)}), nil
}

// Precondition is an IssuancePrecondition (ADR-0038 Decision 7): the state
// the operator's preflight retrieval saw. It confers no authority.
type Precondition struct {
	ProjectID, EnvironmentID, StateDigest string
	StateDigests                          map[string]string
}

// PreflightItem is what issuance established about one item.
type PreflightItem struct {
	Name       string
	Present    bool
	Authorized bool
	Reason     string
}

// JSValue is the item as the TypeScript server answers it.
func (p PreflightItem) JSValue() any {
	o := jsvalue.Object{{Key: "name", Value: p.Name}, {Key: "present", Value: p.Present}, {Key: "authorized", Value: p.Authorized}}
	if p.Reason != "" {
		o = append(o, jsvalue.Member{Key: "reason", Value: p.Reason})
	}
	return o
}

// stateCategories is STATE_CATEGORIES.
var stateCategories = []string{"environment", "contract", "items", "rotation"}

// CheckPrecondition is checkIssuancePrecondition, in a snapshot of its own
// before the issuance: the state must be the one the preflight saw, or the
// categories that changed are returned (STATE_CHANGED). On a match, each
// item's presence as a Secret and the Agent's secret.use, decrypting
// nothing. Whether an exercise can resolve each reference is not decided
// here.
func (s *Service) CheckPrecondition(ctx context.Context, req Request, pre Precondition, agentID string, items []string) ([]PreflightItem, error) {
	var out []PreflightItem
	var changed []string
	err := s.snapshot(ctx, func(tx *sql.Tx, now int64) error {
		st, err := scope(ctx, tx, req)
		if err != nil {
			return err
		}
		if pre.ProjectID != st.Project.ID || pre.EnvironmentID != st.Env.ID {
			return domainerr.New("VALIDATION_FAILED", "The precondition names another project or Environment")
		}
		if err := capture(ctx, tx, &st, now, func(Item) bool { return false }); err != nil {
			return err
		}
		_, digest, err := st.Manifest()
		if err != nil {
			return err
		}
		if digest != pre.StateDigest {
			current, err := st.stateDigests()
			if err != nil {
				return err
			}
			for _, m := range current {
				if pre.StateDigests[m.Key] != m.Value {
					changed = append(changed, m.Key)
				}
			}
			if len(changed) == 0 {
				changed = stateCategories
			}
			return nil
		}
		e, err := agentEvaluation(ctx, tx, &st, agentID, "secret.use")
		if err != nil {
			return err
		}
		secrets := map[string]bool{}
		for _, it := range st.Items {
			if it.Sensitive {
				secrets[it.Name] = true
			}
		}
		for _, name := range items {
			p := PreflightItem{Name: name, Present: secrets[name], Authorized: e.Allowed}
			if !e.Allowed {
				p.Reason = "permission"
				if e.Denial == "requirement-failed" {
					p.Reason = "requirement"
				}
			}
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		return nil, s.refused(ctx, req, &tracker{}, err)
	}
	if changed != nil {
		// Categories only, never identifiers: the client retries both
		// requests once.
		list := make([]any, len(changed))
		for i, c := range changed {
			list[i] = c
		}
		return nil, &domainerr.Error{Code: "STATE_CHANGED", Message: "The configuration changed since the preflight retrieval",
			Details: jsvalue.Object{{Key: "categories", Value: list}}}
	}
	return out, nil
}

// Placement is one substitution the Broker will make (ADR-0039 Decision 7).
type Placement struct{ Item, Target string }

// Exercise is an exercise's body.
type Exercise struct {
	Secret     string
	Host       string
	Port       int
	Placements []Placement
}

// objectPrototype are the names a plain JavaScript object inherits:
// looking one up in a Capability's targets finds Object.prototype's member,
// which has no includes, and the TypeScript server fails (500).
var objectPrototype = []string{
	"__proto__", "constructor", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString",
	"toString", "valueOf", "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__",
}

// ExerciseCapability is POST …/capabilities/{capability}/exercises
// (exerciseCapability): in the snapshot, the environment, the Broker, the
// body (parse, once the Broker is known), the Capability, the Agent's
// secret.use and config.value.read, and the values; then the checks, each
// refusal audited as capability.denied; then capability.exercised,
// committed before the placed Secrets are decrypted, and each level of
// references, audited before it is decrypted (ADR-0026: resolve or deny).
func (s *Service) ExerciseCapability(ctx context.Context, req Request, capabilityID string, parse func() (Exercise, error)) (jsvalue.Object, error) {
	t := &tracker{}
	var st State
	var in Exercise
	var row *query.Capability
	var use, plainRead authz.Evaluation
	issuerAllowed := true
	bound := map[string]bool{}
	err := s.snapshot(ctx, func(tx *sql.Tx, now int64) error {
		var err error
		if st, err = scope(ctx, tx, req); err != nil {
			return err
		}
		if err := RequireBroker(req.Principal, st.Org.ID); err != nil {
			return err
		}
		if in, err = parse(); err != nil {
			return err
		}
		// captureExercise: the incident freeze, read in the snapshot.
		if err := authz.RefuseIfIncidentFrozen(ctx, tx, st.Org.ID, ""); err != nil {
			return err
		}
		if _, err := write.Text(capabilityID); err != nil {
			return err
		}
		r, err := query.New(tx).CapabilityOf(ctx, query.CapabilityOfParams{ID: capabilityID, OrganizationID: st.Org.ID, EnvironmentID: st.Env.ID})
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return err
		default:
			row = &r
			items, err := stringList(r.Items)
			if err != nil {
				return err
			}
			for _, n := range items {
				bound[n] = true
			}
			if use, err = agentEvaluation(ctx, tx, &st, r.AgentIdentityID, "secret.use"); err != nil {
				return err
			}
			if plainRead, err = agentEvaluation(ctx, tx, &st, r.AgentIdentityID, "config.value.read"); err != nil {
				return err
			}
			if r.CreatedBy != r.BrokerIdentityID {
				if issuerAllowed, err = issuerMayIssue(ctx, tx, &st, r.CreatedBy); err != nil {
					return err
				}
			}
		}
		if err := capture(ctx, tx, &st, now, func(it Item) bool {
			if it.Sensitive {
				return bound[it.Name]
			}
			return plainRead.Allowed
		}); err != nil {
			return err
		}
		// A Broker's (machine) request: exempt, but checked like any other.
		return t.requireAccess(ctx, tx, req, st.Org.ID, now)
	})
	if err != nil {
		return nil, s.refused(ctx, req, t, err)
	}
	broker := req.Principal.Identity.ID
	destination := in.Host + ":" + strconv.Itoa(in.Port)
	resource := func() jsvalue.Object {
		var agent any
		if row != nil {
			agent = row.AgentIdentityID
		}
		return jsvalue.Object{{Key: "capabilityId", Value: capabilityID}, {Key: "agentIdentityId", Value: agent},
			{Key: "projectId", Value: st.Project.ID}, {Key: "environmentId", Value: st.Env.ID}}
	}
	// issuer names who issued the Capability, when that is not its Broker.
	issuer := func() jsvalue.Object {
		if row == nil || row.CreatedBy == row.BrokerIdentityID {
			return nil
		}
		return jsvalue.Object{{Key: "issuedByIdentityId", Value: row.CreatedBy}}
	}
	// spent is set while this exercise holds a single-use Capability's use.
	spent := false
	deny := func(reason string, detail ...jsvalue.Member) error {
		md := append(jsvalue.Object{{Key: "reason", Value: reason}, {Key: "destination", Value: destination}}, detail...)
		md = append(md, issuer()...)
		event := audit.Event{
			Type: "capability.denied", Decision: audit.Deny, ActorIdentityID: ptr(broker), OrganizationID: ptr(st.Org.ID),
			Action: ptr("secret.use"), Resource: resource(), RequestID: ptr(req.RequestID), Metadata: md,
		}
		if err := s.store.Write(ctx, func(tx *storage.Tx) error {
			if spent {
				// Refused after all: the use is not spent.
				hash, _, _ := SecretState(row.SecretHash)
				if err := query.New(tx).ReleaseCapability(ctx, query.ReleaseCapabilityParams{ID: row.ID, Used: singleUseUsed + hash, Unused: singleUseUnused + hash}); err != nil {
					return err
				}
			}
			_, err := audit.Record(ctx, tx, event)
			return err
		}); err != nil {
			return err
		}
		return exerciseRefusal(reason, detail, authz.TailnetFrom(ctx) != nil)
	}

	if row == nil {
		return nil, deny("not-found")
	}
	if row.BrokerIdentityID != broker {
		return nil, deny("wrong-broker")
	}
	// An exercise-only credential bound to a run exercises that run's
	// Capabilities; another run's is as unknown to it as another Broker's.
	if x := req.Principal.Credential.ExerciseOnly; x != nil && x.RunID != nil && (!row.RunID.Valid || row.RunID.String != *x.RunID) {
		return nil, deny("wrong-run")
	}
	hash, singleUse, used := SecretState(row.SecretHash)
	if subtle.ConstantTimeCompare([]byte(HashSecret(in.Secret)), []byte(hash)) != 1 {
		return nil, deny("bad-secret")
	}
	if row.RevokedAt.Valid {
		return nil, deny("revoked")
	}
	if used {
		return nil, deny("already-used")
	}
	if row.ExpiresAt/1000 <= st.Now/1000 {
		return nil, deny("expired")
	}
	// Issued for this Broker by another identity: that identity may still
	// issue here (it is live and its Grant holds), as of this exercise.
	if !issuerAllowed {
		return nil, deny("issuer-not-allowed")
	}
	selectors, err := stringList(row.Destinations)
	if err != nil {
		return nil, err
	}
	matched := false
	for _, raw := range selectors {
		if sel, ok := authz.ParseDestinationSelector(raw); ok && sel.Matches(authz.Destination{Host: in.Host, Port: in.Port}) {
			matched = true
		}
	}
	if !matched {
		return nil, deny("destination-mismatch")
	}

	// Substitution targets (ADR-0039 Decisions 7 and 9): a Capability issued
	// before targets is never exercised, and the Broker names each
	// substitution it will make; only those items are returned.
	if !row.Targets.Valid {
		return nil, deny("capability-without-targets")
	}
	parsed, err := jsvalue.Parse([]byte(row.Targets.String))
	if err != nil {
		return nil, err
	}
	held, _ := jsvalue.Jsonb(parsed).(jsvalue.Object)
	if len(in.Placements) == 0 {
		return nil, deny("placement-not-targeted")
	}
	for _, p := range in.Placements {
		list, own := held.Get(p.Item)
		if !own && slices.Contains(objectPrototype, p.Item) {
			return nil, errors.New("values: a placement names a member of Object.prototype (the TypeScript server's TypeError)")
		}
		if l, ok := list.([]any); !ok || !slices.Contains(l, any(p.Target)) {
			return nil, deny("placement-not-targeted", jsvalue.Member{Key: "item", Value: p.Item}, jsvalue.Member{Key: "target", Value: p.Target})
		}
	}
	var placed []string
	for _, p := range in.Placements {
		placed = append(placed, p.Item)
	}
	slices.SortFunc(placed, targets.Compare)
	placed = slices.Compact(placed)

	// Model B: the effective versions and the Agent's secret.use, both as
	// the snapshot saw them.
	secrets := map[string]Item{}
	plainByName := map[string]Item{}
	for _, it := range st.Items {
		if it.Sensitive {
			secrets[it.Name] = it
		} else {
			plainByName[it.Name] = it
		}
	}
	var selected []Item
	withheld := []any{}
	for _, name := range placed {
		if it, ok := secrets[name]; ok {
			selected = append(selected, it)
		} else {
			withheld = append(withheld, name)
		}
	}
	if !use.Allowed {
		if use.Denial == "requirement-failed" {
			return nil, deny("requirement-failed")
		}
		return nil, deny("authz-denied")
	}

	runID := nullable(row.RunID)
	entries := make([]string, len(selected))
	var versions []string
	for i, it := range selected {
		entries[i] = it.Name + "@" + it.VersionID
		versions = append(versions, it.VersionID)
		if it.RetiringVersionID != "" {
			entries[i] += "+" + it.RetiringVersionID
			versions = append(versions, it.RetiringVersionID)
		}
	}
	placements := make([]string, len(in.Placements))
	for i, p := range in.Placements {
		placements[i] = p.Item + "=" + p.Target
	}
	exercised := jsvalue.Object{
		{Key: "destination", Value: destination}, {Key: "items", Value: strings.Join(entries, ",")},
		{Key: "placements", Value: strings.Join(placements, ";")}, {Key: "withheld", Value: len(withheld)}, {Key: "runId", Value: runID},
	}
	exercised = append(exercised, issuer()...)
	var spend beforeAudit
	ended := "already-used"
	if singleUse {
		exercised = append(exercised, jsvalue.Member{Key: "singleUse", Value: true})
		// The use is spent in capability.exercised's own job: two exercises
		// at once, and only one of them has it. From here on it stays
		// spent, whatever becomes of the answer, unless deny takes it back.
		spend = func(ctx context.Context, tx *storage.Tx) (jsvalue.Object, error) {
			q := query.New(tx)
			n, err := q.UseCapability(ctx, query.UseCapabilityParams{ID: row.ID, Unused: singleUseUnused + hash, Used: singleUseUsed + hash})
			if err != nil || n == 1 {
				return nil, err
			}
			now, err := q.CapabilityOf(ctx, query.CapabilityOfParams{ID: row.ID, OrganizationID: st.Org.ID, EnvironmentID: st.Env.ID})
			if err != nil {
				return nil, err
			}
			if now.RevokedAt.Valid {
				ended = "revoked"
			}
			return nil, errCapabilityEnded
		}
	}
	plaintext, err := s.auditThenDecrypt(ctx, &st, []audit.Event{{
		Type: "capability.exercised", Decision: audit.Allow, ActorIdentityID: ptr(broker), OrganizationID: ptr(st.Org.ID),
		Action: ptr("secret.use"), Resource: resource(), Authz: authz.AuditAuthz(use), RequestID: ptr(req.RequestID),
		Metadata: exercised,
	}}, versions, spend)
	if errors.Is(err, errCapabilityEnded) {
		return nil, deny(ended)
	}
	if err != nil {
		return nil, err
	}
	spent = singleUse

	type out struct {
		item     Item
		value    string
		retiring *string
	}
	results := make([]out, len(selected))
	lookup := map[string]string{}
	for i, it := range selected {
		results[i] = out{item: it, value: plaintext[it.VersionID]}
		lookup[it.Name] = results[i].value
		if it.RetiringVersionID != "" {
			// References resolve to primaries only (ADR-0027 §2): the
			// retiring copy is passed through unexpanded.
			r := plaintext[it.RetiringVersionID]
			results[i].retiring = &r
		}
	}

	// Reference expansion at exercise (ADR-0026): a referenced Secret must
	// be bound in this Capability, and a non-sensitive item is pulled in
	// only when the Agent may read it here; a bound Secret referenced but
	// not placed is decrypted to expand, never returned. One level at a
	// time, each named by a committed audit event before it is decrypted.
	type ref struct{ by, raw string }
	frontier := make([]ref, len(results))
	for i, r := range results {
		frontier[i] = ref{r.item.Name, r.value}
	}
	queued := map[string]bool{}
	for depth := 0; len(frontier) > 0 && depth < MaxReferenceDepth; depth++ {
		var secretNeeded, plainNeeded []Item
		var plainBy []string
		for _, f := range frontier {
			for _, name := range ReferencedNames(f.raw) {
				if _, have := lookup[name]; have || queued[name] {
					continue
				}
				if it, ok := secrets[name]; ok {
					if !bound[name] {
						return nil, deny("unresolved-reference", jsvalue.Member{Key: "reference", Value: name},
							jsvalue.Member{Key: "referencedBy", Value: f.by}, jsvalue.Member{Key: "cause", Value: "secret-not-bound"})
					}
					queued[name] = true
					secretNeeded = append(secretNeeded, it)
					continue
				}
				it, ok := plainByName[name]
				if !ok {
					return nil, deny("unresolved-reference", jsvalue.Member{Key: "reference", Value: name},
						jsvalue.Member{Key: "referencedBy", Value: f.by}, jsvalue.Member{Key: "cause", Value: "unknown-item"})
				}
				queued[name] = true
				plainNeeded, plainBy = append(plainNeeded, it), append(plainBy, f.by)
			}
		}
		if len(secretNeeded) == 0 && len(plainNeeded) == 0 {
			break
		}
		if len(plainNeeded) > 0 && !plainRead.Allowed {
			return nil, deny("unresolved-reference", jsvalue.Member{Key: "reference", Value: plainNeeded[0].Name},
				jsvalue.Member{Key: "referencedBy", Value: plainBy[0]}, jsvalue.Member{Key: "cause", Value: "plain-read-denied"})
		}
		var events []audit.Event
		names := func(list []Item) string {
			n := make([]string, len(list))
			for i, it := range list {
				n[i] = it.Name + "@" + it.VersionID
			}
			return strings.Join(n, ",")
		}
		if len(secretNeeded) > 0 {
			events = append(events, audit.Event{
				Type: "secret.disclosed", Decision: audit.Allow, ActorIdentityID: ptr(broker), OrganizationID: ptr(st.Org.ID),
				Action: ptr("secret.use"), Resource: resource(), Authz: authz.AuditAuthz(use), RequestID: ptr(req.RequestID),
				Metadata: jsvalue.Object{{Key: "mode", Value: "reference-expansion"}, {Key: "items", Value: names(secretNeeded)}, {Key: "runId", Value: runID}},
			})
		}
		if len(plainNeeded) > 0 {
			events = append(events, audit.Event{
				Type: "value.disclosed", Decision: audit.Allow, ActorIdentityID: ptr(broker), OrganizationID: ptr(st.Org.ID),
				Action: ptr("config.value.read"), Resource: resource(), Authz: authz.AuditAuthz(plainRead), RequestID: ptr(req.RequestID),
				Metadata: jsvalue.Object{{Key: "mode", Value: "reference-expansion"}, {Key: "items", Value: names(plainNeeded)}, {Key: "runId", Value: runID}},
			})
		}
		level := append(slices.Clone(secretNeeded), plainNeeded...)
		ids := make([]string, len(level))
		for i, it := range level {
			ids[i] = it.VersionID
		}
		decrypted, err := s.auditThenDecrypt(ctx, &st, events, ids, nil)
		if err != nil {
			return nil, err
		}
		frontier = frontier[:0]
		for _, it := range level {
			v := decrypted[it.VersionID]
			lookup[it.Name] = v
			frontier = append(frontier, ref{it.Name, v})
		}
	}
	items := make([]any, len(results))
	for i, r := range results {
		value, err := expandStrict(r.value, func(n string) (string, bool) { v, ok := lookup[n]; return v, ok })
		if err != nil {
			return nil, deny("unresolved-reference", jsvalue.Member{Key: "referencedBy", Value: r.item.Name},
				jsvalue.Member{Key: "cause", Value: "incomplete-or-excessive-expansion"})
		}
		o := jsvalue.Object{{Key: "name", Value: r.item.Name}, {Key: "versionId", Value: r.item.VersionID}, {Key: "value", Value: value}}
		if r.retiring != nil {
			o = append(o, jsvalue.Member{Key: "retiring", Value: jsvalue.Object{{Key: "versionId", Value: r.item.RetiringVersionID}, {Key: "value", Value: *r.retiring}}})
		}
		items[i] = o
	}
	s.settle(t)
	return jsvalue.Object{{Key: "items", Value: items}, {Key: "withheld", Value: withheld}, {Key: "targets", Value: held}}, nil
}

// issuerMayIssue is whether the identity that issued a Capability for
// another may still issue in st's environment: live, of a kind that may,
// and holding capability.issue.
func issuerMayIssue(ctx context.Context, db query.DBTX, st *State, issuerID string) (bool, error) {
	id, err := query.New(db).GetIdentity(ctx, issuerID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil || id.Disabled || !authz.MayIssueCapabilities(id.Kind) || id.OrganizationID.String != st.Org.ID {
		return false, err
	}
	grants, err := authz.LoadGrants(ctx, db, st.Org.ID, issuerID)
	if err != nil {
		return false, err
	}
	return authz.Evaluate(authz.Input{Action: authz.CapabilityIssue, Resource: st.resource(), Grants: grants}).Allowed, nil
}

// exerciseRefusal is the error deny throws for reason. Existence is hidden:
// only the bound Broker presenting the right secret learns more than
// not-found.
func exerciseRefusal(reason string, detail jsvalue.Object, tailnet bool) error {
	get := func(key string) string {
		v, _ := detail.Get(key)
		s, _ := v.(string)
		return s
	}
	details := append(jsvalue.Object{{Key: "reason", Value: reason}}, detail...)
	switch reason {
	case "not-found", "wrong-broker", "wrong-run", "bad-secret":
		return domainerr.New("RESOURCE_NOT_FOUND", "Capability not found")
	case "requirement-failed":
		if tailnet {
			return domainerr.New("TAILNET_CONTEXT_UNAVAILABLE", "Tailnet Context does not satisfy the required selector")
		}
		return domainerr.New("TAILNET_CONTEXT_REQUIRED", "This exercise requires trusted Tailnet Context")
	case "already-used":
		return &domainerr.Error{Code: "PERMISSION_DENIED", Message: "This Capability may be exercised once, and was", Details: details}
	case "issuer-not-allowed":
		return &domainerr.Error{Code: "PERMISSION_DENIED", Message: "The identity that issued this Capability may no longer issue Capabilities here", Details: details}
	case "capability-without-targets":
		return &domainerr.Error{Code: "PERMISSION_DENIED", Details: details,
			Message: "This Capability was issued before substitution targets were required. Restart the agent-safe run with Varlatch CLI 0.11.0 or later."}
	case "placement-not-targeted":
		msg := "The Broker named a placement this Capability does not hold"
		if get("item") != "" {
			msg += " (" + get("item") + " at " + get("target") + ")"
		}
		return &domainerr.Error{Code: "PERMISSION_DENIED", Message: msg, Details: details}
	case "unresolved-reference":
		reference, has := detail.Get("reference")
		if !has {
			reference = "undefined"
		}
		var which string
		switch get("cause") {
		case "secret-not-bound":
			which = "is a Secret this Capability does not name \u2014 bind it in the Capability's items"
		case "plain-read-denied":
			which = "the Agent's Grants do not allow reading here (config.value.read)"
		default:
			which = "does not exist in this environment \u2014 escape as $${NAME} if literal text is intended"
		}
		return &domainerr.Error{Code: "PERMISSION_DENIED", Details: details,
			Message: "Exercised material references ${" + reference.(string) + "} (in " + get("referencedBy") + "), which " + which}
	}
	return &domainerr.Error{Code: "PERMISSION_DENIED", Message: "Capability cannot be exercised", Details: details}
}

// stringList reads a text[] column, stored as a JSON array of strings.
func stringList(text string) ([]string, error) {
	v, err := jsvalue.Parse([]byte(text))
	if err != nil {
		return nil, err
	}
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out, nil
}
