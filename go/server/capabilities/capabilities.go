// SPDX-License-Identifier: AGPL-3.0-or-later

// Package capabilities is broker Capabilities' writes and their list
// (ADR-0022, ADR-0039; domain/capabilities.ts): a Broker issues a
// Capability for one of its Organization's Agents, naming explicit Config
// Items, destinations and, per item, where its Placeholder may be
// substituted; a Broker revokes its own, and a person with policy authority
// any of the Organization's. Its exercise is a retrieval (go/server/values).
package capabilities

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/targets"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// MaxTTLSeconds bounds a Capability's lifetime: a day.
const MaxTTLSeconds = 24 * 60 * 60

// itemName is CONFIG_ITEM_NAME_PATTERN.
var itemName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// Scope is the environment a Capability is issued in.
type Scope struct {
	OrganizationID, ProjectID, EnvironmentID string
	// Environment is everything authorization reads of it.
	Environment authz.Environment
}

// IssueInput is issueCapability's input, as the route's schema output it.
type IssueInput struct {
	AgentIdentityID string
	Items           []string
	Destinations    []string
	// Targets is per item, in the order the body's object enumerates them;
	// nil when the body has none (a CLI older than 0.11.0).
	Targets    []targets.Item
	TTLSeconds int64
	RunID      *string
}

func invalid(msg string) error { return domainerr.New("VALIDATION_FAILED", msg) }

// Issue is issueCapability: the input checked, then, in a job with the
// writer's checks (the Organization's, the Broker's and the Agent's gates
// held shared), the Broker's credential still live, the Agent named, the advisory preflight (the Agent's
// secret.use without Requirements, which depend on an exercise's Tailnet
// Context), the row and capability.issued. Its secret is returned once;
// only its hash is stored. preflightItems, when set, is added to the
// answer.
func Issue(ctx context.Context, w *write.Writer, p *auth.Principal, s Scope, in IssueInput, preflightItems []values.PreflightItem, now func() time.Time) (jsvalue.Object, []auth.PendingReport, error) {
	if len(in.Items) == 0 {
		return nil, nil, invalid("A Capability names explicit Config Items")
	}
	for _, item := range in.Items {
		if !itemName.MatchString(item) {
			return nil, nil, invalid("Invalid Config Item name: " + item)
		}
	}
	if len(in.Destinations) == 0 {
		return nil, nil, invalid("A Capability names explicit destinations")
	}
	selectors := make([]string, len(in.Destinations))
	for i, raw := range in.Destinations {
		sel, ok := authz.ParseDestinationSelector(raw)
		if !ok {
			return nil, nil, invalid("Invalid destination selector: " + raw)
		}
		selectors[i] = sel.String()
	}
	// Targets are required and validated here (ADR-0039 Decision 6).
	if in.Targets == nil {
		return nil, nil, invalid("Capabilities need substitution targets for every item; issue them with Varlatch CLI 0.11.0 or later (--target NAME=kind:location)")
	}
	canonical, err := targets.Canonical(in.Items, in.Targets)
	var te *targets.Error
	if errors.As(err, &te) {
		return nil, nil, invalid(te.Message)
	}
	if err != nil {
		return nil, nil, err
	}
	if in.TTLSeconds < 1 || in.TTLSeconds > MaxTTLSeconds {
		return nil, nil, invalid("ttlSeconds must be 1.." + strconv.Itoa(MaxTTLSeconds))
	}

	broker := p.Identity.ID
	id := ids.New(ids.Capability)
	secret := "vlt_cap_" + randomToken()
	at := now()
	expires := (at.UnixMilli() + in.TTLSeconds*1000) * 1000
	expiresAt := audit.ISOTime(expires)
	targetsObj := jsvalue.Object{}
	for _, t := range canonical {
		list := make([]any, len(t.Targets))
		for i, x := range t.Targets {
			list[i] = x
		}
		targetsObj = append(targetsObj, jsvalue.Member{Key: t.Name, Value: list})
	}
	var runID any
	if in.RunID != nil {
		runID = *in.RunID
	}
	preflight := ""
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(s.OrganizationID, write.Shared), write.Person(broker, write.Shared), write.Person(in.AgentIdentityID, write.Shared)}
	err = w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if _, err := write.Text(in.AgentIdentityID); err != nil {
			return err
		}
		// The request authenticated before the gates. Retirement holds the
		// Broker's gate exclusive while it disables it, revokes its
		// credentials and its Capabilities: with the gate held here, a
		// retirement is either seen or comes after this Capability, which
		// it then revokes. Its expiry is read against the clock now, in the
		// job: the request may have waited for the gates past it.
		live, err := query.New(tx).LiveRequesterCredential(ctx, query.LiveRequesterCredentialParams{
			ID: p.Credential.ID, IdentityID: broker, Now: sql.NullInt64{Int64: now().UnixMicro(), Valid: true},
		})
		if err != nil {
			return err
		}
		if live == 0 {
			return domainerr.New("INVALID_CREDENTIAL", "Credential is invalid, revoked, or expired")
		}
		agent, err := query.New(tx).CapabilityAgent(ctx, query.CapabilityAgentParams{ID: in.AgentIdentityID, OrganizationID: sql.NullString{String: s.OrganizationID, Valid: true}})
		if errors.Is(err, sql.ErrNoRows) || err == nil && agent.Kind != "agent" {
			return invalid("agentIdentityId must name an agent identity in this organization")
		}
		if err != nil {
			return err
		}
		if agent.Disabled {
			return invalid("Agent identity is disabled")
		}
		grants, err := authz.LoadGrants(ctx, tx, s.OrganizationID, agent.ID)
		if err != nil {
			return err
		}
		env := s.Environment
		e := authz.Evaluate(authz.Input{Action: "secret.use", Grants: grants,
			Resource: authz.Resource{OrganizationID: s.OrganizationID, ProjectID: s.ProjectID, Environment: &env}})
		preflight = "agent-lacks-secret-use"
		if e.Allowed {
			preflight = "ok"
		}
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: s.OrganizationID, ProjectID: s.ProjectID, EnvironmentIDs: []string{s.EnvironmentID}}); err != nil {
			return err
		}
		if reports, err = write.Checkpoint(ctx, tx, p, s.OrganizationID); err != nil {
			return err
		}
		var run sql.NullString
		if in.RunID != nil {
			stored, err := write.Text(*in.RunID)
			if err != nil {
				return err
			}
			run = sql.NullString{String: stored, Valid: true}
		}
		if err := jsvalue.JsonbRefuses(targetsObj); err != nil {
			return write.ErrPostgresText
		}
		if err := query.New(tx).InsertCapability(ctx, query.InsertCapabilityParams{
			ID: id, OrganizationID: s.OrganizationID, BrokerIdentityID: broker, AgentIdentityID: agent.ID,
			ProjectID: s.ProjectID, EnvironmentID: s.EnvironmentID, Items: list(in.Items), Destinations: list(selectors),
			Targets:    sql.NullString{String: string(jsvalue.Stringify(jsvalue.Jsonb(targetsObj))), Valid: true},
			SecretHash: values.HashSecret(secret), RunID: run, ExpiresAt: expires, CreatedAt: at.UnixMicro(),
		}); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "capability.issued", Decision: audit.Info, ActorIdentityID: &broker, OrganizationID: &s.OrganizationID,
			Action: ptr("secret.use"),
			Resource: jsvalue.Object{{Key: "capabilityId", Value: id}, {Key: "agentIdentityId", Value: agent.ID},
				{Key: "projectId", Value: s.ProjectID}, {Key: "environmentId", Value: s.EnvironmentID}},
			Metadata: jsvalue.Object{
				{Key: "items", Value: strings.Join(in.Items, ",")}, {Key: "destinations", Value: strings.Join(selectors, ",")},
				{Key: "targets", Value: targets.Describe(canonical)}, {Key: "runId", Value: runID},
				{Key: "expiresAt", Value: expiresAt}, {Key: "preflight", Value: preflight},
			},
		})
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	items := make([]any, len(in.Items))
	for i, x := range in.Items {
		items[i] = x
	}
	dests := make([]any, len(selectors))
	for i, x := range selectors {
		dests[i] = x
	}
	out := jsvalue.Object{
		{Key: "id", Value: id}, {Key: "secret", Value: secret}, {Key: "agentIdentityId", Value: in.AgentIdentityID},
		{Key: "environmentId", Value: s.EnvironmentID}, {Key: "items", Value: items}, {Key: "destinations", Value: dests},
		{Key: "targets", Value: targetsObj}, {Key: "runId", Value: runID}, {Key: "expiresAt", Value: expiresAt},
		{Key: "preflight", Value: preflight},
	}
	if preflightItems != nil {
		list := make([]any, len(preflightItems))
		for i, x := range preflightItems {
			list[i] = x
		}
		out = append(out, jsvalue.Member{Key: "preflightItems", Value: list})
	}
	return out, reports, nil
}

// List is listCapabilities as the route answers it: an environment's
// Capabilities, newest first; only broker's own when broker is set.
func List(ctx context.Context, db query.DBTX, organizationID, environmentID, broker string) (jsvalue.Object, error) {
	var filter any
	if broker != "" {
		filter = broker
	}
	rows, err := query.New(db).ListCapabilities(ctx, query.ListCapabilitiesParams{OrganizationID: organizationID, EnvironmentID: environmentID, Broker: filter})
	if err != nil {
		return nil, err
	}
	items := make([]any, len(rows))
	for i, r := range rows {
		itemList, err := jsvalue.Parse([]byte(r.Items))
		if err != nil {
			return nil, err
		}
		destList, err := jsvalue.Parse([]byte(r.Destinations))
		if err != nil {
			return nil, err
		}
		var run, revoked any
		if r.RunID.Valid {
			run = r.RunID.String
		}
		if r.RevokedAt.Valid {
			revoked = audit.ISOTime(r.RevokedAt.Int64)
		}
		items[i] = jsvalue.Object{
			{Key: "id", Value: r.ID}, {Key: "brokerIdentityId", Value: r.BrokerIdentityID}, {Key: "agentIdentityId", Value: r.AgentIdentityID},
			{Key: "environmentId", Value: r.EnvironmentID}, {Key: "items", Value: itemList}, {Key: "destinations", Value: destList},
			{Key: "runId", Value: run}, {Key: "expiresAt", Value: audit.ISOTime(r.ExpiresAt)}, {Key: "revokedAt", Value: revoked},
			{Key: "createdAt", Value: audit.ISOTime(r.CreatedAt)},
		}
	}
	return jsvalue.Object{{Key: "items", Value: items}, {Key: "nextCursor", Value: nil}}, nil
}

// Revoke is revokeCapability: in a job with the writer's checks (recovery
// while frozen; the Organization's and the actor's gates shared), the
// Capability unrevoked in the Organization (the Broker's own, when broker
// is set; in any of its environments), then the passkey-verification
// checkpoint, then revoked_at and capability.revoked.
func Revoke(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, capabilityID, broker string, now func() time.Time) ([]auth.PendingReport, error) {
	actor := p.Identity.ID
	var filter any
	if broker != "" {
		filter = broker
	}
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(organizationID, write.Shared), write.Person(actor, write.Shared)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID, DuringFreeze: authz.DuringFreezeRecovery}); err != nil {
			return err
		}
		if _, err := write.Text(capabilityID); err != nil {
			return err
		}
		q := query.New(tx)
		// Existence first, then passkey-verification (ADR-0054 Decision 7).
		_, err := q.LiveCapability(ctx, query.LiveCapabilityParams{ID: capabilityID, OrganizationID: organizationID, Broker: filter})
		if errors.Is(err, sql.ErrNoRows) {
			return domainerr.NotFound("Capability")
		}
		if err != nil {
			return err
		}
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return err
		}
		n, err := q.RevokeCapability(ctx, query.RevokeCapabilityParams{
			Now: sql.NullInt64{Int64: now().UnixMicro(), Valid: true}, ID: capabilityID, OrganizationID: organizationID, Broker: filter,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return domainerr.NotFound("Capability")
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "capability.revoked", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
			Action: ptr("secret.use"), Resource: jsvalue.Object{{Key: "capabilityId", Value: capabilityID}},
		})
		return err
	})
	return reports, err
}

// list is a text[] value as stored: a JSON array of strings.
func list(xs []string) string {
	a := make([]any, len(xs))
	for i, x := range xs {
		a[i] = x
	}
	return string(jsvalue.Stringify(a))
}

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func ptr(s string) *string { return &s }
