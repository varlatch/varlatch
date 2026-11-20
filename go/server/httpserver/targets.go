// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	vsync "github.com/varlatch/varlatch/go/lib/sync"
	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/contracts"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/environments"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/syncs"
)

// Sync Targets (ADR-0031, ADR-0050; ADR-0059 step 4.9c), as http/app.ts
// serves them: config.sync.manage, existence hidden, on the Organization
// (its listing) or on the environment. Listing is inspection while frozen
// and pausing a recovery operation. Creating one, and a change that
// widens what it discloses, re-points it or changes its destination, run
// the write-time disclosure gate (secret.reveal and config.value.read on
// the environment, as the mapping needs them) and record its decisions.
// pushSyncTarget comes with the converge engine (4.9d).

const (
	listOrgSyncTargetsPattern = "GET /v1/organizations/{org}/sync-targets"
	listSyncTargetsPattern    = "GET /v1/organizations/{org}/projects/{project}/environments/{environment}/sync-targets"
	createSyncTargetPattern   = "POST /v1/organizations/{org}/projects/{project}/environments/{environment}/sync-targets"
	getSyncTargetPattern      = "GET /v1/organizations/{org}/projects/{project}/environments/{environment}/sync-targets/{target}"
	updateSyncTargetPattern   = "PATCH /v1/organizations/{org}/projects/{project}/environments/{environment}/sync-targets/{target}"
	revokeSyncTargetPattern   = "DELETE /v1/organizations/{org}/projects/{project}/environments/{environment}/sync-targets/{target}"
	pauseSyncTargetPattern    = "POST /v1/organizations/{org}/projects/{project}/environments/{environment}/sync-targets/{target}/pause"
	resumeSyncTargetPattern   = "POST /v1/organizations/{org}/projects/{project}/environments/{environment}/sync-targets/{target}/resume"
	pushSyncTargetPattern     = "POST /v1/organizations/{org}/projects/{project}/environments/{environment}/sync-targets/{target}/push"
	orgSyncTargetsRoute       = "/v1/organizations/:org/sync-targets"
	syncTargetsRoute          = "/v1/organizations/:org/projects/:project/environments/:environment/sync-targets"
	syncTargetRoute           = syncTargetsRoute + "/:target"
)

// pauseWait and pauseWaitPoll are PAUSE_WAIT_MS and PAUSE_WAIT_POLL_MS:
// ?wait=true holds a pause's answer until no run of the Target can start
// another request, for at most 30 s.
var (
	pauseWait     = 30 * time.Second
	pauseWaitPoll = 250 * time.Millisecond
)

func init() {
	for _, p := range []string{listOrgSyncTargetsPattern, listSyncTargetsPattern, createSyncTargetPattern, getSyncTargetPattern,
		updateSyncTargetPattern, revokeSyncTargetPattern, pauseSyncTargetPattern, resumeSyncTargetPattern, pushSyncTargetPattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitListOrgSyncTargetsResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitPushSyncTargetResponse(w http.ResponseWriter) error     { return r.visit(w) }
func (r reply) VisitListSyncTargetsResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitCreateSyncTargetResponse(w http.ResponseWriter) error   { return r.visit(w) }
func (r reply) VisitGetSyncTargetResponse(w http.ResponseWriter) error      { return r.visit(w) }
func (r reply) VisitUpdateSyncTargetResponse(w http.ResponseWriter) error   { return r.visit(w) }
func (r reply) VisitRevokeSyncTargetResponse(w http.ResponseWriter) error   { return r.visit(w) }
func (r reply) VisitPauseSyncTargetResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitResumeSyncTargetResponse(w http.ResponseWriter) error   { return r.visit(w) }

// zDiscriminated is z.discriminatedUnion(key, options): an object whose
// key names one option, parsed as that option.
type zDiscriminated struct {
	key     string
	values  []string
	options []zObject
}

func (d zDiscriminated) parse(v any, present bool, path []string) (any, []zIssue) {
	obj, ok := v.(jsvalue.Object)
	if !present || !ok {
		return nil, []zIssue{{path, "Invalid input: expected object, received " + received(v, present), true}}
	}
	tag, _ := obj.Get(d.key)
	for i, value := range d.values {
		if tag == value {
			return d.options[i].parse(v, present, path)
		}
	}
	return nil, []zIssue{{zPath(path, d.key), "Invalid discriminator value. Expected '" + strings.Join(d.values, "' | '") + "'", true}}
}

var (
	// mappingSchema is the mapping: a wildcard (with exclusions, shape
	// only here) or explicit items.
	mappingSchema = zDiscriminated{key: "kind", values: []string{"wildcard", "explicit"}, options: []zObject{
		{{name: "kind", schema: zLiteral("wildcard")}, {name: "exclude", schema: zArray{element: zString{min: 1, max: 200}, max: 200}, optional: true}},
		{{name: "kind", schema: zLiteral("explicit")}, {name: "items", schema: zArray{element: zObject{
			{name: "name", schema: zString{min: 1, max: 200}},
			{name: "rename", schema: zString{min: 1, max: 200}, optional: true},
		}, min: 1, max: 500}}},
	}}
	createTargetBody = zObject{
		{name: "connectionId", schema: zString{min: 1}},
		{name: "destination", schema: zRecord{value: zUnknown{}}},
		{name: "mapping", schema: mappingSchema},
		{name: "removeOrphans", schema: zBool{}, optional: true},
		{name: "redeploy", schema: zBool{}, optional: true},
	}
	updateTargetBody = zObject{
		{name: "expectedVersion", schema: zInt{min: 1}},
		{name: "connectionId", schema: zString{min: 1}, optional: true},
		{name: "destination", schema: zRecord{value: zUnknown{}}, optional: true},
		{name: "mapping", schema: mappingSchema, optional: true},
		{name: "removeOrphans", schema: zBool{}, optional: true},
		{name: "redeploy", schema: zBool{}, optional: true},
	}
)

// targetRequest is targetEnvScope's: the environment's request, with
// config.sync.manage authorized on it.
type targetRequest struct {
	*projectRequest
	env environments.Environment
}

func (o *operations) targetEnv(ctx context.Context, route, exception string) (*targetRequest, error) {
	p, env, err := o.enterEnvironment(ctx, route, exception)
	if err != nil {
		return nil, err
	}
	if err := p.authorizeOn(ctx, "config.sync.manage", p.envResource(env)); err != nil {
		return nil, err
	}
	return &targetRequest{p, env}, nil
}

// target is targetScope: the environment's request and its live Target.
// route is the operation's own, as a freeze denial records it.
func (o *operations) target(ctx context.Context, route, exception string) (*targetRequest, syncs.Target, error) {
	t, err := o.targetEnv(ctx, route, exception)
	if err != nil {
		return nil, syncs.Target{}, err
	}
	target, err := syncs.GetTarget(ctx, o.s.opts.Auth.Store().Reader(), t.org.ID, pathSegment(t.r, 8))
	if err == nil && target.EnvironmentID != t.env.ID {
		err = domainerr.New("RESOURCE_NOT_FOUND", "Sync Target not found")
	}
	return t, target, err
}

// sensitivity is sensitivityOf on the Project's active Contract.
func (t *targetRequest) sensitivity(ctx context.Context) (func(string) bool, error) {
	active, err := contracts.Active(ctx, t.o.s.opts.Auth.Store().Reader(), t.project.ID, t.project.ActiveContractRevisionID)
	if err != nil {
		return nil, err
	}
	return func(name string) bool {
		if active != nil {
			for _, it := range active.Items {
				if it.Name == name {
					return it.Sensitive
				}
			}
		}
		return true
	}, nil
}

// disclosureGate is syncDisclosureGate: each action the mapping needs on
// the environment, authorized as authorize does (a denial recorded and
// answered), with the decisions every allowed action records.
func (t *targetRequest) disclosureGate(ctx context.Context, m syncs.Mapping, sensitive func(string) bool) (jsvalue.Object, error) {
	reader := t.o.s.opts.Auth.Store().Reader()
	decisions := jsvalue.Object{}
	for _, action := range syncs.RequiredDisclosureActions(m, sensitive) {
		d, err := authz.Decide(ctx, reader, authzPrincipal(t.p), action, t.envResource(t.env), authz.Options{RequestID: requestIDOf(t.r)})
		if err != nil {
			return nil, err
		}
		if !d.Allowed {
			if d.DenialEvent != nil {
				if err := t.o.s.opts.Auth.Store().Write(ctx, func(tx *storage.Tx) error { return authz.RecordDenial(ctx, tx, d) }); err != nil {
					return nil, err
				}
			}
			return nil, d.Err
		}
		decisions = append(decisions, jsvalue.Member{Key: action, Value: authz.AuditAuthz(d.Evaluation)})
	}
	return decisions, nil
}

// canonicalDestination is canonicalDestinationOf.
func canonicalDestination(platform string, raw jsvalue.Object) (vsync.Fields, error) {
	adapter, err := vsync.GetAdapter(platform)
	if err == nil {
		var d vsync.Destination
		if d, err = adapter.CanonicalizeDestination(syncs.SyncObject(raw)); err == nil {
			return d.Fields, nil
		}
	}
	if ae, ok := err.(*vsync.AdapterError); ok {
		return nil, domainerr.New("VALIDATION_FAILED", ae.Message)
	}
	return nil, err
}

func (o *operations) targetsJS(ctx context.Context, targets []syncs.Target) ([]any, error) {
	return syncs.TargetsJS(ctx, o.s.opts.Auth.Store().Reader(), targets, o.s.opts.Now().UnixMicro())
}

func (o *operations) targetJS(ctx context.Context, t syncs.Target) (jsvalue.Object, error) {
	out, err := o.targetsJS(ctx, []syncs.Target{t})
	if err != nil {
		return nil, err
	}
	return out[0].(jsvalue.Object), nil
}

// ListOrgSyncTargets is GET /v1/organizations/{org}/sync-targets:
// inspection while frozen, config.sync.manage on the Organization.
func (o *operations) ListOrgSyncTargets(ctx context.Context, _ api.ListOrgSyncTargetsRequestObject) (api.ListOrgSyncTargetsResponseObject, error) {
	q, err := o.syncManage(ctx, orgSyncTargetsRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	targets, err := syncs.ListTargets(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID, "")
	if err != nil {
		return nil, err
	}
	items, err := o.targetsJS(ctx, targets)
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return listed(items), nil
}

// ListSyncTargets is GET …/sync-targets: inspection while frozen.
func (o *operations) ListSyncTargets(ctx context.Context, _ api.ListSyncTargetsRequestObject) (api.ListSyncTargetsResponseObject, error) {
	t, err := o.targetEnv(ctx, syncTargetsRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	targets, err := syncs.ListTargets(ctx, o.s.opts.Auth.Store().Reader(), t.org.ID, t.env.ID)
	if err != nil {
		return nil, err
	}
	items, err := o.targetsJS(ctx, targets)
	if err != nil {
		return nil, err
	}
	if err := t.settle(ctx); err != nil {
		return nil, err
	}
	return listed(items), nil
}

// CreateSyncTarget is POST …/sync-targets: the body, the Connection, the
// mapping normalized against its destination, the disclosure gate, then
// the Target. 201.
func (o *operations) CreateSyncTarget(ctx context.Context, _ api.CreateSyncTargetRequestObject) (api.CreateSyncTargetResponseObject, error) {
	if err := o.assertSyncEnabled(); err != nil {
		return nil, err
	}
	t, err := o.targetEnv(ctx, syncTargetsRoute, "")
	if err != nil {
		return nil, err
	}
	raw, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(createTargetBody, raw)
	if err != nil {
		return nil, err
	}
	body := parsed.(jsvalue.Object)
	connectionID, _ := body.Get("connectionId")
	destination, _ := body.Get("destination")
	mappingRaw, _ := body.Get("mapping")
	reader := o.s.opts.Auth.Store().Reader()
	c, err := syncs.Get(ctx, reader, t.org.ID, connectionID.(string))
	if err != nil {
		return nil, err
	}
	sensitive, err := t.sensitivity(ctx)
	if err != nil {
		return nil, err
	}
	dest, err := canonicalDestination(c.Platform, destination.(jsvalue.Object))
	if err != nil {
		return nil, err
	}
	mapping, err := syncs.NormalizeMapping(c.Platform, mappingRaw.(jsvalue.Object), sensitive, nil, dest)
	if err != nil {
		return nil, err
	}
	decisions, err := t.disclosureGate(ctx, mapping, sensitive)
	if err != nil {
		return nil, err
	}
	in := syncs.TargetInput{ConnectionID: c.ID, Destination: destination.(jsvalue.Object), Mapping: mapping}
	if v, ok := body.Get("removeOrphans"); ok {
		in.RemoveOrphans = v == true
	}
	if v, ok := body.Get("redeploy"); ok {
		in.Redeploy = v == true
	}
	created, reports, err := o.syncService().CreateTarget(ctx, orgOf(t).syncRequest(ctx), t.org, t.project.ID, t.env.ID, in, decisions)
	if err != nil {
		return nil, t.refused(ctx, err)
	}
	if err := orgOf(t).written(ctx, reports); err != nil {
		return nil, err
	}
	out, err := o.targetJS(ctx, created)
	if err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: out}, nil
}

func orgOf(t *targetRequest) *orgRequest { return t.orgRequest }

// GetSyncTarget is GET …/sync-targets/{target}: the Target with its
// per-name delivery state.
func (o *operations) GetSyncTarget(ctx context.Context, _ api.GetSyncTargetRequestObject) (api.GetSyncTargetResponseObject, error) {
	t, target, err := o.target(ctx, syncTargetRoute, "")
	if err != nil {
		return nil, err
	}
	names, err := syncs.LedgerJS(ctx, o.s.opts.Auth.Store().Reader(), target.ID)
	if err != nil {
		return nil, err
	}
	out, err := o.targetJS(ctx, target)
	if err != nil {
		return nil, err
	}
	if err := t.settle(ctx); err != nil {
		return nil, err
	}
	return ok(append(out, jsvalue.Member{Key: "names", Value: names})), nil
}

// UpdateSyncTarget is PATCH …/sync-targets/{target}: a destination change,
// a re-point or a widening mapping runs the disclosure gate; a narrowing
// or an operational toggle needs only config.sync.manage.
func (o *operations) UpdateSyncTarget(ctx context.Context, _ api.UpdateSyncTargetRequestObject) (api.UpdateSyncTargetResponseObject, error) {
	if err := o.assertSyncEnabled(); err != nil {
		return nil, err
	}
	t, target, err := o.target(ctx, syncTargetRoute, "")
	if err != nil {
		return nil, err
	}
	raw, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(updateTargetBody, raw)
	if err != nil {
		return nil, err
	}
	body := parsed.(jsvalue.Object)
	version, _ := body.Get("expectedVersion")
	patch := syncs.TargetPatch{ExpectedVersion: int64(version.(float64)), ConnectionID: optionalString(body, "connectionId")}
	connectionID := target.ConnectionID
	if patch.ConnectionID != nil {
		connectionID = *patch.ConnectionID
	}
	reader := o.s.opts.Auth.Store().Reader()
	c, err := syncs.Get(ctx, reader, t.org.ID, connectionID)
	if err != nil {
		return nil, err
	}
	sensitive, err := t.sensitivity(ctx)
	if err != nil {
		return nil, err
	}
	destinationRaw, hasDestination := body.Get("destination")
	destination := jsvalue.Object{}
	if hasDestination {
		destination = destinationRaw.(jsvalue.Object)
		patch.Destination, patch.HasDestination = destination, true
	} else {
		v, err := jsvalue.Parse([]byte(target.Destination))
		if err != nil {
			return nil, err
		}
		o, ok := jsvalue.JSOrder(v).(jsvalue.Object)
		if !ok {
			return nil, errors.New("the Sync Target's stored destination is not an object")
		}
		destination = o
	}
	dest, err := canonicalDestination(c.Platform, destination)
	if err != nil {
		return nil, err
	}
	prev, err := syncs.ParseMapping(target.Mapping)
	if err != nil {
		return nil, err
	}
	mapping := prev
	mappingRaw, hasMapping := body.Get("mapping")
	if hasMapping {
		if mapping, err = syncs.NormalizeMapping(c.Platform, mappingRaw.(jsvalue.Object), sensitive, &prev, dest); err != nil {
			return nil, err
		}
		patch.Mapping = &mapping
	} else if hasDestination && !prev.Wildcard {
		// A new destination re-checks the names of the mapping it keeps.
		if _, err := syncs.NormalizeMapping(c.Platform, prev.JS(), sensitive, &prev, dest); err != nil {
			return nil, err
		}
	}
	if v, ok := body.Get("removeOrphans"); ok {
		b := v == true
		patch.RemoveOrphans = &b
	}
	if v, ok := body.Get("redeploy"); ok {
		b := v == true
		patch.Redeploy = &b
	}
	var decisions jsvalue.Object
	if hasDestination || patch.ConnectionID != nil || (hasMapping && syncs.MappingWidens(prev, mapping)) {
		if decisions, err = t.disclosureGate(ctx, mapping, sensitive); err != nil {
			return nil, err
		}
	}
	updated, reports, err := o.syncService().UpdateTarget(ctx, orgOf(t).syncRequest(ctx), t.org, target, patch, decisions)
	if err != nil {
		return nil, t.refused(ctx, err)
	}
	if err := orgOf(t).written(ctx, reports); err != nil {
		return nil, err
	}
	out, err := o.targetJS(ctx, updated)
	if err != nil {
		return nil, err
	}
	return ok(out), nil
}

// PauseSyncTarget is POST …/{target}/pause: a recovery operation while
// frozen. With ?wait=true the answer waits, for at most 30 s, until no run
// of the Target can start another request. The Target is read again: it
// may have been resumed, or revoked (not found), meanwhile.
func (o *operations) PauseSyncTarget(ctx context.Context, _ api.PauseSyncTargetRequestObject) (api.PauseSyncTargetResponseObject, error) {
	t, target, err := o.target(ctx, syncTargetRoute+"/pause", authz.DuringFreezeRecovery)
	if err != nil {
		return nil, err
	}
	_, reports, err := o.syncService().SetTargetState(ctx, orgOf(t).syncRequest(ctx), t.org, target.ID, syncs.Pause)
	if err != nil {
		return nil, t.refused(ctx, err)
	}
	if err := orgOf(t).written(ctx, reports); err != nil {
		return nil, err
	}
	reader := o.s.opts.Auth.Store().Reader()
	if rawOf(ctx).query.Get("wait") == "true" { // the query as sent (keepRaw)
		until := time.Now().Add(pauseWait)
		for time.Now().Before(until) && ctx.Err() == nil {
			running, err := syncs.Running(ctx, reader, target.ID, o.s.opts.Now().UnixMicro())
			if err != nil || !running {
				break
			}
			select {
			case <-ctx.Done():
			case <-time.After(pauseWaitPoll):
			}
		}
	}
	again, err := syncs.GetTarget(ctx, reader, t.org.ID, target.ID)
	if err != nil {
		return nil, err
	}
	out, err := o.targetJS(ctx, again)
	if err != nil {
		return nil, err
	}
	return ok(out), nil
}

// PushSyncTarget is POST …/{target}/push: the Target due at the engine's
// next pass, its backoff cleared. 202.
func (o *operations) PushSyncTarget(ctx context.Context, _ api.PushSyncTargetRequestObject) (api.PushSyncTargetResponseObject, error) {
	t, target, err := o.target(ctx, syncTargetRoute+"/push", "")
	if err != nil {
		return nil, err
	}
	if err := o.assertSyncEnabled(); err != nil {
		return nil, err
	}
	reports, err := o.syncService().RequestPush(ctx, orgOf(t).syncRequest(ctx), t.org, target.ID)
	if err != nil {
		return nil, t.refused(ctx, err)
	}
	if err := orgOf(t).written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusAccepted, body: jsvalue.Object{{Key: "scheduled", Value: true}}}, nil
}

// ResumeSyncTarget is POST …/{target}/resume: an immediate converge.
func (o *operations) ResumeSyncTarget(ctx context.Context, _ api.ResumeSyncTargetRequestObject) (api.ResumeSyncTargetResponseObject, error) {
	if err := o.assertSyncEnabled(); err != nil {
		return nil, err
	}
	t, target, err := o.target(ctx, syncTargetRoute+"/resume", "")
	if err != nil {
		return nil, err
	}
	updated, reports, err := o.syncService().SetTargetState(ctx, orgOf(t).syncRequest(ctx), t.org, target.ID, syncs.Resume)
	if err != nil {
		return nil, t.refused(ctx, err)
	}
	if err := orgOf(t).written(ctx, reports); err != nil {
		return nil, err
	}
	out, err := o.targetJS(ctx, *updated)
	if err != nil {
		return nil, err
	}
	return ok(out), nil
}

// RevokeSyncTarget is DELETE …/{target}: releases the destination claim
// and fences a run in progress. 204.
func (o *operations) RevokeSyncTarget(ctx context.Context, _ api.RevokeSyncTargetRequestObject) (api.RevokeSyncTargetResponseObject, error) {
	t, target, err := o.target(ctx, syncTargetRoute, "")
	if err != nil {
		return nil, err
	}
	_, reports, err := o.syncService().SetTargetState(ctx, orgOf(t).syncRequest(ctx), t.org, target.ID, syncs.Revoke)
	if err != nil {
		return nil, t.refused(ctx, err)
	}
	if err := orgOf(t).written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}
