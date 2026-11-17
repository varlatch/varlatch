// SPDX-License-Identifier: AGPL-3.0-or-later

// Package values is the read path of values (ADR-0059 step 3.6,
// varlatchd-core decision 2): the effective configuration and Secret
// disclosures, as the TypeScript server serves them (http/app.ts, the
// effective-configuration and disclosures routes; domain/retrieval.ts,
// domain/values.ts, domain/manifest.ts, domain/references.ts).
//
// A retrieval has two phases (ADR-0038 Decision 6):
//
//  1. a snapshot: one read transaction on the storage engine's read-only
//     pool does every read the request depends on (the scope, the
//     authorization inputs, the Contract, the values and the ciphertext of
//     every version it could decrypt) and decides authorization, writing
//     nothing;
//  2. audit, then decryption: each disclosure's audit event is one write
//     job of the single writer, and nothing is decrypted before Write
//     returned nil, which it does only once the job's savepoint was
//     released and the COMMIT holding it returned (ADR-0059 Decision 2).
//     Nothing is read again.
//
// The key hierarchy is the TypeScript server's (ADR-0011): the Root KEK
// unwraps the Organization's KEK, which unwraps each version's DEK, which
// opens the value (lib/envelope).
package values

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/stages"
	"github.com/varlatch/varlatch/go/server/write"
)

// Purposes a client may declare for a disclosure (DISCLOSURE_PURPOSES).
var Purposes = []string{"scan", "export"}

// Service serves the read path.
type Service struct {
	store   *storage.DB
	rootKEK []byte
	log     *slog.Logger
	now     func() time.Time

	// The report counts queued after responses (securityreport.ts
	// queueAccessCount): bounded, best effort.
	counts  sync.WaitGroup
	pending chan struct{}

	approvals *auth.Service
	gates     *write.Gates
	admit     func() (func(), bool)
}

// Options configures New.
type Options struct {
	Log *slog.Logger
	// Now is the clock (tests); nil is time.Now.
	Now func() time.Time
	// Approvals and Gates serve an export under admin-step-up's enforce
	// (exportstepup.ts): its approval is consumed in the disclosure's audit
	// job, behind the Organization's and the requester's gates. Without
	// them such an export is refused.
	Approvals *auth.Service
	Gates     *write.Gates
	// Admit is the maintenance admission (nil for none). A report count
	// runs after its response, so it enters on its own: it is dropped
	// while a gate is open, and counted until its write ends.
	Admit func() (leave func(), ok bool)
}

// maxQueuedCounts is ACCESS_COUNTS.maxQueued: counts beyond it are dropped.
const maxQueuedCounts = 1000

// New returns the read path over store, opening values with rootKEK.
func New(store *storage.DB, rootKEK []byte, opts Options) *Service {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Service{store: store, rootKEK: rootKEK, log: opts.Log, now: opts.Now, pending: make(chan struct{}, maxQueuedCounts),
		approvals: opts.Approvals, gates: opts.Gates, admit: opts.Admit}
}

// Settled waits until every queued report count has run (tests, and a stop).
func (s *Service) Settled() { s.counts.Wait() }

// Request is one request to the read path.
type Request struct {
	Principal *auth.Principal
	RequestID string
	// Method and Route name the request in an incident freeze's refusal
	// (the route pattern as Hono names it).
	Method, Route string
	// Org, Project and Environment are the route's parameters, decoded as
	// the TypeScript server reads them.
	Org, Project, Environment string
	// Approval is the Varlatch-Approval header as sent, nil for none: read
	// only by an export under admin-step-up's enforce.
	Approval *string
}

func (r Request) authzPrincipal() authz.Principal {
	p := authz.Principal{IdentityID: r.Principal.Identity.ID, IdentityKind: r.Principal.Identity.Kind, CredentialID: r.Principal.Credential.ID}
	if r.Principal.Identity.OrganizationID != nil {
		p.OrganizationID = *r.Principal.Identity.OrganizationID
	}
	return p
}

// Item is one resolved item (ResolvedItem).
type Item struct {
	Name       string
	Sensitive  bool
	Source     string // "self" or "parent"
	ValueRowID string
	VersionID  string
	// RetiringVersionID is set while a rotation's window is open at the
	// snapshot's time.
	RetiringVersionID string
}

type ciphertext struct {
	valueRowID string
	payload    envelope.Envelope
	wrappedDEK envelope.Envelope
}

type contractDoc struct {
	Items []struct {
		Name      string `json:"name"`
		Sensitive *bool  `json:"sensitive"`
	} `json:"items"`
	SemanticsVersion *float64 `json:"semanticsVersion"`
}

// State is everything a retrieval read, from one snapshot (CapturedState).
type State struct {
	Now        int64 // microseconds: the snapshot's time, the request's only clock
	Org        authz.Organization
	wrappedKEK sql.NullString
	Project    query.LiveProjectRow
	Env        query.LiveEnvironmentRow
	revision   *query.ProjectContractRevisionRow
	contract   *contractDoc
	Items      []Item
	ciphertext map[string]ciphertext
}

func (s *State) resource() authz.Resource {
	return authz.Resource{
		OrganizationID: s.Org.ID,
		ProjectID:      s.Project.ID,
		Environment:    &authz.Environment{ID: s.Env.ID, RootID: rootID(s.Env), Tier: s.Env.Tier},
	}
}

func rootID(e query.LiveEnvironmentRow) string {
	if e.ParentEnvironmentID.Valid {
		return e.ParentEnvironmentID.String
	}
	return e.ID
}

func sensitivityOf(c *contractDoc, name string) bool {
	if c == nil {
		return true
	}
	for _, it := range c.Items {
		if it.Name == name {
			return it.Sensitive == nil || *it.Sensitive
		}
	}
	return true
}

// tracker is what the TypeScript server keeps on the request's context: the
// first action it was authorized for and its resource (AUTHORIZED_ACTION),
// and passkey-verification's decision (requestaccess.ts).
type tracker struct {
	action   string
	resource *authz.Resource
	decided  bool
	reports  []auth.PendingReport
	at       int64
}

func (t *tracker) decide(ctx context.Context, db query.DBTX, req Request, action string, r authz.Resource, hide bool) (authz.Decision, error) {
	m := stages.Start()
	d, err := authz.Decide(ctx, db, req.authzPrincipal(), action, r, authz.Options{HideExistence: hide, RequestID: req.RequestID})
	stages.Since(ctx, "authorization", m)
	if err != nil {
		return d, err
	}
	if d.Allowed && t.action == "" {
		t.action, t.resource = action, &r
	}
	return d, nil
}

// requireAccess is requireOrganizationAccess in the snapshot: under
// enforce, a blocked person's request is refused; under report, its count
// is noted for after the response.
func (t *tracker) requireAccess(ctx context.Context, db query.DBTX, req Request, organizationID string, now int64) error {
	out, err := auth.PasskeyVerification(ctx, db, req.Principal, []string{organizationID})
	if err != nil {
		return err
	}
	if reason, ok := out.Blocked[organizationID]; ok {
		return auth.PasskeyVerificationRequired(organizationID, reason)
	}
	t.decided = true
	t.at = now
	t.reports = nil
	for _, r := range out.Reports {
		if r.OrganizationID == organizationID {
			t.reports = append(t.reports, r)
			break
		}
	}
	return nil
}

// hookKey carries, in tests, a function a retrieval calls between two of
// its reads (WithReadHook); a production context has none.
type hookKey struct{}

// WithReadHook returns a context whose retrievals call hook at points
// between their reads, inside the snapshot: a test commits a write there
// and checks the retrieval does not see it (retrieval-consistency).
func WithReadHook(ctx context.Context, hook func(point string)) context.Context {
	return context.WithValue(ctx, hookKey{}, hook)
}

func readHook(ctx context.Context, point string) {
	if h, ok := ctx.Value(hookKey{}).(func(string)); ok {
		h(point)
	}
}

// snapshot runs read in one read transaction of the read-only pool.
func (s *Service) snapshot(ctx context.Context, read func(tx *sql.Tx, now int64) error) error {
	m := stages.Start()
	err := s.readSnapshot(ctx, read)
	stages.Since(ctx, "snapshot", m)
	return err
}

func (s *Service) readSnapshot(ctx context.Context, read func(tx *sql.Tx, now int64) error) error {
	tx, err := s.store.Reader().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	return read(tx, s.now().UnixMicro())
}

// scope is envScope: the Organization as the request enters it (its
// incident freeze included), then the Project and the environment.
func scope(ctx context.Context, db query.DBTX, req Request) (State, error) {
	p := req.authzPrincipal()
	org, err := authz.EnterOrganization(ctx, db, req.Org, &p, "")
	if err != nil {
		return State{}, err
	}
	// Whether the principal can see the Organization first: an outsider gets
	// the same answer whether the Project or environment exists or not.
	denied, event, err := authz.RequireVisible(ctx, db, p, org.ID, req.RequestID)
	if err != nil {
		return State{}, err
	}
	if denied != nil {
		if event != nil {
			return State{}, &security.DeferredDenial{Err: denied, Event: *event}
		}
		return State{}, denied
	}
	q := query.New(db)
	project, err := q.LiveProject(ctx, query.LiveProjectParams{OrganizationID: org.ID, SlugOrID: req.Project})
	if errors.Is(err, sql.ErrNoRows) {
		return State{}, domainerr.NotFound("Project")
	}
	if err != nil {
		return State{}, err
	}
	env, err := q.LiveEnvironment(ctx, query.LiveEnvironmentParams{ProjectID: project.ID, NameOrID: req.Environment})
	if errors.Is(err, sql.ErrNoRows) {
		return State{}, domainerr.NotFound("Environment")
	}
	if err != nil {
		return State{}, err
	}
	return State{Org: org, Project: project, Env: env}, nil
}

// capture is captureState: the incident freeze again (read in the
// snapshot), the active Contract Revision, the resolved items, and the
// ciphertext of every version of the items wants selects.
func capture(ctx context.Context, db query.DBTX, st *State, now int64, wants func(Item) bool) error {
	st.Now = now
	if err := authz.RefuseIfIncidentFrozen(ctx, db, st.Org.ID, ""); err != nil {
		return err
	}
	q := query.New(db)
	org, err := q.RetrievalOrganization(ctx, st.Org.ID)
	if err != nil {
		return err
	}
	st.wrappedKEK = org.WrappedOrgKek
	if st.Project.ActiveContractRevisionID.Valid {
		rev, err := q.ProjectContractRevision(ctx, query.ProjectContractRevisionParams{ID: st.Project.ActiveContractRevisionID.String, ProjectID: st.Project.ID})
		if errors.Is(err, sql.ErrNoRows) {
			return domainerr.NotFound("Contract revision")
		}
		if err != nil {
			return err
		}
		var c contractDoc
		if err := json.Unmarshal([]byte(rev.Contract), &c); err != nil {
			return fmt.Errorf("values: the active Contract of %s is not JSON: %w", st.Project.ID, err)
		}
		st.revision, st.contract = &rev, &c
	}
	items, err := resolveItems(ctx, q, st, now)
	if err != nil {
		return err
	}
	st.Items = items

	rowOf := map[string]string{}
	var ids []string
	for _, it := range items {
		if !wants(it) {
			continue
		}
		for _, v := range []string{it.VersionID, it.RetiringVersionID} {
			if v == "" {
				continue
			}
			if _, ok := rowOf[v]; !ok {
				ids = append(ids, v)
			}
			rowOf[v] = it.ValueRowID
		}
	}
	st.ciphertext = map[string]ciphertext{}
	if len(ids) == 0 {
		return nil
	}
	rows, err := q.CapturedCiphertext(ctx, ids)
	if err != nil {
		return err
	}
	for _, r := range rows {
		var c ciphertext
		if err := json.Unmarshal([]byte(r.Payload.String), &c.payload); err != nil {
			return fmt.Errorf("values: the payload of %s is not an envelope: %w", r.ID, err)
		}
		if err := json.Unmarshal([]byte(r.WrappedDek.String), &c.wrappedDEK); err != nil {
			return fmt.Errorf("values: the wrapped DEK of %s is not an envelope: %w", r.ID, err)
		}
		c.valueRowID = rowOf[r.ID]
		st.ciphertext[r.ID] = c
	}
	return nil
}

// resolveItems is resolveItems: the environment's own current values,
// then its parent's for names it does not set, each with the version a
// rotation retires while its window is open at now, sorted by name as
// JavaScript sorts strings.
func resolveItems(ctx context.Context, q *query.Queries, st *State, now int64) ([]Item, error) {
	byName := map[string]int{}
	var items []Item
	load := func(environmentID, source string) error {
		rows, err := q.CurrentValuesOfEnvironment(ctx, environmentID)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if _, seen := byName[r.ItemName]; source == "parent" && seen {
				continue
			}
			it := Item{
				Name: r.ItemName, Sensitive: sensitivityOf(st.contract, r.ItemName), Source: source,
				ValueRowID: r.ID, VersionID: r.CurrentVersionID.String,
			}
			if r.RetiringVersionID.Valid && r.RotationDeadline.Valid && r.RotationDeadline.Int64 > now {
				it.RetiringVersionID = r.RetiringVersionID.String
			}
			if i, seen := byName[r.ItemName]; seen {
				items[i] = it
			} else {
				byName[r.ItemName] = len(items)
				items = append(items, it)
			}
		}
		return nil
	}
	if err := load(st.Env.ID, "self"); err != nil {
		return nil, err
	}
	readHook(ctx, "between the environment's values and its parent's")
	if st.Env.ParentEnvironmentID.Valid {
		if err := load(st.Env.ParentEnvironmentID.String, "parent"); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return utf16Less(items[i].Name, items[j].Name) })
	return items, nil
}

// expired is assertNotExpired.
func (st *State) expired() error {
	if st.Env.ExpiresAt.Valid && st.Env.ExpiresAt.Int64 <= st.Now {
		return domainerr.New("ENVIRONMENT_EXPIRED", "This environment has expired; retrieval and mutation are disabled until it is deleted or its expiry is changed")
	}
	return nil
}

// Manifest is stateManifest with its digest (manifestOf): identifiers and
// names only, never plaintext.
func (st *State) Manifest() (jsvalue.Object, string, error) {
	env := jsvalue.Object{
		{Key: "id", Value: st.Env.ID},
		{Key: "rootId", Value: rootID(st.Env)},
		{Key: "parentId", Value: nullable(st.Env.ParentEnvironmentID)},
		{Key: "tier", Value: st.Env.Tier},
		{Key: "expiresAt", Value: nil},
	}
	canonEnv := map[string]any{"id": st.Env.ID, "rootId": rootID(st.Env), "parentId": nullable(st.Env.ParentEnvironmentID), "tier": st.Env.Tier, "expiresAt": nil}
	if st.Env.ExpiresAt.Valid {
		env[4].Value = audit.ISOTime(st.Env.ExpiresAt.Int64)
		canonEnv["expiresAt"] = audit.ISOTime(st.Env.ExpiresAt.Int64)
	}
	var contract, canonContract any
	if st.revision != nil && st.contract != nil {
		version := 1.0
		if st.contract.SemanticsVersion != nil {
			version = *st.contract.SemanticsVersion
		}
		contract = jsvalue.Object{{Key: "revisionId", Value: st.revision.ID}, {Key: "contentHash", Value: st.revision.ContentHash}, {Key: "semanticsVersion", Value: version}}
		canonContract = map[string]any{"revisionId": st.revision.ID, "contentHash": st.revision.ContentHash, "semanticsVersion": version}
	}
	items := make([]any, 0, len(st.Items))
	canonItems := make([]any, 0, len(st.Items))
	for _, it := range st.Items {
		o := jsvalue.Object{{Key: "name", Value: it.Name}, {Key: "source", Value: it.Source}, {Key: "valueRowId", Value: it.ValueRowID}, {Key: "versionId", Value: it.VersionID}}
		c := map[string]any{"name": it.Name, "source": it.Source, "valueRowId": it.ValueRowID, "versionId": it.VersionID}
		if it.RetiringVersionID != "" {
			o = append(o, jsvalue.Member{Key: "retiringVersionId", Value: it.RetiringVersionID})
			c["retiringVersionId"] = it.RetiringVersionID
		}
		items, canonItems = append(items, o), append(canonItems, c)
	}
	manifest := jsvalue.Object{
		{Key: "manifestVersion", Value: 1},
		{Key: "projectId", Value: st.Project.ID},
		{Key: "environment", Value: env},
		{Key: "contract", Value: contract},
		{Key: "items", Value: items},
	}
	canon, err := envelope.CanonicalJSON(map[string]any{
		"manifestVersion": 1, "projectId": st.Project.ID, "environment": canonEnv, "contract": canonContract, "items": canonItems,
	})
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256([]byte(canon))
	return manifest, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func nullable(s sql.NullString) any {
	if s.Valid {
		return s.String
	}
	return nil
}

// orgKEK is orgKekOf: the Organization's KEK, unwrapped with the Root KEK.
func (s *Service) orgKEK(st *State) ([]byte, error) {
	if !st.wrappedKEK.Valid {
		return nil, domainerr.New("ORGANIZATION_DELETED", "This Organization was deleted: its key is destroyed")
	}
	var wrapped envelope.Envelope
	if err := json.Unmarshal([]byte(st.wrappedKEK.String), &wrapped); err != nil {
		return nil, fmt.Errorf("values: the wrapped KEK of %s is not an envelope: %w", st.Org.ID, err)
	}
	return envelope.UnwrapOrgKEK(s.rootKEK, wrapped, st.Org.ID)
}

// beforeAudit runs in the audit's write job, before its events.
// beforeAudit runs in the audit job before the events: a report count, or
// an export's phase 2. Metadata it returns is added to every event.
type beforeAudit func(ctx context.Context, tx *storage.Tx) (jsvalue.Object, error)

// AuditThenDecrypt is auditThenDecrypt: events are committed, as one
// write job, before anything is decrypted; if the job fails, nothing is
// decrypted and the error ends the request. Then exactly versionIDs are
// opened from the captured ciphertext; nothing is read again.
func (s *Service) auditThenDecrypt(ctx context.Context, st *State, events []audit.Event, versionIDs []string, before beforeAudit, gates ...write.Gate) (map[string]string, error) {
	if len(events) > 0 {
		run := s.store.Write
		if len(gates) > 0 {
			// An export's phase 2: its gates before the job, released once
			// the job has its answer.
			gctx, release, err := s.gates.Acquire(ctx, gates...)
			if err != nil {
				return nil, err
			}
			defer release()
			ctx = gctx
		}
		err := run(ctx, func(tx *storage.Tx) error {
			out := events
			if before != nil {
				added, err := before(ctx, tx)
				if err != nil {
					return err
				}
				if len(added) > 0 {
					out = make([]audit.Event, len(events))
					for i, e := range events {
						e.Metadata = append(slices.Clone(e.Metadata), added...)
						out[i] = e
					}
				}
			}
			_, err := audit.Record(ctx, tx, out...)
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	m := stages.Start()
	out, err := s.decrypt(st, versionIDs)
	stages.Since(ctx, "decryption", m)
	return out, err
}

// decrypt opens exactly versionIDs from the captured ciphertext.
func (s *Service) decrypt(st *State, versionIDs []string) (map[string]string, error) {
	kek, err := s.orgKEK(st)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	out := make(map[string]string, len(versionIDs))
	for _, v := range versionIDs {
		c, ok := st.ciphertext[v]
		if !ok {
			return nil, domainerr.New("INTERNAL", "A value version was not captured in the retrieval snapshot")
		}
		plain, err := envelope.DecryptValue(kek, st.Org.ID, c.valueRowID, v, envelope.EncryptedValue{Payload: c.payload, WrappedDEK: c.wrappedDEK})
		if err != nil {
			return nil, err
		}
		out[v] = decode(plain)
		clear(plain)
	}
	return out, nil
}

// recordDenial is recordDenial: a denial's audit event, in a write job of
// its own.
func (s *Service) recordDenial(ctx context.Context, d authz.Decision) error {
	if d.Allowed || d.DenialEvent == nil {
		return nil
	}
	return s.store.Write(ctx, func(tx *storage.Tx) error { return authz.RecordDenial(ctx, tx, d) })
}

// reject is reject: the denial recorded, then its error.
func (s *Service) reject(ctx context.Context, d authz.Decision) error {
	if err := s.recordDenial(ctx, d); err != nil {
		return err
	}
	return d.Err
}

func allowedAuthz(d *authz.Decision) any {
	if d == nil || !d.Allowed {
		return nil
	}
	return authz.AuditAuthz(d.Evaluation)
}

func resourceOf(st *State) jsvalue.Object {
	return jsvalue.Object{{Key: "projectId", Value: st.Project.ID}, {Key: "environmentId", Value: st.Env.ID}}
}

func ptr(s string) *string { return &s }

// refused audits a refusal the TypeScript server audits from app.onError,
// once, after the snapshot that refused it ended: the incident freeze
// (auditFrozenRefusal), passkey-verification (auditPasskeyRefusal) and an
// Organization the principal cannot see (auditDeferredDenial).
// Best effort, as there: a failure is logged and the answer stays.
func (s *Service) refused(ctx context.Context, req Request, t *tracker, err error) error {
	var frozen *authz.FrozenError
	var verification *auth.VerificationRefusal
	var event *audit.Event
	var deferred *security.DeferredDenial
	switch {
	case errors.As(err, &deferred):
		event = &deferred.Event
	case errors.As(err, &frozen):
		p := req.authzPrincipal()
		e := authz.FrozenRefusalEvent(&p, frozen, req.Method, req.Route, req.RequestID)
		event = &e
	case errors.As(err, &verification) && !verification.SelfLockout:
		same := t.resource != nil && t.resource.OrganizationID == verification.OrganizationID
		var action *string
		resource := jsvalue.Object{{Key: "projectId", Value: nil}, {Key: "environmentId", Value: nil}}
		if same {
			action = ptr(t.action)
			resource = jsvalue.Object{{Key: "projectId", Value: orNull(t.resource.ProjectID)}, {Key: "environmentId", Value: nil}}
			if t.resource.Environment != nil {
				resource[1].Value = t.resource.Environment.ID
			}
		}
		org := verification.OrganizationID
		event = &audit.Event{
			Type: "authorization.denied", Decision: audit.Deny,
			ActorIdentityID: ptr(req.Principal.Identity.ID), CredentialID: audit.Value(req.Principal.Credential.ID),
			OrganizationID: &org, Action: action, Resource: resource,
			Metadata:  jsvalue.Object{{Key: "reason", Value: "passkey_verification_required"}, {Key: "evidence", Value: verification.Reason}},
			RequestID: ptr(req.RequestID),
		}
	}
	if event != nil {
		if werr := s.store.Write(ctx, func(tx *storage.Tx) error { _, e := audit.Record(ctx, tx, *event); return e }); werr != nil {
			s.log.Error("could not audit a refusal", "type", event.Type, "requestId", req.RequestID, "error", werr)
		}
	}
	return err
}

func orNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// settle is settleOrganizationAccess for a request that succeeded:
// passkey-verification's report count, from the request's checkpoint, as
// the first action it was authorized for, queued after the response.
func (s *Service) settle(t *tracker) {
	if !t.decided || len(t.reports) == 0 {
		return
	}
	action := t.action
	if action == "" {
		action = "organization.access"
	}
	for _, r := range t.reports {
		s.queueCount(r, action, t.at)
	}
}
