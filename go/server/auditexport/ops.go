// SPDX-License-Identifier: AGPL-3.0-or-later

package auditexport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// Service is what the operations work with.
type Service struct {
	Writer    *write.Writer
	Approvals *auth.Service
	RootKEK   []byte
	// Policy is the outbound policy: every request to a destination goes
	// through its audit_export client, and the endpoint is checked before
	// anything is held.
	Policy *outbound.Policy
	Now    func() time.Time
	// Enabled is the host's switch (audit_export, VARLATCH_AUDIT_EXPORT):
	// off refuses every operation but reading and removal.
	Enabled bool
	// VerifiedProvider treats an endpoint as a verified Object Lock
	// provider (tests: the local S3 server, Decision 7); nil for none.
	VerifiedProvider func(endpoint string) bool
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) store() *storage.DB { return s.Writer.Store }

// Request is who asks, with what Varlatch-Approval header (nil for none)
// and the request's id.
type Request struct {
	Principal *auth.Principal
	Approval  *string
	RequestID string
}

func (r Request) security(approvals *auth.Service) security.Request {
	out := security.Request{Principal: r.Principal, Approvals: approvals}
	if r.Approval != nil {
		if out.ApprovalID = auth.ParseApprovalID(*r.Approval); out.ApprovalID == "" {
			out.ApprovalMalformed = true
		}
	}
	return out
}

func (r Request) carries() bool { return r.Approval != nil }

// personGate is effectRequester: the requester exclusive when the request
// carries an approval it may consume.
func (r Request) personGate() write.Gate {
	if r.carries() {
		return write.Person(r.Principal.Identity.ID, write.Exclusive)
	}
	return write.Person(r.Principal.Identity.ID, write.Shared)
}

func exportGate(id string) write.Gate { return write.Resource("audit_export", id) }

// RequirePerson is the routes' auditExportPerson: a person's browser or
// CLI credential, never a machine (Decision 9).
func RequirePerson(p *auth.Principal) error {
	if p.Identity.Kind != "human" || (p.Credential.Kind != auth.KindBrowser && p.Credential.Kind != auth.KindCLI) {
		return &domainerr.Error{Code: "PERMISSION_DENIED", Message: "Only a person can change the audit export; machine credentials never can",
			Details: jsvalue.Object{{Key: "reason", Value: "machine-credential"}}}
	}
	return nil
}

// requirePerson is the domain's own refusal (requirePerson), for a caller
// that is not a route.
func requirePerson(p *auth.Principal) error {
	if p.Identity.Kind != "human" || (p.Credential.Kind != auth.KindBrowser && p.Credential.Kind != auth.KindCLI) {
		return &domainerr.Error{Code: "PERMISSION_DENIED", Message: "Audit exports are changed by a person, never a machine credential",
			Details: jsvalue.Object{{Key: "reason", Value: "machine-credential"}}}
	}
	return nil
}

func (s *Service) requireSwitchOn() error {
	if !s.Enabled {
		return &domainerr.Error{Code: "PERMISSION_DENIED", Message: "The host operator turned audit export off on this installation (VARLATCH_AUDIT_EXPORT=off)",
			Details: jsvalue.Object{{Key: "reason", Value: "audit-export-off"}}}
	}
	return nil
}

func notFound() error { return domainerr.New("RESOURCE_NOT_FOUND", "Audit export not found") }

func exportExists() error {
	return &domainerr.Error{Code: "VALIDATION_FAILED", Message: "This Organization already has an audit export; change or remove it instead",
		Details: jsvalue.Object{{Key: "reason", Value: "export-exists"}}}
}

func probeFailed(r ProbeResult) error {
	msg := "The destination check failed"
	if r.Message != nil {
		msg = *r.Message
	}
	return &domainerr.Error{Code: "VALIDATION_FAILED", Message: msg, Details: jsvalue.Object{{Key: "check", Value: r.JS()}}}
}

func endpointRefused(r *outbound.RefusedError) error {
	return &domainerr.Error{Code: "VALIDATION_FAILED", Message: r.Error(), Details: jsvalue.Object{{Key: "outbound", Value: string(r.Reason)}}}
}

func versionConflict(current, expected int64) error {
	return &domainerr.Error{Code: "VERSION_CONFLICT",
		Message: fmt.Sprintf("The audit export is at version %d, not %d: it changed meanwhile. Read it again", current, expected),
		Details: jsvalue.Object{{Key: "currentVersion", Value: current}}}
}

func stateChanged() error {
	return domainerr.New("STATE_CHANGED", "The audit export changed meanwhile; read it again")
}

// manageIn is auditExportRecheck: organization.manage rechecked in the
// operation's job. These operations run whatever the Security Controls'
// modes, so a denial is audited after the rollback only when a control is
// on (security.AuthorizeControlled).
func manageIn(ctx context.Context, tx query.DBTX, req Request, organizationID string) error {
	return security.AuthorizeControlled(ctx, tx, req.Principal, "organization.manage", organizationID, req.RequestID)
}

// refusalEvent notes a refused endpoint for the effect it runs in: written
// with its final job, or alone when it fails (recordEndpointRefusal).
func (s *Service) noteRefusal(ctx context.Context, organizationID string, r *outbound.RefusedError, exportID, actor string) {
	resource := jsvalue.Object{}
	if exportID != "" {
		resource = jsvalue.Object{{Key: "exportId", Value: exportID}}
	}
	if e, ok := s.Policy.RefusalEvent(outbound.RefusalRecord{
		OrganizationID: organizationID, Purpose: outbound.AuditExport, Phase: "configuration", Refusal: r, Resource: resource, ActorIdentityID: &actor,
	}); ok {
		write.NoteRefusal(ctx, e)
	}
}

// orgKEK is orgKekOf, read in db.
func (s *Service) orgKEK(ctx context.Context, db query.DBTX, organizationID string) ([]byte, error) {
	o, err := query.New(db).RetrievalOrganization(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	if !o.WrappedOrgKek.Valid {
		return nil, domainerr.New("ORGANIZATION_DELETED", "This Organization was deleted: its key is destroyed")
	}
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(o.WrappedOrgKek.String), &env); err != nil {
		return nil, err
	}
	return envelope.UnwrapOrgKEK(s.RootKEK, env, organizationID)
}

// sealCredential is encryptAuditExportCredential of the key's JSON.
func (s *Service) sealCredential(ctx context.Context, organizationID, exportID string, c Credential) (string, error) {
	kek, err := s.orgKEK(ctx, s.store().Reader(), organizationID)
	if err != nil {
		return "", err
	}
	sealed, err := envelope.Seal(kek, jsvalue.Stringify(c.js()), envelope.AuditExportCredentialContext(organizationID, exportID))
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(sealed)
	return string(b), err
}

// storedCredential is storedCredential: the live export's key.
func (s *Service) storedCredential(ctx context.Context, db query.DBTX, r query.AuditExport) (Credential, error) {
	if !r.CredentialEnvelope.Valid {
		return Credential{}, domainerr.New("STATE_CHANGED", "The audit export has no key")
	}
	kek, err := s.orgKEK(ctx, db, r.OrganizationID)
	if err != nil {
		return Credential{}, err
	}
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(r.CredentialEnvelope.String), &env); err != nil {
		return Credential{}, err
	}
	plain, err := envelope.Open(kek, env, envelope.AuditExportCredentialContext(r.OrganizationID, r.ID))
	if err != nil {
		return Credential{}, err
	}
	var c Credential
	err = json.Unmarshal(plain, &c)
	return c, err
}

func liveExport(ctx context.Context, db query.DBTX, organizationID string) (*query.AuditExport, error) {
	r, err := query.New(db).LiveAuditExport(ctx, organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

// activeExport is the export by id, while it is active; nil otherwise.
func activeExport(ctx context.Context, db query.DBTX, organizationID, exportID string) (*query.AuditExport, error) {
	r, err := query.New(db).OrganizationAuditExport(ctx, query.OrganizationAuditExportParams{ID: exportID, OrganizationID: organizationID})
	if errors.Is(err, sql.ErrNoRows) || (err == nil && r.State != "active") {
		return nil, nil
	}
	return &r, err
}

func nullInt(v int64, ok bool) sql.NullInt64   { return sql.NullInt64{Int64: v, Valid: ok} }
func nullStr(v string, ok bool) sql.NullString { return sql.NullString{String: v, Valid: ok} }
func nullBoolOf(p *bool) sql.NullBool {
	if p == nil {
		return sql.NullBool{}
	}
	return sql.NullBool{Bool: *p, Valid: true}
}

func retentionColumns(r *Retention) (sql.NullString, sql.NullInt64) {
	if r == nil {
		return sql.NullString{}, sql.NullInt64{}
	}
	return nullStr(r.Mode, true), nullInt(r.Days, true)
}

func endpointHost(endpoint string) string {
	u, _ := whatwg.ParseURL(endpoint)
	return u.Host
}

// CreateInput is createAuditExport's input, as zod leaves it.
type CreateInput struct {
	Destination Destination
	Credential  Credential
	Retention   *Retention
	// From is "beginning" (backfill the whole log) or "now" (start at the
	// creation event).
	From string
}

// Create is createAuditExport: no approval (creating only adds
// protection, Decision 9). The probe runs as an external effect: the
// Organization and the actor held, the passkey-verification checkpoint
// passed before the key is sent anywhere. Refused while frozen or while a
// deletion is pending, and when the host switched the export off.
func (s *Service) Create(ctx context.Context, req Request, org authz.Organization, in CreateInput) ([]auth.PendingReport, error) {
	if err := requirePerson(req.Principal); err != nil {
		return nil, err
	}
	if err := s.requireSwitchOn(); err != nil {
		return nil, err
	}
	dest, err := NormalizeDestination(in.Destination)
	if err != nil {
		return nil, err
	}
	retention, err := ValidateRetention(in.Retention)
	if err != nil {
		return nil, err
	}
	cred, err := ValidateCredential(in.Credential)
	if err != nil {
		return nil, err
	}
	if in.From != "beginning" && in.From != "now" {
		return nil, invalid("from: beginning or now")
	}
	actor := req.Principal.Identity.ID
	if err := write.RefuseIfDeleting(ctx, s.store().Reader(), org.ID); err != nil {
		return nil, err
	}
	refusal, err := s.Policy.RefusalFor(ctx, dest.Endpoint, outbound.AuditExport)
	if err != nil {
		return nil, err
	}
	id, streamID := ids.New(ids.AuditExport), ids.New(ids.AuditExportStream)
	sealed, err := s.sealCredential(ctx, org.ID, id, cred)
	if err != nil {
		return nil, err
	}
	var now time.Time
	_, reports, err := write.RunEffect(ctx, s.Writer, write.Effect[ProbeResult, struct{}]{
		OrganizationID: org.ID, People: []write.Gate{write.Person(actor, write.Shared)}, Principal: req.Principal,
		Checked: func(ctx context.Context, tx *sql.Tx) error {
			if err := manageIn(ctx, tx, req, org.ID); err != nil {
				return err
			}
			if live, err := liveExport(ctx, tx, org.ID); err != nil || live != nil {
				if err == nil {
					err = exportExists()
				}
				return err
			}
			if refusal != nil {
				s.noteRefusal(ctx, org.ID, refusal, "", actor)
				return endpointRefused(refusal)
			}
			now = s.now()
			return nil
		},
		Call: func(ctx context.Context) (ProbeResult, error) {
			r := s.probe(ctx, org.ID, dest, cred, retention, now)
			if !r.OK {
				return r, probeFailed(r)
			}
			return r, nil
		},
		Final: func(ctx context.Context, tx *storage.Tx, checked ProbeResult) (struct{}, error) {
			// Two creations at once both found none and both probed: the
			// second meets the first's live export.
			if live, err := liveExport(ctx, tx, org.ID); err != nil || live != nil {
				if err == nil {
					err = exportExists()
				}
				return struct{}{}, err
			}
			mode, days := retentionColumns(retention)
			var rmode, rdays any
			if retention != nil {
				rmode, rdays = retention.Mode, retention.Days
			}
			action := "organization.manage"
			recorded, err := audit.Record(ctx, tx,
				audit.Event{
					Type: "audit_export.created", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID, Action: &action,
					RequestID: &req.RequestID, Resource: jsvalue.Object{{Key: "exportId", Value: id}},
					Metadata: jsvalue.Object{
						{Key: "host", Value: endpointHost(dest.Endpoint)}, {Key: "bucket", Value: dest.Bucket}, {Key: "prefix", Value: dest.Prefix},
						{Key: "retentionMode", Value: rmode}, {Key: "retentionDays", Value: rdays}, {Key: "from", Value: in.From},
					},
				},
				streamStarted(org.ID, id, streamID, nil, "created", &actor, &req.RequestID))
			if err != nil {
				return struct{}{}, err
			}
			var cursor int64
			if in.From == "now" {
				cursor = recorded[0].Position
			}
			at := s.now().UnixMicro()
			var lock sql.NullBool
			if retention != nil {
				lock = sql.NullBool{Bool: checked.ObjectLock != nil && *checked.ObjectLock == "verified", Valid: true}
			}
			if err := query.New(tx).InsertAuditExport(ctx, query.InsertAuditExportParams{
				ID: id, OrganizationID: org.ID, Endpoint: dest.Endpoint, Region: dest.Region, Bucket: dest.Bucket, Prefix: dest.Prefix,
				PathStyle: dest.PathStyle, CredentialEnvelope: nullStr(sealed, true), RetentionMode: mode, RetentionDays: days,
				StreamID: streamID, StreamStartedAt: at, CursorOrder: cursor, CreatedBy: actor, ConditionalCheckedAt: nullInt(at, true),
				LockVerified: lock, KeyCanRead: nullBoolOf(checked.KeyCanRead), RetentionReadable: nullBoolOf(checked.RetentionReadable),
				CreatedAt: at, UpdatedAt: at,
			}); err != nil {
				return struct{}{}, err
			}
			return struct{}{}, insertPlan(ctx, tx, id, 1, streamID, 0,
				manifestPlan(dest.Prefix, org.ID, streamID, cursor, nil, "created", now), retention, now)
		},
	})
	return reports, err
}

// CheckInput is checkAuditExport's input; a nil Credential uses the live
// export's own key.
type CheckInput struct {
	Destination Destination
	Credential  *Credential
	Retention   *Retention
}

// Check is checkAuditExport: the probe alone, nothing saved. The key is
// the one supplied, or the live export's, which is only sent to that
// export's own destination. It records nothing but a refused endpoint (as
// the outbound policy records every configuration-time refusal).
func (s *Service) Check(ctx context.Context, req Request, org authz.Organization, in CheckInput) (ProbeResult, []auth.PendingReport, error) {
	if err := requirePerson(req.Principal); err != nil {
		return ProbeResult{}, nil, err
	}
	if err := s.requireSwitchOn(); err != nil {
		return ProbeResult{}, nil, err
	}
	dest, err := NormalizeDestination(in.Destination)
	if err != nil {
		return ProbeResult{}, nil, err
	}
	retention, err := ValidateRetention(in.Retention)
	if err != nil {
		return ProbeResult{}, nil, err
	}
	var cred Credential
	if in.Credential != nil {
		if cred, err = ValidateCredential(*in.Credential); err != nil {
			return ProbeResult{}, nil, err
		}
	}
	actor := req.Principal.Identity.ID
	if err := write.RefuseIfDeleting(ctx, s.store().Reader(), org.ID); err != nil {
		return ProbeResult{}, nil, err
	}
	refusal, err := s.Policy.RefusalFor(ctx, dest.Endpoint, outbound.AuditExport)
	if err != nil {
		return ProbeResult{}, nil, err
	}
	var stored *query.AuditExport
	var answer *ProbeResult
	var now time.Time
	return write.RunEffect(ctx, s.Writer, write.Effect[ProbeResult, ProbeResult]{
		OrganizationID: org.ID, People: []write.Gate{write.Person(actor, write.Shared)}, Principal: req.Principal,
		Check: func(ctx context.Context, tx *sql.Tx) error {
			if in.Credential != nil {
				return nil
			}
			r, err := liveExport(ctx, tx, org.ID)
			if err != nil {
				return err
			}
			if r == nil || r.State != "active" {
				return notFound()
			}
			stored = r
			return nil
		},
		Checked: func(ctx context.Context, tx *sql.Tx) error {
			if err := manageIn(ctx, tx, req, org.ID); err != nil {
				return err
			}
			if stored != nil {
				// The stored key goes only to the export's own destination:
				// sending it elsewhere is a destination change, which needs an
				// approval (Decision 9).
				if classify(destinationOf(*stored), nil, dest, nil).destinationChanged {
					return &domainerr.Error{Code: "VALIDATION_FAILED",
						Message: "The stored key is only checked against the export's own destination; give a key to check another one",
						Details: jsvalue.Object{{Key: "reason", Value: "stored-key-other-destination"}}}
				}
				c, err := s.storedCredential(ctx, tx, *stored)
				if err != nil {
					return err
				}
				cred = c
			}
			// After its not-found and the checkpoint: a refused endpoint is
			// the check's answer, recorded once.
			if refusal != nil {
				s.noteRefusal(ctx, org.ID, refusal, "", actor)
				r := refusedProbe(refusal.Error(), ProbeResult{})
				answer = &r
				return nil
			}
			now = s.now()
			return nil
		},
		Call: func(ctx context.Context) (ProbeResult, error) {
			if answer != nil {
				return *answer, nil
			}
			return s.probe(ctx, org.ID, dest, cred, retention, now), nil
		},
		Final: func(_ context.Context, _ *storage.Tx, r ProbeResult) (ProbeResult, error) { return r, nil },
	})
}

// classified is a change field by field (ADR-0054 Decision 2).
type classified struct {
	changes            []auth.ApprovalChange
	destinationChanged bool
	loosened           bool
}

func retentionText(r *Retention) string {
	if r == nil {
		return "none"
	}
	return r.Mode + ", " + strconv.FormatInt(r.Days, 10) + " days"
}

// classify is classifyChange: any loosening part makes the whole change
// need the approval. Another destination always loosens (it redirects the
// copy).
func classify(curDest Destination, curRet *Retention, nextDest Destination, nextRet *Retention) classified {
	var out classified
	fields := []struct{ name, from, to string }{
		{"endpoint", curDest.Endpoint, nextDest.Endpoint}, {"region", curDest.Region, nextDest.Region},
		{"bucket", curDest.Bucket, nextDest.Bucket}, {"prefix", curDest.Prefix, nextDest.Prefix},
		{"pathStyle", strconv.FormatBool(curDest.PathStyle), strconv.FormatBool(nextDest.PathStyle)},
	}
	for _, f := range fields {
		if f.from != f.to {
			out.destinationChanged = true
			from, to := f.from, f.to
			out.changes = append(out.changes, auth.ApprovalChange{Field: f.name, From: &from, To: &to, Loosens: true})
		}
	}
	if a, b := retentionText(curRet), retentionText(nextRet); a != b {
		loosens := false
		switch {
		case nextRet == nil:
			loosens = curRet != nil
		case curRet == nil:
		default:
			loosens = nextRet.Days < curRet.Days || (curRet.Mode == "compliance" && nextRet.Mode == "governance")
		}
		out.changes = append(out.changes, auth.ApprovalChange{Field: "retention", From: &a, To: &b, Loosens: loosens})
	}
	for _, c := range out.changes {
		out.loosened = out.loosened || c.Loosens
	}
	return out
}

// DestinationPatch is a change's destination fields; nil keeps a field.
type DestinationPatch struct {
	Endpoint, Region, Bucket, Prefix *string
	PathStyle                        *bool
}

// ChangeInput is changeAuditExport's input.
type ChangeInput struct {
	Destination DestinationPatch
	// SetRetention replaces the retention with Retention (nil removes it);
	// false keeps it.
	SetRetention    bool
	Retention       *Retention
	ExpectedVersion int64
}

// ChangeOutcome is changeAuditExport's.
type ChangeOutcome struct{ Changed, Loosened bool }

// next is the export as the change would leave it.
func (in ChangeInput) next(r query.AuditExport) (Destination, *Retention, error) {
	d := destinationOf(r)
	p := in.Destination
	if p.Endpoint != nil {
		d.Endpoint = *p.Endpoint
	}
	if p.Region != nil {
		d.Region = *p.Region
	}
	if p.Bucket != nil {
		d.Bucket = *p.Bucket
	}
	if p.Prefix != nil {
		d.Prefix = *p.Prefix
	}
	if p.PathStyle != nil {
		d.PathStyle = *p.PathStyle
	}
	d, err := NormalizeDestination(d)
	if err != nil {
		return Destination{}, nil, err
	}
	ret := retentionOf(r)
	if in.SetRetention {
		if ret, err = ValidateRetention(in.Retention); err != nil {
			return Destination{}, nil, err
		}
	}
	return d, ret, nil
}

func changeBinding(org authz.Organization, exportID string, d Destination, r *Retention, expected int64, c classified) auth.Binding {
	orgID := org.ID
	body := jsvalue.Object{{Key: "destination", Value: d.JS()}, {Key: "retention", Value: r.js()}, {Key: "expectedVersion", Value: expected}}
	return auth.Binding{
		Operation: "audit_export.change", OrganizationID: &orgID, Target: map[string]string{"exportId": exportID}, Body: body,
		Query: map[string]string{}, ExpectedVersion: &expected,
		Summary: auth.ApprovalSummary{Title: "Change the audit export of " + org.Name, Changes: c.changes},
	}
}

// approve is gate.require: consume the approval bound to b, or ask for
// one; a header that cannot be an approval id is not found.
func (s *Service) approve(ctx context.Context, tx query.DBTX, req Request, b auth.Binding) (*auth.UsedApproval, error) {
	sr := req.security(s.Approvals)
	if !req.carries() {
		return nil, &auth.ApprovalNeeded{Binding: b}
	}
	if sr.ApprovalMalformed {
		return nil, auth.ApprovalInvalid("not-found", nil)
	}
	used, err := s.Approvals.ConsumeApproval(ctx, tx, auth.RequesterOf(req.Principal), sr.ApprovalID, b)
	if err != nil {
		return nil, err
	}
	return &used, nil
}

// precheck is gate.precheck (amendment D): an unapproved request never
// sends the key out.
func (s *Service) precheck(ctx context.Context, tx query.DBTX, req Request, b auth.Binding) error {
	sr := req.security(s.Approvals)
	if sr.ApprovalMalformed {
		return auth.ApprovalInvalid("not-found", nil)
	}
	return s.Approvals.PrecheckApproval(ctx, tx, auth.RequesterOf(req.Principal), sr.ApprovalID, b)
}

func changeMetadata(c classified, used *auth.UsedApproval) jsvalue.Object {
	var md jsvalue.Object
	var loosened []string
	for _, ch := range c.changes {
		md = append(md, jsvalue.Member{Key: "from_" + ch.Field, Value: orNull(ch.From)}, jsvalue.Member{Key: "to_" + ch.Field, Value: orNull(ch.To)})
		if ch.Loosens {
			loosened = append(loosened, ch.Field)
		}
	}
	md = append(md, jsvalue.Member{Key: "loosened", Value: c.loosened}, jsvalue.Member{Key: "loosenedFields", Value: strings.Join(loosened, ",")})
	return append(md, security.ApprovalMetadata(used)...)
}

// Change is changeAuditExport: the destination or the retention.
// Tightening the retention needs no approval; another destination, a
// shorter or removed retention, or compliance to governance needs the
// requester's step-up approval (audit_export.change), always. Another
// destination starts a new stream at the current cursor and must pass the
// probe first, inside an external effect that holds the export's gate;
// under an approval the probe runs only after a precheck found it
// (amendment D).
func (s *Service) Change(ctx context.Context, req Request, org authz.Organization, exportID string, in ChangeInput) (ChangeOutcome, []auth.PendingReport, error) {
	if err := requirePerson(req.Principal); err != nil {
		return ChangeOutcome{}, nil, err
	}
	if err := s.requireSwitchOn(); err != nil {
		return ChangeOutcome{}, nil, err
	}
	actor := req.Principal.Identity.ID
	reader := s.store().Reader()
	if err := write.RefuseIfDeleting(ctx, reader, org.ID); err != nil {
		return ChangeOutcome{}, nil, err
	}
	seen, err := activeExport(ctx, reader, org.ID, exportID)
	if err != nil {
		return ChangeOutcome{}, nil, err
	}
	if seen == nil {
		return ChangeOutcome{}, nil, notFound()
	}
	planDest, planRet, err := in.next(*seen)
	if err != nil {
		return ChangeOutcome{}, nil, err
	}
	willProbe := classify(destinationOf(*seen), retentionOf(*seen), planDest, planRet).destinationChanged
	// The name is resolved here, before any gate; a refusal is answered
	// after the checkpoint.
	var refusal *outbound.RefusedError
	if willProbe {
		if refusal, err = s.Policy.RefusalFor(ctx, planDest.Endpoint, outbound.AuditExport); err != nil {
			return ChangeOutcome{}, nil, err
		}
	}

	// decide is run's part before any approval: the row read, its version,
	// the classification, the refusals; it answers the binding (nil when
	// none is needed) and whether there is nothing to change.
	type decided struct {
		row     query.AuditExport
		dest    Destination
		ret     *Retention
		c       classified
		binding *auth.Binding
	}
	decide := func(ctx context.Context, tx query.DBTX, row query.AuditExport) (decided, bool, error) {
		if row.Version != in.ExpectedVersion {
			return decided{}, false, versionConflict(row.Version, in.ExpectedVersion)
		}
		d, r, err := in.next(row)
		if err != nil {
			return decided{}, false, err
		}
		c := classify(destinationOf(row), retentionOf(row), d, r)
		if len(c.changes) == 0 {
			return decided{row: row}, true, nil
		}
		if c.destinationChanged != willProbe {
			return decided{}, false, stateChanged()
		}
		if refusal != nil {
			s.noteRefusal(ctx, org.ID, refusal, exportID, actor)
			return decided{}, false, endpointRefused(refusal)
		}
		out := decided{row: row, dest: d, ret: r, c: c}
		if c.loosened {
			b := changeBinding(org, exportID, d, r, in.ExpectedVersion, c)
			out.binding = &b
			if !req.carries() {
				return decided{}, false, &auth.ApprovalNeeded{Binding: b}
			}
		}
		return out, false, nil
	}
	// write is the change itself, in its job, with the probe's findings.
	commit := func(ctx context.Context, tx *storage.Tx, dc decided, probed *ProbeResult, plannedAt time.Time) error {
		var used *auth.UsedApproval
		if dc.binding != nil {
			var err error
			if used, err = s.approve(ctx, tx, req, *dc.binding); err != nil {
				return err
			}
			if err := manageIn(ctx, tx, req, org.ID); err != nil {
				return err
			}
		}
		locked, err := activeExport(ctx, tx, org.ID, exportID)
		switch {
		case err != nil:
			return err
		case locked == nil:
			return notFound()
		case locked.Version != in.ExpectedVersion:
			return versionConflict(locked.Version, in.ExpectedVersion)
		}
		q := query.New(tx)
		streamID := locked.StreamID
		if dc.c.destinationChanged {
			// A new stream at the current cursor; the pending plan goes (Decision 3).
			plan, err := q.AuditExportPlanOf(ctx, exportID)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if err == nil {
				if err := q.DeleteAuditExportPlan(ctx, plan.ID); err != nil {
					return err
				}
			}
			streamID = ids.New(ids.AuditExportStream)
		}
		mode, days := retentionColumns(dc.ret)
		var lock sql.NullBool
		var keyRead, retRead sql.NullBool
		if probed != nil {
			if dc.ret != nil {
				lock = sql.NullBool{Bool: probed.ObjectLock != nil && *probed.ObjectLock == "verified", Valid: true}
			}
			keyRead, retRead = nullBoolOf(probed.KeyCanRead), nullBoolOf(probed.RetentionReadable)
		}
		var probedFlag int64
		if probed != nil {
			probedFlag = 1
		}
		at := s.now().UnixMicro()
		updated, err := q.ChangeAuditExport(ctx, query.ChangeAuditExportParams{
			Endpoint: dc.dest.Endpoint, Region: dc.dest.Region, Bucket: dc.dest.Bucket, Prefix: dc.dest.Prefix, PathStyle: dc.dest.PathStyle,
			RetentionMode: mode, RetentionDays: days, StreamID: streamID, At: at, Probed: nullInt(probedFlag, true),
			LockVerified: lock, KeyCanRead: keyRead, RetentionReadable: retRead, UpdatedAt: at, ID: exportID,
		})
		if err != nil {
			return err
		}
		if dc.c.destinationChanged {
			previous := locked.StreamID
			if err := insertPlan(ctx, tx, exportID, updated.Version, streamID, updated.Generation,
				manifestPlan(dc.dest.Prefix, org.ID, streamID, updated.CursorOrder, &previous, "destination_changed", plannedAt), dc.ret, plannedAt); err != nil {
				return err
			}
		}
		action := "organization.manage"
		events := []audit.Event{{
			Type: "audit_export.changed", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID, Action: &action,
			RequestID: &req.RequestID, Resource: jsvalue.Object{{Key: "exportId", Value: exportID}}, Metadata: changeMetadata(dc.c, used),
		}}
		if dc.c.destinationChanged {
			previous := locked.StreamID
			events = append(events, streamStarted(org.ID, exportID, streamID, &previous, "destination_changed", &actor, &req.RequestID))
		}
		_, err = audit.Record(ctx, tx, events...)
		return err
	}

	gates := []write.Gate{req.personGate(), exportGate(exportID)}
	if !willProbe {
		var out ChangeOutcome
		var reports []auth.PendingReport
		err := s.Writer.Job(ctx, append([]write.Gate{write.Organization(org.ID, write.Shared)}, gates...), func(ctx context.Context, tx *storage.Tx) error {
			out, reports = ChangeOutcome{}, nil
			if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: org.ID}); err != nil {
				return err
			}
			row, err := activeExport(ctx, tx, org.ID, exportID)
			if err != nil {
				return err
			}
			if row == nil {
				return notFound()
			}
			if reports, err = write.Checkpoint(ctx, tx, req.Principal, org.ID); err != nil {
				return err
			}
			if err := manageIn(ctx, tx, req, org.ID); err != nil {
				return err
			}
			dc, noop, err := decide(ctx, tx, *row)
			if err != nil || noop {
				return err
			}
			out = ChangeOutcome{Changed: true, Loosened: dc.c.loosened}
			return commit(ctx, tx, dc, nil, s.now())
		})
		if err != nil {
			return ChangeOutcome{}, nil, err
		}
		return out, reports, nil
	}

	var dc decided
	var noop bool
	var plannedAt time.Time
	var cred Credential
	out, reports, err := write.RunEffect(ctx, s.Writer, write.Effect[*ProbeResult, ChangeOutcome]{
		OrganizationID: org.ID, People: gates[:1], Resources: gates[1:], Principal: req.Principal,
		Check: func(ctx context.Context, tx *sql.Tx) error {
			row, err := activeExport(ctx, tx, org.ID, exportID)
			if err == nil && row == nil {
				err = notFound()
			}
			if err == nil {
				dc.row = *row
			}
			return err
		},
		Checked: func(ctx context.Context, tx *sql.Tx) error {
			if err := manageIn(ctx, tx, req, org.ID); err != nil {
				return err
			}
			var err error
			if dc, noop, err = decide(ctx, tx, dc.row); err != nil || noop {
				return err
			}
			if dc.binding != nil {
				if err := s.precheck(ctx, tx, req, *dc.binding); err != nil {
					return err
				}
			}
			if cred, err = s.storedCredential(ctx, tx, dc.row); err != nil {
				return err
			}
			plannedAt = s.now()
			return nil
		},
		Call: func(ctx context.Context) (*ProbeResult, error) {
			if noop {
				return nil, nil
			}
			r := s.probe(ctx, org.ID, dc.dest, cred, dc.ret, plannedAt)
			if !r.OK {
				return nil, probeFailed(r)
			}
			return &r, nil
		},
		Final: func(ctx context.Context, tx *storage.Tx, probed *ProbeResult) (ChangeOutcome, error) {
			if noop {
				return ChangeOutcome{}, nil
			}
			if err := commit(ctx, tx, dc, probed, s.now()); err != nil {
				return ChangeOutcome{}, err
			}
			return ChangeOutcome{Changed: true, Loosened: dc.c.loosened}, nil
		},
	})
	return out, reports, err
}

// ReplaceCredential is replaceAuditExportCredential: always an approval
// (audit_export.change: a wrong key stops delivery). The stream and the
// pending plan are kept, and the next lease holder uploads the plan with
// the new key (Decision 3). No probe. Both read flags are cleared: they
// described the old key.
func (s *Service) ReplaceCredential(ctx context.Context, req Request, org authz.Organization, exportID string, c Credential, expected int64) ([]auth.PendingReport, error) {
	if err := requirePerson(req.Principal); err != nil {
		return nil, err
	}
	if err := s.requireSwitchOn(); err != nil {
		return nil, err
	}
	cred, err := ValidateCredential(c)
	if err != nil {
		return nil, err
	}
	sealed, err := s.sealCredential(ctx, org.ID, exportID, cred)
	if err != nil {
		return nil, err
	}
	return s.approvedJob(ctx, req, org, exportID, expected, func(row query.AuditExport) auth.Binding {
		orgID := org.ID
		return auth.Binding{
			Operation: "audit_export.change", OrganizationID: &orgID, Target: map[string]string{"exportId": exportID},
			// The intent keeps only the body's keyed hash; the summary never names the key.
			Body:  jsvalue.Object{{Key: "credential", Value: cred.js()}, {Key: "expectedVersion", Value: expected}},
			Query: map[string]string{}, ExpectedVersion: &expected,
			Summary: auth.ApprovalSummary{Title: "Replace the key of the audit export of " + org.Name,
				Changes: []auth.ApprovalChange{{Field: "credential", Loosens: true}}},
		}
	}, func(ctx context.Context, tx *storage.Tx, row query.AuditExport, used *auth.UsedApproval) error {
		if _, err := query.New(tx).ReplaceAuditExportCredential(ctx, query.ReplaceAuditExportCredentialParams{
			CredentialEnvelope: nullStr(sealed, true), UpdatedAt: s.now().UnixMicro(), ID: exportID,
		}); err != nil {
			return err
		}
		action := "organization.manage"
		_, err := audit.Record(ctx, tx, audit.Event{
			Type: "audit_export.credential_replaced", Decision: audit.Info, ActorIdentityID: &req.Principal.Identity.ID, OrganizationID: &org.ID,
			Action: &action, RequestID: &req.RequestID, Resource: jsvalue.Object{{Key: "exportId", Value: exportID}},
			Metadata: append(jsvalue.Object{}, security.ApprovalMetadata(used)...),
		})
		return err
	})
}

// Remove is removeAuditExport: always an approval (audit_export.remove).
// In one job: removed, the pending plan deleted, the key cleared, the
// generation incremented (Decision 9). Allowed with the switch off, so an
// Organization can still take its key out of an installation that stopped
// exporting. It answers the removed export.
func (s *Service) Remove(ctx context.Context, req Request, org authz.Organization, exportID string, expected int64) (jsvalue.Object, []auth.PendingReport, error) {
	if err := requirePerson(req.Principal); err != nil {
		return nil, nil, err
	}
	var out jsvalue.Object
	reports, err := s.approvedJob(ctx, req, org, exportID, expected, func(row query.AuditExport) auth.Binding {
		orgID := org.ID
		from := endpointHost(row.Endpoint) + "/" + row.Bucket + "/" + row.Prefix
		return auth.Binding{
			Operation: "audit_export.remove", OrganizationID: &orgID, Target: map[string]string{"exportId": exportID},
			Body:  jsvalue.Object{{Key: "expectedVersion", Value: expected}},
			Query: map[string]string{}, ExpectedVersion: &expected,
			Summary: auth.ApprovalSummary{Title: "Remove the audit export of " + org.Name,
				Changes: []auth.ApprovalChange{{Field: "destination", From: &from, Loosens: true}}},
		}
	}, func(ctx context.Context, tx *storage.Tx, row query.AuditExport, used *auth.UsedApproval) error {
		q := query.New(tx)
		plan, err := q.AuditExportPlanOf(ctx, exportID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		deleted := err == nil
		if deleted {
			if err := q.DeleteAuditExportPlan(ctx, plan.ID); err != nil {
				return err
			}
		}
		removed, err := q.RemoveAuditExport(ctx, query.RemoveAuditExportParams{At: nullInt(s.now().UnixMicro(), true), ID: exportID})
		if err != nil {
			return err
		}
		action := "organization.manage"
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "audit_export.removed", Decision: audit.Info, ActorIdentityID: &req.Principal.Identity.ID, OrganizationID: &org.ID,
			Action: &action, RequestID: &req.RequestID, Resource: jsvalue.Object{{Key: "exportId", Value: exportID}},
			Metadata: append(jsvalue.Object{{Key: "streamId", Value: row.StreamID}, {Key: "pendingPlanDeleted", Value: deleted}}, security.ApprovalMetadata(used)...),
		}); err != nil {
			return err
		}
		out = removedView(removed)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return out, reports, nil
}

// approvedJob is the shape replaceAuditExportCredential and
// removeAuditExport share: the scope and the requester held (steps 1 and
// 2), the export read and the checkpoint passed (preflight), its version,
// then the binding, its approval consumed (or asked for),
// organization.manage rechecked, the version again, then apply.
func (s *Service) approvedJob(ctx context.Context, req Request, org authz.Organization, exportID string, expected int64,
	bind func(row query.AuditExport) auth.Binding,
	apply func(ctx context.Context, tx *storage.Tx, row query.AuditExport, used *auth.UsedApproval) error) ([]auth.PendingReport, error) {
	gates := []write.Gate{write.Organization(org.ID, write.Shared), req.personGate(), exportGate(exportID)}
	var reports []auth.PendingReport
	err := s.Writer.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		reports = nil
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: org.ID}); err != nil {
			return err
		}
		row, err := activeExport(ctx, tx, org.ID, exportID)
		if err != nil {
			return err
		}
		if row == nil {
			return notFound()
		}
		if reports, err = write.Checkpoint(ctx, tx, req.Principal, org.ID); err != nil {
			return err
		}
		if err := manageIn(ctx, tx, req, org.ID); err != nil {
			return err
		}
		if row.Version != expected {
			return versionConflict(row.Version, expected)
		}
		used, err := s.approve(ctx, tx, req, bind(*row))
		if err != nil {
			return err
		}
		if err := manageIn(ctx, tx, req, org.ID); err != nil {
			return err
		}
		return apply(ctx, tx, *row, used)
	})
	return reports, err
}
