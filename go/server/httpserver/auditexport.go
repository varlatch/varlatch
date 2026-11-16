// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"database/sql"
	"net/http"
	"regexp"
	"strconv"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/auditexport"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
)

// The audit export to object storage (ADR-0056; capability
// audit.storage-export; ADR-0059 step 4.11a), as http/app.ts serves it.
// One export per Organization. Reading needs organization.manage (it names
// the destination and its failures) and is inspection while frozen. Every
// write needs organization.manage and a person's credential. Creating and
// checking need no approval; another destination, a new key, a shorter or
// removed retention, compliance to governance, and removal always need the
// requester's step-up approval (server/auditexport).

const (
	getAuditExportPattern     = "GET /v1/organizations/{org}/audit-export"
	createAuditExportPattern  = "POST /v1/organizations/{org}/audit-export"
	checkAuditExportPattern   = "POST /v1/organizations/{org}/audit-export/check"
	changeAuditExportPattern  = "PATCH /v1/organizations/{org}/audit-export"
	replaceAuditExportPattern = "PUT /v1/organizations/{org}/audit-export/credential"
	removeAuditExportPattern  = "DELETE /v1/organizations/{org}/audit-export"
	storageExportRoute        = "/v1/organizations/:org/audit-export"
)

func init() {
	for _, p := range []string{getAuditExportPattern, createAuditExportPattern, checkAuditExportPattern, changeAuditExportPattern,
		replaceAuditExportPattern, removeAuditExportPattern} {
		readsItself[p] = true
	}
	// The removal reads its own expectedVersion; the binder gets one it accepts.
	boundQuery[removeAuditExportPattern] = "expectedVersion=1"
}

func (r reply) VisitGetAuditExportResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitCreateAuditExportResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitCheckAuditExportResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitChangeAuditExportResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitReplaceAuditExportCredentialResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitRemoveAuditExportResponse(w http.ResponseWriter) error { return r.visit(w) }

// auditExportService is the operations' server/auditexport.
func (o *operations) auditExportService() *auditexport.Service {
	return &auditexport.Service{Writer: o.s.opts.Writer, Approvals: o.s.opts.Auth, RootKEK: o.s.opts.RootKEK, Policy: o.policy(),
		Now: o.clock(), Enabled: !o.s.opts.AuditExportOff, VerifiedProvider: o.s.opts.AuditExportVerifiedProvider}
}

func (q *orgRequest) auditExportRequest(ctx context.Context) auditexport.Request {
	return auditexport.Request{Principal: q.p, Approval: approvalHeaderOf(ctx), RequestID: requestIDOf(q.r)}
}

var (
	exportDestinationBody = zStrict{
		{name: "endpoint", schema: zString{min: 1, max: 2048}},
		{name: "region", schema: zString{min: 1, max: 64}},
		{name: "bucket", schema: zString{min: 3, max: 63}},
		{name: "prefix", schema: zDefault{zString{max: 256}, ""}},
		{name: "pathStyle", schema: zDefault{zBool{}, false}},
	}
	exportCredentialBody = zStrict{
		{name: "accessKeyId", schema: zString{min: 1, max: 128}},
		{name: "secretAccessKey", schema: zString{min: 1, max: 256}},
	}
	exportRetentionBody = zStrict{
		{name: "mode", schema: zEnum{"compliance", "governance"}},
		{name: "days", schema: zInt{min: 1, max: 3650}},
	}
	createAuditExportBody = zStrict{
		{name: "destination", schema: exportDestinationBody},
		{name: "credential", schema: exportCredentialBody},
		{name: "retention", schema: zDefault{zNullable{exportRetentionBody}, nil}},
		{name: "from", schema: zDefault{zEnum{"beginning", "now"}, "beginning"}},
	}
	checkAuditExportBody = zStrict{
		{name: "destination", schema: exportDestinationBody},
		{name: "credential", schema: exportCredentialBody, optional: true},
		{name: "retention", schema: zDefault{zNullable{exportRetentionBody}, nil}},
	}
	changeAuditExportBody = zStrict{
		{name: "expectedVersion", schema: zInt{min: 1}},
		// Only the fields named change: no defaults here, unlike creation.
		{name: "destination", schema: zStrict{
			{name: "endpoint", schema: zString{min: 1, max: 2048}, optional: true},
			{name: "region", schema: zString{min: 1, max: 64}, optional: true},
			{name: "bucket", schema: zString{min: 3, max: 63}, optional: true},
			{name: "prefix", schema: zString{max: 256}, optional: true},
			{name: "pathStyle", schema: zBool{}, optional: true},
		}, optional: true},
		{name: "retention", schema: zNullable{exportRetentionBody}, optional: true},
	}
	replaceAuditExportBody = zStrict{
		{name: "expectedVersion", schema: zInt{min: 1}},
		{name: "credential", schema: exportCredentialBody},
	}
)

// exportBody is c.req.json().catch(() => undefined) through a schema.
func exportBody(ctx context.Context, schema zSchema) (jsvalue.Object, error) {
	var body any = undefinedBody{}
	if v, err := jsvalue.Parse(rawOf(ctx).body); err == nil {
		body = v
	}
	out, err := zParse(schema, body)
	if err != nil {
		return nil, err
	}
	return out.(jsvalue.Object), nil
}

func member(o jsvalue.Object, key string) (any, bool) { return o.Get(key) }

func destinationIn(v any) auditexport.Destination {
	o := v.(jsvalue.Object)
	str := func(k string) string { s, _ := member(o, k); out, _ := s.(string); return out }
	b, _ := member(o, "pathStyle")
	path, _ := b.(bool)
	return auditexport.Destination{Endpoint: str("endpoint"), Region: str("region"), Bucket: str("bucket"), Prefix: str("prefix"), PathStyle: path}
}

func credentialIn(v any) auditexport.Credential {
	o := v.(jsvalue.Object)
	id, _ := member(o, "accessKeyId")
	secret, _ := member(o, "secretAccessKey")
	return auditexport.Credential{AccessKeyID: id.(string), SecretAccessKey: secret.(string)}
}

func retentionIn(v any) *auditexport.Retention {
	o, ok := v.(jsvalue.Object)
	if !ok {
		return nil
	}
	mode, _ := member(o, "mode")
	days, _ := member(o, "days")
	return &auditexport.Retention{Mode: mode.(string), Days: int64(days.(float64))}
}

// exportManage is the writes' entry: the route (no freeze exception),
// organization.manage, a person's credential.
func (o *operations) exportManage(ctx context.Context, route string) (*orgRequest, error) {
	q, err := o.organizationManage(ctx, route, "")
	if err != nil {
		return nil, err
	}
	if err := auditexport.RequirePerson(q.p); err != nil {
		return nil, err
	}
	return q, nil
}

// exportStatus is auditExportStatus, in one read snapshot.
func (o *operations) exportStatus(ctx context.Context, organizationID string) (jsvalue.Object, error) {
	tx, err := o.s.opts.Auth.Store().Reader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	return auditexport.Status(ctx, tx, organizationID, !o.s.opts.AuditExportOff)
}

func statusExport(s jsvalue.Object) any {
	v, _ := s.Get("export")
	return v
}

// GetAuditExport is GET …/audit-export: inspection while frozen,
// organization.manage; whether the host left the export on, and the
// export (the live one, else the most recent, else null). Never cached.
func (o *operations) GetAuditExport(ctx context.Context, _ api.GetAuditExportRequestObject) (api.GetAuditExportResponseObject, error) {
	q, err := o.organizationManage(ctx, storageExportRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	status, err := o.exportStatus(ctx, q.org.ID)
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(status), nil
}

// CreateAuditExport is POST …/audit-export: 201 with the new export.
func (o *operations) CreateAuditExport(ctx context.Context, _ api.CreateAuditExportRequestObject) (api.CreateAuditExportResponseObject, error) {
	q, err := o.exportManage(ctx, storageExportRoute)
	if err != nil {
		return nil, err
	}
	body, err := exportBody(ctx, createAuditExportBody)
	if err != nil {
		return nil, err
	}
	dest, _ := body.Get("destination")
	cred, _ := body.Get("credential")
	ret, _ := body.Get("retention")
	from, _ := body.Get("from")
	reports, err := o.auditExportService().Create(ctx, q.auditExportRequest(ctx), q.org, auditexport.CreateInput{
		Destination: destinationIn(dest), Credential: credentialIn(cred), Retention: retentionIn(ret), From: from.(string),
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	status, err := o.exportStatus(ctx, q.org.ID)
	if err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: statusExport(status)}, nil
}

// CheckAuditExport is POST …/audit-export/check: the probe alone.
func (o *operations) CheckAuditExport(ctx context.Context, _ api.CheckAuditExportRequestObject) (api.CheckAuditExportResponseObject, error) {
	q, err := o.exportManage(ctx, storageExportRoute+"/check")
	if err != nil {
		return nil, err
	}
	body, err := exportBody(ctx, checkAuditExportBody)
	if err != nil {
		return nil, err
	}
	dest, _ := body.Get("destination")
	ret, _ := body.Get("retention")
	in := auditexport.CheckInput{Destination: destinationIn(dest), Retention: retentionIn(ret)}
	if c, has := body.Get("credential"); has {
		cred := credentialIn(c)
		in.Credential = &cred
	}
	// Set before the check runs, as there: its refusals are not cached either.
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	result, reports, err := o.auditExportService().Check(ctx, q.auditExportRequest(ctx), q.org, in)
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return ok(result.JS()), nil
}

// ChangeAuditExport is PATCH …/audit-export: the destination or the
// retention, under the approval a loosening change needs.
func (o *operations) ChangeAuditExport(ctx context.Context, _ api.ChangeAuditExportRequestObject) (api.ChangeAuditExportResponseObject, error) {
	q, err := o.exportManage(ctx, storageExportRoute)
	if err != nil {
		return nil, err
	}
	body, err := exportBody(ctx, changeAuditExportBody)
	if err != nil {
		return nil, err
	}
	version, _ := body.Get("expectedVersion")
	in := auditexport.ChangeInput{ExpectedVersion: int64(version.(float64))}
	if d, has := body.Get("destination"); has {
		dd := d.(jsvalue.Object)
		in.Destination = auditexport.DestinationPatch{Endpoint: optionalString(dd, "endpoint"), Region: optionalString(dd, "region"),
			Bucket: optionalString(dd, "bucket"), Prefix: optionalString(dd, "prefix")}
		if b, has := dd.Get("pathStyle"); has {
			v := b.(bool)
			in.Destination.PathStyle = &v
		}
	}
	if r, has := body.Get("retention"); has {
		in.SetRetention, in.Retention = true, retentionIn(r)
	}
	exportID, err := auditexport.LiveID(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID)
	if err != nil {
		return nil, err
	}
	type result struct {
		out     auditexport.ChangeOutcome
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := o.auditExportService().Change(ctx, q.auditExportRequest(ctx), q.org, exportID, in)
		return result{out, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	status, err := o.exportStatus(ctx, q.org.ID)
	if err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "export", Value: statusExport(status)}, {Key: "changed", Value: res.out.Changed},
		{Key: "loosened", Value: res.out.Loosened}}), nil
}

// ReplaceAuditExportCredential is PUT …/audit-export/credential: always
// an approval.
func (o *operations) ReplaceAuditExportCredential(ctx context.Context, _ api.ReplaceAuditExportCredentialRequestObject) (api.ReplaceAuditExportCredentialResponseObject, error) {
	q, err := o.exportManage(ctx, storageExportRoute+"/credential")
	if err != nil {
		return nil, err
	}
	body, err := exportBody(ctx, replaceAuditExportBody)
	if err != nil {
		return nil, err
	}
	version, _ := body.Get("expectedVersion")
	cred, _ := body.Get("credential")
	exportID, err := auditexport.LiveID(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID)
	if err != nil {
		return nil, err
	}
	reports, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() ([]auth.PendingReport, error) {
		return o.auditExportService().ReplaceCredential(ctx, q.auditExportRequest(ctx), q.org, exportID, credentialIn(cred), int64(version.(float64)))
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	status, err := o.exportStatus(ctx, q.org.ID)
	if err != nil {
		return nil, err
	}
	return ok(statusExport(status)), nil
}

var expectedVersionQuery = regexp.MustCompile(`^[1-9]\d{0,9}$`)

// RemoveAuditExport is DELETE …/audit-export?expectedVersion=n: always
// an approval; allowed with the host switch off.
func (o *operations) RemoveAuditExport(ctx context.Context, _ api.RemoveAuditExportRequestObject) (api.RemoveAuditExportResponseObject, error) {
	q, err := o.exportManage(ctx, storageExportRoute)
	if err != nil {
		return nil, err
	}
	raw, present := rawOf(ctx).query["expectedVersion"]
	if !present || !expectedVersionQuery.MatchString(raw[0]) {
		return nil, domainerr.New("VALIDATION_FAILED", "expectedVersion: the export's current version, a whole number from 1, as a query parameter")
	}
	expected, _ := strconv.ParseInt(raw[0], 10, 64)
	exportID, err := auditexport.LiveID(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID)
	if err != nil {
		return nil, err
	}
	type result struct {
		out     jsvalue.Object
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := o.auditExportService().Remove(ctx, q.auditExportRequest(ctx), q.org, exportID, expected)
		return result{out, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return ok(res.out), nil
}
