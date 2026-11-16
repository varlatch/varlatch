// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"errors"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
)

// Security Controls (ADR-0054 Decisions 1, 2, 4, 9 and 11; ADR-0059 step
// 4.3a): listSecurityControls, changeSecurityControl,
// securityControlReport and securityApprovalKeys, as http/app.ts serves
// them. Reading the controls needs organization.read; the report and the
// approval keys name people and what they did, so they need
// organization.manage, as changing a control does.

const (
	listSecurityControlsPattern  = "GET /v1/organizations/{org}/security/controls"
	changeSecurityControlPattern = "PATCH /v1/organizations/{org}/security/controls/{control}"
	securityControlReportPattern = "GET /v1/organizations/{org}/security/control-report"
	securityApprovalKeysPattern  = "GET /v1/organizations/{org}/security/approval-keys"
	securityControlRoute         = "/v1/organizations/:org/security/controls/:control"
	securityRoute                = "/v1/organizations/:org/security/"
)

func init() {
	for _, p := range []string{listSecurityControlsPattern, changeSecurityControlPattern, securityControlReportPattern, securityApprovalKeysPattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitListSecurityControlsResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitChangeSecurityControlResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitSecurityControlReportResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitSecurityApprovalKeysResponse(w http.ResponseWriter) error  { return r.visit(w) }

func stringList(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

// ListSecurityControls is GET …/security/controls: inspection while frozen,
// organization.read; each control with the modes it accepts in this
// release, and the modes every control accepts.
func (o *operations) ListSecurityControls(ctx context.Context, _ api.ListSecurityControlsRequestObject) (api.ListSecurityControlsResponseObject, error) {
	q, err := o.enterRoute(ctx, securityRoute+"controls", authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.read"); err != nil {
		return nil, err
	}
	states, err := security.List(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID)
	if err != nil {
		return nil, err
	}
	items := make([]any, len(states))
	for i, st := range states {
		items[i] = append(st.JS(), jsvalue.Member{Key: "availableModes", Value: stringList(security.AvailableModesOf(st.Control))})
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "items", Value: items}, {Key: "availableModes", Value: stringList(security.AvailableModes)}}), nil
}

var reportDays = regexp.MustCompile(`^[0-9]{1,2}$`)

// SecurityControlReport is GET …/security/control-report: inspection
// while frozen, organization.manage; days, 30 when absent, two digits at
// most (checked after authorization), then 1 to 30 (checked once
// Cache-Control: no-store is set, as the TypeScript route sets it before
// the report checks its window).
func (o *operations) SecurityControlReport(ctx context.Context, _ api.SecurityControlReportRequestObject) (api.SecurityControlReportResponseObject, error) {
	q, err := o.enterRoute(ctx, securityRoute+"control-report", authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.manage"); err != nil {
		return nil, err
	}
	days := int64(30)
	if raw, present := rawOf(ctx).query["days"]; present {
		if !reportDays.MatchString(raw[0]) {
			return nil, domainerr.New("VALIDATION_FAILED", "days must be an integer in 1..30")
		}
		days, _ = strconv.ParseInt(raw[0], 10, 64)
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	report, err := security.ControlReportOf(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID, days, o.s.opts.Now)
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(report), nil
}

// SecurityApprovalKeys is GET …/security/approval-keys: inspection while
// frozen, organization.manage, never cached.
func (o *operations) SecurityApprovalKeys(ctx context.Context, _ api.SecurityApprovalKeysRequestObject) (api.SecurityApprovalKeysResponseObject, error) {
	q, err := o.enterRoute(ctx, securityRoute+"approval-keys", authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.manage"); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	keys, err := security.ApprovalKeys(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID, o.s.opts.Now)
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(keys), nil
}

// ChangeSecurityControl is PATCH …/security/controls/{control}: recovery
// while frozen, organization.manage, a person's browser or cli credential,
// a known control (not found otherwise), the body's zod schema, the
// self-lockout check for passkey-verification at enforce, then the
// Varlatch-Approval header and the change (security.ChangeControl), which
// answers STEP_UP_REQUIRED when it loosens the control without an
// approval.
func (o *operations) ChangeSecurityControl(ctx context.Context, _ api.ChangeSecurityControlRequestObject) (api.ChangeSecurityControlResponseObject, error) {
	q, err := o.enterRoute(ctx, securityControlRoute, authz.DuringFreezeRecovery)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.manage"); err != nil {
		return nil, err
	}
	p := q.p
	if p.Identity.Kind != "human" || (p.Credential.Kind != auth.KindBrowser && p.Credential.Kind != auth.KindCLI) {
		return nil, domainerr.New("PERMISSION_DENIED", "Only a person can change a security control; machine credentials never can")
	}
	segs := strings.Split(strings.TrimPrefix(q.r.URL.Path, "/"), "/")
	control := tryDecodeURIComponent(segs[5])
	if !security.IsControl(control) {
		return nil, domainerr.New("RESOURCE_NOT_FOUND", "No such security control")
	}
	// c.req.json().catch(() => undefined): a body that is not JSON is undefined.
	var body any = undefinedBody{}
	if v, err := jsvalue.Parse(rawOf(ctx).body); err == nil {
		body = v
	}
	in, err := parseControlChange(body)
	if err != nil {
		return nil, err
	}
	in.OrganizationID, in.Control, in.Principal, in.RequestID = q.org.ID, control, p, requestIDOf(q.r)
	// Enforcing passkey-verification from a sign-in it would refuse locks
	// the person making the change out at once: refused, nothing changed.
	if control == security.PasskeyVerification && in.Mode != nil && *in.Mode == security.Enforce {
		gap, err := auth.VerificationGap(ctx, o.s.opts.Auth.Store().Reader(), p.Credential.ID, p.Credential.Kind)
		if err != nil {
			return nil, err
		}
		if gap != "" {
			return nil, auth.EnforceWouldRefuseYou(q.org.ID, gap)
		}
	}
	if raw := rawOf(ctx); raw.approvalPresent {
		if in.ApprovalID = auth.ParseApprovalID(raw.approval); in.ApprovalID == "" {
			return nil, auth.ApprovalInvalid("not-found", nil)
		}
	}
	type result struct {
		change  security.Change
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(p), func() (result, error) {
		c, reports, err := security.ChangeControl(ctx, o.s.opts.Writer, o.s.opts.Auth, in, o.s.opts.Now)
		return result{c, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	q.checked, q.reports, q.at = true, res.reports, o.s.opts.Now().UnixMicro()
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(res.change.JS()), nil
}

// undefinedBody is JavaScript's undefined, for zod's "received undefined".
type undefinedBody struct{}

// zodReceived is the type zod names in "received ...", for a value
// JSON.parse made (or undefined).
func zodReceived(v any) string {
	if _, isUndefined := v.(undefinedBody); isUndefined {
		return "undefined"
	}
	if x, isNum := v.(float64); isNum && (math.IsInf(x, 0) || math.IsNaN(x)) {
		if math.IsNaN(x) {
			return "NaN"
		}
		if x < 0 {
			return "-Infinity"
		}
		return "Infinity"
	}
	return zodType(v)
}

const maxSafeInt = 1<<53 - 1

// zodInt is z.number().int().min(lo).max(hi)'s issues for a present value,
// in zod 4's order: a value that is not a number, or not an integer, stops
// there; a safe-integer bound and the range checks each add one.
func zodInt(path string, v any, lo, hi float64) []string {
	x, isNum := v.(float64)
	if !isNum || math.IsInf(x, 0) || math.IsNaN(x) {
		return []string{path + ": Invalid input: expected number, received " + zodReceived(v)}
	}
	if x != math.Trunc(x) {
		return []string{path + ": Invalid input: expected int, received number"}
	}
	var issues []string
	if x > maxSafeInt {
		issues = append(issues, path+": Too big: expected int to be <=9007199254740991")
	}
	if x < -maxSafeInt {
		issues = append(issues, path+": Too small: expected int to be >=-9007199254740991")
	}
	if x < lo {
		issues = append(issues, path+": Too small: expected number to be >="+jsvalue.Number(lo))
	}
	if x > hi {
		issues = append(issues, path+": Too big: expected number to be <="+jsvalue.Number(hi))
	}
	return issues
}

// unrecognized is a strict object's issue for the keys it does not know.
func unrecognized(path string, obj jsvalue.Object, known ...string) []string {
	var extra []string
	for _, m := range obj {
		if !containsString(known, m.Key) {
			extra = append(extra, `"`+m.Key+`"`)
		}
	}
	switch len(extra) {
	case 0:
		return nil
	case 1:
		return []string{path + ": Unrecognized key: " + extra[0]}
	}
	return []string{path + ": Unrecognized keys: " + strings.Join(extra, ", ")}
}

const maxTTL = 315_360_000

// parseControlChange is the change's zod schema:
//
//	z.object({
//	  mode: z.enum(["off", "report", "enforce"]).optional(),
//	  config: z.object({ defaultTtlSeconds: ttl, maxTtlSeconds: ttl }).strict().nullable().optional(),
//	  expectedVersion: z.number().int().min(0),
//	}).strict()
//
// with ttl z.number().int().min(1).max(315_360_000): every issue, in zod's
// order (the members in the schema's order, then the unknown keys).
func parseControlChange(body any) (security.ChangeInput, error) {
	fail := func(issues []string) error { return domainerr.New("VALIDATION_FAILED", strings.Join(issues, "; ")) }
	obj, isObj := body.(jsvalue.Object)
	if !isObj {
		return security.ChangeInput{}, fail([]string{"(root): Invalid input: expected object, received " + zodReceived(body)})
	}
	in := security.ChangeInput{Config: security.ConfigChange{Keep: true}}
	var issues []string
	if v, present := obj.Get("mode"); present {
		if s, isStr := v.(string); isStr && containsString([]string{security.Off, security.Report, security.Enforce}, s) {
			in.Mode = &s
		} else {
			issues = append(issues, `mode: Invalid option: expected one of "off"|"report"|"enforce"`)
		}
	}
	if v, present := obj.Get("config"); present {
		switch c := v.(type) {
		case nil:
			in.Config = security.ConfigChange{}
		case jsvalue.Object:
			var cfgIssues []string
			var l security.Lifetime
			for _, f := range []struct {
				name string
				dst  *int64
			}{{"defaultTtlSeconds", &l.DefaultTTLSeconds}, {"maxTtlSeconds", &l.MaxTTLSeconds}} {
				fv, present := c.Get(f.name)
				if !present {
					cfgIssues = append(cfgIssues, "config."+f.name+": Invalid input: expected number, received undefined")
					continue
				}
				if is := zodInt("config."+f.name, fv, 1, maxTTL); len(is) > 0 {
					cfgIssues = append(cfgIssues, is...)
					continue
				}
				*f.dst = int64(fv.(float64))
			}
			cfgIssues = append(cfgIssues, unrecognized("config", c, "defaultTtlSeconds", "maxTtlSeconds")...)
			if len(cfgIssues) > 0 {
				issues = append(issues, cfgIssues...)
			} else {
				in.Config = security.ConfigChange{Set: &l}
			}
		default:
			issues = append(issues, "config: Invalid input: expected object, received "+zodReceived(v))
		}
	}
	if v, present := obj.Get("expectedVersion"); !present {
		issues = append(issues, "expectedVersion: Invalid input: expected number, received undefined")
	} else if is := zodInt("expectedVersion", v, 0, math.Inf(1)); len(is) > 0 {
		issues = append(issues, is...)
	} else {
		in.ExpectedVersion = int64(v.(float64))
	}
	issues = append(issues, unrecognized("(root)", obj, "mode", "config", "expectedVersion")...)
	if len(issues) > 0 {
		return security.ChangeInput{}, fail(issues)
	}
	return in, nil
}

// recordDeferredDenial records a denial a write job found and rolled back
// (security.DeferredDenial), after the job, as app.onError's
// auditDeferredDenial does; best effort.
func (q *orgRequest) recordDeferredDenial(ctx context.Context, err error) {
	var deferred *security.DeferredDenial
	if !errors.As(err, &deferred) {
		return
	}
	if werr := q.o.s.opts.Auth.Store().Write(ctx, func(tx *storage.Tx) error {
		_, e := audit.Record(ctx, tx, deferred.Event)
		return e
	}); werr != nil {
		q.o.s.opts.Log.Error("could not audit a refusal", "type", deferred.Event.Type, "requestId", requestIDOf(q.r), "error", werr)
	}
}
