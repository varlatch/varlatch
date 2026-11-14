// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/whatwg"
)

// testdata/ts-vectors.json comes from the TypeScript server's own code
// (services/varlatchd/test/go-authz-vectors.test.ts, which also checks it
// is current). Every vector must give the same answer here.

type resourceJSON struct {
	OrganizationID string `json:"organizationId"`
	ProjectID      string `json:"projectId"`
	Environment    *struct {
		ID     string `json:"id"`
		RootID string `json:"rootId"`
		Tier   string `json:"tier"`
	} `json:"environment"`
}

func (r resourceJSON) resource() Resource {
	out := Resource{OrganizationID: r.OrganizationID, ProjectID: r.ProjectID}
	if r.Environment != nil {
		out.Environment = &Environment{ID: r.Environment.ID, RootID: r.Environment.RootID, Tier: r.Environment.Tier}
	}
	return out
}

type grantJSON struct {
	ID                string    `json:"id"`
	SubjectIdentityID string    `json:"subjectIdentityId"`
	Scope             Scope     `json:"scope"`
	Actions           []*string `json:"actions"`
	ViaGroupID        string    `json:"viaGroupId"`
	RoleID            string    `json:"roleId"`
	RoleVersion       *int64    `json:"roleVersion"`
}

type requirementJSON struct {
	ID       string          `json:"id"`
	Version  *int64          `json:"version"`
	Target   Target          `json:"target"`
	Selector TailnetSelector `json:"selector"`
}

type contextJSON struct {
	Tailnet   string   `json:"tailnet"`
	NodeID    string   `json:"nodeId"`
	NodeName  *string  `json:"nodeName"`
	Tags      []string `json:"tags"`
	UserLogin *string  `json:"userLogin"`
}

func (c *contextJSON) context() *TailnetContext {
	if c == nil {
		return nil
	}
	return &TailnetContext{Tailnet: c.Tailnet, NodeID: c.NodeID, NodeName: c.NodeName, Tags: c.Tags, UserLogin: c.UserLogin}
}

type errorJSON struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Details json.RawMessage `json:"details"`
}

type outcomeJSON struct {
	Allowed     bool            `json:"allowed"`
	Evaluation  json.RawMessage `json:"evaluation"`
	Error       *errorJSON      `json:"error"`
	DenialEvent json.RawMessage `json:"denialEvent"`
}

type vectorFile struct {
	Actions              []string                `json:"actions"`
	EvaluateResources    map[string]resourceJSON `json:"evaluateResources"`
	EvaluateGrants       []grantJSON             `json:"evaluateGrants"`
	EvaluateRequirements []requirementJSON       `json:"evaluateRequirements"`
	EvaluateContexts     map[string]*contextJSON `json:"evaluateContexts"`
	Evaluate             []struct {
		Action       string          `json:"action"`
		Resource     string          `json:"resource"`
		OrgRole      *string         `json:"orgRole"`
		Grants       bool            `json:"grants"`
		Requirements bool            `json:"requirements"`
		Tailnet      string          `json:"tailnet"`
		Evaluation   json.RawMessage `json:"evaluation"`
		AuditAuthz   json.RawMessage `json:"auditAuthz"`
	} `json:"evaluate"`
	Rows []struct {
		Table string                     `json:"table"`
		Row   map[string]json.RawMessage `json:"row"`
	} `json:"rows"`
	Principals []struct {
		Identity struct {
			ID             string  `json:"id"`
			Kind           string  `json:"kind"`
			OrganizationID *string `json:"organization_id"`
		} `json:"identity"`
		CredentialID string `json:"credentialId"`
	} `json:"principals"`
	Resources    map[string]resourceJSON               `json:"resources"`
	Contexts     map[string]*contextJSON               `json:"contexts"`
	Grants       map[string]map[string]json.RawMessage `json:"grants"`
	Requirements map[string]json.RawMessage            `json:"requirements"`
	Decisions    []struct {
		Principal string `json:"principal"`
		Action    string `json:"action"`
		Resource  string `json:"resource"`
		Tailnet   string `json:"tailnet"`
		outcomeJSON
		Hidden *outcomeJSON `json:"hidden"`
	} `json:"decisions"`
	Entries []struct {
		Principal      *string    `json:"principal"`
		Ref            string     `json:"ref"`
		Exception      *string    `json:"exception"`
		OrganizationID string     `json:"organizationId"`
		Error          *errorJSON `json:"error"`
	} `json:"entries"`
	ScopeChecks []struct {
		OrganizationID string     `json:"organizationId"`
		Exception      *string    `json:"exception"`
		Error          *errorJSON `json:"error"`
	} `json:"scopeChecks"`
	Requests []struct {
		Principal string     `json:"principal"`
		Ref       string     `json:"ref"`
		Exception *string    `json:"exception"`
		Action    string     `json:"action"`
		Stage     string     `json:"stage"`
		Allowed   bool       `json:"allowed"`
		Error     *errorJSON `json:"error"`
	} `json:"requests"`
	DestinationHosts []struct {
		Input         string  `json:"input"`
		Canonical     *string `json:"canonical"`
		DomainToASCII string  `json:"domainToASCII"`
		IsIP          int     `json:"isIP"`
	} `json:"destinationHosts"`
	DestinationLongHosts []struct {
		Shape         string  `json:"shape"`
		Bytes         int     `json:"bytes"`
		Canonical     *digest `json:"canonical"`
		DomainToASCII *digest `json:"domainToASCII"`
	} `json:"destinationLongHosts"`
	DestinationSelectors []struct {
		Input    string `json:"input"`
		Selector *struct {
			Host     string `json:"host"`
			Wildcard bool   `json:"wildcard"`
			Port     int    `json:"port"`
		} `json:"selector"`
		Formatted *string `json:"formatted"`
	} `json:"destinationSelectors"`
	DestinationMatches []struct {
		Selector string `json:"selector"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Matches  bool   `json:"matches"`
	} `json:"destinationMatches"`
}

// digest is a long answer's length (UTF-16 code units, here ASCII bytes)
// and SHA-256.
type digest struct {
	Length int    `json:"length"`
	SHA256 string `json:"sha256"`
}

func digestOf(s string) digest {
	h := sha256.Sum256([]byte(s))
	return digest{len(s), hex.EncodeToString(h[:])}
}

// longHost builds the inputs of go-authz-vectors.test.ts's LONG_SHAPES.
func longHost(shape string, n int) string {
	labels := func(n int) string {
		s := strings.Repeat(strings.Repeat("a", 63)+".", (n+63)/64)[:n]
		if strings.HasSuffix(s, ".") {
			s = s[:len(s)-1] + "a"
		}
		return s
	}
	const u = "\u00fc"
	switch shape {
	case "ascii":
		return strings.Repeat("a", n)
	case "asciiLabels":
		return labels(n)
	case "nonAsciiFirst":
		return u + strings.Repeat("a", n-2)
	case "nonAsciiLast":
		return strings.Repeat("a", n-2) + u
	case "nonAsciiLabels":
		return u + labels(n - 2)[1:] + "a"
	}
	panic("unknown shape " + shape)
}

func loadVectors(t *testing.T) *vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

// js is JSON.stringify of a value the TypeScript code produced, recovered
// from the file: the order of its members is kept.
func js(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	v, err := jsvalue.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return string(jsvalue.Stringify(v))
}

func TestActionsMatchTypeScript(t *testing.T) {
	v := loadVectors(t)
	want := append(slices.Clone(Actions), "unknown.action")
	if !slices.Equal(v.Actions, want) {
		t.Fatalf("actions %v, TypeScript's %v", want, v.Actions)
	}
}

// The pure evaluator: the same evaluation and audit authz, byte for byte
// (member order included: the input fixes the Grants' order here).
func TestEvaluateVectors(t *testing.T) {
	v := loadVectors(t)
	grants := make([]Grant, len(v.EvaluateGrants))
	for i, g := range v.EvaluateGrants {
		grants[i] = Grant(g)
	}
	reqs := make([]Requirement, len(v.EvaluateRequirements))
	for i, r := range v.EvaluateRequirements {
		reqs[i] = Requirement(r)
	}
	if len(v.Evaluate) < 1000 {
		t.Fatalf("only %d evaluate vectors", len(v.Evaluate))
	}
	for i, vec := range v.Evaluate {
		in := Input{Action: vec.Action, Resource: v.EvaluateResources[vec.Resource].resource(), TailnetContext: v.EvaluateContexts[vec.Tailnet].context()}
		if vec.OrgRole != nil {
			in.OrgRole = *vec.OrgRole
		}
		if vec.Grants {
			in.Grants = grants
		}
		if vec.Requirements {
			in.Requirements = reqs
		}
		e := Evaluate(in)
		name := fmt.Sprintf("#%d %s %v %s on %s from %s", i, vec.Action, vec.OrgRole, map[bool]string{true: "grants", false: "no grants"}[vec.Grants], vec.Resource, vec.Tailnet)
		if got, want := string(jsvalue.Stringify(e)), js(t, vec.Evaluation); got != want {
			t.Errorf("%s: evaluation\n got %s\nwant %s", name, got, want)
		}
		if got, want := string(jsvalue.Stringify(AuditAuthz(e))), js(t, vec.AuditAuthz); got != want {
			t.Errorf("%s: auditAuthz\n got %s\nwant %s", name, got, want)
		}
	}
}

// seed inserts the fixture's rows, in order, as the TypeScript test
// inserted them into PostgreSQL: timestamps ({"$ts": ...}) as
// microseconds, arrays (text[]) and objects (jsonb) as JSON text.
func seed(t *testing.T, v *vectorFile) *storage.DB {
	t.Helper()
	s, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := db.Init(context.Background(), s, "0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	err = s.Write(context.Background(), func(tx *storage.Tx) error {
		for _, r := range v.Rows {
			cols := make([]string, 0, len(r.Row))
			for c := range r.Row {
				cols = append(cols, c)
			}
			slices.Sort(cols)
			args := make([]any, len(cols))
			for i, c := range cols {
				val, err := seedValue(r.Row[c])
				if err != nil {
					return fmt.Errorf("%s.%s: %w", r.Table, c, err)
				}
				args[i] = val
			}
			q := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", r.Table, strings.Join(cols, ", "), strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", "))
			if _, err := tx.ExecContext(context.Background(), q, args...); err != nil {
				return fmt.Errorf("%s: %w", q, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func seedValue(raw json.RawMessage) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	switch x := v.(type) {
	case json.Number:
		return x.Int64()
	case map[string]any:
		if s, ok := x["$ts"].(string); ok {
			tm, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				return nil, err
			}
			return tm.UnixMicro(), nil
		}
		return string(raw), nil
	case []any:
		return string(raw), nil
	}
	return v, nil
}

func (v *vectorFile) principal(t *testing.T, id string) Principal {
	t.Helper()
	for _, p := range v.Principals {
		if p.Identity.ID == id {
			out := Principal{IdentityID: id, IdentityKind: p.Identity.Kind, CredentialID: p.CredentialID}
			if p.Identity.OrganizationID != nil {
				out.OrganizationID = *p.Identity.OrganizationID
			}
			return out
		}
	}
	t.Fatalf("no principal %s", id)
	return Principal{}
}

// setOrder normalizes what PostgreSQL returns in no defined order. The
// TypeScript server's loadGrants query has no ORDER BY, so the order of the
// Grants it loads, and with it the order of grantIds, groupIds, roleIds and
// applied in an evaluation, is whatever plan PostgreSQL picks (on the
// fixture, a scan of grants_subject_group_idx: Grants by Group, direct
// Grants last). These lists are sets; they are compared sorted. The pure
// vectors above check the order the evaluator itself gives them.
func setOrder(v any) any {
	switch x := v.(type) {
	case jsvalue.Object:
		o := make(jsvalue.Object, len(x))
		for i, m := range x {
			val := setOrder(m.Value)
			switch m.Key {
			case "grantIds", "groupIds", "roleIds", "applied":
				if a, ok := val.([]any); ok {
					a = slices.Clone(a)
					slices.SortFunc(a, func(p, q any) int {
						return strings.Compare(string(jsvalue.Stringify(p)), string(jsvalue.Stringify(q)))
					})
					val = a
				}
			}
			o[i] = jsvalue.Member{Key: m.Key, Value: val}
		}
		return o
	case []any:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = setOrder(e)
		}
		return a
	}
	return v
}

// normalized renders v first, so a value with a JSValue method is sorted
// as well.
func normalized(t *testing.T, v any) string {
	t.Helper()
	rendered, err := jsvalue.Parse(jsvalue.Stringify(v))
	if err != nil {
		t.Fatal(err)
	}
	return string(jsvalue.Stringify(setOrder(rendered)))
}

func parsed(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	v, err := jsvalue.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// eventJS is an audit event input as the TypeScript code writes its
// object literal: the fields it sets, nothing else.
func eventJS(e audit.Event) jsvalue.Object {
	o := jsvalue.Object{{Key: "eventType", Value: e.Type}, {Key: "decision", Value: e.Decision}}
	if e.ActorIdentityID != nil {
		o = append(o, jsvalue.Member{Key: "actorIdentityId", Value: *e.ActorIdentityID})
	}
	if e.CredentialID.IsSet() {
		var c any
		if p := e.CredentialID.Get(); p != nil {
			c = *p
		}
		o = append(o, jsvalue.Member{Key: "credentialId", Value: c})
	}
	if e.OrganizationID != nil {
		o = append(o, jsvalue.Member{Key: "organizationId", Value: *e.OrganizationID})
	}
	if e.Action != nil {
		o = append(o, jsvalue.Member{Key: "action", Value: *e.Action})
	}
	if e.Resource != nil {
		o = append(o, jsvalue.Member{Key: "resource", Value: e.Resource})
	}
	if e.Authz != nil {
		o = append(o, jsvalue.Member{Key: "authz", Value: e.Authz})
	}
	if e.RequestID != nil {
		o = append(o, jsvalue.Member{Key: "requestId", Value: *e.RequestID})
	}
	if e.Metadata != nil {
		o = append(o, jsvalue.Member{Key: "metadata", Value: e.Metadata})
	}
	return o
}

func errorValue(e *domainerr.Error) string {
	o := jsvalue.Object{{Key: "code", Value: e.Code}, {Key: "message", Value: e.Message}}
	if e.Details != nil {
		o = append(o, jsvalue.Member{Key: "details", Value: e.Details})
	}
	return string(jsvalue.Stringify(o))
}

func wantError(t *testing.T, e *errorJSON) string {
	t.Helper()
	o := jsvalue.Object{{Key: "code", Value: e.Code}, {Key: "message", Value: e.Message}}
	if e.Details != nil {
		o = append(o, jsvalue.Member{Key: "details", Value: parsed(t, e.Details)})
	}
	return string(jsvalue.Stringify(o))
}

func domainError(err error) *domainerr.Error {
	var de *domainerr.Error
	if errors.As(err, &de) {
		return de
	}
	return nil
}

// LoadGrants and LoadRequirements load what loadGrants and
// loadTailnetRequirements load, for every subject (as sets: see setOrder).
func TestLoadVectors(t *testing.T) {
	v := loadVectors(t)
	s := seed(t, v)
	ctx := context.Background()
	for org, bySubject := range v.Grants {
		for subject, raw := range bySubject {
			grants, err := LoadGrants(ctx, s.Reader(), org, subject)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]any, len(grants))
			for i, g := range grants {
				got[i] = jsvalue.Jsonb(g)
			}
			want := jsvalue.Jsonb(parsed(t, raw)).([]any)
			sortValues(got)
			sortValues(want)
			if g, w := string(jsvalue.Stringify(got)), string(jsvalue.Stringify(want)); g != w {
				t.Errorf("grants of %s in %s\n got %s\nwant %s", subject, org, g, w)
			}
		}
	}
	for org, raw := range v.Requirements {
		reqs, err := LoadRequirements(ctx, s.Reader(), org)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]any, len(reqs))
		for i, r := range reqs {
			got[i] = jsvalue.Jsonb(requirementValue(r))
		}
		want := jsvalue.Jsonb(parsed(t, raw)).([]any)
		sortValues(got)
		sortValues(want)
		if g, w := string(jsvalue.Stringify(got)), string(jsvalue.Stringify(want)); g != w {
			t.Errorf("requirements of %s\n got %s\nwant %s", org, g, w)
		}
	}
}

func sortValues(a []any) {
	slices.SortFunc(a, func(p, q any) int { return strings.Compare(string(jsvalue.Stringify(p)), string(jsvalue.Stringify(q))) })
}

func requirementValue(r Requirement) any {
	target := jsvalue.Object{{Key: "kind", Value: r.Target.Kind}}
	if r.Target.Tier != "" {
		target = append(target, jsvalue.Member{Key: "tier", Value: r.Target.Tier})
	}
	if r.Target.EnvironmentIDs != nil {
		target = append(target, jsvalue.Member{Key: "environmentIds", Value: r.Target.EnvironmentIDs})
	}
	sel := jsvalue.Object{{Key: "tailnet", Value: r.Selector.Tailnet}}
	for _, l := range []struct {
		k string
		v []string
	}{{"tags", r.Selector.Tags}, {"users", r.Selector.Users}, {"nodes", r.Selector.Nodes}} {
		if l.v != nil {
			sel = append(sel, jsvalue.Member{Key: l.k, Value: l.v})
		}
	}
	return jsvalue.Object{{Key: "id", Value: r.ID}, {Key: "version", Value: *r.Version}, {Key: "target", Value: target}, {Key: "selector", Value: sel}}
}

func checkOutcome(t *testing.T, name string, d Decision, want outcomeJSON) {
	t.Helper()
	if d.Allowed != want.Allowed {
		t.Errorf("%s: allowed %v, TypeScript %v (%v)", name, d.Allowed, want.Allowed, d.Err)
		return
	}
	if want.Allowed {
		if g, w := normalized(t, d.Evaluation), normalized(t, parsed(t, want.Evaluation)); g != w {
			t.Errorf("%s: evaluation\n got %s\nwant %s", name, g, w)
		}
		return
	}
	if g, w := errorValue(d.Err), wantError(t, want.Error); g != w {
		t.Errorf("%s: error\n got %s\nwant %s", name, g, w)
	}
	switch {
	case d.DenialEvent == nil && string(want.DenialEvent) != "null":
		t.Errorf("%s: no denial event, TypeScript records %s", name, want.DenialEvent)
	case d.DenialEvent != nil:
		if g, w := normalized(t, eventJS(*d.DenialEvent)), normalized(t, parsed(t, want.DenialEvent)); g != w {
			t.Errorf("%s: denial event\n got %s\nwant %s", name, g, w)
		}
	}
}

// Decide answers as decide does: allowed or not, the evaluation, the error
// (code, message, details) and the denial's audit event, with and without
// existence hiding.
func TestDecideVectors(t *testing.T) {
	v := loadVectors(t)
	s := seed(t, v)
	ctx := context.Background()
	if len(v.Decisions) < 2000 {
		t.Fatalf("only %d decisions", len(v.Decisions))
	}
	for i, d := range v.Decisions {
		p := v.principal(t, d.Principal)
		opts := Options{TailnetContext: v.Contexts[d.Tailnet].context(), RequestID: "req_vector"}
		name := fmt.Sprintf("#%d %s %s on %s from %s", i, d.Principal, d.Action, d.Resource, d.Tailnet)
		shown, err := Decide(ctx, s.Reader(), p, d.Action, v.Resources[d.Resource].resource(), opts)
		if err != nil {
			t.Fatal(err)
		}
		checkOutcome(t, name, shown, d.outcomeJSON)
		opts.HideExistence = true
		hidden, err := Decide(ctx, s.Reader(), p, d.Action, v.Resources[d.Resource].resource(), opts)
		if err != nil {
			t.Fatal(err)
		}
		want := d.outcomeJSON
		if d.Hidden != nil {
			want = *d.Hidden
		}
		checkOutcome(t, name+" (hiding existence)", hidden, want)
	}
}

func optString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// The incident freeze at Organization entry, in RefuseIfIncidentFrozen,
// and before authorization in a request.
func TestFreezeVectors(t *testing.T) {
	v := loadVectors(t)
	s := seed(t, v)
	ctx := context.Background()
	for i, e := range v.Entries {
		var p *Principal
		if e.Principal != nil {
			pp := v.principal(t, *e.Principal)
			p = &pp
		}
		name := fmt.Sprintf("entry #%d %v into %s under %q", i, optString(e.Principal), e.Ref, optString(e.Exception))
		org, err := EnterOrganization(ctx, s.Reader(), e.Ref, p, optString(e.Exception))
		checkEntry(t, name, org.ID, err, e.OrganizationID, e.Error)
	}
	for _, c := range v.ScopeChecks {
		err := RefuseIfIncidentFrozen(ctx, s.Reader(), c.OrganizationID, optString(c.Exception))
		checkEntry(t, fmt.Sprintf("scope %s under %q", c.OrganizationID, optString(c.Exception)), "", err, "", c.Error)
	}
	for i, r := range v.Requests {
		p := v.principal(t, r.Principal)
		name := fmt.Sprintf("request #%d %s %s in %s under %q", i, r.Principal, r.Action, r.Ref, optString(r.Exception))
		org, err := EnterOrganization(ctx, s.Reader(), r.Ref, &p, optString(r.Exception))
		if err != nil {
			if r.Stage != "entry" {
				t.Errorf("%s: refused at entry (%v), TypeScript at %s", name, err, r.Stage)
				continue
			}
			checkEntry(t, name, "", err, "", r.Error)
			continue
		}
		if r.Stage != "decide" {
			t.Errorf("%s: entered, TypeScript refused at entry with %s", name, r.Error.Code)
			continue
		}
		d, err := Decide(ctx, s.Reader(), p, r.Action, Resource{OrganizationID: org.ID}, Options{HideExistence: true, RequestID: "req_vector"})
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed != r.Allowed {
			t.Errorf("%s: allowed %v, TypeScript %v", name, d.Allowed, r.Allowed)
			continue
		}
		if !d.Allowed {
			if g, w := errorValue(d.Err), wantError(t, r.Error); g != w {
				t.Errorf("%s: error\n got %s\nwant %s", name, g, w)
			}
		}
	}
}

func checkEntry(t *testing.T, name, gotOrg string, err error, wantOrg string, want *errorJSON) {
	t.Helper()
	if want == nil {
		if err != nil {
			t.Errorf("%s: %v, TypeScript passes", name, err)
		} else if gotOrg != wantOrg {
			t.Errorf("%s: Organization %s, TypeScript %s", name, gotOrg, wantOrg)
		}
		return
	}
	de := domainError(err)
	if de == nil {
		t.Errorf("%s: %v, TypeScript refuses with %s", name, err, want.Code)
		return
	}
	if g, w := errorValue(de), wantError(t, want); g != w {
		t.Errorf("%s:\n got %s\nwant %s", name, g, w)
	}
}

// authz/destination.ts, and Node's domainToASCII and isIP under it.
func TestDestinationVectors(t *testing.T) {
	v := loadVectors(t)
	for _, h := range v.DestinationHosts {
		got, ok := CanonicalizeHost(h.Input)
		if want := h.Canonical; (want == nil) == ok || (ok && got != *want) {
			t.Errorf("canonicalizeHost(%q) = %q, %v; TypeScript %v", h.Input, got, ok, optString(want))
		}
		if got := whatwg.DomainToASCII(h.Input); got != h.DomainToASCII {
			t.Errorf("domainToASCII(%q) = %q, Node %q", h.Input, got, h.DomainToASCII)
		}
		if got := whatwg.IsIP(h.Input); got != h.IsIP {
			t.Errorf("isIP(%q) = %d, Node %d", h.Input, got, h.IsIP)
		}
	}
	if len(v.DestinationLongHosts) != 15 {
		t.Fatalf("%d long host vectors, want 15", len(v.DestinationLongHosts))
	}
	for _, h := range v.DestinationLongHosts {
		input := longHost(h.Shape, h.Bytes)
		if len(input) != h.Bytes {
			t.Fatalf("%s %d: built %d bytes", h.Shape, h.Bytes, len(input))
		}
		canonical, ok := CanonicalizeHost(input)
		if (h.Canonical == nil) == ok || (ok && digestOf(canonical) != *h.Canonical) {
			t.Errorf("canonicalizeHost(%s of %d bytes): %d bytes, %v; TypeScript %+v", h.Shape, h.Bytes, len(canonical), ok, h.Canonical)
		}
		if got := digestOf(whatwg.DomainToASCII(input)); got != *h.DomainToASCII {
			t.Errorf("domainToASCII(%s of %d bytes): %d bytes, Node %d", h.Shape, h.Bytes, got.Length, h.DomainToASCII.Length)
		}
	}
	selectors := map[string]DestinationSelector{}
	for _, s := range v.DestinationSelectors {
		got, ok := ParseDestinationSelector(s.Input)
		if (s.Selector == nil) == ok {
			t.Errorf("parseDestinationSelector(%q) = %+v, %v; TypeScript %+v", s.Input, got, ok, s.Selector)
			continue
		}
		if !ok {
			continue
		}
		selectors[s.Input] = got
		if got.Host != s.Selector.Host || got.Wildcard != s.Selector.Wildcard || got.Port != s.Selector.Port {
			t.Errorf("parseDestinationSelector(%q) = %+v, TypeScript %+v", s.Input, got, *s.Selector)
		}
		if got.String() != *s.Formatted {
			t.Errorf("formatSelector(%q) = %q, TypeScript %q", s.Input, got.String(), *s.Formatted)
		}
	}
	for _, m := range v.DestinationMatches {
		sel, ok := selectors[m.Selector]
		if !ok {
			continue
		}
		if got := sel.Matches(Destination{Host: m.Host, Port: m.Port}); got != m.Matches {
			t.Errorf("destinationMatches(%q, %q:%d) = %v, TypeScript %v", m.Selector, m.Host, m.Port, got, m.Matches)
		}
	}
}
