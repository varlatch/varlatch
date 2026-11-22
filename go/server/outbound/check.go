// SPDX-License-Identifier: AGPL-3.0-or-later

package outbound

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
)

// The configured destinations check (net/outbound-check.ts; ADR-0057
// Decision 10): every live destination an Organization configured, with
// the policy's verdict and the allow list value that would open the
// refused ones. It reads only webhooks, platform_connections and
// oidc_bindings and the Organizations' slugs, and makes DNS lookups only,
// never an HTTP request: an OIDC issuer's jwks_uri is known only from its
// discovery document, so it is checked when it connects.

// Kind is a destination's kind.
type Kind string

// The kinds.
const (
	KindWebhook Kind = "webhook"
	KindCoolify Kind = "coolify"
	KindConvex  Kind = "convex"
	KindIssuer  Kind = "oidc-issuer"
)

// KindGitHub is a GitHub Sync Target's connection, whose destination is
// GitHub's API. Only `varlatchd admin outbound check` lists it
// (RunAdminCheck): the API's report keeps the four kinds it documents.
const KindGitHub Kind = "github"

var kindLabel = map[Kind]string{KindWebhook: "webhook", KindCoolify: "Coolify", KindConvex: "Convex", KindIssuer: "OIDC issuer", KindGitHub: "GitHub"}

// GitHubAPI is where every GitHub connection goes (githubapps.GitHubAPI).
const GitHubAPI = "https://api.github.com"

// githubDestinations are the live GitHub Sync Target connections (org:
// an Organization's id or slug, "" for all), each a destination at
// GitHubAPI.
func githubDestinations(ctx context.Context, db query.DBTX, org string) ([]row, error) {
	if db == nil {
		return nil, nil
	}
	filter, args := "", []any{}
	if org != "" {
		filter, args = " AND (o.id = ? OR o.slug = ?)", []any{org, org}
	}
	rs, err := db.QueryContext(ctx, `SELECT c.organization_id, o.slug, c.id, c.name FROM platform_connections c
		JOIN organizations o ON o.id = c.organization_id
		WHERE c.revoked_at IS NULL AND o.deleted_at IS NULL AND c.platform = 'github-actions'`+filter+`
		ORDER BY o.slug, c.created_at, c.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var rows []row
	for rs.Next() {
		r := row{kind: KindGitHub, name: new(string), url: GitHubAPI}
		if err := rs.Scan(&r.organizationID, &r.organization, &r.id, r.name); err != nil {
			return nil, err
		}
		rows = append(rows, r)
	}
	return rows, rs.Err()
}

// Checked is one configured destination and its verdict: "public",
// "allowed" (Entries open it), "refused" (Reason) or "unresolved" (Error,
// the resolver's code).
type Checked struct {
	Organization   string   `json:"organization"`
	OrganizationID string   `json:"organizationId"`
	Kind           Kind     `json:"kind"`
	ID             string   `json:"id"`
	Name           *string  `json:"name"`
	Scheme         string   `json:"scheme"` // "https" or "http"
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Addresses      []string `json:"addresses"`
	Verdict        string   `json:"verdict"`
	Entries        []string `json:"entries,omitempty"`
	Reason         Reason   `json:"reason,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// Apart is a refusal no name entry fixes, with why.
type Apart struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Kind Kind   `json:"kind"`
	ID   string `json:"id"`
	Why  string `json:"why"`
}

// Report is OutboundCheckReport. ExitCode is 0 when everything is
// allowed, 1 when something is refused, 2 when nothing is refused but
// something did not resolve.
type Report struct {
	CheckedAt    string    `json:"checkedAt"`
	Allow        []string  `json:"allow"`
	Destinations []Checked `json:"destinations"`
	Suggested    *string   `json:"suggested"`
	Apart        []Apart   `json:"apart"`
	ExitCode     int       `json:"exitCode"`
}

type row struct {
	organizationID, organization string
	kind                         Kind
	id                           string
	name                         *string
	url                          string
}

func liveDestinations(ctx context.Context, db query.DBTX, org string) ([]row, error) {
	if db == nil {
		return nil, nil
	}
	filter, args := "", []any{}
	if org != "" {
		filter, args = " AND (o.id = ? OR o.slug = ?)", []any{org, org}
	}
	var rows []row
	scan := func(q string, k func(*row, []any) []any) error {
		rs, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var r row
			if err := rs.Scan(k(&r, nil)...); err != nil {
				return err
			}
			rows = append(rows, r)
		}
		return rs.Err()
	}
	if err := scan(`SELECT w.organization_id, o.slug, w.id, w.url FROM webhooks w JOIN organizations o ON o.id = w.organization_id
		WHERE w.revoked_at IS NULL AND o.deleted_at IS NULL`+filter+` ORDER BY o.slug, w.created_at, w.id`, func(r *row, _ []any) []any {
		r.kind = KindWebhook
		return []any{&r.organizationID, &r.organization, &r.id, &r.url}
	}); err != nil {
		return nil, err
	}
	if err := scan(`SELECT c.organization_id, o.slug, c.id, c.name, c.platform, c.base_identity FROM platform_connections c
		JOIN organizations o ON o.id = c.organization_id
		WHERE c.revoked_at IS NULL AND o.deleted_at IS NULL AND c.platform IN ('coolify', 'convex')`+filter+`
		ORDER BY o.slug, c.created_at, c.id`, func(r *row, _ []any) []any {
		r.name = new(string)
		return []any{&r.organizationID, &r.organization, &r.id, r.name, (*string)(&r.kind), &r.url}
	}); err != nil {
		return nil, err
	}
	if err := scan(`SELECT b.organization_id, o.slug, b.id, b.issuer FROM oidc_bindings b JOIN organizations o ON o.id = b.organization_id
		WHERE b.revoked_at IS NULL AND o.deleted_at IS NULL`+filter+` ORDER BY o.slug, b.created_at, b.id`, func(r *row, _ []any) []any {
		r.kind = KindIssuer
		return []any{&r.organizationID, &r.organization, &r.id, &r.url}
	}); err != nil {
		return nil, err
	}
	return rows, nil
}

func (p *Policy) checkRow(ctx context.Context, r row, lookup Resolver) (*Checked, error) {
	u, ok := whatwg.ParseURL(r.url)
	if !ok || u.Protocol != "https:" && u.Protocol != "http:" {
		return nil, nil
	}
	c, err := p.CheckURL(ctx, u, lookup)
	if err != nil {
		return nil, err
	}
	d := Checked{
		Organization: r.organization, OrganizationID: r.organizationID, Kind: r.kind, ID: r.id, Name: r.name,
		Scheme: strings.TrimSuffix(c.Destination.Scheme, ":"), Host: c.Destination.Host, Port: c.Destination.Port, Addresses: c.Addresses,
	}
	switch {
	case c.Outcome == "unresolved":
		d.Verdict, d.Error = "unresolved", c.Error
	case c.Verdict.Allowed && c.Verdict.Via == "public":
		d.Verdict = "public"
	case c.Verdict.Allowed:
		d.Verdict, d.Entries = "allowed", c.Verdict.Entries
	default:
		d.Verdict, d.Reason = "refused", c.Verdict.Reason
	}
	return &d, nil
}

// Bounding the DNS work: the check runs from the operator's terminal, and
// from two dashboard pages anyone with the authority may load as often as
// they like. Every lookup in the process takes one of LookupSlots;
// concurrent lookups of one name with one policy share one; within a
// scan a name is resolved once; and the pages' scans (SharedCheck) are
// shared while running and reused for ScanTTL.

// LookupSlots is how many lookups run at once in this process.
const LookupSlots = 8

var lookupSlots = make(chan struct{}, LookupSlots)

type flight struct {
	done    chan struct{}
	answers []Answer
	err     error
}

type lookups struct {
	mu       sync.Mutex
	inFlight map[string]*flight
}

// sharedLookup is one lookup per policy and name at a time, within the
// process-wide slots.
func (p *Policy) sharedLookup(ctx context.Context, name string) ([]Answer, error) {
	p.lookups.mu.Lock()
	if p.lookups.inFlight == nil {
		p.lookups.inFlight = map[string]*flight{}
	}
	f, running := p.lookups.inFlight[name]
	if !running {
		f = &flight{done: make(chan struct{})}
		p.lookups.inFlight[name] = f
	}
	p.lookups.mu.Unlock()
	if !running {
		go func() {
			defer close(f.done)
			lookupSlots <- struct{}{}
			defer func() { <-lookupSlots }()
			// Not the caller's cancellation (others share it), but the
			// lookup's own deadline (Lookup).
			f.answers, f.err = p.Lookup(context.WithoutCancel(ctx), name)
			p.lookups.mu.Lock()
			if p.lookups.inFlight[name] == f {
				delete(p.lookups.inFlight, name)
			}
			p.lookups.mu.Unlock()
		}()
	}
	select {
	case <-f.done:
		return f.answers, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// rowsAtOnce is how many rows one scan checks at once.
const rowsAtOnce = 8

// RunCheck is outboundCheck: DNS lookups and the policy's decisions, for
// every live destination (org: an Organization's id or slug, "" for all).
func (p *Policy) RunCheck(ctx context.Context, db query.DBTX, org string, now func() time.Time) (Report, error) {
	rows, err := liveDestinations(ctx, db, org)
	if err != nil {
		return Report{}, err
	}
	return p.scan(ctx, rows, now)
}

// RunAdminCheck is RunCheck with the GitHub Sync Targets' connections
// too, after the others, in the same scan (GitHub's API resolved once, and
// in the suggestion when refused): `varlatchd admin outbound check` lists
// them, the API's report keeps the kinds it documents.
func (p *Policy) RunAdminCheck(ctx context.Context, db query.DBTX, org string, now func() time.Time) (Report, error) {
	rows, err := liveDestinations(ctx, db, org)
	if err != nil {
		return Report{}, err
	}
	github, err := githubDestinations(ctx, db, org)
	if err != nil {
		return Report{}, err
	}
	return p.scan(ctx, append(rows, github...), now)
}

// scan checks the rows and makes the report: verdicts in the rows' order,
// the suggestion, what is left apart, and the exit code.
func (p *Policy) scan(ctx context.Context, rows []row, now func() time.Time) (Report, error) {
	// Each name once per scan, however many rows point at it.
	var mu sync.Mutex
	resolved := map[string]*flight{}
	lookup := func(ctx context.Context, name string) ([]Answer, error) {
		mu.Lock()
		f, ok := resolved[name]
		if !ok {
			f = &flight{done: make(chan struct{})}
			resolved[name] = f
		}
		mu.Unlock()
		if !ok {
			f.answers, f.err = p.sharedLookup(ctx, name)
			close(f.done)
		}
		<-f.done
		return f.answers, f.err
	}
	checked := make([]*Checked, len(rows))
	errs := make([]error, len(rows))
	var next sync.Mutex
	i := 0
	var wg sync.WaitGroup
	for range min(rowsAtOnce, len(rows)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				next.Lock()
				index := i
				i++
				next.Unlock()
				if index >= len(rows) {
					return
				}
				checked[index], errs[index] = p.checkRow(ctx, rows[index], lookup)
			}
		}()
	}
	wg.Wait()
	r := Report{CheckedAt: iso(now()), Allow: []string{}, Destinations: []Checked{}, Apart: []Apart{}}
	for i, c := range checked {
		if errs[i] != nil {
			return Report{}, errs[i]
		}
		if c != nil {
			r.Destinations = append(r.Destinations, *c)
		}
	}
	var suggestions []string
	for _, d := range r.Destinations {
		if d.Verdict != "refused" {
			continue
		}
		portSuffix := ""
		if d.Port != DefaultPort(d.Scheme+":") {
			portSuffix = ":" + strconv.Itoa(d.Port)
		}
		classes := make([]Class, len(d.Addresses))
		for i, a := range d.Addresses {
			if c, ok := ClassOf(a); ok {
				classes[i] = c
			} else {
				classes[i] = Never
			}
		}
		switch {
		case whatwg.IsIP(d.Host) != 0:
			why := "a literal address of a class that is never allowed"
			if cls := classes[0]; cls != Never {
				entry := d.Host + "/32"
				if strings.Contains(d.Host, ":") {
					entry = "[" + d.Host + "/128]"
				}
				why = fmt.Sprintf("a literal %s address: only a CIDR entry opens it, such as %s%s; add one only if every Organization may reach it", cls, entry, portSuffix)
			}
			r.Apart = append(r.Apart, Apart{d.Host, d.Port, d.Kind, d.ID, why})
		case slices.ContainsFunc(classes, func(c Class) bool { return c == HostOnly || c == Never }):
			r.Apart = append(r.Apart, Apart{d.Host, d.Port, d.Kind, d.ID, "resolves to a loopback, link-local, metadata or reserved address, which a hostname entry never opens"})
		default:
			if s := d.Host + portSuffix; !slices.Contains(suggestions, s) {
				suggestions = append(suggestions, s)
			}
		}
	}
	for _, e := range p.Entries {
		r.Allow = append(r.Allow, e.Text)
	}
	var added []string
	for _, s := range suggestions {
		if !slices.Contains(r.Allow, s) {
			added = append(added, s)
		}
	}
	if len(added) > 0 {
		s := strings.Join(append(slices.Clone(r.Allow), added...), ",")
		r.Suggested = &s
	}
	refused := slices.ContainsFunc(r.Destinations, func(d Checked) bool { return d.Verdict == "refused" })
	unresolved := slices.ContainsFunc(r.Destinations, func(d Checked) bool { return d.Verdict == "unresolved" })
	switch {
	case refused:
		r.ExitCode = 1
	case unresolved:
		r.ExitCode = 2
	}
	return r, nil
}

// ScanTTL is how long a page's scan is reused; MaxScans how many are kept
// per policy.
const (
	ScanTTL  = 30 * time.Second
	MaxScans = 1000
)

type scan struct {
	at     time.Time // zero while it runs
	done   chan struct{}
	report Report
	err    error
}

type scans struct {
	mu    sync.Mutex
	kept  map[string]*scan
	order []string
}

// SharedCheck is sharedOutboundCheck, for the dashboard's pages: a scan
// already running for the same policy and Organization (or the whole
// installation) is shared, and a finished one is reused for ScanTTL. A
// failed scan is never kept.
func (p *Policy) SharedCheck(ctx context.Context, db query.DBTX, org string, now func() time.Time) (Report, error) {
	s := &p.scans
	s.mu.Lock()
	if s.kept == nil {
		s.kept = map[string]*scan{}
	}
	t := now()
	if hit, ok := s.kept[org]; ok && (hit.at.IsZero() || t.Sub(hit.at) < ScanTTL) {
		s.mu.Unlock()
		<-hit.done
		return hit.report, hit.err
	}
	for k, sc := range s.kept {
		if !sc.at.IsZero() && t.Sub(sc.at) >= ScanTTL {
			s.forget(k)
		}
	}
	for len(s.kept) >= MaxScans {
		s.forget(s.order[0])
	}
	sc := &scan{done: make(chan struct{})}
	s.kept[org] = sc
	s.order = append(s.order, org)
	s.mu.Unlock()
	sc.report, sc.err = p.RunCheck(context.WithoutCancel(ctx), db, org, now)
	s.mu.Lock()
	if sc.err != nil {
		if s.kept[org] == sc {
			s.forget(org)
		}
	} else {
		sc.at = now()
	}
	s.mu.Unlock()
	close(sc.done)
	return sc.report, sc.err
}

func (s *scans) forget(k string) {
	delete(s.kept, k)
	if i := slices.Index(s.order, k); i >= 0 {
		s.order = slices.Delete(s.order, i, i+1)
	}
}

// RefusedView is a refused destination as the API shows it: never the
// resolved addresses. NotSuggested is why the suggested allow list leaves
// it out, nil when it covers it.
type RefusedView struct {
	Checked
	NotSuggested *string
}

// Refused is refusedDestinations: the report's refused destinations.
func (r Report) Refused() []RefusedView {
	out := []RefusedView{}
	for _, d := range r.Destinations {
		if d.Verdict != "refused" || d.Reason == "" {
			continue
		}
		v := RefusedView{Checked: d}
		for _, a := range r.Apart {
			if a.Kind == d.Kind && a.ID == d.ID {
				why := a.Why
				v.NotSuggested = &why
				break
			}
		}
		out = append(out, v)
	}
	return out
}

// Setting is how a report names the allow list's setting: its label, and
// the lines that suggest a value.
type Setting struct {
	Name    string
	Suggest func(value string) []string
}

// TypeScriptSetting is the TypeScript server's: VARLATCH_OUTBOUND_ALLOW in
// its environment.
var TypeScriptSetting = Setting{Name: "VARLATCH_OUTBOUND_ALLOW", Suggest: func(v string) []string {
	return []string{"Suggested (then restart varlatchd):", "  VARLATCH_OUTBOUND_ALLOW=" + v}
}}

// Lines is outboundCheckLines: the report for a person, as the TypeScript
// server words it.
func (r Report) Lines() []string { return r.LinesFor(TypeScriptSetting) }

// LinesFor is the report for a person, the setting named as s says.
func (r Report) LinesFor(s Setting) []string {
	allow := "(not set)"
	if len(r.Allow) > 0 {
		allow = strings.Join(r.Allow, ",")
	}
	lines := []string{s.Name + ": " + allow, ""}
	if len(r.Destinations) == 0 {
		lines = append(lines, "No destinations configured.")
	}
	for _, d := range r.Destinations {
		verdict := ""
		switch d.Verdict {
		case "public":
			verdict = "public"
		case "allowed":
			verdict = "allowed by " + strings.Join(d.Entries, ", ")
		case "refused":
			verdict = "REFUSED (" + string(d.Reason) + ")"
		default:
			verdict = "not resolved (" + d.Error + ")"
		}
		name := ""
		if d.Name != nil && *d.Name != "" {
			name = ` "` + *d.Name + `"`
		}
		addresses := strings.Join(d.Addresses, ", ")
		if addresses == "" {
			addresses = "-"
		}
		lines = append(lines, fmt.Sprintf("%s  %s  %s%s  %s://%s:%d  [%s]  %s", d.Organization, kindLabel[d.Kind], d.ID, name, d.Scheme, d.Host, d.Port, addresses, verdict))
	}
	if r.Suggested != nil {
		lines = append(lines, "")
		lines = append(lines, s.Suggest(*r.Suggested)...)
	}
	if len(r.Apart) > 0 {
		lines = append(lines, "", "Not suggested, decide yourself:")
		for _, a := range r.Apart {
			lines = append(lines, fmt.Sprintf("  %s:%d (%s %s): %s", a.Host, a.Port, kindLabel[a.Kind], a.ID, a.Why))
		}
	}
	if r.ExitCode == 0 && len(r.Destinations) > 0 {
		lines = append(lines, "", "Every destination is allowed.")
	}
	return lines
}

func iso(t time.Time) string { return audit.ISOTime(t.UnixMicro()) }
