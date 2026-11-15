// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"database/sql"
	"encoding/base64"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/contracts"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/projects"
)

// The cross-project Config Item name search (ADR-0030, capability
// search.items; ADR-0059 step 4.1d), as http/app.ts serves it. Names only:
// values never take part in matching or in the answer. The candidate
// environments are those the caller may read metadata of, decided before
// matching, so a hit it may not see is indistinguishable from no hit.

const (
	searchPattern = "GET /v1/organizations/{org}/config-items"
	searchRoute   = "/v1/organizations/:org/config-items"
	// maxSearchEnvironments is MAX_ENVIRONMENTS: a hit lists at most so many.
	maxSearchEnvironments = 50
)

func init() { readsItself[searchPattern] = true }

func (r reply) VisitSearchConfigItemsResponse(w http.ResponseWriter) error { return r.visit(w) }

func invalidSearch(message string) error { return domainerr.New("VALIDATION_FAILED", message) }

// SearchConfigItems is GET …/config-items?q=&limit=&cursor=.
func (o *operations) SearchConfigItems(ctx context.Context, _ api.SearchConfigItemsRequestObject) (api.SearchConfigItemsResponseObject, error) {
	q, err := o.enterRoute(ctx, searchRoute, "")
	if err != nil {
		return nil, err
	}
	if q.p.Identity.Kind != "human" && (q.p.Identity.OrganizationID == nil || *q.p.Identity.OrganizationID != q.org.ID) {
		return nil, domainerr.New("RESOURCE_NOT_FOUND", "Organization not found")
	}
	query1 := func(name string) (string, bool) {
		v, ok := rawOf(ctx).query[name]
		if !ok {
			return "", false
		}
		return v[0], true
	}
	needle, _ := query1("q")
	if needle == "" || len(utf16.Encode([]rune(needle))) > 256 {
		return nil, invalidSearch("q is required (1-256 characters); an empty query never lists all")
	}
	limit := 20
	if raw, ok := query1("limit"); ok {
		n := jsToNumber(raw)
		if n != math.Trunc(n) || math.IsInf(n, 0) || n < 1 || n > 100 {
			return nil, invalidSearch("limit must be an integer in 1..100")
		}
		limit = int(n)
	}
	var after []string
	if raw, ok := query1("cursor"); ok {
		if after = decodeCursor(raw); len(after) != 3 {
			return nil, invalidSearch("Invalid cursor")
		}
	}

	reader := o.s.opts.Auth.Store().Reader()
	role := ""
	if q.p.Identity.Kind == "human" {
		if role, err = authz.OrgRole(ctx, reader, q.org.ID, q.p.Identity.ID); err != nil {
			return nil, err
		}
	}
	grants, err := authz.LoadGrants(ctx, reader, q.org.ID, q.p.Identity.ID)
	if err != nil {
		return nil, err
	}
	if q.p.Identity.Kind == "human" && role == "" && len(grants) == 0 {
		// Zero visibility: not found (anti-enumeration, ADR-0018 section 11).
		return nil, domainerr.New("RESOURCE_NOT_FOUND", "Organization not found")
	}
	db := query.New(reader)
	envs, err := db.SearchEnvironments(ctx, query.SearchEnvironmentsParams{OrganizationID: q.org.ID, Now: sql.NullInt64{Int64: o.s.opts.Now().UnixMicro(), Valid: true}})
	if err != nil {
		return nil, err
	}
	// config.metadata.read is not tailnet-constrained: no Requirements.
	var eligible []query.SearchEnvironmentsRow
	for _, e := range envs {
		root := e.ID
		if e.ParentEnvironmentID.Valid {
			root = e.ParentEnvironmentID.String
		}
		if authz.Evaluate(authz.Input{
			Action: "config.metadata.read", OrgRole: role, Grants: grants,
			Resource: authz.Resource{OrganizationID: q.org.ID, ProjectID: e.ProjectID, Environment: &authz.Environment{ID: e.ID, RootID: root, Tier: e.Tier}},
		}).Allowed {
			eligible = append(eligible, e)
		}
	}
	// Effective presence (ADR-0030 section 3): a live value in the
	// environment or inherited from its parent.
	seen := map[string]bool{}
	var ids []string
	for _, e := range eligible {
		for _, id := range []string{e.ID, e.ParentEnvironmentID.String} {
			if id != "" && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	namesByEnv := map[string][]string{}
	if len(ids) > 0 {
		rows, err := db.LiveItemNamesOf(ctx, ids)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			namesByEnv[r.EnvironmentID] = append(namesByEnv[r.EnvironmentID], r.ItemName)
		}
	}
	// A literal case-insensitive substring: toLowerCase on both sides.
	lowered := jsLower(needle)
	type hit struct {
		projectID, projectSlug, projectName, name string
		envs                                      []query.SearchEnvironmentsRow
	}
	hits := map[string]*hit{}
	var order []*hit
	for _, e := range eligible {
		effective := map[string]bool{}
		var names []string
		for _, n := range append(append([]string{}, namesByEnv[e.ID]...), namesByEnv[e.ParentEnvironmentID.String]...) {
			if !effective[n] {
				effective[n] = true
				names = append(names, n)
			}
		}
		for _, n := range names {
			if !strings.Contains(jsLower(n), lowered) {
				continue
			}
			key := e.ProjectID + "\x00" + n
			h, ok := hits[key]
			if !ok {
				h = &hit{projectID: e.ProjectID, projectSlug: e.ProjectSlug, projectName: e.ProjectName, name: n}
				hits[key] = h
				order = append(order, h)
			}
			h.envs = append(h.envs, e)
		}
	}
	// Ordered by project slug, the exact item name, then the project's
	// id, as JavaScript compares strings.
	tuple := func(h *hit) []string { return []string{h.projectSlug, h.name, h.projectID} }
	lt := func(a, b []string) bool {
		for i := range 3 {
			if a[i] != b[i] {
				return jsLess(a[i], b[i])
			}
		}
		return false
	}
	sortStable(order, func(a, b *hit) bool { return lt(tuple(a), tuple(b)) })
	if after != nil {
		var kept []*hit
		for _, h := range order {
			if lt(after, tuple(h)) {
				kept = append(kept, h)
			}
		}
		order = kept
	}
	page := order
	if len(page) > limit {
		page = page[:limit]
	}
	var next any
	if len(order) > limit && len(page) > 0 {
		next = encodeCursor(tuple(page[len(page)-1]))
	}
	// Sensitivity from each Project's active Contract; an item it does not
	// name is sensitive.
	sensitive := map[string]func(string) bool{}
	for _, h := range page {
		if _, ok := sensitive[h.projectID]; ok {
			continue
		}
		project, err := projects.Get(ctx, reader, q.org.ID, h.projectID)
		if err != nil {
			return nil, err
		}
		active, err := contracts.Active(ctx, reader, project.ID, project.ActiveContractRevisionID)
		if err != nil {
			return nil, err
		}
		sensitive[h.projectID] = func(name string) bool {
			if active == nil {
				return true
			}
			for _, it := range active.Items {
				if it.Name == name {
					return it.Sensitive
				}
			}
			return true
		}
	}
	items := make([]any, 0, len(page))
	for _, h := range page {
		envs := make([]any, 0, min(len(h.envs), maxSearchEnvironments))
		for _, e := range h.envs[:min(len(h.envs), maxSearchEnvironments)] {
			envs = append(envs, jsvalue.Object{{Key: "id", Value: e.ID}, {Key: "name", Value: e.Name}, {Key: "tier", Value: e.Tier}})
		}
		item := jsvalue.Object{
			{Key: "project", Value: jsvalue.Object{{Key: "id", Value: h.projectID}, {Key: "slug", Value: h.projectSlug}, {Key: "name", Value: h.projectName}}},
			{Key: "name", Value: h.name}, {Key: "sensitive", Value: sensitive[h.projectID](h.name)}, {Key: "environments", Value: envs},
		}
		if len(h.envs) > maxSearchEnvironments {
			item = append(item, jsvalue.Member{Key: "environmentsTruncated", Value: true})
		}
		items = append(items, item)
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "items", Value: items}, {Key: "nextCursor", Value: next}}), nil
}

// sortStable is a stable insertion-merge sort by less (sort.SliceStable on
// a typed slice).
func sortStable[T any](s []T, less func(a, b T) bool) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && less(s[j], s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// jsLess is JavaScript's a < b on strings: by UTF-16 code units.
func jsLess(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// jsLower is String.prototype.toLowerCase.
func jsLower(s string) string { return whatwg.ToLower(s) }

// jsWhitespace is StrWhiteSpaceChar: ECMAScript's WhiteSpace and
// LineTerminator code points, which Number(string) trims.
func jsWhitespace(r rune) bool {
	switch r {
	case '\t', '\v', '\f', ' ', 0xA0, 0xFEFF, '\n', '\r', 0x2028, 0x2029:
		return true
	}
	return unicode.Is(unicode.Zs, r)
}

var (
	jsDecimal = regexp.MustCompile(`^[+-]?(?:Infinity|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)$`)
	jsRadix   = regexp.MustCompile(`^0(?:[xX][0-9a-fA-F]+|[oO][0-7]+|[bB][01]+)$`)
)

// jsToNumber is Number(string) (StringToNumber): whitespace trimmed, empty
// is 0, a decimal literal with an optional sign or Infinity, or an
// unsigned 0x, 0o or 0b integer; anything else is NaN.
func jsToNumber(s string) float64 {
	t := strings.TrimFunc(s, jsWhitespace)
	switch {
	case t == "":
		return 0
	case jsRadix.MatchString(t):
		base := map[byte]int{'x': 16, 'X': 16, 'o': 8, 'O': 8, 'b': 2, 'B': 2}[t[1]]
		n := 0.0
		for _, c := range t[2:] {
			d, _ := strconv.ParseInt(string(c), base, 64)
			n = n*float64(base) + float64(d)
		}
		return n
	case jsDecimal.MatchString(t):
		if strings.HasSuffix(t, "Infinity") {
			if t[0] == '-' {
				return math.Inf(-1)
			}
			return math.Inf(1)
		}
		// Beyond a double's range: ±Inf, or 0 below its smallest.
		f, _ := strconv.ParseFloat(t, 64)
		return f
	}
	return math.NaN()
}

// decodeCursor is decodeCursor (http/support.ts): Buffer.from(cursor,
// "base64url") (lenient: either alphabet, other characters skipped, the
// first "=" ends it), the bytes as UTF-8, JSON.parse, and an array of
// strings; nil otherwise.
func decodeCursor(cursor string) []string {
	var b strings.Builder
scan:
	for _, c := range cursor {
		switch {
		case c == '=':
			break scan
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			b.WriteRune(c)
		case c == '+':
			b.WriteByte('-')
		case c == '/':
			b.WriteByte('_')
		}
	}
	text := b.String()
	if len(text)%4 == 1 {
		text = text[:len(text)-1]
	}
	raw, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return nil
	}
	v, err := jsvalue.Parse(raw)
	if err != nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, len(list))
	for i, e := range list {
		s, ok := e.(string)
		if !ok {
			return nil
		}
		out[i] = s
	}
	return out
}

// encodeCursor is encodeCursor: the parts as JSON, base64url, unpadded.
func encodeCursor(parts []string) string {
	list := make([]any, len(parts))
	for i, p := range parts {
		list[i] = p
	}
	return base64.RawURLEncoding.EncodeToString(jsvalue.Stringify(list))
}
