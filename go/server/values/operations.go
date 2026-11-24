// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// purposeIssue is zod's message for a purpose outside DISCLOSURE_PURPOSES.
const purposeIssue = `Invalid option: expected one of "scan"|"export"`

// EffectiveConfiguration is GET …/effective-configuration: every resolved
// item's metadata, and with include=values the non-sensitive values the
// caller may read (never a Secret: those need the disclosure operation),
// audited as value.disclosed before they are decrypted. purpose is the
// query's purpose (nil when absent).
func (s *Service) EffectiveConfiguration(ctx context.Context, req Request, includeValues bool, purpose *string) (jsvalue.Object, error) {
	if purpose != nil && *purpose != "scan" && *purpose != "export" {
		return nil, domainerr.New("VALIDATION_FAILED", "(root): "+purposeIssue)
	}
	t := &tracker{}
	var st State
	var denied, plain *authz.Decision
	err := s.snapshot(ctx, func(tx *sql.Tx, now int64) error {
		var err error
		if st, err = scope(ctx, tx, req); err != nil {
			return err
		}
		readHook(ctx, "after the scope, before authorization")
		r := st.resource()
		metadata, err := t.decide(ctx, tx, req, "config.metadata.read", r, true)
		if err != nil {
			return err
		}
		if !metadata.Allowed {
			denied = &metadata
			return nil
		}
		if includeValues {
			d, err := t.decide(ctx, tx, req, "config.value.read", r, false)
			if err != nil {
				return err
			}
			plain = &d
		}
		if err := capture(ctx, tx, &st, now, func(it Item) bool { return !it.Sensitive && plain != nil && plain.Allowed }); err != nil {
			return err
		}
		if plain != nil && !plain.Allowed && strings.HasPrefix(plain.Err.Code, "TAILNET_") {
			denied = plain
			return nil
		}
		return t.requireAccess(ctx, tx, req, st.Org.ID, now)
	})
	if err != nil {
		return nil, s.refused(ctx, req, t, err)
	}
	if denied != nil {
		return nil, s.reject(ctx, *denied)
	}
	if plain != nil && !plain.Allowed {
		if err := s.recordDenial(ctx, *plain); err != nil {
			return nil, err
		}
	}
	if err := st.expired(); err != nil {
		return nil, err
	}
	readable := func(sensitive bool) bool { return !sensitive && plain != nil && plain.Allowed }

	items := make([]any, 0, len(st.Items))
	unexpanded := []any{}
	// What is listed: the seeds of one-time codes too, whose value is always
	// null here.
	all := st.all()
	if !includeValues {
		for _, it := range all {
			o := jsvalue.Object{{Key: "name", Value: it.Name}, {Key: "sensitive", Value: it.Sensitive}, {Key: "source", Value: it.Source}, {Key: "versionId", Value: it.VersionID}, {Key: "value", Value: nil}}
			if it.RetiringVersionID != "" {
				o = append(o, jsvalue.Member{Key: "rotating", Value: true})
			}
			items = append(items, withCode(o, it))
		}
	} else {
		var disclosed []string
		var versions []string
		for _, it := range st.Items {
			if readable(it.Sensitive) {
				disclosed = append(disclosed, it.Name+"@"+it.VersionID)
				versions = append(versions, it.VersionID)
			}
		}
		md := jsvalue.Object{{Key: "items", Value: strings.Join(disclosed, ",")}, {Key: "withheld", Value: len(st.Items) - len(disclosed)}}
		if purpose != nil {
			md = append(md, jsvalue.Member{Key: "purpose", Value: *purpose})
		}
		plaintext, err := s.auditThenDecrypt(ctx, &st, []audit.Event{{
			Type: "value.disclosed", Decision: audit.Allow, ActorIdentityID: ptr(req.Principal.Identity.ID),
			OrganizationID: ptr(st.Org.ID), Action: ptr("config.value.read"), Resource: resourceOf(&st),
			Authz: allowedAuthz(plain), RequestID: ptr(req.RequestID), Metadata: md,
		}}, versions, nil)
		if err != nil {
			return nil, err
		}
		type result struct {
			o     jsvalue.Object
			value *string
		}
		results := make([]result, 0, len(all))
		lookup := map[string]string{}
		for _, it := range all {
			var value *string
			if v, ok := plaintext[it.VersionID]; ok {
				value = &v
				lookup[it.Name] = v
			}
			o := jsvalue.Object{{Key: "name", Value: it.Name}, {Key: "sensitive", Value: it.Sensitive}, {Key: "source", Value: it.Source}, {Key: "versionId", Value: it.VersionID}, {Key: "value", Value: nil}}
			results = append(results, result{o: o, value: value})
		}
		for i, it := range all {
			r := results[i]
			if r.value != nil {
				literal := literalSet{}
				expanded, err := ExpandReferences(*r.value, func(n string) (string, bool) { v, ok := lookup[n]; return v, ok }, literal.add)
				if err != nil {
					return nil, err
				}
				if len(literal) > 0 {
					unexpanded = append(unexpanded, jsvalue.Object{{Key: "name", Value: it.Name}, {Key: "references", Value: literal.sorted()}})
				}
				r.o[4].Value = expanded
				if expanded != *r.value {
					r.o = append(r.o, jsvalue.Member{Key: "rawValue", Value: *r.value})
				}
			}
			if it.RetiringVersionID != "" {
				r.o = append(r.o, jsvalue.Member{Key: "rotating", Value: true})
			}
			items = append(items, withCode(r.o, it))
		}
	}
	withheld := []any{}
	if plain != nil && !plain.Allowed {
		reason := "permission"
		if strings.HasPrefix(plain.Err.Code, "TAILNET_") {
			reason = "requirement"
		}
		for _, it := range st.Items {
			if !it.Sensitive {
				withheld = append(withheld, jsvalue.Object{{Key: "name", Value: it.Name}, {Key: "requires", Value: "config.value.read"}, {Key: "reason", Value: reason}})
			}
		}
	}
	manifest, digest, err := st.Manifest()
	if err != nil {
		return nil, err
	}
	s.settle(t)
	return jsvalue.Object{
		{Key: "environmentId", Value: st.Env.ID},
		{Key: "items", Value: items},
		{Key: "manifest", Value: manifest},
		{Key: "stateDigest", Value: digest},
		{Key: "callerView", Value: jsvalue.Object{{Key: "withheld", Value: withheld}, {Key: "unexpanded", Value: unexpanded}}},
	}, nil
}

// disclosureRequest is the body as zod leaves it.
type disclosureRequest struct {
	items   []string // nil for the all-authorized scope
	all     bool
	purpose string // "" when none was declared
	// seeds is whether the request asks for the seeds among items (ADR-0061).
	// Without it a seed is withheld, so whoever asks for every Secret by
	// name, as clients do, is not given one.
	seeds bool
}

// Disclose is POST …/disclosures: the Secrets the request names, or every
// one it may reveal, each audited as secret.disclosed, and committed,
// before any is decrypted; reference expansion pulls non-sensitive values
// in only for a caller who may read them, one audited level at a time.
// body is the request body as sent; it is parsed only once authorization
// decided (readJson).
func (s *Service) Disclose(ctx context.Context, req Request, body []byte) (jsvalue.Object, error) {
	t := &tracker{}
	var st State
	var denied, reveal, plain, metadata *authz.Decision
	var dr disclosureRequest
	var attempts []WouldBlock
	enforce := false
	err := s.snapshot(ctx, func(tx *sql.Tx, now int64) error {
		var err error
		if st, err = scope(ctx, tx, req); err != nil {
			return err
		}
		r := st.resource()
		d, err := t.decide(ctx, tx, req, "secret.reveal", r, true)
		if err != nil {
			return err
		}
		if !d.Allowed {
			denied = &d
			return nil
		}
		reveal = &d
		if dr, err = parseDisclosure(body); err != nil {
			return err
		}
		p, err := t.decide(ctx, tx, req, "config.value.read", r, false)
		if err != nil {
			return err
		}
		plain = &p
		m, err := t.decide(ctx, tx, req, "config.metadata.read", r, false)
		if err != nil {
			return err
		}
		metadata = &m
		requested := map[string]bool{}
		for _, n := range dr.items {
			requested[n] = true
		}
		st.wantsCode = func(it Item) bool { return dr.seeds && requested[it.Name] }
		if err := capture(ctx, tx, &st, now, func(it Item) bool {
			if it.Sensitive {
				return dr.all || requested[it.Name]
			}
			return plain.Allowed
		}); err != nil {
			return err
		}
		if dr.purpose == "export" {
			c, err := query.New(tx).ExportControl(ctx, st.Org.ID)
			switch {
			case errors.Is(err, sql.ErrNoRows):
			case err != nil:
				return err
			case c.Mode == "enforce":
				enforce = true
			case c.Mode == "report":
				reason := "no-approval"
				if req.Principal.Identity.Kind != "human" {
					reason = "machine-credential"
				}
				attempts = []WouldBlock{{Control: "admin-step-up", ConfigVersion: c.Version, Operation: "secret.export", ActorIdentityID: req.Principal.Identity.ID, Reason: reason}}
			}
		}
		if !plain.Allowed && strings.HasPrefix(plain.Err.Code, "TAILNET_") {
			denied = plain
			return nil
		}
		return t.requireAccess(ctx, tx, req, st.Org.ID, now)
	})
	if err != nil {
		return nil, s.refused(ctx, req, t, err)
	}
	if denied != nil {
		return nil, s.reject(ctx, *denied)
	}
	if !plain.Allowed {
		if err := s.recordDenial(ctx, *plain); err != nil {
			return nil, err
		}
	}
	if err := st.expired(); err != nil {
		return nil, err
	}

	// selectDisclosure.
	var selected, seeds []Item
	withheld := []any{}
	secrets := map[string]Item{}
	codes := map[string]Item{}
	for _, it := range st.Codes {
		codes[it.Name] = it
	}
	for _, it := range st.Items {
		if it.Sensitive {
			if dr.all {
				selected = append(selected, it)
			}
			secrets[it.Name] = it
		}
	}
	if !dr.all {
		for _, n := range dr.items {
			if it, ok := secrets[n]; ok {
				selected = append(selected, it)
			} else if it, ok := codes[n]; ok && dr.seeds {
				seeds = append(seeds, it)
			} else {
				withheld = append(withheld, n)
			}
		}
	}
	mode := "requested"
	if dr.all {
		mode = "all-authorized-secrets"
	}
	entries := make([]string, 0, len(selected)+len(seeds))
	var versions, seedVersions []string
	for _, it := range append(slices.Clone(selected), seeds...) {
		to := &versions
		if it.Code != nil {
			to = &seedVersions
		}
		if it.RetiringVersionID != "" {
			entries = append(entries, it.Name+"@"+it.VersionID+"+"+it.RetiringVersionID)
			*to = append(*to, it.VersionID, it.RetiringVersionID)
		} else {
			entries = append(entries, it.Name+"@"+it.VersionID)
			*to = append(*to, it.VersionID)
		}
	}
	md := jsvalue.Object{{Key: "mode", Value: mode}, {Key: "items", Value: strings.Join(entries, ",")}, {Key: "withheld", Value: len(withheld)}}
	if dr.purpose != "" {
		md = append(md, jsvalue.Member{Key: "purpose", Value: dr.purpose})
	}
	if len(seeds) > 0 {
		md = append(md, jsvalue.Member{Key: "totpSeeds", Value: len(seeds)})
	}
	var before beforeAudit
	var gates []write.Gate
	if len(attempts) > 0 {
		at := st.Now
		before = func(ctx context.Context, tx *storage.Tx) (jsvalue.Object, error) {
			return nil, countWouldBlockInLiveOrganization(ctx, tx, st.Org.ID, attempts, at, s.now)
		}
	}
	if enforce {
		// Phase 2 of an export under enforce (export.go): the approval
		// consumed in the audit job, before anything is decrypted.
		if s.approvals == nil || s.gates == nil {
			return nil, errors.New("values: an export under admin-step-up's enforce needs the approvals and the gates")
		}
		before, gates = s.exportPhase2(req, &st, dr, selected)
	}
	disclosed := []audit.Event{{
		Type: "secret.disclosed", Decision: audit.Allow, ActorIdentityID: ptr(req.Principal.Identity.ID),
		OrganizationID: ptr(st.Org.ID), Action: ptr("secret.reveal"), Resource: resourceOf(&st),
		Authz: allowedAuthz(reveal), RequestID: ptr(req.RequestID), Metadata: md,
	}}
	var plaintext map[string]string
	if enforce {
		plaintext, err = security.WithApproval(ctx, s.approvals, auth.RequesterOf(req.Principal), func() (map[string]string, error) {
			return s.auditThenDecrypt(ctx, &st, disclosed, versions, before, gates...)
		})
		if err != nil {
			return nil, s.phase2Refused(ctx, req, t, err)
		}
	} else {
		plaintext, err = s.auditThenDecrypt(ctx, &st, disclosed, versions, before)
	}
	if err != nil {
		return nil, err
	}

	type out struct {
		item     Item
		value    string
		retiring *string
	}
	results := make([]out, 0, len(selected))
	lookup := map[string]string{}
	var order []string // lookup's insertion order (a Map's)
	set := func(name, value string) {
		if _, ok := lookup[name]; !ok {
			order = append(order, name)
		}
		lookup[name] = value
	}
	for _, it := range selected {
		v := plaintext[it.VersionID]
		set(it.Name, v)
		o := out{item: it, value: v}
		if it.RetiringVersionID != "" {
			r := plaintext[it.RetiringVersionID]
			o.retiring = &r
		}
		results = append(results, o)
	}
	if plain.Allowed {
		plainByName := map[string]Item{}
		for _, it := range st.Items {
			if !it.Sensitive {
				plainByName[it.Name] = it
			}
		}
		frontier := make([]string, 0, len(order))
		for _, n := range order {
			frontier = append(frontier, lookup[n])
		}
		for depth := 0; len(frontier) > 0 && depth < MaxReferenceDepth; depth++ {
			var needed []Item
			seen := map[string]bool{}
			for _, raw := range frontier {
				for _, name := range ReferencedNames(raw) {
					p, ok := plainByName[name]
					if _, have := lookup[name]; ok && !have && !seen[name] {
						seen[name] = true
						needed = append(needed, p)
					}
				}
			}
			if len(needed) == 0 {
				break
			}
			names := make([]string, len(needed))
			ids := make([]string, len(needed))
			for i, it := range needed {
				names[i], ids[i] = it.Name+"@"+it.VersionID, it.VersionID
			}
			md := jsvalue.Object{{Key: "mode", Value: "reference-expansion"}, {Key: "items", Value: strings.Join(names, ",")}}
			if dr.purpose != "" {
				md = append(md, jsvalue.Member{Key: "purpose", Value: dr.purpose})
			}
			decrypted, err := s.auditThenDecrypt(ctx, &st, []audit.Event{{
				Type: "value.disclosed", Decision: audit.Allow, ActorIdentityID: ptr(req.Principal.Identity.ID),
				OrganizationID: ptr(st.Org.ID), Action: ptr("config.value.read"), Resource: resourceOf(&st),
				Authz: allowedAuthz(plain), RequestID: ptr(req.RequestID), Metadata: md,
			}}, ids, nil)
			if err != nil {
				return nil, err
			}
			frontier = frontier[:0]
			for _, it := range needed {
				v := decrypted[it.VersionID]
				set(it.Name, v)
				frontier = append(frontier, v)
			}
		}
	}
	items := make([]any, 0, len(results))
	unexpanded := []any{}
	for _, r := range results {
		literal := literalSet{}
		value, err := ExpandReferences(r.value, func(n string) (string, bool) { v, ok := lookup[n]; return v, ok }, literal.add)
		if err != nil {
			return nil, err
		}
		if len(literal) > 0 {
			unexpanded = append(unexpanded, jsvalue.Object{{Key: "name", Value: r.item.Name}, {Key: "references", Value: literal.sorted()}})
		}
		o := jsvalue.Object{{Key: "name", Value: r.item.Name}, {Key: "versionId", Value: r.item.VersionID}, {Key: "value", Value: value}}
		if r.retiring != nil {
			o = append(o, jsvalue.Member{Key: "retiring", Value: jsvalue.Object{{Key: "versionId", Value: r.item.RetiringVersionID}, {Key: "value", Value: *r.retiring}}})
		}
		items = append(items, o)
	}
	if len(seeds) > 0 {
		opened, err := s.openSeeds(&st, seedVersions)
		if err != nil {
			return nil, err
		}
		for _, it := range seeds {
			o := jsvalue.Object{{Key: "name", Value: it.Name}, {Key: "versionId", Value: it.VersionID}, {Key: "value", Value: opened[it.VersionID].URI()}}
			if it.RetiringVersionID != "" {
				o = append(o, jsvalue.Member{Key: "retiring", Value: jsvalue.Object{{Key: "versionId", Value: it.RetiringVersionID}, {Key: "value", Value: opened[it.RetiringVersionID].URI()}}})
			}
			items = append(items, withCode(o, it))
		}
		for _, seed := range opened {
			seed.Clear()
		}
	}
	result := jsvalue.Object{{Key: "items", Value: items}, {Key: "withheld", Value: withheld}}
	s.settle(t)
	if !metadata.Allowed {
		return result, nil
	}
	manifest, digest, err := st.Manifest()
	if err != nil {
		return nil, err
	}
	return append(result,
		jsvalue.Member{Key: "manifest", Value: manifest},
		jsvalue.Member{Key: "stateDigest", Value: digest},
		jsvalue.Member{Key: "callerView", Value: jsvalue.Object{{Key: "withheld", Value: []any{}}, {Key: "unexpanded", Value: unexpanded}}},
	), nil
}

// errNotJSON is c.req.json()'s rejection of a body that is not JSON: the
// TypeScript server answers it as an internal error.
var errNotJSON = errors.New("values: the request body is not JSON")

// parseDisclosure is the route's zod schema:
//
//	z.union([
//	  z.object({ items: z.array(z.string().min(1)).min(1), purpose }),
//	  z.object({ scope: z.literal("all-authorized-secrets"), purpose }),
//	])
//
// with purpose z.enum(["scan", "export"]).optional(). Unknown members are
// stripped; the first option that fits wins. When neither fits, zod 4
// reports the issues of the one option whose issues are all checks
// (too_small), when exactly one is; otherwise "(root): Invalid input".
//
// Then totpSeeds, which the TypeScript server does not have (ADR-0061): a
// boolean that is true only with items and without a purpose, since a seed
// is never part of a scan, an export or everything one may reveal.
func parseDisclosure(body []byte) (disclosureRequest, error) {
	dr, v, err := parseDisclosureItems(body)
	if err != nil {
		return dr, err
	}
	if raw, ok := v.Get("totpSeeds"); ok {
		seeds, isBool := raw.(bool)
		switch {
		case !isBool:
			return dr, domainerr.New("VALIDATION_FAILED", "totpSeeds: Invalid input: expected boolean, received "+jsKind(raw))
		case seeds && (dr.all || dr.purpose != ""):
			return dr, domainerr.New("VALIDATION_FAILED", "totpSeeds: seeds are disclosed by their items' names, without a purpose")
		}
		dr.seeds = seeds
	}
	return dr, nil
}

func parseDisclosureItems(body []byte) (disclosureRequest, jsvalue.Object, error) {
	v, err := jsvalue.Parse(body)
	if err != nil {
		return disclosureRequest{}, nil, errNotJSON
	}
	obj, isObject := v.(jsvalue.Object)
	invalid := domainerr.New("VALIDATION_FAILED", "(root): Invalid input")
	if !isObject {
		return disclosureRequest{}, nil, invalid
	}
	purpose, purposeOK := "", true
	if p, ok := obj.Get("purpose"); ok {
		s, isString := p.(string)
		purposeOK = isString && (s == "scan" || s == "export")
		purpose = s
	}
	// The items option: a type issue aborts it; too_small issues do not.
	var items []string
	var checks []string
	itemsAborted := !purposeOK
	if raw, ok := obj.Get("items"); !ok {
		itemsAborted = true
	} else if arr, ok := raw.([]any); !ok {
		itemsAborted = true
	} else {
		for i, e := range arr {
			s, ok := e.(string)
			if !ok {
				itemsAborted = true
				continue
			}
			if s == "" {
				checks = append(checks, "items."+itoa(i)+": Too small: expected string to have >=1 characters")
			}
			items = append(items, s)
		}
		if len(arr) == 0 {
			checks = append(checks, "items: Too small: expected array to have >=1 items")
		}
	}
	if !itemsAborted && len(checks) == 0 {
		return disclosureRequest{items: items, purpose: purpose}, obj, nil
	}
	scopeOK := false
	if sc, ok := obj.Get("scope"); ok {
		scopeOK = sc == "all-authorized-secrets"
	}
	if scopeOK && purposeOK {
		return disclosureRequest{all: true, purpose: purpose}, obj, nil
	}
	// The scope option failed on a type or value, which aborts it: only the
	// items option can be the one that did not abort.
	if !itemsAborted {
		return disclosureRequest{}, nil, domainerr.New("VALIDATION_FAILED", strings.Join(checks, "; "))
	}
	return disclosureRequest{}, nil, invalid
}

func itoa(i int) string {
	const digits = "0123456789"
	if i < 10 {
		return digits[i : i+1]
	}
	return itoa(i/10) + digits[i%10:i%10+1]
}
