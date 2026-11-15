// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Validation (ADR-0038 Decisions 5 and 6, domain/values.ts
// validateEnvironment and the validate route; ADR-0059 step 4.1d): the
// active Contract's verdicts on the environment's values as they would be
// delivered, from one snapshot, each class judged only with the right to
// read what it describes.

// The access a class of values has (ValidationAccess).
const (
	accessAllowed     = "allowed"
	accessPermission  = "permission"
	accessRequirement = "requirement"
)

// accessOf is accessOf: an allowed decision, an unmet Requirement, or a
// missing permission; any other refusal ends the request.
func accessOf(d authz.Decision) (string, error) {
	switch {
	case d.Allowed:
		return accessAllowed, nil
	case strings.HasPrefix(d.Err.Code, "TAILNET_"):
		return accessRequirement, nil
	case d.Err.Code == "PERMISSION_DENIED" || d.Err.Code == "RESOURCE_NOT_FOUND":
		return accessPermission, nil
	}
	return "", d.Err
}

// fullContract is the snapshot's active Contract in go/lib/contract's
// model (parseContract), nil without one.
func (st *State) fullContract() (*contract.Contract, error) {
	if st.revision == nil {
		return nil, nil
	}
	v, err := contract.ParseJSON([]byte(st.revision.Contract))
	if err != nil {
		return nil, err
	}
	c, err := contract.Normalize(v, contract.Options{})
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// validation is ValidationResult, in its members' order.
type validation struct {
	environmentID, contractRevisionID string
	valid, complete                   bool
	missing                           []any
	invalid, notEvaluated, unresolved []any
}

func newValidation(st *State) *validation {
	return &validation{
		environmentID: st.Env.ID, contractRevisionID: st.Project.ActiveContractRevisionID.String,
		valid: true, complete: true, missing: []any{}, invalid: []any{}, notEvaluated: []any{}, unresolved: []any{},
	}
}

func (v *validation) js(st *State) jsvalue.Object {
	return jsvalue.Object{
		{Key: "environmentId", Value: v.environmentID}, {Key: "contractRevisionId", Value: nullable(st.Project.ActiveContractRevisionID)},
		{Key: "valid", Value: v.valid}, {Key: "complete", Value: v.complete},
		{Key: "missing", Value: v.missing}, {Key: "invalid", Value: v.invalid},
		{Key: "notEvaluated", Value: v.notEvaluated}, {Key: "unresolved", Value: v.unresolved},
	}
}

func named(name, reason string) jsvalue.Object {
	return jsvalue.Object{{Key: "name", Value: name}, {Key: "reason", Value: reason}}
}

func notEvaluated(name, reason, requires string) jsvalue.Object {
	return jsvalue.Object{{Key: "name", Value: name}, {Key: "reason", Value: reason}, {Key: "requires", Value: requires}}
}

// finish sets complete and valid from the verdicts.
func (v *validation) finish() {
	authority := false
	for _, u := range v.unresolved {
		if r, _ := u.(jsvalue.Object).Get("reason"); r == "authority" {
			authority = true
		}
	}
	v.complete = len(v.notEvaluated) == 0 && !authority
	v.valid = v.complete && len(v.missing) == 0 && len(v.invalid) == 0 && len(v.unresolved) == 0
}

// Validate is POST …/validate. In one snapshot: the scope (refused while
// the Organization is frozen), environment.read (existence hidden; a
// denial ends the request), the three classes' decisions
// (config.metadata.read, config.value.read, secret.reveal), the captured
// state with the ciphertext of what the caller may read, and the
// checkpoint. Then validateEnvironment: a class's denial is recorded only
// when validation consults it; every decryption is audited first, one
// event per class and reference level, naming the exact versions; the
// verdicts themselves are never audited.
func (s *Service) Validate(ctx context.Context, req Request) (jsvalue.Object, error) {
	t := &tracker{}
	var st State
	var denied *authz.Decision
	var metadata, plain, secret authz.Decision
	err := s.snapshot(ctx, func(tx *sql.Tx, now int64) error {
		var err error
		if st, err = scope(ctx, tx, req); err != nil {
			return err
		}
		r := st.resource()
		read, err := t.decide(ctx, tx, req, "environment.read", r, true)
		if err != nil {
			return err
		}
		if !read.Allowed {
			denied = &read
			return nil
		}
		if metadata, err = t.decide(ctx, tx, req, "config.metadata.read", r, false); err != nil {
			return err
		}
		if plain, err = t.decide(ctx, tx, req, "config.value.read", r, false); err != nil {
			return err
		}
		if secret, err = t.decide(ctx, tx, req, "secret.reveal", r, false); err != nil {
			return err
		}
		if err := capture(ctx, tx, &st, now, func(it Item) bool {
			return metadata.Allowed && (it.Sensitive && secret.Allowed || !it.Sensitive && plain.Allowed)
		}); err != nil {
			return err
		}
		return t.requireAccess(ctx, tx, req, st.Org.ID, now)
	})
	if err != nil {
		return nil, s.refused(ctx, req, t, err)
	}
	if denied != nil {
		return nil, s.reject(ctx, *denied)
	}
	// consult is the route's lazy check: a class's denial is recorded the
	// first time validation needs that class.
	consult := func(d authz.Decision) func() (string, error) {
		done, access := false, ""
		return func() (string, error) {
			if done {
				return access, nil
			}
			done = true
			if !d.Allowed {
				if err := s.recordDenial(ctx, d); err != nil {
					return "", err
				}
			}
			var err error
			access, err = accessOf(d)
			return access, err
		}
	}
	result, err := s.validateEnvironment(ctx, req, &st, map[string]func() (string, error){
		"metadata": consult(metadata), "plain": consult(plain), "secret": consult(secret),
	}, allowedAuthz(&plain), allowedAuthz(&secret))
	if err != nil {
		return nil, err
	}
	s.settle(t)
	return result.js(&st), nil
}

func (s *Service) validateEnvironment(ctx context.Context, req Request, st *State, access map[string]func() (string, error), plainAuthz, secretAuthz any) (*validation, error) {
	result := newValidation(st)
	c, err := st.fullContract()
	if err != nil || c == nil {
		return result, err
	}
	metadata, err := access["metadata"]()
	if err != nil {
		return nil, err
	}
	if metadata != accessAllowed {
		for _, it := range c.Items {
			result.notEvaluated = append(result.notEvaluated, notEvaluated(it.Name, metadata, "config.metadata.read"))
		}
		result.complete, result.valid = false, false
		return result, nil
	}
	present := map[string]Item{}
	for _, it := range st.Items {
		present[it.Name] = it
	}
	envCtx := contract.Environment{RootID: rootID(st.Env), Tier: st.Env.Tier}
	sem, err := contract.SemanticsFor(c.Version())
	if err != nil {
		return nil, err
	}
	type check struct {
		item     contract.Item
		resolved Item
	}
	var toCheck []check
	decided := map[string]string{}
	classAccess := func(kind string) (string, error) {
		if a, ok := decided[kind]; ok {
			return a, nil
		}
		a, err := access[kind]()
		if err != nil {
			return "", err
		}
		decided[kind] = a
		return a, nil
	}
	for _, it := range c.Items {
		resolved, ok := present[it.Name]
		if !ok {
			if sem.MissingWhenAbsent(it, envCtx) {
				result.missing = append(result.missing, it.Name)
			}
			continue
		}
		kind, requires := "plain", "config.value.read"
		if it.Sensitive {
			kind, requires = "secret", "secret.reveal"
		}
		a, err := classAccess(kind)
		if err != nil {
			return nil, err
		}
		if a == accessAllowed {
			toCheck = append(toCheck, check{it, resolved})
		} else {
			result.notEvaluated = append(result.notEvaluated, notEvaluated(it.Name, a, requires))
		}
	}

	raw := map[string]string{}
	// Audit before decryption: one event per class and level, naming the
	// exact versions, committed before any of them is decrypted.
	auditAndDecrypt := func(batch []Item, expansion bool) error {
		var events []audit.Event
		for _, sensitive := range []bool{true, false} {
			var names []string
			for _, r := range batch {
				if r.Sensitive == sensitive {
					names = append(names, r.Name+"@"+r.VersionID)
				}
			}
			if len(names) == 0 {
				continue
			}
			typ, action, az := "value.validated", "config.value.read", plainAuthz
			if sensitive {
				typ, action, az = "secret.validated", "secret.reveal", secretAuthz
			}
			md := jsvalue.Object{{Key: "purpose", Value: "validation"}}
			if expansion {
				md = append(md, jsvalue.Member{Key: "mode", Value: "reference-expansion"})
			}
			md = append(md, jsvalue.Member{Key: "contractRevisionId", Value: nullable(st.Project.ActiveContractRevisionID)},
				jsvalue.Member{Key: "items", Value: strings.Join(names, ",")})
			events = append(events, audit.Event{
				Type: typ, Decision: audit.Allow, ActorIdentityID: ptr(req.Principal.Identity.ID), OrganizationID: ptr(st.Org.ID),
				Action: ptr(action), Resource: resourceOf(st), Authz: az, RequestID: ptr(req.RequestID), Metadata: md,
			})
		}
		versions := make([]string, len(batch))
		for i, r := range batch {
			versions[i] = r.VersionID
		}
		plaintext, err := s.auditThenDecrypt(ctx, st, events, versions, nil)
		if err != nil {
			return err
		}
		for _, r := range batch {
			raw[r.Name] = plaintext[r.VersionID]
		}
		return nil
	}
	batch := make([]Item, len(toCheck))
	for i, ch := range toCheck {
		batch[i] = ch.resolved
	}
	if err := auditAndDecrypt(batch, false); err != nil {
		return nil, err
	}

	// What a delivery may expand from: a non-sensitive value from
	// non-sensitive values; a Secret from Secrets and, when the caller may
	// read them (asked only when a Secret references one), non-sensitive
	// values.
	inDomain := func(origin, name string) (bool, error) {
		it, ok := present[name]
		if !ok {
			return false, nil
		}
		if origin == "plain" {
			return !it.Sensitive, nil
		}
		if it.Sensitive {
			return true, nil
		}
		a, err := classAccess("plain")
		return a == accessAllowed, err
	}
	type ref struct{ origin, name string }
	frontier := make([]ref, len(toCheck))
	for i, ch := range toCheck {
		frontier[i] = ref{"plain", ch.item.Name}
		if ch.item.Sensitive {
			frontier[i].origin = "secret"
		}
	}
	scanned := map[ref]bool{}
	for depth := 0; len(frontier) > 0 && depth < MaxReferenceDepth; depth++ {
		var next []ref
		var toDecrypt []Item
		queued := map[string]bool{}
		for _, f := range frontier {
			if scanned[f] {
				continue
			}
			scanned[f] = true
			value, ok := raw[f.name]
			if !ok {
				continue
			}
			for _, name := range ReferencedNames(value) {
				in, err := inDomain(f.origin, name)
				if err != nil {
					return nil, err
				}
				if !in {
					continue
				}
				next = append(next, ref{f.origin, name})
				if _, have := raw[name]; !have && !queued[name] {
					queued[name] = true
					toDecrypt = append(toDecrypt, present[name])
				}
			}
		}
		if len(toDecrypt) > 0 {
			if err := auditAndDecrypt(toDecrypt, true); err != nil {
				return nil, err
			}
		}
		frontier = next
	}

	plainReadable := decided["plain"] == accessAllowed
	for _, ch := range toCheck {
		value, ok := raw[ch.item.Name]
		if !ok {
			continue
		}
		secretOrigin := ch.item.Sensitive
		blocked, other := false, false
		lookup := func(name string) (string, bool) {
			r, exists := present[name]
			readable := exists && (secretOrigin && (r.Sensitive || plainReadable) || !secretOrigin && !r.Sensitive)
			if exists && !readable && secretOrigin {
				blocked = true
			}
			v, have := "", false
			if readable {
				v, have = raw[name]
			}
			if !have && !(exists && !readable && secretOrigin) {
				other = true
			}
			return v, have
		}
		// A lenient pass sees every reference; a strict one then catches
		// cycles and depth.
		delivered, err := ExpandReferences(value, lookup, nil)
		if err == nil && !blocked && !other {
			_, err = expandStrict(value, lookup)
		}
		if err != nil {
			var unresolved *unresolvedError
			if errors.As(err, &unresolved) {
				result.unresolved = append(result.unresolved, named(ch.item.Name, "reference"))
			} else {
				result.invalid = append(result.invalid, named(ch.item.Name, "expands beyond the delivery size limit"))
			}
			continue
		}
		if blocked || other {
			reason := "reference"
			if blocked && !other {
				reason = "authority"
			}
			result.unresolved = append(result.unresolved, named(ch.item.Name, reason))
			continue
		}
		if problem := sem.Validate(ch.item, delivered); problem != "" {
			result.invalid = append(result.invalid, named(ch.item.Name, problem))
		}
	}
	result.finish()
	return result, nil
}
