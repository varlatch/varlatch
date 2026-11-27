// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"

	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/contracts"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Strict retrieval (ADR-0038 Decision 6, domain/strict.ts and the
// retrievals route; ADR-0059 step 4.1d): the non-sensitive values and every
// authorized Secret, from one snapshot, with the state manifest, the caller
// view, the Contract, and the validation of exactly the values returned,
// in one response. Each class is authorized separately. A preflight returns
// no Secret value, only its verdict.

// StrictRetrieval is POST …/retrievals. body is the request body as sent:
// it is parsed only once metadata access decided (readJson), with
// z.object({ mode: z.enum(["strict", "preflight"]) }).
func (s *Service) StrictRetrieval(ctx context.Context, req Request, body func() (any, error)) (jsvalue.Object, error) {
	t := &tracker{}
	var st State
	var denied *authz.Decision
	var plain, secret, contractRead authz.Decision
	var mode string
	err := s.snapshot(ctx, func(tx *sql.Tx, now int64) error {
		var err error
		if st, err = scope(ctx, tx, req); err != nil {
			return err
		}
		r := st.resource()
		metadata, err := t.decide(ctx, tx, req, "config.metadata.read", r, true)
		if err != nil {
			return err
		}
		if !metadata.Allowed {
			denied = &metadata
			return nil
		}
		if mode, err = parseMode(body); err != nil {
			return err
		}
		if plain, err = t.decide(ctx, tx, req, "config.value.read", r, false); err != nil {
			return err
		}
		if secret, err = t.decide(ctx, tx, req, "secret.reveal", r, false); err != nil {
			return err
		}
		if contractRead, err = t.decide(ctx, tx, req, "contract.read", authz.Resource{OrganizationID: st.Org.ID, ProjectID: st.Project.ID}, false); err != nil {
			return err
		}
		if err := capture(ctx, tx, &st, now, func(it Item) bool {
			return it.Sensitive && secret.Allowed || !it.Sensitive && plain.Allowed
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
	for _, d := range []authz.Decision{plain, secret, contractRead} {
		if err := s.recordDenial(ctx, d); err != nil {
			return nil, err
		}
	}
	plainAccess, err := accessOf(plain)
	if err != nil {
		return nil, err
	}
	secretAccess, err := accessOf(secret)
	if err != nil {
		return nil, err
	}
	out, err := s.strict(ctx, req, &st, mode, plainAccess, secretAccess, contractRead.Allowed, allowedAuthz(&plain), allowedAuthz(&secret))
	if err != nil {
		return nil, err
	}
	s.settle(t)
	return out, nil
}

// parseMode is the body's zod check.
func parseMode(body func() (any, error)) (string, error) {
	v, err := body()
	if err != nil {
		return "", err
	}
	o, ok := v.(jsvalue.Object)
	if !ok {
		return "", domainerr.New("VALIDATION_FAILED", "(root): Invalid input: expected object, received "+jsKind(v))
	}
	m, _ := o.Get("mode")
	if m != "strict" && m != "preflight" {
		return "", domainerr.New("VALIDATION_FAILED", `mode: Invalid option: expected one of "strict"|"preflight"`)
	}
	return m.(string), nil
}

// jsKind is a JSON value's type as zod names it after "received".
func jsKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	}
	return "object"
}

// stateDigests is categoryDigests: one digest per category of the
// manifest, so a later mismatch can say which changed.
func (st *State) stateDigests() (jsvalue.Object, error) {
	digest := func(v any) (string, error) {
		canon, err := envelope.CanonicalJSON(v)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256([]byte(canon))
		return "sha256:" + hex.EncodeToString(sum[:]), nil
	}
	env := map[string]any{"id": st.Env.ID, "rootId": rootID(st.Env), "parentId": nullable(st.Env.ParentEnvironmentID), "tier": st.Env.Tier, "expiresAt": nil}
	if st.Env.ExpiresAt.Valid {
		env["expiresAt"] = audit.ISOTime(st.Env.ExpiresAt.Int64)
	}
	var contractPart any
	if st.revision != nil && st.contract != nil {
		version := 1.0
		if st.contract.SemanticsVersion != nil {
			version = *st.contract.SemanticsVersion
		}
		contractPart = map[string]any{"revisionId": st.revision.ID, "contentHash": st.revision.ContentHash, "semanticsVersion": version}
	}
	items, rotation := []any{}, []any{}
	for _, it := range st.all() {
		items = append(items, map[string]any{"name": it.Name, "source": it.Source, "valueRowId": it.ValueRowID, "versionId": it.VersionID})
		if it.RetiringVersionID != "" {
			rotation = append(rotation, map[string]any{"name": it.Name, "retiringVersionId": it.RetiringVersionID})
		}
	}
	out := jsvalue.Object{}
	for _, c := range []struct {
		key   string
		value any
	}{
		{"environment", map[string]any{"projectId": st.Project.ID, "environment": env}},
		{"contract", contractPart}, {"items", items}, {"rotation", rotation},
	} {
		d, err := digest(c.value)
		if err != nil {
			return nil, err
		}
		out = append(out, jsvalue.Member{Key: c.key, Value: d})
	}
	return out, nil
}

func (s *Service) strict(ctx context.Context, req Request, st *State, mode, plainAccess, secretAccess string, contractAllowed bool, plainAuthz, secretAuthz any) (jsvalue.Object, error) {
	preflight := mode == "preflight"
	if err := st.expired(); err != nil {
		return nil, err
	}
	delivers := func(it Item) bool {
		if it.Sensitive {
			return secretAccess == accessAllowed
		}
		return plainAccess == accessAllowed
	}
	var plain, secrets []Item
	for _, it := range st.Items {
		switch {
		case !delivers(it):
		case it.Sensitive:
			secrets = append(secrets, it)
		default:
			plain = append(plain, it)
		}
	}

	// One commit covers every decryption below, and precedes all of them.
	var events []audit.Event
	base := func(typ, action string, az any, md jsvalue.Object) audit.Event {
		return audit.Event{
			Type: typ, Decision: audit.Allow, ActorIdentityID: ptr(req.Principal.Identity.ID), OrganizationID: ptr(st.Org.ID),
			Action: ptr(action), Resource: resourceOf(st), Authz: az, RequestID: ptr(req.RequestID), Metadata: md,
		}
	}
	list := func(items []Item, withRetiring bool) string {
		names := make([]string, len(items))
		for i, it := range items {
			names[i] = it.Name + "@" + it.VersionID
			if withRetiring && it.RetiringVersionID != "" {
				names[i] += "+" + it.RetiringVersionID
			}
		}
		return strings.Join(names, ",")
	}
	if len(plain) > 0 {
		events = append(events, base("value.disclosed", "config.value.read", plainAuthz,
			jsvalue.Object{{Key: "mode", Value: "strict-retrieval"}, {Key: "items", Value: list(plain, false)}}))
	}
	if len(secrets) > 0 {
		if preflight {
			events = append(events, base("secret.validated", "secret.reveal", secretAuthz,
				jsvalue.Object{{Key: "purpose", Value: "preflight-validation"}, {Key: "items", Value: list(secrets, false)}}))
		} else {
			events = append(events, base("secret.disclosed", "secret.reveal", secretAuthz,
				jsvalue.Object{{Key: "mode", Value: "strict-retrieval"}, {Key: "items", Value: list(secrets, true)}}))
		}
	}
	var versions []string
	for _, it := range append(append([]Item{}, plain...), secrets...) {
		versions = append(versions, it.VersionID)
		if it.Sensitive && it.RetiringVersionID != "" && !preflight {
			versions = append(versions, it.RetiringVersionID)
		}
	}
	plaintext, err := s.auditThenDecrypt(ctx, st, events, versions, nil)
	if err != nil {
		return nil, err
	}

	// Expansion follows delivery: a non-sensitive value from non-sensitive
	// values; a Secret from Secrets and the non-sensitive values delivered.
	plainValues := map[string]string{}
	for _, it := range plain {
		plainValues[it.Name] = plaintext[it.VersionID]
	}
	secretDomain := map[string]string{}
	for _, it := range secrets {
		secretDomain[it.Name] = plaintext[it.VersionID]
	}
	for k, v := range plainValues {
		secretDomain[k] = v
	}
	items := make([]any, 0, len(st.Items))
	unexpanded, withheld := []any{}, []any{}
	evaluable := map[string]string{}
	type denial struct{ reason, requires string }
	notEvaluable := map[string]denial{}
	literalByName := map[string][]string{}
	for _, it := range st.all() {
		entry := jsvalue.Object{{Key: "name", Value: it.Name}, {Key: "sensitive", Value: it.Sensitive}, {Key: "source", Value: it.Source},
			{Key: "versionId", Value: it.VersionID}, {Key: "value", Value: nil}}
		if it.RetiringVersionID != "" {
			entry = append(entry, jsvalue.Member{Key: "rotating", Value: true})
		}
		if it.special() {
			// A seed of one-time codes is delivered to nobody here (ADR-0061),
			// nor an OAuth connection's client secret or tokens (ADR-0062).
			if !preflight {
				reason := "one-time-code"
				if it.Connection != nil {
					reason = "oauth-connection"
				}
				withheld = append(withheld, jsvalue.Object{{Key: "name", Value: it.Name}, {Key: "reason", Value: reason}, {Key: "requires", Value: "secret.use"}})
			}
			items = append(items, withCode(entry, it))
			continue
		}
		if !delivers(it) {
			access, requires := plainAccess, "config.value.read"
			if it.Sensitive {
				access, requires = secretAccess, "secret.reveal"
			}
			d := denial{accessPermission, requires}
			if access == accessRequirement {
				d.reason = accessRequirement
			}
			notEvaluable[it.Name] = d
			// A preflight delivers no Secret by design: only non-sensitive
			// values count as withheld.
			if !(preflight && it.Sensitive) {
				withheld = append(withheld, jsvalue.Object{{Key: "name", Value: it.Name}, {Key: "reason", Value: d.reason}, {Key: "requires", Value: d.requires}})
			}
			items = append(items, entry)
			continue
		}
		raw := plaintext[it.VersionID]
		domain := plainValues
		if it.Sensitive {
			domain = secretDomain
		}
		literal := literalSet{}
		value, err := ExpandReferences(raw, func(n string) (string, bool) { v, ok := domain[n]; return v, ok }, literal.add)
		if err != nil {
			return nil, err // a size or work limit: the whole retrieval fails
		}
		evaluable[it.Name] = value
		if len(literal) > 0 {
			refs := literal.sorted()
			literalByName[it.Name] = refs
			unexpanded = append(unexpanded, jsvalue.Object{{Key: "name", Value: it.Name}, {Key: "references", Value: refs}})
		}
		if preflight && it.Sensitive {
			items = append(items, entry)
			continue
		}
		entry[4].Value = value
		if value != raw {
			entry = append(entry, jsvalue.Member{Key: "rawValue", Value: raw})
		}
		if it.Sensitive && it.RetiringVersionID != "" {
			entry = append(entry, jsvalue.Member{Key: "retiring", Value: jsvalue.Object{
				{Key: "versionId", Value: it.RetiringVersionID}, {Key: "value", Value: plaintext[it.RetiringVersionID]},
			}})
		}
		items = append(items, entry)
	}

	// validateDelivered: verdicts on exactly the values returned.
	result := newValidation(st)
	c, err := st.fullContract()
	if err != nil {
		return nil, err
	}
	if c != nil {
		sem, err := contract.SemanticsFor(c.Version())
		if err != nil {
			return nil, err
		}
		envCtx := contract.Environment{RootID: rootID(st.Env), Tier: st.Env.Tier}
		stored := map[string]Item{}
		for _, it := range st.all() {
			stored[it.Name] = it
		}
		for _, it := range c.Items {
			if _, ok := stored[it.Name]; !ok {
				if sem.MissingWhenAbsent(it, envCtx) {
					result.missing = append(result.missing, it.Name)
				}
				continue
			}
			if stored[it.Name].special() {
				if problem := specialProblem(stored[it.Name], it); problem != "" {
					result.invalid = append(result.invalid, named(it.Name, problem))
				}
				continue
			}
			if d, ok := notEvaluable[it.Name]; ok {
				result.notEvaluated = append(result.notEvaluated, notEvaluated(it.Name, d.reason, d.requires))
				continue
			}
			if refs, ok := literalByName[it.Name]; ok {
				// "authority": a Secret whose only literal references are
				// non-sensitive values this caller may not read.
				authority := it.Sensitive && plainAccess != accessAllowed
				for _, n := range refs {
					r, exists := stored[n]
					authority = authority && exists && !r.Sensitive
				}
				reason := "reference"
				if authority {
					reason = "authority"
				}
				result.unresolved = append(result.unresolved, named(it.Name, reason))
				continue
			}
			if problem := sem.Validate(it, evaluable[it.Name]); problem != "" {
				result.invalid = append(result.invalid, named(it.Name, problem))
			}
		}
		result.finish()
	}

	manifest, digest, err := st.Manifest()
	if err != nil {
		return nil, err
	}
	digests, err := st.stateDigests()
	if err != nil {
		return nil, err
	}
	var contractJS any
	if contractAllowed && st.revision != nil {
		if contractJS, err = contracts.Stored(st.revision.Contract); err != nil {
			return nil, err
		}
	}
	return jsvalue.Object{
		{Key: "mode", Value: mode}, {Key: "environmentId", Value: st.Env.ID},
		{Key: "manifest", Value: manifest}, {Key: "stateDigest", Value: digest}, {Key: "stateDigests", Value: digests},
		{Key: "contract", Value: contractJS}, {Key: "items", Value: items},
		{Key: "callerView", Value: jsvalue.Object{{Key: "withheld", Value: withheld}, {Key: "unexpanded", Value: unexpanded},
			{Key: "contractWithheld", Value: !contractAllowed && st.revision != nil}}},
		{Key: "validation", Value: result.js(st)},
	}, nil
}
