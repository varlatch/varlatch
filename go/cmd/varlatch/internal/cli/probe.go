// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"strconv"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// whoamiCapability is whoami.ts's WHOAMI_CAPABILITY.
const whoamiCapability = "identity.whoami"

// probeServer is main.ts's probeServer (ADR-0032 Decision 3): whether the
// stored credential still works ("valid", "invalid" with the error's
// checked code, "unreachable" with what went wrong), what it resolves to
// where the server can say, and the store's metadata backfilled from the
// credential's own record. It never fails: every error becomes the probe's
// state. The answers are read as JavaScript reads them, so an answer of
// another shape gives the TypeScript CLI's TypeError text as the detail.
func (r *Run) probeServer(server string, token any, tokenOK bool) jsjson.Object {
	probe, err := r.probe(server, token, tokenOK)
	if err == nil {
		return probe
	}
	var api *apiclient.APIError
	if errors.As(err, &api) {
		return jsjson.Object{{Key: "state", Value: "invalid"}, {Key: "detail", Value: safeCode(api.Code)}}
	}
	// Its text goes out through the composed masker like any other
	// (RedactValue in --json, shownValue in the human format).
	return jsjson.Object{{Key: "state", Value: "unreachable"}, {Key: "detail", Value: err.Error()}}
}

func (r *Run) probe(server string, token any, tokenOK bool) (jsjson.Object, error) {
	bearer := ""
	if tokenOK && jsjson.Truthy(token) {
		bearer = jsjson.String(token)
	}
	api := r.plainClient(server, bearer)
	ctx := context.Background()
	meta, err := api.Meta(ctx)
	if err != nil {
		return nil, err
	}
	// Verifies the credential and identifies it: OwnCredential.current marks
	// the one authenticating this request, so a probe can backfill store
	// metadata that logins before ADR-0032 never recorded.
	credentials, err := api.ListMyCredentials(ctx)
	if err != nil {
		return nil, err
	}
	items, itemsOK, err := read(credentials, credentials != apiclient.Undefined, "items")
	if err != nil {
		return nil, err
	}
	if _, isArray := items.([]any); !isArray {
		if !itemsOK || items == nil {
			return nil, typeErrorRead(items, itemsOK, "find")
		}
		// V8 names the expression as the release bundle spells it: esbuild
		// renamed main.ts's `credentials` there.
		return nil, &clientctx.TypeError{Message: "credentials2.items.find is not a function"}
	}
	var current any
	currentOK := false
	for _, c := range items.([]any) {
		v, ok, err := read(c, true, "current")
		if err != nil {
			return nil, err
		}
		if ok && jsjson.Truthy(v) {
			current, currentOK = c, true
			break
		}
	}
	stored, err := clientctx.LoadCredential(server, r.Env)
	if err != nil {
		return nil, err
	}
	storedToken, storedTokenOK := getOptional(stored, "token")
	if currentOK && jsjson.Truthy(current) && sameValue(storedToken, storedTokenOK, token, tokenOK) {
		if err := r.backfill(server, stored, current); err != nil {
			return nil, err
		}
	}
	// The resolved identity (ADR-0032 Decision 3), where the server can say.
	capabilities, capOK, err := read(meta, meta != apiclient.Undefined, "capabilities")
	if err != nil {
		return nil, err
	}
	has, err := includes(capabilities, capOK, whoamiCapability, "meta3.capabilities.includes") // the bundle's name, as above
	if err != nil {
		return nil, err
	}
	if !has {
		return jsjson.Object{{Key: "state", Value: "valid"}, {Key: "detail", Value: nil}}, nil
	}
	me, err := api.WhoAmI(ctx)
	if err != nil {
		return nil, err
	}
	if me == apiclient.Undefined || me == nil {
		what := "undefined"
		if me == nil {
			what = "null"
		}
		return nil, &clientctx.TypeError{Message: "Cannot destructure property 'identity' of '(intermediate value)' as it is " + what + "."}
	}
	identity, identityOK := jsval.Get(me, "identity")
	organization, organizationOK := jsval.Get(me, "organization")
	shown := jsjson.Object{}
	for _, key := range []string{"id", "name", "kind"} {
		v, ok, err := read(identity, identityOK, key)
		if err != nil {
			return nil, err
		}
		// undefined is left out, as JSON.stringify does; so is an object or
		// array where the API defines a scalar.
		if sv, isScalar := scalar(v); ok && isScalar {
			shown = append(shown, jsjson.Member{Key: key, Value: sv})
		}
	}
	var org any
	if organizationOK && jsjson.Truthy(organization) {
		o := jsjson.Object{}
		for _, key := range []string{"id", "slug", "name"} {
			if v, ok := jsval.Get(organization, key); ok {
				if sv, isScalar := scalar(v); isScalar {
					o = append(o, jsjson.Member{Key: key, Value: sv})
				}
			}
		}
		org = o
	}
	return jsjson.Object{
		{Key: "state", Value: "valid"},
		{Key: "detail", Value: nil},
		{Key: "identity", Value: shown},
		{Key: "organization", Value: org},
	}, nil
}

// getOptional is v?.[key]: undefined (false) when v is null.
func getOptional(v any, key string) (any, bool) {
	if v == nil {
		return nil, false
	}
	return jsval.Get(v, key)
}

// sameValue is a === b for two values that may be undefined.
func sameValue(a any, aOK bool, b any, bOK bool) bool {
	if !aOK || !bOK {
		return aOK == bOK
	}
	return jsval.StrictEqual(a, b)
}

// includes is `list.includes(value)` for what a server sent as a list: an
// array's elements, a string's substrings; anything else has no includes.
func includes(list any, present bool, value, expr string) (bool, error) {
	switch x := list.(type) {
	case []any:
		for _, e := range x {
			if e == value {
				return true, nil
			}
		}
		return false, nil
	case string:
		return bytes.Contains([]byte(x), []byte(value)), nil
	}
	if !present || list == nil {
		return false, typeErrorRead(list, present, "includes")
	}
	return false, &clientctx.TypeError{Message: expr + " is not a function"}
}

// spread is `{...v}` for a JSON value: an object's members, an array's
// elements and a string's code units under their indexes, nothing for the
// rest.
func spread(v any) jsjson.Object {
	out := jsjson.Object{}
	switch x := v.(type) {
	case jsjson.Object:
		out = append(out, x...)
	case []any:
		for i, e := range x {
			out = append(out, jsjson.Member{Key: strconv.Itoa(i), Value: e})
		}
	case string:
		for i, u := range jsval.UTF16(x) {
			out = append(out, jsjson.Member{Key: strconv.Itoa(i), Value: jsval.FromUTF16([]uint16{u})})
		}
	}
	return out
}

// setOrDrop is o[key] = v, where an undefined v is a key JSON.stringify
// leaves out: dropped, since only the JSON is used afterwards.
func setOrDrop(o jsjson.Object, key string, v any, present bool) jsjson.Object {
	if present {
		return o.Set(key, v)
	}
	out := o[:0:0]
	for _, m := range o {
		if m.Key != key {
			out = append(out, m)
		}
	}
	return out
}

// backfill is the probe's store update:
//
//	{...stored, ...(current.expiresAt ? {expiresAt} : {}), credentialId: current.id,
//	 ...(current.name ? {name} : {}), issuedAt: stored.issuedAt ?? current.createdAt}
//
// saved when its JSON differs from the stored entry's.
func (r *Run) backfill(server string, stored, current any) error {
	backfilled := spread(stored)
	if v, ok := jsval.Get(current, "expiresAt"); ok && jsjson.Truthy(v) {
		backfilled = backfilled.Set("expiresAt", v)
	}
	id, idOK := jsval.Get(current, "id")
	backfilled = setOrDrop(backfilled, "credentialId", id, idOK)
	if v, ok := jsval.Get(current, "name"); ok && jsjson.Truthy(v) {
		backfilled = backfilled.Set("name", v)
	}
	issuedAt, issuedOK, err := read(stored, true, "issuedAt")
	if err != nil {
		return err
	}
	if !issuedOK || issuedAt == nil {
		issuedAt, issuedOK = jsval.Get(current, "createdAt")
	}
	backfilled = setOrDrop(backfilled, "issuedAt", issuedAt, issuedOK)
	if bytes.Equal(jsjson.Stringify(backfilled), jsjson.Stringify(stored)) {
		return nil
	}
	return clientctx.SaveCredential(server, backfilled, r.Env)
}
