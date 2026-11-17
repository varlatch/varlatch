// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// Convex adapter: Convex Cloud deployments and self-hosted Convex backends.
// The base identity is the deployment URL as an https origin, pinned (https
// required, no redirects followed), and it is the destination: the
// destination record is empty and its key is "". Writes and deletes are one
// batch call, one transaction (POST /api/update_environment_variables);
// reads run the CLI's system query; the access check is GET
// /api/check_admin_key. Functions read env vars live, so there is no
// redeploy.

var convexNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

const (
	convexMaxNameLength = 256
	convexMaxValueBytes = 8 * 1024
	convexEnvListQuery  = "_system/cli/queryEnvironmentVariables"
)

// convexReserved is the backend's forbidden system names (not a blanket
// CONVEX_ prefix ban).
var convexReserved = map[string]bool{"CONVEX_CLOUD_URL": true, "CONVEX_SITE_URL": true}

type convex struct{}

// ConvexAdapter is convexAdapter.
var ConvexAdapter Adapter = convex{}

func (convex) Platform() Platform             { return Convex }
func (convex) CredentialScopeUnit() ScopeUnit { return ScopeDestination }
func (convex) SupportsReadBack() bool         { return true }
func (convex) SupportsRedeploy() bool         { return false }

// convexRequest is a POST with a body, or a GET without one.
func convexRequest(ctx context.Context, req *Request, path string, body []byte) (*response, error) {
	method := "POST"
	if body == nil {
		method = "GET"
	}
	return send(ctx, req, method, req.BaseIdentity+path, [][2]string{
		{"Authorization", "Convex " + req.Credential},
		{"Content-Type", "application/json"},
		{"Accept", "application/json"},
	}, body)
}

type convexChange struct {
	name  string
	value *string // nil deletes
}

// convexUpdate is one batch update: every name shares the request's
// outcome.
func convexUpdate(ctx context.Context, req *Request, changes []convexChange) ([]NameOutcome, error) {
	stop, err := req.abort(ctx)
	if err != nil {
		return nil, err
	}
	if stop {
		return []NameOutcome{}, nil
	}
	list := make([]any, len(changes))
	for i, c := range changes {
		var value any
		if c.value != nil {
			value = *c.value
		}
		list[i] = Object{{"name", c.name}, {"value", value}}
	}
	res, err := convexRequest(ctx, req, "/api/update_environment_variables", stringify(Object{{"changes", list}}))
	if err != nil {
		return nil, err
	}
	outcomes := make([]NameOutcome, len(changes))
	for i, c := range changes {
		outcomes[i] = outcome(c.name, res, false)
	}
	return outcomes, nil
}

// canonicalOrigin is the canonical form of an https origin a user
// entered, or the adapter's refusal in its words.
func canonicalOrigin(raw, what string) (string, error) {
	u, ok := whatwg.ParseURL(whatwg.Trim(raw))
	if !ok {
		return "", &AdapterError{Message: "Invalid " + what}
	}
	if u.Protocol != "https:" {
		return "", &AdapterError{Message: what + " must be https"}
	}
	if u.Username != "" || u.Password != "" {
		return "", &AdapterError{Message: what + " must not contain userinfo credentials"}
	}
	if u.Search != "" || u.Hash != "" || (u.Pathname != "/" && u.Pathname != "") {
		return "", &AdapterError{Message: what + " must be a bare origin (https://host[:port])"}
	}
	return whatwg.ToLower(u.Protocol + "//" + u.Host), nil
}

func (convex) CanonicalizeBaseIdentity(raw string) (string, error) {
	return canonicalOrigin(raw, "Convex deployment URL")
}

func (convex) CanonicalizeDestination(raw Object) (Destination, error) {
	// The base identity is the deployment: nothing to narrow to.
	for _, m := range raw {
		if m.Value != nil && m.Value != "" {
			return Destination{}, &AdapterError{Message: "Convex destinations take no fields (got " + m.Key + "): the Connection's deployment URL is the destination"}
		}
	}
	return Destination{Fields: Fields{}, Key: ""}, nil
}

func (convex) ValidateName(name string, _ Fields) string {
	if !convexNamePattern.MatchString(name) {
		return "Convex env var names allow only letters, digits, and _, not starting with a digit"
	}
	if len(name) > convexMaxNameLength {
		return "Convex env var names are limited to " + strconv.Itoa(convexMaxNameLength) + " characters"
	}
	if convexReserved[name] {
		return name + " is a reserved Convex system name"
	}
	return ""
}

func (convex) CanonicalizeName(name string) string { return name }

func (convex) WriteValues(ctx context.Context, req *Request, items []SyncItem) ([]NameOutcome, error) {
	// The batch is one transaction: a value over the backend's limit would
	// fail every name with it, so oversized items fail locally.
	oversized := map[string]NameOutcome{}
	var sendable []convexChange
	for _, item := range items {
		if len(wellFormed(item.Value)) > convexMaxValueBytes {
			oversized[item.Name] = NameOutcome{Name: item.Name, Error: "value exceeds Convex's " + strconv.Itoa(convexMaxValueBytes) + "-byte limit"}
		} else {
			v := item.Value
			sendable = append(sendable, convexChange{item.Name, &v})
		}
	}
	byName := map[string]NameOutcome{}
	if len(sendable) > 0 {
		sent, err := convexUpdate(ctx, req, sendable)
		if err != nil {
			return nil, err
		}
		for _, o := range sent {
			byName[o.Name] = o
		}
	}
	// Input order; an aborted batch stays visibly cut short.
	outcomes := []NameOutcome{}
	for _, item := range items {
		if o, ok := oversized[item.Name]; ok {
			outcomes = append(outcomes, o)
		} else if o, ok := byName[item.Name]; ok {
			outcomes = append(outcomes, o)
		}
	}
	return outcomes, nil
}

func (convex) DeleteNames(ctx context.Context, req *Request, names []string) ([]NameOutcome, error) {
	changes := make([]convexChange, len(names))
	for i, n := range names {
		changes[i] = convexChange{name: n}
	}
	return convexUpdate(ctx, req, changes)
}

func (convex) ReadValues(ctx context.Context, req *Request) (map[string]*string, error) {
	res, err := convexRequest(ctx, req, "/api/query", stringify(Object{
		{"path", convexEnvListQuery}, {"args", Object{}}, {"format", "json"},
	}))
	if err != nil {
		return nil, err
	}
	if !res.ok() {
		return nil, &AdapterError{
			Message:   "Convex env query failed (" + strconv.Itoa(res.status) + ")",
			Retryable: res.status != 401 && res.status != 403 && res.status != 404,
		}
	}
	parsed, err := res.json()
	if err != nil {
		return nil, err
	}
	if parsed == nil {
		// parsed.status on null.
		return nil, &ScriptError{Name: "TypeError", Message: "the query answer is null"}
	}
	o, _ := parsed.(Object)
	list, isArray := o.get("value").([]any)
	if o.get("status") != "success" || !isArray {
		// A UDF-level error body never enters the message.
		return nil, &AdapterError{Message: "Convex env query failed (udf error)", Retryable: true}
	}
	values := map[string]*string{}
	for _, e := range list {
		if e == nil {
			continue
		}
		entry, _ := e.(Object)
		name, ok := entry.get("name").(string)
		if !ok {
			continue
		}
		// A value Convex does not return as a string is unknown, not empty.
		if v, isString := entry.get("value").(string); isString {
			values[name] = &v
		} else {
			values[name] = nil
		}
	}
	return values, nil
}

func (convex) CheckAccess(ctx context.Context, req *Request) AccessCheck {
	host := hostOf(req.BaseIdentity)
	where := WhereConnection // the deployment is both
	res, err := convexRequest(ctx, req, "/api/check_admin_key", nil)
	if err != nil {
		return unreachable(host, err, where)
	}
	if res.status == 401 || res.status == 403 {
		return AccessCheck{Status: StatusCredentialRejected, Where: where, HTTPStatus: res.status,
			Message: "Convex rejected the key for this deployment. A key works only for the deployment it was made for: check that it matches this URL."}
	}
	if res.status == 404 {
		return AccessCheck{Status: StatusNotFound, Where: where, HTTPStatus: 404,
			Message: "No Convex deployment answered at " + host + ". Check the deployment URL; a self-hosted backend from before March 2025 also answers this way."}
	}
	if !res.ok() {
		return foreign("Convex", "deployment", host, res.status)
	}
	body, _ := res.jsonBody()
	key, isObject := body.(Object)
	if !isObject || key.get("success") != true {
		return foreign("Convex", "deployment", host, res.status)
	}
	ops, _ := key.get("allowedOps").([]any)
	allowed := false
	for _, op := range ops {
		if op == "WriteEnvironmentVariables" {
			allowed = true
		}
	}
	if key.get("isReadOnly") == true || (len(ops) > 0 && !allowed) {
		return AccessCheck{Status: StatusPermissionMissing, Where: where, HTTPStatus: res.status,
			Message: "Convex accepted the key, but it may not change environment variables. Use a deploy key with full access, or the admin key."}
	}
	return AccessCheck{Status: StatusOK, Where: where, Message: "Convex accepted the key, and it may set environment variables."}
}

// hostOf is new URL(origin).host.
func hostOf(origin string) string {
	u, ok := whatwg.ParseURL(origin)
	if !ok {
		return strings.TrimPrefix(origin, "https://")
	}
	return u.Host
}
